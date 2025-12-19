package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type SystemMetric struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	IPv4               string    `json:"ipv4,omitempty"`
	IPv6               string    `json:"ipv6,omitempty"`
	Time               string    `json:"time,omitempty"`
	Location           string    `json:"location,omitempty"`
	VirtualizationType string    `json:"virtualization_type,omitempty"` // "VPS" or "DS"
	OS                 string    `json:"os,omitempty"`
	OSIcon             string    `json:"os_icon,omitempty"`
	CPU                float64   `json:"cpu"`
	CPUModel           string    `json:"cpu_model,omitempty"`
	Memory             float64   `json:"memory"`
	MemoryInfo         string    `json:"memory_info,omitempty"`   // Format: "383.60 MiB / 1.88 GiB"
	SwapInfo           string    `json:"swap_info,omitempty"`     // Format: "75.12 MiB / 975.00 MiB"
	Disk               float64   `json:"disk"`
	DiskInfo           string    `json:"disk_info,omitempty"`     // Format: "9.86 GiB / 18.58 GiB"
	NetInMBps          float64   `json:"net_in_mb_s"`
	NetOutMBps         float64   `json:"net_out_mb_s"`
	TotalNetInBytes    uint64    `json:"total_net_in_bytes,omitempty"`  // Total received bytes
	TotalNetOutBytes   uint64    `json:"total_net_out_bytes,omitempty"` // Total transmitted bytes
	AgentVersion       string                        `json:"agent_version"`
	Order              int                           `json:"order"` // Display order for sorting
	Alert              bool                          `json:"alert"`
	UpdatedAt          time.Time                     `json:"updated_at"`
	TCPingData         map[string]TCPingTargetData   `json:"tcping_data,omitempty"` // Map of target -> latest tcping data
}

// TCPingTargetData represents the latest tcping data for a specific target
type TCPingTargetData struct {
	Latency   float64   `json:"latency"`    // Latest tcping latency in ms
	Timestamp time.Time `json:"timestamp"`  // Latest tcping timestamp
}

type metricPayload struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	IPv4               string  `json:"ipv4,omitempty"`
	IPv6               string  `json:"ipv6,omitempty"`
	Uptime             int64   `json:"uptime"` // Uptime in seconds
	Location           string  `json:"location,omitempty"`
	VirtualizationType string  `json:"virtualization_type,omitempty"` // "VPS" or "DS"
	OS                 string  `json:"os,omitempty"`
	OSIcon             string  `json:"os_icon,omitempty"`
	CPU                float64 `json:"cpu"`
	CPUModel           string  `json:"cpu_model,omitempty"`
	Memory             float64 `json:"memory"`
	MemoryInfo         string  `json:"memory_info,omitempty"`   // Format: "383.60 MiB / 1.88 GiB"
	SwapInfo           string  `json:"swap_info,omitempty"`     // Format: "75.12 MiB / 975.00 MiB"
	Disk               float64 `json:"disk"`
	DiskInfo           string  `json:"disk_info,omitempty"`     // Format: "9.86 GiB / 18.58 GiB"
	NetInMBps          float64 `json:"net_in_mb_s"`
	NetOutMBps         float64 `json:"net_out_mb_s"`
	TotalNetInBytes    uint64  `json:"total_net_in_bytes,omitempty"`  // Total received bytes
	TotalNetOutBytes   uint64  `json:"total_net_out_bytes,omitempty"` // Total transmitted bytes
	AgentVersion       string  `json:"agent_version"`
	Alert              bool    `json:"alert"`
}

// SSE Broker for broadcasting updates
type SSEBroker struct {
	clients map[chan string]bool
	mu      sync.RWMutex
}

func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		clients: make(map[chan string]bool),
	}
}

func (b *SSEBroker) Subscribe() chan string {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	ch := make(chan string, 10)
	b.clients[ch] = true
	return ch
}

func (b *SSEBroker) Unsubscribe(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	delete(b.clients, ch)
	close(ch)
}

func (b *SSEBroker) Broadcast(event string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	for ch := range b.clients {
		select {
		case ch <- event:
		default:
			// Client buffer full, skip
		}
	}
}

// Client registry for tracking agent clients
type ClientInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Port string `json:"port"`
	IP   string `json:"ip,omitempty"` // Client IP address
	URL  string `json:"url"`           // Full URL to client
}

type ClientRegistry struct {
	clients map[string]*ClientInfo // key: client ID
	mu      sync.RWMutex
}

// IP to country cache
type IPCountryCache struct {
	cache map[string]string // key: IP, value: country
	mu    sync.RWMutex
}

func NewIPCountryCache() *IPCountryCache {
	return &IPCountryCache{
		cache: make(map[string]string),
	}
}

func (c *IPCountryCache) Get(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	country, exists := c.cache[ip]
	return country, exists
}

func (c *IPCountryCache) Set(ip, country string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = country
}

func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{
		clients: make(map[string]*ClientInfo),
	}
}

func (r *ClientRegistry) Register(id, name, port, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Construct client URL - always use IP, never localhost
	var url string
	if ip != "" && ip != "127.0.0.1" && ip != "localhost" {
		url = fmt.Sprintf("http://%s:%s", ip, port)
	} else {
		// If IP is invalid, try to get server's own IP
		serverIP := getServerIP()
		if serverIP != "" {
			url = fmt.Sprintf("http://%s:%s", serverIP, port)
			ip = serverIP
		} else {
			// Still register but with warning
			url = fmt.Sprintf("http://%s:%s", ip, port)
		}
	}
	
	r.clients[id] = &ClientInfo{
		ID:   id,
		Name: name,
		Port: port,
		IP:   ip,
		URL:  url,
	}
}

// getServerIP gets the server's own IP address (non-loopback)
func getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func (r *ClientRegistry) GetAll() []*ClientInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	clients := make([]*ClientInfo, 0, len(r.clients))
	for _, client := range r.clients {
		clients = append(clients, client)
	}
	return clients
}

// Shared HTTP client for all polling operations (connection pooling)
var sharedHTTPClient *http.Client
var sharedHTTPClientOnce sync.Once

func getSharedHTTPClient() *http.Client {
	sharedHTTPClientOnce.Do(func() {
		// Create a shared HTTP client with optimized connection pooling for stable connection
		sharedHTTPClient = &http.Client{
			Timeout: 8 * time.Second, // Longer timeout for stability
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second, // Longer dial timeout for stability
					KeepAlive: 120 * time.Second, // Longer keep-alive for connection reuse (like LAN)
				}).DialContext,
				MaxIdleConns:          200,              // More connections for stability
				MaxIdleConnsPerHost:   20,               // More per-host connections
				IdleConnTimeout:       180 * time.Second, // Longer idle timeout for stable connection
				TLSHandshakeTimeout:   5 * time.Second,
				ExpectContinueTimeout: 2 * time.Second,
				DisableCompression:    false, // Enable compression for efficiency
			},
		}
	})
	return sharedHTTPClient
}

func (r *ClientRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, id)
}


func main() {
	log.Println("🚀 Starting Probe Server...")

	// Initialize database with persistence
	dbPath := DBPath()
	store, err := NewStore(dbPath)
	if err != nil {
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer store.Close()

	// Initialize SSE broker
	broker := NewSSEBroker()
	
	// Initialize client registry
	clientRegistry := NewClientRegistry()
	
	// Initialize IP country cache
	ipCache := NewIPCountryCache()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n🛑 Shutting down gracefully...")
		store.Close()
		os.Exit(0)
	}()

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		handleSSE(broker, w, r)
	})
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListMetrics(store, w, r)
		case http.MethodPost:
			handleIngestMetric(store, broker, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/metrics/order", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			handleUpdateOrder(store, broker, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/metrics/", func(w http.ResponseWriter, r *http.Request) {
		// Extract ID from path: /api/metrics/{id}
		id := strings.TrimPrefix(r.URL.Path, "/api/metrics/")
		if id == "" {
			http.Error(w, "missing system id", http.StatusBadRequest)
			return
		}
		
		switch r.Method {
		case http.MethodDelete:
			handleDeleteMetric(store, broker, clientRegistry, w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/clients/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleClientRegister(store, clientRegistry, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/tcping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleTCPingResult(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/tcping/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleGetTCPingConfig(store, w, r)
		} else if r.Method == http.MethodPost {
			handleSetTCPingConfig(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/tcping/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleGetTCPingHistory(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	
	// Auth endpoints
	mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleAuthStatus(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/auth/setup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleAuthSetup(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleAuthLogin(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleAuthVerify(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleAuthChangePassword(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	addr := ":" + portFromEnv()
	// Start polling clients every 3 seconds
	go startClientPolling(store, broker, clientRegistry, ipCache)
	
	// Start tcping polling every 5 seconds
	go startTCPingPolling(clientRegistry, store)
	
	// Start cleanup old tcping data every hour
	go startTCPingCleanup(store)
	
	log.Printf("🌐 Backend listening on %s", addr)
	
	if err := http.ListenAndServe(addr, corsMiddleware(mux)); err != nil {
		log.Fatalf("❌ Server stopped: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleSSE(broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Important for reverse proxy - tells nginx/other proxies not to buffer
	w.Header().Set("X-Accel-Buffering", "no")

	// Subscribe to broker
	ch := broker.Subscribe()
	defer broker.Unsubscribe(ch)

	// Get flusher for real-time streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send initial connection message
	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Connected to updates stream\"}\n\n")
	flusher.Flush()

	// Listen for client disconnect and broker messages
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			return
		case msg := <-ch:
			// Send update to client
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func handleListMetrics(store *Store, w http.ResponseWriter, r *http.Request) {
	metrics, err := store.List()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	
	// Mark systems as offline if they haven't updated in the last 10 seconds
	// Also mark as offline if UpdatedAt is zero (newly added systems)
	now := time.Now().UTC()
	authenticated := isAuthenticated(r)
	
	for i := range metrics {
		// Check if system should be marked as offline based on update time
		shouldBeOffline := metrics[i].UpdatedAt.IsZero() || now.Sub(metrics[i].UpdatedAt) > 10*time.Second
		
		// Always calculate Alert based on update time for consistency
		// This ensures the status is always accurate based on the latest update
		if shouldBeOffline {
			metrics[i].Alert = true // Offline/paused state
		} else {
			metrics[i].Alert = false // Online state
		}
		
		// Hide IP addresses if not authenticated (security)
		if !authenticated {
			metrics[i].IPv4 = ""
			metrics[i].IPv6 = ""
		}
	}
	
	writeJSON(w, http.StatusOK, metrics)
}

func handleIngestMetric(store *Store, broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var payload metricPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.ID) == "" || strings.TrimSpace(payload.Name) == "" {
		http.Error(w, "id and name are required", http.StatusBadRequest)
		return
	}

	// Format uptime for display
	timeDisplay := formatUptime(payload.Uptime)

	// Get existing system to preserve order
	existing, _ := store.Get(strings.TrimSpace(payload.ID))
	order := 0
	var updatedAt time.Time
	if existing != nil {
		order = existing.Order
		updatedAt = existing.UpdatedAt
	} else {
		// New system: set order to be at the end (max order + 1)
		// Get all systems to find the maximum order value
		allSystems, err := store.List()
		if err == nil && len(allSystems) > 0 {
			maxOrder := 0
			for _, sys := range allSystems {
				if sys.Order > maxOrder {
					maxOrder = sys.Order
				}
			}
			order = maxOrder + 1
		} else {
			// No existing systems, start with order 0
			order = 0
		}
	}
	
	// Determine if this is from admin page (manual add/edit) or from client
	// Admin page adds/edits systems with no uptime and no real data
	// Client sends data with uptime > 0 or has real metrics
	isFromClient := payload.Uptime > 0 || payload.IPv4 != "" || payload.OS != ""
	
	if isFromClient {
		// Client is sending data, system is online - update timestamp
		updatedAt = time.Now().UTC()
	} else if existing == nil {
		// New system from admin page - keep UpdatedAt as zero to mark as offline
		updatedAt = time.Time{}
	}
	// If existing system and not from client, preserve existing UpdatedAt
	
	// Initialize metric with payload values
	var metric SystemMetric
	
	if !isFromClient && existing != nil {
		// Admin page is updating existing system - preserve ALL existing data, only update name
		metric = *existing
		metric.Name = strings.TrimSpace(payload.Name)
		// Keep existing order and updatedAt
	} else {
		// Either from client, or new system from admin page
		// Preserve existing values for new fields if updating existing system
		var cpuModel, memoryInfo, swapInfo, diskInfo string
		var tcpingData map[string]TCPingTargetData
		if existing != nil {
			cpuModel = existing.CPUModel
			memoryInfo = existing.MemoryInfo
			swapInfo = existing.SwapInfo
			diskInfo = existing.DiskInfo
			// Preserve existing tcping data map
			if existing.TCPingData != nil {
				tcpingData = make(map[string]TCPingTargetData)
				for k, v := range existing.TCPingData {
					tcpingData[k] = v
				}
			}
		}
		// Use payload values if provided, otherwise keep existing or use empty string
		if payload.CPUModel != "" {
			cpuModel = payload.CPUModel
		}
		if payload.MemoryInfo != "" {
			memoryInfo = payload.MemoryInfo
		}
		if payload.SwapInfo != "" {
			swapInfo = payload.SwapInfo
		}
		if payload.DiskInfo != "" {
			diskInfo = payload.DiskInfo
		}

		metric = SystemMetric{
			ID:                 strings.TrimSpace(payload.ID),
			Name:               strings.TrimSpace(payload.Name),
			IPv4:               payload.IPv4,
			IPv6:               payload.IPv6,
			Time:               timeDisplay,
			Location:           payload.Location,
			VirtualizationType: payload.VirtualizationType,
			OS:                 payload.OS,
			OSIcon:             payload.OSIcon,
			CPU:                payload.CPU,
			CPUModel:           cpuModel,
			Memory:             payload.Memory,
			MemoryInfo:         memoryInfo,
			SwapInfo:           swapInfo,
			Disk:               payload.Disk,
			DiskInfo:           diskInfo,
			NetInMBps:          payload.NetInMBps,
			NetOutMBps:         payload.NetOutMBps,
			TotalNetInBytes:    payload.TotalNetInBytes,
			TotalNetOutBytes:   payload.TotalNetOutBytes,
			AgentVersion:       payload.AgentVersion,
			Order:              order,
			Alert:              payload.Alert,
			UpdatedAt:          updatedAt,
			TCPingData:         tcpingData,
		}
	}

	if err := store.Upsert(metric); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	
	// Broadcast update to all connected clients
	broker.Broadcast(`{"type":"metric_updated","id":"` + metric.ID + `"}`)
	
	writeJSON(w, http.StatusAccepted, metric)
}

func handleDeleteMetric(store *Store, broker *SSEBroker, registry *ClientRegistry, w http.ResponseWriter, r *http.Request, id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "system id is required", http.StatusBadRequest)
		return
	}

	// Check if system exists
	existing, err := store.Get(id)
	if err != nil || existing == nil {
		http.Error(w, "system not found", http.StatusNotFound)
		return
	}

	if err := store.Delete(id); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Remove client from registry to stop polling
	registry.Remove(id)
	
	// Broadcast deletion to all connected clients
	broker.Broadcast(`{"type":"metric_deleted","id":"` + id + `"}`)
	
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted", "id": id})
}

func handleClientRegister(store *Store, registry *ClientRegistry, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	
	var payload struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Port string `json:"port"`
		IP   string `json:"ip,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	if strings.TrimSpace(payload.ID) == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	
	// Verify that the server ID exists in the database
	existing, err := store.Get(payload.ID)
	if err != nil || existing == nil {
		http.Error(w, fmt.Sprintf("server id '%s' not found in database. Please add the server in admin page first", payload.ID), http.StatusNotFound)
		return
	}
	
	
	// Get client IP from request - prioritize request IP over payload IP
	// This ensures we use the actual connection IP, not what client reports
	ip := ""
	
	// First try to get from HTTP headers (for proxies/load balancers)
	ip = r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	
	// If not in headers, get from connection
	if ip == "" {
		// Parse RemoteAddr (format: "IP:PORT")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil && host != "" {
			ip = host
		} else {
			// Fallback: try to parse directly
			parts := strings.Split(r.RemoteAddr, ":")
			if len(parts) > 0 {
				ip = parts[0]
			}
		}
	}
	
	// Clean up IP (take first if comma-separated, remove whitespace)
	if idx := strings.Index(ip, ","); idx > 0 {
		ip = strings.TrimSpace(ip[:idx])
	}
	ip = strings.TrimSpace(ip)
	
	// If still empty or localhost, try payload IP as fallback
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		if payload.IP != "" && payload.IP != "127.0.0.1" && payload.IP != "localhost" {
			ip = payload.IP
		} else {
			// Last resort: try to get server's own IP
			serverIP := getServerIP()
			if serverIP != "" {
				ip = serverIP
			}
		}
	}

	registry.Register(payload.ID, payload.Name, payload.Port, ip)
	writeJSON(w, http.StatusOK, map[string]string{"message": "registered", "id": payload.ID})
}

func startClientPolling(store *Store, broker *SSEBroker, registry *ClientRegistry, ipCache *IPCountryCache) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	
	// Track consecutive failures for each client
	failureCount := make(map[string]int)
	const maxFailures = 15 // Remove from registry after 15 consecutive failures (45 seconds) - very tolerant for stable connection
	
	for {
		<-ticker.C
		
		clients := registry.GetAll()
		if len(clients) == 0 {
			continue
		}
		
		// Use WaitGroup with timeout pattern
		var wg sync.WaitGroup
		// Use mutex-protected slice to collect results safely
		var mu sync.Mutex
		var updatedClientIDs []string
		
		for _, client := range clients {
			// First check if client is actually connected/available
			if !isClientConnected(client) {
				failureCount[client.ID]++
				
				// Mark system as offline in database immediately on first failure
				if failureCount[client.ID] == 1 {
					go markSystemAsOffline(store, broker, client.ID)
				}
				
				// Remove from registry after max failures to stop polling
				if failureCount[client.ID] >= maxFailures {
					registry.Remove(client.ID)
					delete(failureCount, client.ID)
				}
				continue
			}
			
			// Client is connected, reset failure count and proceed with polling
			if failureCount[client.ID] > 0 {
				delete(failureCount, client.ID)
			}
			
			// Client is connected, proceed with polling
			wg.Add(1)
			go func(c *ClientInfo) {
				defer wg.Done()
				updated := pollClient(store, c, ipCache)
				if updated {
					mu.Lock()
					updatedClientIDs = append(updatedClientIDs, c.ID)
					mu.Unlock()
				}
			}(client)
		}
		
		// Wait with timeout - don't wait for slow clients
		// Use a channel to detect when WaitGroup is done
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		
		// Maximum wait time is 2.5 seconds to ensure we can broadcast before next tick
		select {
		case <-done:
			// All clients responded in time
		case <-time.After(2500 * time.Millisecond):
			// Timeout - proceed with whatever updates we have
			// Slow clients will complete in background and update DB
			// Their data will be included in next broadcast
		}
		
		// Broadcast all updates at once if there are any
		mu.Lock()
		count := len(updatedClientIDs)
		mu.Unlock()
		
		if count > 0 {
			// Broadcast a single update event that triggers frontend to reload all data
			broker.Broadcast(`{"type":"metric_updated","count":` + fmt.Sprintf("%d", count) + `}`)
		}
	}
}

// markSystemAsOffline marks a system as offline in the database
func markSystemAsOffline(store *Store, broker *SSEBroker, systemID string) {
	existing, err := store.Get(systemID)
	if err != nil || existing == nil {
		return // System doesn't exist, nothing to update
	}
	
	// Only update if system is currently marked as online
	if !existing.Alert {
		// Mark as offline and set UpdatedAt to 11 seconds ago
		// This ensures handleListMetrics will correctly detect it as offline
		existing.Alert = true // Mark as offline/paused
		existing.UpdatedAt = time.Now().UTC().Add(-11 * time.Second) // Set to past to trigger offline detection
		
		if err := store.Upsert(*existing); err != nil {
			return
		}
		
		// Broadcast update to frontend immediately
		broker.Broadcast(`{"type":"metric_updated","id":"` + systemID + `"}`)
	}
}

// isClientConnected checks if a client is actually reachable and responding
func isClientConnected(client *ClientInfo) bool {
	// Use shared HTTP client for connection reuse
	httpClient := getSharedHTTPClient()
	
	// Create a request with reasonable timeout for health check (longer for stability)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	
	// Try to reach the health endpoint first (faster than /metrics)
	healthURL := client.URL + "/health"
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return false
	}
	
	// Set proper headers for connection reuse
		req.Header.Set("User-Agent", "PulseMonitor/1.0")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "*/*")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		// Health check failed, client is not connected
		return false
	}
	defer resp.Body.Close()
	
	// Client responded, check if it's a valid response
	return resp.StatusCode == http.StatusOK
}

func pollClient(store *Store, client *ClientInfo, ipCache *IPCountryCache) bool {
	// Use shared HTTP client for connection reuse and efficiency
	httpClient := getSharedHTTPClient()
	
	// Create request with context for timeout control
	// 8 second timeout - longer timeout for better reliability, prevents slow clients from blocking
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	
	// Request metrics from client
	url := client.URL + "/metrics"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	
	// Set proper headers for connection reuse and efficiency
		req.Header.Set("User-Agent", "PulseMonitor/1.0")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // Enable compression
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return false
	}
	
	var payload metricPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}
	
	// Get location from IPv4 if not provided
	if payload.Location == "" && payload.IPv4 != "" {
		// Check cache first
		if country, found := ipCache.Get(payload.IPv4); found {
			payload.Location = country
		} else {
			// Query and cache
			country := getCountryFromIP(payload.IPv4)
			if country != "" {
				ipCache.Set(payload.IPv4, country)
				payload.Location = country
			}
		}
	} else {
		// Ensure location is only country
		payload.Location = extractCountry(payload.Location)
	}
	
	// Format uptime for display
	timeDisplay := formatUptime(payload.Uptime)
	
	// Get existing system to preserve order and name from database
	existing, _ := store.Get(client.ID)
	order := 0
	name := client.Name // Default to client name if not in database
	var tcpingData map[string]TCPingTargetData
	if existing != nil {
		order = existing.Order
		// Preserve name from database (don't override with client name)
		name = existing.Name
		// Preserve existing tcping data map
		if existing.TCPingData != nil {
			tcpingData = make(map[string]TCPingTargetData)
			for k, v := range existing.TCPingData {
				tcpingData[k] = v
			}
		}
	}
	
	// Check if system was previously offline and is now back online
	wasOffline := false
	if existing != nil && existing.Alert {
		wasOffline = true
	}
	
	// Client is sending data, so system is definitely online
	// Set Alert to false (online) and update timestamp
	metric := SystemMetric{
		ID:                 client.ID,
		Name:               name, // Use name from database, not from client registration
		IPv4:               payload.IPv4,
		IPv6:               payload.IPv6,
		Time:               timeDisplay,
		Location:           payload.Location,
		VirtualizationType: payload.VirtualizationType,
		OS:                 payload.OS,
		OSIcon:             payload.OSIcon,
		CPU:          payload.CPU,
		CPUModel:     payload.CPUModel,
		Memory:       payload.Memory,
		MemoryInfo:   payload.MemoryInfo,
		SwapInfo:     payload.SwapInfo,
		Disk:            payload.Disk,
		DiskInfo:        payload.DiskInfo,
		NetInMBps:       payload.NetInMBps,
		NetOutMBps:      payload.NetOutMBps,
		TotalNetInBytes: payload.TotalNetInBytes,
		TotalNetOutBytes: payload.TotalNetOutBytes,
		AgentVersion:    payload.AgentVersion,
		Order:           order,
		Alert:           false, // Client is sending data, so system is online
		UpdatedAt:    time.Now().UTC(),
		TCPingData:   tcpingData,
	}
	
	// If system was offline and is now online, log the reconnection
	_ = wasOffline // Can be used for notifications in the future
	
	if err := store.Upsert(metric); err != nil {
		return false
	}
	
	
	// Return true to indicate this client was successfully updated
	return true
}

// Get country from IP address using free IP geolocation API
func getCountryFromIP(ip string) string {
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		// Skip private/local IPs
		return ""
	}
	
	// Use ip-api.com free service (no API key required, 45 requests/minute limit)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode", ip)
	
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	
	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}
	
	if result.Status == "success" && result.Country != "" {
		return result.Country
	}
	
	return ""
}

// Extract country from location string
func extractCountry(location string) string {
	if location == "" {
		return ""
	}
	
	// If location contains comma, take the last part (usually country)
	parts := strings.Split(location, ",")
	if len(parts) > 0 {
		country := strings.TrimSpace(parts[len(parts)-1])
		// Remove any extra details after country
		countryParts := strings.Fields(country)
		if len(countryParts) > 0 {
			return countryParts[0]
		}
		return country
	}
	
	return strings.TrimSpace(location)
}

func handleUpdateOrder(store *Store, broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	
	var payload struct {
		Order []string `json:"order"` // Array of system IDs in desired order
	}
	
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	if len(payload.Order) == 0 {
		http.Error(w, "order array is required", http.StatusBadRequest)
		return
	}
	
	// Update order for each system
	for i, id := range payload.Order {
		system, err := store.Get(id)
		if err != nil || system == nil {
			continue
		}
		
		system.Order = i
		if err := store.Upsert(*system); err != nil {
			continue
		}
	}
	
	
	// Broadcast order change to all connected clients
	broker.Broadcast(`{"type":"order_updated","count":` + fmt.Sprintf("%d", len(payload.Order)) + `}`)
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "order updated",
		"count":   len(payload.Order),
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
	}
}

func portFromEnv() string {
	if val := strings.TrimSpace(os.Getenv("PORT")); val != "" {
		return val
	}
	return "8080"
}

// formatUptime formats uptime in seconds to human-readable string
// < 1 day: shows hours (e.g., "5h", "23h")
// >= 1 day: shows days (e.g., "2d", "15d")
func formatUptime(seconds int64) string {
	if seconds < 0 {
		return "0h"
	}

	hours := seconds / 3600
	days := hours / 24

	// If less than 1 day, show hours
	if days < 1 {
		return fmt.Sprintf("%dh", hours)
	}

	// Otherwise show days
	return fmt.Sprintf("%dd", days)
}

// TCPingResultPayload represents the payload from client
type TCPingResultPayload struct {
	ClientID string  `json:"client_id"`
	Target   string  `json:"target"`   // Target address (e.g., "8.8.8.8:53")
	Latency  float64 `json:"latency"`
	Success  bool    `json:"success"`
	Error    string  `json:"error,omitempty"`
}

// TCPingResponse represents the response from client
type TCPingResponse struct {
	Latency float64 `json:"latency"`
	Success bool    `json:"success"`
	Error   string  `json:"error,omitempty"`
}

// Handle tcping result from client
func handleTCPingResult(store *Store, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var payload TCPingResultPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	if payload.ClientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	
	// Save result regardless of success/failure (nil latency for failures)
	var latency *float64
	if payload.Success {
		latency = &payload.Latency
	} else {
		latency = nil // nil indicates timeout/failure
	}
	
	result := TCPingResult{
		ClientID:  payload.ClientID,
		Target:    payload.Target,
		Latency:   latency,
		Timestamp: time.Now().UTC(),
	}
	
	if err := store.SaveTCPingResult(result); err != nil {
		http.Error(w, "failed to save result", http.StatusInternalServerError)
		return
	}
	
	
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Handle get tcping config
func handleGetTCPingConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	config, err := store.GetTCPingConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get config: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, config)
}

// Handle get tcping history
func handleGetTCPingHistory(store *Store, w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	target := r.URL.Query().Get("target")
	
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	
	var results []TCPingResult
	var err error
	if target != "" {
		results, err = store.GetTCPingResults(clientID, target)
	} else {
		results, err = store.GetTCPingResults(clientID)
	}
	
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get history: %v", err), http.StatusInternalServerError)
		return
	}
	
	writeJSON(w, http.StatusOK, results)
}

// Handle set tcping config
func handleSetTCPingConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var config TCPingConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	// Validate config
	if config.IntervalSecs < 1 {
		http.Error(w, "interval_secs must be at least 1", http.StatusBadRequest)
		return
	}
	// Allow empty targets list (default state)
	// Empty targets means tcping is disabled
	
	// Validate target format (basic check: should contain ":")
	for _, target := range config.Targets {
		if target.Name == "" {
			http.Error(w, "target name is required", http.StatusBadRequest)
			return
		}
		if target.Address == "" {
			http.Error(w, fmt.Sprintf("target address is required for target: %s", target.Name), http.StatusBadRequest)
			return
		}
		if !strings.Contains(target.Address, ":") {
			http.Error(w, fmt.Sprintf("invalid target format: %s (expected format: host:port)", target.Address), http.StatusBadRequest)
			return
		}
	}
	
	// Get old config to compare targets
	oldConfig, err := store.GetTCPingConfig()
	if err == nil && oldConfig != nil {
		// Find targets that were removed
		oldTargets := make(map[string]bool)
		for _, t := range oldConfig.Targets {
			oldTargets[t.Address] = true
		}
		
		newTargets := make(map[string]bool)
		for _, t := range config.Targets {
			newTargets[t.Address] = true
		}
		
		// Delete data for removed targets
		for oldTarget := range oldTargets {
			if !newTargets[oldTarget] {
				if err := store.DeleteTCPingResultsByTarget(oldTarget); err != nil {
				}
			}
		}
	}
	
	if err := store.SaveTCPingConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("failed to save config: %v", err), http.StatusInternalServerError)
		return
	}
	
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Start tcping polling with configurable interval and targets
func startTCPingPolling(registry *ClientRegistry, store *Store) {
	// Get initial config
	config, err := store.GetTCPingConfig()
	if err != nil {
		config = &TCPingConfig{
			Targets:      []TCPingTargetEntry{},
			IntervalSecs: 60,
		}
	}
	
	// Create ticker with initial interval
	ticker := time.NewTicker(time.Duration(config.IntervalSecs) * time.Second)
	defer ticker.Stop()
	
	// Format targets for logging
	if len(config.Targets) == 0 {
		// TCPing disabled (no targets)
	} else {
		targetsStr := ""
		for i, t := range config.Targets {
			if i > 0 {
				targetsStr += ", "
			}
			targetsStr += fmt.Sprintf("%s (%s)", t.Name, t.Address)
		}
	}
	
	// Track current config to detect changes
	currentInterval := config.IntervalSecs
	currentTargets := make(map[string]TCPingTargetEntry)
	for _, target := range config.Targets {
		currentTargets[target.Address] = target
	}
	
	// Create a separate HTTP client for tcping with longer timeout
	// Client tcping operation can take up to 5 seconds, plus network overhead
	tcpingHTTPClient := &http.Client{
		Timeout: 8 * time.Second, // Longer timeout for tcping operations
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 3 * time.Second,
		},
	}
	
	for {
		<-ticker.C
		
		// Reload config on each tick to support dynamic updates
		config, err := store.GetTCPingConfig()
		if err != nil {
			continue
		}
		
		// Check if interval changed
		if config.IntervalSecs != currentInterval {
			newInterval := time.Duration(config.IntervalSecs) * time.Second
			ticker.Reset(newInterval)
			currentInterval = config.IntervalSecs
		}
		
		// Check if targets changed
		newTargets := make(map[string]TCPingTargetEntry)
		for _, target := range config.Targets {
			newTargets[target.Address] = target
		}
		
		// Compare targets to detect changes
		targetsChanged := false
		if len(newTargets) != len(currentTargets) {
			targetsChanged = true
		} else {
			for addr, target := range newTargets {
				oldTarget, exists := currentTargets[addr]
				if !exists || oldTarget.Name != target.Name {
					targetsChanged = true
					break
				}
			}
		}
		
		if targetsChanged {
			currentTargets = newTargets
			targetsStr := ""
			for i, t := range config.Targets {
				if i > 0 {
					targetsStr += ", "
				}
				targetsStr += fmt.Sprintf("%s (%s)", t.Name, t.Address)
			}
		}
		
		// Skip if no targets configured
		if len(config.Targets) == 0 {
			continue
		}
		
		clients := registry.GetAll()
		if len(clients) == 0 {
			continue
		}
		
		for _, client := range clients {
			// Only send tcping to connected clients
			if !isClientConnected(client) {
				continue
			}
			
			// Send tcping request for each target
			for _, target := range config.Targets {
				go func(c *ClientInfo, tgt TCPingTargetEntry) {
					url := c.URL + "/tcping"
					// Send target address in request body
					tcpingRequest := map[string]string{
						"target": tgt.Address,
					}
					requestData, _ := json.Marshal(tcpingRequest)
					req, err := http.NewRequest("POST", url, strings.NewReader(string(requestData)))
					if err != nil {
						return
					}
					req.Header.Set("Content-Type", "application/json")
					
					resp, err := tcpingHTTPClient.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()
					
					if resp.StatusCode != http.StatusOK {
						return
					}
					
					var tcpingResp TCPingResponse
					if err := json.NewDecoder(resp.Body).Decode(&tcpingResp); err != nil {
						return
					}
					
					// Save result directly to database and update SystemMetric (save even if failed)
					var latency *float64
					if tcpingResp.Success {
						latency = &tcpingResp.Latency
					} else {
						latency = nil // nil indicates timeout/failure
					}
					
					result := TCPingResult{
						ClientID:  c.ID,
						Target:    tgt.Address,
						Latency:   latency,
						Timestamp: time.Now().UTC(),
					}
					
					if err := store.SaveTCPingResult(result); err != nil {
						// TCPing result save failed
					} else {
					}
					
					// Update SystemMetric with latest tcping data for this target (only if successful)
					if tcpingResp.Success {
						existing, err := store.Get(c.ID)
						if err == nil && existing != nil {
							// Initialize TCPingData map if nil
							if existing.TCPingData == nil {
								existing.TCPingData = make(map[string]TCPingTargetData)
							}
							// Update data for this target (use address as key)
							existing.TCPingData[tgt.Address] = TCPingTargetData{
								Latency:   tcpingResp.Latency,
								Timestamp: time.Now().UTC(),
							}
							if err := store.Upsert(*existing); err != nil {
								// Update failed silently
							}
						}
					}
				}(client, target)
			}
		}
	}
}

// Start cleanup old tcping data every hour
func startTCPingCleanup(store *Store) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	
	for {
		<-ticker.C
		_ = store.CleanupOldTCPingResults()
	}
}

// Auth token storage (in-memory, simple implementation)
var authTokens = make(map[string]time.Time)
var authTokensMu sync.Mutex

// Cleanup expired tokens every 5 minutes
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			authTokensMu.Lock()
			now := time.Now()
			for token, expiry := range authTokens {
				if now.After(expiry) {
					delete(authTokens, token)
				}
			}
			authTokensMu.Unlock()
		}
	}()
}

// handleAuthStatus checks if password is set
func handleAuthStatus(store *Store, w http.ResponseWriter, r *http.Request) {
	set, err := store.CheckPasswordSet()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"set": set})
}

// handleAuthSetup sets the admin password (first time only)
func handleAuthSetup(store *Store, w http.ResponseWriter, r *http.Request) {
	// Check if password is already set
	set, err := store.CheckPasswordSet()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if set {
		http.Error(w, "password already set", http.StatusBadRequest)
		return
	}

	var payload struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(payload.Password) < 6 {
		http.Error(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	if err := store.SetPassword(payload.Password); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleAuthLogin authenticates and returns a token
func handleAuthLogin(store *Store, w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	valid, err := store.VerifyPassword(payload.Password)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	// Generate token
	token, err := GenerateAuthToken()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Store token with 24 hour expiry
	authTokensMu.Lock()
	authTokens[token] = time.Now().Add(24 * time.Hour)
	authTokensMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"token":   token,
	})
}

// handleAuthVerify verifies an auth token
func handleAuthVerify(store *Store, w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	authTokensMu.Lock()
	expiry, exists := authTokens[payload.Token]
	authTokensMu.Unlock()

	if !exists || time.Now().After(expiry) {
		writeJSON(w, http.StatusOK, map[string]bool{"valid": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

// handleAuthChangePassword changes the admin password (requires authentication)
func handleAuthChangePassword(store *Store, w http.ResponseWriter, r *http.Request) {
	// Require authentication
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var payload struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify current password
	valid, err := store.VerifyPassword(payload.CurrentPassword)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !valid {
		http.Error(w, "invalid current password", http.StatusUnauthorized)
		return
	}

	// Validate new password
	if len(payload.NewPassword) < 6 {
		http.Error(w, "new password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	// Set new password
	if err := store.SetPassword(payload.NewPassword); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// isAuthenticated checks if request is authenticated
func isAuthenticated(r *http.Request) bool {
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			authTokensMu.Lock()
			expiry, exists := authTokens[token]
			authTokensMu.Unlock()
			if exists && time.Now().Before(expiry) {
				return true
			}
		}
	}

	// Check token in query parameter (for backward compatibility)
	token := r.URL.Query().Get("token")
	if token != "" {
		authTokensMu.Lock()
		expiry, exists := authTokens[token]
		authTokensMu.Unlock()
		if exists && time.Now().Before(expiry) {
			return true
		}
	}

	return false
}

