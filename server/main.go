package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed all:web/dist
var webFiles embed.FS

// Check if running in standalone mode (with embedded files) or Docker mode (with Nginx)
func hasEmbeddedFiles() bool {
	// Try to access the embedded FS
	distFS, err := fs.Sub(webFiles, "web/dist")
	if err != nil {
		return false
	}
	// Check if index.html exists (real frontend files)
	if _, err := distFS.Open("index.html"); err != nil {
		return false
	}
	// Check if _astro directory exists (contains CSS/JS)
	if entries, err := fs.ReadDir(distFS, "_astro"); err != nil || len(entries) == 0 {
		return false
	}
	return true
}

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
	Tags               []string                      `json:"tags,omitempty"`        // User-defined tags for the service
	Secret             string                         `json:"secret,omitempty"`      // Secret for client authentication
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
	AgentVersion       string   `json:"agent_version"`
	Alert              bool     `json:"alert"`
	Tags               []string `json:"tags,omitempty"` // User-defined tags
	Secret             string   `json:"secret,omitempty"` // Secret for client authentication (sent by client during registration)
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
	
	ch := make(chan string, 30) // Increased from 10 to 30: allows 30 updates buffering (10 seconds worth at 3s interval)
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

// broadcastJSON safely broadcasts a JSON event by marshaling the data structure
// This prevents JSON injection vulnerabilities from user-controlled input
func broadcastJSON(broker *SSEBroker, eventType string, data map[string]interface{}) {
	if broker == nil {
		return
	}
	
	// Build event data with type
	eventData := map[string]interface{}{
		"type": eventType,
	}
	// Merge additional data
	for k, v := range data {
		eventData[k] = v
	}
	
	// Marshal to JSON safely
	jsonData, err := json.Marshal(eventData)
	if err != nil {
		// If marshaling fails, log error but don't crash
		log.Printf("⚠️  Failed to marshal broadcast event: %v", err)
		return
	}
	
	broker.Broadcast(string(jsonData))
}

// Client registry for tracking agent clients
type ClientInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Port string `json:"port"`
	IP   string `json:"ip,omitempty"`   // Client IPv4 address (primary)
	IPv6 string `json:"ipv6,omitempty"` // Client IPv6 address (fallback)
	URL  string `json:"url"`            // Full URL to client (IPv4)
	URL6 string `json:"url6,omitempty"` // Full URL to client (IPv6, fallback)
	// WorkingURL caches the last successful URL (IPv4 or IPv6) to avoid repeated failures
	// This is set when a connection succeeds and cleared when both URLs fail
	WorkingURL string `json:"working_url,omitempty"`
	// Secret is cached from database to avoid repeated lookups during polling
	// Updated when client registers or when system data is modified
	Secret string `json:"-"` // Not exposed in JSON (security)
}

type ClientRegistry struct {
	clients map[string]*ClientInfo // key: client ID
	mu      sync.RWMutex
}

// IP to country cache with expiration
// Special value "FAILED" is used to cache failed lookups to avoid repeated API calls
type IPCountryCacheEntry struct {
	Country   string
	ExpiresAt time.Time
}

type IPCountryCache struct {
	cache map[string]IPCountryCacheEntry // key: IP, value: cache entry with expiration
	mu    sync.RWMutex
}

func NewIPCountryCache() *IPCountryCache {
	return &IPCountryCache{
		cache: make(map[string]IPCountryCacheEntry),
	}
}

func (c *IPCountryCache) Get(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, exists := c.cache[ip]
	if !exists {
		return "", false
	}
	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return "", false // Expired, act as cache miss
	}
	if entry.Country == "FAILED" {
		// Return empty string for failed lookups, but indicate it was cached
		return "", true
	}
	return entry.Country, true
}

func (c *IPCountryCache) Set(ip, country string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Cache for 24 hours
	c.cache[ip] = IPCountryCacheEntry{
		Country:   country,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

// SetFailed marks an IP lookup as failed to avoid repeated API calls
func (c *IPCountryCache) SetFailed(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Cache failed lookups for 1 hour (shorter than successful lookups)
	c.cache[ip] = IPCountryCacheEntry{
		Country:   "FAILED",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

// CleanExpired removes expired entries from cache
func (c *IPCountryCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	removed := 0
	for ip, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, ip)
			removed++
		}
	}
	return removed
}

func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{
		clients: make(map[string]*ClientInfo),
	}
}

// buildURL constructs a proper HTTP URL for an IP address
// IPv6 addresses must be enclosed in square brackets
func buildURL(ip, port string) string {
	if ip == "" {
		return ""
	}
	// Use net.ParseIP to accurately detect IPv6 addresses
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil && parsedIP.To4() == nil {
		// IPv6 address - wrap in square brackets
		return fmt.Sprintf("http://[%s]:%s", ip, port)
	}
	// IPv4 address - use as is
	return fmt.Sprintf("http://%s:%s", ip, port)
}

func (r *ClientRegistry) Register(id, name, port, ip, ipv6 string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// IMPORTANT: One client per ID - this ensures a client can only connect to one service
	// If a client with this ID already exists, we replace it with the new registration
	// This is the correct behavior: the latest registration wins (handles client restarts, IP changes, etc.)
	// Note: We don't check IP/Port differences because clients may change IP addresses (e.g., dynamic IP, VPN, etc.)
	// CRITICAL: Strict ID-based isolation - each ID is managed independently
	// Registering ID=3 only affects ID=3, never touches ID=4, even if they share the same IP
	// 
	// However, if another client (different ID) is using the same IP/port combination,
	// and the new registration is from the same physical machine (same IP/port),
	// we should remove the old registration to prevent confusion.
	// This handles the case where a user switches from ID=3 to ID=4 on the same machine.
	// We only do this if BOTH IP and port match exactly, to avoid false positives.
	for existingID, existingClient := range r.clients {
		if existingID != id && existingClient != nil {
			// Check if existing client uses the exact same IP/port combination
			// Only remove if both IPv4/IPv6 AND port match exactly
			exactMatch := false
			if port == existingClient.Port {
				// Port matches, check if IPs match exactly
				if (ip != "" && existingClient.IP != "" && ip == existingClient.IP) ||
					(ipv6 != "" && existingClient.IPv6 != "" && ipv6 == existingClient.IPv6) {
					// Exact match: same IP and port - this is likely the same physical machine
					// Remove the old registration to prevent confusion
					exactMatch = true
				}
			}
			
			if exactMatch {
				// Same physical machine registering with a different ID
				// Remove the old registration to prevent duplicate polling/TCPing
				log.Printf("⚠️  Removing client %s (ID=%s) because new client %s is registering from the same IP/port", existingClient.Name, existingID, id)
				delete(r.clients, existingID)
			}
		}
	}
	
	// Construct client URLs - prefer IPv4, fallback to IPv6
	var url, url6 string
	
	// Build IPv4 URL if available (and not localhost/loopback)
	if ip != "" && ip != "127.0.0.1" && ip != "localhost" && ip != "::1" {
		url = buildURL(ip, port)
	}
	
	// Build IPv6 URL if available (and not loopback)
	if ipv6 != "" && ipv6 != "::1" && ipv6 != "localhost" {
		url6 = buildURL(ipv6, port)
	}
	
	// Register or update the client (one client per ID)
	// Note: It's OK if both URLs are empty - client might be behind NAT
	// The client will still be tracked, but polling will fail (which is expected)
	
	// Preserve WorkingURL if client already exists
	// Always preserve WorkingURL unless URLs actually changed, as it represents a working connection
	existingClient, exists := r.clients[id]
	workingURL := ""
	if exists && existingClient != nil {
		// CRITICAL: Always preserve WorkingURL if it's still valid
		// WorkingURL represents a known working connection, so we should preserve it whenever possible
		if existingClient.WorkingURL != "" {
			// CRITICAL: Always preserve WorkingURL if URLs haven't changed
			// This is the most important case - if URLs are unchanged, preserve WorkingURL
			// This ensures that once IPv6 works, we keep using it even after re-registration
			if existingClient.URL == url && existingClient.URL6 == url6 {
				// URLs haven't changed at all, always preserve working URL
				workingURL = existingClient.WorkingURL
			} else if existingClient.WorkingURL == url || existingClient.WorkingURL == url6 {
				// Working URL still matches one of the current URLs, preserve it
				workingURL = existingClient.WorkingURL
			} else {
				// URLs have changed, but if WorkingURL is still reachable (matches new URLs), preserve it
				// This handles cases where IPs change but the working connection is still valid
				// Double-check: maybe WorkingURL matches one of the new URLs (redundant but safe)
				if existingClient.WorkingURL == url || existingClient.WorkingURL == url6 {
					workingURL = existingClient.WorkingURL
				}
			}
		}
	}
	
	// CRITICAL: Before creating new object, double-check existingClient.WorkingURL
	// This handles the case where pollClient updated WorkingURL after we first checked
	// Since we're still holding the lock, we can safely check again
	if exists && existingClient != nil && workingURL == "" && existingClient.WorkingURL != "" {
		// WorkingURL was set by pollClient after our initial check
		// Check if it matches one of the current URLs
		if existingClient.WorkingURL == url || existingClient.WorkingURL == url6 {
			workingURL = existingClient.WorkingURL
		} else if existingClient.URL == url && existingClient.URL6 == url6 {
			// URLs haven't changed, preserve WorkingURL even if it doesn't match current URLs
			// This is important for IPv6 connections
			workingURL = existingClient.WorkingURL
		}
	}
	
	r.clients[id] = &ClientInfo{
		ID:         id,
		Name:       name,
		Port:       port,
		IP:         ip,
		IPv6:       ipv6,
		URL:        url,
		URL6:       url6,
		WorkingURL: workingURL,
	}
	
	// Log registration details
	if url == "" && url6 == "" {
		log.Printf("⚠️  Client %s registered but no valid URL (IPv4=%s, IPv6=%s) - client may be behind NAT", id, ip, ipv6)
	}
}

// getServerIP gets the server's own IP address (non-loopback)
func getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	// Safe type assertion to prevent panic
	localAddr := conn.LocalAddr()
	udpAddr, ok := localAddr.(*net.UDPAddr)
	if !ok {
		return ""
	}
	return udpAddr.IP.String()
}

func (r *ClientRegistry) Get(id string) *ClientInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.clients[id]
}

// UpdateWorkingURL updates the WorkingURL for a client atomically
// This ensures that WorkingURL updates from pollClient are preserved even during re-registration
func (r *ClientRegistry) UpdateWorkingURL(id, workingURL string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client, exists := r.clients[id]; exists && client != nil {
		if client.WorkingURL != workingURL {
			client.WorkingURL = workingURL
		}
	}
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
		// Create a shared HTTP client with optimized connection pooling for cross-continent networks
		// Configure DialContext to support both IPv4 and IPv6
		dialer := &net.Dialer{
			Timeout:   10 * time.Second, // Increased from 5s to 10s for slow connections
			KeepAlive: 120 * time.Second, // Longer keep-alive for connection reuse (like LAN)
		}
		
		// Create custom DialContext that supports IPv6
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Try IPv6 first if address contains IPv6 format, otherwise use default
			// Go's net.Dial will automatically try both IPv4 and IPv6
			return dialer.DialContext(ctx, network, addr)
		}
		
		sharedHTTPClient = &http.Client{
			Timeout: 20 * time.Second, // Increased from 8s to 20s for high-latency networks (e.g., Australia-Russia ~300ms RTT)
			Transport: &http.Transport{
				DialContext:           dialContext,
				MaxIdleConns:          200,               // More connections for stability
				MaxIdleConnsPerHost:   20,                // More per-host connections
				IdleConnTimeout:       180 * time.Second, // Longer idle timeout for stable connection
				TLSHandshakeTimeout:   10 * time.Second,  // Increased from 5s to 10s for slow TLS
				ResponseHeaderTimeout: 10 * time.Second,  // Wait up to 10s for response headers
				ExpectContinueTimeout: 5 * time.Second,   // Increased from 2s to 5s
				DisableCompression:    false,             // Enable compression for efficiency
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
		handleSSE(store, broker, w, r)
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
	mux.HandleFunc("/api/navbar/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleGetNavbarConfig(store, w, r)
		} else if r.Method == http.MethodPost {
			handleSetNavbarConfig(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/privacy/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleGetPrivacyConfig(store, w, r)
		} else if r.Method == http.MethodPost {
			handleSetPrivacyConfig(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/privacy/verify-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleVerifyShareToken(store, w, r)
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

	// Start tcping polling with configurable interval
	go startTCPingPolling(clientRegistry, store)
	
	// Start cleanup old tcping data every hour
	go startTCPingCleanup(store)
	
	// Start IP cache cleanup every hour
	go startIPCacheCleanup(ipCache)
	
	// Check if running in standalone mode or Docker mode
	standalone := hasEmbeddedFiles()
	
	var handler http.Handler
	
	if standalone {
		// Standalone mode: serve embedded static files
		log.Printf("🌐 Server listening on %s (standalone mode with embedded frontend)", addr)
		log.Printf("📁 Frontend files embedded from web/dist")
		log.Printf("🎉 Access the dashboard at http://localhost%s", addr)
		
		distFS, err := fs.Sub(webFiles, "web/dist")
		if err != nil {
			log.Fatalf("❌ Failed to access embedded files: %v", err)
		}
		
		// Create a handler that combines API routes and static files
		finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try API routes first
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
				mux.ServeHTTP(w, r)
				return
			}
			
			// Handle static files
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			
			// Try to open the file from embedded FS
			if f, err := distFS.Open(path); err == nil {
				// File exists, serve it
				f.Close()
				http.FileServer(http.FS(distFS)).ServeHTTP(w, r)
				return
			}
			
			// File doesn't exist - try directory index.html
			// For paths like /admin, /login, try opening admin/index.html, login/index.html
			if filepath.Ext(path) == "" {
				// Remove trailing slash if present
				cleanPath := strings.TrimSuffix(path, "/")
				indexPath := cleanPath + "/index.html"
				
				if f, err := distFS.Open(indexPath); err == nil {
					// Directory index.html exists, read and serve it
					defer f.Close()
					content, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "failed to read file", http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Write(content)
					return
				}
				
				// No directory index, serve root index.html for SPA routing
				indexFile, err := distFS.Open("index.html")
				if err != nil {
					http.Error(w, "index.html not found", http.StatusNotFound)
					return
				}
				defer indexFile.Close()
				
				content, err := io.ReadAll(indexFile)
				if err != nil {
					http.Error(w, "failed to read index.html", http.StatusInternalServerError)
					return
				}
				
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(content)
				return
			}
			
			// File with extension not found
			http.NotFound(w, r)
		})
		
		handler = corsMiddleware(cdnFriendlyMiddleware(finalHandler))
	} else {
		// Docker mode: only serve API (Nginx handles static files)
		log.Printf("🌐 Backend listening on %s (Docker mode - Nginx serves frontend)", addr)
		handler = corsMiddleware(cdnFriendlyMiddleware(mux))
	}
	
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("❌ Server stopped: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleSSE(store *Store, broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	// Check privacy mode - if enabled, require authentication or valid share token
	privacyConfig, err := store.GetPrivacyConfig()
	if err == nil && privacyConfig.Enabled {
		// Privacy mode is enabled, check authentication
		authenticated := isAuthenticated(r)
		
		// If not authenticated, check for share token or admin token in query
		if !authenticated {
			shareToken := r.URL.Query().Get("token")
			adminToken := r.URL.Query().Get("admin_token")
			
			if shareToken != "" {
				// Verify share token
				if shareToken == privacyConfig.ShareToken && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
					// Valid share token, allow access
					authenticated = true
				}
			} else if adminToken != "" {
				// Check admin token
				authTokensMu.Lock()
				expiry, exists := authTokens[adminToken]
				authTokensMu.Unlock()
				if exists && time.Now().Before(expiry) {
					authenticated = true
				}
			}
			
			if !authenticated {
				// No valid authentication or share token, deny access
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}
	
	// Set headers for SSE with CDN support
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Important for reverse proxy/CDN - tells nginx/other proxies not to buffer
	w.Header().Set("X-Accel-Buffering", "no")
	// CDN-specific headers to prevent caching and buffering
	w.Header().Set("X-Cache-Control", "no-cache")

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
	// Check privacy mode - if enabled, require authentication or valid share token
	privacyConfig, err := store.GetPrivacyConfig()
	if err == nil && privacyConfig.Enabled {
		// Privacy mode is enabled, check authentication
		authenticated := isAuthenticated(r)
		
		// If not authenticated, check for share token
		if !authenticated {
			shareToken := r.URL.Query().Get("token")
			if shareToken == "" {
				// Try to get from Authorization header as fallback
				authHeader := r.Header.Get("Authorization")
				if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
					// This is admin token, not share token, so check admin auth
					authenticated = isAuthenticated(r)
				}
			}
			
			if !authenticated && shareToken != "" {
				// Verify share token
				if shareToken == privacyConfig.ShareToken && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
					// Valid share token, allow access
					authenticated = true
				} else {
					// Invalid or expired share token, deny access
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			} else if !authenticated {
				// No valid authentication or share token, deny access
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}
	
	metrics, err := store.List()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	
	// Mark systems as offline if they haven't updated in the last 5 seconds
	// This matches the 3-second polling interval with a 2-second buffer for network delays
	// Also mark as offline if UpdatedAt is zero (newly added systems)
	now := time.Now().UTC()
	authenticated := isAuthenticated(r)
	
	for i := range metrics {
		// Check if system should be marked as offline based on update time
		// Use 5 seconds threshold (3s polling + 2s buffer) to ensure accurate status
		shouldBeOffline := metrics[i].UpdatedAt.IsZero() || now.Sub(metrics[i].UpdatedAt) > 5*time.Second
		
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
		
		// CRITICAL SECURITY: Never expose secret to unauthenticated users
		// For authenticated admin users, return secret so they can generate install commands
		if !authenticated {
			metrics[i].Secret = ""
		}
		// Authenticated admin users can see secret for generating install commands
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
	
	// SECURITY: Authentication/Authorization
	// - If from admin page (!isFromClient): require admin authentication
	// - If from client (isFromClient): verify secret matches database and system exists
	if !isFromClient {
		// Admin page operation - require authentication
		if !isAuthenticated(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		// Client operation - system must exist and verify secret if configured
		if existing == nil {
			// Client cannot create new systems - only update existing ones
			// New systems must be created by admin first
			http.Error(w, "system not found", http.StatusNotFound)
			return
		}
		
		// Verify secret if configured
		if existing.Secret != "" {
			authHeader := r.Header.Get("Authorization")
			providedSecret := ""
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				providedSecret = strings.TrimPrefix(authHeader, "Bearer ")
			} else {
				// Fallback: check query parameter
				providedSecret = r.URL.Query().Get("secret")
			}
			
			if providedSecret != existing.Secret {
				http.Error(w, "unauthorized: invalid secret", http.StatusUnauthorized)
				return
			}
		}
		// If no secret configured, allow for backward compatibility (but log warning)
		// This matches the behavior of /metrics endpoint on client
	}
	
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
		// Admin page is updating existing system - preserve ALL existing data, only update name and tags
		metric = *existing
		metric.Name = strings.TrimSpace(payload.Name)
		// Update tags if provided in payload (from admin edit form)
		// IMPORTANT: If payload.Tags is nil, preserve existing tags; if empty array, clear tags
		if payload.Tags != nil {
			metric.Tags = payload.Tags
		}
		// Keep existing order, updatedAt, and secret
	} else {
		// Either from client, or new system from admin page
		// Preserve existing values for new fields if updating existing system
		var cpuModel, memoryInfo, swapInfo, diskInfo, secret string
		var tags []string
		var tcpingData map[string]TCPingTargetData
		if existing != nil {
			cpuModel = existing.CPUModel
			memoryInfo = existing.MemoryInfo
			swapInfo = existing.SwapInfo
			diskInfo = existing.DiskInfo
			secret = existing.Secret
			tags = existing.Tags
			// Preserve existing tcping data map
			if existing.TCPingData != nil {
				tcpingData = make(map[string]TCPingTargetData)
				for k, v := range existing.TCPingData {
					tcpingData[k] = v
				}
			}
		}
		
		// Generate secret for new systems (only if not from client and doesn't exist)
		if !isFromClient && existing == nil && secret == "" {
			secret = generateSecret()
		}
		
		// Update tags if provided in payload (from admin form)
		if payload.Tags != nil {
			tags = payload.Tags
		}
		// Use payload values if provided, otherwise keep existing or use empty string
		if payload.CPUModel != "" {
			cpuModel = payload.CPUModel
		}
		if payload.MemoryInfo != "" {
			memoryInfo = payload.MemoryInfo
		}
		// Always update SwapInfo (including "0 B / 0 B" for systems without swap)
		// This allows frontend to distinguish between "no data yet" (empty) and "no swap" (0 B / 0 B)
		swapInfo = payload.SwapInfo
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
			Tags:               tags,
			Secret:             secret,
		}
	}

	if err := store.Upsert(metric); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Only broadcast immediately if this is from admin page (manual add/edit)
	// Client data updates will be broadcast by the polling loop every 3 seconds
	// This prevents duplicate broadcasts when client sends data and polling happens simultaneously
	if broker != nil && !isFromClient {
		// SECURITY: Use JSON marshaling to prevent injection from user-controlled ID
		broadcastJSON(broker, "metric_updated", map[string]interface{}{
			"id": metric.ID,
		})
	}
	
	// CRITICAL SECURITY: Never expose secret in API responses to unauthenticated users
	// For authenticated admin users, return secret so they can generate install commands
	responseMetric := metric
	authenticated := isAuthenticated(r)
	if !authenticated {
		// Unauthenticated users should never see secret
		responseMetric.Secret = ""
	}
	// Authenticated admin users can see secret for generating install commands
	
	writeJSON(w, http.StatusAccepted, responseMetric)
}

func handleDeleteMetric(store *Store, broker *SSEBroker, registry *ClientRegistry, w http.ResponseWriter, r *http.Request, id string) {
	// Require authentication for deleting systems
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	
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
	if broker != nil {
		// SECURITY: Use JSON marshaling to prevent injection from user-controlled ID
		broadcastJSON(broker, "metric_deleted", map[string]interface{}{
			"id": id,
		})
	}
	
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted", "id": id})
}

func handleClientRegister(store *Store, registry *ClientRegistry, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	
	var payload struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Port   string `json:"port"`
		IP     string `json:"ip,omitempty"`     // IPv4 address
		IPv6   string `json:"ipv6,omitempty"`   // IPv6 address
		Secret string `json:"secret,omitempty"` // Secret for authentication
	}
	
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("❌ Client registration failed: invalid JSON payload from %s", r.RemoteAddr)
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	if strings.TrimSpace(payload.ID) == "" {
		log.Printf("❌ Client registration failed: missing ID")
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	
	// Verify that the server ID exists in the database
	existing, err := store.Get(payload.ID)
	if err != nil || existing == nil {
		log.Printf("❌ Client registration failed: server ID '%s' not found in database", payload.ID)
		http.Error(w, fmt.Sprintf("server id '%s' not found in database. Please add the server in admin page first", payload.ID), http.StatusNotFound)
		return
	}
	
	// Verify secret if it's set in the database
	if existing.Secret != "" {
		if payload.Secret == "" {
			log.Printf("❌ Client registration failed: secret required for ID '%s'", payload.ID)
			http.Error(w, "secret is required for authentication", http.StatusUnauthorized)
			return
		}
		if payload.Secret != existing.Secret {
			log.Printf("❌ Client registration failed: invalid secret for ID '%s'", payload.ID)
			http.Error(w, "invalid secret", http.StatusUnauthorized)
			return
		}
	}
	
	// Check if there's already a client registered with this ID
	// If yes, verify it's the same client (same IP/port) or reject the new registration
	existingRegisteredClient := registry.Get(payload.ID)
	if existingRegisteredClient != nil {
		// There's already a client registered with this ID
		// Check if it's the same client (same IP and port) or a different one
		isSameClient := false
		
		// Normalize IPs for comparison (handle IPv4/IPv6)
		newIPv4 := payload.IP
		newIPv6 := payload.IPv6
		existingIPv4 := existingRegisteredClient.IP
		existingIPv6 := existingRegisteredClient.IPv6
		
		// Check if it's the same client by comparing IPs and port
		if payload.Port == existingRegisteredClient.Port {
			// Port matches, check IPs
			if newIPv4 != "" && existingIPv4 != "" && newIPv4 == existingIPv4 {
				isSameClient = true
			} else if newIPv6 != "" && existingIPv6 != "" && newIPv6 == existingIPv6 {
				isSameClient = true
			} else if newIPv4 != "" && existingIPv6 != "" && newIPv4 == existingIPv6 {
				// IPv4 matches existing IPv6 (same client, different IP version)
				isSameClient = true
			} else if newIPv6 != "" && existingIPv4 != "" && newIPv6 == existingIPv4 {
				// IPv6 matches existing IPv4 (same client, different IP version)
				isSameClient = true
			}
		}
		
		if !isSameClient {
			// Different client trying to register with the same ID
			log.Printf("❌ Client registration failed: ID '%s' is already registered by another client (existing: IPv4=%s, IPv6=%s, Port=%s; new: IPv4=%s, IPv6=%s, Port=%s)", 
				payload.ID, existingIPv4, existingIPv6, existingRegisteredClient.Port, newIPv4, newIPv6, payload.Port)
			http.Error(w, fmt.Sprintf("client ID '%s' is already registered by another client. Please use a different ID or disconnect the existing client first", payload.ID), http.StatusConflict)
			return
		}
		
		// Same client re-registering (e.g., after restart or IP change)
		// Silent re-registration - no log needed for normal operation
	}
	
	// IMPORTANT: For client registration, we should trust the client's reported IP addresses
	// The client knows its own public IPs better than we can detect from the connection
	// This is especially important when:
	// 1. Client is behind NAT (connection IP is not the client's public IP)
	// 2. Client connects through proxy/load balancer (RemoteAddr is proxy IP)
	// 3. Client has both IPv4 and IPv6 (we need both for proper fallback)
	
	// Use IPv4 and IPv6 directly from payload (client reports its own IPs)
	ip := payload.IP
	ipv6 := payload.IPv6
	
	// Only use connection IP as fallback if payload IP is missing or invalid
	// This handles edge cases where client doesn't report its IP
	if ip == "" || ip == "127.0.0.1" || ip == "localhost" {
		// Try to get from HTTP headers (for proxies/load balancers)
		ip = r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.Header.Get("X-Real-IP")
		}
		
		// If not in headers, get from connection
		if ip == "" {
			// Parse RemoteAddr (format: "IP:PORT" or "[IP]:PORT" for IPv6)
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil && host != "" {
				ip = host
			} else {
				// Fallback: try to parse directly
				// Handle IPv6 format [::1]:port
				if strings.HasPrefix(r.RemoteAddr, "[") {
					end := strings.Index(r.RemoteAddr, "]")
					if end > 0 {
						ip = r.RemoteAddr[1:end]
					}
				} else {
					parts := strings.Split(r.RemoteAddr, ":")
					if len(parts) > 0 {
						ip = parts[0]
					}
				}
			}
		}
		
		// Clean up IP (take first if comma-separated, remove whitespace)
		if idx := strings.Index(ip, ","); idx > 0 {
			ip = strings.TrimSpace(ip[:idx])
		}
		ip = strings.TrimSpace(ip)
		
		// If connection IP is still localhost, clear it
		if ip == "127.0.0.1" || ip == "localhost" || ip == "::1" {
			ip = ""
		}
	}
	
	// Validate IPv4: if it's not a valid IPv4, clear it
	if ip != "" {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			if parsedIP.To4() == nil {
				// It's an IPv6 address, not IPv4
				// If we don't have IPv6 yet, use it as IPv6
				if ipv6 == "" {
					ipv6 = ip
				}
				ip = "" // Clear IPv4 since this is IPv6
			}
		} else {
			// Invalid IP format, clear it
			ip = ""
		}
	}
	
	// Validate IPv6: if it's not a valid IPv6, clear it
	if ipv6 != "" {
		parsedIP := net.ParseIP(ipv6)
		if parsedIP == nil || parsedIP.To4() != nil {
			// Invalid IPv6 format or it's actually an IPv4 address, clear it
			ipv6 = ""
		}
	}

	registry.Register(payload.ID, payload.Name, payload.Port, ip, ipv6)
	
	// Update secret in registry cache (optimization: avoid DB lookups during polling)
	if client := registry.Get(payload.ID); client != nil {
		client.Secret = existing.Secret
	}
	
	// CDN-friendly: ensure registration response is not cached
	// This is critical for client registration which happens frequently
	writeJSON(w, http.StatusOK, map[string]string{"message": "registered", "id": payload.ID})
}

// Global registry reference for pollClient to update WorkingURL
var globalClientRegistry *ClientRegistry

func startClientPolling(store *Store, broker *SSEBroker, registry *ClientRegistry, ipCache *IPCountryCache) {
	// Store global reference for pollClient to use
	globalClientRegistry = registry
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	
	// Track consecutive failures for each client - MUST use mutex for concurrent access
	var failureCountMu sync.RWMutex
	failureCount := make(map[string]int)
	const maxFailures = 30 // Remove from registry after 30 consecutive failures (90 seconds) - very tolerant for cross-continent networks (e.g., Australia-Russia)
	
	// Track cleanup cycle for failureCount (cleanup every 100 ticks ≈ 5 minutes)
	cleanupCounter := 0
	const cleanupInterval = 100
	
	for {
		tickTime := <-ticker.C
		
		// Periodically cleanup failureCount for clients no longer in registry
		// This prevents memory leak when systems are deleted via admin page
		cleanupCounter++
		if cleanupCounter >= cleanupInterval {
			cleanupCounter = 0
			
			// Collect IDs that are in failureCount but not in registry
			failureCountMu.Lock()
			for id := range failureCount {
				if registry.Get(id) == nil {
					// Client no longer in registry, remove from failureCount
					delete(failureCount, id)
				}
			}
			failureCountMu.Unlock()
		}
		
		clients := registry.GetAll()
		if len(clients) == 0 {
			// Still broadcast even if no clients to maintain stable interval
			if broker != nil {
				broker.Broadcast(`{"type":"metric_updated","count":0}`)
			}
			continue
		}
		
		// Use WaitGroup with timeout pattern
		var wg sync.WaitGroup
		// Use mutex-protected slice to collect results safely
		var mu sync.Mutex
		var updatedClientIDs []string
		
		// Poll all clients in parallel - skip health check to avoid blocking
		// Health checks can be slow and cause false negatives, so we poll directly
		// This ensures we always try to get data, even if health check would fail
		for _, client := range clients {
			// Safety check: skip nil clients or clients with empty ID/URL
			if client == nil || client.ID == "" || (client.URL == "" && client.URL6 == "") {
				continue
			}
			
			// Registry already maintains consistency with database:
			// - Clients are added when they register (POST /api/clients/register)
			// - Clients are removed when systems are deleted (handleDeleteMetric)
			// - No need to verify existence on every poll (reduces DB load by 33 queries/sec)
			// Note: If a client somehow gets out of sync, it will be removed after maxFailures
			
			wg.Add(1)
			go func(c *ClientInfo) {
				defer wg.Done()
				
				// Additional safety check inside goroutine
				// Must have at least one URL (IPv4 or IPv6)
				if c == nil || c.ID == "" || (c.URL == "" && c.URL6 == "") {
					return
				}
				
				// Try to poll client directly - this is faster and more reliable than health check
				// pollClient has its own timeout (8s) which is sufficient for cross-continent networks
				updated := pollClient(store, c, ipCache)
				
				if updated {
					// Polling succeeded, reset failure count
					failureCountMu.Lock()
					if failureCount[c.ID] > 0 {
						delete(failureCount, c.ID)
					}
					failureCountMu.Unlock()
					
					mu.Lock()
					updatedClientIDs = append(updatedClientIDs, c.ID)
					mu.Unlock()
				} else {
					// Polling failed, increment failure count
					failureCountMu.Lock()
					failureCount[c.ID]++
					currentCount := failureCount[c.ID]
					failureCountMu.Unlock()
					
					// Only mark as offline after 2 consecutive failures to avoid false negatives
					// This prevents temporary network glitches from causing false offline status
					if currentCount >= 2 {
						// Mark system as offline in database after 2 consecutive failures
						if currentCount == 2 {
							go markSystemAsOffline(store, broker, c.ID)
						}
						
						// Remove from registry after max failures to stop polling
						if currentCount >= maxFailures {
							registry.Remove(c.ID)
							failureCountMu.Lock()
							delete(failureCount, c.ID)
							failureCountMu.Unlock()
						}
					}
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
		
		// Wait for polling to complete (with timeout) and then schedule broadcast at fixed time
		// This ensures broadcasts happen at consistent intervals regardless of polling completion time
		go func() {
			// Wait for polling to complete or timeout
			select {
			case <-done:
				// All clients responded in time
			case <-time.After(2800 * time.Millisecond):
				// Timeout - proceed with whatever updates we have
				// Slow clients will complete in background and update DB
				// Their data will be included in next broadcast
			}
			
			// Calculate time elapsed since tick to ensure stable 3-second intervals
			elapsed := time.Since(tickTime)
			remainingTime := 2900*time.Millisecond - elapsed
			if remainingTime > 0 {
				// Wait until 2.9 seconds have passed since tick
				time.Sleep(remainingTime)
			}
			// If already past 2.9 seconds, broadcast immediately (shouldn't happen in normal operation)
			
			// Broadcast all updates at once
			// Always broadcast every 3 seconds to ensure frontend gets updates even if no data changed
			// This maintains the 3-second update frequency for all metrics (except TCPing)
			mu.Lock()
			count := len(updatedClientIDs)
			mu.Unlock()
			
			// Always broadcast to maintain 3-second update frequency
			// Frontend will check if data actually changed and update accordingly
			if broker != nil {
				// SECURITY: Use JSON marshaling to prevent injection
				broadcastJSON(broker, "metric_updated", map[string]interface{}{
					"count": count,
				})
			}
		}()
	}
}

// markSystemAsOffline marks a system as offline in the database
// NOTE: This function does NOT broadcast updates - all updates are handled by the polling loop
// to maintain a stable 3-second update frequency. The offline status will be included in the
// next regular broadcast from startClientPolling.
func markSystemAsOffline(store *Store, broker *SSEBroker, systemID string) {
	// Safety checks: prevent nil pointer dereference
	if store == nil || broker == nil || systemID == "" {
		return
	}
	
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
		
		// DO NOT broadcast here - let the polling loop handle all broadcasts
		// This ensures stable 3-second update frequency without interruptions
		// The offline status will be included in the next regular broadcast from startClientPolling
	}
}

// isClientConnected checks if a client is actually reachable and responding
// Uses retry logic to avoid false negatives due to temporary network issues
func isClientConnected(client *ClientInfo) bool {
	// Safety check
	if client == nil {
		return false
	}
	
	// Must have at least one URL (IPv4 or IPv6)
	if client.URL == "" && client.URL6 == "" {
		return false
	}
	
	// Use shared HTTP client for connection reuse
	httpClient := getSharedHTTPClient()
	
	// Retry health check up to 2 times with shorter timeout to avoid blocking
	// This prevents false negatives from temporary network glitches
	maxRetries := 2
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Use shorter timeout for health check (5s) to avoid blocking polling
		// If health check fails, we'll retry once more
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		// Build URL list: prioritize working URL if available
		// CRITICAL: If WorkingURL is set (especially if it's IPv6), use ONLY that URL
		// This ensures that once IPv6 connection succeeds, we never try IPv4 again
		urls := []string{}
		if client.WorkingURL != "" {
			// If we have a working URL, use ONLY that URL
			// This ensures that once IPv6 works, we never try IPv4 again
			urls = append(urls, client.WorkingURL)
			// Don't add other URLs if WorkingURL is set - it represents the known working connection
		} else {
			// No working URL yet, try IPv4 first, then IPv6
			if client.URL != "" {
				urls = append(urls, client.URL)
			}
			if client.URL6 != "" {
				urls = append(urls, client.URL6)
			}
		}
		
		var resp *http.Response
		var err error
		var successfulURL string
		for _, url := range urls {
			// Try to reach the health endpoint first (faster than /metrics)
			healthURL := url + "/health"
			req, reqErr := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
			if reqErr != nil {
				continue
			}
			
			// Set proper headers for connection reuse
			req.Header.Set("User-Agent", "PulseMonitor/1.0")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Accept", "*/*")
			
			resp, err = httpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				successfulURL = url
				resp.Body.Close()
				cancel() // ✅ Cancel context immediately on success
				// Update working URL if we successfully connected
				// CRITICAL: Always update WorkingURL when we successfully connect
				// Use registry method to update atomically, so it's preserved even during re-registration
				if successfulURL != "" {
					// Update directly on the client object (pointer, so it updates the registry)
					if client.WorkingURL != successfulURL {
						client.WorkingURL = successfulURL
					}
					// CRITICAL: Also update via registry to ensure it's preserved during re-registration
					// This is a safety measure in case Register creates a new object
					if globalClientRegistry != nil {
						globalClientRegistry.UpdateWorkingURL(client.ID, successfulURL)
					}
				}
				return true // Success
			}
			if resp != nil {
				resp.Body.Close()
			}
			resp = nil
		}
		
		cancel() // ✅ Always cancel context after each attempt
		
		// If this is not the last attempt, retry
		if attempt < maxRetries-1 {
			time.Sleep(100 * time.Millisecond) // Brief delay before retry
			continue
		}
		
		// Health check failed after all retries
		// Don't clear WorkingURL here - let the polling loop handle it
		// This prevents clearing WorkingURL due to temporary health check failures
		return false
	}
	
	// This should never be reached, but required by Go compiler
	return false
}

func pollClient(store *Store, client *ClientInfo, ipCache *IPCountryCache) bool {
	// Safety checks: prevent nil pointer dereference
	if client == nil || client.ID == "" {
		return false
	}
	if store == nil || ipCache == nil {
		return false
	}
	
	// Must have at least one URL (IPv4 or IPv6)
	if client.URL == "" && client.URL6 == "" {
		return false
	}
	
	// Use shared HTTP client for connection reuse and efficiency
	httpClient := getSharedHTTPClient()
	if httpClient == nil {
		return false
	}
	
	// Create request with context for timeout control
	// Use longer timeout (15s) for cross-continent networks (e.g., China to overseas)
	// This is important for high-latency networks where RTT can be 200-400ms
	// The polling loop waits up to 2.8s, but slow clients will complete in background
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // Increased to 15s for cross-continent networks
	defer cancel()
	
	// Build URL list: prioritize working URL if available
	// CRITICAL: If WorkingURL is set (especially if it's IPv6), use ONLY that URL
	// This ensures that once IPv6 connection succeeds, we never try IPv4 again
	urls := []string{}
	if client.WorkingURL != "" {
		// If we have a working URL, use ONLY that URL
		// This ensures that once IPv6 works, we never try IPv4 again
		urls = append(urls, client.WorkingURL)
		// Don't add other URLs if WorkingURL is set - it represents the known working connection
	} else {
		// No working URL yet, try IPv4 first, then IPv6
		if client.URL != "" {
			urls = append(urls, client.URL)
		}
		if client.URL6 != "" {
			urls = append(urls, client.URL6)
		}
	}
	
	// Get secret from client registry cache (optimized: no DB lookup)
	secret := client.Secret
	
	var resp *http.Response
	var err error
	var successfulURL string
	for _, url := range urls {
		// Request metrics from client
		metricsURL := url + "/metrics"
		req, reqErr := http.NewRequestWithContext(ctx, "GET", metricsURL, nil)
		if reqErr != nil {
			// Silent failure - request creation errors are rare
			continue
		}
		
		// Set proper headers for connection reuse and efficiency
		req.Header.Set("User-Agent", "PulseMonitor/1.0")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "gzip, deflate") // Enable compression
		
		// Security: Add secret to Authorization header if configured
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		
		resp, err = httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			successfulURL = url
			break // Success, exit loop
		}
		if err != nil {
			// Only log if working URL failed (this is important to track)
			if client.WorkingURL != "" && url == client.WorkingURL {
				log.Printf("⚠️  Client %s: cached working URL (%s) failed: %v, trying alternatives...", client.ID, url, err)
			}
			// Don't log individual connection attempts - only log final failure
		} else if resp != nil {
			if resp.StatusCode != http.StatusOK {
				// Don't log individual HTTP errors - only log final failure
			}
			resp.Body.Close()
		}
		resp = nil
	}
	
	if resp == nil {
		// All URLs failed, clear working URL only if it was in the failed list
		// Don't clear if WorkingURL wasn't tried (e.g., if it was removed during registration)
		if client.WorkingURL != "" {
			// Check if WorkingURL was in the failed URLs list
			workingURLTried := false
			for _, triedURL := range urls {
				if triedURL == client.WorkingURL {
					workingURLTried = true
					break
				}
			}
			if workingURLTried {
				// Only clear if WorkingURL was actually tried and failed
				client.WorkingURL = ""
				log.Printf("⚠️  Client %s: all URLs failed (including working URL), cleared working URL", client.ID)
			}
		}
		// Only log polling failures after multiple consecutive failures to reduce log spam
		// Individual failures are handled by the failure count mechanism
		// This prevents log flooding when clients have temporary network issues
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return false
	}
	
	// Update working URL if we successfully connected
	// CRITICAL: Always update WorkingURL when we successfully connect, even if it's the same
	// This ensures WorkingURL is preserved across registrations
	// Use registry method to update atomically, so it's preserved even during re-registration
	if successfulURL != "" {
		// Update directly on the client object (pointer, so it updates the registry)
		if client.WorkingURL != successfulURL {
			client.WorkingURL = successfulURL
		}
		// CRITICAL: Also update via registry to ensure it's preserved during re-registration
		// This is a safety measure in case Register creates a new object
		if globalClientRegistry != nil {
			globalClientRegistry.UpdateWorkingURL(client.ID, successfulURL)
		}
	}
	
	var payload metricPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}
	
	// Get location from IP if not provided
	// Try IPv4 first, then IPv6 as fallback
	if payload.Location == "" {
		var country string
		var found bool
		
		// Try IPv4 first
		if payload.IPv4 != "" {
			if country, found = ipCache.Get(payload.IPv4); found {
				// Cache hit (including failed lookups)
				if country != "" {
					payload.Location = country
				}
			} else {
				// Query and cache
				country = getCountryFromIP(payload.IPv4)
				if country != "" {
					ipCache.Set(payload.IPv4, country)
					payload.Location = country
				} else {
					// Cache the failure to avoid repeated API calls
					ipCache.SetFailed(payload.IPv4)
				}
			}
		}
		
		// If IPv4 lookup failed or IPv4 is empty, try IPv6
		if payload.Location == "" && payload.IPv6 != "" {
			if country, found = ipCache.Get(payload.IPv6); found {
				// Cache hit (including failed lookups)
				if country != "" {
					payload.Location = country
				}
			} else {
				// Query and cache
				country = getCountryFromIP(payload.IPv6)
				if country != "" {
					ipCache.Set(payload.IPv6, country)
					payload.Location = country
				} else {
					// Cache the failure to avoid repeated API calls
					ipCache.SetFailed(payload.IPv6)
				}
			}
		}
	} else {
		// Ensure location is only country
		payload.Location = extractCountry(payload.Location)
	}
	
	// Format uptime for display
	timeDisplay := formatUptime(payload.Uptime)
	
	// Get existing system to preserve order, name, tags, and secret from database
	var existing *SystemMetric
	existing, _ = store.Get(client.ID)
	order := 0
	name := client.Name // Default to client name if not in database
	var tcpingData map[string]TCPingTargetData
	var tags []string
	// Update secret from database (will be synced to registry cache)
	if existing != nil {
		order = existing.Order
		// Preserve name from database (don't override with client name)
		name = existing.Name
		// CRITICAL: Preserve tags and secret from database (client should never override these)
		tags = existing.Tags
		secret = existing.Secret
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
	// CRITICAL: Always preserve Tags and Secret from database - client should never override these
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
		Tags:         tags,   // CRITICAL: Preserve tags from database
		Secret:       secret, // CRITICAL: Preserve secret from database
	}
	
	// If system was offline and is now online, log the reconnection
	_ = wasOffline // Can be used for notifications in the future
	
	if err := store.Upsert(metric); err != nil {
		return false
	}
	
	// Update secret in registry cache if it changed (optimization: keep cache in sync)
	if existing != nil && existing.Secret != "" {
		if c := globalClientRegistry.Get(client.ID); c != nil && c.Secret != existing.Secret {
			c.Secret = existing.Secret
		}
	}

	// Return true to indicate this client was successfully updated
	return true
}

// isPrivateIP checks if an IP address is a private/local address
// Compatible with Go 1.15 (net.IP.IsPrivate() was added in Go 1.17)
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	
	// Check IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// Loopback: 127.0.0.0/8
		if ip4[0] == 127 {
			return true
		}
		// Private: 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// Private: 172.16.0.0/12 (includes 172.17.0.0/16 used by Docker)
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// Private: 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// Link-local: 169.254.0.0/16
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// Multicast: 224.0.0.0/4
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		return false
	}
	
	// Check IPv6 private ranges
	// Loopback: ::1
	if ip.IsLoopback() {
		return true
	}
	// Link-local: fe80::/10
	if len(ip) >= 2 && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	// Unique local: fc00::/7
	if len(ip) > 0 && (ip[0] == 0xfc || ip[0] == 0xfd) {
		return true
	}
	// Multicast: ff00::/8
	if len(ip) > 0 && ip[0] == 0xff {
		return true
	}
	// IPv4-mapped IPv6 addresses (::ffff:0:0/96) - check if mapped IPv4 is private
	if len(ip) == 16 && ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
		// Extract IPv4 from IPv4-mapped IPv6
		ipv4 := net.IP(ip[12:16])
		return isPrivateIP(ipv4)
	}
	
	return false
}

// Get country from IP address using free IP geolocation API
// Uses multiple services with fallback for better reliability, especially for China
// Includes retry mechanism and better error handling
func getCountryFromIP(ip string) string {
	if ip == "" {
		return ""
	}
	
	// Check if it's a private/local IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}
	
	// Skip private/local IPs (IPv4 and IPv6)
	// Note: Go 1.15 doesn't have IsPrivate(), so we check manually
	if isPrivateIP(parsedIP) {
		return ""
	}
	
	// Use shared HTTP client for connection reuse
	httpClient := getSharedHTTPClient()
	if httpClient == nil {
		return ""
	}
	
	// Try multiple services with fallback for better reliability
	// Priority: ipinfo.io first (most accurate), then fallback to others
	// Some services may be blocked in China, so we try multiple options
	services := []struct {
		url    string
		parser func(*http.Response) string
	}{
		{
			// ipinfo.io (most accurate, try first)
			// Returns ISO 3166-1 alpha-2 country code (e.g., "US", "CN", "HK")
			// We'll use the country code directly for emojione-v1 flag icons
			url: fmt.Sprintf("https://ipinfo.io/%s/json", ip),
			parser: func(resp *http.Response) string {
				var result struct {
					Country string `json:"country"`
					Region  string `json:"region"`
					City    string `json:"city"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return ""
				}
				// ipinfo.io returns country code (2-letter ISO 3166-1 alpha-2)
				// Return it directly (uppercase) for emojione-v1 flag format
				if result.Country != "" {
					return strings.ToUpper(result.Country)
				}
				return ""
			},
		},
		{
			// ip-api.com (fallback, provides country code)
			url: fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode", ip),
			parser: func(resp *http.Response) string {
				var result struct {
					Status      string `json:"status"`
					Country     string `json:"country"`
					CountryCode string `json:"countryCode"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return ""
				}
				// Prefer country code for emojione-v1 flag format
				if result.Status == "success" && result.CountryCode != "" {
					return strings.ToUpper(result.CountryCode)
				}
				return ""
			},
		},
		{
			// ipapi.co (alternative service, may work better in China)
			url: fmt.Sprintf("https://ipapi.co/%s/json/", ip),
			parser: func(resp *http.Response) string {
				var result struct {
					CountryName string `json:"country_name"`
					CountryCode string `json:"country_code"`
					Country     string `json:"country"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return ""
				}
				// Prefer country code for emojione-v1 flag format
				if result.CountryCode != "" {
					return strings.ToUpper(result.CountryCode)
				}
				return ""
			},
		},
		{
			// ip-api.io (another alternative)
			url: fmt.Sprintf("https://ip-api.io/json/%s", ip),
			parser: func(resp *http.Response) string {
				var result struct {
					CountryName string `json:"country_name"`
					CountryCode string `json:"country_code"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return ""
				}
				// Prefer country code for emojione-v1 flag format
				if result.CountryCode != "" {
					return strings.ToUpper(result.CountryCode)
				}
				return ""
			},
		},
		{
			// geojs.io (another alternative, works well globally)
			url: fmt.Sprintf("https://get.geojs.io/v1/ip/country/%s", ip),
			parser: func(resp *http.Response) string {
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return ""
				}
				country := strings.TrimSpace(string(body))
				// geojs.io returns country code directly
				if len(country) == 2 {
					return strings.ToUpper(country)
				}
				return ""
			},
		},
	}
	
	// Try each service with retry mechanism
	maxRetries := 2
	for _, service := range services {
		for attempt := 0; attempt < maxRetries; attempt++ {
			// Use longer timeout for cross-continent networks (15 seconds)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			
			req, err := http.NewRequestWithContext(ctx, "GET", service.url, nil)
			if err != nil {
				cancel() // ✅ Cancel context on error
				break // Try next service
			}
			
			req.Header.Set("User-Agent", "PulseMonitor/1.0")
			req.Header.Set("Accept", "application/json")
			
			resp, err := httpClient.Do(req)
			cancel() // ✅ Always cancel context immediately after request completes
			
			if err != nil {
				// Network error - retry if not last attempt
				if attempt < maxRetries-1 {
					time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond) // Exponential backoff
					continue
				}
				break // Try next service
			}
			
			// Handle rate limiting (429 Too Many Requests)
			if resp.StatusCode == http.StatusTooManyRequests {
				resp.Body.Close()
				// Wait a bit before trying next service
				time.Sleep(1 * time.Second)
				break // Try next service
			}
			
			if resp.StatusCode == http.StatusOK {
				country := service.parser(resp)
				resp.Body.Close()
				if country != "" {
					return country
				}
				// If parsing failed but got 200, don't retry this service
				break
			} else {
				resp.Body.Close()
				// For non-200 status codes, try next service immediately
				break
			}
		}
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

// generateSecret generates a short secret for client authentication
// Returns a base64-encoded string of 12 random bytes (16 characters when encoded)
func generateSecret() string {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based secret if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())[:16]
	}
	// Use base64 URL encoding (no padding) for shorter, URL-safe secrets
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
}

func handleUpdateOrder(store *Store, broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	// Require authentication for updating order
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	
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
	if broker != nil {
		// SECURITY: Use JSON marshaling to prevent injection
		broadcastJSON(broker, "order_updated", map[string]interface{}{
			"count": len(payload.Order),
		})
	}
	
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

// cdnFriendlyMiddleware adds CDN-friendly headers to prevent caching of dynamic API responses
// This is critical when the server is behind a CDN (e.g., Cloudflare, CloudFront)
func cdnFriendlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply to API endpoints (not static files)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// For POST/PUT/DELETE requests, ensure they are never cached
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	// CDN-friendly headers: ensure responses are not cached
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("⚠️  Failed to encode JSON response: %v", err)
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
	
	// SECURITY: Verify that the client_id exists and verify secret if configured
	existing, err := store.Get(payload.ClientID)
	if err != nil || existing == nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}
	
	// If secret is configured in database, require authentication
	if existing.Secret != "" {
		authHeader := r.Header.Get("Authorization")
		providedSecret := ""
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			providedSecret = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// Fallback: check query parameter
			providedSecret = r.URL.Query().Get("secret")
		}
		
		if providedSecret != existing.Secret {
			http.Error(w, "unauthorized: invalid secret", http.StatusUnauthorized)
			return
		}
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
	// Check privacy mode - if enabled, require authentication or valid share token
	privacyConfig, err := store.GetPrivacyConfig()
	if err == nil && privacyConfig.Enabled {
		authenticated := isAuthenticated(r)
		if !authenticated {
			shareToken := r.URL.Query().Get("token")
			if shareToken == "" {
				authHeader := r.Header.Get("Authorization")
				if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
					authenticated = isAuthenticated(r)
				}
			}
			if !authenticated && shareToken != "" {
				if shareToken == privacyConfig.ShareToken && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
					authenticated = true
				}
			}
			if !authenticated {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}
	
	config, err := store.GetTCPingConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get config: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, config)
}

// Handle get tcping history
func handleGetTCPingHistory(store *Store, w http.ResponseWriter, r *http.Request) {
	// Check privacy mode - if enabled, require authentication or valid share token
	privacyConfig, err := store.GetPrivacyConfig()
	if err == nil && privacyConfig.Enabled {
		authenticated := isAuthenticated(r)
		if !authenticated {
			shareToken := r.URL.Query().Get("token")
			if shareToken == "" {
				authHeader := r.Header.Get("Authorization")
				if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
					authenticated = isAuthenticated(r)
				}
			}
			if !authenticated && shareToken != "" {
				if shareToken == privacyConfig.ShareToken && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
					authenticated = true
				}
			}
			if !authenticated {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}
	
	clientID := r.URL.Query().Get("client_id")
	target := r.URL.Query().Get("target")
	
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	
	var results []TCPingResult
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

// Handle get navbar config
func handleGetNavbarConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	// Navbar config is public (no authentication required)
	// It's used by the frontend to display custom navbar text and logo
	config, err := store.GetNavbarConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get navbar config: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, config)
}

func handleSetNavbarConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	
	defer r.Body.Close()
	var config NavbarConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	// Validate config
	if config.Text == "" {
		config.Text = "Pulse" // Default to "Pulse" if empty
	}
	
	if err := store.SaveNavbarConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("failed to save navbar config: %v", err), http.StatusInternalServerError)
		return
	}
	
	writeJSON(w, http.StatusOK, map[string]string{"message": "navbar config saved"})
}

func handleGetPrivacyConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	config, err := store.GetPrivacyConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get privacy config: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Check if user is authenticated - only authenticated users can see share_token
	authenticated := isAuthenticated(r)
	
	// Convert TokenExpires to RFC3339 string for JSON serialization
	configResponse := map[string]interface{}{
		"enabled":           config.Enabled,
		"server_time":       time.Now().Format(time.RFC3339), // Include server time for client to calculate time difference
	}
	
	// Only include share_token and expiration info if authenticated
	if authenticated {
		configResponse["share_token"] = config.ShareToken
		configResponse["expires_in_seconds"] = config.ExpiresInSeconds
		if !config.TokenExpires.IsZero() {
			configResponse["token_expires"] = config.TokenExpires.Format(time.RFC3339)
			// Also include whether token is expired (based on server time)
			configResponse["token_expired"] = time.Now().After(config.TokenExpires)
		} else {
			configResponse["token_expires"] = ""
			configResponse["token_expired"] = false
		}
	} else {
		// Unauthenticated users can only see if privacy is enabled
		configResponse["share_token"] = ""
		configResponse["expires_in_seconds"] = 0
		configResponse["token_expires"] = ""
		configResponse["token_expired"] = false
	}
	
	writeJSON(w, http.StatusOK, configResponse)
}

func handleSetPrivacyConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	
	defer r.Body.Close()
	var payload struct {
		Enabled      bool   `json:"enabled"`
		ShareToken   string `json:"share_token"`
		TokenExpires string `json:"token_expires"` // ISO 8601 string or empty
		ExpiresInSeconds int `json:"expires_in_seconds"` // Alternative: seconds from now
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	config := PrivacyConfig{
		Enabled:          payload.Enabled,
		ShareToken:       payload.ShareToken,
		ExpiresInSeconds: payload.ExpiresInSeconds, // Save the expiration seconds value
	}
	
	// Calculate expiration time on server side
	if payload.ShareToken != "" {
		if payload.ExpiresInSeconds > 0 {
			// Use server time + seconds (more accurate)
			config.TokenExpires = time.Now().Add(time.Duration(payload.ExpiresInSeconds) * time.Second)
		} else if payload.TokenExpires != "" {
			// Parse provided expiration time (fallback for backward compatibility)
			expiresTime, err := time.Parse(time.RFC3339, payload.TokenExpires)
			if err != nil {
				http.Error(w, "invalid token_expires format", http.StatusBadRequest)
				return
			}
			config.TokenExpires = expiresTime
		}
		// If both are empty, TokenExpires remains zero (no expiration)
	} else {
		// ShareToken is empty, clear TokenExpires to revoke the share link
		config.TokenExpires = time.Time{}
		config.ExpiresInSeconds = 0
	}
	
	if err := store.SavePrivacyConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("failed to save privacy config: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Return the saved config with server-calculated expiration time
	// Convert TokenExpires to RFC3339 string for JSON serialization
	configResponse := map[string]interface{}{
		"enabled":           config.Enabled,
		"share_token":       config.ShareToken,
		"expires_in_seconds": config.ExpiresInSeconds, // Include saved expiration seconds value
		"server_time":       time.Now().Format(time.RFC3339), // Include server time for client to calculate time difference
	}
	if !config.TokenExpires.IsZero() {
		configResponse["token_expires"] = config.TokenExpires.Format(time.RFC3339)
		// Also include whether token is expired (based on server time)
		configResponse["token_expired"] = time.Now().After(config.TokenExpires)
	} else {
		configResponse["token_expires"] = ""
		configResponse["token_expired"] = false
	}
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "privacy config saved",
		"config":  configResponse,
	})
}

func handleVerifyShareToken(store *Store, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	
	config, err := store.GetPrivacyConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get privacy config: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Check if privacy is enabled
	if !config.Enabled {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "reason": "privacy_not_enabled"})
		return
	}
	
	// Check if token matches
	if config.ShareToken == "" || config.ShareToken != payload.Token {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "reason": "invalid_token"})
		return
	}
	
	// Check if token is expired
	if !config.TokenExpires.IsZero() && time.Now().After(config.TokenExpires) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "reason": "token_expired"})
		return
	}
	
	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": true})
}

func handleSetTCPingConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	// Require authentication for setting TCPing config
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	
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
	
	// SECURITY: Validate target format with enhanced checks
	// - Check length to prevent DoS attacks
	// - Validate format (host:port)
	// - Validate port range (1-65535)
	// - Validate hostname format
	for _, target := range config.Targets {
		if target.Name == "" {
			http.Error(w, "target name is required", http.StatusBadRequest)
			return
		}
		
		// Validate name length
		if len(target.Name) > 100 {
			http.Error(w, fmt.Sprintf("target name too long (max 100 characters) for target: %s", target.Name), http.StatusBadRequest)
			return
		}
		
		if target.Address == "" {
			http.Error(w, fmt.Sprintf("target address is required for target: %s", target.Name), http.StatusBadRequest)
			return
		}
		
		// Validate address length (RFC 1035: Domain names limited to 255 characters)
		address := strings.TrimSpace(target.Address)
		if len(address) > 255 {
			http.Error(w, fmt.Sprintf("target address too long for target: %s", target.Name), http.StatusBadRequest)
			return
		}
		
		// Must contain ":" to separate host and port
		if !strings.Contains(address, ":") {
			http.Error(w, fmt.Sprintf("invalid target format: %s (expected format: host:port) for target: %s", address, target.Name), http.StatusBadRequest)
			return
		}
		
		// Split host and port
		parts := strings.SplitN(address, ":", 2)
		if len(parts) != 2 {
			http.Error(w, fmt.Sprintf("invalid target format: %s (expected format: host:port) for target: %s", address, target.Name), http.StatusBadRequest)
			return
		}
		
		host := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])
		
		// Validate host is not empty
		if host == "" {
			http.Error(w, fmt.Sprintf("target host cannot be empty for target: %s", target.Name), http.StatusBadRequest)
			return
		}
		
		// Validate port is a number and in valid range (1-65535)
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			http.Error(w, fmt.Sprintf("invalid port number (must be 1-65535) for target: %s", target.Name), http.StatusBadRequest)
			return
		}
		
		// Additional validation: check for common injection patterns
		// Allow valid characters for hostnames and IP addresses
		// Hostname regex: alphanumeric, dots, hyphens, brackets (for IPv6)
		hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9.\-\[\]:]+$`)
		if !hostnameRegex.MatchString(host) {
			http.Error(w, fmt.Sprintf("invalid target host format for target: %s", target.Name), http.StatusBadRequest)
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
				_ = store.DeleteTCPingResultsByTarget(oldTarget)
			}
		}
	}
	
	if err := store.SaveTCPingConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("failed to save config: %v", err), http.StatusInternalServerError)
		return
	}
	
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Shared HTTP client for TCPing operations (connection pooling)
var tcpingHTTPClient *http.Client
var tcpingHTTPClientOnce sync.Once

func getTCPingHTTPClient() *http.Client {
	tcpingHTTPClientOnce.Do(func() {
		// Create a shared HTTP client for tcping with longer timeout for cross-continent networks
		// Client tcping operation can take up to 5 seconds, plus network overhead for high-latency networks
		// Configure DialContext to support both IPv4 and IPv6 with proper timeouts
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,  // DNS + TCP connection timeout
			KeepAlive: 120 * time.Second, // Longer keep-alive for connection reuse
		}
		
		tcpingHTTPClient = &http.Client{
			Timeout: 15 * time.Second, // Increased from 8s to 15s for cross-continent networks
			Transport: &http.Transport{
				DialContext:           dialer.DialContext, // Enable proper DNS and TCP timeout control
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,   // Increased from 3s to 10s for slow TLS
				ResponseHeaderTimeout: 8 * time.Second,    // Wait up to 8s for response headers
				ExpectContinueTimeout: 5 * time.Second,    // Added for better HTTP/1.1 support
				DisableCompression:    false,              // Enable compression for efficiency
			},
		}
	})
	return tcpingHTTPClient
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
	// TCPing disabled if no targets configured
	
	// Track current config to detect changes
	currentInterval := config.IntervalSecs
	currentTargets := make(map[string]TCPingTargetEntry)
	for _, target := range config.Targets {
		currentTargets[target.Address] = target
	}
	
	// Use shared HTTP client for connection reuse
	httpClient := getTCPingHTTPClient()
	
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
			// Safety check: skip nil clients or clients with empty ID
			// Must have at least one URL (IPv4 or IPv6)
			if client == nil || client.ID == "" || (client.URL == "" && client.URL6 == "") {
				continue
			}
			
			// Registry already maintains consistency with database (same as client polling):
			// - Clients are added when they register (POST /api/clients/register)
			// - Clients are removed when systems are deleted (handleDeleteMetric)
			// - Clients are removed after maxFailures in client polling (handled there)
			// - No need to verify existence on every TCPing poll (consistency with client polling)
			
			// Only send tcping to connected clients
			// CRITICAL: Re-fetch client from registry to get latest WorkingURL before checking connection
			// This ensures we use the most up-to-date WorkingURL (especially IPv6) which may have been
			// updated by pollClient or isClientConnected
			latestClient := registry.Get(client.ID)
			if latestClient == nil {
				continue
			}
			// CRITICAL: If WorkingURL is set (especially IPv6), we should trust it and allow tcping
			// This is important because isClientConnected may fail due to temporary network issues,
			// but if we have a WorkingURL, it means we've successfully connected before
			if latestClient.WorkingURL != "" {
				// WorkingURL is set, trust it and allow tcping (skip connection check)
				// This is especially important for IPv6 connections which may have intermittent issues
			} else if !isClientConnected(latestClient) {
				// No WorkingURL and connection check failed, skip tcping
				// Silent skip - no log needed for normal operation
				continue
			}
			
			// Send tcping request for each target
			for _, target := range config.Targets {
				// Safety check: skip empty target address
				if target.Address == "" {
					continue
				}
				
				go func(clientID string, tgt TCPingTargetEntry) {
					// CRITICAL: Re-fetch client from registry inside goroutine to get latest WorkingURL
					// This ensures we always use the most up-to-date WorkingURL (especially IPv6)
					// which may have been updated by pollClient or isClientConnected
					c := registry.Get(clientID)
					if c == nil || c.ID == "" || tgt.Address == "" {
						return
					}
					// Must have at least one URL
					if c.URL == "" && c.URL6 == "" {
						return
					}
					
					// Build URL list: prioritize working URL if available
					// CRITICAL: If WorkingURL is set (especially if it's IPv6), use ONLY that URL
					// This ensures that once IPv6 connection succeeds, we never try IPv4 again
					urls := []string{}
					if c.WorkingURL != "" {
						// If we have a working URL, use ONLY that URL
						// This ensures that once IPv6 works, we never try IPv4 again
						urls = append(urls, c.WorkingURL+"/tcping")
						// Don't add other URLs if WorkingURL is set - it represents the known working connection
					} else {
						// No working URL yet, try IPv4 first, then IPv6
						if c.URL != "" {
							urls = append(urls, c.URL+"/tcping")
						}
						if c.URL6 != "" {
							urls = append(urls, c.URL6+"/tcping")
						}
					}
					
				// Get secret from client registry cache (optimized: no DB lookup)
				secret := c.Secret
				
				// Create context with timeout for TCPing request
					// Use 12-second timeout (shorter than HTTP client's 15s timeout)
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					defer cancel()
					
				var resp *http.Response
					var err error
					var successfulBaseURL string
					for _, url := range urls {
						// Send target address in request body
						tcpingRequest := map[string]string{
							"target": tgt.Address,
						}
					requestData, _ := json.Marshal(tcpingRequest)
					req, reqErr := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(requestData)))
					if reqErr != nil {
						// Silent failure - request creation errors are rare and usually indicate programming errors
						continue
					}
					req.Header.Set("Content-Type", "application/json")
					
					// Security: Add secret to Authorization header if configured
					if secret != "" {
						req.Header.Set("Authorization", "Bearer "+secret)
					}
					
					resp, err = httpClient.Do(req)
					if err == nil && resp.StatusCode == http.StatusOK {
						// Extract base URL (remove /tcping suffix)
						if strings.HasSuffix(url, "/tcping") {
							successfulBaseURL = strings.TrimSuffix(url, "/tcping")
						} else {
							successfulBaseURL = url
						}
						break // Success, exit loop
					}
					// Silent failures - TCPing failures are expected in some network conditions
					// Only log critical failures that indicate system issues
					if resp != nil {
						resp.Body.Close()
					}
					resp = nil
					}
					
					if resp == nil {
						// Silent failure - TCPing failures are expected and handled gracefully
						// Results are saved to database even on failure, so no log needed
						return // All attempts failed
					}
					
					// CRITICAL: defer resp.Body.Close() must be before any early returns
					// This ensures the response body is always closed, even if there's an error
					defer resp.Body.Close()
					
					// Update working URL if we successfully connected via TCPing
					// CRITICAL: Always update WorkingURL when we successfully connect via TCPing
					// This ensures WorkingURL is preserved and reflects the actual working connection
					// Use registry method to update atomically, so it's preserved even during re-registration
					if successfulBaseURL != "" {
						// Update working URL via the registry to ensure atomicity and persistence across re-registrations
						registry.UpdateWorkingURL(clientID, successfulBaseURL)
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
						ClientID:  clientID,
						Target:    tgt.Address,
						Latency:   latency,
						Timestamp: time.Now().UTC(),
					}
					
					if err := store.SaveTCPingResult(result); err != nil {
						// TCPing result save failed, continue silently
					}
					
					// Update SystemMetric with latest tcping data for this target (only if successful)
					if tcpingResp.Success {
						existing, err := store.Get(clientID)
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
				}(client.ID, target)
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

// Start IP cache cleanup every hour
func startIPCacheCleanup(ipCache *IPCountryCache) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		<-ticker.C
		if ipCache != nil {
			removed := ipCache.CleanExpired()
			if removed > 0 {
				log.Printf("🧹 IP cache cleanup: removed %d expired entries", removed)
			}
		}
	}
}

// Auth token storage (in-memory, simple implementation)
var authTokens = make(map[string]time.Time)
var authTokensMu sync.Mutex

// Login attempt tracking for brute force protection
type loginAttempt struct {
	count     int
	lastAttempt time.Time
	lockedUntil time.Time
}
var loginAttempts = make(map[string]*loginAttempt) // key: IP address
var loginAttemptsMu sync.RWMutex

// Token verification attempt tracking
type verifyAttempt struct {
	count     int
	lastAttempt time.Time
}
var verifyAttempts = make(map[string]*verifyAttempt) // key: IP address
var verifyAttemptsMu sync.RWMutex

// Cleanup expired tokens and login attempts every 5 minutes
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			// Cleanup expired tokens
			authTokensMu.Lock()
			now := time.Now()
			for token, expiry := range authTokens {
				if now.After(expiry) {
					delete(authTokens, token)
				}
			}
			authTokensMu.Unlock()
			
			// Cleanup old login attempts (older than 1 hour)
			loginAttemptsMu.Lock()
			for ip, attempt := range loginAttempts {
				if time.Since(attempt.lastAttempt) > 1*time.Hour && attempt.count == 0 {
					delete(loginAttempts, ip)
				}
			}
			loginAttemptsMu.Unlock()
			
			// Cleanup old verify attempts (older than 5 minutes)
			verifyAttemptsMu.Lock()
			for ip, attempt := range verifyAttempts {
				if time.Since(attempt.lastAttempt) > 5*time.Minute {
					delete(verifyAttempts, ip)
				}
			}
			verifyAttemptsMu.Unlock()
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

	// SECURITY: Validate password length to prevent DoS attacks
	// Bcrypt is computationally expensive, so limit password length
	if len(payload.Password) < 6 {
		http.Error(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}
	if len(payload.Password) > 128 {
		http.Error(w, "password too long (max 128 characters)", http.StatusBadRequest)
		return
	}

	if err := store.SetPassword(payload.Password); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// 1. Check X-Forwarded-For header (for proxies/load balancers)
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// 2. Check X-Real-IP header (for nginx proxy)
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	
	// 3. Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleAuthLogin authenticates and returns a token
func handleAuthLogin(store *Store, w http.ResponseWriter, r *http.Request) {
	// SECURITY: Rate limiting to prevent brute force attacks
	clientIP := getClientIP(r)
	loginAttemptsMu.Lock()
	attempt, exists := loginAttempts[clientIP]
	if !exists {
		attempt = &loginAttempt{count: 0, lastAttempt: time.Now()}
		loginAttempts[clientIP] = attempt
	}
	
	// Check if IP is locked due to too many failed attempts
	if time.Now().Before(attempt.lockedUntil) {
		loginAttemptsMu.Unlock()
		// Return same error message to avoid information disclosure
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	
	// Reset count if last attempt was more than 15 minutes ago
	if time.Since(attempt.lastAttempt) > 15*time.Minute {
		attempt.count = 0
	}
	loginAttemptsMu.Unlock()
	
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// SECURITY: Validate password length to prevent DoS attacks
	// Bcrypt is computationally expensive, so limit password length
	if len(payload.Password) < 6 {
		http.Error(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}
	if len(payload.Password) > 128 {
		http.Error(w, "password too long (max 128 characters)", http.StatusBadRequest)
		return
	}

	valid, err := store.VerifyPassword(payload.Password)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Update attempt tracking
	loginAttemptsMu.Lock()
	attempt.lastAttempt = time.Now()
	if !valid {
		attempt.count++
		// Lock IP after 5 failed attempts for 15 minutes
		if attempt.count >= 5 {
			attempt.lockedUntil = time.Now().Add(15 * time.Minute)
		}
		loginAttemptsMu.Unlock()
		// Return same error message to avoid information disclosure
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	// Reset count on successful login
	attempt.count = 0
	attempt.lockedUntil = time.Time{}
	loginAttemptsMu.Unlock()

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
	// SECURITY: Rate limiting to prevent token enumeration attacks
	clientIP := getClientIP(r)
	verifyAttemptsMu.Lock()
	attempt, exists := verifyAttempts[clientIP]
	if !exists {
		attempt = &verifyAttempt{count: 0, lastAttempt: time.Now()}
		verifyAttempts[clientIP] = attempt
	}
	
	// Reset count if last attempt was more than 1 minute ago
	if time.Since(attempt.lastAttempt) > 1*time.Minute {
		attempt.count = 0
	}
	
	// Limit to 30 attempts per minute per IP
	if attempt.count >= 30 {
		verifyAttemptsMu.Unlock()
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	
	attempt.count++
	attempt.lastAttempt = time.Now()
	verifyAttemptsMu.Unlock()
	
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

	// SECURITY: Validate new password length to prevent DoS attacks
	if len(payload.NewPassword) < 6 {
		http.Error(w, "new password must be at least 6 characters", http.StatusBadRequest)
		return
	}
	if len(payload.NewPassword) > 128 {
		http.Error(w, "new password too long (max 128 characters)", http.StatusBadRequest)
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
	// SECURITY: Prefer Authorization header over query parameter
	// Query parameters can leak tokens via logs, referer headers, etc.
	
	// Check Authorization header (preferred method)
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

	// SECURITY: Query parameter support is kept for backward compatibility
	// but should be deprecated. Tokens in query parameters can be leaked via:
	// - Server access logs
	// - Referer headers
	// - Browser history
	// - Proxy logs
	// Consider removing this in future versions
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


