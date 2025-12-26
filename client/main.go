package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	netutil "github.com/shirou/gopsutil/v3/net"
)

type metricPayload struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	IPv4               string  `json:"ipv4,omitempty"`
	IPv6               string  `json:"ipv6,omitempty"`
	Uptime             int64   `json:"uptime"` // Uptime in seconds since agent started
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

var (
	agentID       string
	agentName     string
	startTime     time.Time
	serverBase    string
	secret        string // Secret for authenticating metrics endpoint
	
	// Cache for data that doesn't change frequently
	cpuModelCache          string
	cpuModelCacheTime      time.Time
	virtualizationTypeCache string
	virtualizationTypeCacheTime time.Time
	cacheMutex             sync.RWMutex
	cacheTTL               = 5 * time.Minute // Cache for 5 minutes
	
	// Shared HTTP client for connection reuse (important for cross-continent networks)
	sharedHTTPClient     *http.Client
	sharedHTTPClientOnce sync.Once
	
	// Security warning log throttling
	lastSecurityWarningTime time.Time
	securityWarningMutex    sync.Mutex
)

func main() {
	agentID = envOr("AGENT_ID", "localhost")
	agentName = envOr("AGENT_NAME", agentID)
	serverBase = strings.TrimSuffix(envOr("SERVER_BASE", "http://localhost:8080"), "/")
	clientPort := envOr("CLIENT_PORT", "9090")
	secret = envOr("SECRET", "")

	// Record start time for uptime calculation
	startTime = time.Now()

	log.Printf("🚀 Starting Probe Client (ID: %s, Name: %s)", agentID, agentName)

	// Initial registration with server
	go registerWithServer()
	
	// Start periodic re-registration to maintain connection
	// This ensures the client auto-recovers if removed from server registry
	go startPeriodicRegistration()

	// Start HTTP server to receive requests from backend
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", handleMetricsRequest)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/tcping", handleTCPingRequest)

	addr := ":" + clientPort
	log.Printf("📡 Client listening on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("❌ Failed to start client server: %v", err)
	}
}

// getSharedHTTPClient returns a shared HTTP client for connection reuse
// This is critical for cross-continent networks (e.g., China to overseas servers)
func getSharedHTTPClient() *http.Client {
	sharedHTTPClientOnce.Do(func() {
		// Create a shared HTTP client with optimized settings for cross-continent networks
		// Key optimizations for China to overseas connections:
		// - Longer timeouts to handle high latency (200-400ms RTT)
		// - Connection reuse to avoid repeated TCP handshakes
		// - DNS resolution timeout to handle slow DNS in China
		sharedHTTPClient = &http.Client{
			Timeout: 30 * time.Second, // Increased to 30s for high-latency cross-continent networks
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   15 * time.Second, // Increased to 15s for slow connections (DNS + TCP)
					KeepAlive: 120 * time.Second, // Longer keep-alive for connection reuse
				}).DialContext,
				MaxIdleConns:            50,                 // More idle connections for better reuse
				MaxIdleConnsPerHost:     20,                 // More per-host connections
				IdleConnTimeout:         180 * time.Second,  // Longer idle timeout
				TLSHandshakeTimeout:     15 * time.Second,   // Increased to 15s for slow TLS (GFW interference)
				ResponseHeaderTimeout:   10 * time.Second,   // Wait up to 10s for response headers
				ExpectContinueTimeout:   5 * time.Second,
				DisableCompression:      false, // Enable compression
				DisableKeepAlives:       false, // Enable keep-alive (critical for connection reuse)
			},
		}
	})
	return sharedHTTPClient
}

// logOncePerMinute logs a message at most once per minute to avoid log spam
func logOncePerMinute(message string) {
	securityWarningMutex.Lock()
	defer securityWarningMutex.Unlock()
	
	now := time.Now()
	if now.Sub(lastSecurityWarningTime) >= 1*time.Minute {
		log.Println(message)
		lastSecurityWarningTime = now
	}
}

// Register client with server
func registerWithServer() {
	// Retry registration with exponential backoff - increased for cross-continent networks
	maxRetries := 10 // Increased from 5 to handle high-latency networks (e.g., China to overseas)
	for i := 0; i < maxRetries; i++ {
		time.Sleep(time.Duration(i+1) * time.Second) // Wait before retry
		
		// Create context with timeout for registration request
		// Use 10-second timeout (shorter than HTTP client's 30s timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		
		// Get public IP addresses (both IPv4 and IPv6)
		// This ensures consistency and uses the real public IP, not private IP
		ipv4, ipv6 := getIPAddresses()
		// Fallback to local IP only if no public IP found (should rarely happen)
		if ipv4 == "" {
			ipv4 = getLocalIP()
		}
		
		payload := map[string]interface{}{
			"id":   agentID,
			"name": agentName,
			"port": envOr("CLIENT_PORT", "9090"),
			"ip":   ipv4,
		}
		// Include IPv6 if available
		if ipv6 != "" {
			payload["ipv6"] = ipv6
		}
		
		// Add secret if provided via environment variable
		if secret := envOr("SECRET", ""); secret != "" {
			payload["secret"] = secret
		}
		
		data, _ := json.Marshal(payload)
		
		// Use shared HTTP client for connection reuse (critical for cross-continent networks)
		httpClient := getSharedHTTPClient()
		
		req, err := http.NewRequestWithContext(ctx, "POST", serverBase+"/api/clients/register", strings.NewReader(string(data)))
		if err != nil {
			cancel()
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "PulseClient/1.0")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Accept-Encoding", "gzip, deflate") // Enable compression
		
		resp, err := httpClient.Do(req)
		cancel() // ✅ Always cancel context after request completes
		if err != nil {
			log.Printf("⚠️  Registration attempt %d/%d failed: %v", i+1, maxRetries, err)
			continue
		}
		
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			log.Printf("✅ Successfully registered with server (ID: %s, IPv4: %s, IPv6: %s)", agentID, ipv4, ipv6)
			return
		} else {
			// Read error response body for debugging
			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("❌ Registration failed (attempt %d/%d): HTTP %d - %s", i+1, maxRetries, resp.StatusCode, string(body))
		}
	}
	log.Printf("❌ Failed to register after %d attempts", maxRetries)
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
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

// startPeriodicRegistration maintains connection with server by periodically re-registering
// This handles: 1) Server restart, 2) Client removed from registry due to failures, 3) Network recovery
func startPeriodicRegistration() {
	// Wait for initial registration to complete
	time.Sleep(5 * time.Second) // Reduced from 10s to 5s for faster recovery
	
	ticker := time.NewTicker(5 * time.Second) // More frequent heartbeat (5s) for faster recovery and stability
	defer ticker.Stop()
	
	// Use shared HTTP client for connection reuse (critical for cross-continent networks)
	httpClient := getSharedHTTPClient()
	
	consecutiveFailures := 0
	
	for range ticker.C {
		// Create context with timeout for registration request
		// Use 10-second timeout (shorter than HTTP client's 30s timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		
		// Get public IP addresses (both IPv4 and IPv6)
		// This ensures consistency and uses the real public IP, not private IP
		ipv4, ipv6 := getIPAddresses()
		// Fallback to local IP only if no public IP found (should rarely happen)
		if ipv4 == "" {
			ipv4 = getLocalIP()
		}
		
		payload := map[string]interface{}{
			"id":   agentID,
			"name": agentName,
			"port": envOr("CLIENT_PORT", "9090"),
			"ip":   ipv4,
		}
		// Include IPv6 if available
		if ipv6 != "" {
			payload["ipv6"] = ipv6
		}
		
		// Add secret if provided via environment variable (CRITICAL: must include secret in periodic registration)
		if secret := envOr("SECRET", ""); secret != "" {
			payload["secret"] = secret
		}
		
		data, _ := json.Marshal(payload)
		
		req, err := http.NewRequestWithContext(ctx, "POST", serverBase+"/api/clients/register", strings.NewReader(string(data)))
		if err != nil {
			cancel()
			consecutiveFailures++
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "PulseClient/1.0")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Accept-Encoding", "gzip, deflate") // Enable compression
		
		resp, err := httpClient.Do(req)
		cancel() // ✅ Always cancel context after request completes
		if err != nil {
			consecutiveFailures++
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			consecutiveFailures = 0
		} else if resp.StatusCode == http.StatusNotFound {
			// Server ID not found in database - this is expected if admin hasn't added this system yet
			// Just silently continue trying
			consecutiveFailures++
		} else {
			consecutiveFailures++
		}
	}
}

// Handle metrics request from backend
func handleMetricsRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Verify secret authentication if configured
	// If secret is configured, it must be provided and match
	// If secret is empty, allow access for backward compatibility (but log warning)
	if secret != "" {
		// Secret is configured - require authentication
		authHeader := r.Header.Get("Authorization")
		providedSecret := ""
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			providedSecret = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// Fallback: check query parameter
			providedSecret = r.URL.Query().Get("secret")
		}
		
		if providedSecret != secret {
			http.Error(w, "unauthorized: invalid secret", http.StatusUnauthorized)
			return
		}
	} else {
		// SECURITY WARNING: No secret configured - allowing access for backward compatibility
		// This is insecure and should be fixed by configuring SECRET environment variable
		// Log warning only once per minute to avoid log spam
		logOncePerMinute("⚠️  SECURITY WARNING: /metrics endpoint is accessible without authentication. Please configure SECRET environment variable for security.")
	}

	// Collect system metrics
	metrics := collectSystemMetrics()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Handle health check
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// TCPingResponse represents the response from tcping
type TCPingResponse struct {
	Latency float64 `json:"latency"` // Latency in milliseconds
	Success bool    `json:"success"`
	Error   string  `json:"error,omitempty"`
}

// TCPingRequest represents the request from backend
type TCPingRequest struct {
	Target string `json:"target"`
}

// Handle tcping request from backend
func handleTCPingRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Verify secret authentication if configured
	// If secret is configured, it must be provided and match
	// If secret is empty, allow access for backward compatibility (but log warning)
	if secret != "" {
		// Secret is configured - require authentication
		authHeader := r.Header.Get("Authorization")
		providedSecret := ""
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			providedSecret = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// Fallback: check query parameter
			providedSecret = r.URL.Query().Get("secret")
		}
		
		if providedSecret != secret {
			http.Error(w, "unauthorized: invalid secret", http.StatusUnauthorized)
			return
		}
	} else {
		// SECURITY WARNING: No secret configured - allowing access for backward compatibility
		// This is insecure and should be fixed by configuring SECRET environment variable
		// Log warning only once per minute to avoid log spam
		logOncePerMinute("⚠️  SECURITY WARNING: /tcping endpoint is accessible without authentication. Please configure SECRET environment variable for security.")
	}

	// Parse target from request body
	var tcpingReq TCPingRequest
	if err := json.NewDecoder(r.Body).Decode(&tcpingReq); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Target must be provided by backend - no default fallback
	if tcpingReq.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate and normalize target address
	// - Check length to prevent DoS attacks
	// - Validate format (host:port or host)
	// - Validate port range (1-65535)
	target := strings.TrimSpace(tcpingReq.Target)
	if len(target) > 255 {
		// RFC 1035: Domain names are limited to 255 characters
		http.Error(w, "target address too long", http.StatusBadRequest)
		return
	}
	
	// Normalize target: if no port specified, add default port 80
	var host, portStr string
	if strings.Contains(target, ":") {
		// Split host and port
		parts := strings.SplitN(target, ":", 2)
		if len(parts) != 2 {
			http.Error(w, "invalid target format", http.StatusBadRequest)
			return
		}
		host = strings.TrimSpace(parts[0])
		portStr = strings.TrimSpace(parts[1])
	} else {
		// No port specified, add default port 80
		host = strings.TrimSpace(target)
		portStr = "80"
	}
	
	// Validate host is not empty
	if host == "" {
		http.Error(w, "target host cannot be empty", http.StatusBadRequest)
		return
	}
	
	// Validate port is a number and in valid range (1-65535)
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		http.Error(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}
	
	// Reconstruct normalized target
	target = fmt.Sprintf("%s:%d", host, port)
	
	// Additional validation: check for common injection patterns
	// Allow valid characters for hostnames and IP addresses
	// Hostname regex: alphanumeric, dots, hyphens, brackets (for IPv6)
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9.\-\[\]:]+$`)
	if !hostnameRegex.MatchString(host) {
		http.Error(w, "invalid target host format", http.StatusBadRequest)
		return
	}

	// Execute tcping to target specified by backend
	latency, err := executeTCPing(target)
	
	response := TCPingResponse{
		Success: err == nil,
		Latency: latency,
	}
	
	if err != nil {
		response.Error = err.Error()
		log.Printf("❌ TCPing to %s failed: %v", target, err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Execute tcping command
func executeTCPing(target string) (float64, error) {
	// Use net.DialTimeout to measure TCP connection latency
	// Use shorter timeout (3 seconds) to avoid blocking the HTTP request handler too long
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return 0, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()
	
	latency := time.Since(start).Seconds() * 1000 // Convert to milliseconds
	return latency, nil
}

// Collect system metrics
func collectSystemMetrics() metricPayload {
	// Get system uptime (not process uptime) from /proc/uptime
	uptime := getSystemUptime()
	
	// Get system information
	osInfo := getOSInfo()
	ipv4, ipv6 := getIPAddresses()
	location := getLocation() // Only country
	
	// Get system metrics
	cpu := getCPUUsage()
	cpuModel := getCPUModel()
	memory := getMemoryUsage()
	memoryInfo := getMemoryInfo()
	swapInfo := getSwapInfo()
	disk := getDiskUsage()
	diskInfo := getDiskInfo()
	netIn, netOut, totalNetInBytes, totalNetOutBytes := getNetworkStats()
	virtualizationType := getVirtualizationType()
	
	return metricPayload{
		ID:                 agentID,
		Name:               agentName,
		IPv4:               ipv4,
		IPv6:               ipv6,
		Uptime:             uptime,
		Location:           location,
		VirtualizationType: virtualizationType,
		OS:                 osInfo.Name,
		OSIcon:             osInfo.Icon,
		CPU:                cpu,
		CPUModel:           cpuModel,
		Memory:             memory,
		MemoryInfo:         memoryInfo,
		SwapInfo:           swapInfo,
		Disk:               disk,
		DiskInfo:           diskInfo,
		NetInMBps:          netIn,
		NetOutMBps:         netOut,
		TotalNetInBytes:    totalNetInBytes,
		TotalNetOutBytes:   totalNetOutBytes,
		AgentVersion:       "1.2.3",
		Alert:              false, // Can be enhanced with actual alert logic
	}
}

type OSInfo struct {
	Name string
	Icon string
}

func getOSInfo() OSInfo {
	osName := runtime.GOOS
	var name, icon string
	
	switch osName {
	case "linux":
		name = detectLinuxDistro()
		icon = getOSIcon(name)
	case "darwin":
		name = "macOS"
		icon = "devicon:apple"
	case "windows":
		name = "Windows"
		icon = "logos:microsoft-windows-icon"
	default:
		name = strings.Title(osName)
		icon = "devicon:linux"
	}
	
	return OSInfo{Name: name, Icon: icon}
}

func detectLinuxDistro() string {
	// Try to detect Linux distribution from /etc/os-release
	data, err := ioutil.ReadFile("/etc/os-release")
	if err == nil {
		content := string(data)
		contentLower := strings.ToLower(content)
		
		// Check for specific distributions (order matters - check specific ones first)
		if strings.Contains(contentLower, "pop!_os") || strings.Contains(contentLower, "pop os") {
			return "Pop!_OS"
		} else if strings.Contains(contentLower, "linux mint") || strings.Contains(contentLower, "linuxmint") {
			return "Linux Mint"
		} else if strings.Contains(contentLower, "elementary") {
			return "Elementary OS"
		} else if strings.Contains(contentLower, "zorin") {
			return "Zorin OS"
		} else if strings.Contains(contentLower, "kali") {
			return "Kali Linux"
		} else if strings.Contains(contentLower, "parrot") {
			return "Parrot OS"
		} else if strings.Contains(contentLower, "manjaro") {
			return "Manjaro"
		} else if strings.Contains(contentLower, "endeavour") {
			return "EndeavourOS"
		} else if strings.Contains(contentLower, "garuda") {
			return "Garuda Linux"
		} else if strings.Contains(contentLower, "arch") {
			return "Arch Linux"
		} else if strings.Contains(contentLower, "ubuntu") {
			return "Ubuntu"
		} else if strings.Contains(contentLower, "debian") {
			return "Debian"
		} else if strings.Contains(contentLower, "rocky") {
			return "Rocky Linux"
		} else if strings.Contains(contentLower, "almalinux") || strings.Contains(contentLower, "alma") {
			return "AlmaLinux"
		} else if strings.Contains(contentLower, "centos") {
			return "CentOS"
		} else if strings.Contains(contentLower, "red hat") || strings.Contains(contentLower, "rhel") {
			return "RHEL"
		} else if strings.Contains(contentLower, "oracle") {
			return "Oracle Linux"
		} else if strings.Contains(contentLower, "fedora") {
			return "Fedora"
		} else if strings.Contains(contentLower, "opensuse") || strings.Contains(contentLower, "suse") {
			return "openSUSE"
		} else if strings.Contains(contentLower, "alpine") {
			return "Alpine Linux"
		} else if strings.Contains(contentLower, "gentoo") {
			return "Gentoo"
		} else if strings.Contains(contentLower, "void") {
			return "Void Linux"
		} else if strings.Contains(contentLower, "slackware") {
			return "Slackware"
		} else if strings.Contains(contentLower, "nixos") {
			return "NixOS"
		} else if strings.Contains(contentLower, "solus") {
			return "Solus"
		} else if strings.Contains(contentLower, "mageia") {
			return "Mageia"
		} else if strings.Contains(contentLower, "pclinuxos") {
			return "PCLinuxOS"
		} else if strings.Contains(contentLower, "clearlinux") || strings.Contains(contentLower, "clear linux") {
			return "Clear Linux"
		}
	}
	
	// Fallback: try reading /etc/issue
	if data, err := ioutil.ReadFile("/etc/issue"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "ubuntu") {
			return "Ubuntu"
		} else if strings.Contains(content, "debian") {
			return "Debian"
		} else if strings.Contains(content, "centos") {
			return "CentOS"
		} else if strings.Contains(content, "fedora") {
			return "Fedora"
		} else if strings.Contains(content, "arch") {
			return "Arch Linux"
		}
	}
	
	return "Linux"
}

func getOSIcon(osName string) string {
	osLower := strings.ToLower(osName)
	
	// Priority: devicon (colored) > logos (colored) > use generic linux icon
	// Debian-based distributions
	if strings.Contains(osLower, "ubuntu") {
		return "logos:ubuntu" // Colored Ubuntu logo
	} else if strings.Contains(osLower, "pop") {
		return "logos:pop-os" // Colored Pop!_OS logo
	} else if strings.Contains(osLower, "mint") {
		return "logos:linux-mint" // Colored Linux Mint logo
	} else if strings.Contains(osLower, "elementary") {
		return "logos:elementary" // Elementary OS logo
	} else if strings.Contains(osLower, "zorin") {
		return "devicon:linux" // No colored icon available, use generic
	} else if strings.Contains(osLower, "kali") {
		return "logos:kalilinux" // Kali Linux logo
	} else if strings.Contains(osLower, "parrot") {
		return "devicon:linux" // No colored icon available, use generic
	} else if strings.Contains(osLower, "debian") {
		return "logos:debian" // Colored Debian logo
	
	// Arch-based distributions
	} else if strings.Contains(osLower, "manjaro") {
		return "logos:manjaro" // Colored Manjaro logo
	} else if strings.Contains(osLower, "endeavour") {
		return "devicon:archlinux" // Use Arch logo as fallback
	} else if strings.Contains(osLower, "garuda") {
		return "devicon:archlinux" // Use Arch logo as fallback
	} else if strings.Contains(osLower, "arch") {
		return "logos:archlinux" // Colored Arch Linux logo
	
	// Red Hat-based distributions
	} else if strings.Contains(osLower, "rocky") {
		return "logos:rockylinux" // Colored Rocky Linux logo
	} else if strings.Contains(osLower, "alma") {
		return "logos:almalinux" // Colored AlmaLinux logo
	} else if strings.Contains(osLower, "centos") {
		return "logos:centos" // Colored CentOS logo
	} else if strings.Contains(osLower, "red hat") || strings.Contains(osLower, "rhel") {
		return "logos:redhat" // Colored Red Hat logo
	} else if strings.Contains(osLower, "oracle") {
		return "devicon:oracle" // Oracle logo (from devicon)
	} else if strings.Contains(osLower, "fedora") {
		return "logos:fedora" // Colored Fedora logo
	
	// Independent distributions
	} else if strings.Contains(osLower, "opensuse") || strings.Contains(osLower, "suse") {
		return "logos:suse" // Colored SUSE logo
	} else if strings.Contains(osLower, "alpine") {
		return "logos:alpine" // Colored Alpine logo
	} else if strings.Contains(osLower, "gentoo") {
		return "logos:gentoo" // Colored Gentoo logo
	} else if strings.Contains(osLower, "void") {
		return "devicon:linux" // No colored icon available, use generic
	} else if strings.Contains(osLower, "slackware") {
		return "logos:slackware" // Colored Slackware logo
	} else if strings.Contains(osLower, "nixos") {
		return "logos:nixos" // Colored NixOS logo
	} else if strings.Contains(osLower, "solus") {
		return "devicon:linux" // No colored icon available, use generic
	} else if strings.Contains(osLower, "mageia") {
		return "devicon:linux" // No colored icon available, use generic
	} else if strings.Contains(osLower, "clear") {
		return "devicon:linux" // No colored icon available, use generic
	}
	
	// Default Linux icon (Tux)
	return "devicon:linux"
}

// isPrivateIP checks if an IP address is a private/local address
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
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	// Unique local: fc00::/7
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}
	// Multicast: ff00::/8
	if ip[0] == 0xff {
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

func getIPAddresses() (ipv4, ipv6 string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	
	// Collect all candidate IPs
	var ipv4Candidates []net.IP
	var ipv6Candidates []net.IP
	
	for _, iface := range interfaces {
		// Skip down interfaces and loopback
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		
		// Skip Docker, bridge, and virtual interfaces
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") ||
			strings.HasPrefix(name, "vmnet") || strings.HasPrefix(name, "lxcbr") {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			
			ip := ipNet.IP
			if ip == nil {
				continue
			}
			
			// Skip private IPs
			if isPrivateIP(ip) {
				continue
			}
			
			// Collect public IPs
			if ip4 := ip.To4(); ip4 != nil {
				ipv4Candidates = append(ipv4Candidates, ip)
			} else if ip.To16() != nil {
				ipv6Candidates = append(ipv6Candidates, ip)
			}
		}
	}
	
	// Prefer IPs from interfaces that are not point-to-point (usually better for public IPs)
	// For now, just take the first public IP found
	if len(ipv4Candidates) > 0 {
		ipv4 = ipv4Candidates[0].String()
	}
	if len(ipv6Candidates) > 0 {
		ipv6 = ipv6Candidates[0].String()
	}
	
	// If no public IP found via interfaces, try external API as fallback (only for IPv4)
	if ipv4 == "" {
		ipv4 = getPublicIPv4()
	}
	
	return ipv4, ipv6
}

// getPublicIPv4 tries to get public IPv4 from external API as fallback
// Uses multiple services including HTTP versions for better reliability in China
func getPublicIPv4() string {
	// Try multiple services for reliability, including HTTP versions (may work better in China)
	// Order: try HTTP first (less likely to be blocked), then HTTPS
	services := []string{
		"http://ifconfig.me/ip",           // HTTP version, may work better in China
		"http://icanhazip.com",            // HTTP version
		"http://api.ipify.org",            // HTTP version
		"https://api.ipify.org",           // HTTPS version
		"https://icanhazip.com",           // HTTPS version
		"https://ifconfig.me/ip",          // HTTPS version
		"http://ip.sb",                    // Alternative service (may work in China)
		"http://myip.ipip.net",            // Chinese service (should work in China)
		"http://ip.3322.net",              // Chinese service (should work in China)
	}
	
	// Use shared HTTP client for connection reuse
	httpClient := getSharedHTTPClient()
	if httpClient == nil {
		// Fallback to simple client if shared client not available
		httpClient = &http.Client{
			Timeout: 10 * time.Second, // Increased timeout for cross-continent networks
		}
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	for _, service := range services {
		req, err := http.NewRequestWithContext(ctx, "GET", service, nil)
		if err != nil {
			continue
		}
		
		req.Header.Set("User-Agent", "PulseClient/1.0")
		req.Header.Set("Accept", "text/plain, */*")
		
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == http.StatusOK {
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			ipStr := strings.TrimSpace(string(body))
			ip := net.ParseIP(ipStr)
			if ip != nil && ip.To4() != nil && !isPrivateIP(ip) {
				return ipStr
			}
		} else {
			resp.Body.Close()
		}
	}
	
	return ""
}

func getLocation() string {
	// Get location (country only)
	location := envOr("LOCATION", "")
	if location != "" {
		// Extract only country part
		parts := strings.Split(location, ",")
		if len(parts) > 0 {
			country := strings.TrimSpace(parts[len(parts)-1])
			// Remove any extra details, keep only country name
			countryParts := strings.Fields(country)
			if len(countryParts) > 0 {
				return countryParts[0]
			}
			return country
		}
		return strings.TrimSpace(location)
	}
	
	// Try to detect from system timezone or IP (simplified)
	// In production, use proper geolocation service
	return ""
}

// CPU stats tracking for accurate calculation
var (
	lastCPUStats cpuStats
	lastCPUStatsTime time.Time
	cpuStatsMutex sync.Mutex
)

type cpuStats struct {
	Total uint64
	Idle  uint64
}

func getCPUUsage() float64 {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Use instant reading (0 interval) for immediate response
		// This gets the CPU usage since last call, much faster than waiting
		percent, err := cpu.Percent(0, false)
		if err == nil && len(percent) > 0 {
			usage := percent[0]
			if usage < 0 {
				usage = 0
			}
			if usage > 100 {
				usage = 100
			}
			return usage
		}
		return 0.0
	}
	
	cpuStatsMutex.Lock()
	defer cpuStatsMutex.Unlock()
	
	// Read /proc/stat for accurate CPU usage (Linux)
	data, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				continue
			}
			
			// Parse CPU stats: user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
			var user, nice, system, idle, iowait, irq, softirq, steal, guest, guestNice uint64
			fmt.Sscanf(fields[1], "%d", &user)
			fmt.Sscanf(fields[2], "%d", &nice)
			fmt.Sscanf(fields[3], "%d", &system)
			fmt.Sscanf(fields[4], "%d", &idle)
			if len(fields) > 5 {
				fmt.Sscanf(fields[5], "%d", &iowait)
			}
			if len(fields) > 6 {
				fmt.Sscanf(fields[6], "%d", &irq)
			}
			if len(fields) > 7 {
				fmt.Sscanf(fields[7], "%d", &softirq)
			}
			if len(fields) > 8 {
				fmt.Sscanf(fields[8], "%d", &steal)
			}
			if len(fields) > 9 {
				fmt.Sscanf(fields[9], "%d", &guest)
			}
			if len(fields) > 10 {
				fmt.Sscanf(fields[10], "%d", &guestNice)
			}
			
			// Calculate total CPU time (excluding guest time to avoid double counting)
			total := user + nice + system + idle + iowait + irq + softirq + steal
			idleTotal := idle + iowait
			
			currentStats := cpuStats{
				Total: total,
				Idle:  idleTotal,
			}
			
			now := time.Now()
			
			// If we have previous stats, calculate usage percentage
			if lastCPUStats.Total > 0 && !lastCPUStatsTime.IsZero() {
				elapsed := now.Sub(lastCPUStatsTime).Seconds()
				if elapsed > 0 {
					totalDiff := float64(currentStats.Total) - float64(lastCPUStats.Total)
					idleDiff := float64(currentStats.Idle) - float64(lastCPUStats.Idle)
					
					// Handle counter wrap-around
					if totalDiff < 0 {
						totalDiff = float64(currentStats.Total)
					}
					if idleDiff < 0 {
						idleDiff = float64(currentStats.Idle)
					}
					
					if totalDiff > 0 {
						usage := ((totalDiff - idleDiff) / totalDiff) * 100.0
						if usage < 0 {
							usage = 0
						}
						if usage > 100 {
							usage = 100
						}
						
						// Update last stats
						lastCPUStats = currentStats
						lastCPUStatsTime = now
						
						return usage
					}
				}
			}
			
			// First call or no previous stats - store current stats and return 0
			lastCPUStats = currentStats
			lastCPUStatsTime = now
			return 0.0
		}
	}
	
	return 0.0
}

func getMemoryUsage() float64 {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		vmStat, err := mem.VirtualMemory()
		if err == nil {
			// Ensure percentage is within 0-100 range
			percent := vmStat.UsedPercent
			if percent < 0 {
				percent = 0
			}
			if percent > 100 {
				percent = 100
			}
			return percent
		}
		return 0.0
	}
	
	// Read /proc/meminfo for accurate memory usage (Linux)
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		// Fallback to free command
		cmd := exec.Command("sh", "-c", "free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'")
		output, err := cmd.Output()
		if err == nil {
			var mem float64
			if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &mem); err == nil {
				return mem
			}
		}
		return 0.0
	}
	
	// Parse /proc/meminfo
	var memTotal, memAvailable, memFree, buffers, cached uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		
		key := strings.TrimSuffix(fields[0], ":")
		value := fields[1]
		
		switch key {
		case "MemTotal":
			fmt.Sscanf(value, "%d", &memTotal)
		case "MemAvailable":
			fmt.Sscanf(value, "%d", &memAvailable)
		case "MemFree":
			fmt.Sscanf(value, "%d", &memFree)
		case "Buffers":
			fmt.Sscanf(value, "%d", &buffers)
		case "Cached":
			fmt.Sscanf(value, "%d", &cached)
		}
	}
	
	if memTotal == 0 {
		return 0.0
	}
	
	// Calculate used memory
	// If MemAvailable is available (kernel 3.14+), use it for more accurate calculation
	var memUsed uint64
	if memAvailable > 0 {
		memUsed = memTotal - memAvailable
	} else {
		// Fallback: MemTotal - MemFree - Buffers - Cached
		memUsed = memTotal - memFree - buffers - cached
	}
	
	// Calculate percentage
	usage := (float64(memUsed) / float64(memTotal)) * 100.0
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}
	
	return usage
}

func getDiskUsage() float64 {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Get all partitions and calculate weighted average
		partitions, err := disk.Partitions(false)
		if err == nil {
			var totalSize, totalUsed uint64
			for _, partition := range partitions {
				// Skip system reserved partitions on Windows
				if runtime.GOOS == "windows" {
					// Only include partitions with drive letters (C:, D:, etc.)
					if len(partition.Mountpoint) >= 2 && partition.Mountpoint[1] == ':' {
						usage, err := disk.Usage(partition.Mountpoint)
						if err == nil && usage.Total > 0 {
							totalSize += usage.Total
							totalUsed += usage.Used
						}
					}
				} else {
					usage, err := disk.Usage(partition.Mountpoint)
					if err == nil && usage.Total > 0 {
						totalSize += usage.Total
						totalUsed += usage.Used
					}
				}
			}
			if totalSize > 0 {
				usage := (float64(totalUsed) / float64(totalSize)) * 100.0
				if usage < 0 {
					usage = 0
				}
				if usage > 100 {
					usage = 100
				}
				return usage
			}
		}
		return 0.0
	}
	
	// Get disk usage percentage for LOCAL physical filesystems only (Linux)
	// Only include /dev/* devices, exclude virtual/network filesystems, track unique devices
	cmd := exec.Command("sh", "-c", `df -B1 -T 2>/dev/null | tail -n +2 | awk '
		$1 ~ /^\/dev\// && 
		$2 !~ /^(tmpfs|devtmpfs|squashfs|overlay|aufs|nfs|nfs4|cifs|smb|smbfs|fuse|sshfs|proc|sysfs|debugfs|securityfs|cgroup|cgroup2|pstore|bpf|tracefs|hugetlbfs|mqueue|configfs|fusectl|efivarfs|binfmt_misc|devpts|ramfs)$/ {
			if (!seen[$1]++) {
				total += $3
				used += $4
			}
		}
		END {
			if (total > 0) printf "%.1f\n", (used/total)*100
			else print "0"
		}'`)
	output, err := cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" && outputStr != "0" {
			var usage float64
			if _, err := fmt.Sscanf(outputStr, "%f", &usage); err == nil {
				if usage < 0 {
					usage = 0
				}
				if usage > 100 {
					usage = 100
				}
				return usage
			}
		}
	}
	
	// Fallback: use df -h for root partition only
	cmd = exec.Command("df", "-h", "/")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 5 {
				var used float64
				if _, err := fmt.Sscanf(fields[4], "%f%%", &used); err == nil {
					return used
				}
			}
		}
	}
	return 0.0
}

// Get system uptime from /proc/uptime (system uptime, not process uptime)
func getSystemUptime() int64 {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		uptime, err := host.Uptime()
		if err == nil {
			return int64(uptime)
		}
		// Fallback: use process uptime
		return int64(time.Since(startTime).Seconds())
	}
	
	// Try to read from /proc/uptime (Linux)
	data, err := ioutil.ReadFile("/proc/uptime")
	if err == nil {
		// Format: "12345.67 1234.56" (uptime in seconds, idle time)
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			var uptimeSeconds float64
			if _, err := fmt.Sscanf(fields[0], "%f", &uptimeSeconds); err == nil {
				return int64(uptimeSeconds)
			}
		}
	}
	
	// Fallback: use process uptime if /proc/uptime is not available
	return int64(time.Since(startTime).Seconds())
}

// Network stats tracking
var (
	lastNetStats     map[string]netInterfaceStats
	lastNetStatsTime time.Time
	netStatsMutex    sync.Mutex
)

type netInterfaceStats struct {
	RxBytes uint64
	TxBytes uint64
}

func getNetworkStats() (inMBps, outMBps float64, totalRxBytes, totalTxBytes uint64) {
	netStatsMutex.Lock()
	defer netStatsMutex.Unlock()
	
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Get network I/O statistics
		ioStats, err := netutil.IOCounters(true)
		if err != nil {
			return 0.0, 0.0, 0, 0
		}
		
		// Sum up all interfaces (excluding loopback)
		for _, stat := range ioStats {
			if stat.Name != "lo" && !strings.HasPrefix(stat.Name, "Loopback") {
				totalRxBytes += stat.BytesRecv
				totalTxBytes += stat.BytesSent
			}
		}
		
		now := time.Now()
		
		// Calculate rate if we have previous stats
		if lastNetStats != nil && !lastNetStatsTime.IsZero() {
			elapsed := now.Sub(lastNetStatsTime).Seconds()
			if elapsed > 0 {
				var prevRxBytes, prevTxBytes uint64
				for _, stats := range lastNetStats {
					prevRxBytes += stats.RxBytes
					prevTxBytes += stats.TxBytes
				}
				
				rxDiff := float64(totalRxBytes) - float64(prevRxBytes)
				txDiff := float64(totalTxBytes) - float64(prevTxBytes)
				
				// Handle counter wrap-around
				if rxDiff < 0 {
					rxDiff = float64(totalRxBytes)
				}
				if txDiff < 0 {
					txDiff = float64(totalTxBytes)
				}
				
				inMBps = (rxDiff / elapsed) / (1024 * 1024)
				outMBps = (txDiff / elapsed) / (1024 * 1024)
			}
		}
		
		// Update last stats (convert to our format)
		currentStats := make(map[string]netInterfaceStats)
		for _, stat := range ioStats {
			if stat.Name != "lo" && !strings.HasPrefix(stat.Name, "Loopback") {
				currentStats[stat.Name] = netInterfaceStats{
					RxBytes: stat.BytesRecv,
					TxBytes: stat.BytesSent,
				}
			}
		}
		lastNetStats = currentStats
		lastNetStatsTime = now
		
		return inMBps, outMBps, totalRxBytes, totalTxBytes
	}
	
	// Read current network stats from /proc/net/dev (Linux)
	currentStats := make(map[string]netInterfaceStats)
	data, err := ioutil.ReadFile("/proc/net/dev")
	if err != nil {
		return 0.0, 0.0, 0, 0
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Skip header lines
		if !strings.Contains(line, ":") {
			continue
		}
		
		// Parse line: "eth0: 123456 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
		// Format: interface: rx_bytes rx_packets ... tx_bytes tx_packets ...
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		
		interfaceName := strings.TrimSpace(parts[0])
		// Skip loopback interface
		if interfaceName == "lo" {
			continue
		}
		
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		
		var rxBytes, txBytes uint64
		fmt.Sscanf(fields[0], "%d", &rxBytes)  // Receive bytes
		fmt.Sscanf(fields[8], "%d", &txBytes)  // Transmit bytes
		
		currentStats[interfaceName] = netInterfaceStats{
			RxBytes: rxBytes,
			TxBytes: txBytes,
		}
	}
	
	// Calculate total bytes across all interfaces
	// Note: totalRxBytes and totalTxBytes are already declared as named return values
	for _, stats := range currentStats {
		totalRxBytes += stats.RxBytes
		totalTxBytes += stats.TxBytes
	}
	
	now := time.Now()
	
	// If we have previous stats, calculate rate
	if lastNetStats != nil && !lastNetStatsTime.IsZero() {
		elapsed := now.Sub(lastNetStatsTime).Seconds()
		if elapsed > 0 {
			// Calculate previous total
			var prevRxBytes, prevTxBytes uint64
			for _, stats := range lastNetStats {
				prevRxBytes += stats.RxBytes
				prevTxBytes += stats.TxBytes
			}
			
			// Calculate rate (bytes per second to MB per second)
			rxDiff := float64(totalRxBytes) - float64(prevRxBytes)
			txDiff := float64(totalTxBytes) - float64(prevTxBytes)
			
			// Handle counter wrap-around (uint64 can wrap)
			if rxDiff < 0 {
				rxDiff = float64(totalRxBytes) // Assume wrap-around, use current value
			}
			if txDiff < 0 {
				txDiff = float64(totalTxBytes) // Assume wrap-around, use current value
			}
			
			inMBps = (rxDiff / elapsed) / (1024 * 1024)  // Convert bytes/s to MB/s
			outMBps = (txDiff / elapsed) / (1024 * 1024) // Convert bytes/s to MB/s
		}
	}
	
	// Update last stats
	lastNetStats = currentStats
	lastNetStatsTime = now
	
	return inMBps, outMBps, totalRxBytes, totalTxBytes
}

// Get CPU model information in format: "Model @ SpeedGHz Count Core"
func getCPUModel() string {
	// Check cache first (only for performance, not as fallback)
	cacheMutex.RLock()
	if cpuModelCache != "" && time.Since(cpuModelCacheTime) < cacheTTL {
		cached := cpuModelCache
		cacheMutex.RUnlock()
		return cached
	}
	cacheMutex.RUnlock()
	
	var model, coreType string
	var coreCount int
	
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" {
		// Windows: Use native WMI command as primary method (faster and more reliable)
		
		// Step 1: Get CPU model name
		cmd := exec.Command("wmic", "cpu", "get", "Name", "/format:list")
		output, err := cmd.Output()
		
		if err == nil && len(output) > 0 {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Name=") {
					model = strings.TrimPrefix(line, "Name=")
					model = strings.TrimSpace(model)
					if model != "" {
						break
					}
				}
			}
		}
		
		// Step 2: Get SYSTEM total logical processors (not per-CPU)
		cmd = exec.Command("wmic", "computersystem", "get", "NumberOfLogicalProcessors", "/format:list")
		output, err = cmd.Output()
		
		if err == nil && len(output) > 0 {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "NumberOfLogicalProcessors=") {
					numStr := strings.TrimPrefix(line, "NumberOfLogicalProcessors=")
					var num int
					if _, err := fmt.Sscanf(strings.TrimSpace(numStr), "%d", &num); err == nil && num > 0 {
						coreCount = num
						break
					}
				}
			}
		}
		
		// Step 3: Get total physical cores (sum from all CPUs)
		cmd = exec.Command("wmic", "cpu", "get", "NumberOfCores", "/format:list")
		output, err = cmd.Output()
		
		var totalPhysicalCores int
		if err == nil && len(output) > 0 {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "NumberOfCores=") {
					coresStr := strings.TrimPrefix(line, "NumberOfCores=")
					var cores int
					if _, err := fmt.Sscanf(strings.TrimSpace(coresStr), "%d", &cores); err == nil && cores > 0 {
						totalPhysicalCores += cores
					}
				}
			}
		}
		
		// Use logical core count (includes hyperthreading)
		// Core type will be determined by virtualization check below
		logicalCount, _ := cpu.Counts(true)
		if logicalCount > coreCount && logicalCount > 0 {
			coreCount = logicalCount
		}
		coreType = "Physical" // Will be corrected if VPS detected
		
		// If WMIC failed, try gopsutil as fallback
		if model == "" {
			// WMIC failed, trying gopsutil
			cpuInfo, err := cpu.Info()
			if err == nil && len(cpuInfo) > 0 {
				model = strings.TrimSpace(cpuInfo[0].ModelName)
				logicalCount, _ := cpu.Counts(true)
				if logicalCount > 0 {
					coreCount = logicalCount
				} else if cpuInfo[0].Cores > 0 {
					coreCount = int(cpuInfo[0].Cores)
				}
			}
		}
		
		// Final fallback: just core count
		if model == "" {
			logicalCount, err := cpu.Counts(true)
			if err == nil && logicalCount > 0 {
				return fmt.Sprintf("CPU %d Core", logicalCount)
			}
			return ""
		}
	} else if runtime.GOOS == "darwin" {
		// macOS: Use gopsutil
		cpuInfo, err := cpu.Info()
		if err != nil {
			return ""
		}
		if len(cpuInfo) == 0 {
			return ""
		}
		model = strings.TrimSpace(cpuInfo[0].ModelName)
		if model == "" {
			return ""
		}
		
		// Get CPU cores count - use logical count (includes hyperthreading)
		logicalCount, err := cpu.Counts(true)
		if err == nil && logicalCount > 0 {
			coreCount = logicalCount
		} else if cpuInfo[0].Cores > 0 {
			coreCount = int(cpuInfo[0].Cores)
		}
		
		// Default to Physical, will be corrected below if VPS
		coreType = "Physical"
	}
	
	// For ALL platforms: Detect virtualization and correct core type
	// Clear cache to force fresh detection
	cacheMutex.Lock()
	virtualizationTypeCache = ""
	virtualizationTypeCacheTime = time.Time{}
	cacheMutex.Unlock()
	
	virtType := getVirtualizationType()
	
	// On VPS, all cores should be marked as Virtual
	// On physical server (DS), always Physical Core
	if virtType == "VPS" {
		coreType = "Virtual"
	} else {
		coreType = "Physical"
	}
	
	// Check if model already contains frequency
	// Intel CPUs usually have it (e.g., "Intel(R) Xeon(R) @ 2.10GHz")
	// AMD CPUs usually don't (e.g., "AMD Ryzen 7 5800X")
	hasFreq := strings.Contains(model, "GHz") || strings.Contains(model, "MHz")
	var speed string
	
	// Get frequency if not in model name (typically AMD CPUs)
	if !hasFreq && (runtime.GOOS == "windows" || runtime.GOOS == "darwin") {
		// For Windows/macOS, try to get frequency from gopsutil
		cpuInfo, err := cpu.Info()
		if err == nil && len(cpuInfo) > 0 && cpuInfo[0].Mhz > 0 {
			speed = fmt.Sprintf("%.2f", float64(cpuInfo[0].Mhz)/1000.0)
		}
	}
	
	// Format output
	var result string
	
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		if speed != "" && coreCount > 0 {
			// Add frequency and core count (for AMD or CPUs without frequency in model)
			result = fmt.Sprintf("%s @ %sGHz %d %s Core", model, speed, coreCount, coreType)
		} else if coreCount > 0 {
			// Just add core count (for Intel or CPUs with frequency in model)
			result = fmt.Sprintf("%s %d %s Core", model, coreCount, coreType)
		} else {
			result = model
		}
		
		// Cache the result
		cacheMutex.Lock()
		cpuModelCache = result
		cpuModelCacheTime = time.Now()
		cacheMutex.Unlock()
		
		return result
	}
	
	// Get CPU model name (Linux)
	cmd := exec.Command("sh", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	output, err := cmd.Output()
	if err == nil {
		model = strings.TrimSpace(string(output))
	}
	
	// If model not found, try lscpu
	if model == "" {
		cmd = exec.Command("sh", "-c", "lscpu | grep 'Model name' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
		output, err = cmd.Output()
		if err == nil {
			model = strings.TrimSpace(string(output))
		}
	}
	
	if model == "" {
		return ""
	}
	
	// Check if model already contains frequency
	// Intel CPUs usually have it, AMD CPUs usually don't
	hasFreqLinux := strings.Contains(model, "GHz") || strings.Contains(model, "MHz")
	var speedLinux string
	
	// Get frequency if not in model name (typically AMD CPUs)
	if !hasFreqLinux {
		// Get CPU frequency (MHz) and convert to GHz
		cmd = exec.Command("sh", "-c", "grep -m1 'cpu MHz' /proc/cpuinfo | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
		output, err = cmd.Output()
		if err == nil {
			var mhz float64
			if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &mhz); err == nil && mhz > 0 {
				speedLinux = fmt.Sprintf("%.2f", mhz/1000.0)
			}
		}
		
		// If speed not found, try lscpu
		if speedLinux == "" {
			cmd = exec.Command("sh", "-c", "lscpu | grep 'CPU MHz' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
			output, err = cmd.Output()
			if err == nil {
				var mhz float64
				if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &mhz); err == nil && mhz > 0 {
					speedLinux = fmt.Sprintf("%.2f", mhz/1000.0)
				}
			}
		}
	}
	
	
	// Check if running in virtualization environment
	isVirtualized := false
	cmd = exec.Command("sh", "-c", "lscpu | grep 'Hypervisor vendor'")
	output, err = cmd.Output()
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		isVirtualized = true
	}
	
	// Get Thread(s) per core to detect hyperthreading
	cmd = exec.Command("sh", "-c", "lscpu | grep '^Thread(s) per core:' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	output, err = cmd.Output()
	threadsPerCore := 1
	if err == nil {
		fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &threadsPerCore)
	}
	
	// Get physical cores and virtual cores from lscpu
	cmd = exec.Command("sh", "-c", "lscpu | grep '^Core(s) per socket:' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	output, err = cmd.Output()
	physicalCores := 0
	if err == nil {
		var sockets, coresPerSocket int
		fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &coresPerSocket)
		
		// Get number of sockets
		cmd = exec.Command("sh", "-c", "lscpu | grep '^Socket(s):' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
		output, err = cmd.Output()
		if err == nil {
			fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &sockets)
	}
		
		physicalCores = sockets * coresPerSocket
	}
	
	// Get total CPU count (virtual cores)
	cmd = exec.Command("sh", "-c", "lscpu | grep '^CPU(s):' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	output, err = cmd.Output()
	virtualCores := 0
	if err == nil {
		fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &virtualCores)
	}
	
	// Determine core type and count
	// VPS = Virtual Core, Physical Server (DS) = Physical Core
	if isVirtualized {
		// Running in virtualized environment - Virtual cores
		coreCount = virtualCores
		if coreCount == 0 {
			coreCount = physicalCores
		}
		coreType = "Virtual"
	} else {
		// Physical server - always Physical Core, even with hyperthreading
		// Use total logical cores (includes hyperthreading)
		if virtualCores > 0 {
			coreCount = virtualCores
		} else if physicalCores > 0 {
			coreCount = physicalCores
		} else {
			// Last resort: count from /proc/cpuinfo
			cmd = exec.Command("sh", "-c", "grep -c '^processor' /proc/cpuinfo")
			output, err = cmd.Output()
			if err == nil {
				fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &coreCount)
			}
		}
		coreType = "Physical"
	}
	
	// Format output
	// Add frequency if not already in model name (AMD CPUs)
	if speedLinux != "" && coreCount > 0 {
		return fmt.Sprintf("%s @ %sGHz %d %s Core", model, speedLinux, coreCount, coreType)
	} else if coreCount > 0 {
		return fmt.Sprintf("%s %d %s Core", model, coreCount, coreType)
	}
	
	return model
}

// Get virtualization type: "VPS" (Virtual Private Server) or "DS" (Dedicated Server)
func getVirtualizationType() string {
	// Check cache first (only for performance)
	cacheMutex.RLock()
	if virtualizationTypeCache != "" && time.Since(virtualizationTypeCacheTime) < cacheTTL {
		cached := virtualizationTypeCache
		cacheMutex.RUnlock()
		return cached
	}
	cacheMutex.RUnlock()
	
	// Windows virtualization detection
	if runtime.GOOS == "windows" {
		
		// Method 1: Check ComputerSystem Model (most reliable for VM detection)
		// Virtual machines have specific model names that physical servers never have
		cmd := exec.Command("wmic", "computersystem", "get", "model", "/format:list")
		output, err := cmd.Output()
		if err == nil {
			outputStr := strings.ToLower(string(output))
			// Exact VM model names - these are ONLY used by virtual machines
			vmModels := []string{
				"vmware virtual platform",  // VMware
				"vmware7,1",                // VMware Fusion
				"virtual machine",          // Hyper-V VM
				"virtualbox",               // VirtualBox
				"kvm",                       // KVM
				"qemu",                      // QEMU
				"hvm domu",                 // Xen HVM
				"bochs",                    // Bochs
				"amazon ec2",               // AWS
				"google compute engine",    // GCP
				"droplet",                  // DigitalOcean
			}
			for _, model := range vmModels {
				if strings.Contains(outputStr, model) {
					result := "VPS"
					cacheMutex.Lock()
					virtualizationTypeCache = result
					virtualizationTypeCacheTime = time.Now()
					cacheMutex.Unlock()
					return result
				}
			}
		}
		
		// Method 2: Check BIOS Manufacturer (not SerialNumber)
		cmd = exec.Command("wmic", "bios", "get", "manufacturer", "/format:list")
		output, err = cmd.Output()
		if err == nil {
			outputStr := strings.ToLower(string(output))
			// BIOS manufacturers that are VM-specific
			vmBiosManufacturers := []string{
				"vmware",      // VMware
				"innotek",     // VirtualBox
				"parallels",   // Parallels
				"seabios",     // QEMU/KVM
				"xen",         // Xen
				"amazon ec2",  // AWS
			}
			for _, mfr := range vmBiosManufacturers {
				if strings.Contains(outputStr, mfr) {
					result := "VPS"
					cacheMutex.Lock()
					virtualizationTypeCache = result
					virtualizationTypeCacheTime = time.Now()
					cacheMutex.Unlock()
					return result
				}
			}
		}
		
		// Method 3: Check BaseBoard (motherboard) Manufacturer
		cmd = exec.Command("wmic", "baseboard", "get", "manufacturer", "/format:list")
		output, err = cmd.Output()
		if err == nil {
			outputStr := strings.ToLower(string(output))
			// Motherboard manufacturers that are VM-specific
			vmBaseboardMfrs := []string{
				"vmware",
				"oracle corporation",  // VirtualBox
				"microsoft corporation virtual", // Azure VM (contains "virtual")
				"qemu",
				"xen",
			}
			for _, mfr := range vmBaseboardMfrs {
				if strings.Contains(outputStr, mfr) {
					result := "VPS"
					cacheMutex.Lock()
					virtualizationTypeCache = result
					virtualizationTypeCacheTime = time.Now()
					cacheMutex.Unlock()
					return result
				}
			}
		}
		
		// If none of the above detected VM, it's a physical server
		// Note: We intentionally do NOT use gopsutil host.Info() here because
		// it can return "hyperv" on physical Windows machines with Hyper-V enabled
		result := "DS"
		cacheMutex.Lock()
		virtualizationTypeCache = result
		virtualizationTypeCacheTime = time.Now()
		cacheMutex.Unlock()
		return result
	} else if runtime.GOOS == "darwin" {
		// macOS: use gopsutil
		cpuInfo, err := cpu.Info()
		if err == nil && len(cpuInfo) > 0 {
			for _, info := range cpuInfo {
				for _, flag := range info.Flags {
					if strings.ToLower(flag) == "hypervisor" {
						result := "VPS"
						cacheMutex.Lock()
						virtualizationTypeCache = result
						virtualizationTypeCacheTime = time.Now()
						cacheMutex.Unlock()
						return result
					}
				}
			}
		}
		
		hostInfo, err := host.Info()
		if err == nil {
			if hostInfo.VirtualizationSystem != "" && hostInfo.VirtualizationSystem != "none" {
				result := "VPS"
				cacheMutex.Lock()
				virtualizationTypeCache = result
				virtualizationTypeCacheTime = time.Now()
				cacheMutex.Unlock()
				return result
			}
		}
		
		result := "DS"
		cacheMutex.Lock()
		virtualizationTypeCache = result
		virtualizationTypeCacheTime = time.Now()
		cacheMutex.Unlock()
		return result
	}
	
	// Linux virtualization detection
	// Method 1: systemd-detect-virt (most reliable on modern Linux)
	cmd := exec.Command("systemd-detect-virt")
	output, err := cmd.Output()
	if err == nil {
		virtType := strings.TrimSpace(string(output))
		// "none" means physical machine, anything else means virtualized
		if virtType != "" && virtType != "none" {
			result := "VPS"
			cacheMutex.Lock()
			virtualizationTypeCache = result
			virtualizationTypeCacheTime = time.Now()
			cacheMutex.Unlock()
			return result
		}
		// If systemd-detect-virt returns "none", it's definitely a physical server
		if virtType == "none" {
			result := "DS"
			cacheMutex.Lock()
			virtualizationTypeCache = result
			virtualizationTypeCacheTime = time.Now()
			cacheMutex.Unlock()
			return result
		}
	}
	
	// Method 2: Check for hypervisor vendor in lscpu (fallback if systemd-detect-virt not available)
	cmd = exec.Command("sh", "-c", "lscpu 2>/dev/null | grep -i 'Hypervisor vendor' | cut -d':' -f2")
	output, err = cmd.Output()
	if err == nil {
		hypervisor := strings.TrimSpace(string(output))
		if hypervisor != "" {
			result := "VPS"
			cacheMutex.Lock()
			virtualizationTypeCache = result
			virtualizationTypeCacheTime = time.Now()
			cacheMutex.Unlock()
			return result
		}
	}
	
	// Method 3: Check /proc/cpuinfo for hypervisor flag
	cmd = exec.Command("sh", "-c", "grep -w 'hypervisor' /proc/cpuinfo 2>/dev/null")
	output, err = cmd.Output()
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		result := "VPS"
		cacheMutex.Lock()
		virtualizationTypeCache = result
		virtualizationTypeCacheTime = time.Now()
		cacheMutex.Unlock()
		return result
	}
	
	// Method 4: Check DMI for known virtualization products
	cmd = exec.Command("sh", "-c", "cat /sys/class/dmi/id/product_name 2>/dev/null")
	output, err = cmd.Output()
	if err == nil {
		productName := strings.ToLower(strings.TrimSpace(string(output)))
		// Only check for definite VM indicators (not "cloud" which could be physical cloud servers)
		vmIndicators := []string{"vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "parallels", "bochs", "virtual machine"}
		for _, indicator := range vmIndicators {
			if strings.Contains(productName, indicator) {
				result := "VPS"
				cacheMutex.Lock()
				virtualizationTypeCache = result
				virtualizationTypeCacheTime = time.Now()
				cacheMutex.Unlock()
				return result
			}
		}
	}
	
	// If none of the above detected virtualization, it's a dedicated server
	result := "DS"
	cacheMutex.Lock()
	virtualizationTypeCache = result
	virtualizationTypeCacheTime = time.Now()
	cacheMutex.Unlock()
	return result
}

// Get memory information in format "used / total" (e.g., "383.60 MiB / 1.88 GiB")
func getMemoryInfo() string {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		vmStat, err := mem.VirtualMemory()
		if err == nil {
			usedStr := formatBytes(vmStat.Used)
			totalStr := formatBytes(vmStat.Total)
			return fmt.Sprintf("%s / %s", usedStr, totalStr)
		}
		return ""
	}
	
	// Read /proc/meminfo for accurate memory info (Linux)
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		// Fallback to free command
		cmd := exec.Command("sh", "-c", "free -h | grep Mem | awk '{print $3 \"/\" $2}'")
		output, err := cmd.Output()
		if err == nil {
			info := strings.TrimSpace(string(output))
			if info != "" {
				parts := strings.Split(info, "/")
				if len(parts) == 2 {
					used := strings.TrimSpace(parts[0])
					total := strings.TrimSpace(parts[1])
					used = addSpaceBeforeUnit(used)
					total = addSpaceBeforeUnit(total)
					return fmt.Sprintf("%s / %s", used, total)
				}
				return info
			}
		}
		return ""
	}
	
	// Parse /proc/meminfo
	var memTotal, memAvailable, memFree, buffers, cached uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		
		key := strings.TrimSuffix(fields[0], ":")
		value := fields[1]
		
		switch key {
		case "MemTotal":
			fmt.Sscanf(value, "%d", &memTotal)
		case "MemAvailable":
			fmt.Sscanf(value, "%d", &memAvailable)
		case "MemFree":
			fmt.Sscanf(value, "%d", &memFree)
		case "Buffers":
			fmt.Sscanf(value, "%d", &buffers)
		case "Cached":
			fmt.Sscanf(value, "%d", &cached)
		}
	}
	
	if memTotal == 0 {
		return ""
	}
	
	// Calculate used memory (same logic as getMemoryUsage)
	var memUsed uint64
	if memAvailable > 0 {
		memUsed = memTotal - memAvailable
	} else {
		memUsed = memTotal - memFree - buffers - cached
	}
	
	// Convert to human-readable format
	usedStr := formatBytes(memUsed * 1024) // /proc/meminfo is in KB, convert to bytes
	totalStr := formatBytes(memTotal * 1024)
	
	return fmt.Sprintf("%s / %s", usedStr, totalStr)
}

// Get swap information in format "used / total" (e.g., "75.12 MiB / 975.00 MiB")
func getSwapInfo() string {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Windows doesn't have swap, but macOS does
		swapStat, err := mem.SwapMemory()
		if err == nil {
			if swapStat.Total > 0 {
				usedStr := formatBytes(swapStat.Used)
				totalStr := formatBytes(swapStat.Total)
				return fmt.Sprintf("%s / %s", usedStr, totalStr)
			}
		}
		// Windows/macOS: return "0 B / 0 B" to indicate no swap (instead of empty string)
		// This allows frontend to distinguish between "no data yet" (empty) and "no swap" (0 B / 0 B)
		return "0 B / 0 B"
	}
	
	// Read /proc/meminfo for accurate swap info (Linux)
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		// Fallback to free command
		cmd := exec.Command("sh", "-c", "free -h | grep Swap | awk '{print $3 \"/\" $2}'")
		output, err := cmd.Output()
		if err == nil {
			info := strings.TrimSpace(string(output))
			if info != "" && info != "/" {
				parts := strings.Split(info, "/")
				if len(parts) == 2 {
					used := strings.TrimSpace(parts[0])
					total := strings.TrimSpace(parts[1])
					if used == "" {
						used = "0"
					}
					if total == "" {
						total = "0"
					}
					used = addSpaceBeforeUnit(used)
					total = addSpaceBeforeUnit(total)
					return fmt.Sprintf("%s / %s", used, total)
				}
				return info
			}
		}
		return ""
	}
	
	// Parse /proc/meminfo for swap
	var swapTotal, swapFree uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		
		key := strings.TrimSuffix(fields[0], ":")
		value := fields[1]
		
		switch key {
		case "SwapTotal":
			fmt.Sscanf(value, "%d", &swapTotal)
		case "SwapFree":
			fmt.Sscanf(value, "%d", &swapFree)
		}
	}
	
	if swapTotal == 0 {
		// Linux: return "0 B / 0 B" to indicate no swap (instead of empty string)
		// This allows frontend to distinguish between "no data yet" (empty) and "no swap" (0 B / 0 B)
		return "0 B / 0 B"
	}
	
	// Calculate used swap
	swapUsed := swapTotal - swapFree
	
	// Convert to human-readable format
	usedStr := formatBytes(swapUsed * 1024) // /proc/meminfo is in KB, convert to bytes
	totalStr := formatBytes(swapTotal * 1024)
	
	return fmt.Sprintf("%s / %s", usedStr, totalStr)
}

// Get disk information in format "used / total" (e.g., "9.86 GiB / 18.58 GiB")
// This function aggregates all mounted filesystems (excluding tmpfs, devtmpfs, squashfs)
func getDiskInfo() string {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Get all partitions and sum up
		partitions, err := disk.Partitions(false)
		if err == nil {
			var totalSize, totalUsed uint64
			for _, partition := range partitions {
				// Skip system reserved partitions on Windows
				if runtime.GOOS == "windows" {
					// Only include partitions with drive letters (C:, D:, etc.)
					if len(partition.Mountpoint) >= 2 && partition.Mountpoint[1] == ':' {
						usage, err := disk.Usage(partition.Mountpoint)
						if err == nil && usage.Total > 0 {
							totalSize += usage.Total
							totalUsed += usage.Used
						}
					}
				} else {
					usage, err := disk.Usage(partition.Mountpoint)
					if err == nil && usage.Total > 0 {
						totalSize += usage.Total
						totalUsed += usage.Used
					}
				}
			}
			if totalSize > 0 {
				usedStr := formatBytes(totalUsed)
				totalStr := formatBytes(totalSize)
				return fmt.Sprintf("%s / %s", usedStr, totalStr)
			}
		}
		return ""
	}
	
	// Get total disk size and used space from LOCAL physical filesystems only (Linux)
	// Exclude: tmpfs, devtmpfs, squashfs, overlay, aufs (containers)
	// Exclude: nfs, nfs4, cifs, smb, smbfs, fuse, sshfs (network)
	// Exclude: proc, sysfs, debugfs, securityfs, cgroup, etc. (virtual)
	// Also filter to only include /dev/* devices to avoid duplicates
	cmd := exec.Command("sh", "-c", `df -B1 -T 2>/dev/null | tail -n +2 | awk '
		$1 ~ /^\/dev\// && 
		$2 !~ /^(tmpfs|devtmpfs|squashfs|overlay|aufs|nfs|nfs4|cifs|smb|smbfs|fuse|sshfs|proc|sysfs|debugfs|securityfs|cgroup|cgroup2|pstore|bpf|tracefs|hugetlbfs|mqueue|configfs|fusectl|efivarfs|binfmt_misc|devpts|ramfs)$/ {
			# Track unique devices to avoid double counting
			if (!seen[$1]++) {
				total += $3
				used += $4
			}
		}
		END {
			if (total > 0) printf "%.0f %.0f\n", used+0.0, total+0.0
			else print "0 0"
		}'`)
	output, err := cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" && outputStr != "0 0" {
			var usedBytes, totalBytes uint64
			fields := strings.Fields(outputStr)
			if len(fields) >= 2 {
				// Parse as uint64 to handle large numbers
				var usedFloat, totalFloat float64
				_, err1 := fmt.Sscanf(fields[0], "%f", &usedFloat)
				_, err2 := fmt.Sscanf(fields[1], "%f", &totalFloat)
				
				if err1 == nil && err2 == nil {
					usedBytes = uint64(usedFloat)
					totalBytes = uint64(totalFloat)
					
					if totalBytes > 0 && usedBytes <= totalBytes {
						usedStr := formatBytes(usedBytes)
						totalStr := formatBytes(totalBytes)
						return fmt.Sprintf("%s / %s", usedStr, totalStr)
					}
				}
			}
		}
	}
	
	// Fallback: use df -h for root partition only
	cmd = exec.Command("sh", "-c", "df -h / | tail -1 | awk '{print $3 \"/\" $2}'")
	output, err = cmd.Output()
	if err == nil {
		info := strings.TrimSpace(string(output))
		if info != "" {
			parts := strings.Split(info, "/")
			if len(parts) == 2 {
				used := strings.TrimSpace(parts[0])
				total := strings.TrimSpace(parts[1])
				// Add space before unit if missing
				used = addSpaceBeforeUnit(used)
				total = addSpaceBeforeUnit(total)
				return fmt.Sprintf("%s / %s", used, total)
			}
			return info
		}
	}
	return ""
}

// formatBytes converts bytes to human-readable format (B, KiB, MiB, GiB, TiB)
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	value := float64(bytes) / float64(div)
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	if exp < len(units) {
		// Format to 2 decimal places, remove trailing zeros
		formatted := fmt.Sprintf("%.2f", value)
		formatted = strings.TrimRight(formatted, "0")
		formatted = strings.TrimRight(formatted, ".")
		return fmt.Sprintf("%s %s", formatted, units[exp])
	}
	return fmt.Sprintf("%.2f EiB", float64(bytes)/float64(div*unit))
}

// Helper function to add space before unit and normalize to MiB/GiB format
func addSpaceBeforeUnit(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	
	// If already has space, normalize units only
	if strings.Contains(s, " ") {
		// Normalize: Gi -> GiB, Mi -> MiB, etc. (but avoid double conversion)
		if strings.HasSuffix(s, " Gi") {
			return strings.TrimSuffix(s, " Gi") + " GiB"
		}
		if strings.HasSuffix(s, " Mi") {
			return strings.TrimSuffix(s, " Mi") + " MiB"
		}
		if strings.HasSuffix(s, " Ki") {
			return strings.TrimSuffix(s, " Ki") + " KiB"
		}
		if strings.HasSuffix(s, " Ti") {
			return strings.TrimSuffix(s, " Ti") + " TiB"
		}
		if strings.HasSuffix(s, " G") && !strings.HasSuffix(s, " GiB") {
			return strings.TrimSuffix(s, " G") + " GiB"
		}
		if strings.HasSuffix(s, " M") && !strings.HasSuffix(s, " MiB") {
			return strings.TrimSuffix(s, " M") + " MiB"
		}
		if strings.HasSuffix(s, " K") && !strings.HasSuffix(s, " KiB") {
			return strings.TrimSuffix(s, " K") + " KiB"
		}
		if strings.HasSuffix(s, " T") && !strings.HasSuffix(s, " TiB") {
			return strings.TrimSuffix(s, " T") + " TiB"
		}
		return s
	}
	
	// No space: find unit and add space, then normalize
	// Try longer units first (GiB before Gi, Gi before G)
	units := []struct {
		old string
		new string
	}{
		{"TiB", " TiB"},
		{"GiB", " GiB"},
		{"MiB", " MiB"},
		{"KiB", " KiB"},
		{"TB", " TiB"},
		{"GB", " GiB"},
		{"MB", " MiB"},
		{"KB", " KiB"},
		{"Ti", " TiB"},
		{"Gi", " GiB"},
		{"Mi", " MiB"},
		{"Ki", " KiB"},
		{"T", " TiB"},
		{"G", " GiB"},
		{"M", " MiB"},
		{"K", " KiB"},
	}
	
	for _, unit := range units {
		if idx := strings.Index(s, unit.old); idx > 0 {
			// Insert space before unit and normalize
			return s[:idx] + unit.new
		}
	}
	return s
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// Auto-generated comment to trigger workflow
// Trigger workflow rebuild with static compilation
