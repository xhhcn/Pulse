package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	netutil "github.com/shirou/gopsutil/v3/net"
)

// tcpKeepAliveListener wraps a TCPListener to enable TCP keepalive on all accepted connections
// This is CRITICAL for Windows: prevents server→client connections from being dropped by firewall/NAT
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// Accept accepts a connection and enables TCP keepalive with a 60-second interval
func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	// Enable TCP keepalive with 60-second interval
	// Windows firewall typically drops idle connections after 60-120 seconds
	// By sending keepalive probes every 60 seconds, we prevent disconnections
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(60 * time.Second)
	return tc, nil
}

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
	MemoryInfo         string  `json:"memory_info,omitempty"` // Format: "383.60 MiB / 1.88 GiB"
	SwapInfo           string  `json:"swap_info,omitempty"`   // Format: "75.12 MiB / 975.00 MiB"
	Disk               float64 `json:"disk"`
	DiskInfo           string  `json:"disk_info,omitempty"` // Format: "9.86 GiB / 18.58 GiB"
	NetInMBps          float64 `json:"net_in_mb_s"`
	NetOutMBps         float64 `json:"net_out_mb_s"`
	TotalNetInBytes    uint64  `json:"total_net_in_bytes,omitempty"`  // Total received bytes
	TotalNetOutBytes   uint64  `json:"total_net_out_bytes,omitempty"` // Total transmitted bytes
	AgentVersion       string  `json:"agent_version"`
	Alert              bool    `json:"alert"`
}

var (
	agentID    string
	agentName  string
	startTime  time.Time
	serverBase string
	secret     string // Secret for authenticating metrics endpoint

	// Cache for data that doesn't change frequently
	cpuModelCache               string
	cpuModelCacheTime           time.Time
	virtualizationTypeCache     string
	virtualizationTypeCacheTime time.Time
	cacheMutex                  sync.RWMutex
	cacheTTL                    = 5 * time.Minute // Cache for 5 minutes

	// Cache for static system info (computed once, never changes)
	osInfoCache   *OSInfo
	osInfoOnce    sync.Once
	locationCache string
	locationOnce  sync.Once

	// Cache for IP addresses (changes rarely, refresh every 60 seconds)
	ipv4Cache    string
	ipv6Cache    string
	ipCacheTime  time.Time
	ipCacheMutex sync.RWMutex
	ipCacheTTL   = 60 * time.Second // Refresh IP every 60 seconds (IP rarely changes)
	// How long a previously detected address is still reported while every
	// refresh fails (see getIPAddresses).
	ipKeepStaleFor = 10 * time.Minute
	ipDetectedAt   time.Time
	// ipRefreshInFlight is true while a background refresh goroutine is running.
	// Without it every caller that sees a stale cache starts its own refresh,
	// and each refresh fires a dozen outbound requests that take seconds to
	// finish — so a single /metrics poll storm (the endpoint is unauthenticated
	// when SECRET is unset) turns into an outbound request flood. Guarded by
	// ipCacheMutex.
	ipRefreshInFlight bool

	// Shared HTTP client for connection reuse (important for cross-continent networks)
	sharedHTTPClient     *http.Client
	sharedHTTPClientOnce sync.Once

	// Per-message log throttling for logOncePerMinute (see there).
	logThrottleTimes = make(map[string]time.Time)
	logThrottleMutex sync.Mutex

	// Most recent metric payload collected by the push loop, served to /metrics
	// callers so that a poll does not rebase the CPU/network delta samplers.
	// See handleMetricsRequest.
	lastPushedMetrics     metricPayload
	lastPushedMetricsTime time.Time
	lastPushedMetricsMu   sync.Mutex

	// Push mode: TCPing targets received from server (refreshed on every push response)
	pushTCPingTargets     []string
	pushTCPingIntervalSec int = 60
	pushTCPingMu          sync.RWMutex

	// pushTCPingIntervalChanged is signalled (non-blocking) whenever the interval
	// received from the server differs from what the TCPing loop is currently using.
	// It lets startPushTCPingLoop cancel an in-flight sleep and pick up the new value
	// immediately, instead of waiting out the old (potentially much longer) cycle.
	// Capacity 1 + non-blocking send collapses bursts of updates into a single wakeup.
	pushTCPingIntervalChanged = make(chan struct{}, 1)

	// Pending TCPing results collected by startPushTCPingLoop, consumed by startPushLoop.
	// Capped at maxPendingTCPingResults to prevent unbounded growth during server downtime.
	pendingTCPingResults   []ClientTCPingResult
	pendingTCPingResultsMu sync.Mutex
)

const maxPendingTCPingResults = 500

// maxResponseBodyBytes caps how much of any HTTP response from the server (or
// from the public-IP detection services) the agent is willing to read. A
// malicious or misbehaving peer must not be able to make the agent allocate
// unbounded memory; every ReadAll/Decode on a response body goes through an
// io.LimitReader with this cap, including the drain-for-keepalive reads.
const maxResponseBodyBytes = 1 << 20 // 1 MiB

// Bounds for the TCPing configuration handed to the agent by the server.
// The server is trusted-ish, but a corrupted or hostile response must not be
// able to make the agent dial thousands of hosts or spin at a 0-second interval.
const (
	maxPushTCPingTargets     = 64
	minPushTCPingIntervalSec = 1
	maxPushTCPingIntervalSec = 86400 // 24 h
)

// tcpingHostRegex validates the host part of a TCPing target. Hostnames, IPv4
// literals and unbracketed IPv6 literals all fit this set (colons for IPv6,
// dots, hyphens, alphanumerics); anything else looks like injection.
var tcpingHostRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-:]+$`)

var (

	// Cache for disk stats (changes slowly; refreshed every 30 s to avoid spawning
	// external processes — df + awk — on every 3-second push cycle).
	diskUsageCache     float64
	diskUsageCacheTime time.Time
	diskInfoCache      string
	diskInfoCacheTime  time.Time
	diskCacheMu        sync.RWMutex
	diskCacheTTL       = 30 * time.Second
)

// applyPushTCPingConfig centralises "update targets / interval and wake the TCPing
// loop if the interval actually changed". Used by the three paths that receive a
// fresh config from the server (initial register, periodic register, push response)
// so they can't drift apart.
func applyPushTCPingConfig(targets []string, intervalSecs int) {
	sanitized := sanitizePushTCPingTargets(targets)

	// A non-positive interval means "server did not specify one"; keep whatever
	// the loop is already using. Anything else is clamped into a sane range so
	// a corrupted response cannot make the TCPing loop spin (0 s) or stall for
	// years.
	if intervalSecs > 0 {
		if intervalSecs < minPushTCPingIntervalSec {
			intervalSecs = minPushTCPingIntervalSec
		}
		if intervalSecs > maxPushTCPingIntervalSec {
			intervalSecs = maxPushTCPingIntervalSec
		}
	}

	pushTCPingMu.Lock()
	pushTCPingTargets = sanitized
	changed := false
	if intervalSecs > 0 && intervalSecs != pushTCPingIntervalSec {
		pushTCPingIntervalSec = intervalSecs
		changed = true
	}
	pushTCPingMu.Unlock()
	if changed {
		select {
		case pushTCPingIntervalChanged <- struct{}{}:
		default:
		}
	}
}

// sanitizePushTCPingTargets filters a target list received from the server
// through the same rules /tcping enforces: invalid or over-long targets are
// dropped, duplicates collapsed, and the list capped at maxPushTCPingTargets so
// one bad config cannot turn the agent into a port scanner.
//
// Entries are stored as the server sent them (whitespace-trimmed) rather than
// in normalised form, so the Target echoed back in ClientTCPingResult still
// matches the server's own configuration string. De-duplication uses the
// normalised form, which is also what validation is performed on.
func sanitizePushTCPingTargets(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}

	sanitized := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	truncated := false

	for _, target := range targets {
		normalized, err := validateTCPingTarget(target)
		if err != nil {
			continue
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		if len(sanitized) >= maxPushTCPingTargets {
			truncated = true
			break
		}
		seen[normalized] = struct{}{}
		sanitized = append(sanitized, strings.TrimSpace(target))
	}

	if truncated {
		logOncePerMinute(fmt.Sprintf("⚠️  Server sent more than %d TCPing targets; extra targets ignored.", maxPushTCPingTargets))
	}

	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

// ── macOS: background CPU sampler ────────────────────────────────────────────
// gopsutil cpu.Percent() compiled with CGO_ENABLED=0 cannot read CPU ticks on
// macOS: the Mach host_processor_info API is CGO-only and the nocgo stub
// returns [0.0] without error. Instead we run "top -l 2 -n 0" in a background
// goroutine; it blocks ~1 s to capture a real 1-second delta.
var (
	macOSCPUVal  float64
	macOSCPUMu   sync.RWMutex
	macOSCPUOnce sync.Once
)

func startMacOSCPULoop() {
	macOSCPUOnce.Do(func() {
		go func() {
			// First sample immediately so the very first push has a real value.
			v := sampleMacOSCPU()
			macOSCPUMu.Lock()
			macOSCPUVal = v
			macOSCPUMu.Unlock()
			for {
				time.Sleep(4 * time.Second)
				v = sampleMacOSCPU()
				macOSCPUMu.Lock()
				macOSCPUVal = v
				macOSCPUMu.Unlock()
			}
		}()
	})
}

// sampleMacOSCPU runs "top -l 2 -n 0" which produces two snapshots ~1 s apart.
// The second "CPU usage" line is the actual delta over that second.
func sampleMacOSCPU() float64 {
	out, err := runCommandOutput(slowProbeCommandTimeout, "sh", "-c",
		`top -l 2 -n 0 2>/dev/null | grep "CPU usage" | tail -1`)
	if err != nil {
		return 0.0
	}
	line := strings.TrimSpace(string(out))
	// Format: "CPU usage: 14.20% user, 7.10% sys, 78.69% idle"
	var user, sys float64
	if _, e := fmt.Sscanf(line, "CPU usage: %f%% user, %f%% sys", &user, &sys); e == nil {
		v := user + sys
		if v < 0 {
			v = 0
		}
		if v > 100 {
			v = 100
		}
		return v
	}
	return 0.0
}

// ── macOS: direct memory stats via vm_stat + sysctl ──────────────────────────
// gopsutil mem.VirtualMemory() with CGO_ENABLED=0 on macOS also uses Mach APIs
// in the CGO path; the nocgo path may misreport or fail on Apple Silicon.
// We read hw.memsize and vm_stat directly instead.
func macOSMemoryStats() (usedPct float64, usedBytes, totalBytes uint64, err error) {
	// Total physical RAM
	out, e := runCommandOutput(probeCommandTimeout, "sysctl", "-n", "hw.memsize")
	if e != nil {
		return 0, 0, 0, e
	}
	if _, e = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &totalBytes); e != nil || totalBytes == 0 {
		return 0, 0, 0, fmt.Errorf("bad hw.memsize")
	}

	// Page size (4096 on Intel, 16384 on Apple Silicon)
	pageSize := uint64(4096)
	if out, e = runCommandOutput(probeCommandTimeout, "sysctl", "-n", "hw.pagesize"); e == nil {
		fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pageSize)
	}

	// Parse vm_stat for page counts
	out, e = runCommandOutput(probeCommandTimeout, "vm_stat")
	if e != nil {
		return 0, 0, totalBytes, e
	}
	var active, wired, compressed uint64
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimRight(strings.TrimSpace(parts[1]), ".")
		var n uint64
		if _, e := fmt.Sscanf(val, "%d", &n); e != nil {
			continue
		}
		switch {
		case strings.HasPrefix(key, "Pages active"):
			active = n
		case strings.HasPrefix(key, "Pages wired down"):
			wired = n
		case strings.HasPrefix(key, "Pages occupied by compressor"):
			compressed = n
		}
	}
	usedBytes = (active + wired + compressed) * pageSize
	if usedBytes > totalBytes {
		usedBytes = totalBytes
	}
	usedPct = float64(usedBytes) / float64(totalBytes) * 100.0
	return usedPct, usedBytes, totalBytes, nil
}

// ── macOS: swap via sysctl vm.swapusage ──────────────────────────────────────
// Output format: "total = 3072.00M  used = 2097.25M  free = 974.75M (encrypted)"
func macOSSwapStats() (usedBytes, totalBytes uint64) {
	out, err := runCommandOutput(probeCommandTimeout, "sysctl", "-n", "vm.swapusage")
	if err != nil {
		return 0, 0
	}
	line := strings.TrimSpace(string(out))
	re := regexp.MustCompile(`total\s*=\s*([\d.]+)M.*used\s*=\s*([\d.]+)M`)
	m := re.FindStringSubmatch(line)
	if len(m) == 3 {
		var totalMB, usedMB float64
		fmt.Sscanf(m[1], "%f", &totalMB)
		fmt.Sscanf(m[2], "%f", &usedMB)
		totalBytes = uint64(totalMB * 1024 * 1024)
		usedBytes = uint64(usedMB * 1024 * 1024)
	}
	return usedBytes, totalBytes
}

// macOSMarketingName maps a macOS major version to Apple's marketing
// name ("Sonoma", "Sequoia", …). Returns "" for versions we don't have
// a mapping for — the caller then falls back to just the number. The
// table only needs the major version because Apple keeps the marketing
// name stable across minor releases (14.0 through 14.x are all Sonoma).
func macOSMarketingName(productVersion string) string {
	major := productVersion
	if i := strings.Index(productVersion, "."); i > 0 {
		major = productVersion[:i]
	}
	switch major {
	case "15":
		return "Sequoia"
	case "14":
		return "Sonoma"
	case "13":
		return "Ventura"
	case "12":
		return "Monterey"
	case "11":
		return "Big Sur"
	case "10":
		// 10.15 Catalina / 10.14 Mojave / 10.13 High Sierra / 10.12 Sierra …
		// The two-component check keeps us useful on legacy systems
		// without bloating the table with every minor.
		switch {
		case strings.HasPrefix(productVersion, "10.15"):
			return "Catalina"
		case strings.HasPrefix(productVersion, "10.14"):
			return "Mojave"
		case strings.HasPrefix(productVersion, "10.13"):
			return "High Sierra"
		}
	}
	return ""
}

// appleSiliconNominalGHz returns the nominal max performance-core clock
// for the given Apple Silicon chip name, or 0 if the name is not
// recognised (e.g. an Intel Mac). The numbers come from Apple's published
// specs for each M-series chip generation; they're deliberately ordered
// longest-prefix-first so that "Apple M2 Max" matches the M2-family entry
// before falling through to the bare "Apple M2" entry.
//
// Why a hard-coded table: on Apple Silicon there is no single sysctl that
// reports the nominal clock — hw.cpufrequency, hw.cpufrequency_max and
// machdep.tbfrequency are either 0, not present, or a timebase (not the
// actual CPU clock). A curated table is small, keeps the display accurate,
// and degrades gracefully to "no GHz" for chips we don't know about yet
// (future M5, etc.) instead of lying.
func appleSiliconNominalGHz(model string) float64 {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" || !strings.Contains(m, "apple") {
		return 0
	}
	// Longest prefixes first so "Apple M2 Max" doesn't match "Apple M2"
	// first and silently pick up the wrong clock.
	switch {
	case strings.Contains(m, "m4"):
		return 4.40
	case strings.Contains(m, "m3"):
		return 4.05
	case strings.Contains(m, "m2"):
		return 3.50
	case strings.Contains(m, "m1"):
		return 3.20
	}
	return 0
}

// ClientTCPingResult is one TCPing measurement to be sent to the server in push mode.
//
// MeasuredAt is the moment the TCP dial completed on the client (UTC). Including it
// lets the server stamp the history record with the real measurement time instead of
// "whenever the next 3-second push happened to arrive", which previously produced
// jittered 3/6/10-second gaps on charts for a cleanly-configured, e.g. 5-second,
// polling interval. Empty / zero timestamps are treated as "use server time" for
// backward compatibility with older clients.
//
// Skipped marks a probe this host was physically unable to attempt (see
// classifyDialError) — e.g. an IPv6 target on a machine with no IPv6 route.
// Such a result is NOT packet loss: the server is expected to record no data
// point rather than a failure, so a mis-targeted probe stops showing up as a
// permanent 50 % loss on the dashboard. Omitted from the wire when false, so
// older servers see exactly the payload they see today.
type ClientTCPingResult struct {
	Target     string    `json:"target"`
	Latency    float64   `json:"latency"` // milliseconds; 0 if failed
	Success    bool      `json:"success"`
	MeasuredAt time.Time `json:"measured_at,omitempty"`
	Skipped    bool      `json:"skipped,omitempty"`
}

// ClientPushResponse is the server's reply to a push request
type ClientPushResponse struct {
	TCPingTargets      []string `json:"tcping_targets"`
	TCPingIntervalSecs int      `json:"tcping_interval_secs"`
}

// RegisterResponse is the server's reply to a registration request
type RegisterResponse struct {
	Message            string   `json:"message"`
	ID                 string   `json:"id"`
	TCPingTargets      []string `json:"tcping_targets"`
	TCPingIntervalSecs int      `json:"tcping_interval_secs"`
}

func main() {
	agentID = envOr("AGENT_ID", "localhost")
	agentName = envOr("AGENT_NAME", agentID)
	serverBase = strings.TrimSuffix(envOr("SERVER_BASE", "http://localhost:8080"), "/")
	clientPort := envOr("CLIENT_PORT", "9090")
	secret = envOr("SECRET", "")

	// Record start time for uptime calculation
	startTime = time.Now()

	log.Printf("🚀 Starting Probe Client (ID: %s, Name: %s)", agentID, agentName)

	// macOS: start background CPU sampler early so the first push has a real value
	if runtime.GOOS == "darwin" {
		startMacOSCPULoop()
	}

	// Initial registration with server
	go registerWithServer()

	// Start periodic re-registration to maintain connection
	// This ensures the client auto-recovers if removed from server registry
	go startPeriodicRegistration()

	// Push mode: always push metrics to server every 3 seconds.
	// This makes the client work behind NAT or with outbound-only connectivity
	// because the server never needs to initiate a connection to the client.
	// For clients with a public IP the server can still pull; push is additive.
	go startPushLoop()
	go startPushTCPingLoop()

	// Start HTTP server to receive requests from backend
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", handleMetricsRequest)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/tcping", handleTCPingRequest)

	addr := ":" + clientPort
	log.Printf("📡 Client listening on %s", addr)

	// Create HTTP server with proper timeouts and keepalive settings
	// This is CRITICAL for Windows: prevents server→client connections from being dropped by firewall/NAT
	server := &http.Server{
		Addr:           addr,
		Handler:        mux,
		ReadTimeout:    30 * time.Second,  // Timeout for reading the entire request (including body)
		WriteTimeout:   30 * time.Second,  // Timeout for writing the response
		IdleTimeout:    120 * time.Second, // Keep idle connections alive (HTTP level)
		MaxHeaderBytes: 1 << 20,           // 1 MB max header size (security)
	}

	// Create custom listener with TCP keepalive enabled
	// This is CRITICAL for Windows: prevents server→client connections from being dropped by firewall/NAT
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("❌ Failed to create listener: %v", err)
	}

	// Wrap listener to enable TCP keepalive (60s) on all accepted connections
	// This solves the Windows auto-disconnect issue
	tcpListener := &tcpKeepAliveListener{listener.(*net.TCPListener)}

	log.Printf("✅ TCP keepalive enabled (60s interval) for Windows compatibility")

	// Serve in a goroutine so main() can react to shutdown signals below.
	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.Serve(tcpListener); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	// Graceful shutdown on SIGTERM/SIGINT. This matters on every platform but
	// especially inside `docker stop`: without it, in-flight /metrics and
	// /tcping responses get truncated mid-write and the server side logs them
	// as transient failures (and double-counts toward offline detection).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("🛑 Shutdown signal received, draining in-flight requests...")
	case err := <-serverErrCh:
		if err != nil {
			log.Fatalf("❌ Failed to start client server: %v", err)
		}
		return
	}

	// Give any in-flight /metrics or /tcping call up to 10 s to finish so the
	// server side sees a clean 200 instead of a truncated connection. 10 s is
	// comfortably below typical container stop-grace windows (30 s default).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️  client server shutdown returned: %v", err)
	} else {
		log.Println("✅ Client server shut down cleanly")
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
					Timeout:   15 * time.Second,  // Increased to 15s for slow connections (DNS + TCP)
					KeepAlive: 120 * time.Second, // Longer keep-alive for connection reuse
				}).DialContext,
				MaxIdleConns:          50,                // More idle connections for better reuse
				MaxIdleConnsPerHost:   20,                // More per-host connections
				IdleConnTimeout:       180 * time.Second, // Longer idle timeout
				TLSHandshakeTimeout:   15 * time.Second,  // Increased to 15s for slow TLS (GFW interference)
				ResponseHeaderTimeout: 10 * time.Second,  // Wait up to 10s for response headers
				ExpectContinueTimeout: 5 * time.Second,
				DisableCompression:    false, // Enable compression
				DisableKeepAlives:     false, // Enable keep-alive (critical for connection reuse)
			},
		}
	})
	return sharedHTTPClient
}

const (
	// logThrottleInterval is how long a given message stays suppressed after
	// it has been logged.
	logThrottleInterval = 1 * time.Minute
	// logThrottleMaxEntries is the map size above which stale entries are
	// pruned, so server-supplied text (TCPing target names) cannot grow the
	// map without bound.
	logThrottleMaxEntries = 128
	// logThrottleRetention is how long an entry is kept when pruning. Anything
	// older than logThrottleInterval can no longer suppress a message, so this
	// is deliberately generous.
	logThrottleRetention = 2 * time.Minute
)

// logOncePerMinute logs a message at most once per minute to avoid log spam.
//
// The throttle is keyed on the message itself. A single shared timestamp (what
// this used to be) means the first caller in any minute silences every other
// caller: the per-target "TCPing skipped" notice fires on every cycle and used
// to permanently suppress the "no SECRET configured" security warning, which
// therefore never reached the log.
func logOncePerMinute(message string) {
	logThrottleMutex.Lock()
	defer logThrottleMutex.Unlock()

	now := time.Now()
	if last, seen := logThrottleTimes[message]; seen && now.Sub(last) < logThrottleInterval {
		return
	}

	if len(logThrottleTimes) > logThrottleMaxEntries {
		for msg, t := range logThrottleTimes {
			if now.Sub(t) > logThrottleRetention {
				delete(logThrottleTimes, msg)
			}
		}
	}

	log.Println(message)
	logThrottleTimes[message] = now
}

// runCommandOutput runs an external command with a hard deadline and returns
// its standard output.
//
// Every system probe the agent shells out to (df, sysctl, lscpu, wmic, ...)
// runs on the push path, and several of them can block forever: `df` wedges on
// a dead NFS/CIFS mount, `wmic` on a stuck WMI service, `lscpu` on a hung
// sysfs. exec.Command applies no timeout whatsoever, so one hung probe used to
// stall metric collection — and with it the 3-second push loop — indefinitely.
//
// On timeout the context kills the process and this returns ctx.Err()-flavoured
// failure, which is the same error shape the call sites already handle: each
// one falls back to its cached value or to the default it uses when the command
// is missing, so a timed-out probe degrades exactly like an absent one.
func runCommandOutput(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

const (
	// probeCommandTimeout bounds the quick probes: df, sysctl, uname,
	// systemd-detect-virt, sw_vers and the /proc greps.
	probeCommandTimeout = 5 * time.Second
	// slowProbeCommandTimeout bounds the probes that are routinely slow even
	// on a healthy machine: wmic spins up a WMI query, lscpu walks every CPU,
	// system_profiler builds a full hardware report and `top -l 2` samples for
	// a second by design.
	slowProbeCommandTimeout = 10 * time.Second
)

// Register client with server
func registerWithServer() {
	// Retry registration with linear backoff: the pause before attempt i is
	// (i+1) seconds, so 1 s, 2 s, 3 s … 10 s, about 55 s of waiting across all
	// ten attempts. Deliberately not exponential — cross-continent registration
	// usually succeeds after a few seconds, and doubling would push the last
	// attempts minutes out.
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

		resp, err := httpClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			cancel()
			log.Printf("⚠️  Registration attempt %d/%d failed: %v", i+1, maxRetries, err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			// Parse registration response to get initial TCPing targets for push mode
			var regResp RegisterResponse
			if body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes)); readErr == nil {
				if jsonErr := json.Unmarshal(body, &regResp); jsonErr == nil {
					applyPushTCPingConfig(regResp.TCPingTargets, regResp.TCPingIntervalSecs)
				}
			}
			resp.Body.Close()
			cancel()
			log.Printf("✅ Successfully registered with server (ID: %s, IPv4: %s, IPv6: %s)", agentID, ipv4, ipv6)
			return
		} else {
			// Read error response body for debugging
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
			resp.Body.Close()
			cancel()
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

// startPeriodicRegistration maintains connection with server by periodically re-registering.
// For push-mode clients the push itself proves liveness, so this only needs to run
// infrequently (60 s) as a recovery mechanism for server restarts or config changes.
func startPeriodicRegistration() {
	// Wait for initial registration to complete before starting the loop.
	time.Sleep(10 * time.Second)

	ticker := time.NewTicker(60 * time.Second) // 60 s — push already keeps client alive
	defer ticker.Stop()

	httpClient := getSharedHTTPClient()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		ipv4, ipv6 := getIPAddresses()
		if ipv4 == "" {
			ipv4 = getLocalIP()
		}

		payload := map[string]interface{}{
			"id":   agentID,
			"name": agentName,
			"port": envOr("CLIENT_PORT", "9090"),
			"ip":   ipv4,
		}
		if ipv6 != "" {
			payload["ipv6"] = ipv6
		}
		if s := envOr("SECRET", ""); s != "" {
			payload["secret"] = s
		}

		data, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, "POST", serverBase+"/api/clients/register", strings.NewReader(string(data)))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "PulseClient/1.0")

		resp, err := httpClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			cancel()
			continue
		}

		// ✅ Always fully drain the body before closing to enable HTTP keep-alive
		// connection reuse. For 200, parse TCPing config; for other statuses, discard.
		if resp.StatusCode == http.StatusOK {
			var regResp RegisterResponse
			if body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes)); readErr == nil {
				if jsonErr := json.Unmarshal(body, &regResp); jsonErr == nil {
					applyPushTCPingConfig(regResp.TCPingTargets, regResp.TCPingIntervalSecs)
				}
			}
		} else {
			io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes)) //nolint:errcheck
		}
		resp.Body.Close()
		cancel()
	}
}

// secretEqual mirrors the server-side helper of the same name: a
// constant-time comparison so an attacker probing /metrics or /tcping cannot
// recover the secret byte by byte from response timing.
func secretEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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

		if !secretEqual(providedSecret, secret) {
			http.Error(w, "unauthorized: invalid secret", http.StatusUnauthorized)
			return
		}
	} else {
		// SECURITY WARNING: No secret configured - allowing access for backward compatibility
		// This is insecure and should be fixed by configuring SECRET environment variable
		// Log warning only once per minute to avoid log spam
		logOncePerMinute("⚠️  SECURITY WARNING: /metrics endpoint is accessible without authentication. Please configure SECRET environment variable for security.")
	}

	// Serve the payload the push loop most recently collected, when it is still
	// fresh.
	//
	// getCPUUsage and getNetworkStats are delta samplers: each one stores the
	// counters it read and reports the change since the previous reading. They
	// are package-level state shared by both paths, so collecting here would
	// consume the interval the push loop is about to report and make the next
	// push show a near-zero delta over a few milliseconds. A poller hitting
	// /metrics (unauthenticated when SECRET is unset) could therefore distort
	// every CPU and traffic figure the server records.
	//
	// The push loop runs unconditionally (see main), so the snapshot is the
	// normal path. The fallback covers the first seconds after start, before
	// the first push, and any future pull-only build with no push loop.
	metrics, fresh := recentMetricsSnapshot()
	if !fresh {
		metrics = collectSystemMetrics()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// metricsSnapshotMaxAge is how old the push loop's last payload may be and
// still be served to a /metrics caller. The push loop collects every 3 s, so 5 s
// keeps the endpoint on the snapshot path across one missed cycle while never
// serving data a caller would consider stale.
const metricsSnapshotMaxAge = 5 * time.Second

// storeMetricsSnapshot records the payload the push loop just collected.
func storeMetricsSnapshot(m metricPayload) {
	lastPushedMetricsMu.Lock()
	lastPushedMetrics = m
	lastPushedMetricsTime = time.Now()
	lastPushedMetricsMu.Unlock()
}

// recentMetricsSnapshot returns the most recent payload collected by the push
// loop and whether it is younger than metricsSnapshotMaxAge.
func recentMetricsSnapshot() (metricPayload, bool) {
	lastPushedMetricsMu.Lock()
	defer lastPushedMetricsMu.Unlock()
	if lastPushedMetricsTime.IsZero() || time.Since(lastPushedMetricsTime) > metricsSnapshotMaxAge {
		return metricPayload{}, false
	}
	return lastPushedMetrics, true
}

// Handle health check
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// TCPingResponse represents the response from tcping
//
// Skipped means the agent could not attempt the probe from this host at all
// (see classifyDialError); the reply is still HTTP 200 with success:false, but
// the caller must treat it as "no measurement" rather than as packet loss.
type TCPingResponse struct {
	Latency float64 `json:"latency"` // Latency in milliseconds
	Success bool    `json:"success"`
	Error   string  `json:"error,omitempty"`
	Skipped bool    `json:"skipped,omitempty"`
}

// TCPingRequest represents the request from backend
type TCPingRequest struct {
	Target string `json:"target"`
}

// validateTCPingTarget validates a TCPing target and returns a dial-ready
// "host:port" form of it.
//
// It is the single source of truth for what the agent is willing to dial, used
// both for targets pushed in by the backend over /tcping and for the target
// list the server hands back in register/push responses:
//   - length capped at 255 (RFC 1035 domain-name limit) to bound the work,
//   - host/port split via net.SplitHostPort so IPv6 literals in brackets
//     ("[::1]:443" → "::1", "443") survive; a target without a port defaults
//     to port 80 on the bare host,
//   - port must parse and fall in 1-65535,
//   - host must match tcpingHostRegex, which rejects whitespace and anything
//     that looks like shell/URL injection.
//
// The returned string is net.JoinHostPort(host, port), i.e. IPv6 literals come
// back bracketed, which is what net.DialTimeout expects.
func validateTCPingTarget(target string) (string, error) {
	if target == "" {
		return "", errors.New("target is required")
	}

	target = strings.TrimSpace(target)
	if len(target) > 255 {
		return "", errors.New("target address too long")
	}

	// Parse host/port. Prefer net.SplitHostPort because it correctly handles
	// IPv6 literals wrapped in brackets ("[::1]:443" → "::1", "443"), which a
	// naive strings.SplitN(":", 2) would mangle into ("[", ":1]:443") and
	// silently reject every IPv6 TCPing target with a 400 error.
	var host, portStr string
	if h, p, splitErr := net.SplitHostPort(target); splitErr == nil {
		host = strings.TrimSpace(h)
		portStr = strings.TrimSpace(p)
	} else {
		// No port in target (or malformed). Default to port 80 on the bare
		// host. This matches the previous behaviour for ":"-free inputs; for
		// bracketed IPv6 literals without a port ("[::1]") we strip brackets.
		host = strings.TrimSpace(target)
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		portStr = "80"
	}

	if host == "" {
		return "", errors.New("target host cannot be empty")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid port number (must be 1-65535)")
	}

	// Validate host characters BEFORE reconstructing the dial target so we
	// still reject injection-looking inputs.
	if !tcpingHostRegex.MatchString(host) {
		return "", errors.New("invalid target host format")
	}

	// net.JoinHostPort wraps IPv6 literals in brackets automatically
	// ("::1" + "443" → "[::1]:443"), the format net.DialTimeout expects.
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// Handle tcping request from backend
func handleTCPingRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)

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

		if !secretEqual(providedSecret, secret) {
			http.Error(w, "unauthorized: invalid secret", http.StatusUnauthorized)
			return
		}
	} else {
		// SECURITY: No secret configured - refuse to run TCPing at all.
		// /tcping turns the agent into an arbitrary TCP connect scanner, so
		// unlike /metrics (read-only, kept open for backward compatibility) it
		// is disabled outright until SECRET is configured.
		logOncePerMinute("⚠️  SECURITY WARNING: /tcping endpoint is disabled because no SECRET environment variable is configured.")
		http.Error(w, "tcping disabled: no SECRET configured", http.StatusForbidden)
		return
	}

	// Parse target from request body
	var tcpingReq TCPingRequest
	if err := json.NewDecoder(r.Body).Decode(&tcpingReq); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate and normalize target address (length, format,
	// port range, host charset). Target must be provided by backend - no
	// default fallback.
	target, err := validateTCPingTarget(tcpingReq.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Execute tcping to target specified by backend
	latency, err := executeTCPing(target)

	response := TCPingResponse{
		Success: err == nil,
		Latency: latency,
		Skipped: classifyDialError(err),
	}

	if err != nil {
		response.Error = err.Error()
		if response.Skipped {
			// Throttled: a mis-targeted probe fails on every single poll, and
			// the operator only needs to be told once why this target has no
			// data. Still HTTP 200 — the caller distinguishes via "skipped".
			logOncePerMinute(fmt.Sprintf("⏭️  TCPing to %s skipped: %v (this host cannot reach that address family — reporting no data instead of packet loss)", target, err))
		} else {
			log.Printf("❌ TCPing to %s failed: %v", target, err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// classifyDialError reports whether a failed TCPing dial means the probe could
// not be attempted from this host at all, as opposed to the target being down.
//
// The motivating bug: a monitored machine with no IPv6 connectivity is given an
// IPv6 tcping target. Every probe fails in ~0 ms with ENETUNREACH, the agent
// reports success:false, and the dashboard shows a flat 50 % packet loss for a
// probe that never once left the box. "Cannot attempt" and "target down" are
// different facts and must be reported differently.
//
// Only three errnos qualify (per platform, see tcping_errno_unix.go /
// tcping_errno_windows.go): ENETUNREACH, EAFNOSUPPORT and EADDRNOTAVAIL — no
// route for that address family, family disabled outright, or no local source
// address to bind. Everything else stays loss: a timeout (no errno at all),
// ECONNREFUSED (the host answered with an RST, so it is up), EHOSTUNREACH (the
// network is reachable, that one host is not), EINVAL (a malformed target such
// as a link-local literal missing its zone) and DNS failures (*net.DNSError,
// which carries no syscall.Errno).
//
// The error chain from net.DialTimeout is
// *net.OpError → *os.SyscallError → syscall.Errno, and both links implement
// Unwrap, so a single errors.As reaches the errno regardless of depth. It also
// sees through executeTCPing's own %w wrapping.
func classifyDialError(err error) (skipped bool) {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return isUnattemptableErrno(errno)
}

// Execute tcping command
//
// The returned error wraps the dial error with %w so callers can hand it to
// classifyDialError; the message text is unchanged from the %v form that the
// /tcping response has always reported.
func executeTCPing(target string) (float64, error) {
	// Use net.DialTimeout to measure TCP connection latency
	// Use shorter timeout (3 seconds) to avoid blocking the HTTP request handler too long
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return 0, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	latency := time.Since(start).Seconds() * 1000 // Convert to milliseconds
	return latency, nil
}

// pushHTTPClient is a dedicated HTTP client for push requests.
// It uses a shorter timeout than the shared client so that a slow server
// response does not delay the next push cycle beyond the 3-second ticker interval.
var (
	pushHTTPClient     *http.Client
	pushHTTPClientOnce sync.Once
)

func getPushHTTPClient() *http.Client {
	pushHTTPClientOnce.Do(func() {
		pushHTTPClient = &http.Client{
			Timeout: 8 * time.Second, // Must be < push interval × offline_threshold / push_interval
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   6 * time.Second,
					KeepAlive: 120 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   6 * time.Second,
				ResponseHeaderTimeout: 6 * time.Second,
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   5,
				IdleConnTimeout:       90 * time.Second,
			},
		}
	})
	return pushHTTPClient
}

// startPushLoop pushes collected system metrics to the server every 3 seconds.
// This enables NAT and outbound-only clients to work without the server needing
// to make inbound connections.  Push is always active; pull (HTTP server) remains
// available as a parallel path for directly reachable clients.
func startPushLoop() {
	// Short initial delay so the first registration can complete before we push.
	time.Sleep(4 * time.Second)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	httpClient := getPushHTTPClient()

	for range ticker.C {
		// Collect current system metrics. This loop owns the CPU/network delta
		// samplers; the snapshot it publishes is what /metrics serves, so a
		// pull never rebases those samplers mid-interval.
		metrics := collectSystemMetrics()
		storeMetricsSnapshot(metrics)

		// Drain any pending TCPing results accumulated by startPushTCPingLoop.
		// We drain into a local variable and put them back on any transient
		// failure (marshal error, request error, 5xx) so a flaky network never
		// loses a measurement. The one case where drained results are dropped
		// on purpose is a 404/401 reply — see that branch below.
		pendingTCPingResultsMu.Lock()
		tcpingResults := pendingTCPingResults
		pendingTCPingResults = nil
		pendingTCPingResultsMu.Unlock()

		// Build push payload (metric fields are inlined via embedding)
		pushPayload := struct {
			metricPayload
			Secret        string               `json:"secret,omitempty"`
			TCPingResults []ClientTCPingResult `json:"tcping_results,omitempty"`
		}{
			metricPayload: metrics,
			TCPingResults: tcpingResults,
		}
		if secret != "" {
			pushPayload.Secret = secret
		}

		data, err := json.Marshal(pushPayload)
		if err != nil {
			// Put TCPing results back so they are not lost
			if len(tcpingResults) > 0 {
				pendingTCPingResultsMu.Lock()
				combined := append(tcpingResults, pendingTCPingResults...)
				if len(combined) > maxPendingTCPingResults {
					combined = combined[len(combined)-maxPendingTCPingResults:]
				}
				pendingTCPingResults = combined
				pendingTCPingResultsMu.Unlock()
			}
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, reqErr := http.NewRequestWithContext(ctx, "POST", serverBase+"/api/clients/push", strings.NewReader(string(data)))
		if reqErr != nil {
			cancel()
			// Put TCPing results back
			if len(tcpingResults) > 0 {
				pendingTCPingResultsMu.Lock()
				combined := append(tcpingResults, pendingTCPingResults...)
				if len(combined) > maxPendingTCPingResults {
					combined = combined[len(combined)-maxPendingTCPingResults:]
				}
				pendingTCPingResults = combined
				pendingTCPingResultsMu.Unlock()
			}
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "PulseClient/1.0")
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}

		resp, doErr := httpClient.Do(req)
		if doErr != nil {
			if resp != nil {
				resp.Body.Close()
			}
			cancel()
			// Push failed — put TCPing results back so they are included in the next push
			if len(tcpingResults) > 0 {
				pendingTCPingResultsMu.Lock()
				combined := append(tcpingResults, pendingTCPingResults...)
				if len(combined) > maxPendingTCPingResults {
					combined = combined[len(combined)-maxPendingTCPingResults:]
				}
				pendingTCPingResults = combined
				pendingTCPingResultsMu.Unlock()
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			// Parse updated TCPing config from server response (bounded to
			// maxResponseBodyBytes like every other response the agent reads).
			// json.NewDecoder reads the full small body into its buffer in one
			// syscall, so resp.Body is at EOF after Decode; no extra drain needed.
			var pushResp ClientPushResponse
			if decErr := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&pushResp); decErr == nil {
				applyPushTCPingConfig(pushResp.TCPingTargets, pushResp.TCPingIntervalSecs)
			} else {
				// Decode failed — drain remainder to enable connection reuse
				io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes)) //nolint:errcheck
			}
		} else if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
			// The server does not know this client ID, or the secret is wrong.
			// These results are discarded on purpose — this is the deliberate
			// exception to "no result is lost on failure". Retrying cannot help
			// (both conditions persist until an admin re-registers the client or
			// fixes SECRET) and re-queueing would grow the backlog until the cap
			// evicts the measurements anyway.
			io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes)) //nolint:errcheck // drain to enable connection reuse
		} else {
			// Transient server error — preserve TCPing results for next cycle
			io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes)) //nolint:errcheck // drain to enable connection reuse
			if len(tcpingResults) > 0 {
				pendingTCPingResultsMu.Lock()
				combined := append(tcpingResults, pendingTCPingResults...)
				if len(combined) > maxPendingTCPingResults {
					combined = combined[len(combined)-maxPendingTCPingResults:]
				}
				pendingTCPingResults = combined
				pendingTCPingResultsMu.Unlock()
			}
		}
		resp.Body.Close()
		cancel()
	}
}

// currentPushTCPingConfig returns a snapshot of the current targets and the
// sanitised (> 0) measurement interval in seconds.
func currentPushTCPingConfig() ([]string, int) {
	pushTCPingMu.RLock()
	targets := make([]string, len(pushTCPingTargets))
	copy(targets, pushTCPingTargets)
	interval := pushTCPingIntervalSec
	pushTCPingMu.RUnlock()
	if interval <= 0 {
		interval = 60
	}
	return targets, interval
}

// measureTCPingOnce runs a concurrent TCPing dial for every configured target
// and stamps each result with the real MeasuredAt timestamp. Results are queued
// for startPushLoop to deliver on the next 3-second push cycle.
func measureTCPingOnce(targets []string) {
	if len(targets) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			latency, err := executeTCPing(tgt)
			skipped := classifyDialError(err)
			if skipped {
				// Throttled: this fires on every cycle for a mis-targeted
				// probe (e.g. an IPv6 target on a v4-only host), so log the
				// reason at most once a minute rather than per probe.
				logOncePerMinute(fmt.Sprintf("⏭️  TCPing target %s skipped: %v (this host cannot reach that address family — reporting no data instead of packet loss)", tgt, err))
			}
			result := ClientTCPingResult{
				Target:     tgt,
				Latency:    latency,
				Success:    err == nil,
				MeasuredAt: time.Now().UTC(),
				Skipped:    skipped,
			}
			pendingTCPingResultsMu.Lock()
			if len(pendingTCPingResults) >= maxPendingTCPingResults {
				// Drop oldest on overflow so long server outages do not grow the
				// queue unboundedly.
				pendingTCPingResults = pendingTCPingResults[1:]
			}
			pendingTCPingResults = append(pendingTCPingResults, result)
			pendingTCPingResultsMu.Unlock()
		}(target)
	}
	wg.Wait()
}

// startPushTCPingLoop runs TCPing for the targets received from the server and
// queues the results for the next startPushLoop iteration.
//
// Cadence contract (this is what produces clean, admin-matching chart gaps):
//
//  1. WARM-UP: wait up to 5 s for the first registration/push to populate
//     pushTCPingTargets and pushTCPingIntervalSec, or less if a config-changed
//     signal arrives earlier. Any shorter and we risk measuring against empty
//     targets; any longer and a small admin interval (e.g. 5 s) would look
//     "late" on the first chart point.
//
//  2. MEASURE — produce one chart point at the current time.
//
//  3. TIME-DRIVEN WAIT — wait until `interval` seconds have passed since the
//     START of the measurement, not since it finished. The measurement itself
//     takes as long as the slowest target's dial (up to the TCPing timeout), so
//     sleeping the full interval afterwards would make the real period
//     `interval + measurement`: with a 5 s interval and targets that time out
//     after 3 s, points would land 8 s apart and the chart would drift steadily
//     away from the configured cadence. A measurement that overruns its own
//     interval simply schedules the next one immediately (no negative wait, no
//     catch-up burst).
//
//     If the admin changes the interval mid-wait the schedule restarts from
//     that moment (fresh "N seconds from now"); we do NOT shoot an extra
//     measurement just because the interval changed. This keeps the chart gap
//     after a change equal to the new interval instead of producing a
//     misleading "bonus" point right after the change.
//
// Net effect for any admin interval N:
//   - First point: ≤ 5 s after client start (or sooner via signal shortcut).
//   - Every subsequent point: N seconds after the previous one — measured
//     start-to-start, so the measurement's own duration is absorbed by the
//     wait — with the server-side timestamp taken from the client's MeasuredAt
//     (so the 3-second push cycle no longer quantises the chart). Only a
//     measurement slower than N itself stretches the gap, and then only by its
//     own overrun.
//   - Changing N from 5→100 or 60→5 in the admin page takes effect within
//     one push cycle (≤ 3 s) without producing out-of-schedule points.
func startPushTCPingLoop() {
	// ── WARM-UP ────────────────────────────────────────────────────────
	select {
	case <-pushTCPingIntervalChanged:
	case <-time.After(5 * time.Second):
	}

	for {
		// ── MEASURE ────────────────────────────────────────────────────
		// cycleStart anchors the schedule: the next point is due `interval`
		// seconds after this instant, however long the measurement takes.
		cycleStart := time.Now()
		targets, _ := currentPushTCPingConfig()
		measureTCPingOnce(targets)

		// ── TIME-DRIVEN WAIT ───────────────────────────────────────────
		// Inner loop keeps us on a strict "N seconds since the last cycle
		// started" schedule. Interval changes re-anchor the schedule instead
		// of jumping straight to another measurement.
	wait:
		for {
			_, interval := currentPushTCPingConfig()
			timer := time.NewTimer(tcpingWaitDuration(interval, time.Since(cycleStart)))
			select {
			case <-pushTCPingIntervalChanged:
				if !timer.Stop() {
					<-timer.C
				}
				// Re-anchor to now and loop around to re-read the new
				// interval. No measurement happens here — the next point
				// will land exactly `new interval` seconds from now.
				cycleStart = time.Now()
				continue
			case <-timer.C:
				// Normal tick — proceed to the next measurement.
				break wait
			}
		}
	}
}

// tcpingWaitDuration returns how long to wait before the next TCPing
// measurement, given the configured interval in seconds and how much time has
// already elapsed since the current cycle started.
//
// The result is clamped at zero: a cycle whose measurement outran its own
// interval starts the next one immediately rather than trying to make up the
// lost time with back-to-back measurements.
func tcpingWaitDuration(intervalSec int, elapsed time.Duration) time.Duration {
	if intervalSec < 0 {
		intervalSec = 0
	}
	wait := time.Duration(intervalSec)*time.Second - elapsed
	if wait < 0 {
		return 0
	}
	return wait
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
		AgentVersion:       "1.3.26",
		Alert:              false, // Can be enhanced with actual alert logic
	}
}

type OSInfo struct {
	Name string
	Icon string
}

func getOSInfo() OSInfo {
	// OS info never changes at runtime, compute once and cache forever
	osInfoOnce.Do(func() {
		osName := runtime.GOOS
		var name, icon string

		switch osName {
		case "linux":
			name = detectLinuxDistro()
			icon = getOSIcon(name)
		case "darwin":
			// Enrich the bare "macOS" label with the product version,
			// and — where we can tell — the marketing name (Sonoma,
			// Sequoia, …). `sw_vers -productVersion` returns something
			// like "14.4.1" even on Apple Silicon and has been stable
			// since Mac OS X 10.3, so it's safe to rely on. Parsing is
			// intentionally tolerant: if sw_vers fails or returns an
			// unexpected format we fall back to the plain "macOS"
			// string rather than logging noise.
			name = "macOS"
			if out, err := runCommandOutput(probeCommandTimeout, "sw_vers", "-productVersion"); err == nil {
				if v := strings.TrimSpace(string(out)); v != "" {
					if mn := macOSMarketingName(v); mn != "" {
						name = fmt.Sprintf("macOS %s %s", mn, v)
					} else {
						name = fmt.Sprintf("macOS %s", v)
					}
				}
			}
			icon = "devicon:apple"
		case "windows":
			name = "Windows"
			icon = "logos:microsoft-windows-icon"
		default:
			// Capitalise the GOOS string ("freebsd" → "Freebsd"). GOOS values
			// are ASCII and single-word, so this needs none of the Unicode
			// word-boundary machinery strings.Title used to apply (and got
			// wrong, which is why it is deprecated).
			name = osName
			if name != "" {
				name = strings.ToUpper(name[:1]) + name[1:]
			}
			icon = "devicon:linux"
		}

		osInfoCache = &OSInfo{Name: name, Icon: icon}
	})
	return *osInfoCache
}

func detectLinuxDistro() string {
	// Try to detect Linux distribution from /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
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
	if data, err := os.ReadFile("/etc/issue"); err == nil {
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

	// ICON POLICY: Only Ubuntu and Windows use "logos:" prefix, all other systems use "devicon:"
	// Debian-based distributions
	if strings.Contains(osLower, "ubuntu") {
		return "logos:ubuntu" // Ubuntu: use logos (as per policy)
	} else if strings.Contains(osLower, "pop") {
		return "devicon:linux" // Pop!_OS: no specific devicon, use generic
	} else if strings.Contains(osLower, "mint") {
		return "devicon:linux" // Linux Mint: no specific devicon, use generic
	} else if strings.Contains(osLower, "elementary") {
		return "devicon:linux" // Elementary OS: no specific devicon, use generic
	} else if strings.Contains(osLower, "zorin") {
		return "devicon:linux" // Zorin OS: no specific devicon, use generic
	} else if strings.Contains(osLower, "kali") {
		return "devicon:linux" // Kali Linux: no specific devicon, use generic
	} else if strings.Contains(osLower, "parrot") {
		return "devicon:linux" // Parrot OS: no specific devicon, use generic
	} else if strings.Contains(osLower, "debian") {
		return "devicon:debian" // Debian: use devicon

		// Arch-based distributions
	} else if strings.Contains(osLower, "manjaro") {
		return "devicon:linux" // Manjaro: no specific devicon, use generic
	} else if strings.Contains(osLower, "endeavour") {
		return "devicon:archlinux" // EndeavourOS: use Arch logo
	} else if strings.Contains(osLower, "garuda") {
		return "devicon:archlinux" // Garuda: use Arch logo
	} else if strings.Contains(osLower, "arch") {
		return "devicon:archlinux" // Arch Linux: use devicon

		// Red Hat-based distributions
	} else if strings.Contains(osLower, "rocky") {
		return "devicon:rockylinux" // Rocky Linux: use devicon
	} else if strings.Contains(osLower, "alma") {
		return "devicon:almalinux" // AlmaLinux: use devicon (FIXED!)
	} else if strings.Contains(osLower, "centos") {
		return "devicon:centos" // CentOS: use devicon
	} else if strings.Contains(osLower, "red hat") || strings.Contains(osLower, "rhel") {
		return "devicon:redhat" // Red Hat: use devicon
	} else if strings.Contains(osLower, "oracle") {
		return "devicon:oracle" // Oracle Linux: use devicon
	} else if strings.Contains(osLower, "fedora") {
		return "devicon:fedora" // Fedora: use devicon

		// Independent distributions
	} else if strings.Contains(osLower, "opensuse") || strings.Contains(osLower, "suse") {
		return "devicon:opensuse" // openSUSE: use devicon
	} else if strings.Contains(osLower, "alpine") {
		return "devicon:linux" // Alpine: no specific devicon, use generic
	} else if strings.Contains(osLower, "gentoo") {
		return "devicon:gentoo" // Gentoo: use devicon
	} else if strings.Contains(osLower, "void") {
		return "devicon:linux" // Void Linux: no specific devicon, use generic
	} else if strings.Contains(osLower, "slackware") {
		return "devicon:linux" // Slackware: no specific devicon, use generic
	} else if strings.Contains(osLower, "nixos") {
		return "devicon:nixos" // NixOS: use devicon
	} else if strings.Contains(osLower, "solus") {
		return "devicon:linux" // Solus: no specific devicon, use generic
	} else if strings.Contains(osLower, "mageia") {
		return "devicon:linux" // Mageia: no specific devicon, use generic
	} else if strings.Contains(osLower, "clear") {
		return "devicon:linux" // Clear Linux: no specific devicon, use generic
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
		// Carrier-grade NAT: 100.64.0.0/10 (RFC 6598). Handed out by mobile
		// networks and by some VPS/IPv4-exhausted providers. It is not
		// reachable from the internet, so reporting one as the machine's
		// public address is as wrong as reporting a 10.x address.
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
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

	// Check IPv6 private ranges.
	// Guard the length first: To4 has already handled every 4-byte form, so
	// anything that is not a 16-byte address here is malformed. Treat it as
	// non-public instead of indexing past the end of the slice.
	if len(ip) != net.IPv6len {
		return true
	}
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
	ipCacheMutex.RLock()
	v4, v6 := ipv4Cache, ipv6Cache
	cacheOk := !ipCacheTime.IsZero() && time.Since(ipCacheTime) < ipCacheTTL
	coldStart := ipCacheTime.IsZero()
	ipCacheMutex.RUnlock()

	if cacheOk {
		return v4, v6
	}

	if coldStart {
		// Very first call: block until we have real IPs so the first push payload
		// is populated correctly.  This happens once at startup.
		v4, v6 = detectIPAddressesFn()
		ipCacheMutex.Lock()
		ipv4Cache = v4
		ipv6Cache = v6
		ipCacheTime = time.Now()
		if v4 != "" || v6 != "" {
			ipDetectedAt = ipCacheTime
		}
		ipCacheMutex.Unlock()
		return v4, v6
	}

	// Cache stale (post-startup): refresh in the background so the push loop is
	// never blocked by external IP-echo API latency (up to 8 s worst-case).
	// The stale IPs are returned immediately; the next push cycle gets fresh IPs.
	//
	// Only one refresh may be in flight. A refresh takes seconds and issues a
	// dozen outbound requests; meanwhile every caller still sees a stale cache,
	// so without this flag each of them starts another full refresh. The push
	// loop alone calls this every 3 s, and /metrics — unauthenticated when no
	// SECRET is configured — calls it once per request, so an unthrottled
	// poller could multiply into an outbound request flood.
	ipCacheMutex.Lock()
	if ipRefreshInFlight {
		// Someone is already refreshing; hand back what we have.
		v4, v6 = ipv4Cache, ipv6Cache
		ipCacheMutex.Unlock()
		return v4, v6
	}
	ipRefreshInFlight = true
	ipCacheMutex.Unlock()

	go func() {
		newV4, newV6 := detectIPAddressesFn()
		ipCacheMutex.Lock()
		defer ipCacheMutex.Unlock()
		ipRefreshInFlight = false
		// A refresh that finds nothing (echo services unreachable for a
		// while) keeps the last known addresses instead of reporting none,
		// which would make the server fall back to the connection source.
		// Not forever, though: after ten minutes without a successful
		// detection the addresses are dropped, so a machine whose address
		// really changed while detection stays broken lets the server take
		// over rather than reporting the old address indefinitely.
		if newV4 != "" || newV6 != "" {
			ipDetectedAt = time.Now()
		}
		stale := !ipDetectedAt.IsZero() && time.Since(ipDetectedAt) > ipKeepStaleFor
		if newV4 != "" {
			ipv4Cache = newV4
		} else if stale {
			ipv4Cache = ""
		}
		if newV6 != "" {
			ipv6Cache = newV6
		} else if stale {
			ipv6Cache = ""
		}
		ipCacheTime = time.Now()
	}()

	return v4, v6
}

// detectIPAddressesFn indirects detectIPAddresses so tests can substitute a
// stub for the network-dependent detection. Production code never reassigns it.
var detectIPAddressesFn = detectIPAddresses

// detectIPAddresses detects the machine's public IPv4 and IPv6 addresses.
//
// Strategy (priority order):
//  1. External IP-echo APIs  — authoritative egress/public IP, works for both
//     NAT machines and direct-IP machines, always reflects what the internet sees.
//  2. Network interface scan — fallback when all external APIs are unreachable
//     (air-gapped, strict firewall, etc.).  Only public (non-private) addresses
//     from real interfaces are considered.
//
// Both API queries run in parallel so the total wait is max(v4_time, v6_time).
func detectIPAddresses() (ipv4, ipv6 string) {
	// --- Step 1: parallel external API queries (highest priority) ---
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(2)
	go func() {
		defer wg.Done()
		if ip := getPublicIPv4(); ip != "" {
			mu.Lock()
			ipv4 = ip
			mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		if ip := getPublicIPv6(); ip != "" {
			mu.Lock()
			ipv6 = ip
			mu.Unlock()
		}
	}()
	wg.Wait()

	// --- Step 2: interface scan fallback (only for IPs still missing) ---
	if ipv4 != "" && ipv6 != "" {
		return // both IPs found via API, no need to scan interfaces
	}

	v4iface, v6iface := scanInterfaceIPs()
	if ipv4 == "" {
		ipv4 = v4iface
	}
	if ipv6 == "" {
		ipv6 = v6iface
	}

	return ipv4, ipv6
}

// scanInterfaceIPs returns the first public IPv4 and IPv6 found on local network
// interfaces, skipping loopback, private ranges, and virtual/container interfaces.
// This is the fallback when external IP-echo APIs are unreachable.
func scanInterfaceIPs() (ipv4, ipv6 string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}

	var ipv4Candidates []net.IP
	var ipv6Candidates []net.IP

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip virtual/container interfaces
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
			if ip == nil || isPrivateIP(ip) {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipv4Candidates = append(ipv4Candidates, ip)
			} else if ip.To16() != nil {
				ipv6Candidates = append(ipv6Candidates, ip)
			}
		}
	}

	if len(ipv4Candidates) > 0 {
		ipv4 = ipv4Candidates[0].String()
	}
	if len(ipv6Candidates) > 0 {
		ipv6 = ipv6Candidates[0].String()
	}
	return ipv4, ipv6
}

// Budgets for one public-IP detection pass. The HTTPS phase and the plaintext
// fallback phase together stay inside publicIPTotalBudget, which is the 8 s
// worst case getIPAddresses documents.
const (
	publicIPTotalBudget       = 8 * time.Second
	publicIPHTTPSBudget       = 6 * time.Second
	publicIPFallbackMinBudget = 2 * time.Second
)

// newIPDetectionClient builds the lightweight one-shot HTTP client used for
// IP-echo queries. No connection reuse is wanted here, and each request carries
// its own timeout so one dead service cannot starve the others.
func newIPDetectionClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second, // per-request timeout (independent of other goroutines)
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 4 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   4 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     true, // no connection reuse needed for one-shot detection
		},
	}
}

// raceIPEchoServices queries every service concurrently and returns the first
// reply that parses as an address `accept` approves of, or "" if none does
// within the budget. Losing goroutines are abandoned; the buffered channel
// means they never block on send.
func raceIPEchoServices(services []string, budget time.Duration, accept func(net.IP) bool) string {
	if len(services) == 0 || budget <= 0 {
		return ""
	}

	resultCh := make(chan string, len(services))

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	detectionClient := newIPDetectionClient()

	// done closes once every service has finished. Without it a phase in which
	// all services fail fast (DNS refused, HTTP 500) would still sit out its
	// whole budget, which in the HTTPS phase leaves the plaintext fallback with
	// only the minimum budget instead of the seconds it should have inherited.
	var wg sync.WaitGroup
	done := make(chan struct{})

	for _, svc := range services {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
			defer reqCancel()

			req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "PulseClient/1.0")
			req.Header.Set("Accept", "text/plain, */*")

			resp, err := detectionClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
			if err != nil {
				return
			}
			ipStr := strings.TrimSpace(string(body))
			// Some services (e.g. ipinfo.io) return JSON; skip if not a plain IP
			if strings.ContainsAny(ipStr, "{}\n") {
				return
			}
			ip := net.ParseIP(ipStr)
			if ip != nil && accept(ip) {
				select {
				case resultCh <- ipStr:
				default: // another goroutine already won
				}
			}
		}(svc)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	// Return the first valid result, or give up once every service has failed
	// or the budget runs out.
	select {
	case ip := <-resultCh:
		return ip
	case <-done:
	case <-ctx.Done():
	}

	// A winner may have landed in the buffer just as we stopped waiting; `done`
	// in particular closes only after every sender has returned.
	select {
	case ip := <-resultCh:
		return ip
	default:
		return ""
	}
}

// racePublicIP asks the HTTPS services first and only falls back to the
// plaintext ones when every HTTPS service has failed.
//
// Racing HTTP against HTTPS and taking the first answer — what this used to do
// — hands the result to whoever replies fastest, and an on-path party is
// exactly the entity that can reply fastest to a plaintext request: it forges a
// response to http://api.ipify.org from the first hop while the real HTTPS
// services are still completing their TLS handshakes. The agent would then
// report, and the dashboard would display, an attacker-chosen address. Trying
// the authenticated services first means a forged plaintext reply can only be
// used when no HTTPS service answered at all.
func racePublicIP(httpsServices, httpServices []string, accept func(net.IP) bool) string {
	deadline := time.Now().Add(publicIPTotalBudget)

	if ip := raceIPEchoServices(httpsServices, publicIPHTTPSBudget, accept); ip != "" {
		return ip
	}

	// Whatever is left of the overall budget goes to the plaintext fallback,
	// with a floor so the phase is not pointless when the HTTPS phase used up
	// nearly everything.
	remaining := time.Until(deadline)
	if remaining < publicIPFallbackMinBudget {
		remaining = publicIPFallbackMinBudget
	}
	return raceIPEchoServices(httpServices, remaining, accept)
}

// isPublicIPv4 reports whether ip is a globally routable IPv4 address.
func isPublicIPv4(ip net.IP) bool { return ip.To4() != nil && !isPrivateIP(ip) }

// isPublicIPv6 reports whether ip is a globally routable IPv6 address.
func isPublicIPv6(ip net.IP) bool { return ip.To4() == nil && !isPrivateIP(ip) }

// getPublicIPv4 fetches the public IPv4 address from external APIs.
// HTTPS services are raced first (first-wins); the plaintext services are only
// consulted if all of them fail — see racePublicIP.
func getPublicIPv4() string {
	httpsServices := []string{
		// Plain-text IP-echo services — most reliable and fast
		"https://api4.my-ip.io/ip", // IPv4-forced endpoint
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ipinfo.io/ip", // ipinfo.io — accurate and widely available
	}
	httpServices := []string{
		// Last resort only: an on-path party can forge any of these, so they
		// run solely when every HTTPS service above has failed (useful behind
		// TLS-stripping proxies and on networks that block 443 outright).
		"http://api.ipify.org",
		"http://icanhazip.com",
		"http://ip.sb",
		"http://myip.ipip.net", // China-friendly
		"http://ip.3322.net",   // China-friendly
		"http://ifconfig.me/ip",
	}

	return racePublicIP(httpsServices, httpServices, isPublicIPv4)
}

// getPublicIPv6 fetches the public IPv6 address from external APIs (parallel, first-wins).
// Useful for NAT machines that have native IPv6 but no direct IPv4.
func getPublicIPv6() string {
	httpsServices := []string{
		"https://api6.my-ip.io/ip", // IPv6-forced endpoint
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
	// No plaintext IPv6 echo services are configured. Any that are added later
	// belong here, so they stay a fallback behind the HTTPS ones rather than
	// racing them.
	var httpServices []string

	return racePublicIP(httpsServices, httpServices, isPublicIPv6)
}

func getLocation() string {
	// Location never changes at runtime, compute once and cache forever
	locationOnce.Do(func() {
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
					locationCache = countryParts[0]
					return
				}
				locationCache = country
				return
			}
			locationCache = strings.TrimSpace(location)
			return
		}

		// Try to detect from system timezone or IP (simplified)
		// In production, use proper geolocation service
		locationCache = ""
	})
	return locationCache
}

// CPU stats tracking for accurate calculation
var (
	lastCPUStats     cpuStats
	lastCPUStatsTime time.Time
	cpuStatsMutex    sync.Mutex
)

type cpuStats struct {
	Total uint64
	Idle  uint64
}

func getCPUUsage() float64 {
	if runtime.GOOS == "darwin" {
		// gopsutil cpu.Percent() is broken with CGO_ENABLED=0 on macOS.
		// Use the background top-based sampler instead.
		startMacOSCPULoop()
		macOSCPUMu.RLock()
		v := macOSCPUVal
		macOSCPUMu.RUnlock()
		return v
	}
	if runtime.GOOS == "windows" {
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
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		// /proc/stat missing/unreadable — classic locked-down LXC symptom.
		// Fall back to cgroup-reported CPU time, which isn't affected by
		// procfs filtering because it lives under /sys/fs/cgroup.
		if v, ok := getCgroupCPUUsage(); ok {
			return v
		}
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
			// Use strconv.ParseUint instead of fmt.Sscanf for ~10x faster integer parsing
			parseField := func(s string) uint64 {
				v, _ := strconv.ParseUint(s, 10, 64)
				return v
			}
			var user, nice, system, idle, iowait, irq, softirq, steal uint64
			user = parseField(fields[1])
			nice = parseField(fields[2])
			system = parseField(fields[3])
			idle = parseField(fields[4])
			if len(fields) > 5 {
				iowait = parseField(fields[5])
			}
			if len(fields) > 6 {
				irq = parseField(fields[6])
			}
			if len(fields) > 7 {
				softirq = parseField(fields[7])
			}
			if len(fields) > 8 {
				steal = parseField(fields[8])
			}

			// Calculate total CPU time (excluding guest time to avoid double counting)
			total := user + nice + system + idle + iowait + irq + softirq + steal
			idleTotal := idle + iowait

			// /proc/stat present but all counters are zero — another lxcfs /
			// procfs-filter symptom. The per-call data is unusable; switch
			// to the cgroup sampler for this container.
			if total == 0 {
				if v, ok := getCgroupCPUUsage(); ok {
					return v
				}
				return 0.0
			}

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

	// /proc/stat was readable but did not contain a "cpu " aggregate line
	// (some procfs filters blank out the content). Fall back to cgroup.
	if v, ok := getCgroupCPUUsage(); ok {
		return v
	}
	return 0.0
}

func getMemoryUsage() float64 {
	if runtime.GOOS == "darwin" {
		pct, _, _, err := macOSMemoryStats()
		if err == nil {
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			return pct
		}
		return 0.0
	}
	if runtime.GOOS == "windows" {
		vmStat, err := mem.VirtualMemory()
		if err == nil {
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

	// Step 1 — Authoritative cgroup limit, if one is set. See the
	// matching comment in getMemoryInfo for the full rationale; the
	// short version is: when an explicit cgroup limit exists it's the
	// only number that reliably reflects the container's real
	// allocation, regardless of how /proc/meminfo is virtualised.
	clamp := func(pct float64) float64 {
		if pct < 0 {
			return 0
		}
		if pct > 100 {
			return 100
		}
		return pct
	}
	if u, t, ok := getCgroupMemoryStats(); ok && t > 0 {
		return clamp(float64(u) / float64(t) * 100.0)
	}

	// Step 2 — /proc/meminfo.
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		if u, t, ok := resolveMemoryStats(); ok && t > 0 {
			return clamp(float64(u) / float64(t) * 100.0)
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
		// /proc/meminfo zeroed-out (lxcfs quirk) — use the cgroup + sysinfo
		// resolver so the % bar in the UI still reflects real usage.
		if u, t, ok := resolveMemoryStats(); ok && t > 0 {
			return clamp(float64(u) / float64(t) * 100.0)
		}
		return 0.0
	}

	// Calculate used memory. Prefer MemAvailable (kernel 3.14+) which
	// already accounts for reclaimable caches.
	var memUsed uint64
	if memAvailable > 0 {
		memUsed = memTotal - memAvailable
	} else {
		memUsed = memTotal - memFree - buffers - cached
	}

	return clamp(float64(memUsed) / float64(memTotal) * 100.0)
}

func getDiskUsage() float64 {
	// Check cache — disk usage changes slowly; spawning df+awk every 3 s wastes CPU.
	diskCacheMu.RLock()
	if !diskUsageCacheTime.IsZero() && time.Since(diskUsageCacheTime) < diskCacheTTL {
		v := diskUsageCache
		diskCacheMu.RUnlock()
		return v
	}
	diskCacheMu.RUnlock()

	result := computeDiskUsage()

	diskCacheMu.Lock()
	diskUsageCache = result
	diskUsageCacheTime = time.Now()
	diskCacheMu.Unlock()

	return result
}

func computeDiskUsage() float64 {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Get all partitions and calculate weighted average
		partitions, err := disk.Partitions(false)
		if err == nil {
			var totalSize, totalUsed uint64
			seenBaseDisks := make(map[string]bool) // macOS: APFS deduplication
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
					// macOS APFS: multiple volumes (System, Data, VM, Preboot…) share one
					// physical container but each reports the full container capacity.
					// Only count / and /Volumes/* and deduplicate by base disk (e.g. "disk3").
					mp := partition.Mountpoint
					if mp != "/" && !strings.HasPrefix(mp, "/Volumes/") {
						continue
					}
					if !strings.HasPrefix(partition.Device, "/dev/disk") {
						continue
					}
					baseDisk := macOSBaseDisk(partition.Device)
					if seenBaseDisks[baseDisk] {
						continue
					}
					seenBaseDisks[baseDisk] = true
					usage, err := disk.Usage(mp)
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
	output, err := runCommandOutput(probeCommandTimeout, "sh", "-c", `df -B1 -T 2>/dev/null | tail -n +2 | awk '
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
	output, err = runCommandOutput(probeCommandTimeout, "df", "-h", "/")
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
	data, err := os.ReadFile("/proc/uptime")
	if err == nil {
		// Format: "12345.67 1234.56" (uptime in seconds, idle time)
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			var uptimeSeconds float64
			if _, err := fmt.Sscanf(fields[0], "%f", &uptimeSeconds); err == nil && uptimeSeconds > 0 {
				return int64(uptimeSeconds)
			}
		}
	}

	// /proc/uptime is unreadable (common in LXC containers with a broken
	// lxcfs — ENOTCONN on the bind mount). Try PID 1 start time against
	// sysinfo(2) uptime: this gives TRUE container uptime (not host
	// uptime) because PID 1 is the container's init, which is spawned
	// when the container boots.
	if contUp, ok := readContainerUptime(); ok && contUp > 0 {
		return contUp
	}
	// Last kernel-backed option: raw sysinfo(2) uptime (host-level, but
	// still better than process uptime for a freshly-restarted agent).
	if hostUp, ok := readSysinfoUptime(); ok && hostUp > 0 {
		return hostUp
	}

	// Fallback: process uptime. This is only reached when both
	// /proc/uptime and the sysinfo syscall fail, which is effectively
	// never on a working Linux kernel.
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

				// A negative delta means an interface disappeared, its
				// counters were reset, or a 32-bit kernel counter wrapped;
				// report a zero rate for this sample instead of dividing the
				// machine's lifetime byte count by three seconds.
				if rxDiff < 0 {
					rxDiff = 0
				}
				if txDiff < 0 {
					txDiff = 0
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
	data, err := os.ReadFile("/proc/net/dev")
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

		// Use strconv.ParseUint for faster integer parsing (avoids fmt.Sscanf overhead)
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64) // Receive bytes
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64) // Transmit bytes

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

			// A negative delta means an interface disappeared, its counters
			// were reset, or a 32-bit kernel counter wrapped; report a zero
			// rate for this sample instead of a spike of the lifetime count.
			if rxDiff < 0 {
				rxDiff = 0
			}
			if txDiff < 0 {
				txDiff = 0
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

// countCPUList parses a Linux cpuset-style list like "0-3,5,8-11" and returns
// the total number of CPU indices it references. Returns 0 for an empty or
// malformed string. Used to turn the contents of cpuset.cpus.effective into
// a plain core count.
func countCPUList(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	total := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if dash := strings.Index(part, "-"); dash > 0 {
			var lo, hi int
			if _, err := fmt.Sscanf(part, "%d-%d", &lo, &hi); err == nil && hi >= lo {
				total += hi - lo + 1
			}
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err == nil && n >= 0 {
			total++
		}
	}
	return total
}

// getCgroupCPUCount returns the effective number of CPUs the current process
// is allowed to use under Linux cgroups (v1 or v2). It considers BOTH sources
// of CPU limiting and picks the stricter (smaller) positive value:
//
//   - cpu bandwidth (cfs_quota / cfs_period on v1, cpu.max on v2) — ceil'd up
//     to a whole core, e.g. quota=200000 period=100000 → 2 cores, quota=50000
//     period=100000 → 1 core (can't display "0.5 core" in the UI).
//   - cpuset pinning (cpuset.cpus.effective) — the number of CPU indices the
//     process is actually allowed to run on.
//
// Returns 0 when no cgroup-imposed limit is in effect or no recognised
// cgroup file is readable (e.g. bare metal, or a container that hasn't been
// given a CPU limit). Callers should fall back to their regular detection
// path in that case.
//
// This is the only reliable way to know the CPU count inside an LXC/Docker
// container that does not run lxcfs: lscpu, /proc/cpuinfo and gopsutil all
// return the HOST's CPU topology, not the container's allocation.
func getCgroupCPUCount() int {
	fromQuota := 0
	fromCpuset := 0

	// ── cpu bandwidth ─────────────────────────────────────────────────
	// cgroup v2 — single file "quota period"; "max" means unlimited.
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		parts := strings.Fields(strings.TrimSpace(string(data)))
		if len(parts) >= 2 && parts[0] != "max" {
			var quota, period int64
			fmt.Sscanf(parts[0], "%d", &quota)
			fmt.Sscanf(parts[1], "%d", &period)
			if quota > 0 && period > 0 {
				n := int((quota + period - 1) / period) // ceil
				if n > 0 {
					fromQuota = n
				}
			}
		}
	} else {
		// cgroup v1 — quota and period in separate files.
		quotaData, qErr := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
		periodData, pErr := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
		if qErr == nil && pErr == nil {
			var quota, period int64
			fmt.Sscanf(strings.TrimSpace(string(quotaData)), "%d", &quota)
			fmt.Sscanf(strings.TrimSpace(string(periodData)), "%d", &period)
			if quota > 0 && period > 0 {
				n := int((quota + period - 1) / period)
				if n > 0 {
					fromQuota = n
				}
			}
		}
	}

	// ── cpuset (affinity) ─────────────────────────────────────────────
	// v2 exposes the effective set at the unified hierarchy root; v1 keeps
	// it under the cpuset controller. We try several paths because
	// containers mount this hierarchy in slightly different ways.
	cpusetPaths := []string{
		"/sys/fs/cgroup/cpuset.cpus.effective", // v2 (preferred — post-restrictions)
		"/sys/fs/cgroup/cpuset/cpuset.cpus",    // v1 legacy path
		"/sys/fs/cgroup/cpuset.cpus",           // v2 fallback
	}
	for _, p := range cpusetPaths {
		if data, err := os.ReadFile(p); err == nil {
			if n := countCPUList(string(data)); n > 0 {
				fromCpuset = n
				break
			}
		}
	}

	// Return the stricter non-zero limit. A container can have both, e.g.
	// quota=2 cores + pinned to CPUs 4-7 (cpuset=4) → we must report 2.
	switch {
	case fromQuota > 0 && fromCpuset > 0:
		if fromQuota < fromCpuset {
			return fromQuota
		}
		return fromCpuset
	case fromQuota > 0:
		return fromQuota
	case fromCpuset > 0:
		return fromCpuset
	}

	// Proxmox LXC fallback — "cores: N" in /etc/vzdump/pct.conf. Proxmox
	// often enforces core count via lxc.cgroup2.cpuset.cpus from the host,
	// which — on unprivileged containers — doesn't propagate to the
	// in-container cgroup view. This file is the admin's configured value.
	if cfg, ok := proxmoxLXCConfigCached(); ok && cfg.Cores > 0 {
		return cfg.Cores
	}
	return 0
}

// cgroup-based CPU usage tracking. We keep separate state from the
// /proc/stat path so the two can be sampled independently without polluting
// each other's rate calculations.
var (
	lastCgroupCPUNs   uint64
	lastCgroupCPUTime time.Time
	cgroupCPUMu       sync.Mutex
)

// readCgroupCPUNanos returns the total CPU time consumed by the current
// cgroup, in nanoseconds. Supports both cgroup v2 (cpu.stat's "usage_usec"
// field, converted from microseconds) and cgroup v1 (cpuacct.usage, which
// is already in nanoseconds). Returns (0, false) if neither file is
// readable — typically because the container is outside a cgroup hierarchy
// or the cpuacct controller is not mounted.
func readCgroupCPUNanos() (uint64, bool) {
	// cgroup v2 — unified hierarchy.
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.stat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "usage_usec" {
				if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return v * 1000, true // µs → ns
				}
			}
		}
	}
	// cgroup v1 — cpuacct controller.
	if data, err := os.ReadFile("/sys/fs/cgroup/cpuacct/cpuacct.usage"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			return v, true
		}
	}
	// cgroup v1 "legacy" — some distros mount cpuacct under cpu,cpuacct.
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// getCgroupCPUUsage returns the CPU usage of the current cgroup as a
// percentage across the cores available to this container. Requires two
// samples spaced apart in wall time to compute a rate; the first call
// primes state and returns (0, false). Subsequent calls return the usage
// since the previous sample.
//
// We divide by (elapsed_ns * cpu_count) so "100%" means "all allocated
// cores fully busy", matching how getCPUUsage on /proc/stat reports.
//
// This is the only reliable CPU usage source in a container whose
// /proc/stat has been zeroed or hidden by lxcfs / procfs filtering.
func getCgroupCPUUsage() (float64, bool) {
	cgroupCPUMu.Lock()
	defer cgroupCPUMu.Unlock()

	curr, ok := readCgroupCPUNanos()
	if !ok {
		return 0, false
	}
	now := time.Now()

	if lastCgroupCPUTime.IsZero() || lastCgroupCPUNs == 0 {
		lastCgroupCPUNs = curr
		lastCgroupCPUTime = now
		return 0, false
	}

	elapsedNs := float64(now.Sub(lastCgroupCPUTime).Nanoseconds())
	if elapsedNs <= 0 {
		return 0, false
	}

	var deltaNs float64
	if curr >= lastCgroupCPUNs {
		deltaNs = float64(curr - lastCgroupCPUNs)
	} else {
		// Counter reset (container restart, cgroup re-parented) — skip
		// this sample rather than return a bogus spike, and rebase.
		lastCgroupCPUNs = curr
		lastCgroupCPUTime = now
		return 0, false
	}

	// Number of cores the container is allowed to use — prefer the
	// cgroup-reported limit so utilisation is expressed per allocated core
	// rather than per host core.
	cores := getCgroupCPUCount()
	if cores <= 0 {
		cores = runtime.NumCPU()
	}
	if cores <= 0 {
		cores = 1
	}

	usage := (deltaNs / (elapsedNs * float64(cores))) * 100.0
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}

	lastCgroupCPUNs = curr
	lastCgroupCPUTime = now
	return usage, true
}

// getCgroupMemoryStats reads the container's memory allocation directly from
// the cgroup pseudo-filesystem. It exists because some LXC templates expose a
// zeroed-out /proc/meminfo (lxcfs bug on unprivileged containers, lxcfs not
// running, or an explicit mount of an empty file). In that case /proc/meminfo
// is readable but MemTotal reports 0, which makes every "used / total" helper
// return nothing usable.
//
// Returns (usedBytes, totalBytes, ok). ok is false when no cgroup memory file
// is readable or the container has no explicit memory limit ("max" on v2,
// "-1"/very-large sentinel on v1). Callers should treat !ok as "no
// cgroup-imposed limit, fall back to host-level sources".
//
// We deliberately do NOT use a "max" sentinel for total: if the container
// truly has no limit and /proc/meminfo is also broken, we can't honestly
// report a total, so we return ok=false and let the caller decide.
// cgroupMemoryReclaimable returns the total reclaimable pages tracked in
// cgroup memory.stat, matching the kernel's definition of "memory that
// looks used but can be evicted on demand". Subtracting this from
// memory.current yields the container's working-set size — the same
// number reported by `kubectl top`, Docker's stats, and (approximately)
// the "used" column of `free -h` on bare metal.
//
// The fields we look at:
//   - inactive_file      — clean page-cache that can be dropped
//   - slab_reclaimable   — dcache / inode cache reclaimed on pressure
//
// Both exist in cgroup v2 stat; cgroup v1 has the same fields, optionally
// prefixed with "total_" in hierarchical accounting. Reading them
// independently lets us tolerate one being absent (older kernels).
func cgroupMemoryReclaimable(statPath string) uint64 {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	// cgroup v1 hierarchical accounting exposes BOTH the per-cgroup field
	// ("inactive_file") AND the recursive hierarchy sum ("total_inactive_file").
	// In a leaf cgroup (every container) they are identical, so a naive
	// sum double-counts and subtracts ~2× from the "used" figure.
	//
	// Prefer the hierarchical (total_*) value when present — it already
	// covers the current cgroup and any future descendants, matching the
	// kernel's MemAvailable definition. Fall back to the plain name only
	// when the total_* variant isn't in the file (older cgroup v1 kernels
	// without hierarchical accounting, or cgroup v2 which uses the plain
	// names only).
	var inactiveFile, totalInactiveFile uint64
	var slabReclaim, totalSlabReclaim uint64
	var haveInactiveTotal, haveSlabTotal bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "inactive_file":
			inactiveFile = v
		case "total_inactive_file":
			totalInactiveFile = v
			haveInactiveTotal = true
		case "slab_reclaimable":
			slabReclaim = v
		case "total_slab_reclaimable":
			totalSlabReclaim = v
			haveSlabTotal = true
		}
	}
	var reclaimable uint64
	if haveInactiveTotal {
		reclaimable += totalInactiveFile
	} else {
		reclaimable += inactiveFile
	}
	if haveSlabTotal {
		reclaimable += totalSlabReclaim
	} else {
		reclaimable += slabReclaim
	}
	return reclaimable
}

func getCgroupMemoryStats() (used, total uint64, ok bool) {
	readUint := func(s string) (uint64, bool) {
		s = strings.TrimSpace(s)
		if s == "" || s == "max" {
			return 0, false
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}

	// ── cgroup v2 (unified hierarchy) ────────────────────────────────
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if t, tok := readUint(string(data)); tok {
			total = t
		}
	}
	if total > 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
			if u, uok := readUint(string(data)); uok {
				used = u
			}
		}
		// Subtract reclaimable caches (inactive_file + slab_reclaimable)
		// to match the kernel's working-set definition — this is what
		// /proc/meminfo's MemAvailable uses, and what monitoring tools
		// like `kubectl top` / Docker stats display as "used".
		if r := cgroupMemoryReclaimable("/sys/fs/cgroup/memory.stat"); r > 0 && r < used {
			used -= r
		}
		return used, total, true
	}

	// ── cgroup v1 ────────────────────────────────────────────────────
	// limit_in_bytes reports a very large sentinel (~9223372036854771712, i.e.
	// PAGE_COUNTER_MAX * PAGE_SIZE) when no limit is set — treat that as
	// "unlimited" by comparing against host total if available, else ok=false.
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if t, tok := readUint(string(data)); tok && t > 0 && t < (1<<62) {
			total = t
		}
	}
	if total > 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
			if u, uok := readUint(string(data)); uok {
				used = u
			}
		}
		if r := cgroupMemoryReclaimable("/sys/fs/cgroup/memory/memory.stat"); r > 0 && r < used {
			used -= r
		}
		return used, total, true
	}

	return 0, 0, false
}

// readCgroupMemoryCurrent reads the container's *current* memory usage in
// bytes, without requiring a memory limit to be set. Unlike
// getCgroupMemoryStats (which insists on a non-"max" limit so a coherent
// total can be reported), this helper succeeds even for unlimited
// containers — useful when combined with a host-level total from sysinfo.
func readCgroupMemoryCurrent() (uint64, bool) {
	// cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			used := v
			if r := cgroupMemoryReclaimable("/sys/fs/cgroup/memory.stat"); r > 0 && r < used {
				used -= r
			}
			return used, true
		}
	}
	// cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			used := v
			if r := cgroupMemoryReclaimable("/sys/fs/cgroup/memory/memory.stat"); r > 0 && r < used {
				used -= r
			}
			return used, true
		}
	}
	return 0, false
}

// proxmoxLXCConfig captures the authoritative resource allocation that
// Proxmox records for an LXC container. Proxmox snapshots the container's
// pct.conf into /etc/vzdump/pct.conf whenever a backup runs, and this
// file is visible from inside the container — making it the only source
// of the originally-configured limits when the live cgroup doesn't have
// them (Proxmox sometimes sets memory/swap via lxc.cgroup directives
// that don't show up as memory.max on all kernels).
type proxmoxLXCConfig struct {
	MemoryBytes uint64 // "memory: 512" → 512 MiB in bytes
	SwapBytes   uint64 // "swap: 512"   → 512 MiB in bytes
	Cores       int    // "cores: 1"
	RootFSBytes uint64 // "rootfs: ... size=8G" → 8 GiB in bytes
	found       bool
}

// parseProxmoxSize parses Proxmox size tokens like "8G", "512M", "2T",
// "1024K" and returns the value in bytes. A bare number is interpreted
// as megabytes (Proxmox convention for the "memory"/"swap" fields).
func parseProxmoxSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := uint64(1 << 20) // default: megabytes
	last := s[len(s)-1]
	num := s
	switch last {
	case 'T', 't':
		mult = 1 << 40
		num = s[:len(s)-1]
	case 'G', 'g':
		mult = 1 << 30
		num = s[:len(s)-1]
	case 'M', 'm':
		mult = 1 << 20
		num = s[:len(s)-1]
	case 'K', 'k':
		mult = 1 << 10
		num = s[:len(s)-1]
	}
	if n, err := strconv.ParseFloat(strings.TrimSpace(num), 64); err == nil && n > 0 {
		return uint64(n * float64(mult))
	}
	return 0
}

// readProxmoxLXCConfig parses /etc/vzdump/pct.conf — the snapshot of the
// container's provisioned resources that Proxmox's vzdump leaves inside
// the container. Returns (cfg, true) if the file exists and at least one
// field parsed, otherwise (_, false).
//
// Sample file contents:
//
//	arch: amd64
//	cores: 1
//	memory: 512
//	rootfs: local-zfs:subvol-100-disk-0,size=8G
//	swap: 512
//	unprivileged: 1
func readProxmoxLXCConfig() (proxmoxLXCConfig, bool) {
	data, err := os.ReadFile("/etc/vzdump/pct.conf")
	if err != nil {
		return proxmoxLXCConfig{}, false
	}
	cfg := proxmoxLXCConfig{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		switch key {
		case "memory":
			// Plain number = megabytes.
			if n, err := strconv.ParseUint(val, 10, 64); err == nil && n > 0 {
				cfg.MemoryBytes = n << 20
				cfg.found = true
			}
		case "swap":
			if n, err := strconv.ParseUint(val, 10, 64); err == nil && n > 0 {
				cfg.SwapBytes = n << 20
				cfg.found = true
			}
		case "cores":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.Cores = n
				cfg.found = true
			}
		case "rootfs", "mp0", "mp1": // rootfs + first couple of mountpoints
			// "local-zfs:subvol-100-disk-0,size=8G" → extract size=8G.
			if idx := strings.Index(val, "size="); idx >= 0 {
				tail := val[idx+len("size="):]
				end := strings.IndexAny(tail, " ,")
				if end >= 0 {
					tail = tail[:end]
				}
				if b := parseProxmoxSize(tail); b > 0 && key == "rootfs" {
					cfg.RootFSBytes = b
					cfg.found = true
				}
			}
		}
	}
	if !cfg.found {
		return proxmoxLXCConfig{}, false
	}
	return cfg, true
}

// proxmoxCfgCache memoises the pct.conf read — it's tiny but we read
// memory every 3 seconds and there's no need to stat/open the file that
// often. The config itself almost never changes at runtime (it's only
// refreshed on Proxmox backups).
var (
	proxmoxCfgOnce   sync.Once
	proxmoxCfgCached proxmoxLXCConfig
	proxmoxCfgOK     bool
)

func proxmoxLXCConfigCached() (proxmoxLXCConfig, bool) {
	proxmoxCfgOnce.Do(func() {
		proxmoxCfgCached, proxmoxCfgOK = readProxmoxLXCConfig()
	})
	return proxmoxCfgCached, proxmoxCfgOK
}

// readCgroupMemoryPeak returns the container's high-water memory usage in
// bytes — the maximum resident set the container has ever reached during
// its lifetime, as recorded by the kernel's memory controller. This is
// available as memory.peak (cgroup v2, kernel ≥ 5.19) or
// memory.max_usage_in_bytes (cgroup v1).
//
// When a container has no explicit memory limit (memory.max = "max"),
// peak is the best signal we have of the container's "natural working
// size" — it reflects what workloads have actually needed, rather than
// inheriting the host's RAM. It's what Proxmox LXC administrators really
// want to see on a rootless/unbounded container.
func readCgroupMemoryPeak() (uint64, bool) {
	// cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.peak"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 {
			return v, true
		}
	}
	// cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.max_usage_in_bytes"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 {
			return v, true
		}
	}
	return 0, false
}

// containerMemoryCeiling returns a container-centric "total" memory
// figure to display when no explicit cgroup limit is set. Strategy:
//
//  1. Start from memory.peak (kernel's recorded high-water mark).
//  2. If peak is too close to current usage (< 20% headroom), pad it to
//     provide at least 20% headroom — a container that peaked at exactly
//     its current usage would otherwise look 100% full forever.
//  3. Round the result up to the next common LXC allocation boundary
//     (128 MiB / 256 MiB / 512 MiB / 1 GiB / 2 GiB / 4 GiB / 8 GiB / …)
//     so the number resembles a provisioned size (e.g. 611 MiB → 1 GiB,
//     matching what an admin would have typed into Proxmox).
//  4. Never exceed the host total — a container can't actually use more
//     than the physical RAM available.
//
// Returns (ceiling, true) on success, (0, false) if we have no peak
// reading and the caller should fall back to host total.
func containerMemoryCeiling(currentUsed, hostTotal uint64) (uint64, bool) {
	peak, ok := readCgroupMemoryPeak()
	if !ok || peak == 0 {
		return 0, false
	}
	// Ensure at least 20% headroom above the larger of current/peak.
	base := peak
	if currentUsed > base {
		base = currentUsed
	}
	withHeadroom := base + base/5
	// Round up to the nearest "friendly" boundary — powers of 2 from
	// 128 MiB up to 1 GiB, then multiples of 1 GiB.
	boundaries := []uint64{
		128 << 20, 256 << 20, 384 << 20, 512 << 20, 768 << 20, 1 << 30,
	}
	var ceil uint64
	for _, b := range boundaries {
		if withHeadroom <= b {
			ceil = b
			break
		}
	}
	if ceil == 0 {
		// Round up to next whole GiB.
		const gib = uint64(1) << 30
		ceil = ((withHeadroom + gib - 1) / gib) * gib
	}
	if hostTotal > 0 && ceil > hostTotal {
		ceil = hostTotal
	}
	return ceil, ceil > 0
}

// resolveMemoryStats is the authoritative Linux memory source. It tries
// every known channel in order of "most container-accurate first" →
// "least container-accurate but never hidden":
//
//  1. cgroup memory.max + memory.current — container has explicit limit
//     (most accurate for limited containers).
//  2. cgroup memory.current + container ceiling derived from memory.peak
//     — container has no explicit limit; both numbers are container-
//     local (much better than showing the host's 500 GiB RAM on an LXC).
//  3. cgroup memory.current + sysinfo host total — absolute fallback
//     when memory.peak is unavailable (very old kernel).
//  4. sysinfo(2) syscall only — last resort; reports host-level figures.
//
// Returns (used, total, ok). ok=false only when every source failed
// (truly catastrophic — sysinfo virtually always succeeds on Linux).
//
// Crucially, this function never touches /proc/meminfo so it works on
// containers where lxcfs has died (ENOTCONN on /proc/*), which is the
// common failure mode on Proxmox LXC when the lxcfs daemon crashes or
// isn't bind-mounted inside the container.
func resolveMemoryStats() (used, total uint64, ok bool) {
	if u, t, cgOK := getCgroupMemoryStats(); cgOK && t > 0 {
		return u, t, true
	}
	hostTotal, hostUsed, _, _, siOK := readSysinfo()
	curUsed, curOK := readCgroupMemoryCurrent()

	// Proxmox LXC config — /etc/vzdump/pct.conf contains the *configured*
	// memory limit even when the cgroup shows "max". This is the key
	// source of "what the admin typed into Proxmox" when the live cgroup
	// limit is unset (common on unprivileged LXCs whose limits are applied
	// via lxc.cgroup2.memory.max in the LXC hookscript rather than as a
	// cgroup file inside the container).
	//
	// CAVEAT: pct.conf is a *snapshot* from the last vzdump backup, so
	// it can drift if the admin edits memory in the Proxmox UI after
	// backup. We protect against that with two staleness checks, tuned
	// to avoid false positives on legitimate small overshoots:
	//
	//   Primary signal  — memory.current > pct.conf limit × 1.1.
	//   If the cgroup is RIGHT NOW using more than the claimed limit
	//   (plus 10% slack for accounting noise), the config is stale.
	//
	//   Secondary signal — memory.peak > pct.conf limit × 2.
	//   memory.peak is monotonic, so it captures historical overshoot.
	//   BUT cgroup v2 lets kernel memory (slab, page tables, etc.)
	//   briefly exceed memory.max without OOM during heavy file I/O;
	//   on a real 512 MiB container we've measured peak rise to ~583 MiB
	//   (14% overshoot) under load. A 10% threshold here would cause
	//   false positives. We use 2× — an admin genuinely raising the
	//   limit from 512 MiB to 1 GiB produces peak ≫ 1024 MiB, while
	//   kernel noise never doubles the limit.
	//
	// When either signal fires, we skip pct.conf and fall through to
	// the peak-based `containerMemoryCeiling` heuristic.
	if cfg, pctOK := proxmoxLXCConfigCached(); pctOK && cfg.MemoryBytes > 0 {
		slackLimit := cfg.MemoryBytes + cfg.MemoryBytes/10 // +10%
		hardStaleLimit := cfg.MemoryBytes * 2              // +100%
		peakBytes, peakOK := readCgroupMemoryPeak()
		stale := false
		if curOK && curUsed > slackLimit {
			stale = true
		} else if peakOK && peakBytes > hardStaleLimit {
			stale = true
		}
		if !stale {
			if curOK {
				return curUsed, cfg.MemoryBytes, true
			}
			if siOK && hostUsed > 0 {
				return hostUsed, cfg.MemoryBytes, true
			}
		}
	}

	if curOK {
		// Derive a container-centric ceiling from memory.peak when no
		// Proxmox config is available (or pct.conf is stale — see above).
		if ceil, ok := containerMemoryCeiling(curUsed, hostTotal); ok {
			return curUsed, ceil, true
		}
		if siOK && hostTotal > 0 {
			return curUsed, hostTotal, true
		}
	}
	if siOK && hostTotal > 0 {
		return hostUsed, hostTotal, true
	}
	return 0, 0, false
}

// resolveSwapStats mirrors resolveMemoryStats for swap. Priority:
//  1. cgroup swap limit + swap current.
//  2. cgroup swap current + sysinfo host swap total.
//  3. sysinfo swap.
//
// Returns (used=0, total=0, ok=true) legitimately when the host has no
// swap at all (sysinfo reports 0) — callers should interpret that as
// "no swap" rather than an error.
func resolveSwapStats() (used, total uint64, ok bool) {
	// Explicit cgroup swap limit (memory.swap.max is a real number) —
	// authoritative, skip everything else.
	if u, t, cgOK := getCgroupSwapStats(); cgOK && t > 0 {
		return u, t, true
	}
	// cgroup v2 swap.current — container's actual swap usage regardless
	// of limit. Reliable inside LXC when /proc/meminfo is masked.
	var cgSwapUsed uint64
	var cgSwapOK bool
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.swap.current"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			cgSwapUsed = v
			cgSwapOK = true
		}
	}

	// Ground-truth from sysinfo(2): the host's actual swap configuration.
	// A container cannot have swap the host doesn't provide — if the host
	// reports Totalswap=0, the container has no swap regardless of what
	// any stale config file claims.
	_, _, hostSwapTotal, hostSwapUsed, siOK := readSysinfo()

	// If the host has NO swap at all, the container has none. This is the
	// definitive test — trust the kernel, not a 6-month-old pct.conf
	// snapshot that the admin may have edited away since.
	if siOK && hostSwapTotal == 0 {
		return 0, 0, true
	}

	// Proxmox LXC config fallback — "swap: N" (MiB). Only trust this when
	// the kernel confirms swap is actually available on the host (we just
	// checked hostSwapTotal > 0 above by falling through). This protects
	// against stale pct.conf snapshots claiming swap that was later
	// removed from the container.
	if cfg, pctOK := proxmoxLXCConfigCached(); pctOK && cfg.SwapBytes > 0 && siOK && hostSwapTotal > 0 {
		// Cap at host total — container can't have more swap than the host.
		total := cfg.SwapBytes
		if total > hostSwapTotal {
			total = hostSwapTotal
		}
		if cgSwapOK {
			return cgSwapUsed, total, true
		}
		return 0, total, true
	}

	if cgSwapOK && siOK && hostSwapTotal > 0 {
		return cgSwapUsed, hostSwapTotal, true
	}
	if siOK {
		// hostSwapTotal > 0 here (the == 0 branch returned above).
		return hostSwapUsed, hostSwapTotal, true
	}
	return 0, 0, false
}

// getCgroupSwapStats reads container swap allocation from cgroup. Some LXC
// templates report SwapTotal=0 in /proc/meminfo even when the container does
// have a swap limit; this helper recovers the real numbers. Same semantics
// as getCgroupMemoryStats: ok=false means no explicit limit / unreadable.
func getCgroupSwapStats() (used, total uint64, ok bool) {
	readUint := func(s string) (uint64, bool) {
		s = strings.TrimSpace(s)
		if s == "" || s == "max" {
			return 0, false
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}

	// cgroup v2: memory.swap.max / memory.swap.current
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max"); err == nil {
		if t, tok := readUint(string(data)); tok {
			total = t
		}
	}
	if total > 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory.swap.current"); err == nil {
			if u, uok := readUint(string(data)); uok {
				used = u
			}
		}
		return used, total, true
	}

	// cgroup v1: memsw.limit_in_bytes is combined (memory + swap). Swap-only
	// limit = memsw_limit - memory_limit; swap-only used = memsw_usage - memory_usage.
	var memswLimit, memswUsage, memLimit, memUsage uint64
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes"); err == nil {
		if v, ok := readUint(string(data)); ok && v < (1<<62) {
			memswLimit = v
		}
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes"); err == nil {
		if v, ok := readUint(string(data)); ok {
			memswUsage = v
		}
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, ok := readUint(string(data)); ok && v < (1<<62) {
			memLimit = v
		}
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		if v, ok := readUint(string(data)); ok {
			memUsage = v
		}
	}
	if memswLimit > memLimit {
		total = memswLimit - memLimit
		if memswUsage > memUsage {
			used = memswUsage - memUsage
		}
		return used, total, true
	}

	return 0, 0, false
}

// isLinuxContainer returns true when the current process is running inside
// a Linux container runtime (LXC, Docker, containerd, podman, Kubernetes
// pods, etc.). We need this because the agent's virtualisation detection
// path otherwise classifies LXC as a physical server — LXC does not set
// a hypervisor vendor flag, so the lscpu / /proc/cpuinfo probes miss it.
//
// Detection heuristics (any ONE positive signal flips us to "container"):
//   - /.dockerenv exists (Docker, Podman, some CRI runtimes).
//   - $container env var set by the container runtime (LXC sets "lxc",
//     systemd-nspawn sets "systemd-nspawn", etc.).
//   - /proc/1/cgroup or /proc/self/cgroup mentions a known container
//     namespace path fragment.
func isLinuxContainer() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if v := os.Getenv("container"); v != "" {
		return true
	}
	containerHints := []string{"/docker", "/lxc", "lxc.payload", "/kubepods", "/containerd", "/podman", "libpod"}
	for _, p := range []string{"/proc/1/cgroup", "/proc/self/cgroup"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		content := string(data)
		for _, hint := range containerHints {
			if strings.Contains(content, hint) {
				return true
			}
		}
	}
	return false
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
		output, err := runCommandOutput(slowProbeCommandTimeout, "wmic", "cpu", "get", "Name", "/format:list")

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
		output, err = runCommandOutput(slowProbeCommandTimeout, "wmic", "computersystem", "get", "NumberOfLogicalProcessors", "/format:list")

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

		// Use logical core count (includes hyperthreading). We deliberately do
		// NOT run `wmic cpu get NumberOfCores` here: its per-CPU physical-core
		// count was previously summed into a local variable that nothing read,
		// spawning a WMI subprocess every 5 min for no effect. The displayed
		// count always uses the logical (SMT-inclusive) value below — the
		// "Physical Core" suffix reflects the VPS/DS distinction, not SMT.
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
		// Intel Mac: machdep.cpu.brand_string is the most reliable source
		if out, err := runCommandOutput(probeCommandTimeout, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
			model = strings.TrimSpace(string(out))
		}
		// Apple Silicon: machdep.cpu.brand_string does not exist; use system_profiler.
		// Result is cached for 5 min so the ~0.5 s latency is only paid once.
		if model == "" {
			if out, err := runCommandOutput(slowProbeCommandTimeout, "sh", "-c",
				`system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/^ *Chip:/{print $2; exit}'`); err == nil {
				if s := strings.TrimSpace(string(out)); s != "" {
					model = s
				}
			}
		}
		// gopsutil fallback (works on Intel, may fail on Apple Silicon)
		if model == "" {
			if info, err := cpu.Info(); err == nil && len(info) > 0 {
				model = strings.TrimSpace(info[0].ModelName)
			}
		}
		if model == "" {
			model = "Apple CPU"
		}
		// Core count on macOS: try three sources in order of reliability.
		// On Apple Silicon running under Rosetta 2 or a sandbox, gopsutil's
		// sysctl helpers can return 0 without an error, so we always do the
		// native `sysctl hw.logicalcpu` as a backstop. runtime.NumCPU() is
		// the final fallback — it reads the process's CPU affinity mask,
		// which matches the machine's logical CPU count on macOS.
		if count, err := cpu.Counts(true); err == nil && count > 0 {
			coreCount = count
		}
		if coreCount == 0 {
			if out, err := runCommandOutput(probeCommandTimeout, "sysctl", "-n", "hw.logicalcpu"); err == nil {
				fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &coreCount)
			}
		}
		if coreCount == 0 {
			// Last-resort fallback. On macOS, NumCPU returns the number
			// of logical CPUs the OS has made available to the Go
			// runtime, which is what we want here.
			if n := runtime.NumCPU(); n > 0 {
				coreCount = n
			}
		}
		// Default to Physical, will be corrected below if VPS
		coreType = "Physical"
	}

	// For ALL platforms: Detect virtualization and correct core type
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
		// macOS-specific fallbacks. gopsutil's cpu.Info().Mhz reads
		// sysctl hw.cpufrequency, which:
		//   • returns a real value on Intel Macs,
		//   • returns 0 on Apple Silicon (the sysctl is not populated —
		//     Apple Silicon performance and efficiency cores run at
		//     different, dynamically-scaled frequencies that don't fit
		//     the "one nominal clock" model).
		// So if we still have no speed on macOS, try:
		//   1. sysctl hw.cpufrequency_max — the nominal max clock; still
		//      works on some Intel Macs where the legacy key is missing.
		//   2. A curated lookup by chip name for Apple Silicon. The clocks
		//      are Apple's published nominal performance-core max and are
		//      accurate to one decimal place for every shipping M-series
		//      chip so far (M1/M2/M3/M4 families). This gives the user a
		//      useful nominal-GHz reading even on Apple Silicon.
		if speed == "" && runtime.GOOS == "darwin" {
			if out, err := runCommandOutput(probeCommandTimeout, "sysctl", "-n", "hw.cpufrequency_max"); err == nil {
				var hz uint64
				if _, se := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &hz); se == nil && hz > 0 {
					speed = fmt.Sprintf("%.2f", float64(hz)/1e9)
				}
			}
		}
		if speed == "" && runtime.GOOS == "darwin" {
			if g := appleSiliconNominalGHz(model); g > 0 {
				speed = fmt.Sprintf("%.2f", g)
			}
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

	// Get CPU model name (Linux).
	// Order of fallbacks (most common first):
	//   1. /proc/cpuinfo "model name" line — x86/x86_64 Intel & AMD.
	//   2. lscpu "Model name" — same info, but available on x86 distros that
	//      have util-linux installed (most).
	//   3. gopsutil cpu.Info() — wraps /proc/cpuinfo and understands ARM
	//      layouts (Hardware / Processor / CPU implementer) that x86-only
	//      regex above misses.
	//   4. /proc/cpuinfo "Hardware" / "Processor" / "Model" — raw ARM fields
	//      as an additional safety net if gopsutil returns empty ModelName.
	//   5. runtime.NumCPU() with a generic "CPU" label — worst-case, so a
	//      container/embedded system that somehow exposes none of the above
	//      still produces a non-empty string. An empty cpu_model used to
	//      cascade in the frontend and suppress Traffic/Total rows, so the
	//      most important invariant here is: on Linux, NEVER return "".
	output, err := runCommandOutput(probeCommandTimeout, "sh", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	if err == nil {
		model = strings.TrimSpace(string(output))
	}

	if model == "" {
		output, err = runCommandOutput(slowProbeCommandTimeout, "sh", "-c", "lscpu | grep 'Model name' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
		if err == nil {
			model = strings.TrimSpace(string(output))
		}
	}

	// Fallback via gopsutil — handles ARM /proc/cpuinfo layouts that don't
	// carry a "model name" line (Raspberry Pi, Ampere Altra, etc.).
	if model == "" {
		if info, err := cpu.Info(); err == nil && len(info) > 0 {
			model = strings.TrimSpace(info[0].ModelName)
		}
	}

	// x86 CPUID fallback — asks the silicon directly for its brand
	// string, bypassing /proc entirely. This is the authoritative source
	// on LXC containers with a broken lxcfs (ENOTCONN on /proc/cpuinfo)
	// and AMD/Intel servers where /proc has been stripped for security.
	// On ARM/other architectures this is a no-op stub; all other
	// fallbacks below still apply.
	if model == "" {
		if brand := cpuBrandStringFromCPUID(); brand != "" {
			model = brand
		}
	}

	// Raw ARM-style /proc/cpuinfo probing as a secondary fallback.
	if model == "" {
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			// Walk the file once, pick the first non-empty match among the
			// candidate keys in priority order.
			armKeys := []string{"Hardware", "Model", "Processor", "CPU part"}
			fields := map[string]string{}
			for _, line := range strings.Split(string(data), "\n") {
				colon := strings.Index(line, ":")
				if colon <= 0 {
					continue
				}
				k := strings.TrimSpace(line[:colon])
				v := strings.TrimSpace(line[colon+1:])
				if v == "" {
					continue
				}
				if _, exists := fields[k]; !exists {
					fields[k] = v
				}
			}
			for _, k := range armKeys {
				if v := fields[k]; v != "" {
					model = v
					break
				}
			}
		}
	}

	// ARM SBC fallback — Raspberry Pi, Rockchip boards, etc. expose the
	// board / SoC model as a NUL-terminated string in the device-tree.
	if model == "" {
		if data, err := os.ReadFile("/sys/firmware/devicetree/base/model"); err == nil {
			s := strings.TrimRight(strings.TrimSpace(string(data)), "\x00")
			if s != "" {
				model = s
			}
		}
	}

	// DMI fallback — x86 systems expose the board/system vendor via DMI.
	// This isn't the CPU model per se, but it's more descriptive than
	// "x86_64 CPU" when /proc/cpuinfo and lscpu are fully stripped. Most
	// LXC templates leave /sys/devices/virtual/dmi/id readable, so this
	// commonly succeeds where the /proc/* paths don't.
	if model == "" {
		for _, p := range []string{
			"/sys/devices/virtual/dmi/id/product_name",
			"/sys/devices/virtual/dmi/id/sys_vendor",
			"/sys/devices/virtual/dmi/id/board_name",
		} {
			if data, err := os.ReadFile(p); err == nil {
				s := strings.TrimSpace(string(data))
				// Common uninformative placeholders put there by cloud /
				// virtualisation vendors — reject rather than display.
				lower := strings.ToLower(s)
				if s != "" &&
					!strings.Contains(lower, "to be filled") &&
					!strings.Contains(lower, "not specified") &&
					!strings.Contains(lower, "default string") &&
					!strings.Contains(lower, "system product") &&
					lower != "unknown" {
					model = s
					break
				}
			}
		}
	}

	// Absolute last resort — we still want a non-empty string so the
	// frontend doesn't treat this system as "placeholder / not yet reporting"
	// and hide Traffic/Total in the details section. Combine architecture
	// (uname -m) with the cgroup-aware core count so even a stripped-down
	// LXC with an empty /proc/cpuinfo shows something like
	// "aarch64 CPU @ 1 Core" instead of a bare "CPU 1 Core".
	if model == "" {
		arch := ""
		if out, err := runCommandOutput(probeCommandTimeout, "uname", "-m"); err == nil {
			arch = strings.TrimSpace(string(out))
		}
		if arch == "" {
			arch = runtime.GOARCH // x86_64-ish fallback via the Go runtime
		}

		// Prefer cgroup-reported core count (accurate inside LXC with a
		// CPU limit); fall back to runtime.NumCPU (which itself respects
		// cgroups on modern Go) and finally to 1.
		cores := getCgroupCPUCount()
		if cores <= 0 {
			cores = runtime.NumCPU()
		}
		if cores <= 0 {
			cores = 1
		}

		if arch != "" {
			model = fmt.Sprintf("%s CPU %d Core", arch, cores)
		} else {
			model = fmt.Sprintf("CPU %d Core", cores)
		}

		// Skip the core-count / virt-type formatting block below — we've
		// already baked the core count into the label.
		cacheMutex.Lock()
		cpuModelCache = model
		cpuModelCacheTime = time.Now()
		cacheMutex.Unlock()
		return model
	}

	// Check if model already contains frequency
	// Intel CPUs usually have it, AMD CPUs usually don't
	hasFreqLinux := strings.Contains(model, "GHz") || strings.Contains(model, "MHz")
	var speedLinux string

	// Get frequency if not in model name (typically AMD CPUs)
	if !hasFreqLinux {
		// Get CPU frequency (MHz) and convert to GHz
		output, err = runCommandOutput(probeCommandTimeout, "sh", "-c", "grep -m1 'cpu MHz' /proc/cpuinfo | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
		if err == nil {
			var mhz float64
			if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &mhz); err == nil && mhz > 0 {
				speedLinux = fmt.Sprintf("%.2f", mhz/1000.0)
			}
		}

		// If speed not found, try lscpu
		if speedLinux == "" {
			output, err = runCommandOutput(slowProbeCommandTimeout, "sh", "-c", "lscpu | grep 'CPU MHz' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
			if err == nil {
				var mhz float64
				if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &mhz); err == nil && mhz > 0 {
					speedLinux = fmt.Sprintf("%.2f", mhz/1000.0)
				}
			}
		}

		// Try /sys/devices/system/cpu/cpu0/cpufreq/* — in kHz.
		if speedLinux == "" {
			for _, p := range []string{
				"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
				"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq",
				"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
			} {
				if data, err := os.ReadFile(p); err == nil {
					if khz, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil && khz > 0 {
						speedLinux = fmt.Sprintf("%.2f", float64(khz)/1e6)
						break
					}
				}
			}
		}

		// Last resort: calibrate against the TSC (x86_64 only — returns 0
		// on ARM etc.). This bypasses /proc and /sys entirely and works
		// even inside LXC containers where lxcfs has masked every
		// kernel-backed frequency source. Runs once per process (~80ms).
		if speedLinux == "" {
			if mhz := tscFrequencyMHz(); mhz > 0 {
				speedLinux = fmt.Sprintf("%.2f", mhz/1000.0)
			}
		}
	}

	// Get physical cores and virtual cores from lscpu (note: inside an LXC
	// container without lxcfs, lscpu reflects the HOST, not the container —
	// we correct for that below using the cgroup limit).
	output, err = runCommandOutput(slowProbeCommandTimeout, "sh", "-c", "lscpu | grep '^Core(s) per socket:' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	physicalCores := 0
	if err == nil {
		var sockets, coresPerSocket int
		fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &coresPerSocket)

		// Get number of sockets
		output, err = runCommandOutput(slowProbeCommandTimeout, "sh", "-c", "lscpu | grep '^Socket(s):' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
		if err == nil {
			fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &sockets)
		}

		physicalCores = sockets * coresPerSocket
	}

	// Get total logical CPU count reported by lscpu (host-wide when inside
	// a container without lxcfs — see cgroup override below).
	output, err = runCommandOutput(slowProbeCommandTimeout, "sh", "-c", "lscpu | grep '^CPU(s):' | cut -d':' -f2 | sed 's/^[[:space:]]*//'")
	virtualCores := 0
	if err == nil {
		fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &virtualCores)
	}

	// ── Cgroup-aware override (LXC / Docker / k8s / podman / nspawn) ──
	// Inside any container runtime the kernel exposes the HOST CPU
	// topology to lscpu, gopsutil and /proc/cpuinfo. The only reliable
	// source of the container's actual CPU allocation is the cgroup
	// hierarchy. If a stricter limit is in effect (cfs_quota / cpuset),
	// clamp virtualCores down to it so users see "2 Virtual Core" for a
	// 2-core LXC instead of "48 Virtual Core" borrowed from the host.
	if cgroupCount := getCgroupCPUCount(); cgroupCount > 0 {
		if virtualCores == 0 || cgroupCount < virtualCores {
			virtualCores = cgroupCount
		}
	}

	// Core type is authoritative from getVirtualizationType() (which
	// already consults isLinuxContainer as Method 1b and therefore
	// correctly classifies LXC/Docker/k8s as VPS). Reuse the value
	// computed at `virtType` above; do NOT re-run the container probe
	// here or re-probe "Hypervisor vendor" via lscpu — both would be
	// redundant with the work already done in getVirtualizationType.
	if virtType == "VPS" {
		coreType = "Virtual"
	} else {
		coreType = "Physical"
	}

	// Pick the final core count: prefer the (cgroup-clamped) logical
	// count, fall back to physical cores, last resort count
	// /proc/cpuinfo directly.
	if virtualCores > 0 {
		coreCount = virtualCores
	} else if physicalCores > 0 {
		coreCount = physicalCores
	} else {
		output, err = runCommandOutput(probeCommandTimeout, "sh", "-c", "grep -c '^processor' /proc/cpuinfo")
		if err == nil {
			fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &coreCount)
		}
		// Even /proc/cpuinfo lies inside a container: apply the cgroup
		// cap one more time so the last-resort path stays honest.
		if cg := getCgroupCPUCount(); cg > 0 && (coreCount == 0 || cg < coreCount) {
			coreCount = cg
		}
	}

	// Format output.
	// Add frequency if not already in model name (AMD CPUs).
	// Cache the final string so the next poll (every 3 s) can early-return
	// without re-running 5+ shell subprocesses — the CPU model is effectively
	// immutable for the process lifetime. We only reached this point by
	// running those shell probes already, so without caching we'd pay that
	// cost on every metrics push.
	var final string
	if speedLinux != "" && coreCount > 0 {
		final = fmt.Sprintf("%s @ %sGHz %d %s Core", model, speedLinux, coreCount, coreType)
	} else if coreCount > 0 {
		final = fmt.Sprintf("%s %d %s Core", model, coreCount, coreType)
	} else {
		final = model
	}
	cacheMutex.Lock()
	cpuModelCache = final
	cpuModelCacheTime = time.Now()
	cacheMutex.Unlock()
	return final
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
		output, err := runCommandOutput(slowProbeCommandTimeout, "wmic", "computersystem", "get", "model", "/format:list")
		if err == nil {
			outputStr := strings.ToLower(string(output))
			// Exact VM model names - these are ONLY used by virtual machines
			vmModels := []string{
				"vmware virtual platform", // VMware
				"vmware7,1",               // VMware Fusion
				"virtual machine",         // Hyper-V VM
				"virtualbox",              // VirtualBox
				"kvm",                     // KVM
				"qemu",                    // QEMU
				"hvm domu",                // Xen HVM
				"bochs",                   // Bochs
				"amazon ec2",              // AWS
				"google compute engine",   // GCP
				"droplet",                 // DigitalOcean
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
		output, err = runCommandOutput(slowProbeCommandTimeout, "wmic", "bios", "get", "manufacturer", "/format:list")
		if err == nil {
			outputStr := strings.ToLower(string(output))
			// BIOS manufacturers that are VM-specific
			vmBiosManufacturers := []string{
				"vmware",     // VMware
				"innotek",    // VirtualBox
				"parallels",  // Parallels
				"seabios",    // QEMU/KVM
				"xen",        // Xen
				"amazon ec2", // AWS
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
		output, err = runCommandOutput(slowProbeCommandTimeout, "wmic", "baseboard", "get", "manufacturer", "/format:list")
		if err == nil {
			outputStr := strings.ToLower(string(output))
			// Motherboard manufacturers that are VM-specific
			vmBaseboardMfrs := []string{
				"vmware",
				"oracle corporation",            // VirtualBox
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
	// Method 1: systemd-detect-virt (most reliable on modern Linux).
	// Handles both hypervisor-based VMs ("kvm", "qemu", "xen", ...) and
	// container runtimes ("lxc", "docker", "podman", "systemd-nspawn").
	output, err := runCommandOutput(probeCommandTimeout, "systemd-detect-virt")
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

	// Method 1b: container runtime detection — LXC/Docker/k8s/podman do
	// not expose a hypervisor flag, so the hypervisor-flag based methods
	// below would miss them entirely. This check is especially important
	// on minimal LXC images where systemd-detect-virt is not installed
	// (Method 1 above would silently error out).
	if isLinuxContainer() {
		result := "VPS"
		cacheMutex.Lock()
		virtualizationTypeCache = result
		virtualizationTypeCacheTime = time.Now()
		cacheMutex.Unlock()
		return result
	}

	// Method 2: Check for hypervisor vendor in lscpu (fallback if systemd-detect-virt not available)
	output, err = runCommandOutput(slowProbeCommandTimeout, "sh", "-c", "lscpu 2>/dev/null | grep -i 'Hypervisor vendor' | cut -d':' -f2")
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
	output, err = runCommandOutput(probeCommandTimeout, "sh", "-c", "grep -w 'hypervisor' /proc/cpuinfo 2>/dev/null")
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		result := "VPS"
		cacheMutex.Lock()
		virtualizationTypeCache = result
		virtualizationTypeCacheTime = time.Now()
		cacheMutex.Unlock()
		return result
	}

	// Method 4: Check DMI for known virtualization products
	output, err = runCommandOutput(probeCommandTimeout, "sh", "-c", "cat /sys/class/dmi/id/product_name 2>/dev/null")
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
	if runtime.GOOS == "darwin" {
		_, usedBytes, totalBytes, err := macOSMemoryStats()
		if err == nil && totalBytes > 0 {
			return fmt.Sprintf("%s / %s", formatBytes(usedBytes), formatBytes(totalBytes))
		}
		return ""
	}
	if runtime.GOOS == "windows" {
		vmStat, err := mem.VirtualMemory()
		if err == nil {
			return fmt.Sprintf("%s / %s", formatBytes(vmStat.Used), formatBytes(vmStat.Total))
		}
		return ""
	}

	// Step 1 — Authoritative cgroup limit, if one is set.
	//
	// When the kernel has an explicit memory limit for this cgroup, that
	// is ALWAYS the most accurate container total: it doesn't depend on
	// lxcfs, doesn't depend on how /proc/meminfo is virtualised, and
	// can't be confused by a privileged container that exposes the host's
	// /proc. We check this BEFORE /proc/meminfo because several common
	// container setups expose the host's /proc/meminfo even when a
	// cgroup limit IS in force (Docker without --pid=host quirks,
	// unprivileged LXC without meminfo bind-mount, systemd-nspawn, etc.).
	//
	// On bare-metal Linux there's no cgroup memory limit at the root
	// (memory.max = "max"), so getCgroupMemoryStats returns ok=false and
	// we fall through to /proc/meminfo — no change in behaviour.
	if u, t, ok := getCgroupMemoryStats(); ok && t > 0 {
		return fmt.Sprintf("%s / %s", formatBytes(u), formatBytes(t))
	}

	// Step 2 — /proc/meminfo. Works for bare metal and for containers
	// where lxcfs is alive and properly virtualising meminfo.
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		// Step 3a — /proc/meminfo unreadable (lxcfs ENOTCONN). Fall back
		// to cgroup.current + sysinfo host total. This is the best we
		// can do for an unlimited container with a broken lxcfs.
		if u, t, ok := resolveMemoryStats(); ok && t > 0 {
			return fmt.Sprintf("%s / %s", formatBytes(u), formatBytes(t))
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
		// Step 3b — /proc/meminfo was readable but MemTotal is 0 (lxcfs
		// quirk on unprivileged LXC, or an intentionally empty bind
		// mount). resolveMemoryStats walks every alternative source.
		if u, t, ok := resolveMemoryStats(); ok && t > 0 {
			return fmt.Sprintf("%s / %s", formatBytes(u), formatBytes(t))
		}
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
	if runtime.GOOS == "darwin" {
		usedBytes, totalBytes := macOSSwapStats()
		if totalBytes > 0 {
			return fmt.Sprintf("%s / %s", formatBytes(usedBytes), formatBytes(totalBytes))
		}
		return "0 B / 0 B"
	}
	if runtime.GOOS == "windows" {
		swapStat, err := mem.SwapMemory()
		if err == nil && swapStat.Total > 0 {
			return fmt.Sprintf("%s / %s", formatBytes(swapStat.Used), formatBytes(swapStat.Total))
		}
		return "0 B / 0 B"
	}

	// Step 1 — Authoritative cgroup swap limit, if one is set. Same
	// rationale as getMemoryInfo: when the kernel enforces a container
	// swap limit we report that, not whatever /proc/meminfo claims.
	if u, t, ok := getCgroupSwapStats(); ok && t > 0 {
		return fmt.Sprintf("%s / %s", formatBytes(u), formatBytes(t))
	}

	// Step 2 — /proc/meminfo. Falls back to cgroup + sysinfo when
	// /proc is unreadable (lxcfs ENOTCONN). We always return something
	// ("0 B / 0 B" at worst) so the frontend can distinguish "no swap
	// configured" from "no data yet".
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		if u, t, ok := resolveSwapStats(); ok {
			if t > 0 {
				return fmt.Sprintf("%s / %s", formatBytes(u), formatBytes(t))
			}
			return "0 B / 0 B" // no swap on host
		}
		return "0 B / 0 B"
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
		// /proc/meminfo reports no swap. On LXC with zeroed-out meminfo this
		// might be wrong — consult the resolver for a second opinion that
		// includes cgroup swap files and sysinfo(2).
		if u, t, ok := resolveSwapStats(); ok && t > 0 {
			return fmt.Sprintf("%s / %s", formatBytes(u), formatBytes(t))
		}
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
	// Check cache — same reason as getDiskUsage: df+awk is expensive to run every 3 s.
	diskCacheMu.RLock()
	if !diskInfoCacheTime.IsZero() && time.Since(diskInfoCacheTime) < diskCacheTTL {
		v := diskInfoCache
		diskCacheMu.RUnlock()
		return v
	}
	diskCacheMu.RUnlock()

	result := computeDiskInfo()

	diskCacheMu.Lock()
	diskInfoCache = result
	diskInfoCacheTime = time.Now()
	diskCacheMu.Unlock()

	return result
}

func computeDiskInfo() string {
	// Use gopsutil for cross-platform support
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Get all partitions and sum up
		partitions, err := disk.Partitions(false)
		if err == nil {
			var totalSize, totalUsed uint64
			seenBaseDisks := make(map[string]bool) // macOS: APFS deduplication
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
					// macOS APFS: same deduplication logic as computeDiskUsage
					mp := partition.Mountpoint
					if mp != "/" && !strings.HasPrefix(mp, "/Volumes/") {
						continue
					}
					if !strings.HasPrefix(partition.Device, "/dev/disk") {
						continue
					}
					baseDisk := macOSBaseDisk(partition.Device)
					if seenBaseDisks[baseDisk] {
						continue
					}
					seenBaseDisks[baseDisk] = true
					usage, err := disk.Usage(mp)
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
	output, err := runCommandOutput(probeCommandTimeout, "sh", "-c", `df -B1 -T 2>/dev/null | tail -n +2 | awk '
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
	output, err = runCommandOutput(probeCommandTimeout, "sh", "-c", "df -h / | tail -1 | awk '{print $3 \"/\" $2}'")
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

// macOSBaseDisk extracts the base APFS container name from a macOS device path.
// On macOS, APFS partitions share one physical container and all report its full
// capacity. Deduplicating by the base disk avoids counting the same storage N times.
// Examples: "/dev/disk3s6" -> "disk3", "/dev/disk3s1s1" -> "disk3"
func macOSBaseDisk(device string) string {
	name := strings.TrimPrefix(device, "/dev/")
	re := regexp.MustCompile(`^(disk\d+)s`)
	if m := re.FindStringSubmatch(name); len(m) > 1 {
		return m[1]
	}
	return name
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// Auto-generated comment to trigger workflow
// Trigger workflow rebuild with static compilation
