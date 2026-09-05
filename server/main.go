package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// secretEqual performs a constant-time comparison of two secret strings.
//
// Plain `==` / `!=` on Go strings short-circuits on the first byte mismatch,
// which leaks timing information an attacker can use to guess a secret
// byte-by-byte (a classic side-channel attack). `subtle.ConstantTimeCompare`
// always walks both operands to completion — its runtime depends only on the
// length of the inputs, never on their content. We use it for every check
// that compares a user-supplied credential against a server-side secret:
// per-system `Secret`, privacy `ShareToken`, and in-memory `authTokens`
// lookups where the key is constructed from attacker-controlled input.
//
// The length-mismatch early return is itself safe because the length of a
// real secret is public (it's either the 16-char base64 from generateSecret,
// the 44-char base64 from GenerateAuthToken, or an admin-chosen string whose
// length is not itself a secret). Returning early on length mismatch avoids
// a fixed-size buffer allocation for obviously bogus inputs.
func secretEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

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

func staticFilePathFromURL(urlPath string) (string, bool) {
	path := strings.TrimPrefix(urlPath, "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return "index.html", true
	}
	if path == "." || strings.Contains(path, "\\") || !fs.ValidPath(path) {
		return "", false
	}
	return path, true
}

type SystemMetric struct {
	ID                 string                      `json:"id"`
	Name               string                      `json:"name"`
	IPv4               string                      `json:"ipv4,omitempty"`
	IPv6               string                      `json:"ipv6,omitempty"`
	Time               string                      `json:"time,omitempty"`
	Location           string                      `json:"location,omitempty"`
	VirtualizationType string                      `json:"virtualization_type,omitempty"` // "VPS" or "DS"
	OS                 string                      `json:"os,omitempty"`
	OSIcon             string                      `json:"os_icon,omitempty"`
	CPU                float64                     `json:"cpu"`
	CPUModel           string                      `json:"cpu_model,omitempty"`
	Memory             float64                     `json:"memory"`
	MemoryInfo         string                      `json:"memory_info,omitempty"` // Format: "383.60 MiB / 1.88 GiB"
	SwapInfo           string                      `json:"swap_info,omitempty"`   // Format: "75.12 MiB / 975.00 MiB"
	Disk               float64                     `json:"disk"`
	DiskInfo           string                      `json:"disk_info,omitempty"` // Format: "9.86 GiB / 18.58 GiB"
	NetInMBps          float64                     `json:"net_in_mb_s"`
	NetOutMBps         float64                     `json:"net_out_mb_s"`
	TotalNetInBytes    uint64                      `json:"total_net_in_bytes,omitempty"`  // Total received bytes
	TotalNetOutBytes   uint64                      `json:"total_net_out_bytes,omitempty"` // Total transmitted bytes
	AgentVersion       string                      `json:"agent_version"`
	Order              int                         `json:"order"` // Display order for sorting
	Alert              bool                        `json:"alert"`
	UpdatedAt          time.Time                   `json:"updated_at"`
	TCPingData         map[string]TCPingTargetData `json:"tcping_data,omitempty"`
	// Targets this write carries a fresh sample for (agent push only); the
	// store lets such entries win over a newer-looking stored copy. Never
	// serialised.
	TCPingFresh map[string]struct{} `json:"-"`                // Map of target -> latest tcping data
	Tags        []string            `json:"tags,omitempty"`   // User-defined tags for the service
	Secret      string              `json:"secret,omitempty"` // Secret for client authentication
	// Admin-controlled visibility toggles. Both default to false (= shown).
	// HideOnHome hides the row from the public homepage only; the REST API
	// and the admin dashboard still return it. HideTCPing hides just the
	// tcping card of this system on the homepage. Agents never set these;
	// every client write path preserves the stored values.
	HideOnHome bool `json:"hide_on_home,omitempty"`
	HideTCPing bool `json:"hide_tcping,omitempty"`
}

// TCPingTargetData represents the latest tcping data for a specific target
type TCPingTargetData struct {
	Latency   float64   `json:"latency"`   // Latest tcping latency in ms
	Timestamp time.Time `json:"timestamp"` // Latest tcping timestamp
}

// TCPing statistics
type TCPingStats struct {
	AvgLatency     float64 `json:"avg_latency"`      // Average latency in milliseconds
	PacketLossRate float64 `json:"packet_loss_rate"` // Packet loss rate in percentage
}

// TCPing API response with statistics
type TCPingHistoryResponse struct {
	Results []TCPingResult `json:"results"`
	Stats   TCPingStats    `json:"stats"`
}

// TCPing query cache to reduce database load.
//
// We cache the *already-encoded* JSON body, not the struct, so a cache hit
// can short-circuit straight to a single ResponseWriter.Write of an
// immutable byte slice. Re-encoding the same TCPingHistoryResponse on every
// hit was measurable on busy deployments (every result row contains a
// pointer-to-float and a time.Time that goes through RFC3339 formatting),
// and json.Encoder.Encode does not memoise. Trading a fixed-size []byte for
// the struct also lets the entry be served read-locked without the encoder
// touching shared state.
type tcpingCacheEntry struct {
	JSON     []byte // marshaled body of TCPingHistoryResponse, ready to ship
	CachedAt time.Time
	Size     int
}

type tcpingCacheKey struct {
	ClientID string
	Target   string
}

var (
	tcpingCache           = make(map[tcpingCacheKey]*tcpingCacheEntry)
	tcpingCacheMu         sync.RWMutex
	tcpingCacheTTL        = 2 * time.Minute // Cache results for 2 minutes
	tcpingCacheMaxEntries = 512
	tcpingCacheMaxBytes   = 32 << 20 // 32 MiB hard cap for cached response bodies
	tcpingCacheBytes      int
)

// Get the cached pre-encoded JSON body if present and not expired.
// The returned slice is owned by the cache and MUST NOT be mutated by the
// caller; the writer only reads from it.
func getCachedTCPingResultsJSON(clientID, target string) ([]byte, bool) {
	tcpingCacheMu.RLock()
	defer tcpingCacheMu.RUnlock()

	entry, exists := tcpingCache[tcpingCacheKey{ClientID: clientID, Target: target}]
	if !exists {
		return nil, false
	}

	if time.Since(entry.CachedAt) > tcpingCacheTTL {
		return nil, false
	}

	return entry.JSON, true
}

// Cache the pre-encoded TCPing response body. Marshal failures fall back to
// not caching (the next request will retry); we never cache a partial body.
//
// The byte layout matches what json.Encoder.Encode would produce — i.e. the
// JSON value followed by a single trailing '\n'. That way cache-hit and
// cache-miss responses are byte-identical on the wire, which simplifies
// downstream tooling (e.g. ETag generation, log diffs, conformance tests).
func cacheTCPingResults(clientID, target string, response TCPingHistoryResponse) {
	if target == "" {
		return
	}

	body, err := json.Marshal(response)
	if err != nil {
		return
	}
	body = append(body, '\n')
	if len(body) > tcpingCacheMaxBytes {
		// Preserve data completeness: over-budget responses are still sent to
		// the caller by handleGetTCPingHistory; we only skip keeping a copy.
		return
	}

	key := tcpingCacheKey{ClientID: clientID, Target: target}
	tcpingCacheMu.Lock()
	defer tcpingCacheMu.Unlock()

	tcpingCacheDeleteLocked(key)
	tcpingCache[key] = &tcpingCacheEntry{
		JSON:     body,
		CachedAt: time.Now(),
		Size:     len(body),
	}
	tcpingCacheBytes += len(body)
	tcpingCacheEnforceBudgetLocked(time.Now())
}

func tcpingCacheDeleteLocked(key tcpingCacheKey) {
	entry, ok := tcpingCache[key]
	if !ok {
		return
	}
	tcpingCacheBytes -= entry.Size
	if tcpingCacheBytes < 0 {
		tcpingCacheBytes = 0
	}
	delete(tcpingCache, key)
}

func tcpingCachePruneExpiredLocked(now time.Time) {
	for key, entry := range tcpingCache {
		if now.Sub(entry.CachedAt) > tcpingCacheTTL {
			tcpingCacheDeleteLocked(key)
		}
	}
}

func tcpingCacheEnforceBudgetLocked(now time.Time) {
	tcpingCachePruneExpiredLocked(now)
	for (len(tcpingCache) > tcpingCacheMaxEntries || tcpingCacheBytes > tcpingCacheMaxBytes) && len(tcpingCache) > 0 {
		var oldestKey tcpingCacheKey
		var oldestAt time.Time
		first := true
		for key, entry := range tcpingCache {
			if first || entry.CachedAt.Before(oldestAt) {
				oldestKey = key
				oldestAt = entry.CachedAt
				first = false
			}
		}
		tcpingCacheDeleteLocked(oldestKey)
	}
}

// Calculate TCPing statistics from results
func calculateTCPingStats(results []TCPingResult) TCPingStats {
	const PACKET_LOSS_THRESHOLD_MS = 1000.0

	totalCount := 0
	successCount := 0
	totalLatency := 0.0

	for _, result := range results {
		totalCount++
		if result.Latency != nil && *result.Latency <= PACKET_LOSS_THRESHOLD_MS {
			successCount++
			totalLatency += *result.Latency
		}
		// nil latency or > 1000ms is considered packet loss
	}

	stats := TCPingStats{
		AvgLatency:     0.0,
		PacketLossRate: 0.0,
	}

	if successCount > 0 {
		stats.AvgLatency = totalLatency / float64(successCount)
	}

	if totalCount > 0 {
		packetLossCount := totalCount - successCount
		stats.PacketLossRate = float64(packetLossCount) / float64(totalCount) * 100.0
	}

	return stats
}

// Invalidate TCPing cache for a specific client
// Called when new TCPing data is saved to ensure data freshness
func invalidateTCPingCache(clientID string) {
	tcpingCacheMu.Lock()
	defer tcpingCacheMu.Unlock()

	for key := range tcpingCache {
		if key.ClientID == clientID {
			tcpingCacheDeleteLocked(key)
		}
	}
}

// Clear all TCPing cache
// Called when TCPing configuration changes or targets are deleted
func clearAllTCPingCache() {
	tcpingCacheMu.Lock()
	defer tcpingCacheMu.Unlock()

	// Clear the entire cache by creating a new map
	tcpingCache = make(map[tcpingCacheKey]*tcpingCacheEntry)
	tcpingCacheBytes = 0
}

// Cleanup expired cache entries periodically
func startTCPingCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		tcpingCacheMu.Lock()
		tcpingCachePruneExpiredLocked(time.Now())
		tcpingCacheMu.Unlock()
	}
}

type metricPayload struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	IPv4               string   `json:"ipv4,omitempty"`
	IPv6               string   `json:"ipv6,omitempty"`
	Uptime             int64    `json:"uptime"` // Uptime in seconds
	Location           string   `json:"location,omitempty"`
	VirtualizationType string   `json:"virtualization_type,omitempty"` // "VPS" or "DS"
	OS                 string   `json:"os,omitempty"`
	OSIcon             string   `json:"os_icon,omitempty"`
	CPU                float64  `json:"cpu"`
	CPUModel           string   `json:"cpu_model,omitempty"`
	Memory             float64  `json:"memory"`
	MemoryInfo         string   `json:"memory_info,omitempty"` // Format: "383.60 MiB / 1.88 GiB"
	SwapInfo           string   `json:"swap_info,omitempty"`   // Format: "75.12 MiB / 975.00 MiB"
	Disk               float64  `json:"disk"`
	DiskInfo           string   `json:"disk_info,omitempty"` // Format: "9.86 GiB / 18.58 GiB"
	NetInMBps          float64  `json:"net_in_mb_s"`
	NetOutMBps         float64  `json:"net_out_mb_s"`
	TotalNetInBytes    uint64   `json:"total_net_in_bytes,omitempty"`  // Total received bytes
	TotalNetOutBytes   uint64   `json:"total_net_out_bytes,omitempty"` // Total transmitted bytes
	AgentVersion       string   `json:"agent_version"`
	Alert              bool     `json:"alert"`
	Tags               []string `json:"tags,omitempty"`   // User-defined tags
	Secret             string   `json:"secret,omitempty"` // Secret for client authentication (sent by client during registration)
	// Admin-only visibility toggles. Pointers so "not provided" (agent
	// pushes, older admin UIs) is distinguishable from an explicit false.
	HideOnHome *bool `json:"hide_on_home,omitempty"`
	HideTCPing *bool `json:"hide_tcping,omitempty"`
}

// SSE Broker for broadcasting updates.
//
// The broker supports two subscriber "views" so the server can push a single
// stream of state-carrying events that is correctly masked per-subscriber:
//
//   - SSEViewPublic: anonymous / share-token users. IPv4, IPv6 and Secret are
//     always stripped before the payload reaches this subscriber.
//   - SSEViewAdmin:  authenticated admin users. Full payload is delivered.
//
// The view is locked in at Subscribe() time (i.e. at SSE connection time) and
// is the same level that the request was authorised at. This matches the
// existing semantics of GET /api/metrics, where the auth decision is made
// once per request.
//
// For state-carrying events (such as "metric_updated" which now embeds the
// full systems list), the caller uses BroadcastByView to deliver a distinct
// pre-marshaled payload per view. For pure signal events (like ping, or
// best-effort notifications), Broadcast delivers the same payload to every
// subscriber regardless of view.
type SSEView int

const (
	SSEViewPublic SSEView = iota
	SSEViewAdmin
)

// Per-subscriber bounded channel.
//
// Because every state-carrying broadcast we send contains the complete,
// authoritative system list, a subscriber that is briefly slow to drain its
// queue can discard older events without losing information — the next event
// fully supersedes everything queued before it. A small buffer (2) is
// therefore sufficient and keeps worst-case memory use bounded even when
// payloads grow: ~N subscribers × 2 events × payload size, rather than
// 30 × payload size per subscriber.
const sseSubscriberBuffer = 2

// Subscriber caps. Every subscriber costs a goroutine, a TCP connection and
// up to sseSubscriberBuffer queued full snapshots, and /api/events is
// reachable anonymously whenever privacy mode is off. Without a ceiling a
// single misbehaving client could open thousands of streams and drive RSS
// up by 2 × snapshot size per stream. The per-IP cap is generous on purpose:
// behind an untrusted reverse proxy all viewers share one address.
// Defaults; override with SSE_MAX_STREAMS / SSE_MAX_STREAMS_PER_IP. Behind a
// reverse proxy that is not listed in TRUSTED_PROXIES every viewer shares the
// proxy's address, so the per-IP limit should then be raised (or the proxy
// trusted). Authenticated admin streams are exempt from both caps: they are
// gated by a login token, and an operator must never be locked out of the
// dashboard by anonymous traffic.
const (
	sseDefaultMaxSubscribers      = 2000
	sseDefaultMaxSubscribersPerIP = 200
	// Per-write deadline. WriteTimeout on http.Server must stay 0 for SSE,
	// so a peer that stops reading (half-open NAT, frozen tab on a lossy
	// link) would otherwise block the handler in Flush forever and pin its
	// goroutine and connection. 15 s is far above any realistic flush time
	// for a payload of a few hundred KB.
	sseWriteTimeout = 15 * time.Second
)

var errSSETooManySubscribers = fmt.Errorf("too many event stream subscribers")

type sseSubscriber struct {
	ch   chan string
	view SSEView
	ip   string
}

type SSEBroker struct {
	clients  map[*sseSubscriber]struct{}
	perIP    map[string]int
	maxTotal int
	maxPerIP int
	mu       sync.RWMutex

	// Latest state-carrying payload per view, remembered by BroadcastByView
	// and by connect-time builds (RememberSnapshot) so a freshly connected
	// subscriber can be primed without rebuilding the snapshot from the
	// database on every connection (see LatestSnapshot).
	latest   map[SSEView]string
	latestAt map[SSEView]time.Time
	primeMu  [2]sync.Mutex
}

// sseSnapshotMaxAge bounds how old a remembered payload may be before a new
// subscriber gets a freshly built one. It must stay well below the 3 s
// broadcast tick: the homepage fetches /api/metrics right before it opens
// the stream, and priming it with a payload older than that fetch makes
// every value visibly jump backwards for one tick on each page load.
const sseSnapshotMaxAge = time.Second

// LatestSnapshot returns the most recent payload for view when it is younger
// than sseSnapshotMaxAge.
func (b *SSEBroker) LatestSnapshot(view SSEView) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.latest == nil {
		return "", false
	}
	if at, ok := b.latestAt[view]; !ok || time.Since(at) > sseSnapshotMaxAge {
		return "", false
	}
	payload, ok := b.latest[view]
	return payload, ok
}

// RememberSnapshot stores a payload built at connect time so that other
// subscribers connecting within sseSnapshotMaxAge (a reconnect storm after a
// restart or a CDN blip) reuse it instead of each scanning the database.
// builtAt is when the caller started building; when a broadcast has been
// remembered since then, that broadcast is newer and is returned instead so
// the caller never primes anyone, itself included, with older data.
func (b *SSEBroker) RememberSnapshot(view SSEView, payload string, builtAt time.Time) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.latest == nil {
		b.latest = make(map[SSEView]string)
		b.latestAt = make(map[SSEView]time.Time)
	}
	if at, ok := b.latestAt[view]; ok && at.After(builtAt) {
		if cur, ok := b.latest[view]; ok {
			return cur
		}
	}
	b.latest[view] = payload
	b.latestAt[view] = builtAt
	return payload
}

// primeLock serialises connect-time snapshot builds per view, so a burst of
// connections that all miss LatestSnapshot costs one database scan instead
// of one per viewer. The returned function releases the lock.
func (b *SSEBroker) primeLock(view SSEView) func() {
	idx := 0
	if view == SSEViewAdmin {
		idx = 1
	}
	b.primeMu[idx].Lock()
	return b.primeMu[idx].Unlock
}

func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		clients:  make(map[*sseSubscriber]struct{}),
		perIP:    make(map[string]int),
		maxTotal: intFromEnv("SSE_MAX_STREAMS", sseDefaultMaxSubscribers),
		maxPerIP: intFromEnv("SSE_MAX_STREAMS_PER_IP", sseDefaultMaxSubscribersPerIP),
	}
}

// perIPCapApplies reports whether the per-address stream cap counts this
// client address. Behind a docker bridge, the bundled nginx or a reverse
// proxy that is not listed in TRUSTED_PROXIES every viewer resolves to the
// same private address, and capping that turned the per-IP limit into a
// global 200-viewer limit. Only globally routable addresses are therefore
// capped individually; the total cap still bounds everything else.
func perIPCapApplies(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsGlobalUnicast() && !p.IsPrivate()
}

// intFromEnv reads a positive integer from the environment, falling back to
// def when unset or invalid.
func intFromEnv(name string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil && v > 0 {
		return v
	}
	return def
}

// Subscribe registers a new subscriber with the given view level. The returned
// pointer must be passed to Unsubscribe when the SSE handler exits. Public
// subscriptions fail with errSSETooManySubscribers when either cap is reached.
func (b *SSEBroker) Subscribe(view SSEView, ip string) (*sseSubscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if view != SSEViewAdmin {
		if len(b.clients) >= b.maxTotal {
			return nil, errSSETooManySubscribers
		}
		if perIPCapApplies(ip) && b.perIP[ip] >= b.maxPerIP {
			return nil, errSSETooManySubscribers
		}
	}
	sub := &sseSubscriber{
		ch:   make(chan string, sseSubscriberBuffer),
		view: view,
		ip:   ip,
	}
	b.clients[sub] = struct{}{}
	b.perIP[ip]++
	return sub, nil
}

func (b *SSEBroker) Unsubscribe(sub *sseSubscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.clients[sub]; !ok {
		return
	}
	delete(b.clients, sub)
	if b.perIP[sub.ip] <= 1 {
		delete(b.perIP, sub.ip)
	} else {
		b.perIP[sub.ip]--
	}
	close(sub.ch)
}

// SubscriberCount reports the number of live subscribers (for /api/admin/runtime).
func (b *SSEBroker) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

// Broadcast delivers the same payload to every subscriber, regardless of
// view. Intended for signal-only events (e.g. "metric_deleted" notifications,
// "order_updated" hints) that carry no privileged fields.
func (b *SSEBroker) Broadcast(event string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for sub := range b.clients {
		sendWithDropOldest(sub.ch, event)
	}
}

// BroadcastByView delivers a different pre-marshaled payload to each view
// level. The caller is responsible for ensuring each payload is correctly
// masked for its audience.
func (b *SSEBroker) BroadcastByView(byView map[SSEView]string) {
	b.mu.Lock()
	now := time.Now()
	b.latest = make(map[SSEView]string, len(byView))
	b.latestAt = make(map[SSEView]time.Time, len(byView))
	for view, payload := range byView {
		b.latest[view] = payload
		b.latestAt[view] = now
	}
	b.mu.Unlock()

	b.mu.RLock()
	defer b.mu.RUnlock()

	for sub := range b.clients {
		payload, ok := byView[sub.view]
		if !ok {
			continue
		}
		sendWithDropOldest(sub.ch, payload)
	}
}

// sendWithDropOldest delivers event into ch without ever blocking the caller.
//
// Semantics:
//   - If the buffer has room, the event is enqueued and we return.
//   - If the buffer is full, the oldest queued event is discarded to make
//     room for the new one. Because every state-carrying event carries the
//     full latest state, losing an older queued event is semantically
//     equivalent to never having sent it — the newer event fully supersedes
//     it.
//   - In the worst-case (full buffer + a concurrent sender raced us to both
//     slots) we fall through and drop the new event rather than spin.  The
//     next broadcast (within 3 s) re-syncs the subscriber from fresh state.
//
// The implementation is intentionally bounded (at most three non-blocking
// select operations, no unbounded loop) so that a pathological interleaving
// with other senders or with Unsubscribe's close(ch) can never live-lock or
// misbehave. A send onto a closed channel would panic; it is only safe
// because Unsubscribe holds the broker's write lock which excludes every
// BroadcastByView/Broadcast call holding the read lock. By the time the
// channel is closed, no sendWithDropOldest for this subscriber is running
// and the subscriber has already been removed from the clients map, so no
// new sends start.
func sendWithDropOldest(ch chan string, event string) {
	// Fast path: room in the buffer right now.
	select {
	case ch <- event:
		return
	default:
	}

	// Buffer was full — try to discard the oldest queued event.
	select {
	case <-ch:
	default:
		// Someone else (most likely the SSE reader goroutine) drained a slot
		// in between; fall through to one last send attempt.
	}

	// Final send attempt. If this fails we drop the event — a concurrent
	// sender beat us to the slot we just freed, and the subscriber will
	// converge on the next broadcast anyway.
	select {
	case ch <- event:
	default:
	}
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
	// Push mode: client actively pushes metrics (used for NAT/outbound-only servers)
	// When PushMode is true, server skips polling and instead tracks LastPushAt for offline detection
	PushMode   bool      `json:"-"` // in-memory only, not persisted
	LastPushAt time.Time `json:"-"` // time of last successful push (in-memory only)
	// LastPollAt is when pollClient last fetched /metrics from this client
	// successfully (in-memory only). The tcping loop uses it to tell a fresh
	// UpdatedAt written by our own poll from one written by a push.
	LastPollAt time.Time `json:"-"`
}

// ClientTCPingResult is a single TCPing measurement sent by the client in push mode.
//
// MeasuredAt carries the exact moment the dial completed on the client (UTC). When
// present (clients ≥ 1.3.6) the server uses it verbatim as the record timestamp so
// the saved history reflects the real measurement time, not "whenever the next 3 s
// push cycle happened to arrive". Older clients that do not send this field leave it
// at the zero value and the server falls back to its own clock.
type ClientTCPingResult struct {
	Target     string    `json:"target"`  // e.g. "8.8.8.8:53"
	Latency    float64   `json:"latency"` // milliseconds; 0 if failed
	Success    bool      `json:"success"`
	MeasuredAt time.Time `json:"measured_at,omitempty"`
}

// ClientPushResponse is returned to push-mode clients with updated TCPing config
type ClientPushResponse struct {
	TCPingTargets      []string `json:"tcping_targets"`
	TCPingIntervalSecs int      `json:"tcping_interval_secs"`
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

	// Registration is strictly ID-based: registering ID=3 only ever affects ID=3.
	// We deliberately do NOT remove other client IDs that share the same IP/port.
	// Rationale: multiple legitimate clients (e.g. two machines behind the same
	// NAT router) share the same public IP and often the same default port (9090).
	// A cross-ID removal loop would cause them to evict each other from the
	// registry every 60 s, creating a permanent re-registration storm.
	// If a user accidentally runs two clients with different IDs on the same machine
	// they can delete the stale service from the admin page.

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

	// Preserve in-memory-only fields from the existing entry (if any).
	// We hold the write lock, so reading existingClient here is race-free.
	existingClient, exists := r.clients[id]

	var workingURL string
	var pushMode bool
	var lastPushAt time.Time
	var lastPollAt time.Time
	var cachedSecret string

	if exists && existingClient != nil {
		// --- WorkingURL: keep if it still matches a valid URL ---
		if existingClient.WorkingURL != "" {
			if existingClient.URL == url && existingClient.URL6 == url6 {
				workingURL = existingClient.WorkingURL // URLs unchanged
			} else if existingClient.WorkingURL == url || existingClient.WorkingURL == url6 {
				workingURL = existingClient.WorkingURL // WorkingURL still valid
			}
			// Otherwise reset — pollClient will rediscover on next success.
		}

		// --- Poll state: preserved so the tcping loop keeps its context ---
		lastPollAt = existingClient.LastPollAt

		// --- Push-mode state: MUST be preserved ---
		// If we zero these out, the polling loop briefly sees PushMode=false for a
		// NAT client, tries to poll, fails twice, and calls markSystemAsOffline.
		// Resetting them on re-registration is always wrong: the client is still
		// actively pushing; only UpdatePushState or explicit removal should change them.
		pushMode = existingClient.PushMode
		lastPushAt = existingClient.LastPushAt

		// --- Secret: preserve to avoid a race window ---
		// handleClientRegister sets client.Secret right after calling Register, but
		// between Register returning and that assignment, a concurrent pollClient
		// could run with an empty secret, causing spurious 401 errors.
		cachedSecret = existingClient.Secret
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
		PushMode:   pushMode,
		LastPushAt: lastPushAt,
		LastPollAt: lastPollAt,
		Secret:     cachedSecret, // caller (handleClientRegister) will overwrite with DB value
	}

	// Log the "no reachable URL" condition once per transition, not on every
	// 60 s re-registration: a NAT agent otherwise writes ~1 400 identical
	// lines per day for years, which is pure log noise and, under Docker's
	// default json-file driver, unbounded disk growth.
	if url == "" && url6 == "" {
		hadURL := !exists || existingClient == nil || existingClient.URL != "" || existingClient.URL6 != ""
		if hadURL {
			log.Printf("⚠️  Client %s registered but no valid URL (IPv4=%s, IPv6=%s) - client may be behind NAT (push mode expected; logged once)", id, ip, ipv6)
		}
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

// Get returns a DEFENSIVE VALUE COPY of the ClientInfo registered under id
// (wrapped in a pointer for API compatibility with nil-checking callers),
// or nil when the id is unknown.
//
// The registry map stores *ClientInfo, and writers (UpdateWorkingURL,
// UpdateSecret, UpdatePushState) mutate fields in place while holding the
// write lock. If Get were to return the raw map pointer, the caller would
// read fields such as WorkingURL / Secret / URL without any lock after
// RUnlock returned, racing with concurrent writers. A string is two words
// on 64-bit (pointer + length), so a torn read could observe a pointer
// from one value and a length from another — either garbage or a segfault.
//
// Returning a copy eliminates the race for callers that do:
//
//	c := registry.Get(id)
//	if c == nil { … }
//	_ = c.WorkingURL   // now reads from an owned copy, race-free
//
// GetAll already follows the same "value copy on release" pattern.
func (r *ClientRegistry) Get(id string) *ClientInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	if !ok || c == nil {
		return nil
	}
	snap := *c
	return &snap
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

// UpdatePushState marks a client as using push mode and records the push timestamp
// Called by handleClientPush each time a push payload is successfully received
func (r *ClientRegistry) UpdatePushState(id string, lastPushAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client, exists := r.clients[id]; exists && client != nil {
		client.PushMode = true
		client.LastPushAt = lastPushAt
	}
}

// UpdatePollState records a successful pull of /metrics from the client.
func (r *ClientRegistry) UpdatePollState(id string, polledAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client, exists := r.clients[id]; exists && client != nil {
		client.LastPollAt = polledAt
	}
}

// UpdateSecret sets the cached secret for a client atomically.
// Must be used instead of direct pointer writes (c.Secret = ...) to avoid
// data races with concurrent Register calls that replace the ClientInfo pointer.
func (r *ClientRegistry) UpdateSecret(id, secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client, exists := r.clients[id]; exists && client != nil {
		client.Secret = secret
	}
}

// GetAll returns a snapshot of all registered clients.
// Each element is a COPY of the ClientInfo struct captured while the read lock
// is held, so callers can safely read fields (including PushMode, LastPushAt)
// without data races against concurrent Register / UpdatePushState calls.
// Mutations to the returned structs do NOT affect the registry; use the
// dedicated Update* methods (UpdateWorkingURL, UpdatePushState) for that.
func (r *ClientRegistry) GetAll() []ClientInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clients := make([]ClientInfo, 0, len(r.clients))
	for _, client := range r.clients {
		if client != nil {
			clients = append(clients, *client) // copy — safe to read without a lock
		}
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
			KeepAlive: 60 * time.Second, // CRITICAL for Windows: prevent firewall from dropping idle connections (Windows timeout: 60-120s)
		}

		sharedHTTPClient = &http.Client{
			Timeout: 20 * time.Second, // Increased from 8s to 20s for high-latency networks (e.g., Australia-Russia ~300ms RTT)
			Transport: &http.Transport{
				DialContext:           dialer.DialContext, // Go's net.Dialer natively supports both IPv4 and IPv6
				MaxIdleConns:          200,                // More connections for stability
				MaxIdleConnsPerHost:   20,                 // More per-host connections
				IdleConnTimeout:       180 * time.Second,  // Longer idle timeout for stable connection
				TLSHandshakeTimeout:   10 * time.Second,   // Increased from 5s to 10s for slow TLS
				ResponseHeaderTimeout: 10 * time.Second,   // Wait up to 10s for response headers
				ExpectContinueTimeout: 5 * time.Second,    // Increased from 2s to 5s
				DisableCompression:    false,              // Enable compression for efficiency
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

	// Initialize SSE broker
	broker := NewSSEBroker()

	// Initialize client registry
	clientRegistry := NewClientRegistry()

	// Initialize IP country cache
	ipCache := NewIPCountryCache()

	// Root context for the whole process; cancelled on SIGTERM/SIGINT so that
	// long-lived goroutines (SSE handlers, polling loops, etc.) can exit
	// cleanly before we close the database. This ordering is critical for
	// bbolt durability: if we call store.Close() while a write transaction is
	// still in flight, the on-disk file can be left in a state that tickles
	// the old "invalid freelist page" class of corruption bugs.
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	// Signal handling: translate the first SIGTERM/SIGINT into a context
	// cancellation, let main() perform the ordered shutdown below. A second
	// signal forces an immediate exit so operators can still kill a stuck
	// process.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n🛑 Shutdown signal received, draining...")
		cancelRoot()
		<-sigChan
		log.Println("🛑 Second signal received, exiting immediately")
		os.Exit(1)
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
	// Push mode: NAT/outbound-only clients send metrics here instead of serving /metrics
	mux.HandleFunc("/api/clients/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleClientPush(store, clientRegistry, ipCache, w, r)
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
			handleSetTCPingConfig(store, broker, clientRegistry, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// Custom CSS endpoint - returns user's custom CSS
	mux.HandleFunc("/api/custom/style.css", func(w http.ResponseWriter, r *http.Request) {
		config, err := store.GetNavbarConfig()
		if err != nil || config.CustomCSS == "" {
			w.Header().Set("Content-Type", "text/css")
			w.Write([]byte("/* No custom CSS */"))
			return
		}
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write([]byte(config.CustomCSS))
	})

	// Custom JS endpoint - returns user's custom JS
	mux.HandleFunc("/api/custom/script.js", func(w http.ResponseWriter, r *http.Request) {
		config, err := store.GetNavbarConfig()
		if err != nil || config.CustomJS == "" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("// No custom JS"))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write([]byte(config.CustomJS))
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

	// Admin-only hot backup. Streams a consistent bbolt snapshot of
	// the entire metrics.db file to the client, no downtime required.
	// See handleAdminBackup above for the migration recipe.
	mux.HandleFunc("/api/admin/backup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleAdminBackup(store, w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Admin-only runtime introspection endpoint.
	mux.HandleFunc("/api/admin/runtime", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"goroutines":          runtime.NumGoroutine(),
			"cgo_calls":           runtime.NumCgoCall(),
			"heap_alloc_bytes":    m.HeapAlloc,
			"heap_inuse_bytes":    m.HeapInuse,
			"heap_idle_bytes":     m.HeapIdle,
			"heap_released_bytes": m.HeapReleased,
			"heap_objects":        m.HeapObjects,
			"stack_inuse_bytes":   m.StackInuse,
			"sys_bytes":           m.Sys,
			"gc_num":              m.NumGC,
			"gc_pause_total_ns":   m.PauseTotalNs,
			"gc_last_pause_ns":    m.PauseNs[(m.NumGC+255)%256],
			"next_gc_bytes":       m.NextGC,
			"clients_in_registry": func() int {
				if clientRegistry == nil {
					return 0
				}
				return len(clientRegistry.GetAll())
			}(),
			"sse_subscribers": broker.SubscriberCount(),
		})
	})

	addr := ":" + portFromEnv()
	// All background loops observe rootCtx and exit promptly when the process
	// is asked to shut down. This matters because the shutdown path is:
	//     cancelRoot() -> srv.Shutdown() -> store.Close()
	// If these loops keep running past srv.Shutdown, they will race with
	// store.Close by issuing db.Update/db.View calls on a closing DB, which
	// can cause half-written transactions (one of the failure modes that
	// contributed to the previous bbolt "invalid freelist page" corruption).
	go startClientPolling(rootCtx, store, broker, clientRegistry, ipCache)
	go startTCPingPolling(rootCtx, clientRegistry, store)
	go startTCPingCleanup(rootCtx, store)
	go startIPCacheCleanup(rootCtx, ipCache)
	go startTCPingCacheCleanup(rootCtx)

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

		// setStaticCacheHeaders mirrors the two-tier caching strategy the
		// nginx config uses in Docker mode (see docker/nginx.conf). Without
		// this, the standalone binary would serve /admin/index.html with
		// whatever Go's http.FileServer produces by default — Last-Modified
		// only, no Cache-Control — and browsers would happily keep the
		// stale HTML in their disk cache across deployments, so newly
		// added UI elements (e.g. the Download Backup button) would
		// silently fail to appear after an upgrade. The two rules are:
		//
		//   1. HTML entrypoints (*.html and the directory-less SPA
		//      routes like /admin, /login) → Cache-Control: no-cache,
		//      must-revalidate. The ETag we still get from http.FileServer
		//      means a revalidation costs a cheap 304 when the file really
		//      hasn't changed, while guaranteeing we notice when it has.
		//
		//   2. Content-addressed bundle assets under /_astro/ (Astro
		//      fingerprints every filename with an 8-char content hash, so
		//      a changed asset is always served under a new URL) →
		//      Cache-Control: public, max-age=31536000, s-maxage=31536000,
		//      immutable. "immutable" tells the browser not even to revalidate;
		//      s-maxage makes the CDN policy explicit.
		//
		//   3. Non-fingerprinted static files such as favicon.svg / robots.txt
		//      get a short browser TTL and a modest CDN TTL. They are cacheable,
		//      but not immutable because their URL does not change on deploy.
		isStaticAssetPath := func(urlPath string) bool {
			switch strings.ToLower(filepath.Ext(urlPath)) {
			case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2":
				return true
			default:
				return false
			}
		}

		setStaticCacheHeaders := func(w http.ResponseWriter, urlPath string) {
			switch {
			case strings.HasSuffix(urlPath, ".html") || urlPath == "/" || filepath.Ext(urlPath) == "":
				w.Header().Set("Cache-Control", "no-cache, must-revalidate")
			case strings.HasPrefix(urlPath, "/_astro/"):
				w.Header().Set("Cache-Control", "public, max-age=31536000, s-maxage=31536000, immutable")
			case urlPath == "/favicon.svg" || urlPath == "/robots.txt":
				w.Header().Set("Cache-Control", "public, max-age=3600, s-maxage=86400")
			case isStaticAssetPath(urlPath):
				w.Header().Set("Cache-Control", "public, max-age=86400, s-maxage=604800")
			}
		}

		// Create a handler that combines API routes and static files
		finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try API routes first
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
				mux.ServeHTTP(w, r)
				return
			}

			// Handle static files. Reject invalid filesystem paths before
			// any embedded-FS lookup or SPA fallback so traversal probes such
			// as /../admin never turn into a successful index.html response.
			path, ok := staticFilePathFromURL(r.URL.Path)
			if !ok {
				http.NotFound(w, r)
				return
			}

			// Try to open the file from embedded FS
			if f, err := distFS.Open(path); err == nil {
				f.Close()
				setStaticCacheHeaders(w, r.URL.Path)
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
					defer f.Close()
					content, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "failed to read file", http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					setStaticCacheHeaders(w, r.URL.Path)
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
				setStaticCacheHeaders(w, r.URL.Path)
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

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
		// ReadHeaderTimeout guards against Slowloris: an attacker who opens a
		// connection and dribbles headers byte-by-byte holds the goroutine for at
		// most 30 s before the server closes the connection.
		ReadHeaderTimeout: 30 * time.Second,
		// IdleTimeout reclaims keep-alive connections that have been idle for >2m.
		// This prevents file-descriptor exhaustion when many clients connect and
		// then go silent.
		IdleTimeout: 2 * time.Minute,
		// ReadTimeout and WriteTimeout are intentionally left at 0 (unlimited):
		// SSE connections (/api/events) are long-lived writes that would be killed
		// by a non-zero WriteTimeout.

		// BaseContext wires the process-wide rootCtx into every incoming
		// request so long-lived handlers (notably /api/events SSE) observe
		// rootCtx cancellation and return promptly during shutdown.
		BaseContext: func(net.Listener) context.Context { return rootCtx },
	}

	serverErrCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	// Wait for either the root context to be cancelled (SIGTERM/SIGINT) or
	// the HTTP server to fail on its own.
	select {
	case <-rootCtx.Done():
		log.Println("🧹 Shutting down HTTP server...")
	case err := <-serverErrCh:
		if err != nil {
			log.Printf("❌ HTTP server error: %v", err)
		}
		cancelRoot()
	}

	// Give in-flight requests up to 25s to finish. We deliberately stay below
	// the 30s supervisord stopwaitsecs so the shutdown completes before the
	// supervisor escalates to SIGKILL.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️  HTTP shutdown returned: %v", err)
	}

	// Now that no handler can be issuing new db.Update calls, it is safe to
	// close the bbolt DB. Closing bbolt flushes in-flight writes and releases
	// the file lock.
	storeClosedOK := false
	if err := store.Close(); err != nil {
		log.Printf("⚠️  store close returned: %v", err)
	} else {
		log.Println("✅ Database closed cleanly")
		storeClosedOK = true
	}

	// Second chance to shrink metrics.db after the daemon handle is gone —
	// complements NewStore.maybeCompact when the OS sends SIGKILL (no graceful
	// shutdown) vs SIGTERM/SIGINT (always hits this branch). Shrinking the file
	// directly bounds bbolt mmap + RSS across restarts without requiring a human
	// to run tooling by hand.
	if storeClosedOK {
		if before, after, vacErr := CompactBoltFileAfterClose(dbPath); vacErr != nil {
			log.Printf("⚠️  offline bbolt vacuum failed (non-fatal): %v", vacErr)
		} else if after > 0 && after < before {
			log.Printf("🧯 offline bbolt vacuum: %.1f MB → %.1f MB (saved %.1f MB)",
				float64(before)/1024/1024,
				float64(after)/1024/1024,
				float64(before-after)/1024/1024)
		}
	}
	log.Println("👋 Shutdown complete")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleSSE(store *Store, broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	// Determine the subscriber's admin status first. Anyone with a valid admin
	// session (cookie / Authorization header / admin_token query param) is an
	// admin subscriber and will receive payloads that still contain IPv4, IPv6
	// and Secret. Everyone else is a public subscriber and receives payloads
	// with those fields stripped server-side before they ever hit the wire.
	//
	// Admin status is locked in at subscription time. This matches the
	// existing semantics of GET /api/metrics (where the auth decision is made
	// once per request) and means that a session that expires mid-stream
	// cannot retroactively be used to escalate privilege — the browser will
	// ultimately have to reconnect, and the new connection will be
	// re-authorised from scratch.
	isAdmin := isAuthenticated(r)
	if !isAdmin {
		// EventSource cannot send an Authorization header, so admin sessions
		// identify themselves to SSE via the admin_token query parameter.
		// We validate it exactly like the Bearer-token path in isAuthenticated.
		//
		// If the token is valid the subscriber is upgraded to the admin view
		// (IPv4 / IPv6 / Secret included). If the token is missing or invalid
		// we silently fall through to the public view: the admin dashboard
		// page guards access via /api/auth/verify at load time, so the only
		// way to reach this code with an invalid admin_token is either
		// (a) a public page (index.astro) whose user happens to have a stale
		// token in localStorage — they should still be able to watch the
		// public stream, not receive a 401, and (b) an admin whose session
		// expired mid-session — any mutation they attempt will fail at the
		// mutation endpoint and redirect them to /login via the page's
		// existing wrapped-fetch logic.
		if adminToken := r.URL.Query().Get("admin_token"); adminToken != "" {
			authTokensMu.Lock()
			expiry, exists := authTokens[adminToken]
			authTokensMu.Unlock()
			if exists && time.Now().Before(expiry) {
				isAdmin = true
			}
		}
	}

	// Check privacy mode - if enabled, require authentication or valid share token
	privacyConfig, err := store.GetPrivacyConfig()
	if err == nil && privacyConfig.Enabled {
		authorised := isAdmin

		if !authorised {
			shareToken := r.URL.Query().Get("token")
			if shareToken != "" {
				if privacyConfig.ShareToken != "" && secretEqual(shareToken, privacyConfig.ShareToken) && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
					// Share token grants access but NOT admin privileges.
					authorised = true
				}
			}
			if !authorised {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}

	// Subscribe before committing any headers so a refused subscription can
	// still answer with a plain 503. The view decides how every broadcast is
	// masked for this connection.
	view := SSEViewPublic
	if isAdmin {
		view = SSEViewAdmin
	}
	sub, err := broker.Subscribe(view, getClientIP(r))
	if err != nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many event streams", http.StatusServiceUnavailable)
		return
	}
	defer broker.Unsubscribe(sub)

	// Every write goes through writeEvent: it arms a fresh write deadline
	// and flushes, returning false as soon as the peer stops draining so the
	// handler exits instead of blocking forever (see sseWriteTimeout).
	rc := http.NewResponseController(w)
	// The deadline is absolute and net/http only re-arms it per request when
	// Server.WriteTimeout is set (it is not, on purpose). Clear it on exit so
	// a keep-alive connection reused for a later request is not left with a
	// stale, already-expired write deadline.
	defer rc.SetWriteDeadline(time.Time{})
	// parts are written back to back so a multi-hundred-KB snapshot is never
	// copied into a fresh string per subscriber just to add the SSE framing.
	writeEvent := func(parts ...string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		for _, part := range parts {
			if _, werr := io.WriteString(w, part); werr != nil {
				return false
			}
		}
		return rc.Flush() == nil
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

	// Tell the browser to auto-reconnect in 3 s if the stream is ever lost.
	// This overrides the default (3–5 s, browser dependent) with a deterministic
	// value so all browsers behave the same. Must be the first SSE line.
	// Then send the initial connection message.
	if !writeEvent("retry: 3000\n\nevent: connected\ndata: {\"message\":\"Connected to updates stream\"}\n\n") {
		return
	}

	// Immediately push a full state snapshot so the frontend can render on
	// connect without ever calling GET /api/metrics. Between this initial
	// push and the 3-second broadcast cadence, an EventSource subscriber has
	// a complete, self-contained feed of authoritative state.
	//
	// Ordering note: between Subscribe() above and the fresh snapshot we are
	// about to build, a broadcast tick may have queued an older state event
	// in sub.ch. That event is by definition at most ~3 s stale relative to
	// our fresh snapshot, and delivering it AFTER the initial snapshot would
	// briefly flash older data over newer data on the client. We therefore
	// drain any such events non-blockingly before pushing the initial
	// snapshot. Genuinely new broadcasts arriving after we enter the select
	// loop below are always fresher than the initial snapshot and get
	// delivered in order.
	payload, havePayload := broker.LatestSnapshot(view)
	if !havePayload {
		// No payload younger than one second: build a fresh one and remember
		// it, so a burst of connections (restart, CDN blip) costs one DB scan
		// per second instead of one per viewer, while any single viewer still
		// starts from data at most one second old. Builds are serialised per
		// view; a handler that waited for the lock usually finds the payload
		// its predecessor just remembered.
		unlock := broker.primeLock(view)
		payload, havePayload = broker.LatestSnapshot(view)
		if !havePayload {
			builtAt := time.Now()
			if snapshot, err := buildMetricsSnapshot(store, globalClientRegistry, isAdmin); err == nil {
				viewName := "public"
				if isAdmin {
					viewName = "admin"
				}
				if b, merr := json.Marshal(map[string]interface{}{
					"type":    "metric_updated",
					"view":    viewName,
					"systems": snapshot,
					"count":   len(snapshot),
				}); merr == nil {
					payload, havePayload = broker.RememberSnapshot(view, string(b), builtAt), true
				}
			}
		}
		unlock()
	}
	if havePayload {
	drain:
		for {
			select {
			case <-sub.ch:
				// Discard: no fresher than our snapshot.
			default:
				break drain
			}
		}
		if !writeEvent("event: update\ndata: ", payload, "\n\n") {
			return
		}
	}

	// Independent SSE keepalive.
	// The 3-second startClientPolling broadcast already keeps the connection
	// warm under normal conditions, but if that loop is ever briefly delayed
	// (slow DB, long GC pause, etc.) the SSE stream can sit idle long enough
	// for an upstream proxy (nginx default 60 s, some CDNs 30 s) to close the
	// TCP connection. An explicit 15 s SSE comment-line ping (lines starting
	// with ":" are ignored by the EventSource API but count as traffic) makes
	// the stream resilient to proxy idle timeouts independent of the polling
	// loop and adds only ~4 bytes / 15 s / client of overhead.
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	// Listen for client disconnect and broker messages
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Client disconnected (or server-wide shutdown via BaseContext)
			return
		case msg, ok := <-sub.ch:
			if !ok {
				// Channel closed by Unsubscribe — stream is being torn down.
				return
			}
			if !writeEvent("event: update\ndata: ", msg, "\n\n") {
				return
			}
		case <-keepalive.C:
			// Comment-line heartbeat; ignored by EventSource but keeps the
			// proxy/CDN connection alive.
			if !writeEvent(": ping\n\n") {
				return
			}
		}
	}
}

// buildMetricsSnapshot assembles the same enriched metrics list that
// GET /api/metrics returns. It is used both by the HTTP handler and by the
// SSE broadcaster so that the two surfaces can never drift apart.
//
// Parameters:
//   - store        : persistent storage
//   - registry     : live in-memory client registry for push-mode freshness
//   - authenticated: when false, IPv4 / IPv6 / Secret fields are cleared on
//     every returned row. The caller is responsible for deciding the auth
//     level up front (privacy mode, share token, admin session, etc.).
//
// Online/offline determination strategy (preserved from the original handler):
//
//	Push-mode clients   → use registry LastPushAt (updated the instant a push
//	  arrives, before any DB write, so zero lag). Threshold = 10 s:
//	  push interval (3 s) × 3 + 1 s buffer. Handles the worst-case where one
//	  push times out (8 s) and the next succeeds immediately afterwards.
//
//	Pull-mode clients   → use DB UpdatedAt (set by pollClient on each success).
//	  Threshold = 5 s: poll interval (3 s) + 2 s network buffer.
//
//	Not in registry     → server may have just restarted; fall back to DB
//	  UpdatedAt with a generous 12 s threshold so stale data is not shown as
//	  offline immediately while clients re-register.
//
//	Zero UpdatedAt      → newly added by admin, never received data → offline.
func buildMetricsSnapshot(store *Store, registry *ClientRegistry, authenticated bool) ([]SystemMetric, error) {
	metrics, err := store.List()
	if err != nil {
		return nil, err
	}

	// Build a snapshot of the client registry for fast per-metric lookups.
	// We do this once (one read-lock) rather than per-metric to minimise lock
	// contention when there are many systems.
	registryMap := make(map[string]ClientInfo)
	if registry != nil {
		for _, c := range registry.GetAll() {
			registryMap[c.ID] = c
		}
	}

	now := time.Now().UTC()

	for i := range metrics {
		var shouldBeOffline bool
		if regClient, inReg := registryMap[metrics[i].ID]; inReg {
			if regClient.PushMode {
				// 15 s: push interval (3 s) + one full 8 s push timeout +
				// scheduling slack. The old 10 s threshold sat so close to
				// the timeout that a single slow push flickered the row
				// offline for one tick on high-latency links.
				shouldBeOffline = regClient.LastPushAt.IsZero() ||
					time.Since(regClient.LastPushAt) > 15*time.Second
			} else {
				shouldBeOffline = metrics[i].UpdatedAt.IsZero() ||
					now.Sub(metrics[i].UpdatedAt) > 5*time.Second
			}
		} else {
			shouldBeOffline = metrics[i].UpdatedAt.IsZero() ||
				now.Sub(metrics[i].UpdatedAt) > 12*time.Second
		}
		metrics[i].Alert = shouldBeOffline

		// SECURITY: Mask privileged fields for unauthenticated callers.
		if !authenticated {
			metrics[i].IPv4 = ""
			metrics[i].IPv6 = ""
			metrics[i].Secret = ""
		}
	}

	return metrics, nil
}

// broadcastMetricsSnapshot fans out the authoritative latest state of the
// system list to every SSE subscriber. Two distinct payloads are prepared:
//
//   - A "public" payload with IPv4 / IPv6 / Secret stripped, delivered to
//     anonymous and share-token subscribers.
//   - An "admin" payload with everything intact, delivered to authenticated
//     admin subscribers.
//
// Because each payload carries the complete state, any subscriber whose
// buffer drops an older event still converges to the correct view on the
// next broadcast — we never rely on the frontend reconstructing state from a
// stream of diffs. This keeps the push path idempotent and self-healing.
func broadcastMetricsSnapshot(store *Store, registry *ClientRegistry, broker *SSEBroker) {
	if broker == nil || store == nil {
		return
	}

	// Build the authoritative (admin-view) snapshot exactly once. The
	// public-view payload is derived from it by shallow-cloning the slice and
	// masking IPv4 / IPv6 / Secret on each entry — this avoids a second
	// store.List (full db.View + JSON unmarshal + sort) and a second
	// registry.GetAll that used to run every 3 s. Shallow copy is safe
	// because:
	//   * IPv4 / IPv6 / Secret are plain strings (value copy)
	//   * TCPingData (map) and Tags (slice) are NOT mutated here; they are
	//     read-only for the marshaller, and we never touch them.
	adminMetrics, err := buildMetricsSnapshot(store, registry, true)
	if err != nil {
		log.Printf("⚠️  broadcastMetricsSnapshot: snapshot failed: %v", err)
		return
	}

	publicMetrics := make([]SystemMetric, len(adminMetrics))
	copy(publicMetrics, adminMetrics)
	for i := range publicMetrics {
		publicMetrics[i].IPv4 = ""
		publicMetrics[i].IPv6 = ""
		publicMetrics[i].Secret = ""
	}

	// "view" tells the subscriber which masking it received. The admin
	// dashboard uses it to notice that its session expired (the server
	// silently downgrades an SSE stream with a stale admin_token to the
	// public view) and re-authenticates instead of rendering blank IPs.
	publicJSON, err := json.Marshal(map[string]interface{}{
		"type":    "metric_updated",
		"view":    "public",
		"systems": publicMetrics,
		"count":   len(publicMetrics),
	})
	if err != nil {
		log.Printf("⚠️  broadcastMetricsSnapshot: public marshal failed: %v", err)
		return
	}
	adminJSON, err := json.Marshal(map[string]interface{}{
		"type":    "metric_updated",
		"view":    "admin",
		"systems": adminMetrics,
		"count":   len(adminMetrics),
	})
	if err != nil {
		log.Printf("⚠️  broadcastMetricsSnapshot: admin marshal failed: %v", err)
		return
	}

	broker.BroadcastByView(map[SSEView]string{
		SSEViewPublic: string(publicJSON),
		SSEViewAdmin:  string(adminJSON),
	})
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
				// Verify share token (constant-time to avoid leaking the token
				// via byte-by-byte timing side channels).
				if privacyConfig.ShareToken != "" && secretEqual(shareToken, privacyConfig.ShareToken) && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
					authenticated = true
				} else {
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

	metrics, err := buildMetricsSnapshot(store, globalClientRegistry, isAuthenticated(r))
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, metrics)
}

func handleIngestMetric(store *Store, broker *SSEBroker, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Cap body at 1 MB: mirrors /api/clients/push and is far larger than any
	// realistic metricPayload (even with long OS / CPU model strings and a
	// generous set of tags a real payload stays well under 16 KB). Without
	// this cap a compromised-secret client or a misconfigured admin browser
	// could stream an unbounded body and force the server to buffer it during
	// json.Decode, driving RSS growth that we've otherwise worked hard to
	// keep bounded.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
				// Fallback: check query parameter.
				// NOTE: Discouraged because query strings may end up in
				// access logs / reverse-proxy logs / referer headers; we
				// accept it for backward compat with older clients only.
				providedSecret = r.URL.Query().Get("secret")
			}

			if !secretEqual(providedSecret, existing.Secret) {
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
		if payload.HideOnHome != nil {
			metric.HideOnHome = *payload.HideOnHome
		}
		if payload.HideTCPing != nil {
			metric.HideTCPing = *payload.HideTCPing
		}
		// Keep existing order, updatedAt, and secret
	} else {
		// Either from client, or new system from admin page
		// Preserve existing values for new fields if updating existing system
		var cpuModel, memoryInfo, swapInfo, diskInfo, secret string
		var tags []string
		var hideOnHome, hideTCPing bool
		var tcpingData map[string]TCPingTargetData
		if existing != nil {
			cpuModel = existing.CPUModel
			memoryInfo = existing.MemoryInfo
			swapInfo = existing.SwapInfo
			diskInfo = existing.DiskInfo
			secret = existing.Secret
			tags = existing.Tags
			hideOnHome = existing.HideOnHome
			hideTCPing = existing.HideTCPing
			// Preserve existing tcping data map
			if existing.TCPingData != nil {
				tcpingData = make(map[string]TCPingTargetData)
				for k, v := range existing.TCPingData {
					tcpingData[k] = v
				}
			}
		}

		// Use shared secret for new systems (only if not from client and doesn't exist)
		if !isFromClient && existing == nil && secret == "" {
			// Get shared secret from navbar config
			navbarConfig, err := store.GetNavbarConfig()
			if err == nil && navbarConfig.SharedSecret != "" {
				secret = navbarConfig.SharedSecret
			} else {
				// Fallback to generating a new secret if shared secret is not available
				secret = generateSecret()
			}
		}

		// Update tags if provided in payload (from admin form)
		if payload.Tags != nil {
			tags = payload.Tags
		}
		// Visibility toggles are admin-only: ignore them on the client path.
		if !isFromClient {
			if payload.HideOnHome != nil {
				hideOnHome = *payload.HideOnHome
			}
			if payload.HideTCPing != nil {
				hideTCPing = *payload.HideTCPing
			}
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
			HideOnHome:         hideOnHome,
			HideTCPing:         hideTCPing,
		}
	}

	// Agent writes merge the admin-owned fields from the stored record inside
	// the transaction; admin writes are authoritative for those fields.
	var saveErr error
	if isFromClient {
		saveErr = store.UpsertFromAgent(metric)
	} else {
		saveErr = store.Upsert(metric)
	}
	if saveErr != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Only broadcast immediately if this is from admin page (manual add/edit).
	// Client data updates are already covered by the 3 s polling-loop
	// broadcast; emitting a second broadcast here would cause duplicate
	// work on every single client tick.
	//
	// For admin mutations we push the full authoritative snapshot so every
	// connected browser re-renders immediately — no GET round-trip required.
	if broker != nil && !isFromClient {
		broadcastMetricsSnapshot(store, globalClientRegistry, broker)
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

	// Invalidate TCPing cache for this client
	invalidateTCPingCache(id)

	// The history of a deleted system is not reachable from the UI any more,
	// so remove it in the background: scanning a day of history for a
	// hundred systems takes seconds and used to keep the admin waiting (and
	// the write lock busy) for the whole time.
	go func(id string) {
		start := time.Now()
		if err := store.DeleteTCPingResultsByClient(id); err != nil {
			log.Printf("⚠️  history cleanup for deleted system %s failed: %v", id, err)
			return
		}
		// A history request served while the scan ran may have re-filled the
		// cache with rows that are gone now.
		invalidateTCPingCache(id)
		log.Printf("🧹 Removed tcping history of deleted system %s in %v", id, time.Since(start).Round(time.Millisecond))
	}(id)

	// Remove client from registry to stop polling
	registry.Remove(id)

	// Push a single authoritative snapshot so every connected browser drops
	// the deleted row without needing to re-fetch. We deliberately do NOT
	// emit a separate "metric_deleted" signal here: that would make clients
	// process the same change twice (once via the signal → GET /api/metrics,
	// once via the snapshot), which is both wasted work and a race risk.
	// The snapshot alone is the single source of truth.
	if broker != nil {
		broadcastMetricsSnapshot(store, globalClientRegistry, broker)
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted", "id": id})
}

func handleClientRegister(store *Store, registry *ClientRegistry, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Registration payloads contain only a handful of short string fields;
	// 8 KB is far more than needed and prevents any oversized-body abuse.
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

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
	// NOTE: We always read from DB (not registry cache) to ensure:
	// 1. System existence is always verified against the authoritative source
	// 2. Secret changes by admin take effect immediately on next registration
	// BoltDB reads are very fast (in-memory B-tree index), so this is acceptable
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
		if !secretEqual(payload.Secret, existing.Secret) {
			log.Printf("❌ Client registration failed: invalid secret for ID '%s'", payload.ID)
			http.Error(w, "invalid secret", http.StatusUnauthorized)
			return
		}
	}

	// No IP/port conflict check here.
	// ID + secret is the complete identity of a client.  A client's IP may change
	// at any time (dynamic IP, NAT rotation, VPN, restart) so comparing IPs would
	// falsely reject legitimate re-registrations.  The secret has already been
	// validated above; if it passed, this is the authorised owner of this ID.

	// Resolve the client's public IPv4.
	// Priority:
	//   1. Use the client-reported IP if it is a valid public IPv4.
	//   2. Fall back to the connection source IP (r.RemoteAddr / X-Forwarded-For).
	//      For NAT/outbound-only clients the HTTP connection comes from the NAT
	//      gateway's public IP even when the client only has private interfaces.
	//
	// We intentionally reject private IPs from the payload so that NAT machines
	// that fail external-API detection don't store a useless 192.168.x.x in the DB.

	ip := payload.IP
	ipv6 := payload.IPv6

	// Apply NAT IP fixup: if the reported IPv4 is absent or private, derive it
	// from the connection source IP (same logic as handleClientPush).
	// getClientIP uses forwarded headers only when the immediate peer is trusted.
	if isPrivateIPStr(ip) {
		if srcIP := getClientIP(r); srcIP != "" {
			if parsed := net.ParseIP(srcIP); parsed != nil && parsed.To4() != nil && !isPrivateIP(parsed) {
				ip = srcIP
			}
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

	// Cache the secret in the registry so pollClient can authenticate without a
	// DB round-trip on every poll.  Use UpdateSecret (holds write lock) instead of
	// a direct pointer write to avoid a data race with concurrent Register calls.
	registry.UpdateSecret(payload.ID, existing.Secret)

	// Return TCPing config in registration response so push-mode clients can start
	// monitoring targets immediately without an extra round-trip.
	tcpingCfg, _ := store.GetTCPingConfig()
	tcpingTargets := []string{}
	tcpingInterval := 60
	if tcpingCfg != nil {
		tcpingInterval = tcpingCfg.IntervalSecs
		for _, t := range tcpingCfg.Targets {
			if t.Address != "" {
				tcpingTargets = append(tcpingTargets, t.Address)
			}
		}
	}
	// CDN-friendly: ensure registration response is not cached
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":              "registered",
		"id":                   payload.ID,
		"tcping_targets":       tcpingTargets,
		"tcping_interval_secs": tcpingInterval,
	})
}

// handleClientPush processes metrics pushed by client agents operating in push mode.
// Push mode is used by clients behind NAT or with outbound-only connectivity.
// The client sends all metrics + optional TCPing results in one POST; the server
// responds with the current TCPing configuration so the client can run TCPing locally.
func handleClientPush(store *Store, registry *ClientRegistry, ipCache *IPCountryCache, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	// Limit push payload to 1 MB.  A normal push with 500 TCPing results is
	// ~30 KB, so 1 MB is very generous while preventing memory exhaustion from
	// a malicious or runaway client sending an unbounded body.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Decode the push payload (metric fields + optional secret + optional TCPing results)
	var payload struct {
		metricPayload
		TCPingResults []ClientTCPingResult `json:"tcping_results,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	clientID := strings.TrimSpace(payload.ID)
	if clientID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	// Verify system exists in database (must be pre-added by admin)
	existing, err := store.Get(clientID)
	if err != nil || existing == nil {
		http.Error(w, fmt.Sprintf("server id '%s' not found", clientID), http.StatusNotFound)
		return
	}

	// Authenticate using secret from DB (same logic as pollClient)
	if existing.Secret != "" {
		providedSecret := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			providedSecret = strings.TrimPrefix(auth, "Bearer ")
		}
		// Also accept secret embedded in payload as fallback
		if providedSecret == "" {
			providedSecret = payload.Secret
		}
		if !secretEqual(providedSecret, existing.Secret) {
			http.Error(w, "invalid secret", http.StatusUnauthorized)
			return
		}
	}

	// --- NAT/outbound-only IP fixup ---
	// For machines behind NAT the client's network interfaces only expose private IPs.
	// The client tries external IP-echo APIs as a fallback, but those can fail
	// (timeouts, firewall, etc.).  However, the HTTP push request always arrives from
	// the real public IP (the NAT gateway's egress IP), so we can use r.RemoteAddr
	// (via getClientIP) as a reliable fallback when the client-reported IPv4 is empty
	// or still private.  This also works correctly when the server is behind a reverse
	// proxy when that proxy is trusted by getClientIP.
	if payload.IPv4 == "" || isPrivateIPStr(payload.IPv4) {
		if srcIP := getClientIP(r); srcIP != "" {
			if parsed := net.ParseIP(srcIP); parsed != nil && parsed.To4() != nil && !isPrivateIP(parsed) {
				payload.IPv4 = srcIP
			}
		}
	}

	// Mark client as push-mode in registry (creates entry if not yet registered)
	now := time.Now()

	// Ensure client is in registry (may not be if server restarted after client registered)
	if registry.Get(clientID) == nil {
		// Push-mode clients have no inbound port; pass empty IP/port so the registry
		// stores no URL (URL="" means server will never attempt to poll this client).
		// The client's IP is already preserved in the metric written to the DB.
		registry.Register(clientID, payload.Name, "", "", "")
		// Cache secret atomically (holds write lock) — avoids a data race with
		// concurrent Register calls that would replace the ClientInfo pointer.
		registry.UpdateSecret(clientID, existing.Secret)
	}
	registry.UpdatePushState(clientID, now)

	// Resolve location without ever blocking the push (see resolveLocation).
	payload.Location = resolveLocation(ipCache, existing, payload.Location, payload.IPv4, payload.IPv6)

	timeDisplay := formatUptime(payload.Uptime)

	// Preserve server-side fields (order, name, tags, secret, tcping data).
	//
	// `existing` is guaranteed non-nil at this point: handleClientPush
	// returns 404 above when no system with this ID is registered.
	order := existing.Order
	name := existing.Name // Always use admin-set name
	tags := existing.Tags
	dbSecret := existing.Secret
	var tcpingData map[string]TCPingTargetData
	if existing.TCPingData != nil {
		tcpingData = make(map[string]TCPingTargetData, len(existing.TCPingData))
		for k, v := range existing.TCPingData {
			tcpingData[k] = v
		}
	}

	// PERFORMANCE / MEMORY FIX (formerly: N+1 fsyncs per push).
	//
	// Compose the final metric (including merged TCPingData) entirely in
	// memory, sanitise tcping results, and persist everything in one bbolt
	// write transaction. The response contract stays unchanged.
	tcpingConfig, configErr := store.GetTCPingConfig()
	if configErr != nil || tcpingConfig == nil {
		tcpingConfig = &TCPingConfig{Targets: []TCPingTargetEntry{}, IntervalSecs: 60}
	}

	allowedTargets := make(map[string]struct{}, len(tcpingConfig.Targets))
	for _, t := range tcpingConfig.Targets {
		if t.Address != "" {
			allowedTargets[t.Address] = struct{}{}
		}
	}
	targetAllowed := func(name string) bool {
		_, ok := allowedTargets[name]
		return ok
	}

	nowUTC := time.Now().UTC()
	// Agents queue up to 500 measurements while the server is unreachable and
	// deliver them on the next successful push, each stamped with its real
	// MeasuredAt. Those stamps are kept so an outage shows as a gap instead of
	// a burst of fake "now" points (the previous behaviour). The agent clock is
	// not trusted blindly, though: the newest stamp in a batch is at most one
	// push cycle old on a healthy clock, so a larger distance from now is
	// clock skew and the whole batch is shifted by that offset. Samples older
	// than the retention window after adjustment are dropped.
	var newest time.Time
	for _, tr := range payload.TCPingResults {
		if tr.MeasuredAt.After(newest) {
			newest = tr.MeasuredAt
		}
	}
	// The "too old" bound scales with the configured interval: with a 5 min
	// interval the newest queued sample of a post-outage backlog is
	// legitimately up to 5 min old, and treating that as skew shifted the
	// whole backlog onto "now" and disabled idempotent storage.
	skewPast := 2 * time.Minute
	if iv := 2 * time.Duration(tcpingConfig.IntervalSecs) * time.Second; iv > skewPast {
		skewPast = iv
	}
	var skew time.Duration
	if !newest.IsZero() {
		if d := nowUTC.Sub(newest.UTC()); d > skewPast || d < -30*time.Second {
			skew = d
		}
	}
	// An agent re-sends the identical batch when its previous push timed out
	// after the server had already committed it. With skew != 0 the stored
	// timestamps differ between the two deliveries, so the idempotent key
	// cannot catch the retry; a per-client signature of the raw batch does.
	if tcpingBatchSeen(clientID, payload.TCPingResults) {
		payload.TCPingResults = nil
	}
	// Drop "latest" entries for targets the admin has removed: the copy of
	// existing.TCPingData above would otherwise write them back after
	// PruneTCPingTargets ran (mergeAdminOwned only ever adds keys).
	for target := range tcpingData {
		if !targetAllowed(target) {
			delete(tcpingData, target)
		}
	}
	// Targets with a sample in this batch: their "latest" entry is replaced
	// unconditionally (see mergeAdminOwned), never kept from a stored copy
	// whose stamp happens to be newer.
	freshTCPing := make(map[string]struct{}, len(payload.TCPingResults))
	for _, tr := range payload.TCPingResults {
		if targetAllowed(tr.Target) {
			freshTCPing[tr.Target] = struct{}{}
		}
	}
	const maxPast = 24 * time.Hour
	// sanitize returns the timestamp to store, whether it is the agent's own
	// unmodified stamp (only then is it safe to use as an idempotency key), and
	// whether the sample is worth keeping at all.
	sanitize := func(t time.Time) (ts time.Time, exact bool, keep bool) {
		if t.IsZero() {
			return nowUTC, false, true // pre-1.3.6 agents: server clock
		}
		ts = t.UTC().Add(skew)
		if nowUTC.Sub(ts) > maxPast {
			return time.Time{}, false, false
		}
		return ts, skew == 0, true
	}

	var batchedResults []TCPingResult
	if len(payload.TCPingResults) > 0 {
		batchedResults = make([]TCPingResult, 0, len(payload.TCPingResults))
		// Targets whose "latest" entry this batch has already written. A
		// backfilled batch may arrive out of order, so within the batch only a
		// newer sample may replace the entry; the persisted entry is always
		// replaced by the first sample, so a stale future-dated value can never
		// freeze the card.
		latestWritten := make(map[string]struct{})
		for _, tr := range payload.TCPingResults {
			if tr.Target == "" || !targetAllowed(tr.Target) {
				continue
			}
			ts, exact, keep := sanitize(tr.MeasuredAt)
			if !keep {
				continue
			}
			var latencyPtr *float64
			if tr.Success {
				l := tr.Latency
				latencyPtr = &l
				if tcpingData == nil {
					tcpingData = make(map[string]TCPingTargetData)
				}
				if _, written := latestWritten[tr.Target]; !written || !ts.Before(tcpingData[tr.Target].Timestamp) {
					tcpingData[tr.Target] = TCPingTargetData{
						Latency:   tr.Latency,
						Timestamp: ts,
					}
					latestWritten[tr.Target] = struct{}{}
				}
			}
			batchedResults = append(batchedResults, TCPingResult{
				ClientID:       clientID,
				Target:         tr.Target,
				Latency:        latencyPtr,
				Timestamp:      ts,
				ExactTimestamp: exact,
			})
		}
	}

	metric := SystemMetric{
		ID:                 clientID,
		Name:               name,
		IPv4:               payload.IPv4,
		IPv6:               payload.IPv6,
		Time:               timeDisplay,
		Location:           payload.Location,
		VirtualizationType: payload.VirtualizationType,
		OS:                 payload.OS,
		OSIcon:             payload.OSIcon,
		CPU:                payload.CPU,
		CPUModel:           payload.CPUModel,
		Memory:             payload.Memory,
		MemoryInfo:         payload.MemoryInfo,
		SwapInfo:           payload.SwapInfo,
		Disk:               payload.Disk,
		DiskInfo:           payload.DiskInfo,
		NetInMBps:          payload.NetInMBps,
		NetOutMBps:         payload.NetOutMBps,
		TotalNetInBytes:    payload.TotalNetInBytes,
		TotalNetOutBytes:   payload.TotalNetOutBytes,
		AgentVersion:       payload.AgentVersion,
		Order:              order,
		Alert:              false, // actively pushing = online
		UpdatedAt:          nowUTC,
		TCPingData:         tcpingData,
		TCPingFresh:        freshTCPing,
		Tags:               tags,
		Secret:             dbSecret,
		HideOnHome:         existing.HideOnHome,
		HideTCPing:         existing.HideTCPing,
	}

	if err := store.SaveClientPushBatch(metric, batchedResults); err != nil {
		http.Error(w, "failed to save metrics", http.StatusInternalServerError)
		return
	}

	if len(batchedResults) > 0 {
		invalidateTCPingCache(clientID)
	}

	// NOTE: Do NOT broadcast immediately here.
	// The polling loop broadcasts every 3 s for all clients (including push-mode ones).
	// Adding a second broadcast here causes the frontend to receive two rapid-fire
	// metric_updated events per push cycle, resulting in double refreshes.
	// The data is already saved to the DB above; the polling loop will pick it up
	// within ≤3 s — identical latency to pull-mode clients.

	// Echo the tcping config we already loaded (see top of handler) so the
	// client can schedule its next measurements. We deliberately reuse
	// that single read to give a consistent snapshot in both the filter
	// and the response.
	targets := make([]string, 0, len(tcpingConfig.Targets))
	for _, t := range tcpingConfig.Targets {
		if t.Address != "" {
			targets = append(targets, t.Address)
		}
	}
	writeJSON(w, http.StatusOK, ClientPushResponse{
		TCPingTargets:      targets,
		TCPingIntervalSecs: tcpingConfig.IntervalSecs,
	})
}

// Global references set once at startup so handlers called from the HTTP mux
// (which don't receive these as parameters) can still reach them.
var globalClientRegistry *ClientRegistry

func startClientPolling(ctx context.Context, store *Store, broker *SSEBroker, registry *ClientRegistry, ipCache *IPCountryCache) {
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

	// Per-client active poll guard: prevents goroutine pile-up when a client's
	// /metrics endpoint is slow (>3 s RTT). If a poll goroutine is still running
	// from the previous tick, we skip spawning a new one for that client.
	var activePollMu sync.Mutex
	activePollClients := make(map[string]bool)

	for {
		var tickTime time.Time
		select {
		case <-ctx.Done():
			return
		case tickTime = <-ticker.C:
		}

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
			// No clients right now, but we still push a state snapshot every
			// tick so that newly-added-but-empty systems (and their offline
			// indicators) stay fresh in every browser.
			broadcastMetricsSnapshot(store, registry, broker)
			continue
		}

		// Use WaitGroup with timeout pattern
		var wg sync.WaitGroup

		// Poll all clients in parallel.
		// GetAll() returns value COPIES (not pointers) so all reads of PushMode,
		// LastPushAt, URL, etc. below are race-free — they snapshot a consistent
		// state at the time GetAll held the read lock.
		for _, client := range clients {
			if client.ID == "" { // values are never nil; zero-ID means empty slot
				continue
			}

			// Push-mode clients push data to the server; the server must NEVER attempt
			// to poll them.  This applies regardless of whether a URL is stored in the
			// registry — a NAT client registers with its NAT-gateway's public IP as URL,
			// but that URL is not reachable (the port is not forwarded).  Polling it
			// would spawn goroutines that each wait 15 s for a TCP timeout, accumulating
			// ~5 blocked goroutines per NAT client and causing high resource usage.
			//
			// Offline detection: client is alive if it pushed within the last 30 s
			// (10× the 3-second push interval).  30 s gives comfortable headroom over
			// the 8-second push HTTP timeout: even if every push takes the maximum 8 s,
			// we still see 3+ pushes before the threshold triggers.
			if client.PushMode {
				if !client.LastPushAt.IsZero() && time.Since(client.LastPushAt) <= 30*time.Second {
					// Recent push received — clear any stale failure counter.
					failureCountMu.Lock()
					if failureCount[client.ID] > 0 {
						delete(failureCount, client.ID)
					}
					failureCountMu.Unlock()
				} else if !client.LastPushAt.IsZero() {
					// Push is stale — apply offline / removal logic
					failureCountMu.Lock()
					failureCount[client.ID]++
					currentCount := failureCount[client.ID]
					failureCountMu.Unlock()
					if currentCount >= 2 {
						if currentCount == 2 {
							go markSystemAsOffline(store, broker, client.ID)
						}
						if currentCount >= maxFailures {
							registry.Remove(client.ID)
							failureCountMu.Lock()
							delete(failureCount, client.ID)
							failureCountMu.Unlock()
						}
					}
				}
				// LastPushAt.IsZero() → client registered but hasn't pushed yet.
				// Do NOT count as a failure; it may still be starting up.
				continue
			}

			// Pull-mode clients: skip those with no reachable URL.
			if client.URL == "" && client.URL6 == "" {
				continue
			}

			// Registry already maintains consistency with database:
			// - Clients are added when they register (POST /api/clients/register)
			// - Clients are removed when systems are deleted (handleDeleteMetric)
			// - No need to verify existence on every poll (reduces DB load by 33 queries/sec)
			// Note: If a client somehow gets out of sync, it will be removed after maxFailures

			// Skip if a poll goroutine for this client is still running from a previous tick.
			// This prevents goroutine pile-up when a client's /metrics endpoint is slow (>3 s).
			activePollMu.Lock()
			if activePollClients[client.ID] {
				activePollMu.Unlock()
				continue
			}
			activePollClients[client.ID] = true
			activePollMu.Unlock()

			wg.Add(1)
			// Pass 'client' by VALUE into the goroutine so each goroutine owns its
			// own copy (avoids the classic "loop variable captured by closure" race).
			// pollClient receives a pointer to that goroutine-local copy; any writes
			// it makes (e.g. WorkingURL clear) now go through globalClientRegistry
			// methods, so the registry is always the source of truth.
			go func(c ClientInfo) {
				defer wg.Done()
				defer func() {
					activePollMu.Lock()
					delete(activePollClients, c.ID)
					activePollMu.Unlock()
				}()

				if c.ID == "" || (c.URL == "" && c.URL6 == "") {
					return
				}

				updated := pollClient(store, &c, ipCache)

				if updated {
					// Polling succeeded, reset failure count
					failureCountMu.Lock()
					if failureCount[c.ID] > 0 {
						delete(failureCount, c.ID)
					}
					failureCountMu.Unlock()
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
			// Use time.NewTimer instead of time.After to allow proper cleanup and avoid timer leak
			pollTimeout := time.NewTimer(2800 * time.Millisecond)
			select {
			case <-done:
				// All clients responded in time - stop timer to release resources immediately
				pollTimeout.Stop()
			case <-pollTimeout.C:
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

			// Push the full authoritative system list on every tick. Each
			// subscriber receives the payload masked for its view level
			// (public or admin), so the browser never needs to call
			// GET /api/metrics — the server is the one doing the pushing.
			//
			// Broadcasting every tick (even when nothing changed in this
			// interval) is deliberate: it guarantees the frontend's visible
			// state is refreshed at a predictable 3 s cadence (e.g. so
			// "online / offline" indicators flip at the right moment as soon
			// as their freshness threshold expires), and it makes the stream
			// self-healing — a subscriber whose TCP pipe swallowed one event
			// fully catches up on the next.
			broadcastMetricsSnapshot(store, registry, broker)
		}()
	}
}

// markSystemAsOffline marks a system as offline in the database
// NOTE: This function does NOT broadcast updates - all updates are handled by the polling loop
// to maintain a stable 3-second update frequency. The offline status will be included in the
// next regular broadcast from startClientPolling.
func markSystemAsOffline(store *Store, broker *SSEBroker, systemID string) {
	if store == nil || broker == nil || systemID == "" {
		return
	}

	existing, err := store.Get(systemID)
	if err != nil || existing == nil {
		return
	}

	// Race guard: this goroutine is spawned when failureCount reaches 2, but a
	// push or poll may have succeeded in the narrow window between that decision
	// and this goroutine actually running.  If UpdatedAt was refreshed within the
	// last 5 seconds the client is alive — abort to avoid a false offline flash.
	// 5 s is chosen as: push/poll interval (3 s) + 2 s scheduling slack.
	if time.Since(existing.UpdatedAt) < 5*time.Second {
		return
	}

	if !existing.Alert {
		// Only the flag is persisted; UpdatedAt is deliberately left alone.
		// buildMetricsSnapshot already reports the system offline from the
		// age of UpdatedAt (the 5 s race guard above guarantees it is old
		// enough), and rewinding the stamp made browsers drop every later
		// snapshot as stale (see Store.MarkOffline).
		store.MarkOffline(systemID) //nolint:errcheck
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
				// Update WorkingURL via the locked registry method only.
				// DO NOT write client.WorkingURL directly here: client is the raw
				// pointer returned by registry.Get() (lock already released), so a
				// direct field write would race with concurrent Register() calls.
				if successfulURL != "" && globalClientRegistry != nil {
					globalClientRegistry.UpdateWorkingURL(client.ID, successfulURL)
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
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			successfulURL = url
			break // Success, exit loop
		}
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			// Only log if working URL failed (this is important to track)
			if client.WorkingURL != "" && url == client.WorkingURL {
				log.Printf("⚠️  Client %s: cached working URL (%s) failed: %v, trying alternatives...", client.ID, url, err)
			}
			// Don't log individual connection attempts - only log final failure
		} else if resp != nil && resp.StatusCode != http.StatusOK {
			// Don't log individual HTTP errors - only log final failure
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
				// Use the registry method to clear WorkingURL atomically.
				// Direct assignment (client.WorkingURL = "") is unsafe here: if Register
				// has already replaced the registry pointer with a new ClientInfo,
				// we would write to a stale struct and the registry entry would keep
				// the (wrongly preserved) WorkingURL.
				if globalClientRegistry != nil {
					globalClientRegistry.UpdateWorkingURL(client.ID, "")
				}
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

	// Persist the working URL.  'client' here points to the goroutine-local copy
	// of ClientInfo (passed by value from the polling loop), so writing its fields
	// is safe.  We still call UpdateWorkingURL for the canonical registry update.
	if successfulURL != "" {
		client.WorkingURL = successfulURL // goroutine-local, race-free
		if globalClientRegistry != nil {
			globalClientRegistry.UpdateWorkingURL(client.ID, successfulURL)
		}
	}

	// Defensive size limit on the client-reported /metrics body.
	// A healthy payload (cpu %, mem, disk, net, uptime, a handful of strings
	// and tags) is well under 16 KB; we allow 1 MB so exotic configurations
	// (many tags, long hostnames) still decode, but a compromised or broken
	// client cannot stream an unbounded body that OOMs the server.
	// This symmetrises with handleClientPush, which already caps the push
	// body via http.MaxBytesReader(..., 1<<20).
	bodyReader := io.LimitReader(resp.Body, 1<<20)
	var payload metricPayload
	if err := json.NewDecoder(bodyReader).Decode(&payload); err != nil {
		return false
	}

	// Load the stored record first: it carries the admin-owned fields we must
	// preserve and the persisted Location that lets us skip the geo lookup.
	var existing *SystemMetric
	existing, _ = store.Get(client.ID)

	// Resolve location without ever blocking the poll (see resolveLocation).
	payload.Location = resolveLocation(ipCache, existing, payload.Location, payload.IPv4, payload.IPv6)

	// Format uptime for display
	timeDisplay := formatUptime(payload.Uptime)

	order := 0
	name := client.Name // Default to client name if not in database
	var tcpingData map[string]TCPingTargetData
	var tags []string
	var hideOnHome, hideTCPing bool
	// Update secret from database (will be synced to registry cache)
	if existing != nil {
		order = existing.Order
		// Preserve name from database (don't override with client name)
		name = existing.Name
		hideOnHome = existing.HideOnHome
		hideTCPing = existing.HideTCPing
		// CRITICAL: Preserve tags and secret from database (client should never override these)
		tags = existing.Tags
		secret = existing.Secret
		// Preserve existing tcping data map (minus targets the admin removed,
		// which the copy would otherwise resurrect after PruneTCPingTargets).
		if existing.TCPingData != nil {
			tcpingData = make(map[string]TCPingTargetData)
			for k, v := range existing.TCPingData {
				tcpingData[k] = v
			}
			pruneTCPingDataToConfig(store, tcpingData)
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
		CPU:                payload.CPU,
		CPUModel:           payload.CPUModel,
		Memory:             payload.Memory,
		MemoryInfo:         payload.MemoryInfo,
		SwapInfo:           payload.SwapInfo,
		Disk:               payload.Disk,
		DiskInfo:           payload.DiskInfo,
		NetInMBps:          payload.NetInMBps,
		NetOutMBps:         payload.NetOutMBps,
		TotalNetInBytes:    payload.TotalNetInBytes,
		TotalNetOutBytes:   payload.TotalNetOutBytes,
		AgentVersion:       payload.AgentVersion,
		Order:              order,
		Alert:              false, // Client is sending data, so system is online
		UpdatedAt:          time.Now().UTC(),
		TCPingData:         tcpingData,
		Tags:               tags,   // CRITICAL: Preserve tags from database
		Secret:             secret, // CRITICAL: Preserve secret from database
		HideOnHome:         hideOnHome,
		HideTCPing:         hideTCPing,
	}

	// If system was offline and is now online, log the reconnection
	_ = wasOffline // Can be used for notifications in the future

	// Stamp the poll before the write lands: tcpingPullSuppressed compares
	// LastPollAt with UpdatedAt, and the reverse order left a window where a
	// fresh UpdatedAt paired with the previous poll's stamp looked like a push.
	if globalClientRegistry != nil {
		globalClientRegistry.UpdatePollState(client.ID, time.Now())
	}
	// Agent write: admin-owned fields are merged from the stored record
	// inside the transaction so a concurrent admin edit is never reverted.
	if err := store.UpsertFromAgent(metric); err != nil {
		return false
	}

	// Keep the registry's cached secret in sync with the DB value so pollClient
	// never uses a stale secret.  UpdateSecret holds the write lock, avoiding the
	// data race that would occur with a direct pointer write after Get().
	if existing != nil && existing.Secret != "" && globalClientRegistry != nil {
		globalClientRegistry.UpdateSecret(client.ID, existing.Secret)
	}

	// Return true to indicate this client was successfully updated
	return true
}

// isPrivateIPStr is a string-based wrapper around isPrivateIP.
// Returns true for invalid, empty, or private addresses.
func isPrivateIPStr(ipStr string) bool {
	if ipStr == "" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return isPrivateIP(ip)
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

// Background geo-IP resolution.
//
// Geo lookups used to run inline in handleClientPush / pollClient. When the
// external services are slow or unreachable (common for servers in mainland
// China) every lookup blocked its request for ~100 s while the agent kept
// retrying every 3 s. Measured with 100 agents this piled up ~5 000
// goroutines and ~1 100 outbound sockets within two minutes, and it repeated
// after every restart because the IP cache is memory-only. The rules now:
//
//  1. Never block a push or poll on a lookup. Return the best value already
//     at hand (cache hit, or the Location persisted in the DB) and schedule
//     the lookup in the background.
//  2. One outstanding lookup per IP, a fixed pool of geoMaxConcurrent
//     workers and a bounded queue, so cost never scales with agent count.
//  3. The answer lands in the IP cache; the next push persists it inside the
//     metric it writes anyway, so a restart never needs the lookup again.
const (
	geoMaxConcurrent = 8    // background lookup workers
	geoQueueSize     = 1024 // pending lookups; overflow is dropped and re-queued by the next push
)

type geoJob struct {
	ip      string
	ipCache *IPCountryCache
}

var (
	geoInflightMu  sync.Mutex
	geoInflight    = make(map[string]struct{})
	geoQueue       = make(chan geoJob, geoQueueSize)
	geoWorkersOnce sync.Once
)

// resolveLocation returns the country to store for a system right now.
// reported is what the agent sent (may be empty); existing is the stored
// record (may be nil). The call never performs network I/O: a cache miss
// only queues a background lookup, and the next push (<= 3 s later) picks
// the cached answer up and persists it as part of its normal write.
func resolveLocation(ipCache *IPCountryCache, existing *SystemMetric, reported, ipv4, ipv6 string) string {
	if reported != "" {
		return extractCountry(reported)
	}
	fallback := ""
	if existing != nil {
		// Records written by older versions may hold "City, CC"; normalise so a
		// reused value is always the bare country code the frontend expects.
		fallback = extractCountry(existing.Location)
		// Reuse the persisted value as long as the public IPs are unchanged.
		if fallback != "" && existing.IPv4 == ipv4 && existing.IPv6 == ipv6 {
			return fallback
		}
	}
	for _, ip := range []string{ipv4, ipv6} {
		if ip == "" || isPrivateIPStr(ip) {
			continue
		}
		if country, found := ipCache.Get(ip); found {
			if country != "" {
				return country
			}
			continue // cached failure for this family; try the other one
		}
		scheduleGeoLookup(ipCache, ip)
		// Do not queue the other family yet: if this one succeeds the
		// answer covers the system, and the next push re-evaluates anyway.
		return fallback
	}
	return fallback
}

// scheduleGeoLookup queues ip for resolution by the worker pool. One
// outstanding lookup per IP; a full queue drops the request (the next push
// re-queues it) so neither goroutines nor memory grow with agent count.
func scheduleGeoLookup(ipCache *IPCountryCache, ip string) {
	geoWorkersOnce.Do(func() {
		for i := 0; i < geoMaxConcurrent; i++ {
			go geoWorker()
		}
	})

	geoInflightMu.Lock()
	if _, busy := geoInflight[ip]; busy {
		geoInflightMu.Unlock()
		return
	}
	geoInflight[ip] = struct{}{}
	geoInflightMu.Unlock()

	select {
	case geoQueue <- geoJob{ip: ip, ipCache: ipCache}:
	default:
		geoInflightMu.Lock()
		delete(geoInflight, ip)
		geoInflightMu.Unlock()
	}
}

func geoWorker() {
	for job := range geoQueue {
		if country := getCountryFromIP(job.ip); country != "" {
			job.ipCache.Set(job.ip, country)
		} else {
			job.ipCache.SetFailed(job.ip)
		}
		geoInflightMu.Lock()
		delete(geoInflight, job.ip)
		geoInflightMu.Unlock()
	}
}

// Get country from IP address using free IP geolocation API
// Uses multiple services with fallback for better reliability, especially for China
// Runs only from scheduleGeoLookup (background, bounded), so the per-service
// budget is kept short: one attempt of at most 6 s each.
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
				body, err := io.ReadAll(resp.Body)
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

	// One attempt per service, 6 s each: enough for the slow-but-working
	// case (mainland China reaching overseas APIs), while a dead service
	// cannot hold a background worker for long.
	for _, service := range services {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", service.url, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "PulseMonitor/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.LimitReader(resp.Body, 32<<10), resp.Body}

		country := ""
		if resp.StatusCode == http.StatusOK {
			country = service.parser(resp)
		}
		resp.Body.Close()
		cancel()
		if country != "" {
			return country
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			// Rate limited: give the next service a moment so we do not
			// trip its limiter as well.
			time.Sleep(1 * time.Second)
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
	// 256 KB is more than enough for ~10k system IDs (each ~30 bytes JSON);
	// prevents an authenticated-but-malicious admin browser tab from being
	// used to amplify a memory-exhaustion attack on the server.
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)

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

	// One transaction for the whole list (see Store.UpdateOrders).
	if err := store.UpdateOrders(payload.Order); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Push a single authoritative snapshot so every connected browser
	// re-sorts its rows without fetching anything. We intentionally do NOT
	// emit a separate "order_updated" signal: the snapshot already carries
	// the final order and dual-firing would make legacy/new clients render
	// twice for the same change.
	if broker != nil {
		broadcastMetricsSnapshot(store, globalClientRegistry, broker)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "order updated",
		"count":   len(payload.Order),
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Permissive CORS is safe here because we never set
		// Access-Control-Allow-Credentials, so browsers do NOT attach cookies
		// on cross-origin requests. Every mutation requires a Bearer token in
		// the Authorization header (which is never auto-sent by the browser),
		// so a malicious origin cannot invoke privileged endpoints without
		// first stealing the token via a completely separate flaw. The
		// public GET surface is, by design, readable by anyone.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Baseline hardening headers applied to every response.
		//   - X-Content-Type-Options: nosniff — stops browsers from
		//     "helpfully" re-interpreting a text/plain body as HTML/JS, which
		//     would otherwise turn a misconfigured error page into an XSS
		//     vector on older browsers.
		//   - X-Frame-Options: SAMEORIGIN — keeps the dashboard out of
		//     attacker-controlled iframes so we cannot be framed into a
		//     clickjacking UI. SAMEORIGIN (vs DENY) leaves the door open if
		//     an admin ever embeds the dashboard inside their own intranet
		//     portal on the same host.
		//   - Referrer-Policy: strict-origin-when-cross-origin — a safe
		//     default that sends full Referer only on same-origin navigation
		//     and strips to just the origin when going cross-site, limiting
		//     leakage of URL-embedded tokens (e.g. old share-token links in
		//     users' browser history).
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

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
		// Only apply to API endpoints (not static files). Set this before
		// dispatch so direct http.Error responses (401/404/405, etc.) cannot
		// be cached by browsers or intermediary CDNs either.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
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

// writeCachedJSON ships an already-encoded body. We deliberately set the
// same headers as writeJSON so cache-hit responses are byte-equivalent to
// fresh responses; the only difference is that we skipped the encoder.
//
// The body is a json.Encoder output (so it ends with '\n'); we reuse it as
// is to keep wire-format identical to writeJSON.
func writeCachedJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		log.Printf("⚠️  Failed to write cached JSON response: %v", err)
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
	Target   string  `json:"target"` // Target address (e.g., "8.8.8.8:53")
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
	// Small JSON (5 fields, all short); 16 KB is plenty.
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
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

		if !secretEqual(providedSecret, existing.Secret) {
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

	// Invalidate cache for this client to ensure data freshness
	invalidateTCPingCache(payload.ClientID)

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
				if privacyConfig.ShareToken != "" && secretEqual(shareToken, privacyConfig.ShareToken) && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
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
				if privacyConfig.ShareToken != "" && secretEqual(shareToken, privacyConfig.ShareToken) && !privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires) {
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

	// Try to get the exact client+target history response from cache first.
	// Cache stores the already-encoded JSON body, so a hit can be served
	// without re-running json.Marshal — measurably reduces CPU under load.
	if body, found := getCachedTCPingResultsJSON(clientID, target); found {
		writeCachedJSON(w, http.StatusOK, body)
		return
	}

	// Cache miss - query database
	if target != "" {
		results, err = store.GetTCPingResults(clientID, target)
	} else {
		results, err = store.GetTCPingResults(clientID)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get history: %v", err), http.StatusInternalServerError)
		return
	}

	// Calculate statistics from results
	stats := calculateTCPingStats(results)

	// Build response with statistics
	response := TCPingHistoryResponse{
		Results: results,
		Stats:   stats,
	}

	cacheTCPingResults(clientID, target, response)

	writeJSON(w, http.StatusOK, response)
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

	// SECURITY: Only return SharedSecret to authenticated admin users
	// Unauthenticated users should never see the secret
	if !isAuthenticated(r) {
		// Create a copy without the secret for public access
		publicConfig := NavbarConfig{
			Text:        config.Text,
			Logo:        config.Logo,
			CustomCSS:   config.CustomCSS,   // Public: used for page styling
			CustomJS:    config.CustomJS,    // Public: used for page functionality
			ShowTraffic: config.ShowTraffic, // Public: controls traffic display in detail section
			ShowGlass:   config.ShowGlass,   // Public: controls glassmorphism effect
			HideTags:    config.HideTags,    // Public: Hotaru-compatible display flag
			HideCards:   config.HideCards,   // Public: Hotaru-compatible display flag
			// SharedSecret is intentionally omitted for security
		}
		writeJSON(w, http.StatusOK, publicConfig)
		return
	}

	// Authenticated admin users can see the full config including SharedSecret
	writeJSON(w, http.StatusOK, config)
}

func handleSetNavbarConfig(store *Store, w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	defer r.Body.Close()
	// NavbarConfig includes CustomCSS and CustomJS, which are free-form
	// text entered by the admin. 1 MB accommodates even the hairy real-world
	// custom stylesheets (minified bootstrap is ~160 KB, full theme kits
	// rarely exceed a few hundred KB) while still capping a runaway request.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var config NavbarConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate config
	if config.Text == "" {
		config.Text = "Pulse" // Default to "Pulse" if empty
	}

	// Get current config to check if SharedSecret has changed
	currentConfig, err := store.GetNavbarConfig()
	if err != nil {
		log.Printf("⚠️ Warning: Failed to get current navbar config: %v", err)
	}

	// Check if SharedSecret has changed
	secretChanged := currentConfig != nil && currentConfig.SharedSecret != "" && config.SharedSecret != "" && currentConfig.SharedSecret != config.SharedSecret

	// Save the new navbar config
	if err := store.SaveNavbarConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("failed to save navbar config: %v", err), http.StatusInternalServerError)
		return
	}

	// If SharedSecret changed, update all existing systems to use the new shared secret
	if secretChanged {
		systems, err := store.List()
		if err != nil {
			log.Printf("⚠️ Warning: Failed to list systems when updating shared secret: %v", err)
		} else {
			for _, system := range systems {
				// Update each system's secret to the new shared secret
				system.Secret = config.SharedSecret
				if err := store.Upsert(system); err != nil {
					log.Printf("⚠️ Warning: Failed to update secret for system %s: %v", system.ID, err)
				}
			}
			log.Printf("✅ Updated shared secret and applied to %d systems", len(systems))
		}
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
		"enabled":     config.Enabled,
		"server_time": time.Now().Format(time.RFC3339), // Include server time for client to calculate time difference
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
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var payload struct {
		Enabled          bool   `json:"enabled"`
		ShareToken       string `json:"share_token"`
		TokenExpires     string `json:"token_expires"`      // ISO 8601 string or empty
		ExpiresInSeconds int    `json:"expires_in_seconds"` // Alternative: seconds from now
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

	// A plain save that keeps the existing link sends expires_in_seconds = 0
	// plus the stored token_expires (so the countdown is not restarted).
	// Keep the previously chosen duration as well: the admin UI shows it as
	// the default for the next link and must not fall back to 1 h.
	// The server is authoritative for the absolute expiry as well: a caller
	// that keeps the token but omits token_expires (scripts, an older UI)
	// must not turn the link into one that never validates (every
	// share-token check requires a non-zero expiry).
	if payload.ShareToken != "" && payload.ExpiresInSeconds <= 0 {
		if current, err := store.GetPrivacyConfig(); err == nil && current != nil && current.ShareToken == payload.ShareToken {
			config.ExpiresInSeconds = current.ExpiresInSeconds
			config.TokenExpires = current.TokenExpires
		}
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
		// Otherwise the stored expiry (copied above) or zero is kept.
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
		"enabled":            config.Enabled,
		"share_token":        config.ShareToken,
		"expires_in_seconds": config.ExpiresInSeconds,         // Include saved expiration seconds value
		"server_time":        time.Now().Format(time.RFC3339), // Include server time for client to calculate time difference
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
	// A token is a short string; anything more than a few KB is abuse.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
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

	// Check if token matches (constant-time).
	if config.ShareToken == "" || !secretEqual(config.ShareToken, payload.Token) {
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

func handleSetTCPingConfig(store *Store, broker *SSEBroker, registry *ClientRegistry, w http.ResponseWriter, r *http.Request) {
	// Require authentication for setting TCPing config
	if !isAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	defer r.Body.Close()
	// 64 KB fits ~500 targets (each target is ~100 bytes of JSON); the
	// handler's per-target validation below further rejects silly lists.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var config TCPingConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Normalize nil slice to empty slice so DB stores [] instead of null
	if config.Targets == nil {
		config.Targets = []TCPingTargetEntry{}
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

		// Split host and port. Use net.SplitHostPort so bracketed IPv6
		// literals like "[::1]:443" or "[2001:db8::1]:443" round-trip
		// correctly; a naive strings.SplitN(":") splits at the first ":"
		// and treats the leading "[" as the host, which makes it
		// impossible to save any IPv6 tcping target from the admin UI.
		host, portStr, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			http.Error(w, fmt.Sprintf("invalid target format: %s (expected format: host:port) for target: %s", address, target.Name), http.StatusBadRequest)
			return
		}
		host = strings.TrimSpace(host)
		portStr = strings.TrimSpace(portStr)

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

		// Additional validation: check for common injection patterns.
		// Valid hosts are hostnames (a-z, 0-9, dot, hyphen), IPv4
		// literals, or IPv6 literals (hex + ":"). Note that after
		// net.SplitHostPort the IPv6 brackets have already been
		// stripped, so we no longer need to allow "[" / "]" here.
		hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9.\-:]+$`)
		if !hostnameRegex.MatchString(host) {
			http.Error(w, fmt.Sprintf("invalid target host format for target: %s", target.Name), http.StatusBadRequest)
			return
		}
	}

	// Collect targets that were removed by this save so we can clean up all
	// their derived state (history, per-system snapshot, frontend cache).
	var removedTargets []string

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

		for oldTarget := range oldTargets {
			if !newTargets[oldTarget] {
				removedTargets = append(removedTargets, oldTarget)
			}
		}
	}

	if err := store.SaveTCPingConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	// Only clear the in-memory tcping cache *after* the new config has
	// been persisted successfully. If SaveTCPingConfig returned an error
	// above we would otherwise have wiped every chart's history for no
	// reason while leaving the old config still in force.
	if oldConfig != nil {
		clearAllTCPingCache()
	}

	// Removed targets: prune the "latest per target" snapshot of every system
	// in one transaction (so the frontend stops showing the target at once)
	// and drop their history in the background, where the full-bucket scan
	// cannot keep the admin waiting or stall agent pushes.
	if len(removedTargets) > 0 {
		if err := store.PruneTCPingTargets(removedTargets); err != nil {
			log.Printf("⚠️  failed to prune removed tcping targets: %v", err)
		}
		go func(targets []string) {
			start := time.Now()
			for _, target := range targets {
				if err := store.DeleteTCPingResultsByTarget(target); err != nil {
					log.Printf("⚠️  history cleanup for removed target %s failed: %v", target, err)
				}
			}
			log.Printf("🧹 Removed history of %d deleted tcping target(s) in %v", len(targets), time.Since(start).Round(time.Millisecond))
		}(removedTargets)
	}

	// Notify every connected browser that the tcping config changed so
	// they can invalidate their cached copy (cachedTCPingConfig in
	// SystemTable.astro) and redraw expanded charts without a manual
	// page reload. The payload is deliberately minimal — just a signal.
	// Right after this we also broadcast a fresh metrics snapshot so the
	// pruned tcping_data reaches the frontend in the same SSE flush.
	if broker != nil {
		if payload, mErr := json.Marshal(map[string]interface{}{
			"type": "tcping_config_updated",
		}); mErr == nil {
			broker.Broadcast(string(payload))
		}
		broadcastMetricsSnapshot(store, registry, broker)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// tcpingPullSuppressed implements the registry-churn guard of the tcping
// loop for clients that have never pushed. A fresh UpdatedAt means "somebody
// wrote this record in the last 10 s"; if that writer was our own poll
// (LastPollAt at or after UpdatedAt) the client is a genuine pull-mode agent
// and must be probed. Only a fresh write that our poll did not produce, i.e.
// a push arriving in the re-registration window, suppresses the pull.
//
// The previous version skipped on any fresh UpdatedAt, which pollClient
// refreshes every 3 s, so pull-mode agents never received server-driven
// tcping at all.
func tcpingPullSuppressed(client ClientInfo, m *SystemMetric, now time.Time) bool {
	if m == nil || m.UpdatedAt.IsZero() || now.Sub(m.UpdatedAt) >= 10*time.Second {
		return false
	}
	if !client.LastPollAt.IsZero() && !m.UpdatedAt.After(client.LastPollAt.Add(500*time.Millisecond)) {
		return false // the fresh record is our own poll result
	}
	return true
}

// pruneTCPingDataToConfig removes "latest tcping" entries for targets that
// are no longer configured, so an agent write composed from a stale copy of
// the record cannot bring a removed target back.
func pruneTCPingDataToConfig(store *Store, data map[string]TCPingTargetData) {
	if len(data) == 0 || store == nil {
		return
	}
	cfg, err := store.GetTCPingConfig()
	if err != nil || cfg == nil {
		return
	}
	allowed := make(map[string]struct{}, len(cfg.Targets))
	for _, t := range cfg.Targets {
		allowed[t.Address] = struct{}{}
	}
	for target := range data {
		if _, ok := allowed[target]; !ok {
			delete(data, target)
		}
	}
}

// tcpingBatchSeen reports whether clientID has just delivered exactly this
// batch before (same targets, stamps, outcomes and latencies) and remembers
// the batch for the next call. Only batches whose samples all carry an
// agent stamp are tracked, so legacy agents (no measured_at) are never
// deduplicated by value. The map holds one entry per pushing client.
var (
	tcpingBatchMu   sync.Mutex
	tcpingBatchLast = map[string]tcpingBatchMark{}
)

type tcpingBatchMark struct {
	sig string
	at  time.Time
}

const tcpingBatchDedupeWindow = 10 * time.Minute

func tcpingBatchSignature(results []ClientTCPingResult) string {
	if len(results) == 0 {
		return ""
	}
	parts := make([]string, 0, len(results))
	for _, r := range results {
		if r.MeasuredAt.IsZero() {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%s|%d|%t|%.3f", r.Target, r.MeasuredAt.UnixNano(), r.Success, r.Latency))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func tcpingBatchSeen(clientID string, results []ClientTCPingResult) bool {
	sig := tcpingBatchSignature(results)
	if sig == "" {
		return false
	}
	now := time.Now()
	tcpingBatchMu.Lock()
	defer tcpingBatchMu.Unlock()
	last, ok := tcpingBatchLast[clientID]
	tcpingBatchLast[clientID] = tcpingBatchMark{sig: sig, at: now}
	return ok && last.sig == sig && now.Sub(last.at) < tcpingBatchDedupeWindow
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
				TLSHandshakeTimeout:   10 * time.Second, // Increased from 3s to 10s for slow TLS
				ResponseHeaderTimeout: 8 * time.Second,  // Wait up to 8s for response headers
				ExpectContinueTimeout: 5 * time.Second,  // Added for better HTTP/1.1 support
				DisableCompression:    false,            // Enable compression for efficiency
			},
		}
	})
	return tcpingHTTPClient
}

// Start tcping polling with configurable interval and targets
func startTCPingPolling(ctx context.Context, registry *ClientRegistry, store *Store) {
	// Get initial config
	config, err := store.GetTCPingConfig()
	if err != nil {
		config = &TCPingConfig{
			Targets:      []TCPingTargetEntry{},
			IntervalSecs: 60,
		}
	}

	// Semaphore to cap the number of concurrent TCPing goroutines.
	// Without this, N_clients × N_targets goroutines fire simultaneously on each tick.
	// 50 is generous (handles ~10 clients × 5 targets) while preventing runaway growth.
	const maxConcurrentTCPing = 50
	tcpingSem := make(chan struct{}, maxConcurrentTCPing)

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
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

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
			// Skip clients with empty ID (zero value) or no reachable URL.
			if client.ID == "" || (client.URL == "" && client.URL6 == "") {
				continue
			}

			// Push-mode clients run TCPing locally and include results in their push payload.
			// The server must NOT send TCPing requests to these clients.
			if client.PushMode {
				continue
			}

			// Registry-churn guard: a push-mode client that was just dropped from the
			// registry (e.g. after a long network glitch) re-registers via
			// handleClientRegister with a real URL and PushMode=false, then UpdatePushState
			// flips the bit on its next push (~3 s later). In that narrow window the tcping
			// ticker used to pull /tcping once and create a stray, non-push-aligned history
			// record. Suppress the pull when the persisted SystemMetric shows a very fresh
			// UpdatedAt (≤ 10 s) — a pure pull-mode client never updates UpdatedAt without
			// the server first polling it, so this unambiguously marks "something is
			// pushing to this ID right now".
			if client.LastPushAt.IsZero() {
				// Re-read the registry entry: the copy taken by GetAll() at the
				// start of the tick can be many seconds old by now (an
				// unreachable client earlier in the loop costs two 5 s
				// connection attempts), and comparing a stale LastPollAt with
				// the live UpdatedAt mistook our own poll for a push.
				fresh := registry.Get(client.ID)
				if fresh == nil || !fresh.LastPushAt.IsZero() {
					continue
				}
				if m, err := store.Get(client.ID); err == nil && m != nil && tcpingPullSuppressed(*fresh, m, time.Now()) {
					continue
				}
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

				// Acquire the semaphore slot BEFORE spawning the goroutine so we
				// never launch more than maxConcurrentTCPing workers at a time.
				// Doing it inside the goroutine (the old pattern) would let a busy
				// tick spawn N_clients × N_targets goroutines up front, all of
				// them blocked on the channel send — the stack and scheduler
				// overhead of hundreds of parked goroutines is exactly what the
				// semaphore is supposed to prevent.
				select {
				case <-ctx.Done():
					return
				case tcpingSem <- struct{}{}:
				}

				go func(clientID string, tgt TCPingTargetEntry) {
					defer func() { <-tcpingSem }()

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
						req, reqErr := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(requestData))
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

					// Defensive size limit: the /tcping response is a tiny JSON
					// object ({ success, latency, error? }) — well under 1 KB in
					// practice. 64 KB is a very generous ceiling that still stops
					// a compromised / runaway client from streaming an unbounded
					// body back at us.
					tcpingBody := io.LimitReader(resp.Body, 64<<10)
					var tcpingResp TCPingResponse
					if err := json.NewDecoder(tcpingBody).Decode(&tcpingResp); err != nil {
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
					} else {
						// Invalidate cache for this client to ensure data freshness
						invalidateTCPingCache(clientID)
					}

					// Update SystemMetric with latest tcping data for this target (only if successful).
					// Merged inside one transaction so a concurrent poll result or admin edit
					// is never overwritten (see Store.SetTCPingLatest).
					if tcpingResp.Success {
						store.SetTCPingLatest(clientID, tgt.Address, TCPingTargetData{ //nolint:errcheck
							Latency:   tcpingResp.Latency,
							Timestamp: time.Now().UTC(),
						})
					}
				}(client.ID, target)
			}
		}
	}
}

// Start cleanup old tcping data every hour
func startTCPingCleanup(ctx context.Context, store *Store) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_ = store.CleanupOldTCPingResults()
	}
}

// Start IP cache cleanup every hour
func startIPCacheCleanup(ctx context.Context, ipCache *IPCountryCache) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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
	count       int
	lastAttempt time.Time
	lockedUntil time.Time
}

var loginAttempts = make(map[string]*loginAttempt) // key: IP address
var loginAttemptsMu sync.RWMutex

// Token verification attempt tracking
type verifyAttempt struct {
	count       int
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

			// Cleanup old login attempts. The previous condition required
			// attempt.count == 0, but count only resets to 0 on a successful
			// login from the same IP — for the vast majority of failed-once-
			// and-never-came-back probes (which is what fills the map in
			// production) the count stays at ≥ 1 forever and the entry
			// leaked. We now drop entries idle for more than 24h
			// unconditionally, or idle for more than 1h once any active
			// lockout has expired. A fresh attempt simply re-creates the
			// entry from scratch, preserving the intended rate-limit while
			// preventing unbounded growth from IP-scanning traffic.
			loginAttemptsMu.Lock()
			for ip, attempt := range loginAttempts {
				idle := now.Sub(attempt.lastAttempt)
				if idle > 24*time.Hour {
					delete(loginAttempts, ip)
					continue
				}
				if idle > 1*time.Hour && !now.Before(attempt.lockedUntil) {
					delete(loginAttempts, ip)
				}
			}
			loginAttemptsMu.Unlock()

			// Cleanup old verify attempts (older than 5 minutes)
			verifyAttemptsMu.Lock()
			for ip, attempt := range verifyAttempts {
				if now.Sub(attempt.lastAttempt) > 5*time.Minute {
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

	defer r.Body.Close()
	// Password JSON is tiny; 4 KB caps any unboundedness without affecting
	// even the upper bound of a legitimate 128-char password.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

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

var (
	trustedProxyOnce sync.Once
	trustedProxyNets []*net.IPNet
)

func loadTrustedProxyNets() {
	raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if raw == "" {
		return
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(part); err == nil {
			trustedProxyNets = append(trustedProxyNets, cidr)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			trustedProxyNets = append(trustedProxyNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		log.Printf("⚠️  Ignoring invalid TRUSTED_PROXIES entry %q", part)
	}
}

func isTrustedProxyIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	trustedProxyOnce.Do(loadTrustedProxyNets)
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteAddrIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	if ip := net.ParseIP(strings.TrimSpace(remoteAddr)); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(remoteAddr)
}

// forwardedClientIP returns the client address from an X-Forwarded-For
// chain as seen by the trusted proxy that delivered the request.
//
// The chain is read from the right: each trusted proxy appends the address
// it accepted the connection from, so the right-most entry that is not
// itself a trusted proxy is the real client. Reading from the left (the
// previous behaviour) trusted whatever the client put in the header before
// the CDN appended the real address, which let anyone spoof their IP and
// walk around the login rate limit and the per-IP SSE cap once a CDN such
// as Cloudflare was listed in TRUSTED_PROXIES.
func forwardedClientIP(header string) string {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if part == "" || strings.EqualFold(part, "unknown") {
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			continue
		}
		if isTrustedProxyIP(ip) {
			continue // hop added by another trusted proxy in the chain
		}
		return ip.String()
	}
	return ""
}

// getClientIP extracts the client IP address from the request. Forwarded
// headers are trusted only when the immediate peer is a trusted proxy
// (loopback by default, plus TRUSTED_PROXIES as comma-separated IP/CIDR
// entries). This preserves the bundled nginx setup while preventing direct
// clients from spoofing X-Forwarded-For to bypass login rate limits.
func getClientIP(r *http.Request) string {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	if isTrustedProxyIP(net.ParseIP(remoteIP)) {
		if ip := forwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
		if ip := forwardedClientIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	return remoteIP
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

	defer r.Body.Close()
	// Cap body before decoding: prevents an attacker from forcing the server
	// to allocate many MB just to parse a login attempt. Still plenty of
	// room for the 128-char upper bound we enforce below.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

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

	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

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

	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var payload struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

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

// handleAdminBackup streams a consistent hot-backup of the bbolt
// database to the client, auth-guarded. The snapshot is produced via
// Store.Snapshot, which internally uses bbolt's Tx.WriteTo inside a
// read-only transaction — no server downtime, no risk of capturing a
// torn page, and no need for docker compose stop.
//
// Migration workflow:
//
//	# On old host — grab a hot snapshot (requires admin token)
//	curl -fsSL -H "Authorization: Bearer $TOKEN" \
//	  http://old-host:8008/api/admin/backup \
//	  -o pulse-metrics.db
//
//	# On new host — drop the file into the Docker volume and boot
//	docker compose down
//	cp pulse-metrics.db datatz/metrics.db
//	docker compose up -d
//
// The endpoint is intentionally GET so it composes with curl/wget,
// cron, and pipe-into-scp without extra tooling. The response
// Content-Type is application/octet-stream so browsers save the file
// rather than trying to render it, and Content-Disposition ships a
// sensible filename that embeds a UTC timestamp for operator sanity.
//
// SECURITY: A stolen backup file is equivalent to possession of every
// per-system secret, the admin password hash, and every piece of
// dashboard configuration. Two layers of defence on top of the normal
// admin-token gate:
//
//  1. Bearer-only — we refuse ?token=xxx query-string auth here, even
//     though the shared isAuthenticated() helper accepts it. Query
//     tokens get logged in nginx access logs, shell history, and
//     referer headers, which is the last place the key to the kingdom
//     should land. curl/cron/manual operators all have no reason to
//     use anything other than Authorization: Bearer.
//
//  2. Audit logging — successful backup pulls are logged with the
//     source IP so operators can spot unexpected snapshots after the
//     fact, e.g. if a token leaked.
func handleAdminBackup(store *Store, w http.ResponseWriter, r *http.Request) {
	// Reject query-param tokens on this endpoint specifically.
	if r.URL.Query().Get("token") != "" {
		http.Error(w, "backup endpoint requires Authorization: Bearer header, not ?token= query param", http.StatusUnauthorized)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	authTokensMu.Lock()
	expiry, exists := authTokens[token]
	authTokensMu.Unlock()
	if !exists || time.Now().After(expiry) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("pulse-backup-%s.db", ts)
	log.Printf("📦 Admin backup requested from %s — streaming snapshot %s", getClientIP(r), filename)

	// Write headers BEFORE beginning the stream. Once Snapshot starts
	// writing, the response is committed and we cannot meaningfully
	// emit a JSON error body any more — the client would see a mix of
	// bbolt pages and HTTP error text. So if anything is going to fail
	// noisily, we want it to be in the View-transaction setup, which
	// raises before the first byte is written to w.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	// Advise proxies (including our own nginx) NOT to buffer — the DB
	// can be several MB and buffering the whole body serves no purpose.
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")

	n, err := store.Snapshot(w)
	if err != nil {
		// If streaming has already begun, headers are committed and we
		// can't switch to a JSON error; log it so operators notice the
		// truncated file. If it failed before the first flush, Go's
		// default behaviour is to emit a 500 — which is the correct
		// outcome.
		log.Printf("⚠️  Backup snapshot failed after %d bytes: %v", n, err)
		return
	}
	log.Printf("✅ Admin backup streamed %d bytes to %s", n, getClientIP(r))
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
