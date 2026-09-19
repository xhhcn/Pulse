package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestValidateTCPingTarget(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"example.com:443", "example.com:443"},
		{"example.com", "example.com:80"},          // bare host defaults to port 80
		{"  example.com:443  ", "example.com:443"}, // surrounding whitespace is trimmed
		{"1.2.3.4:65535", "1.2.3.4:65535"},
		{"1.2.3.4", "1.2.3.4:80"},
		{"[::1]:443", "[::1]:443"}, // bracketed IPv6 literal with port
		{"[::1]", "[::1]:80"},      // bracketed IPv6 literal without port
		{"my-host.example.com:1", "my-host.example.com:1"},
		{"example.com\n:80", "example.com:80"}, // stray edge whitespace is trimmed away
	}
	for _, tc := range valid {
		got, err := validateTCPingTarget(tc.in)
		if err != nil {
			t.Errorf("validateTCPingTarget(%q) returned error %v, want %q", tc.in, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("validateTCPingTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalid := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"too long", strings.Repeat("a", 256) + ":80"},
		{"missing host", ":80"},
		{"port zero", "example.com:0"},
		{"port too high", "example.com:70000"},
		{"port not a number", "example.com:http"},
		{"negative port", "example.com:-1"},
		{"whitespace inside host", "exa mple.com:80"},
		{"command injection", "example.com:80; rm -rf /"},
		{"shell substitution", "$(whoami):80"},
		{"url form", "http://example.com:80"},
		{"newline inside host", "exa\nmple.com:80"},
		{"tab inside host", "exa\tmple.com:80"},
	}
	for _, tc := range invalid {
		if got, err := validateTCPingTarget(tc.in); err == nil {
			t.Errorf("%s: validateTCPingTarget(%q) = %q, want error", tc.name, tc.in, got)
		}
	}
}

// resetPushTCPingState restores the package-level TCPing config to its defaults
// and empties the change signal so each test starts from a known state.
func resetPushTCPingState(t *testing.T) {
	t.Helper()
	pushTCPingMu.Lock()
	pushTCPingTargets = nil
	pushTCPingIntervalSec = 60
	pushTCPingMu.Unlock()
	drainIntervalChanged()
}

func drainIntervalChanged() bool {
	select {
	case <-pushTCPingIntervalChanged:
		return true
	default:
		return false
	}
}

func currentTargets() []string {
	pushTCPingMu.RLock()
	defer pushTCPingMu.RUnlock()
	out := make([]string, len(pushTCPingTargets))
	copy(out, pushTCPingTargets)
	return out
}

func currentInterval() int {
	pushTCPingMu.RLock()
	defer pushTCPingMu.RUnlock()
	return pushTCPingIntervalSec
}

func TestApplyPushTCPingConfigSanitisesTargets(t *testing.T) {
	// Silence the "too many targets" warning emitted by the capping case.
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	t.Run("drops invalid and empty targets", func(t *testing.T) {
		resetPushTCPingState(t)
		applyPushTCPingConfig([]string{
			"good.example.com:443",
			"",
			"   ",
			strings.Repeat("a", 300) + ":80",
			"bad host:80",
			"example.com:0",
			"1.2.3.4:53",
		}, 0)

		got := currentTargets()
		want := []string{"good.example.com:443", "1.2.3.4:53"}
		if len(got) != len(want) {
			t.Fatalf("targets = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("targets = %v, want %v", got, want)
			}
		}
	})

	t.Run("de-duplicates targets", func(t *testing.T) {
		resetPushTCPingState(t)
		applyPushTCPingConfig([]string{
			"example.com:443",
			"example.com:443",
			" example.com:443 ", // same target after trimming
			"example.com",       // normalises to example.com:80, a different target
			"example.com:80",    // duplicate of the previous entry
		}, 0)

		got := currentTargets()
		if len(got) != 2 {
			t.Fatalf("targets = %v, want 2 unique entries", got)
		}
	})

	t.Run("caps the list at maxPushTCPingTargets", func(t *testing.T) {
		resetPushTCPingState(t)
		targets := make([]string, 0, maxPushTCPingTargets*2)
		for i := 0; i < maxPushTCPingTargets*2; i++ {
			targets = append(targets, fmt.Sprintf("host%d.example.com:80", i))
		}
		applyPushTCPingConfig(targets, 0)

		got := currentTargets()
		if len(got) != maxPushTCPingTargets {
			t.Fatalf("len(targets) = %d, want %d", len(got), maxPushTCPingTargets)
		}
		if got[0] != "host0.example.com:80" {
			t.Errorf("first target = %q, want the first entry the server sent", got[0])
		}
	})

	t.Run("empty config clears targets", func(t *testing.T) {
		resetPushTCPingState(t)
		applyPushTCPingConfig([]string{"example.com:80"}, 0)
		applyPushTCPingConfig(nil, 0)
		if got := currentTargets(); len(got) != 0 {
			t.Fatalf("targets = %v, want empty", got)
		}
	})

	t.Run("targets are stored as the server sent them", func(t *testing.T) {
		resetPushTCPingState(t)
		// A bare host must not be rewritten to host:80 on the wire, otherwise
		// the server can no longer match the reported result to its config.
		applyPushTCPingConfig([]string{"example.com"}, 0)
		got := currentTargets()
		if len(got) != 1 || got[0] != "example.com" {
			t.Fatalf("targets = %v, want [example.com]", got)
		}
	})
}

func TestApplyPushTCPingConfigClampsInterval(t *testing.T) {
	cases := []struct {
		name         string
		interval     int
		want         int
		wantSignal   bool
		startingFrom int
	}{
		{name: "in range", interval: 5, want: 5, wantSignal: true, startingFrom: 60},
		{name: "zero means unspecified", interval: 0, want: 60, wantSignal: false, startingFrom: 60},
		{name: "negative is ignored", interval: -7, want: 60, wantSignal: false, startingFrom: 60},
		{name: "minimum accepted", interval: 1, want: minPushTCPingIntervalSec, wantSignal: true, startingFrom: 60},
		{name: "above maximum is clamped", interval: 999999, want: maxPushTCPingIntervalSec, wantSignal: true, startingFrom: 60},
		{name: "maximum accepted", interval: maxPushTCPingIntervalSec, want: maxPushTCPingIntervalSec, wantSignal: true, startingFrom: 60},
		{name: "unchanged interval does not signal", interval: 60, want: 60, wantSignal: false, startingFrom: 60},
		{name: "clamped value equal to current does not signal", interval: 999999, want: maxPushTCPingIntervalSec, wantSignal: false, startingFrom: maxPushTCPingIntervalSec},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetPushTCPingState(t)
			pushTCPingMu.Lock()
			pushTCPingIntervalSec = tc.startingFrom
			pushTCPingMu.Unlock()

			applyPushTCPingConfig([]string{"example.com:80"}, tc.interval)

			if got := currentInterval(); got != tc.want {
				t.Errorf("interval = %d, want %d", got, tc.want)
			}
			if got := drainIntervalChanged(); got != tc.wantSignal {
				t.Errorf("interval-changed signal = %v, want %v", got, tc.wantSignal)
			}
		})
	}
}

func TestHandleTCPingRequestRequiresSecret(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	originalSecret := secret
	defer func() { secret = originalSecret }()

	t.Run("no secret configured is refused", func(t *testing.T) {
		secret = ""
		req := httptest.NewRequest(http.MethodPost, "/tcping", strings.NewReader(`{"target":"example.com:80"}`))
		rec := httptest.NewRecorder()
		handleTCPingRequest(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		if !strings.Contains(rec.Body.String(), "tcping disabled: no SECRET configured") {
			t.Fatalf("body = %q, want the disabled message", rec.Body.String())
		}
	})

	t.Run("wrong secret is rejected", func(t *testing.T) {
		secret = "s3cret"
		req := httptest.NewRequest(http.MethodPost, "/tcping", strings.NewReader(`{"target":"example.com:80"}`))
		req.Header.Set("Authorization", "Bearer nope")
		rec := httptest.NewRecorder()
		handleTCPingRequest(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid secret still validates the target", func(t *testing.T) {
		secret = "s3cret"
		req := httptest.NewRequest(http.MethodPost, "/tcping", strings.NewReader(`{"target":""}`))
		req.Header.Set("Authorization", "Bearer s3cret")
		rec := httptest.NewRecorder()
		handleTCPingRequest(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})
}

// ─── skipped-probe classification ───────────────────────────────────────

// ipv6Discard is an address in the RFC 3849 documentation prefix. It is
// guaranteed never to be routed on the public internet, so on a host without
// IPv6 connectivity a dial to it fails immediately with ENETUNREACH — exactly
// the condition classifyDialError exists to recognise.
const ipv6Discard = "[2001:db8::1]:80"

// fakeTimeoutError is a net.Error that times out and carries no syscall.Errno,
// mirroring what net.DialTimeout produces when the 3-second budget runs out.
type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

// dialErr rebuilds the error chain net.DialTimeout returns for a failed
// connect: *net.OpError → *os.SyscallError → syscall.Errno.
func dialErr(inner error) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
		Err:  os.NewSyscallError("connect", inner),
	}
}

func TestClassifyDialError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// The probe never left the box: no route, no address family, no
		// local source address.
		{"ENETUNREACH is skipped", dialErr(syscall.ENETUNREACH), true},
		{"EAFNOSUPPORT is skipped", dialErr(syscall.EAFNOSUPPORT), true},
		{"EADDRNOTAVAIL is skipped", dialErr(syscall.EADDRNOTAVAIL), true},
		// Still wrapped once more, the way executeTCPing returns it.
		{"wrapped by executeTCPing", fmt.Errorf("connection failed: %w", dialErr(syscall.ENETUNREACH)), true},

		// Real signals about a reachable network — these stay loss.
		{"ECONNREFUSED is loss", dialErr(syscall.ECONNREFUSED), false},
		{"EHOSTUNREACH is loss", dialErr(syscall.EHOSTUNREACH), false},
		{"EINVAL is loss", dialErr(syscall.EINVAL), false},
		{"timeout is loss", &net.OpError{Op: "dial", Net: "tcp", Err: fakeTimeoutError{}}, false},
		{"bare timeout is loss", fakeTimeoutError{}, false},
		{"DNS failure is loss", &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}, false},
		{"opaque error is loss", errors.New("something else went wrong"), false},

		// Success.
		{"nil is not skipped", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDialError(tc.err); got != tc.want {
				t.Errorf("classifyDialError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// liveIPv6DialError dials the documentation prefix and returns the error, or
// skips the test when this host's behaviour makes the assertion meaningless
// (IPv6 is available, or the failure is something other than ENETUNREACH).
func liveIPv6DialError(t *testing.T) error {
	t.Helper()

	start := time.Now()
	_, err := executeTCPing(ipv6Discard)
	if err == nil {
		t.Skipf("dial to %s unexpectedly succeeded; nothing to assert", ipv6Discard)
	}

	var errno syscall.Errno
	if !errors.As(err, &errno) {
		t.Skipf("host has IPv6 connectivity or a non-errno failure after %v (%v); nothing to assert", time.Since(start).Round(time.Millisecond), err)
	}
	if !isUnattemptableErrno(errno) {
		t.Skipf("host reported errno %d (%v) rather than ENETUNREACH; nothing to assert", uintptr(errno), err)
	}
	return err
}

// TestClassifyDialErrorLiveIPv6 checks the real error chain the local network
// stack produces, not just a synthetic one — the wrapping layers are exactly
// what a refactor is most likely to break.
func TestClassifyDialErrorLiveIPv6(t *testing.T) {
	err := liveIPv6DialError(t)
	if !classifyDialError(err) {
		t.Fatalf("classifyDialError(%v) = false, want true for an unreachable-network dial", err)
	}
}

// TestHandleTCPingRequestReportsSkipped covers the pull-mode wire contract: a
// probe this host cannot attempt answers HTTP 200 with success:false and
// skipped:true, so the server records no data point instead of packet loss.
func TestHandleTCPingRequestReportsSkipped(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	liveIPv6DialError(t) // skips the test unless this host really lacks IPv6

	originalSecret := secret
	defer func() { secret = originalSecret }()
	secret = "s3cret"

	body := fmt.Sprintf(`{"target":%q}`, ipv6Discard)
	req := httptest.NewRequest(http.MethodPost, "/tcping", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	handleTCPingRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"skipped":true`) {
		t.Errorf("body = %q, want it to contain \"skipped\":true", rec.Body.String())
	}

	var resp TCPingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !resp.Skipped {
		t.Errorf("Skipped = false, want true")
	}
	if resp.Success {
		t.Errorf("Success = true, want false")
	}
	if resp.Latency != 0 {
		t.Errorf("Latency = %v, want 0", resp.Latency)
	}
	if resp.Error == "" {
		t.Errorf("Error = %q, want a human-readable message", resp.Error)
	}
}

// TestHandleTCPingRequestOmitsSkippedForOrdinaryFailure pins the other half of
// the contract: a normal failure must look exactly as it did before this
// change, i.e. no "skipped" key at all.
func TestHandleTCPingRequestOmitsSkippedForOrdinaryFailure(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	// A listener that is closed immediately gives a deterministic
	// connection-refused on a port nothing else is using.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open a loopback listener: %v", err)
	}
	target := ln.Addr().String()
	ln.Close()

	originalSecret := secret
	defer func() { secret = originalSecret }()
	secret = "s3cret"

	body := fmt.Sprintf(`{"target":%q}`, target)
	req := httptest.NewRequest(http.MethodPost, "/tcping", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	handleTCPingRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(rec.Body.String(), "skipped") {
		t.Errorf("body = %q, want no \"skipped\" key for an ordinary failure", rec.Body.String())
	}
}

// TestMeasureTCPingOnceMarksSkipped covers the push-mode wire contract: the
// queued result carries skipped:true with latency 0 and success:false.
func TestMeasureTCPingOnceMarksSkipped(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	liveIPv6DialError(t) // skips the test unless this host really lacks IPv6

	pendingTCPingResultsMu.Lock()
	saved := pendingTCPingResults
	pendingTCPingResults = nil
	pendingTCPingResultsMu.Unlock()
	defer func() {
		pendingTCPingResultsMu.Lock()
		pendingTCPingResults = saved
		pendingTCPingResultsMu.Unlock()
	}()

	measureTCPingOnce([]string{ipv6Discard})

	pendingTCPingResultsMu.Lock()
	got := append([]ClientTCPingResult(nil), pendingTCPingResults...)
	pendingTCPingResultsMu.Unlock()

	if len(got) != 1 {
		t.Fatalf("queued %d results, want 1", len(got))
	}
	if !got[0].Skipped || got[0].Success || got[0].Latency != 0 {
		t.Errorf("result = %+v, want skipped:true success:false latency:0", got[0])
	}
	if got[0].Target != ipv6Discard {
		t.Errorf("Target = %q, want %q", got[0].Target, ipv6Discard)
	}
	if got[0].MeasuredAt.IsZero() {
		t.Errorf("MeasuredAt is zero, want the measurement time")
	}

	encoded, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshalling result: %v", err)
	}
	if !strings.Contains(string(encoded), `"skipped":true`) {
		t.Errorf("payload = %s, want it to contain \"skipped\":true", encoded)
	}
}

// ─── log throttling ─────────────────────────────────────────────────────

// resetLogThrottle empties the per-message throttle map so each test starts
// from a known state.
func resetLogThrottle() {
	logThrottleMutex.Lock()
	logThrottleTimes = make(map[string]time.Time)
	logThrottleMutex.Unlock()
}

// captureLog redirects the standard logger into a buffer for the duration of
// the test and strips the timestamp prefix so assertions can match on content.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return &buf
}

// TestLogOncePerMinuteThrottlesPerMessage is the regression test for a shared
// throttle timestamp. With one timestamp for all messages, the first message
// logged in a minute silenced every other one: the per-target "TCPing skipped"
// notice fires on every cycle, so the "no SECRET configured" security warning
// was never printed at all.
func TestLogOncePerMinuteThrottlesPerMessage(t *testing.T) {
	buf := captureLog(t)
	resetLogThrottle()
	t.Cleanup(resetLogThrottle)

	const chatty = "TCPing target example.com:80 skipped"
	const warning = "SECURITY WARNING: /metrics is unauthenticated"

	logOncePerMinute(chatty)
	logOncePerMinute(chatty)
	logOncePerMinute(chatty)
	logOncePerMinute(warning)
	logOncePerMinute(warning)

	out := buf.String()
	if got := strings.Count(out, chatty); got != 1 {
		t.Errorf("chatty message logged %d times, want 1; log was:\n%s", got, out)
	}
	if got := strings.Count(out, warning); got != 1 {
		t.Errorf("security warning logged %d times, want 1; log was:\n%s", got, out)
	}
}

// TestLogOncePerMinuteLogsAgainAfterInterval checks the throttle releases: an
// entry older than logThrottleInterval must not keep suppressing its message.
func TestLogOncePerMinuteLogsAgainAfterInterval(t *testing.T) {
	buf := captureLog(t)
	resetLogThrottle()
	t.Cleanup(resetLogThrottle)

	const msg = "disk probe timed out"
	logOncePerMinute(msg)

	// Back-date the entry instead of waiting a real minute.
	logThrottleMutex.Lock()
	logThrottleTimes[msg] = time.Now().Add(-2 * logThrottleInterval)
	logThrottleMutex.Unlock()

	logOncePerMinute(msg)

	if got := strings.Count(buf.String(), msg); got != 2 {
		t.Errorf("message logged %d times across two throttle windows, want 2", got)
	}
}

// TestLogOncePerMinutePrunesStaleEntries checks the map stays bounded. Messages
// are built from server-supplied TCPing target names, so an unpruned map would
// grow with every distinct target the server ever sends.
func TestLogOncePerMinutePrunesStaleEntries(t *testing.T) {
	captureLog(t)
	resetLogThrottle()
	t.Cleanup(resetLogThrottle)

	stale := time.Now().Add(-2 * logThrottleRetention)
	logThrottleMutex.Lock()
	for i := 0; i <= logThrottleMaxEntries; i++ {
		logThrottleTimes[fmt.Sprintf("stale message %d", i)] = stale
	}
	fresh := time.Now()
	logThrottleTimes["recent message"] = fresh
	logThrottleMutex.Unlock()

	logOncePerMinute("a new message that trips the prune")

	logThrottleMutex.Lock()
	size := len(logThrottleTimes)
	_, keptRecent := logThrottleTimes["recent message"]
	_, keptStale := logThrottleTimes["stale message 0"]
	logThrottleMutex.Unlock()

	if keptStale {
		t.Errorf("a stale entry survived the prune")
	}
	if !keptRecent {
		t.Errorf("a recent entry was pruned; only entries older than logThrottleRetention may go")
	}
	if size != 2 { // "recent message" + the message just logged
		t.Errorf("map size after prune = %d, want 2", size)
	}
}

// ─── single-flight public IP refresh ────────────────────────────────────

// TestGetIPAddressesRefreshesOnlyOnceAtATime is the regression test for the
// refresh stampede. Every caller that finds the 60 s cache stale used to launch
// its own detectIPAddresses goroutine — a dozen outbound requests each, taking
// seconds — so the push loop (every 3 s) plus /metrics (unauthenticated when
// SECRET is unset, one call per request) could multiply into a request flood.
func TestGetIPAddressesRefreshesOnlyOnceAtATime(t *testing.T) {
	const (
		cachedV4  = "198.51.100.7"
		cachedV6  = "2001:db8::7"
		refreshV4 = "203.0.113.9"
		refreshV6 = "2001:db8::9"
	)

	origDetect := detectIPAddressesFn
	ipCacheMutex.Lock()
	origV4, origV6 := ipv4Cache, ipv6Cache
	origCacheTime, origDetectedAt := ipCacheTime, ipDetectedAt
	ipCacheMutex.Unlock()
	t.Cleanup(func() {
		detectIPAddressesFn = origDetect
		ipCacheMutex.Lock()
		ipv4Cache, ipv6Cache = origV4, origV6
		ipCacheTime, ipDetectedAt = origCacheTime, origDetectedAt
		ipRefreshInFlight = false
		ipCacheMutex.Unlock()
	})

	var detections int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	detectIPAddressesFn = func() (string, string) {
		if atomic.AddInt32(&detections, 1) == 1 {
			started <- struct{}{}
		}
		<-release // hold the refresh open while the callers pile up
		return refreshV4, refreshV6
	}

	// Prime a stale-but-warm cache: a non-zero timestamp keeps us off the
	// blocking cold-start path, and a timestamp older than the TTL is what
	// makes every caller want a refresh.
	ipCacheMutex.Lock()
	ipv4Cache, ipv6Cache = cachedV4, cachedV6
	ipCacheTime = time.Now().Add(-2 * ipCacheTTL)
	ipDetectedAt = ipCacheTime
	ipRefreshInFlight = false
	ipCacheMutex.Unlock()

	const callers = 50
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Callers must never block on the refresh: the cached values come
			// back immediately.
			if v4, v6 := getIPAddresses(); v4 != cachedV4 || v6 != cachedV6 {
				t.Errorf("getIPAddresses() = (%q, %q) while a refresh is in flight, want the cached (%q, %q)", v4, v6, cachedV4, cachedV6)
			}
		}()
	}
	wg.Wait()

	<-started // the winning caller's goroutine is running
	if got := atomic.LoadInt32(&detections); got != 1 {
		t.Fatalf("detector ran %d times for %d stale-cache callers, want exactly 1", got, callers)
	}

	close(release)

	// The refresh must land, and clear the in-flight flag so later refreshes
	// are not blocked forever.
	deadline := time.Now().Add(10 * time.Second)
	for {
		ipCacheMutex.RLock()
		inFlight := ipRefreshInFlight
		gotV4, gotV6 := ipv4Cache, ipv6Cache
		ipCacheMutex.RUnlock()
		if !inFlight {
			if gotV4 != refreshV4 || gotV6 != refreshV6 {
				t.Fatalf("cache after refresh = (%q, %q), want (%q, %q)", gotV4, gotV6, refreshV4, refreshV6)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh never completed or never cleared ipRefreshInFlight")
		}
		time.Sleep(2 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&detections); got != 1 {
		t.Errorf("detector ran %d times in total, want exactly 1", got)
	}
}

// ─── /metrics snapshot reuse ────────────────────────────────────────────

// saveMetricsSnapshot stashes and restores the push-loop snapshot globals.
func saveMetricsSnapshot(t *testing.T) {
	t.Helper()
	lastPushedMetricsMu.Lock()
	m, ts := lastPushedMetrics, lastPushedMetricsTime
	lastPushedMetricsMu.Unlock()
	t.Cleanup(func() {
		lastPushedMetricsMu.Lock()
		lastPushedMetrics, lastPushedMetricsTime = m, ts
		lastPushedMetricsMu.Unlock()
	})
}

// samplerState reads the CPU and network delta-sampler timestamps. A fresh
// collection rebases both; serving a snapshot must leave them alone.
func samplerState() (time.Time, time.Time) {
	cpuStatsMutex.Lock()
	cpuAt := lastCPUStatsTime
	cpuStatsMutex.Unlock()
	netStatsMutex.Lock()
	netAt := lastNetStatsTime
	netStatsMutex.Unlock()
	return cpuAt, netAt
}

// TestHandleMetricsRequestServesPushSnapshot is the regression test for
// /metrics and the push loop sharing the delta samplers. getCPUUsage and
// getNetworkStats report the change since their last reading; collecting on the
// /metrics path consumed the interval the push loop was about to report, so a
// poller could flatten every CPU and traffic figure the server recorded.
func TestHandleMetricsRequestServesPushSnapshot(t *testing.T) {
	captureLog(t)
	saveMetricsSnapshot(t)

	originalSecret := secret
	t.Cleanup(func() { secret = originalSecret })
	secret = "" // the unauthenticated path, which is the one that gets polled

	want := metricPayload{
		ID:           "snapshot-agent",
		Name:         "snapshot",
		CPU:          42.5,
		Memory:       17.25,
		NetInMBps:    1.5,
		NetOutMBps:   2.5,
		AgentVersion: "1.3.26",
	}
	storeMetricsSnapshot(want)

	cpuBefore, netBefore := samplerState()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handleMetricsRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got metricPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.ID != want.ID || got.CPU != want.CPU || got.NetInMBps != want.NetInMBps || got.NetOutMBps != want.NetOutMBps {
		t.Errorf("payload = %+v, want the push loop's snapshot %+v", got, want)
	}

	cpuAfter, netAfter := samplerState()
	if !cpuAfter.Equal(cpuBefore) {
		t.Errorf("CPU sampler was rebased by a /metrics request (%v → %v)", cpuBefore, cpuAfter)
	}
	if !netAfter.Equal(netBefore) {
		t.Errorf("network sampler was rebased by a /metrics request (%v → %v)", netBefore, netAfter)
	}
}

// TestRecentMetricsSnapshotFreshness pins the age window. The fallback (a fresh
// collection) has to cover the startup gap before the first push and any build
// with no push loop at all, so a stale snapshot must be rejected.
func TestRecentMetricsSnapshotFreshness(t *testing.T) {
	saveMetricsSnapshot(t)

	t.Run("no snapshot yet", func(t *testing.T) {
		lastPushedMetricsMu.Lock()
		lastPushedMetrics = metricPayload{}
		lastPushedMetricsTime = time.Time{}
		lastPushedMetricsMu.Unlock()

		if _, ok := recentMetricsSnapshot(); ok {
			t.Error("recentMetricsSnapshot() = ok before any push collected metrics")
		}
	})

	t.Run("fresh snapshot is served", func(t *testing.T) {
		storeMetricsSnapshot(metricPayload{ID: "fresh"})
		got, ok := recentMetricsSnapshot()
		if !ok {
			t.Fatal("recentMetricsSnapshot() = !ok for a just-stored snapshot")
		}
		if got.ID != "fresh" {
			t.Errorf("ID = %q, want %q", got.ID, "fresh")
		}
	})

	t.Run("stale snapshot is rejected", func(t *testing.T) {
		lastPushedMetricsMu.Lock()
		lastPushedMetrics = metricPayload{ID: "stale"}
		lastPushedMetricsTime = time.Now().Add(-metricsSnapshotMaxAge - time.Second)
		lastPushedMetricsMu.Unlock()

		if _, ok := recentMetricsSnapshot(); ok {
			t.Errorf("recentMetricsSnapshot() = ok for a snapshot older than %v", metricsSnapshotMaxAge)
		}
	})
}

// ─── external command timeouts ──────────────────────────────────────────

// TestRunCommandOutputTimesOut is the regression test for unbounded
// exec.Command calls. `df` on a dead NFS mount is the real case: it runs on the
// push path and used to be able to wedge metric collection forever.
func TestRunCommandOutputTimesOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no sleep(1) on windows")
	}
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skipf("sleep not available: %v", err)
	}

	start := time.Now()
	out, err := runCommandOutput(200*time.Millisecond, "sleep", "5")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("runCommandOutput returned nil error after %v, want a timeout failure", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("runCommandOutput blocked for %v with a 200ms budget; the deadline is not being enforced", elapsed)
	}
	if len(out) != 0 {
		t.Errorf("output = %q, want empty for a killed command", out)
	}
}

// TestRunCommandOutputReturnsOutput is the positive control: the helper must
// still behave like exec.Command().Output() for a command that finishes.
func TestRunCommandOutputReturnsOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no echo(1) on windows")
	}
	out, err := runCommandOutput(5*time.Second, "echo", "pulse")
	if err != nil {
		t.Fatalf("runCommandOutput(echo) returned %v", err)
	}
	if strings.TrimSpace(string(out)) != "pulse" {
		t.Errorf("output = %q, want %q", out, "pulse")
	}
}

// TestRunCommandOutputMissingBinary pins the degradation shape every call site
// relies on: a missing probe is an error, never a hang, so callers fall back to
// their cached value exactly as before.
func TestRunCommandOutputMissingBinary(t *testing.T) {
	if _, err := runCommandOutput(time.Second, "pulse-no-such-command-exists"); err == nil {
		t.Error("runCommandOutput returned nil error for a missing binary")
	}
}

// ─── TCPing cadence ─────────────────────────────────────────────────────

// TestTCPingWaitDuration covers the cadence maths. The wait used to start when
// the measurement finished, making the real period interval+measurement: with a
// 5 s interval and targets that time out after 3 s, points landed 8 s apart.
func TestTCPingWaitDuration(t *testing.T) {
	cases := []struct {
		name     string
		interval int
		elapsed  time.Duration
		want     time.Duration
	}{
		{"instant measurement waits the full interval", 60, 0, 60 * time.Second},
		{"measurement time is subtracted", 60, 5 * time.Second, 55 * time.Second},
		{"short interval, slow targets", 5, 3 * time.Second, 2 * time.Second},
		{"measurement exactly fills the interval", 5, 5 * time.Second, 0},
		{"overrun never waits a negative time", 5, 9 * time.Second, 0},
		{"sub-second precision is kept", 10, 1500 * time.Millisecond, 8500 * time.Millisecond},
		{"zero interval", 0, 0, 0},
		{"negative interval is treated as zero", -7, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcpingWaitDuration(tc.interval, tc.elapsed); got != tc.want {
				t.Errorf("tcpingWaitDuration(%d, %v) = %v, want %v", tc.interval, tc.elapsed, got, tc.want)
			}
		})
	}
}

// TestTCPingWaitDurationKeepsPeriod states the property the comment block
// promises: consecutive points land `interval` apart start-to-start, whatever
// the measurement costs, until the measurement outruns the interval itself.
func TestTCPingWaitDurationKeepsPeriod(t *testing.T) {
	for _, interval := range []int{1, 5, 30, 60, 300} {
		for _, measure := range []time.Duration{0, 250 * time.Millisecond, time.Second, 3 * time.Second} {
			period := measure + tcpingWaitDuration(interval, measure)
			want := time.Duration(interval) * time.Second
			if measure > want {
				want = measure // overrun: the next cycle starts immediately
			}
			if period != want {
				t.Errorf("interval=%ds measurement=%v: period = %v, want %v", interval, measure, period, want)
			}
		}
	}
}

// ─── private address classification ─────────────────────────────────────

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// The reason this test exists: a CGNAT address is not reachable from
		// the internet, so reporting one as the machine's public IP is as
		// wrong as reporting a 10.x address.
		{"100.64.0.1", true},      // RFC 6598 CGNAT, first usable
		{"100.127.255.255", true}, // RFC 6598 CGNAT, last
		{"100.63.255.255", false}, // just below the CGNAT block
		{"100.128.0.1", false},    // just above the CGNAT block

		{"127.0.0.1", true},    // loopback
		{"10.1.2.3", true},     // RFC 1918
		{"172.16.0.1", true},   // RFC 1918
		{"172.32.0.1", false},  // outside 172.16.0.0/12
		{"192.168.1.1", true},  // RFC 1918
		{"169.254.10.1", true}, // link-local
		{"224.0.0.1", true},    // multicast
		{"8.8.8.8", false},     // public
		{"1.1.1.1", false},     // public

		{"::1", true},                   // IPv6 loopback
		{"fe80::1", true},               // IPv6 link-local, fe80::/10
		{"febf::1", true},               // last of fe80::/10
		{"fd00::1", true},               // IPv6 unique-local, fc00::/7
		{"fc00::1", true},               // fc00::/7
		{"ff02::1", true},               // IPv6 multicast
		{"2001:4860:4860::8888", false}, // public IPv6
		{"2606:4700:4700::1111", false}, // public IPv6

		{"::ffff:10.0.0.1", true},   // IPv4-mapped private
		{"::ffff:127.0.0.1", true},  // IPv4-mapped loopback
		{"::ffff:100.64.0.1", true}, // IPv4-mapped CGNAT
		{"::ffff:8.8.8.8", false},   // IPv4-mapped public
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			ip := net.ParseIP(tc.in)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil; bad test input", tc.in)
			}
			if got := isPrivateIP(ip); got != tc.want {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	t.Run("nil is private", func(t *testing.T) {
		if !isPrivateIP(nil) {
			t.Error("isPrivateIP(nil) = false, want true")
		}
	})

	t.Run("malformed address does not panic", func(t *testing.T) {
		if !isPrivateIP(net.IP{1, 2, 3}) {
			t.Error("isPrivateIP(malformed) = false, want true")
		}
	})
}

// TestPublicIPAcceptors checks the predicates the IP-echo race uses to decide
// whether a reply is usable, including that a CGNAT reply is rejected.
func TestPublicIPAcceptors(t *testing.T) {
	if !isPublicIPv4(net.ParseIP("203.0.113.5")) {
		t.Error("isPublicIPv4(203.0.113.5) = false, want true")
	}
	if isPublicIPv4(net.ParseIP("100.64.0.1")) {
		t.Error("isPublicIPv4(100.64.0.1) = true, want false (CGNAT)")
	}
	if isPublicIPv4(net.ParseIP("2001:db8::1")) {
		t.Error("isPublicIPv4(2001:db8::1) = true, want false (not IPv4)")
	}
	if !isPublicIPv6(net.ParseIP("2001:4860:4860::8888")) {
		t.Error("isPublicIPv6(2001:4860:4860::8888) = false, want true")
	}
	if isPublicIPv6(net.ParseIP("fd00::1")) {
		t.Error("isPublicIPv6(fd00::1) = true, want false (unique-local)")
	}
	if isPublicIPv6(net.ParseIP("8.8.8.8")) {
		t.Error("isPublicIPv6(8.8.8.8) = true, want false (not IPv6)")
	}
}

// TestRaceIPEchoServicesPrefersHTTPS covers the phase split directly: a
// plaintext service that answers instantly must not beat an HTTPS service, so
// the HTTPS answer wins even when the HTTP one is faster.
func TestRaceIPEchoServicesPrefersHTTPS(t *testing.T) {
	const httpsAnswer = "203.0.113.10"
	const httpAnswer = "198.51.100.20"

	httpsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately slower than the plaintext impostor below.
		time.Sleep(150 * time.Millisecond)
		fmt.Fprintln(w, httpsAnswer)
	}))
	defer httpsSrv.Close()

	// An on-path attacker's forged plaintext reply: instant, and wrong.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, httpAnswer)
	}))
	defer httpSrv.Close()

	// httptest serves plain HTTP; racePublicIP's phase order is what is under
	// test here, not TLS itself, so the "HTTPS" list is simply the first phase.
	if got := racePublicIP([]string{httpsSrv.URL}, []string{httpSrv.URL}, isPublicIPv4); got != httpsAnswer {
		t.Errorf("racePublicIP = %q, want the first-phase answer %q (a faster plaintext reply must not win)", got, httpsAnswer)
	}

	// When the first phase yields nothing, the fallback is still used.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer failing.Close()

	if got := racePublicIP([]string{failing.URL}, []string{httpSrv.URL}, isPublicIPv4); got != httpAnswer {
		t.Errorf("racePublicIP = %q, want the fallback answer %q when every first-phase service fails", got, httpAnswer)
	}
}

// TestRaceIPEchoServicesEmptyList pins the no-fallback case getPublicIPv6 uses:
// an empty service list returns immediately rather than burning its budget.
func TestRaceIPEchoServicesEmptyList(t *testing.T) {
	start := time.Now()
	if got := raceIPEchoServices(nil, 5*time.Second, isPublicIPv4); got != "" {
		t.Errorf("raceIPEchoServices(nil) = %q, want \"\"", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("raceIPEchoServices(nil) took %v, want an immediate return", elapsed)
	}
}

// ─── install script ─────────────────────────────────────────────────────

// bashOrSkip returns the path to bash, or skips the test.
func bashOrSkip(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash not available: %v", err)
	}
	return path
}

// TestInstallScriptParses runs `bash -n install.sh`. The installer is shipped
// by curl-to-shell, so a syntax error reaches users as a half-installed agent.
func TestInstallScriptParses(t *testing.T) {
	bash := bashOrSkip(t)
	if _, err := os.Stat("install.sh"); err != nil {
		t.Skipf("install.sh not present: %v", err)
	}
	if out, err := exec.Command(bash, "-n", "install.sh").CombinedOutput(); err != nil {
		t.Fatalf("bash -n install.sh failed: %v\n%s", err, out)
	}
}

// TestGeneratedUpdateScriptParses extracts the update.sh that install.sh writes
// out and syntax-checks that too — it is generated from a quoted heredoc, so
// nothing else would catch a syntax error in it before it lands on a machine.
func TestGeneratedUpdateScriptParses(t *testing.T) {
	bash := bashOrSkip(t)

	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Skipf("install.sh not readable: %v", err)
	}
	const open = "<< 'UPDATEEOF'\n"
	start := strings.Index(string(raw), open)
	if start < 0 {
		t.Fatal("install.sh no longer contains the UPDATEEOF heredoc that generates update.sh")
	}
	body := string(raw)[start+len(open):]
	end := strings.Index(body, "\nUPDATEEOF\n")
	if end < 0 {
		t.Fatal("unterminated UPDATEEOF heredoc in install.sh")
	}
	body = body[:end]

	path := filepath.Join(t.TempDir(), "update.sh")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing extracted update.sh: %v", err)
	}
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n on the generated update.sh failed: %v\n%s", err, out)
	}

	// The download must be fail-fast: without curl -f an HTTP error page is
	// written out and chmod +x'd as if it were the new agent.
	if !strings.Contains(body, "curl -fsSL") {
		t.Error("generated update.sh does not use `curl -f`; an HTTP error body would be installed as the binary")
	}
	if !strings.Contains(body, "validate_binary \"$TEMP_BINARY\"") {
		t.Error("generated update.sh does not validate the downloaded binary")
	}
}

// TestInstallScriptDownloadIsValidated pins the installer-side fixes: download
// to a temp file, validate it, then move it into place. Writing straight onto a
// running binary also fails with ETXTBSY, which is exactly the re-install case.
func TestInstallScriptDownloadIsValidated(t *testing.T) {
	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Skipf("install.sh not readable: %v", err)
	}
	script := string(raw)

	for _, want := range []string{
		"curl -fsSL --proto '=https' --connect-timeout 15 --max-time 300",
		"--tries=3 --timeout=120",
		`if ! validate_binary "$tmp_binary"; then`,
		`mv -f "$tmp_binary" "$INSTALL_DIR/probe-client"`,
		"umask 077",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.sh is missing %q", want)
		}
	}

	if strings.Contains(script, `curl -sSL --proto '=https' "$download_url"`) {
		t.Error("install.sh still downloads the binary without curl -f")
	}
}

// TestRaceIPEchoServicesFailsFast checks a phase in which every service fails
// returns as soon as they have all failed, instead of sitting out its whole
// budget. The HTTPS phase inherits the remainder of the overall budget to the
// plaintext fallback, so burning the budget on fast failures would leave the
// fallback with only its minimum.
func TestRaceIPEchoServicesFailsFast(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer failing.Close()

	start := time.Now()
	got := raceIPEchoServices([]string{failing.URL, failing.URL, failing.URL}, 6*time.Second, isPublicIPv4)
	elapsed := time.Since(start)

	if got != "" {
		t.Errorf("raceIPEchoServices = %q, want \"\" when every service fails", got)
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v to conclude every service had failed; the budget is being burned instead of returning early", elapsed)
	}
}
