package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	log.SetOutput(ioutil.Discard)
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
	log.SetOutput(ioutil.Discard)
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
	log.SetOutput(ioutil.Discard)
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
	log.SetOutput(ioutil.Discard)
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
	log.SetOutput(ioutil.Discard)
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
