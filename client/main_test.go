package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
