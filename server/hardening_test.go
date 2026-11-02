package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A push whose write fails is answered 500 and re-sent unchanged by the agent;
// the retry must be stored, not taken for a duplicate of a delivered batch.
func TestFailedPushIsStoredOnIdenticalRetry(t *testing.T) {
	resetTCPingCacheForTest(t)
	path := filepath.Join(t.TempDir(), "metrics.db")
	st, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatal(err)
	}
	if err := st.Upsert(SystemMetric{ID: "retry-agent", Name: "Agent"}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	now := time.Now().UTC()
	samples := []map[string]interface{}{
		{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": now.Add(-62 * time.Second).Format(time.RFC3339Nano)},
		{"target": "1.1.1.1:443", "latency": 11, "success": true, "measured_at": now.Add(-2 * time.Second).Format(time.RFC3339Nano)},
	}
	push := func(store *Store) int {
		data, _ := json.Marshal(map[string]interface{}{"id": "retry-agent", "name": "x", "uptime": 5, "location": "US", "tcping_results": samples})
		req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
		rr := httptest.NewRecorder()
		handleClientPush(store, NewClientRegistry(), NewIPCountryCache(), rr, req)
		return rr.Code
	}

	// A read-only handle stands in for a failing disk.
	ro, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if code := push(&Store{db: ro}); code != http.StatusInternalServerError {
		t.Fatalf("write on a read-only store: HTTP %d, want 500", code)
	}
	ro.Close()

	st, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if code := push(st); code != http.StatusOK {
		t.Fatalf("retry: HTTP %d, want 200", code)
	}
	res, err := st.GetTCPingResults("retry-agent", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("the retried batch must be stored: %d of 2 samples", len(res))
	}
}

// The server polls the addresses an agent registers. Unspecified, loopback,
// private and link-local addresses never become a poll URL, for IPv6 as well
// as IPv4 ("::" and "0.0.0.0" reach the server's own loopback).
func TestRegisterIgnoresLocalAddresses(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "reg", Name: "Reg", Secret: "fleet-secret"}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip, ipv6     string
		want4, want6 bool
	}{
		{"0.0.0.0", "::", false, false},
		{"0.1.2.3", "::1", false, false},
		{"10.1.2.3", "fd00::1", false, false},
		{"192.168.1.5", "fe80::1", false, false},
		{"203.0.113.9", "2001:db8::9", true, true},
	}
	for _, c := range cases {
		registry := NewClientRegistry()
		body, _ := json.Marshal(map[string]string{"id": "reg", "port": "9090", "ip": c.ip, "ipv6": c.ipv6, "secret": "fleet-secret"})
		req := httptest.NewRequest(http.MethodPost, "/api/clients/register", bytes.NewReader(body))
		req.RemoteAddr = "10.9.9.9:5555" // a private source: nothing is derived from it
		rr := httptest.NewRecorder()
		handleClientRegister(store, registry, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("register %s / %s: HTTP %d %s", c.ip, c.ipv6, rr.Code, rr.Body.String())
		}
		got := registry.Get("reg")
		if got == nil {
			t.Fatalf("register %s / %s: no registry entry", c.ip, c.ipv6)
		}
		if (got.URL != "") != c.want4 || (got.URL6 != "") != c.want6 {
			t.Errorf("register %s / %s: URL=%q URL6=%q", c.ip, c.ipv6, got.URL, got.URL6)
		}
	}
}

// interval_secs is bounded like the agent's: a huge value is refused, and one
// already stored is read back clamped, so the pollers' tickers never panic.
func TestTCPingIntervalIsBounded(t *testing.T) {
	store := newTestStore(t)
	withAdminToken(t, "interval-admin")
	req := httptest.NewRequest(http.MethodPost, "/api/tcping/config", bytes.NewReader([]byte(`{"targets":[{"name":"cf","address":"1.1.1.1:443"}],"interval_secs":10000000000}`)))
	req.Header.Set("Authorization", "Bearer interval-admin")
	rr := httptest.NewRecorder()
	handleSetTCPingConfig(store, nil, NewClientRegistry(), rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("interval_secs 1e10: HTTP %d, want 400", rr.Code)
	}

	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 10000000000}); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.GetTCPingConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IntervalSecs != maxTCPingIntervalSecs {
		t.Fatalf("stored interval read back as %d, want %d", cfg.IntervalSecs, maxTCPingIntervalSecs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	startTCPingPolling(ctx, NewClientRegistry(), store) // panicked with a negative ticker interval
}

// A push that lands after the admin deleted its system writes nothing: no
// record and no history rows.
func TestPushForDeletedSystemWritesNoHistory(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	latency := 10.0
	err := store.SaveClientPushBatch(SystemMetric{ID: "gone", Name: "Gone", UpdatedAt: now}, []TCPingResult{
		{ClientID: "gone", Target: "1.1.1.1:443", Latency: &latency, Timestamp: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sys, _ := store.Get("gone"); sys != nil {
		t.Fatal("a push must not create a system")
	}
	res, err := store.GetTCPingResults("gone")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("a deleted system's push stored %d history rows", len(res))
	}
}

// Login and token-check limits count an IPv6 /64 as one client: addresses
// inside it share the lockout, IPv4 addresses are counted one by one.
func TestRateLimitKeyGroupsIPv6Prefix(t *testing.T) {
	a, b, c := rateLimitKey("2001:db8:1:2:aaaa::1"), rateLimitKey("2001:db8:1:2:bbbb::9"), rateLimitKey("2001:db8:1:3::1")
	if a != b || a == c {
		t.Fatalf("IPv6 keys: %q %q %q", a, b, c)
	}
	if rateLimitKey("203.0.113.7") != "203.0.113.7" || rateLimitKey("203.0.113.7") == rateLimitKey("203.0.113.8") {
		t.Fatal("IPv4 addresses must be counted individually")
	}

	store := newTestStore(t)
	if err := store.SetPassword("right-password"); err != nil {
		t.Fatal(err)
	}
	login := func(remote, password string) int {
		req := jsonRequest(http.MethodPost, "/api/auth/login", remote, map[string]string{"password": password})
		rr := httptest.NewRecorder()
		handleAuthLogin(store, rr, req)
		return rr.Code
	}
	loginAttemptsMu.Lock()
	delete(loginAttempts, rateLimitKey("2001:db8:77:1::1"))
	loginAttemptsMu.Unlock()
	for i := 1; i <= 5; i++ {
		remote := "[2001:db8:77:1::" + string(rune('0'+i)) + "]:4000"
		if code := login(remote, "wrong-password"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: HTTP %d", i, code)
		}
	}
	if code := login("[2001:db8:77:1:ffff::1]:4000", "right-password"); code != http.StatusUnauthorized {
		t.Fatalf("another address in a locked /64 logged in: HTTP %d", code)
	}
	if code := login("[2001:db8:77:2::1]:4000", "right-password"); code != http.StatusOK {
		t.Fatalf("a different /64 must not be locked: HTTP %d", code)
	}
}

// A backup download that stops moving ends instead of holding the
// snapshot's read transaction open.
func TestStalledBackupReleasesItsTransaction(t *testing.T) {
	store := newTestStore(t)
	// Some 24 MB of data, more than the socket buffers can absorb.
	blob := bytes.Repeat([]byte("x"), 1<<20)
	if err := store.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("stall-test-padding"))
		if err != nil {
			return err
		}
		for i := 0; i < 24; i++ {
			if err := b.Put([]byte{byte(i)}, blob); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	withAdminToken(t, "backup-admin")
	prev := backupStallTimeout
	backupStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { backupStallTimeout = prev })

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		handleAdminBackup(store, w, r)
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Ask for the backup, then never read the answer.
	fmt.Fprintf(conn, "GET /api/admin/backup HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer backup-admin\r\n\r\n")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the backup handler was still writing to a client that stopped reading")
	}
	if open := store.db.Stats().OpenTxN; open != 0 {
		t.Fatalf("%d read transaction(s) still open after the stalled download ended", open)
	}
}
