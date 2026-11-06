package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func postNavbar(t *testing.T, store *Store, cfg NavbarConfig) {
	t.Helper()
	authTokensMu.Lock()
	authTokens["test-admin-token"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() { authTokensMu.Lock(); delete(authTokens, "test-admin-token"); authTokensMu.Unlock() })
	rr := httptest.NewRecorder()
	handleSetNavbarConfig(store, rr, adminRequest(t, http.MethodPost, "/api/navbar/config", cfg))
	if rr.Code != http.StatusOK {
		t.Fatalf("save navbar: %d %s", rr.Code, rr.Body.String())
	}
}

func TestSharedSecretChangeIsOneTransactionThatOnlyTouchesSecrets(t *testing.T) {
	store := newTestStore(t)
	for i := 0; i < 40; i++ {
		id := string(rune('a'+i%26)) + string(rune('0'+i/26))
		if err := store.Upsert(SystemMetric{ID: id, Name: "S " + id, Secret: "old", Order: i, Tags: []string{"t"}, CPU: float64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	postNavbar(t, store, NavbarConfig{Text: "x", SharedSecret: "old"})
	// a push lands after the admin page read the systems: its numbers must survive
	m, _ := store.Get("c0")
	m.CPU = 99.5
	if err := store.Upsert(*m); err != nil {
		t.Fatal(err)
	}
	postNavbar(t, store, NavbarConfig{Text: "x", SharedSecret: "new"})
	list, _ := store.List()
	if len(list) != 40 {
		t.Fatalf("systems %d", len(list))
	}
	for _, s := range list {
		if s.Secret != "new" || s.Name != "S "+s.ID || len(s.Tags) != 1 {
			t.Fatalf("%s: %+v", s.ID, s)
		}
	}
	if m, _ := store.Get("c0"); m.CPU != 99.5 {
		t.Fatalf("the change wrote back a stale record: cpu %v", m.CPU)
	}
	if cfg, _ := store.GetNavbarConfig(); cfg.SharedSecret != "new" {
		t.Fatalf("config %+v", cfg)
	}
}

func TestSavingWithTheSameSharedSecretKeepsEachSystemsOwn(t *testing.T) {
	store := newTestStore(t)
	cfg, _ := store.GetNavbarConfig() // a shared secret is generated when there is none
	if err := store.Upsert(SystemMetric{ID: "own", Name: "own", Secret: "its-own"}); err != nil {
		t.Fatal(err)
	}
	postNavbar(t, store, NavbarConfig{Text: "renamed", SharedSecret: cfg.SharedSecret})
	if m, _ := store.Get("own"); m.Secret != "its-own" {
		t.Fatalf("a save that does not change the shared secret must leave a system's own alone: %q", m.Secret)
	}
	postNavbar(t, store, NavbarConfig{Text: "renamed", SharedSecret: "rotated"})
	if m, _ := store.Get("own"); m.Secret != "rotated" {
		t.Fatalf("a changed shared secret goes to every system: %q", m.Secret)
	}
}

func TestPushCountsOnlyOnceStored(t *testing.T) {
	store, registry, ipCache := setupClockTest(t, "disk")
	storeHealth = storeHealthState{}
	defer func() {
		storeHealth = storeHealthState{}
		saveClientPush = func(s *Store, m SystemMetric, r []TCPingResult) error { return s.SaveClientPushBatch(m, r) }
	}()
	pushTCPingBatch(t, store, registry, ipCache, "disk", nil)
	first := registry.Get("disk").LastPushAt
	if first.IsZero() || !registry.Get("disk").PushMode {
		t.Fatal("a stored push counts")
	}
	saveClientPush = func(*Store, SystemMetric, []TCPingResult) error {
		return errors.New("write metrics.db: no space left on device")
	}
	time.Sleep(5 * time.Millisecond)
	body, _ := json.Marshal(map[string]interface{}{"id": "disk", "name": "x", "uptime": 5})
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(body)))
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "no space") {
		t.Fatalf("failed save: %d %q (the error stays in the log)", rr.Code, rr.Body.String())
	}
	if got := registry.Get("disk").LastPushAt; !got.Equal(first) {
		t.Fatalf("a push the disk refused counted: LastPushAt %v → %v", first, got)
	}
	rr = httptest.NewRecorder()
	handleHealth(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "space") {
		t.Fatalf("healthz while pushes fail: %d %s", rr.Code, rr.Body.String())
	}
	saveClientPush = func(s *Store, m SystemMetric, r []TCPingResult) error { return s.SaveClientPushBatch(m, r) }
	pushTCPingBatch(t, store, registry, ipCache, "disk", nil)
	rr = httptest.NewRecorder()
	handleHealth(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK || !registry.Get("disk").LastPushAt.After(first) {
		t.Fatalf("after recovery: healthz %d", rr.Code)
	}
}

func TestUnknownIDAndWrongSecretGetTheSameAnswer(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.Upsert(SystemMetric{ID: "7", Name: "seven", Secret: "right"}); err != nil {
		t.Fatal(err)
	}
	ask := func(path, id string) (int, string) {
		body, _ := json.Marshal(map[string]interface{}{"id": id, "name": "x", "port": "9090", "secret": "wrong"})
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer wrong")
		rr := httptest.NewRecorder()
		if path == "/api/clients/push" {
			handleClientPush(store, registry, ipCache, rr, req)
		} else {
			handleClientRegister(store, registry, rr, req)
		}
		return rr.Code, rr.Body.String()
	}
	for _, path := range []string{"/api/clients/push", "/api/clients/register"} {
		c1, b1 := ask(path, "7")
		c2, b2 := ask(path, "8")
		if c1 != http.StatusUnauthorized || c1 != c2 || b1 != b2 || strings.Contains(b2, "8") {
			t.Fatalf("%s: known id with a wrong secret %d %q, unknown id %d %q", path, c1, b1, c2, b2)
		}
	}
}

func TestHistoryCacheKeepsOnlyTheGzipCopyAndServesBoth(t *testing.T) {
	results := make([]TCPingResult, 0, 1440)
	base := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 1440; i++ {
		l := 20 + float64(i%17)
		results = append(results, TCPingResult{ClientID: "c", Target: "1.1.1.1:443", Latency: &l, Timestamp: base.Add(time.Duration(i) * time.Minute)})
	}
	resp := TCPingHistoryResponse{Results: results, Stats: calculateTCPingStats(results)}
	want, _ := json.Marshal(resp)
	want = append(want, '\n')
	entry := buildTCPingCacheEntry(resp)
	if entry == nil || entry.JSON != nil || entry.GZ == nil || entry.Size != len(entry.GZ) || entry.Size*4 > len(want) {
		t.Fatalf("entry: json %d gz %d size %d (body %d)", len(entry.JSON), len(entry.GZ), entry.Size, len(want))
	}
	for _, enc := range []string{"gzip", ""} {
		req := httptest.NewRequest(http.MethodGet, "/api/tcping/history?client_id=c", nil)
		if enc != "" {
			req.Header.Set("Accept-Encoding", enc)
		}
		rr := httptest.NewRecorder()
		writeCachedTCPingEntry(rr, req, entry)
		got := rr.Body.Bytes()
		if enc == "gzip" {
			if rr.Header().Get("Content-Encoding") != "gzip" {
				t.Fatal("a gzip client gets the gzip copy")
			}
			got, _ = (&tcpingCacheEntry{GZ: got}).plain()
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Accept-Encoding %q: the body differs from the JSON encoding (%d vs %d bytes)", enc, len(got), len(want))
		}
	}
}

func TestLoginBudgetPerIPv6Slash48AndConcurrentChecks(t *testing.T) {
	store := newTestStore(t)
	if err := store.SetPassword("correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	var checks, running, peak int32
	orig := loginVerify
	loginVerify = func(st *Store, pw string) (bool, error) {
		atomic.AddInt32(&checks, 1)
		n := atomic.AddInt32(&running, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		return pw == "correct-horse-battery", nil
	}
	defer func() { loginVerify = orig }()
	loginAttemptsMu.Lock()
	for k := range loginAttempts {
		if strings.HasPrefix(k, "2001:db8:42") {
			delete(loginAttempts, k)
		}
	}
	loginAttemptsMu.Unlock()
	var wg sync.WaitGroup
	for p := 0; p < 200; p++ { // 200 /64s of one /48, 6 guesses each
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for a := 0; a < 6; a++ {
				r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"password":"guess-%d-%d"}`, p, a)))
				r.RemoteAddr = fmt.Sprintf("[2001:db8:42:%x::%x]:4000", p, a+1)
				handleAuthLogin(store, httptest.NewRecorder(), r)
			}
		}(p)
	}
	wg.Wait()
	if n := atomic.LoadInt32(&checks); n > loginMaxAttempts48 {
		t.Fatalf("one /48 bought %d password checks; its budget is %d (was 5 per /64: 1000)", n, loginMaxAttempts48)
	}
	if p := atomic.LoadInt32(&peak); p > loginConcurrentChecks {
		t.Fatalf("%d checks ran at once; at most %d", p, loginConcurrentChecks)
	}
	// another /48 and IPv4 are not affected
	for _, addr := range []string{"[2001:db8:43::1]:4000", "198.51.100.90:4000"} {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"correct-horse-battery"}`))
		r.RemoteAddr = addr
		rr := httptest.NewRecorder()
		handleAuthLogin(store, rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", addr, rr.Code)
		}
	}
}

func TestSetupAfterADamagedDatabaseOnlyFromTheServerItself(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/metrics.db"
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword("owner-password"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// both meta pages bad (as a truncated copy or a torn write leaves them)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	junk := bytes.Repeat([]byte{0xA5}, 256)
	for _, off := range []int64{16, 4096 + 16} {
		if _, err := f.WriteAt(junk, off); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("a damaged database must not keep the server down: %v", err)
	}
	defer store.Close()
	status := httptest.NewRecorder()
	handleAuthStatus(store, status, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	if !strings.Contains(status.Body.String(), `"locked":true`) || !strings.Contains(status.Body.String(), `"set":false`) {
		t.Fatalf("status: %s", status.Body.String())
	}
	setup := func(remote, xff string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"password":"attacker-pw-123"}`))
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rr := httptest.NewRecorder()
		handleAuthSetup(store, rr, req)
		return rr.Code
	}
	if c := setup("203.0.113.9:5555", ""); c != http.StatusForbidden {
		t.Fatalf("a visitor set the password of a fresh database: %d", c)
	}
	if c := setup("203.0.113.9:5555", "127.0.0.1"); c != http.StatusForbidden {
		t.Fatalf("a forwarded header claiming loopback must not count: %d", c)
	}
	if set, _ := store.CheckPasswordSet(); set {
		t.Fatal("no password may have been set")
	}
	if c := setup("127.0.0.1:5555", ""); c != http.StatusOK {
		t.Fatalf("from the server itself: %d", c)
	}
	if store.SetupLocked() {
		t.Fatal("the lock goes once a password is set")
	}
	// and a genuinely new install still has its normal first run
	fresh, err := NewStore(t.TempDir() + "/new.db")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.SetupLocked() {
		t.Fatal("a new install is not locked")
	}
}

func TestStreamTicketsAreSingleUseShortLivedAndNeedASession(t *testing.T) {
	authTokensMu.Lock()
	authTokens["ticket-session"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	defer func() { authTokensMu.Lock(); delete(authTokens, "ticket-session"); authTokensMu.Unlock() }()
	get := func(bearer string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/stream-ticket", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		handleStreamTicket(rr, req)
		var out struct {
			Ticket string `json:"ticket"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out.Ticket
	}
	if c, _ := get(""); c != http.StatusUnauthorized {
		t.Fatalf("no session: %d", c)
	}
	if c, _ := get("not-a-session"); c != http.StatusUnauthorized {
		t.Fatalf("a bad session: %d", c)
	}
	c, ticket := get("ticket-session")
	if c != http.StatusOK || len(ticket) < 32 || strings.Contains(ticket, "ticket-session") {
		t.Fatalf("ticket: %d %q", c, ticket)
	}
	if tok, ok := redeemStreamTicket(ticket, time.Now()); !ok || tok != "ticket-session" {
		t.Fatalf("redeem: %q %v", tok, ok)
	}
	if _, ok := redeemStreamTicket(ticket, time.Now()); ok {
		t.Fatal("a ticket works once")
	}
	_, late := get("ticket-session")
	if _, ok := redeemStreamTicket(late, time.Now().Add(streamTicketTTL+time.Second)); ok {
		t.Fatal("a ticket expires")
	}
}

func TestStreamWithATicketGetsTheAdminView(t *testing.T) {
	store := newTestStore(t)
	broker := NewSSEBroker()
	if err := store.Upsert(SystemMetric{ID: "s1", Name: "one", Secret: "agent-secret", IPv4: "203.0.113.5", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	authTokensMu.Lock()
	authTokens["view-session"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	defer func() { authTokensMu.Lock(); delete(authTokens, "view-session"); authTokensMu.Unlock() }()
	ticket, _ := issueStreamTicket("view-session", time.Now())
	firstEvent := func(query string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/api/events"+query, nil).WithContext(ctx)
		rr := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { handleSSE(store, broker, rr, req); close(done) }()
		time.Sleep(300 * time.Millisecond)
		cancel()
		<-done
		return rr.Body.String()
	}
	if body := firstEvent("?ticket=" + ticket); !strings.Contains(body, "agent-secret") {
		t.Fatalf("a valid ticket must give the admin view: %.300s", body)
	}
	if body := firstEvent("?ticket=" + ticket); strings.Contains(body, "agent-secret") {
		t.Fatal("a spent ticket must give the public view only")
	}
}
