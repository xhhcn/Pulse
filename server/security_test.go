package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// withAdminToken mints a live admin session for the test and revokes it on
// cleanup so tests cannot leak sessions into each other.
func withAdminToken(t *testing.T, token string) {
	t.Helper()
	authTokensMu.Lock()
	authTokens[token] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() { revokeAuthToken(token) })
}

func jsonRequest(method, path, remote string, body interface{}) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if remote != "" {
		req.RemoteAddr = remote
	}
	return req
}

func TestIngestEchoMasksAddressesForAgentCallers(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "echo", Name: "Echo", Secret: "fleet-secret"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	req := jsonRequest(http.MethodPost, "/api/metrics", "203.0.113.7:5000", map[string]interface{}{
		"id": "echo", "name": "Echo", "uptime": 5, "os": "linux", "location": "US", "ipv4": "203.0.113.7",
	})
	req.Header.Set("Authorization", "Bearer fleet-secret")
	rr := httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", rr.Code, rr.Body.String())
	}
	var echo map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &echo); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	for _, k := range []string{"ipv4", "ipv6", "location_ip", "secret"} {
		if v, _ := echo[k].(string); v != "" {
			t.Fatalf("agent-side echo leaks %s=%q", k, v)
		}
	}
	m, _ := store.Get("echo")
	if m.IPv4 != "203.0.113.7" {
		t.Fatalf("the write itself must still store the address: %+v", m)
	}
}

func TestQueryStringAdminTokenIsRejected(t *testing.T) {
	withAdminToken(t, "qs-admin-token")
	req := httptest.NewRequest(http.MethodGet, "/api/metrics?token=qs-admin-token", nil)
	if isAuthenticated(req) {
		t.Fatal("an admin token in the query string must not authenticate")
	}
	req = httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer qs-admin-token")
	if !isAuthenticated(req) {
		t.Fatal("the same token in the Authorization header must authenticate")
	}
}

func TestLogoutAndPasswordChangeRevokeSessions(t *testing.T) {
	store := newTestStore(t)
	if err := store.SetPassword("old-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	withAdminToken(t, "session-a")
	withAdminToken(t, "session-b")

	req := jsonRequest(http.MethodPost, "/api/auth/change-password", "", map[string]string{
		"currentPassword": "old-password", "newPassword": "new-password-1",
	})
	req.Header.Set("Authorization", "Bearer session-a")
	rr := httptest.NewRecorder()
	handleAuthChangePassword(store, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", rr.Code, rr.Body.String())
	}
	if !authTokenValid("session-a") {
		t.Fatal("the session that changed the password must stay valid")
	}
	if authTokenValid("session-b") {
		t.Fatal("other sessions must be revoked by a password change")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer session-a")
	rr = httptest.NewRecorder()
	handleAuthLogout(rr, req)
	if rr.Code != http.StatusOK || authTokenValid("session-a") {
		t.Fatalf("logout must end the session: code=%d valid=%v", rr.Code, authTokenValid("session-a"))
	}
}

func TestFirstRunSetupIsAtomic(t *testing.T) {
	store := newTestStore(t)
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := jsonRequest(http.MethodPost, "/api/auth/setup", "", map[string]string{"password": fmt.Sprintf("candidate-%d", i)})
			rr := httptest.NewRecorder()
			handleAuthSetup(store, rr, req)
			codes[i] = rr.Code
		}(i)
	}
	wg.Wait()
	winners := 0
	for i, c := range codes {
		if c == http.StatusOK {
			winners++
			if ok, _ := store.VerifyPassword(fmt.Sprintf("candidate-%d", i)); !ok {
				t.Fatalf("call %d reported success but its password does not verify", i)
			}
		}
	}
	if winners != 1 {
		t.Fatalf("exactly one concurrent first-run setup may succeed, got %d (%v)", winners, codes)
	}
}

func TestShareTokenVerifyNeedsExpiryAndIsThrottled(t *testing.T) {
	store := newTestStore(t)
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true, ShareToken: "share-token-1"}); err != nil {
		t.Fatalf("SavePrivacyConfig: %v", err)
	}
	verify := func(remote string) (int, map[string]interface{}) {
		req := jsonRequest(http.MethodPost, "/api/privacy/verify-token", remote, map[string]string{"token": "share-token-1"})
		rr := httptest.NewRecorder()
		handleVerifyShareToken(store, rr, req)
		var out map[string]interface{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	if code, out := verify("198.51.100.10:1"); code != http.StatusOK || out["valid"] != false || out["reason"] != "token_expired" {
		t.Fatalf("a token without expiry must not verify: %d %v", code, out)
	}
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true, ShareToken: "share-token-1", TokenExpires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SavePrivacyConfig: %v", err)
	}
	if code, out := verify("198.51.100.10:1"); code != http.StatusOK || out["valid"] != true {
		t.Fatalf("a live token must verify: %d %v", code, out)
	}
	throttled := 0
	for i := 0; i < 40; i++ {
		if code, _ := verify("198.51.100.11:1"); code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatal("verify-token must be rate limited per client address")
	}
}

func TestSanitizeAgentStrings(t *testing.T) {
	if got := sanitizeAgentString("x\"><img src=y onerror=alert(1)>", 128); got != "ximg src=y onerror=alert(1)" {
		t.Fatalf("markup characters must be stripped: %q", got)
	}
	ctrl := "a" + string(rune(0)) + "b" + string(rune(0x1f)) + "c" + string(rune(0x7f)) + "d"
	if got := sanitizeAgentString(ctrl, 128); got != "abcd" {
		t.Fatalf("control characters must be stripped: %q", got)
	}
	if got := sanitizeAgentString(strings.Repeat("é", 300), 128); len([]rune(got)) != 128 {
		t.Fatalf("length must be capped in runes: %d", len([]rune(got)))
	}
	if got := sanitizeAgentString("Côte d'Ivoire, 中国 ", 128); got != "Côte d'Ivoire, 中国" {
		t.Fatalf("ordinary text must survive: %q", got)
	}
	for in, want := range map[string]string{
		"logos:ubuntu": "logos:ubuntu", "Logos:Microsoft-Windows-Icon": "logos:microsoft-windows-icon",
		"x\"><img/src=y>": "", "../etc": "", "logos:": "", "": "",
	} {
		if got := sanitizeIconName(in); got != want {
			t.Fatalf("sanitizeIconName(%q) = %q, want %q", in, got, want)
		}
	}
	if clampPercent(-5) != 0 || clampPercent(150) != 100 || clampPercent(42.5) != 42.5 {
		t.Fatal("percentages must be clamped to 0..100")
	}

	// End to end: a push with hostile strings stores only the sanitised form.
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.Upsert(SystemMetric{ID: "san", Name: "San"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	req := jsonRequest(http.MethodPost, "/api/clients/push", "", map[string]interface{}{
		"id": "san", "name": "x", "uptime": 5, "location": "US",
		"os_icon": "x\"><img/src=y/onerror=alert(1)>", "cpu_model": strings.Repeat("A", 5000),
		"os": "Debian <script>1</script>", "ipv6": "not-an-address", "cpu": 250.0,
	})
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: %d %s", rr.Code, rr.Body.String())
	}
	m, _ := store.Get("san")
	if m.OSIcon != "" || len(m.CPUModel) != agentStringMaxLen || m.OS != "Debian script1/script" || m.IPv6 != "" || m.CPU != 100 {
		t.Fatalf("stored fields not sanitised: icon=%q cpu_model_len=%d os=%q ipv6=%q cpu=%v", m.OSIcon, len(m.CPUModel), m.OS, m.IPv6, m.CPU)
	}
}

func TestRegisterRejectsMalformedPort(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	if err := store.Upsert(SystemMetric{ID: "reg", Name: "Reg"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	for _, bad := range []string{"1@127.0.0.1:8008", "80/x?a=", "0", "70000", "abc"} {
		req := jsonRequest(http.MethodPost, "/api/clients/register", "203.0.113.5:4000", map[string]string{"id": "reg", "port": bad, "ip": "203.0.113.5"})
		rr := httptest.NewRecorder()
		handleClientRegister(store, registry, rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("port %q must be rejected, got %d %s", bad, rr.Code, rr.Body.String())
		}
	}
	req := jsonRequest(http.MethodPost, "/api/clients/register", "203.0.113.5:4000", map[string]string{"id": "reg", "port": "9090", "ip": "203.0.113.5"})
	rr := httptest.NewRecorder()
	handleClientRegister(store, registry, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("a numeric port must register: %d %s", rr.Code, rr.Body.String())
	}
	if got := buildURL("203.0.113.5", "9090"); got != "http://203.0.113.5:9090" {
		t.Fatalf("buildURL v4 = %q", got)
	}
	if got := buildURL("2001:db8::1", "9090"); got != "http://[2001:db8::1]:9090" {
		t.Fatalf("buildURL v6 = %q", got)
	}
}

func TestPushCapsTCPingBatchAndStaysFast(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "flood", Name: "Flood"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	samples := make([]map[string]interface{}, 0, 5000)
	for i := 0; i < 5000; i++ {
		// No measured_at: every sample gets the same server-side stamp, the
		// case that used to probe sequence numbers quadratically.
		samples = append(samples, map[string]interface{}{"target": "1.1.1.1:443", "latency": 1, "success": true})
	}
	start := time.Now()
	pushTCPingBatch(t, store, registry, ipCache, "flood", samples)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("a 5000-sample push took %v", elapsed)
	}
	results, err := store.GetTCPingResults("flood", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != maxTCPingResultsPerPush {
		t.Fatalf("stored %d samples, want the newest %d", len(results), maxTCPingResultsPerPush)
	}
}

func TestLegacyTCPingRejectsUnknownTarget(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "lg", Name: "Legacy"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	post := func(target string) int {
		req := jsonRequest(http.MethodPost, "/api/tcping", "", map[string]interface{}{"client_id": "lg", "target": target, "latency": 1, "success": true})
		rr := httptest.NewRecorder()
		handleTCPingResult(store, rr, req)
		return rr.Code
	}
	if code := post("evil.example:1"); code != http.StatusBadRequest {
		t.Fatalf("unconfigured target accepted: %d", code)
	}
	if code := post(""); code != http.StatusBadRequest {
		t.Fatalf("empty target accepted: %d", code)
	}
	if code := post("1.1.1.1:443"); code != http.StatusOK {
		t.Fatalf("configured target rejected: %d", code)
	}
}

func TestIPCountryCacheIsBounded(t *testing.T) {
	cache := NewIPCountryCache()
	for i := 0; i < ipCountryCacheMax+50; i++ {
		cache.Set(fmt.Sprintf("203.%d.%d.%d", i>>16&255, i>>8&255, i&255), "US")
	}
	cache.mu.RLock()
	n := len(cache.cache)
	cache.mu.RUnlock()
	if n > ipCountryCacheMax {
		t.Fatalf("cache grew to %d entries, bound is %d", n, ipCountryCacheMax)
	}
}

func TestHistoryUnknownClientIs404(t *testing.T) {
	resetTCPingCacheForTest(t)
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "known", Name: "Known"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	get := func(id string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/tcping/history?client_id="+id, nil)
		rr := httptest.NewRecorder()
		handleGetTCPingHistory(store, rr, req)
		return rr.Code
	}
	if code := get("nope"); code != http.StatusNotFound {
		t.Fatalf("unknown client: %d", code)
	}
	if code := get("known"); code != http.StatusOK {
		t.Fatalf("known client: %d", code)
	}
}

func TestSSEStreamEndsWhenAdmissionIsRevoked(t *testing.T) {
	old := sseReauthInterval
	sseReauthInterval = 40 * time.Millisecond
	t.Cleanup(func() { sseReauthInterval = old })

	store := newTestStore(t)
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true, ShareToken: "share-1", TokenExpires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SavePrivacyConfig: %v", err)
	}
	broker := NewSSEBroker()
	open := func(path string) (chan struct{}, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		req.RemoteAddr = "203.0.113.20:1"
		done := make(chan struct{})
		go func() { handleSSE(store, broker, httptest.NewRecorder(), req); close(done) }()
		return done, cancel
	}
	stillOpen := func(done chan struct{}, after time.Duration) bool {
		select {
		case <-done:
			return false
		case <-time.After(after):
			return true
		}
	}

	// Share-token stream: survives while the token is valid, ends when it is
	// revoked.
	done, cancel := open("/api/events?token=share-1")
	defer cancel()
	if !stillOpen(done, 150*time.Millisecond) {
		t.Fatal("a valid share-token stream must stay open")
	}
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true, ShareToken: ""}); err != nil {
		t.Fatalf("SavePrivacyConfig: %v", err)
	}
	if stillOpen(done, 2*time.Second) {
		t.Fatal("revoking the share token must end the stream")
	}

	// Admin stream: ends when the session is revoked (logout or password change).
	withAdminToken(t, "sse-admin")
	done, cancel = open("/api/events?admin_token=sse-admin")
	defer cancel()
	if !stillOpen(done, 150*time.Millisecond) {
		t.Fatal("a valid admin stream must stay open")
	}
	revokeAuthToken("sse-admin")
	if stillOpen(done, 2*time.Second) {
		t.Fatal("revoking the admin session must end the stream")
	}
}

func TestReadDeadlineMiddlewarePassesRequestsThrough(t *testing.T) {
	h := readDeadlineMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(m, "/api/metrics", strings.NewReader("{}")))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s: %d", m, rr.Code)
		}
	}
}
