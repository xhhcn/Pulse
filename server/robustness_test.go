package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- geo resolution never blocks ---------------------------------------------

func TestResolveLocationReportedValueWins(t *testing.T) {
	cache := NewIPCountryCache()
	got := resolveLocation(cache, nil, "Los Angeles, US", "8.8.8.8", "")
	if got != "US" {
		t.Fatalf("resolveLocation() = %q, want US", got)
	}
}

func TestResolveLocationReusesStoredLocationWhenIPUnchanged(t *testing.T) {
	cache := NewIPCountryCache()
	existing := &SystemMetric{ID: "sys", Location: "DE", IPv4: "203.0.113.10"}
	got := resolveLocation(cache, existing, "", "203.0.113.10", "")
	if got != "DE" {
		t.Fatalf("resolveLocation() = %q, want DE (persisted value reused)", got)
	}
	if _, found := cache.Get("203.0.113.10"); found {
		t.Fatalf("cache must not be touched on the persisted-value path")
	}
}

func TestResolveLocationUsesCacheAndFallsBackAcrossFamilies(t *testing.T) {
	cache := NewIPCountryCache()
	cache.SetFailed("203.0.113.10")
	cache.Set("2001:db8::1", "JP")
	got := resolveLocation(cache, nil, "", "203.0.113.10", "2001:db8::1")
	if got != "JP" {
		t.Fatalf("resolveLocation() = %q, want JP (v4 cached failure, v6 cache hit)", got)
	}
}

func TestResolveLocationKeepsOldLocationWhileIPChanges(t *testing.T) {
	cache := NewIPCountryCache()
	// Old IP resolved earlier; new IP has a cached answer, so the change is
	// picked up immediately without any network call.
	cache.Set("198.51.100.7", "FR")
	existing := &SystemMetric{ID: "sys", Location: "DE", IPv4: "203.0.113.10"}
	got := resolveLocation(cache, existing, "", "198.51.100.7", "")
	if got != "FR" {
		t.Fatalf("resolveLocation() = %q, want FR", got)
	}
}

func TestResolveLocationSkipsPrivateAddresses(t *testing.T) {
	cache := NewIPCountryCache()
	start := time.Now()
	got := resolveLocation(cache, nil, "", "192.168.1.5", "fd00::1")
	if got != "" {
		t.Fatalf("resolveLocation() = %q, want empty for private IPs", got)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("resolveLocation blocked for %v", time.Since(start))
	}
}

// --- tcping batches are idempotent --------------------------------------------

func TestSaveClientPushBatchIgnoresResentMeasurements(t *testing.T) {
	store := newTestStore(t)
	measured := time.Now().UTC().Add(-2 * time.Minute)
	lat := 12.5
	batch := []TCPingResult{{ClientID: "agent", Target: "1.1.1.1:443", Latency: &lat, Timestamp: measured, ExactTimestamp: true}}
	metric := SystemMetric{ID: "agent", Name: "agent"}

	// First push commits; the agent times out waiting and re-sends the same
	// measurement on its next push.
	for i := 0; i < 2; i++ {
		if err := store.SaveClientPushBatch(metric, batch); err != nil {
			t.Fatalf("SaveClientPushBatch(%d) error = %v", i, err)
		}
	}
	results, err := store.GetTCPingResults("agent", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1 (duplicate must be dropped)", len(results))
	}
}

// --- SSE subscriber caps --------------------------------------------------------

func TestSSEBrokerEnforcesPerIPCap(t *testing.T) {
	b := NewSSEBroker()
	subs := make([]*sseSubscriber, 0, b.maxPerIP)
	for i := 0; i < b.maxPerIP; i++ {
		s, err := b.Subscribe(SSEViewPublic, "203.0.113.10")
		if err != nil {
			t.Fatalf("Subscribe(%d) error = %v", i, err)
		}
		subs = append(subs, s)
	}
	if _, err := b.Subscribe(SSEViewPublic, "203.0.113.10"); err == nil {
		t.Fatalf("Subscribe beyond per-IP cap must fail")
	}
	if _, err := b.Subscribe(SSEViewPublic, "203.0.113.11"); err != nil {
		t.Fatalf("other IP must still be admitted: %v", err)
	}
	b.Unsubscribe(subs[0])
	if _, err := b.Subscribe(SSEViewPublic, "203.0.113.10"); err != nil {
		t.Fatalf("Unsubscribe must free a per-IP slot: %v", err)
	}
	if got := b.SubscriberCount(); got != b.maxPerIP+1 {
		t.Fatalf("SubscriberCount() = %d, want %d", got, b.maxPerIP+1)
	}
	// Admin streams are never refused by the anonymous caps.
	for i := 0; i < 3; i++ {
		if _, err := b.Subscribe(SSEViewAdmin, "203.0.113.10"); err != nil {
			t.Fatalf("admin Subscribe must bypass the per-IP cap: %v", err)
		}
	}
}

// --- admin visibility toggles survive agent writes ----------------------------

func adminRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-admin-token")
	return req
}

func TestVisibilityTogglesPersistThroughPushAndAdminEdit(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()

	authTokensMu.Lock()
	authTokens["test-admin-token"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() {
		authTokensMu.Lock()
		delete(authTokens, "test-admin-token")
		authTokensMu.Unlock()
	})

	// Admin creates the system.
	rr := httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{"id": "vm1", "name": "VM 1"}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("create: status %d body %s", rr.Code, rr.Body.String())
	}
	created, _ := store.Get("vm1")
	if created == nil || created.HideOnHome || created.HideTCPing {
		t.Fatalf("new systems must default to shown: %+v", created)
	}

	// Admin edit flips both toggles.
	hide := true
	rr = httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{
		"id": "vm1", "name": "VM 1 renamed", "tags": []string{"a"}, "hide_on_home": hide, "hide_tcping": hide,
	}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("edit: status %d body %s", rr.Code, rr.Body.String())
	}
	edited, _ := store.Get("vm1")
	if !edited.HideOnHome || !edited.HideTCPing || edited.Name != "VM 1 renamed" {
		t.Fatalf("edit did not persist toggles: %+v", edited)
	}

	// Agent push (with the secret) must not reset them, even if it sends
	// explicit false values.
	pushBody := map[string]interface{}{
		"id": "vm1", "name": "agent-name", "uptime": 123, "os": "Linux", "cpu": 3.0,
		"secret": edited.Secret, "location": "US", "hide_on_home": false, "hide_tcping": false,
	}
	data, _ := json.Marshal(pushBody)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	pushed, _ := store.Get("vm1")
	if !pushed.HideOnHome || !pushed.HideTCPing {
		t.Fatalf("agent push reset the toggles: %+v", pushed)
	}
	if pushed.Name != "VM 1 renamed" || pushed.CPU != 3.0 || pushed.Location != "US" {
		t.Fatalf("push did not update metrics as expected: %+v", pushed)
	}

	// Admin edit without the toggle fields (older UI) leaves them untouched.
	rr = httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{"id": "vm1", "name": "VM 1 again"}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("edit2: status %d body %s", rr.Code, rr.Body.String())
	}
	again, _ := store.Get("vm1")
	if !again.HideOnHome || !again.HideTCPing {
		t.Fatalf("edit without toggle fields must preserve them: %+v", again)
	}

	// Public and admin snapshots both still contain the hidden system (the
	// homepage filters client-side; the API keeps returning it).
	for _, admin := range []bool{true, false} {
		snap, err := buildMetricsSnapshot(store, registry, admin)
		if err != nil {
			t.Fatalf("buildMetricsSnapshot(%v) error = %v", admin, err)
		}
		if len(snap) != 1 || !snap[0].HideOnHome {
			t.Fatalf("snapshot(admin=%v) = %+v, want the hidden system with hide_on_home=true", admin, snap)
		}
	}
}

// --- old tcping samples keep their real timestamps --------------------------------

func TestClientPushKeepsBackfilledTimestampsAndDropsExpired(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "vm2", Name: "VM 2"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	now := time.Now().UTC()
	old := now.Add(-40 * time.Minute) // server was down for a while: must be kept verbatim
	expired := now.Add(-25 * time.Hour)
	body := map[string]interface{}{
		"id": "vm2", "name": "x", "uptime": 5, "location": "US",
		"tcping_results": []map[string]interface{}{
			{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": old.Format(time.RFC3339Nano)},
			{"target": "1.1.1.1:443", "latency": 11, "success": true, "measured_at": expired.Format(time.RFC3339Nano)},
			{"target": "1.1.1.1:443", "latency": 12, "success": true, "measured_at": now.Format(time.RFC3339Nano)},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	results, err := store.GetTCPingResults("vm2", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2 (expired sample dropped)", len(results))
	}
	if d := results[0].Timestamp.Sub(old); d < -time.Second || d > time.Second {
		t.Fatalf("backfilled sample re-stamped: got %v want %v", results[0].Timestamp, old)
	}
	m, _ := store.Get("vm2")
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 12 {
		t.Fatalf("latest tcping datum = %+v, want the newest sample (12 ms)", got)
	}
}

// --- legacy agents (no measured_at) keep every sample in a batch ---------------

func TestClientPushKeepsAllSamplesFromLegacyAgents(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "legacy", Name: "Legacy"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	body := map[string]interface{}{
		"id": "legacy", "name": "x", "uptime": 5, "location": "US",
		"tcping_results": []map[string]interface{}{
			{"target": "1.1.1.1:443", "latency": 10, "success": true},
			{"target": "1.1.1.1:443", "latency": 11, "success": true},
			{"target": "1.1.1.1:443", "latency": 12, "success": false},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	results, err := store.GetTCPingResults("legacy", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3 (server-stamped samples must never be deduplicated)", len(results))
	}
}

func TestClientPushShiftsSkewedAgentClock(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "skew", Name: "Skew"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	now := time.Now().UTC()
	// Agent clock is 6 h behind: its "just measured" sample says now-6h and
	// its 1-minute-old sample says now-6h-1m. Both must land near now.
	body := map[string]interface{}{
		"id": "skew", "name": "x", "uptime": 5, "location": "US",
		"tcping_results": []map[string]interface{}{
			{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": now.Add(-6 * time.Hour).Format(time.RFC3339Nano)},
			{"target": "1.1.1.1:443", "latency": 11, "success": true, "measured_at": now.Add(-6*time.Hour - time.Minute).Format(time.RFC3339Nano)},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
	results, err := store.GetTCPingResults("skew", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("GetTCPingResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, r := range results {
		if age := time.Since(r.Timestamp); age > 2*time.Minute || age < -5*time.Second {
			t.Fatalf("skewed sample not shifted to the present: %v (age %v)", r.Timestamp, age)
		}
	}
	m, _ := store.Get("skew")
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 10 {
		t.Fatalf("latest datum = %+v, want the newest sample (10 ms)", got)
	}
}

// --- admin edits survive a concurrent agent write ------------------------------

func TestAgentWriteNeverRevertsConcurrentAdminEdit(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "race", Name: "Old name", Secret: "s", Order: 1}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Agent reads its snapshot ...
	snapshot, _ := store.Get("race")
	agentRecord := *snapshot
	agentRecord.CPU = 55

	// ... the admin edits in between ...
	edited := *snapshot
	edited.Name = "New name"
	edited.Tags = []string{"prod"}
	edited.Order = 7
	edited.HideOnHome = true
	edited.HideTCPing = true
	if err := store.Upsert(edited); err != nil {
		t.Fatalf("admin Upsert: %v", err)
	}

	// ... and the agent's write lands last, on both agent paths.
	if err := store.UpsertFromAgent(agentRecord); err != nil {
		t.Fatalf("UpsertFromAgent: %v", err)
	}
	got, _ := store.Get("race")
	if got.CPU != 55 {
		t.Fatalf("agent metrics not written: %+v", got)
	}
	if got.Name != "New name" || len(got.Tags) != 1 || got.Order != 7 || !got.HideOnHome || !got.HideTCPing || got.Secret != "s" {
		t.Fatalf("UpsertFromAgent reverted admin-owned fields: %+v", got)
	}

	agentRecord.CPU = 66
	if err := store.SaveClientPushBatch(agentRecord, nil); err != nil {
		t.Fatalf("SaveClientPushBatch: %v", err)
	}
	got, _ = store.Get("race")
	if got.CPU != 66 || got.Name != "New name" || !got.HideOnHome || !got.HideTCPing || got.Order != 7 {
		t.Fatalf("SaveClientPushBatch reverted admin-owned fields: %+v", got)
	}
}

// --- admin operations: single-transaction reorder, key-based history deletes ----

func TestUpdateOrdersTouchesOnlyOrder(t *testing.T) {
	store := newTestStore(t)
	for i, id := range []string{"a", "b", "c"} {
		if err := store.Upsert(SystemMetric{ID: id, Name: "n-" + id, Order: i, CPU: float64(10 * i), Secret: "s"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	if err := store.UpdateOrders([]string{"c", "missing", "a", "b"}); err != nil {
		t.Fatalf("UpdateOrders: %v", err)
	}
	want := map[string]int{"c": 0, "a": 2, "b": 3}
	for id, order := range want {
		m, _ := store.Get(id)
		if m.Order != order {
			t.Fatalf("%s: order = %d, want %d", id, m.Order, order)
		}
		if m.Secret != "s" || m.Name != "n-"+id {
			t.Fatalf("%s: other fields changed: %+v", id, m)
		}
	}
}

func TestDeleteTCPingHistoryDoesNotMatchPrefixCollisions(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	lat := 1.0
	put := func(client, target string, offset time.Duration) {
		if err := store.SaveTCPingResult(TCPingResult{ClientID: client, Target: target, Latency: &lat, Timestamp: now.Add(offset)}); err != nil {
			t.Fatalf("SaveTCPingResult: %v", err)
		}
	}
	put("a", "x:1", -time.Minute)
	put("a_b", "x:1", -2*time.Minute) // shares the "a_" key prefix
	put("a", "x:10", -3*time.Minute)  // shares the "_x:1" suffix start
	put("b", "x:1", -4*time.Minute)

	if err := store.DeleteTCPingResultsByClient("a"); err != nil {
		t.Fatalf("DeleteTCPingResultsByClient: %v", err)
	}
	if r, _ := store.GetTCPingResults("a"); len(r) != 0 {
		t.Fatalf("client a still has %d records", len(r))
	}
	if r, _ := store.GetTCPingResults("a_b"); len(r) != 1 {
		t.Fatalf("client a_b lost records: %d", len(r))
	}
	if err := store.DeleteTCPingResultsByTarget("x:1"); err != nil {
		t.Fatalf("DeleteTCPingResultsByTarget: %v", err)
	}
	if r, _ := store.GetTCPingResults("b", "x:1"); len(r) != 0 {
		t.Fatalf("target x:1 of b still present")
	}
	if r, _ := store.GetTCPingResults("a_b"); len(r) != 0 {
		t.Fatalf("target x:1 of a_b still present")
	}
}

func TestDeleteTCPingKeysChunksLargeSets(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	lat := 1.0
	var batch []TCPingResult
	for i := 0; i < 2*tcpingDeleteChunk+7; i++ {
		batch = append(batch, TCPingResult{ClientID: "big", Target: "t:1", Latency: &lat, Timestamp: now.Add(-time.Duration(i) * time.Second), ExactTimestamp: true})
	}
	if err := store.SaveClientPushBatch(SystemMetric{ID: "big", Name: "big"}, batch); err != nil {
		t.Fatalf("SaveClientPushBatch: %v", err)
	}
	if err := store.DeleteTCPingResultsByClient("big"); err != nil {
		t.Fatalf("DeleteTCPingResultsByClient: %v", err)
	}
	if r, _ := store.GetTCPingResults("big"); len(r) != 0 {
		t.Fatalf("%d records survived the chunked delete", len(r))
	}
}

// --- privacy: a plain save keeps the existing link, its expiry and its duration ---

func TestPrivacySaveWithoutNewTokenKeepsExpiryAndDuration(t *testing.T) {
	store := newTestStore(t)
	authTokensMu.Lock()
	authTokens["test-admin-token"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() {
		authTokensMu.Lock()
		delete(authTokens, "test-admin-token")
		authTokensMu.Unlock()
	})

	// Generate a 24 h link.
	rr := httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{
		"enabled": true, "share_token": "tok-1", "expires_in_seconds": 86400,
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: status %d body %s", rr.Code, rr.Body.String())
	}
	first, _ := store.GetPrivacyConfig()
	if first.ShareToken != "tok-1" || first.ExpiresInSeconds != 86400 || first.TokenExpires.IsZero() {
		t.Fatalf("unexpected stored config after generate: %+v", first)
	}

	// Plain save (toggle only) as the fixed admin UI sends it.
	time.Sleep(1100 * time.Millisecond)
	rr = httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{
		"enabled": false, "share_token": "tok-1", "expires_in_seconds": 0, "token_expires": first.TokenExpires.Format(time.RFC3339),
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("plain save: status %d body %s", rr.Code, rr.Body.String())
	}
	second, _ := store.GetPrivacyConfig()
	if second.Enabled || second.ShareToken != "tok-1" {
		t.Fatalf("plain save changed token/enabled: %+v", second)
	}
	if d := second.TokenExpires.Sub(first.TokenExpires); d < -time.Second || d > time.Second {
		t.Fatalf("plain save restarted the countdown: %v vs %v", second.TokenExpires, first.TokenExpires)
	}
	if second.ExpiresInSeconds != 86400 {
		t.Fatalf("plain save lost the saved duration: %d", second.ExpiresInSeconds)
	}

	// Empty share_token is still an explicit revoke.
	rr = httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{"enabled": true, "share_token": ""}))
	third, _ := store.GetPrivacyConfig()
	if third.ShareToken != "" || !third.TokenExpires.IsZero() {
		t.Fatalf("revoke did not clear the link: %+v", third)
	}
}

// --- server-driven tcping reaches pull-mode agents ----------------------------

func TestTCPingPullGateDistinguishesOwnPollFromPush(t *testing.T) {
	now := time.Now()
	fresh := &SystemMetric{ID: "a", UpdatedAt: now.Add(-2 * time.Second)}

	// Pure pull-mode agent: our poll wrote the record moments ago.
	pulled := ClientInfo{ID: "a", LastPollAt: now.Add(-2 * time.Second)}
	if tcpingPullSuppressed(pulled, fresh, now) {
		t.Fatalf("a record written by our own poll must not suppress the tcping pull")
	}
	// Never polled, yet the record is fresh: a push wrote it (re-registration window).
	if !tcpingPullSuppressed(ClientInfo{ID: "a"}, fresh, now) {
		t.Fatalf("a fresh record we did not poll must suppress the pull")
	}
	// Poll happened, but a newer write landed afterwards: something else is pushing.
	stalePoll := ClientInfo{ID: "a", LastPollAt: now.Add(-8 * time.Second)}
	if !tcpingPullSuppressed(stalePoll, fresh, now) {
		t.Fatalf("a write newer than our last poll must suppress the pull")
	}
	// Old record: never suppressed.
	old := &SystemMetric{ID: "a", UpdatedAt: now.Add(-30 * time.Second)}
	if tcpingPullSuppressed(ClientInfo{ID: "a"}, old, now) {
		t.Fatalf("a stale record must not suppress the pull")
	}
}

// --- connect-time snapshot reuse must never serve stale data -----------------

func TestSSEBrokerLatestSnapshotAgeAndPerView(t *testing.T) {
	b := NewSSEBroker()
	if _, ok := b.LatestSnapshot(SSEViewPublic); ok {
		t.Fatalf("empty broker must not return a snapshot")
	}
	b.RememberSnapshot(SSEViewAdmin, "admin-1", time.Now())
	if _, ok := b.LatestSnapshot(SSEViewPublic); ok {
		t.Fatalf("a payload remembered for the admin view must not be served to the public view")
	}
	if p, ok := b.LatestSnapshot(SSEViewAdmin); !ok || p != "admin-1" {
		t.Fatalf("fresh admin payload not returned: %q %v", p, ok)
	}
	b.BroadcastByView(map[SSEView]string{SSEViewPublic: "pub-2", SSEViewAdmin: "admin-2"})
	if p, _ := b.LatestSnapshot(SSEViewPublic); p != "pub-2" {
		t.Fatalf("broadcast payload not remembered: %q", p)
	}
	b.mu.Lock()
	for v := range b.latestAt {
		b.latestAt[v] = time.Now().Add(-2 * sseSnapshotMaxAge)
	}
	b.mu.Unlock()
	if _, ok := b.LatestSnapshot(SSEViewPublic); ok {
		t.Fatalf("a payload older than %v must not prime a new subscriber", sseSnapshotMaxAge)
	}
}

// --- 2026-09 audit fixes -------------------------------------------------------

func TestSSEBrokerPerIPCapSkipsPrivateAndLoopbackAddresses(t *testing.T) {
	b := NewSSEBroker()
	for _, ip := range []string{"172.17.0.1", "10.8.0.2", "127.0.0.1", "fd00::1"} {
		for i := 0; i < b.maxPerIP+5; i++ {
			if _, err := b.Subscribe(SSEViewPublic, ip); err != nil {
				t.Fatalf("Subscribe(%s #%d) must not hit the per-IP cap: %v", ip, i, err)
			}
		}
	}
	if !perIPCapApplies("203.0.113.7") || !perIPCapApplies("2001:db8::1") {
		t.Fatalf("public addresses must be capped individually")
	}
	if perIPCapApplies("192.168.1.9") || perIPCapApplies("") || perIPCapApplies("garbage") {
		t.Fatalf("private, empty or unparsable addresses must not be capped individually")
	}
}

func TestSSEBrokerTotalCapStillBoundsPrivateAddresses(t *testing.T) {
	t.Setenv("SSE_MAX_STREAMS", "5")
	b := NewSSEBroker()
	for i := 0; i < 5; i++ {
		if _, err := b.Subscribe(SSEViewPublic, "172.17.0.1"); err != nil {
			t.Fatalf("Subscribe #%d: %v", i, err)
		}
	}
	if _, err := b.Subscribe(SSEViewPublic, "172.17.0.1"); err == nil {
		t.Fatalf("total cap must still apply to private addresses")
	}
}

func TestRememberSnapshotKeepsNewerBroadcast(t *testing.T) {
	b := NewSSEBroker()
	builtAt := time.Now().Add(-50 * time.Millisecond)
	b.BroadcastByView(map[SSEView]string{SSEViewPublic: "broadcast"})
	if got := b.RememberSnapshot(SSEViewPublic, "older-prime", builtAt); got != "broadcast" {
		t.Fatalf("RememberSnapshot returned %q, want the newer broadcast", got)
	}
	if p, ok := b.LatestSnapshot(SSEViewPublic); !ok || p != "broadcast" {
		t.Fatalf("latest = %q,%v; the older prime must not overwrite the broadcast", p, ok)
	}
	if got := b.RememberSnapshot(SSEViewPublic, "newer-prime", time.Now()); got != "newer-prime" {
		t.Fatalf("a prime built after the broadcast must be stored, got %q", got)
	}
}

func TestMarkOfflineKeepsUpdatedAtAndOtherFields(t *testing.T) {
	store := newTestStore(t)
	stamp := time.Now().UTC().Add(-8 * time.Second)
	if err := store.Upsert(SystemMetric{ID: "pull1", Name: "Pull", CPU: 42, UpdatedAt: stamp, Tags: []string{"a"}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.MarkOffline("pull1"); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	m, _ := store.Get("pull1")
	if !m.Alert || !m.UpdatedAt.Equal(stamp) || m.CPU != 42 || m.Name != "Pull" || len(m.Tags) != 1 {
		t.Fatalf("MarkOffline must only set Alert: %+v", m)
	}
	if err := store.MarkOffline("missing"); err != nil {
		t.Fatalf("MarkOffline on an unknown id must be a no-op: %v", err)
	}
}

func TestSetTCPingLatestMergesWithoutClobbering(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "pull2", Name: "Pull 2", CPU: 10}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// A poll lands after the tcping goroutine would have read the record.
	if err := store.UpsertFromAgent(SystemMetric{ID: "pull2", CPU: 90, UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("UpsertFromAgent: %v", err)
	}
	now := time.Now().UTC()
	if err := store.SetTCPingLatest("pull2", "1.1.1.1:443", TCPingTargetData{Latency: 12, Timestamp: now}); err != nil {
		t.Fatalf("SetTCPingLatest: %v", err)
	}
	m, _ := store.Get("pull2")
	if m.CPU != 90 || m.Name != "Pull 2" {
		t.Fatalf("SetTCPingLatest must not overwrite concurrent writes: %+v", m)
	}
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 12 {
		t.Fatalf("latest tcping not stored: %+v", m.TCPingData)
	}
	// An older sample never replaces a newer stored one.
	if err := store.SetTCPingLatest("pull2", "1.1.1.1:443", TCPingTargetData{Latency: 99, Timestamp: now.Add(-time.Minute)}); err != nil {
		t.Fatalf("SetTCPingLatest(old): %v", err)
	}
	m, _ = store.Get("pull2")
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 12 {
		t.Fatalf("older sample replaced newer one: %+v", got)
	}
	if err := store.SetTCPingLatest("nope", "x", TCPingTargetData{}); err != nil {
		t.Fatalf("unknown id must be a no-op: %v", err)
	}
}

func pushTCPingBatch(t *testing.T, store *Store, registry *ClientRegistry, ipCache *IPCountryCache, id string, samples []map[string]interface{}) {
	t.Helper()
	body := map[string]interface{}{"id": id, "name": "x", "uptime": 5, "location": "US", "tcping_results": samples}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestClientPushLongIntervalBacklogKeepsStampsAndIgnoresRetry(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 300}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "slow", Name: "Slow"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	now := time.Now().UTC()
	newest := now.Add(-4 * time.Minute) // healthy clock, 5 min interval, server was down
	samples := []map[string]interface{}{
		{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": newest.Add(-10 * time.Minute).Format(time.RFC3339Nano)},
		{"target": "1.1.1.1:443", "latency": 11, "success": true, "measured_at": newest.Add(-5 * time.Minute).Format(time.RFC3339Nano)},
		{"target": "1.1.1.1:443", "latency": 12, "success": true, "measured_at": newest.Format(time.RFC3339Nano)},
	}
	pushTCPingBatch(t, store, registry, ipCache, "slow", samples)
	results, err := store.GetTCPingResults("slow", "1.1.1.1:443")
	if err != nil || len(results) != 3 {
		t.Fatalf("results = %d (%v), want 3", len(results), err)
	}
	if d := results[2].Timestamp.Sub(newest); d < -time.Second || d > time.Second {
		t.Fatalf("a 4 min old newest sample with a 5 min interval is not skew; got %v want %v", results[2].Timestamp, newest)
	}
	// The agent's retry of the same batch (push timed out after commit).
	pushTCPingBatch(t, store, registry, ipCache, "slow", samples)
	results, _ = store.GetTCPingResults("slow", "1.1.1.1:443")
	if len(results) != 3 {
		t.Fatalf("retry stored duplicates: %d rows", len(results))
	}
}

func TestClientPushRetryOfSkewedBatchIsNotStoredTwice(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "skewed", Name: "Skewed"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	newest := time.Now().UTC().Add(-10 * time.Minute) // clock 10 min behind
	samples := []map[string]interface{}{
		{"target": "1.1.1.1:443", "latency": 10, "success": true, "measured_at": newest.Add(-time.Minute).Format(time.RFC3339Nano)},
		{"target": "1.1.1.1:443", "latency": 12, "success": true, "measured_at": newest.Format(time.RFC3339Nano)},
	}
	pushTCPingBatch(t, store, registry, ipCache, "skewed", samples)
	pushTCPingBatch(t, store, registry, ipCache, "skewed", samples)
	results, _ := store.GetTCPingResults("skewed", "1.1.1.1:443")
	if len(results) != 2 {
		t.Fatalf("skewed retry stored duplicates: %d rows", len(results))
	}
	// A genuinely new batch is still stored.
	next := []map[string]interface{}{{"target": "1.1.1.1:443", "latency": 13, "success": true, "measured_at": newest.Add(time.Minute).Format(time.RFC3339Nano)}}
	pushTCPingBatch(t, store, registry, ipCache, "skewed", next)
	results, _ = store.GetTCPingResults("skewed", "1.1.1.1:443")
	if len(results) != 3 {
		t.Fatalf("new batch after a retry must be stored: %d rows", len(results))
	}
	// Legacy agents (no measured_at) are never deduplicated by value.
	legacy := []map[string]interface{}{{"target": "1.1.1.1:443", "latency": 7, "success": true}}
	pushTCPingBatch(t, store, registry, ipCache, "skewed", legacy)
	pushTCPingBatch(t, store, registry, ipCache, "skewed", legacy)
	results, _ = store.GetTCPingResults("skewed", "1.1.1.1:443")
	if len(results) != 5 {
		t.Fatalf("legacy batches must all be stored: %d rows", len(results))
	}
}

func TestClientPushDropsRemovedTargetsFromLatestMap(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	stale := time.Now().UTC().Add(-time.Minute)
	if err := store.Upsert(SystemMetric{ID: "pruned", Name: "Pruned", TCPingData: map[string]TCPingTargetData{
		"1.1.1.1:443": {Latency: 5, Timestamp: stale},
		"9.9.9.9:53":  {Latency: 7, Timestamp: stale}, // removed by the admin meanwhile
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	pushTCPingBatch(t, store, registry, ipCache, "pruned", nil)
	m, _ := store.Get("pruned")
	if _, ok := m.TCPingData["9.9.9.9:53"]; ok {
		t.Fatalf("removed target resurrected: %+v", m.TCPingData)
	}
	if _, ok := m.TCPingData["1.1.1.1:443"]; !ok {
		t.Fatalf("configured target must be kept: %+v", m.TCPingData)
	}
	copyMap := map[string]TCPingTargetData{"1.1.1.1:443": {}, "gone:1": {}}
	pruneTCPingDataToConfig(store, copyMap)
	if _, ok := copyMap["gone:1"]; ok || len(copyMap) != 1 {
		t.Fatalf("pruneTCPingDataToConfig: %+v", copyMap)
	}
}

func TestPrivacySaveWithTokenOnlyKeepsStoredExpiry(t *testing.T) {
	store := newTestStore(t)
	authTokensMu.Lock()
	authTokens["test-admin-token"] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() {
		authTokensMu.Lock()
		delete(authTokens, "test-admin-token")
		authTokensMu.Unlock()
	})
	expires := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true, ShareToken: "tok123", TokenExpires: expires, ExpiresInSeconds: 7200}); err != nil {
		t.Fatalf("SavePrivacyConfig: %v", err)
	}
	rr := httptest.NewRecorder()
	handleSetPrivacyConfig(store, rr, adminRequest(t, http.MethodPost, "/api/privacy/config", map[string]interface{}{"enabled": true, "share_token": "tok123"}))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	cfg, _ := store.GetPrivacyConfig()
	if !cfg.TokenExpires.Equal(expires) || cfg.ExpiresInSeconds != 7200 {
		t.Fatalf("token-only save must keep the stored expiry: %+v", cfg)
	}
}

func TestMergeAdminOwnedTCPingRules(t *testing.T) {
	newer := time.Now().UTC()
	older := newer.Add(-time.Minute)
	stored := &SystemMetric{Name: "Stored", TCPingData: map[string]TCPingTargetData{
		"a:1": {Latency: 1, Timestamp: newer}, // newer stored copy
		"b:2": {Latency: 2, Timestamp: older}, // only stored
		"z:9": {Latency: 9, Timestamp: newer}, // target removed by the admin
	}}
	incoming := SystemMetric{Name: "Agent", TCPingData: map[string]TCPingTargetData{
		"a:1": {Latency: 10, Timestamp: older}, // fresh sample, older stamp (skewed clock)
		"c:3": {Latency: 30, Timestamp: older}, // copied from an earlier read
	}, TCPingFresh: map[string]struct{}{"a:1": {}}}
	allowed := map[string]struct{}{"a:1": {}, "b:2": {}, "c:3": {}}
	mergeAdminOwned(&incoming, stored, allowed)
	if incoming.Name != "Stored" {
		t.Fatalf("admin-owned name not merged: %+v", incoming)
	}
	if got := incoming.TCPingData["a:1"]; got.Latency != 10 {
		t.Fatalf("fresh sample must win over a newer stored copy: %+v", got)
	}
	if got, ok := incoming.TCPingData["b:2"]; !ok || got.Latency != 2 {
		t.Fatalf("stored-only entry must be kept: %+v", incoming.TCPingData)
	}
	if got := incoming.TCPingData["c:3"]; got.Latency != 30 {
		t.Fatalf("incoming-only entry must be kept: %+v", got)
	}
	if _, ok := incoming.TCPingData["z:9"]; ok {
		t.Fatalf("removed target must be dropped: %+v", incoming.TCPingData)
	}
	// Without a known target set nothing is dropped, and a copied entry
	// (not fresh) never overrides a newer stored one.
	copyOnly := SystemMetric{TCPingData: map[string]TCPingTargetData{"a:1": {Latency: 5, Timestamp: older}}}
	mergeAdminOwned(&copyOnly, stored, nil)
	if got := copyOnly.TCPingData["a:1"]; got.Latency != 1 {
		t.Fatalf("copied entry must not override a newer stored one: %+v", got)
	}
	if _, ok := copyOnly.TCPingData["z:9"]; !ok {
		t.Fatalf("nil allowed set must keep every entry: %+v", copyOnly.TCPingData)
	}
}

func TestClientPushFreshSampleReplacesFutureStampedEntry(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	ipCache := NewIPCountryCache()
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	future := time.Now().UTC().Add(90 * time.Second)
	if err := store.Upsert(SystemMetric{ID: "fz", Name: "Frozen", TCPingData: map[string]TCPingTargetData{
		"1.1.1.1:443": {Latency: 77, Timestamp: future},
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	pushTCPingBatch(t, store, registry, ipCache, "fz", []map[string]interface{}{
		{"target": "1.1.1.1:443", "latency": 12, "success": true, "measured_at": time.Now().UTC().Format(time.RFC3339Nano)},
	})
	m, _ := store.Get("fz")
	if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 12 {
		t.Fatalf("the card would stay frozen on the future-stamped value: %+v", got)
	}
}
