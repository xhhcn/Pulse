package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPushDropsFarFutureStamps(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "clock")
	pushTCPingBatch(t, store, registry, ipCache, "clock", []map[string]interface{}{
		{"target": skipV4Target, "latency": 1234, "success": true, "measured_at": "9999-01-01T00:00:00Z"},
	})
	m, _ := store.Get("clock")
	if _, ok := m.TCPingData[skipV4Target]; ok {
		t.Fatalf("a far-future sample must not become the latest entry: %+v", m.TCPingData[skipV4Target])
	}
	if rows, _ := store.GetTCPingResults("clock", skipV4Target); len(rows) != 0 {
		t.Fatalf("a far-future sample must not be stored: %d rows", len(rows))
	}
	// A sane sample afterwards is accepted as usual.
	pushTCPingBatch(t, store, registry, ipCache, "clock", []map[string]interface{}{
		{"target": skipV4Target, "latency": 5, "success": true},
	})
	m, _ = store.Get("clock")
	if got := m.TCPingData[skipV4Target]; got.Latency != 5 {
		t.Fatalf("normal sample not stored after the bad one: %+v", got)
	}
}

func TestHistoryRejectsUnconfiguredTarget(t *testing.T) {
	resetTCPingCacheForTest(t)
	store, _, _ := tcpingSkippedFixture(t, "hist")
	get := func(q string) int {
		rr := httptest.NewRecorder()
		handleGetTCPingHistory(store, rr, httptest.NewRequest(http.MethodGet, "/api/tcping/history?client_id=hist"+q, nil))
		return rr.Code
	}
	if code := get("&target=evil.example%3A1"); code != http.StatusBadRequest {
		t.Fatalf("unconfigured target: %d", code)
	}
	if code := get("&target=" + skipV4Target); code != http.StatusOK {
		t.Fatalf("configured target: %d", code)
	}
	if code := get(""); code != http.StatusOK {
		t.Fatalf("all targets: %d", code)
	}
}

func TestAdminEditKeepsAgentDataAndPrunedTargets(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "edit")
	withAdminToken(t, "edit-admin")
	pushTCPingBatch(t, store, registry, ipCache, "edit", []map[string]interface{}{
		{"target": skipV4Target, "latency": 9, "success": true},
	})
	// The admin page read the record while the v4 target was still configured;
	// the target is then removed and a push lands before the edit is saved.
	before, _ := store.Get("edit")
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "v6", Address: skipV6Target}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.PruneTCPingTargets([]string{skipV4Target}); err != nil {
		t.Fatalf("PruneTCPingTargets: %v", err)
	}
	req := jsonRequest(http.MethodPost, "/api/clients/push", "", map[string]interface{}{"id": "edit", "name": "x", "uptime": 5, "location": "US", "cpu": 77})
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push: %d", rr.Code)
	}
	// Admin saves the edit from its stale copy: only the labels may change.
	req = adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{"id": "edit", "name": "Renamed", "tags": []string{"a", " b "}, "cpu": before.CPU})
	req.Header.Set("Authorization", "Bearer edit-admin")
	rr = httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("admin edit: %d %s", rr.Code, rr.Body.String())
	}
	m, _ := store.Get("edit")
	if m.Name != "Renamed" || len(m.Tags) != 2 || m.Tags[1] != "b" {
		t.Fatalf("labels not applied: %+v", m)
	}
	if m.CPU != 77 {
		t.Fatalf("admin edit reverted the agent's data: cpu=%v", m.CPU)
	}
	if _, resurrected := m.TCPingData[skipV4Target]; resurrected {
		t.Fatalf("admin edit resurrected a pruned target: %+v", m.TCPingData)
	}
	// Over-long labels are bounded.
	req = adminRequest(t, http.MethodPost, "/api/metrics", map[string]interface{}{"id": "edit", "name": strings.Repeat("n", 500), "tags": make([]string, 0)})
	req.Header.Set("Authorization", "Bearer edit-admin")
	rr = httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, req)
	m, _ = store.Get("edit")
	if len([]rune(m.Name)) != adminNameMaxRunes {
		t.Fatalf("name not bounded: %d runes", len([]rune(m.Name)))
	}
}

func TestAgentWriteOnDeletedSystemIsDropped(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "gone", Name: "Gone"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.Delete("gone"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.UpsertFromAgent(SystemMetric{ID: "gone", Name: "<img src=x onerror=alert(1)>", CPU: 5}); err != nil {
		t.Fatalf("UpsertFromAgent: %v", err)
	}
	if m, _ := store.Get("gone"); m != nil {
		t.Fatalf("an agent write must not recreate a deleted system: %+v", m)
	}
}

func TestBogusLatencyCountsAsLoss(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "bogus")
	pushTCPingBatch(t, store, registry, ipCache, "bogus", []map[string]interface{}{
		{"target": skipV4Target, "latency": -1e12, "success": true},
	})
	rows, _ := store.GetTCPingResults("bogus", skipV4Target)
	if len(rows) != 1 || rows[0].Latency != nil {
		t.Fatalf("a negative latency must be stored as a failure: %+v", rows)
	}
	if stats := tcpingStats(t, store, "bogus"); stats.PacketLossRate != 100 || stats.AvgLatency != 0 {
		t.Fatalf("stats = %+v, want 100%% loss and no average", stats)
	}
	m, _ := store.Get("bogus")
	if _, ok := m.TCPingData[skipV4Target]; ok {
		t.Fatalf("a bogus latency must not become the latest entry")
	}
}

func TestTCPingConfigIntervalIsClampedOnRead(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "a", Address: "1.1.1.1:53"}}, IntervalSecs: 0}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	cfg, err := store.GetTCPingConfig()
	if err != nil || cfg.IntervalSecs < 1 {
		t.Fatalf("interval not clamped: %+v (%v)", cfg, err)
	}
}

func TestLogThrottledLimitsPerKey(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	logThrottleMu.Lock()
	delete(logThrottleLast, "test:key")
	delete(logThrottleLast, "test:other")
	logThrottleMu.Unlock()
	for i := 0; i < 5; i++ {
		logThrottled("test:key", "line %d", i)
	}
	logThrottled("test:other", "other %q", "id\nwith newline")
	out := buf.String()
	if strings.Count(out, "line ") != 1 {
		t.Fatalf("expected one line for the key, got: %q", out)
	}
	if !strings.Contains(out, `"id\nwith newline"`) {
		t.Fatalf("ids must be quoted so a newline cannot forge a log line: %q", out)
	}
}

func TestAdminStreamsDoNotConsumeThePerIPCap(t *testing.T) {
	b := NewSSEBroker()
	b.maxPerIP = 1
	ip := "203.0.113.77"
	a1, err := b.Subscribe(SSEViewAdmin, ip)
	if err != nil {
		t.Fatalf("admin 1: %v", err)
	}
	a2, err := b.Subscribe(SSEViewAdmin, ip)
	if err != nil {
		t.Fatalf("admin 2: %v", err)
	}
	pub, err := b.Subscribe(SSEViewPublic, ip)
	if err != nil {
		t.Fatalf("a public viewer must still get its slot next to admin streams: %v", err)
	}
	if _, err := b.Subscribe(SSEViewPublic, ip); err == nil {
		t.Fatal("the per-IP cap must still apply to public viewers")
	}
	b.Unsubscribe(a1)
	b.Unsubscribe(a2)
	b.Unsubscribe(pub)
	if _, err := b.Subscribe(SSEViewPublic, ip); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
	_ = time.Second
}
