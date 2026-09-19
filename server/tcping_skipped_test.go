package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A probe the monitored host cannot even attempt (classically an IPv6 target
// on a machine without IPv6, where every dial returns ENETUNREACH at once) is
// reported by the agent with skipped=true. It must never reach the history
// bucket: counted as a failed probe it showed the node at ~50 % packet loss.
// These tests pin the whole server-side contract of that flag.

const (
	skipV4Target = "1.1.1.1:443"
	skipV6Target = "[2606:4700:4700::1111]:443"
)

// tcpingSkippedFixture creates a system with both targets configured.
func tcpingSkippedFixture(t *testing.T, id string) (*Store, *ClientRegistry, *IPCountryCache) {
	t.Helper()
	resetTCPingCacheForTest(t)
	store := newTestStore(t)
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{
		{Name: "cf4", Address: skipV4Target},
		{Name: "cf6", Address: skipV6Target},
	}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: id, Name: "v4 only"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	return store, NewClientRegistry(), NewIPCountryCache()
}

// tcpingStats runs the public history endpoint for every target of a client
// and returns the computed statistics.
func tcpingStats(t *testing.T, store *Store, id string) TCPingStats {
	t.Helper()
	resetTCPingCacheForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/tcping/history?client_id="+id, nil)
	rr := httptest.NewRecorder()
	handleGetTCPingHistory(store, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("history: status %d body %s", rr.Code, rr.Body.String())
	}
	var resp TCPingHistoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	return resp.Stats
}

func TestClientPushSkippedTargetIsNotPacketLoss(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "v4only")
	now := time.Now().UTC()
	pushTCPingBatch(t, store, registry, ipCache, "v4only", []map[string]interface{}{
		{"target": skipV4Target, "latency": 10, "success": true, "measured_at": now.Add(-20 * time.Second).Format(time.RFC3339Nano)},
		{"target": skipV6Target, "latency": 0, "success": false, "skipped": true, "measured_at": now.Add(-20 * time.Second).Format(time.RFC3339Nano)},
		// success + skipped is contradictory: the probe evidently ran, so the
		// flag is ignored and the sample is stored like any measurement.
		{"target": skipV4Target, "latency": 9, "success": true, "skipped": true, "measured_at": now.Add(-5 * time.Second).Format(time.RFC3339Nano)},
	})

	if rows, err := store.GetTCPingResults("v4only", skipV6Target); err != nil || len(rows) != 0 {
		t.Fatalf("a skipped probe must not be stored as history: %d rows (%v)", len(rows), err)
	}
	rows, err := store.GetTCPingResults("v4only", skipV4Target)
	if err != nil || len(rows) != 2 {
		t.Fatalf("v4 history = %d rows (%v), want 2", len(rows), err)
	}
	if stats := tcpingStats(t, store, "v4only"); stats.PacketLossRate != 0 {
		t.Fatalf("packet_loss_rate = %v, want 0: a skipped target is not loss", stats.PacketLossRate)
	}

	m, _ := store.Get("v4only")
	marker, ok := m.TCPingData[skipV6Target]
	if !ok || !marker.Skipped || marker.Latency != 0 {
		t.Fatalf("v6 latest entry = %+v (present=%v), want a skipped marker with no latency", marker, ok)
	}
	live, ok := m.TCPingData[skipV4Target]
	if !ok || live.Skipped || live.Latency != 9 {
		t.Fatalf("v4 latest entry = %+v (present=%v), want the newest measurement", live, ok)
	}
}

func TestClientPushSuccessReplacesSkippedMarker(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "v6later")
	now := time.Now().UTC()
	pushTCPingBatch(t, store, registry, ipCache, "v6later", []map[string]interface{}{
		{"target": skipV6Target, "success": false, "skipped": true, "measured_at": now.Add(-30 * time.Second).Format(time.RFC3339Nano)},
	})
	m, _ := store.Get("v6later")
	if got := m.TCPingData[skipV6Target]; !got.Skipped {
		t.Fatalf("marker not stored: %+v", got)
	}

	// IPv6 came up on the machine: the next real sample takes over.
	pushTCPingBatch(t, store, registry, ipCache, "v6later", []map[string]interface{}{
		{"target": skipV6Target, "latency": 21, "success": true, "measured_at": now.Add(-10 * time.Second).Format(time.RFC3339Nano)},
	})
	m, _ = store.Get("v6later")
	got := m.TCPingData[skipV6Target]
	if got.Skipped || got.Latency != 21 {
		t.Fatalf("a real sample must replace the marker: %+v", got)
	}
	rows, err := store.GetTCPingResults("v6later", skipV6Target)
	if err != nil || len(rows) != 1 {
		t.Fatalf("v6 history = %d rows (%v), want the one real sample", len(rows), err)
	}
	if rows[0].Latency == nil || *rows[0].Latency != 21 {
		t.Fatalf("stored history row = %+v", rows[0])
	}
}

func TestClientPushLatestEntryRuleForSkippedMarkers(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "backlog")
	now := time.Now().UTC()

	// Within one batch the newest sample wins whatever the order: a marker
	// after a newer measurement does not replace it, and a measurement after
	// an older marker does.
	pushTCPingBatch(t, store, registry, ipCache, "backlog", []map[string]interface{}{
		{"target": skipV4Target, "latency": 12, "success": true, "measured_at": now.Add(-20 * time.Second).Format(time.RFC3339Nano)},
		{"target": skipV4Target, "success": false, "skipped": true, "measured_at": now.Add(-90 * time.Second).Format(time.RFC3339Nano)},
	})
	m, _ := store.Get("backlog")
	if got := m.TCPingData[skipV4Target]; got.Skipped || got.Latency != 12 {
		t.Fatalf("an older marker in the same batch hid a newer measurement: %+v", got)
	}
	pushTCPingBatch(t, store, registry, ipCache, "backlog", []map[string]interface{}{
		{"target": skipV6Target, "success": false, "skipped": true, "measured_at": now.Add(-90 * time.Second).Format(time.RFC3339Nano)},
		{"target": skipV6Target, "latency": 7, "success": true, "measured_at": now.Add(-20 * time.Second).Format(time.RFC3339Nano)},
	})
	m, _ = store.Get("backlog")
	if got := m.TCPingData[skipV6Target]; got.Skipped || got.Latency != 7 {
		t.Fatalf("a newer measurement after a marker must win: %+v", got)
	}

	// Across batches the first sample of a batch replaces the stored entry
	// (like a measurement does), so a stored value can never freeze the card.
	pushTCPingBatch(t, store, registry, ipCache, "backlog", []map[string]interface{}{
		{"target": skipV6Target, "success": false, "skipped": true, "measured_at": now.Add(-10 * time.Second).Format(time.RFC3339Nano)},
	})
	m, _ = store.Get("backlog")
	if got := m.TCPingData[skipV6Target]; !got.Skipped {
		t.Fatalf("a marker in a new batch must replace the stored measurement: %+v", got)
	}
}

func TestLegacyTCPingSkippedStoresMarkerOnly(t *testing.T) {
	store, _, _ := tcpingSkippedFixture(t, "legacy")
	req := jsonRequest(http.MethodPost, "/api/tcping", "", map[string]interface{}{
		"client_id": "legacy", "target": skipV6Target, "latency": 0, "success": false, "skipped": true,
	})
	rr := httptest.NewRecorder()
	handleTCPingResult(store, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy skipped report: status %d body %s", rr.Code, rr.Body.String())
	}
	if rows, err := store.GetTCPingResults("legacy", skipV6Target); err != nil || len(rows) != 0 {
		t.Fatalf("a skipped report must not write history: %d rows (%v)", len(rows), err)
	}
	m, _ := store.Get("legacy")
	if got := m.TCPingData[skipV6Target]; !got.Skipped || got.Latency != 0 {
		t.Fatalf("legacy marker not stored: %+v", got)
	}

	// A plain failure is still a lost packet and still stored.
	req = jsonRequest(http.MethodPost, "/api/tcping", "", map[string]interface{}{
		"client_id": "legacy", "target": skipV4Target, "latency": 0, "success": false,
	})
	rr = httptest.NewRecorder()
	handleTCPingResult(store, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy failure: status %d body %s", rr.Code, rr.Body.String())
	}
	if rows, _ := store.GetTCPingResults("legacy", skipV4Target); len(rows) != 1 {
		t.Fatalf("a genuine failure must still be recorded: %d rows", len(rows))
	}
	if stats := tcpingStats(t, store, "legacy"); stats.PacketLossRate != 100 {
		t.Fatalf("packet_loss_rate = %v, want 100 for one genuine failure", stats.PacketLossRate)
	}
}

func TestPublicSnapshotSerialisesSkippedMarker(t *testing.T) {
	store, registry, ipCache := tcpingSkippedFixture(t, "snap")
	now := time.Now().UTC()
	pushTCPingBatch(t, store, registry, ipCache, "snap", []map[string]interface{}{
		{"target": skipV4Target, "latency": 10, "success": true, "measured_at": now.Add(-10 * time.Second).Format(time.RFC3339Nano)},
		{"target": skipV6Target, "success": false, "skipped": true, "measured_at": now.Add(-10 * time.Second).Format(time.RFC3339Nano)},
	})

	metrics, err := buildMetricsSnapshot(store, registry, false)
	if err != nil {
		t.Fatalf("buildMetricsSnapshot: %v", err)
	}
	body, err := json.Marshal(metrics)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var rows []struct {
		ID         string                            `json:"id"`
		TCPingData map[string]map[string]interface{} `json:"tcping_data"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	var data map[string]map[string]interface{}
	for _, row := range rows {
		if row.ID == "snap" {
			data = row.TCPingData
		}
	}
	if data == nil {
		t.Fatalf("system missing from the public snapshot: %s", body)
	}
	if skipped, _ := data[skipV6Target]["skipped"].(bool); !skipped {
		t.Fatalf("public snapshot must carry skipped:true for %s: %s", skipV6Target, body)
	}
	if _, present := data[skipV4Target]["skipped"]; present {
		t.Fatalf("a normal entry must not carry a skipped key: %s", body)
	}
	if latency, _ := data[skipV4Target]["latency"].(float64); latency != 10 {
		t.Fatalf("normal entry latency = %v, want 10: %s", latency, body)
	}
}

func TestSetTCPingLatestMergesSkippedMarker(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	if err := store.Upsert(SystemMetric{ID: "pull3", Name: "Pull 3", TCPingData: map[string]TCPingTargetData{
		skipV6Target: {Latency: 12, Timestamp: now.Add(-time.Minute)},
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// The newer marker replaces the measurement...
	if err := store.SetTCPingLatest("pull3", skipV6Target, TCPingTargetData{Timestamp: now, Skipped: true}); err != nil {
		t.Fatalf("SetTCPingLatest(marker): %v", err)
	}
	m, _ := store.Get("pull3")
	if got := m.TCPingData[skipV6Target]; !got.Skipped || got.Latency != 0 {
		t.Fatalf("marker not merged: %+v", got)
	}
	// ...an older one never does...
	if err := store.SetTCPingLatest("pull3", skipV6Target, TCPingTargetData{Timestamp: now.Add(-2 * time.Minute), Skipped: true}); err != nil {
		t.Fatalf("SetTCPingLatest(old marker): %v", err)
	}
	m, _ = store.Get("pull3")
	if got := m.TCPingData[skipV6Target]; !got.Timestamp.Equal(now) {
		t.Fatalf("older marker replaced the newer entry: %+v", got)
	}
	// ...and a later measurement clears the marker again.
	if err := store.SetTCPingLatest("pull3", skipV6Target, TCPingTargetData{Latency: 8, Timestamp: now.Add(time.Minute)}); err != nil {
		t.Fatalf("SetTCPingLatest(sample): %v", err)
	}
	m, _ = store.Get("pull3")
	if got := m.TCPingData[skipV6Target]; got.Skipped || got.Latency != 8 {
		t.Fatalf("marker not cleared by a real sample: %+v", got)
	}
	// The record is untouched otherwise.
	if m.Name != "Pull 3" {
		t.Fatalf("admin-owned fields clobbered: %+v", m)
	}
}
