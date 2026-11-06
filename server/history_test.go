package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setSwitches(t *testing.T, store *Store, resource, latency bool) {
	t.Helper()
	withAdminToken(t, "test-admin-token")
	rr := httptest.NewRecorder()
	handleSetNavbarConfig(store, rr, adminRequest(t, http.MethodPost, "/api/navbar/config", map[string]interface{}{"text": "Pulse", "resource_history": resource, "latency_view": latency}))
	if rr.Code != http.StatusOK {
		t.Fatalf("save switches: %d %s", rr.Code, rr.Body.String())
	}
}

// Both switches are off on a new install, and public (the page reads them before drawing).
func TestHistorySwitchesDefaultOffAndPublic(t *testing.T) {
	store := newTestStore(t)
	rr := httptest.NewRecorder()
	handleGetNavbarConfig(store, rr, httptest.NewRequest(http.MethodGet, "/api/navbar/config", nil))
	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"resource_history", "resource_average", "latency_view"} {
		if v, ok := got[k]; !ok || v != false {
			t.Fatalf("%s should be present and false by default: %s", k, rr.Body.String())
		}
	}
	setSwitches(t, store, true, true)
	rr = httptest.NewRecorder()
	handleGetNavbarConfig(store, rr, httptest.NewRequest(http.MethodGet, "/api/navbar/config", nil))
	got = nil
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["resource_history"] != true || got["latency_view"] != true || got["resource_average"] != false {
		t.Fatalf("saved switches not public: %s", rr.Body.String())
	}
}

// The averaged resource charts are their own switch, off by default (every
// recorded minute), saved and public on its own.
func TestResourceAverageSwitch(t *testing.T) {
	store := newTestStore(t)
	withAdminToken(t, "test-admin-token")
	save := func(body map[string]interface{}) {
		t.Helper()
		rr := httptest.NewRecorder()
		handleSetNavbarConfig(store, rr, adminRequest(t, http.MethodPost, "/api/navbar/config", body))
		if rr.Code != http.StatusOK {
			t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
		}
	}
	public := func() map[string]interface{} {
		t.Helper()
		rr := httptest.NewRecorder()
		handleGetNavbarConfig(store, rr, httptest.NewRequest(http.MethodGet, "/api/navbar/config", nil))
		var got map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return got
	}
	save(map[string]interface{}{"text": "Pulse", "resource_history": true, "resource_average": true})
	if got := public(); got["resource_average"] != true || got["resource_history"] != true {
		t.Fatalf("switched on: %v", got)
	}
	if v, _ := public()["shared_secret"].(string); v != "" {
		t.Fatal("the public config must not carry the shared secret")
	}
	// An older admin page sends no resource_average: the charts go back to minutes.
	save(map[string]interface{}{"text": "Pulse", "resource_history": true})
	if got := public(); got["resource_average"] != false || got["resource_history"] != true {
		t.Fatalf("absent means off: %v", got)
	}
}

// Recorded whatever the switch (it only shows the history): one averaged
// sample per server and minute, the current minute kept until it ends.
func TestResourceRecorderMinutes(t *testing.T) {
	resourceRec.reset()
	t.Cleanup(func() { resourceRec.reset() })
	base := time.Unix(1_800_000_000, 0).Truncate(time.Minute)
	for i, cpu := range []float64{10, 20, 30} {
		resourceRec.add(SystemMetric{ID: "a", CPU: cpu, Memory: 40, Disk: 30, NetInMBps: 0.5, NetOutMBps: 0.25}, base.Add(time.Duration(i*15)*time.Second))
	}
	resourceRec.add(SystemMetric{ID: "a", CPU: 99}, base.Add(70*time.Second)) // the next minute
	got := resourceRec.take(base.Unix()/60 + 1)
	if len(got) != 1 || got[0].ID != "a" || got[0].Minute != base.Unix()/60 || got[0].CPU != 20 || got[0].Mem != 40 || got[0].In != 0.5 || got[0].Out != 0.25 {
		t.Fatalf("minute average: %+v", got)
	}
	if left := resourceRec.take(base.Unix()/60 + 100); len(left) != 1 || left[0].CPU != 99 {
		t.Fatalf("the next minute: %+v", left)
	}
}

// Stored minutes come back oldest first; old ones are pruned; a deleted
// server's are removed; a server that does not exist gets none.
func TestResourceHistoryStore(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "srv", Name: "srv"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Minute)
	m := func(d time.Duration) int64 { return now.Add(d).Unix() / 60 }
	err := store.SaveResourceSamples([]resourceSample{
		{ID: "srv", Minute: m(-2 * time.Minute), CPU: 2, Mem: 50, Disk: 30, In: 1, Out: 2},
		{ID: "srv", Minute: m(-1 * time.Minute), CPU: 3, Mem: 51, Disk: 30, In: 1, Out: 2},
		{ID: "srv", Minute: m(-25 * time.Hour), CPU: 9},
		{ID: "ghost", Minute: m(-1 * time.Minute), CPU: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetResourceHistory("srv", now.Add(-24*time.Hour))
	if err != nil || len(got) != 2 || got[0].CPU != 2 || got[1].CPU != 3 || got[1].Mem != 51 {
		t.Fatalf("read: %v %+v", err, got)
	}
	if ghost, _ := store.GetResourceHistory("ghost", now.Add(-48*time.Hour)); len(ghost) != 0 {
		t.Fatalf("stored for an unknown server: %+v", ghost)
	}
	if err := store.PruneResourceHistory(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	all, _ := store.GetResourceHistory("srv", now.Add(-48*time.Hour))
	if len(all) != 2 {
		t.Fatalf("prune kept %d samples, want the 2 recent", len(all))
	}
	if err := store.DeleteResourceHistory("srv"); err != nil {
		t.Fatal(err)
	}
	if left, _ := store.GetResourceHistory("srv", now.Add(-48*time.Hour)); len(left) != 0 {
		t.Fatalf("delete left %d samples", len(left))
	}
}

func TestResourceHistoryEndpoint(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "srv", Name: "srv"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Minute)
	_ = store.SaveResourceSamples([]resourceSample{{ID: "srv", Minute: now.Add(-time.Minute).Unix() / 60, CPU: 12.345, Mem: 40, Disk: 30, In: 0.5, Out: 0.25}})
	get := func(q string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleGetResourceHistory(store, rr, httptest.NewRequest(http.MethodGet, "/api/resource/history"+q, nil))
		return rr
	}
	if rr := get("?client_id=srv"); rr.Code != http.StatusNotFound {
		t.Fatalf("switched off: want 404, got %d", rr.Code)
	}
	setSwitches(t, store, true, false)
	rr := get("?client_id=srv")
	var body resourceHistoryResponse
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil || body.Interval != 60 || len(body.Points) != 1 || body.Points[0][1] != 12.35 || body.Points[0][4] != 0.5 {
		t.Fatalf("on: %d %s", rr.Code, rr.Body.String())
	}
	if rr := get("?client_id=nope"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown server: want 404, got %d", rr.Code)
	}
	if err := store.Upsert(SystemMetric{ID: "hidden", Name: "hidden", HideOnHome: true}); err != nil {
		t.Fatal(err)
	}
	_ = store.SaveResourceSamples([]resourceSample{{ID: "hidden", Minute: now.Add(-time.Minute).Unix() / 60, CPU: 1}})
	if rr := get("?client_id=hidden"); rr.Code != http.StatusNotFound {
		t.Fatalf("a server hidden from the homepage: want 404, got %d", rr.Code)
	}
	if rr := get(""); rr.Code != http.StatusBadRequest {
		t.Fatalf("no client_id: want 400, got %d", rr.Code)
	}
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if rr := get("?client_id=srv"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("privacy mode, no token: want 401, got %d", rr.Code)
	}
}

func TestLatencySummary(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "srv", Name: "srv"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ms := func(v float64) *float64 { return &v }
	for i, lat := range []*float64{ms(100), ms(200), nil, ms(5000)} {
		if err := store.SaveTCPingResult(TCPingResult{ClientID: "srv", Target: "a:80", Latency: lat, Timestamp: now.Add(-time.Duration(10+i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.SaveTCPingResult(TCPingResult{ClientID: "srv", Target: "a:80", Latency: ms(999), Timestamp: now.Add(-2 * time.Hour)}) // outside the hour
	_ = store.SaveTCPingResult(TCPingResult{ClientID: "srv", Target: "b:80", Latency: nil, Timestamp: now.Add(-5 * time.Minute)})
	// left out: a target no longer configured, a server hidden from the
	// homepage, one whose TCPing the homepage does not show, a deleted one
	_ = store.SaveTCPingResult(TCPingResult{ClientID: "srv", Target: "old:80", Latency: ms(10), Timestamp: now.Add(-5 * time.Minute)})
	for _, m := range []SystemMetric{{ID: "hidden", Name: "hidden", HideOnHome: true}, {ID: "notcp", Name: "notcp", HideTCPing: true}} {
		if err := store.Upsert(m); err != nil {
			t.Fatal(err)
		}
		_ = store.SaveTCPingResult(TCPingResult{ClientID: m.ID, Target: "a:80", Latency: ms(10), Timestamp: now.Add(-5 * time.Minute)})
	}
	_ = store.SaveTCPingResult(TCPingResult{ClientID: "gone", Target: "a:80", Latency: ms(10), Timestamp: now.Add(-5 * time.Minute)})
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "A", Address: "a:80"}, {Name: "B", Address: "b:80"}}}); err != nil {
		t.Fatal(err)
	}
	latencySummaryCache.Lock()
	latencySummaryCache.body = nil
	latencySummaryCache.Unlock()
	get := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleGetLatencySummary(store, rr, httptest.NewRequest(http.MethodGet, "/api/tcping/summary", nil))
		return rr
	}
	if rr := get(); rr.Code != http.StatusNotFound {
		t.Fatalf("switched off: want 404, got %d", rr.Code)
	}
	setSwitches(t, store, false, true)
	rr := get()
	var body latencySummaryResponse
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil {
		t.Fatalf("on: %d %s", rr.Code, rr.Body.String())
	}
	a := body.Servers["srv"]["a:80"]
	if a.N != 4 || a.Avg == nil || *a.Avg != 150 || a.Loss != 50 {
		t.Fatalf("a:80 over the hour: %+v (avg %v)", a, a.Avg)
	}
	b := body.Servers["srv"]["b:80"]
	if b.N != 1 || b.Avg != nil || b.Loss != 100 {
		t.Fatalf("b:80 all lost: %+v", b)
	}
	if _, ok := body.Servers["srv"]["old:80"]; ok || len(body.Servers) != 1 {
		t.Fatalf("answered beyond the homepage's servers and targets: %s", rr.Body.String())
	}
}

// An older agent's report (POST /api/metrics) counts toward the minute as a
// push does.
func TestResourceRecorderLegacyIngest(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "old", Name: "Old"}); err != nil {
		t.Fatal(err)
	}
	resourceRec.reset()
	t.Cleanup(func() { resourceRec.reset() })
	rr := httptest.NewRecorder()
	handleIngestMetric(store, nil, rr, jsonRequest(http.MethodPost, "/api/metrics", "", map[string]interface{}{"id": "old", "name": "Old", "uptime": 60, "cpu": 42.0, "memory": 50.0, "disk": 20.0}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", rr.Code, rr.Body.String())
	}
	got := resourceRec.take(time.Now().Unix()/60 + 1)
	if len(got) != 1 || got[0].ID != "old" || got[0].CPU != 42 || got[0].Mem != 50 {
		t.Fatalf("legacy report not recorded: %+v", got)
	}
}
