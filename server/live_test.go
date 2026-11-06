package main

// Tests of the agents' live state kept in memory and written behind (live.go).

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func liveTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	if liveFlushInterval == 0 {
		t.Skip("PULSE_LIVE_FLUSH=0")
	}
	path := filepath.Join(t.TempDir(), "metrics.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.live == nil {
		t.Fatal("overlay off")
	}
	return s, path
}

func storedRecord(t *testing.T, s *Store, id string) *SystemMetric {
	t.Helper()
	var m *SystemMetric
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket([]byte(bucketName)).Get([]byte(id)); v != nil {
			m = &SystemMetric{}
			_ = json.Unmarshal(v, m)
		}
		return nil
	})
	return m
}

func writeTxCount(s *Store) int64 {
	st := s.db.Stats()
	return st.TxStats.GetWrite()
}

// A push without samples writes nothing; readers see it; the flush writes it.
func TestR23LivePushStaysInMemoryUntilFlush(t *testing.T) {
	s, _ := liveTestStore(t)
	defer s.Close()
	if err := s.Upsert(SystemMetric{ID: "a", Name: "A", Secret: "s", Tags: []string{"t"}, Order: 3}); err != nil {
		t.Fatal(err)
	}
	before := writeTxCount(s)
	push := SystemMetric{ID: "a", Name: "agent-name", CPU: 42, UpdatedAt: time.Now().UTC(), Secret: "s"}
	if err := s.SaveClientPushBatch(push, nil); err != nil {
		t.Fatal(err)
	}
	if writeTxCount(s) != before {
		t.Fatal("a push without samples wrote to disk")
	}
	got, _ := s.Get("a")
	if got.CPU != 42 || got.Name != "A" || got.Order != 3 || len(got.Tags) != 1 {
		t.Fatalf("Get: %+v", got)
	}
	list, _ := s.List()
	if len(list) != 1 || list[0].CPU != 42 || list[0].Name != "A" {
		t.Fatalf("List: %+v", list)
	}
	if storedRecord(t, s, "a").CPU != 0 {
		t.Fatal("stored before the flush")
	}
	if n, err := s.FlushLive(); err != nil || n != 1 {
		t.Fatalf("flush: %d %v", n, err)
	}
	st := storedRecord(t, s, "a")
	if st.CPU != 42 || st.Name != "A" || st.Order != 3 || st.Secret != "s" {
		t.Fatalf("stored after flush: %+v", st)
	}
	if n, _ := s.FlushLive(); n != 0 {
		t.Fatal("a clean overlay flushed again")
	}
}

// An admin edit between a push and the flush is kept; a deletion is kept.
func TestR23LiveFlushKeepsAdminEditsAndDeletions(t *testing.T) {
	s, _ := liveTestStore(t)
	defer s.Close()
	for _, id := range []string{"a", "b"} {
		_ = s.Upsert(SystemMetric{ID: id, Name: id, Secret: "s"})
	}
	now := time.Now().UTC()
	_ = s.SaveClientPushBatch(SystemMetric{ID: "a", Name: "a", CPU: 1, UpdatedAt: now, Secret: "s"}, nil)
	_ = s.SaveClientPushBatch(SystemMetric{ID: "b", Name: "b", CPU: 2, UpdatedAt: now, Secret: "s"}, nil)
	if _, err := s.UpdateAdminOwned(SystemMetric{ID: "a", Name: "renamed", Tags: []string{"x"}, HideOnHome: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOrders([]string{"b", "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveNavbarConfigAndSecret(&NavbarConfig{Text: "P", SharedSecret: "new"}, "new"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get("a"); got.Name != "renamed" || !got.HideOnHome || got.Order != 1 || got.Secret != "new" || got.CPU != 1 {
		t.Fatalf("read before flush: %+v", got)
	}
	if _, err := s.FlushLive(); err != nil {
		t.Fatal(err)
	}
	st := storedRecord(t, s, "a")
	if st.Name != "renamed" || !st.HideOnHome || st.Order != 1 || st.Secret != "new" || st.CPU != 1 || len(st.Tags) != 1 {
		t.Fatalf("flush reverted an admin edit: %+v", st)
	}
	if storedRecord(t, s, "b") != nil {
		t.Fatal("flush resurrected a deleted server")
	}
	if list, _ := s.List(); len(list) != 1 {
		t.Fatalf("List after delete: %d", len(list))
	}
}

// Kill -9: what was flushed survives, later pushes are lost; Close flushes.
func TestR23LiveCrashAndCleanStop(t *testing.T) {
	s, path := liveTestStore(t)
	_ = s.Upsert(SystemMetric{ID: "a", Name: "A", Secret: "s"})
	_ = s.SaveClientPushBatch(SystemMetric{ID: "a", CPU: 10, UpdatedAt: time.Now().UTC()}, nil)
	_, _ = s.FlushLive()
	_ = s.SaveClientPushBatch(SystemMetric{ID: "a", CPU: 20, UpdatedAt: time.Now().UTC()}, nil)
	// a crash: the file is closed without the store's Close
	_ = s.db.Close()
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.Get("a"); got.CPU != 10 {
		t.Fatalf("after a crash: CPU %v, want the flushed 10", got.CPU)
	}
	_ = s2.SaveClientPushBatch(SystemMetric{ID: "a", CPU: 30, UpdatedAt: time.Now().UTC()}, nil)
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if got, _ := s3.Get("a"); got.CPU != 30 {
		t.Fatalf("after a clean stop: CPU %v, want 30", got.CPU)
	}
}

// Going offline writes the last report itself.
func TestR23LiveMarkOfflineWritesLastReport(t *testing.T) {
	s, _ := liveTestStore(t)
	defer s.Close()
	_ = s.Upsert(SystemMetric{ID: "a", Name: "A", Secret: "s"})
	last := time.Now().UTC().Add(-40 * time.Second)
	_ = s.SaveClientPushBatch(SystemMetric{ID: "a", CPU: 7, UpdatedAt: last}, nil)
	if err := s.MarkOffline("a"); err != nil {
		t.Fatal(err)
	}
	st := storedRecord(t, s, "a")
	if !st.Alert || st.CPU != 7 || !st.UpdatedAt.Equal(last) || st.Name != "A" {
		t.Fatalf("offline record: %+v", st)
	}
	if got, _ := s.Get("a"); !got.Alert {
		t.Fatal("Get after MarkOffline still shows the in-memory online copy")
	}
}

// A server clock stepped back does not freeze the rows (no UpdatedAt ordering).
func TestR23LiveClockStepBack(t *testing.T) {
	s, _ := liveTestStore(t)
	defer s.Close()
	_ = s.Upsert(SystemMetric{ID: "a", Name: "A", Secret: "s"})
	now := time.Now().UTC()
	_ = s.SaveClientPushBatch(SystemMetric{ID: "a", CPU: 1, UpdatedAt: now}, nil)
	_, _ = s.FlushLive()
	_ = s.SaveClientPushBatch(SystemMetric{ID: "a", CPU: 2, UpdatedAt: now.Add(-135 * time.Second)}, nil)
	if got, _ := s.Get("a"); got.CPU != 2 {
		t.Fatalf("after a clock step back: CPU %v", got.CPU)
	}
	_, _ = s.FlushLive()
	if st := storedRecord(t, s, "a"); st.CPU != 2 {
		t.Fatalf("flush after a clock step back: CPU %v", st.CPU)
	}
}

// TCPing samples are committed before the push returns; a removed target's
// "latest" entry disappears from reads at once.
func TestR23LiveTCPingRowsDurableAndPrunedTargets(t *testing.T) {
	s, _ := liveTestStore(t)
	defer s.Close()
	_ = s.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "x", Address: "x:1"}, {Name: "y", Address: "y:1"}}, IntervalSecs: 60})
	_ = s.Upsert(SystemMetric{ID: "a", Name: "A", Secret: "s"})
	now := time.Now().UTC()
	l := 12.5
	m := SystemMetric{ID: "a", UpdatedAt: now, TCPingData: map[string]TCPingTargetData{"x:1": {Latency: l, Timestamp: now}, "y:1": {Latency: l, Timestamp: now}}, TCPingFresh: map[string]struct{}{"x:1": {}, "y:1": {}}}
	rows := []TCPingResult{{ClientID: "a", Target: "x:1", Latency: &l, Timestamp: now, ExactTimestamp: true}, {ClientID: "a", Target: "y:1", Latency: &l, Timestamp: now, ExactTimestamp: true}}
	if err := s.SaveClientPushBatch(m, rows); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.GetTCPingResults("a"); len(res) != 2 {
		t.Fatalf("rows not committed: %d", len(res))
	}
	_ = s.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "x", Address: "x:1"}}, IntervalSecs: 60})
	_ = s.PruneTCPingTargets([]string{"y:1"})
	if got, _ := s.Get("a"); len(got.TCPingData) != 1 {
		t.Fatalf("removed target still read: %+v", got.TCPingData)
	}
	_, _ = s.FlushLive()
	if st := storedRecord(t, s, "a"); len(st.TCPingData) != 1 {
		t.Fatalf("flush wrote a removed target back: %+v", st.TCPingData)
	}
}

// While storage fails a push without samples is refused and does not count;
// the first push after the recovery probes it and counts.
func TestR23LivePushRefusedWhileStorageFails(t *testing.T) {
	store, registry, ipCache := setupClockTest(t, "disk")
	if store.live == nil {
		t.Skip("overlay off")
	}
	storeHealth = storeHealthState{}
	defer func() { storeHealth = storeHealthState{} }()
	pushTCPingBatch(t, store, registry, ipCache, "disk", nil)
	first := registry.Get("disk").LastPushAt
	storeHealth.failed(time.Now(), errors.New("no space left on device"))
	// storage still broken: the probe fails too
	probeStorage = func(*Store, time.Time) error { return errors.New("no space left on device") }
	defer func() { probeStorage = func(s *Store, now time.Time) error { return s.probeWrite(now) } }()
	probeState.at = time.Time{}
	body, _ := json.Marshal(map[string]interface{}{"id": "disk", "name": "x", "uptime": 5})
	rr := httptest.NewRecorder()
	handleClientPush(store, registry, ipCache, rr, httptest.NewRequest(http.MethodPost, "/api/clients/push", bytes.NewReader(body)))
	if rr.Code != http.StatusInternalServerError || !registry.Get("disk").LastPushAt.Equal(first) {
		t.Fatalf("push while storage fails: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	handleHealth(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz: %d", rr.Code)
	}
	// storage back: the next push probes it and counts
	probeStorage = func(s *Store, now time.Time) error { return s.probeWrite(now) }
	probeState.at = time.Time{}
	time.Sleep(2 * time.Millisecond)
	pushTCPingBatch(t, store, registry, ipCache, "disk", nil)
	if !registry.Get("disk").LastPushAt.After(first) {
		t.Fatal("the push after the recovery did not count")
	}
	rr = httptest.NewRecorder()
	handleHealth(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz after recovery: %d", rr.Code)
	}
}
