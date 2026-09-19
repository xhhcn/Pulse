package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("store.Close() error = %v", err)
		}
	})
	return store
}

func TestSaveClientPushBatchWritesMetricAndTCPingHistory(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	latency := 12.5

	metric := SystemMetric{
		ID:        "push-client",
		Name:      "Push Client",
		UpdatedAt: now,
		TCPingData: map[string]TCPingTargetData{
			"example.com": {
				Latency:   latency,
				Timestamp: now,
			},
		},
	}

	// Agent writes never create a system; the admin-created record exists first.
	if err := store.Upsert(SystemMetric{ID: "push-client", Name: "Push Client"}); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	if err := store.SaveClientPushBatch(metric, []TCPingResult{{
		ClientID:  "push-client",
		Target:    "example.com",
		Latency:   &latency,
		Timestamp: now,
	}}); err != nil {
		t.Fatalf("SaveClientPushBatch() error = %v", err)
	}

	gotMetric, err := store.Get("push-client")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if gotMetric == nil || gotMetric.Name != "Push Client" {
		t.Fatalf("stored metric = %#v, want Push Client", gotMetric)
	}

	results, err := store.GetTCPingResults("push-client", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Latency == nil || *results[0].Latency != latency {
		t.Fatalf("latency = %#v, want %v", results[0].Latency, latency)
	}
}

func TestGetTCPingResultsDoesNotMixClientIDPrefixes(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	latencyA := 10.0
	latencyB := 20.0

	for _, result := range []TCPingResult{
		{ClientID: "node", Target: "example.com", Latency: &latencyA, Timestamp: now},
		{ClientID: "node-extra", Target: "example.com", Latency: &latencyB, Timestamp: now.Add(time.Second)},
	} {
		if err := store.SaveTCPingResult(result); err != nil {
			t.Fatalf("SaveTCPingResult(%s) error = %v", result.ClientID, err)
		}
	}

	results, err := store.GetTCPingResults("node", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].ClientID != "node" {
		t.Fatalf("ClientID = %q, want node", results[0].ClientID)
	}
}

func TestSaveTCPingResultKeepsMultipleSamplesInSameSecond(t *testing.T) {
	store := newTestStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	latencyA := 10.0
	latencyB := 11.0

	for _, result := range []TCPingResult{
		{ClientID: "same-second", Target: "example.com", Latency: &latencyA, Timestamp: base.Add(100 * time.Millisecond)},
		{ClientID: "same-second", Target: "example.com", Latency: &latencyB, Timestamp: base.Add(200 * time.Millisecond)},
	} {
		if err := store.SaveTCPingResult(result); err != nil {
			t.Fatalf("SaveTCPingResult() error = %v", err)
		}
	}

	results, err := store.GetTCPingResults("same-second", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
}

func TestSaveTCPingResultKeepsDuplicateTimestampSamples(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	latencyA := 10.0
	latencyB := 11.0

	for _, result := range []TCPingResult{
		{ClientID: "duplicate-ts", Target: "example.com", Latency: &latencyA, Timestamp: now},
		{ClientID: "duplicate-ts", Target: "example.com", Latency: &latencyB, Timestamp: now},
	} {
		if err := store.SaveTCPingResult(result); err != nil {
			t.Fatalf("SaveTCPingResult() error = %v", err)
		}
	}

	results, err := store.GetTCPingResults("duplicate-ts", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
}

func TestGetTCPingResultsReadsLegacySecondKeyFormat(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	latency := 9.5
	result := TCPingResult{
		ClientID:  "legacy-client",
		Target:    "example.com",
		Latency:   &latency,
		Timestamp: now,
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := store.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		key := fmt.Sprintf("%d_%s_%s", now.Unix(), result.ClientID, result.Target)
		return bucket.Put([]byte(key), data)
	}); err != nil {
		t.Fatalf("legacy Put() error = %v", err)
	}

	results, err := store.GetTCPingResults("legacy-client", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
}

func TestVerifyPasswordRoundTrip(t *testing.T) {
	store := newTestStore(t)

	if err := store.SetPassword("correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	ok, err := store.VerifyPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword() = false, want true")
	}
}

func TestNavbarConfigPreservesHotaruCompatibilityFlags(t *testing.T) {
	store := newTestStore(t)

	config := &NavbarConfig{
		Text:         "Pulse",
		Logo:         "logo.svg",
		SharedSecret: "secret",
		HideTags:     true,
		HideCards:    true,
	}
	if err := store.SaveNavbarConfig(config); err != nil {
		t.Fatalf("SaveNavbarConfig() error = %v", err)
	}

	got, err := store.GetNavbarConfig()
	if err != nil {
		t.Fatalf("GetNavbarConfig() error = %v", err)
	}
	if !got.HideTags || !got.HideCards {
		t.Fatalf("Hotaru flags were not preserved: HideTags=%v HideCards=%v", got.HideTags, got.HideCards)
	}
}

func TestNewStoreCleansOldTCPingResultsOnStartup(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "metrics.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	oldLatency := 5.0
	recentLatency := 6.0
	if err := store.SaveTCPingResult(TCPingResult{
		ClientID:  "startup-cleanup",
		Target:    "example.com",
		Latency:   &oldLatency,
		Timestamp: time.Now().UTC().Add(-25 * time.Hour),
	}); err != nil {
		t.Fatalf("SaveTCPingResult(old) error = %v", err)
	}
	if err := store.SaveTCPingResult(TCPingResult{
		ClientID:  "startup-cleanup",
		Target:    "example.com",
		Latency:   &recentLatency,
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveTCPingResult(recent) error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close() error = %v", err)
	}

	reopened, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("reopen NewStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("reopened.Close() error = %v", err)
		}
	})

	results, err := reopened.GetTCPingResults("startup-cleanup", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want only recent sample", len(results))
	}
	if results[0].Latency == nil || *results[0].Latency != recentLatency {
		t.Fatalf("remaining latency = %#v, want %v", results[0].Latency, recentLatency)
	}
}

func TestOfflineCompactPreservesTCPingHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "metrics.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	now := time.Now().UTC()
	latency := 8.25
	if err := store.SaveTCPingResult(TCPingResult{
		ClientID:  "compact-client",
		Target:    "example.com",
		Latency:   &latency,
		Timestamp: now,
	}); err != nil {
		t.Fatalf("SaveTCPingResult() error = %v", err)
	}

	if err := store.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("compact_test_filler"))
		if err != nil {
			return err
		}
		return b.Put([]byte("blob"), bytes.Repeat([]byte("x"), 20<<20))
	}); err != nil {
		t.Fatalf("write filler data error = %v", err)
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte("compact_test_filler"))
	}); err != nil {
		t.Fatalf("delete filler data error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close() error = %v", err)
	}

	before, after, err := CompactBoltFileAfterClose(dbPath)
	if err != nil {
		t.Fatalf("CompactBoltFileAfterClose() error = %v", err)
	}
	if after != 0 && after >= before {
		t.Fatalf("compact sizes before=%d after=%d, want shrink when compact runs", before, after)
	}

	reopened, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("reopen after compact error = %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("reopened.Close() error = %v", err)
		}
	})

	results, err := reopened.GetTCPingResults("compact-client", "example.com")
	if err != nil {
		t.Fatalf("GetTCPingResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Latency == nil || *results[0].Latency != latency {
		t.Fatalf("latency = %#v, want %v", results[0].Latency, latency)
	}
}
