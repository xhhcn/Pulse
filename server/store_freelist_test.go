package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The store no longer persists bbolt's freelist (NoFreelistSync). Files
// written by older builds (freelist synced) must open, the freelist must be
// rebuilt from the tree on reopen, and an older build must still be able to
// open a file this build has written.
func TestStoreFreelistNotSyncedAndCompatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")

	// An older build's file: freelist synced on every commit.
	legacy, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	if err := legacy.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return b.Put([]byte("legacy"), []byte(`{"id":"legacy","name":"Legacy"}`))
	}); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	legacy.Close()

	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore on a legacy file: %v", err)
	}
	if !st.db.NoFreelistSync {
		t.Fatal("the store must open bbolt with NoFreelistSync")
	}
	if m, _ := st.Get("legacy"); m == nil || m.Name != "Legacy" {
		t.Fatalf("legacy record not readable: %+v", m)
	}
	// Create and delete enough history to leave free pages behind.
	now := time.Now().UTC()
	var keys [][]byte
	if err := st.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tcpingBucket))
		for i := 0; i < 20000; i++ {
			l := float64(i % 200)
			r := TCPingResult{ClientID: "legacy", Target: "1.1.1.1:53", Latency: &l, Timestamp: now.Add(time.Duration(i) * time.Millisecond)}
			if err := putTCPingResultIdempotent(b, r); err != nil {
				return err
			}
			keys = append(keys, tcpingResultKey(r, 0))
		}
		return nil
	}); err != nil {
		t.Fatalf("fill history: %v", err)
	}
	if err := st.deleteTCPingKeys(keys[:15000]); err != nil {
		t.Fatalf("delete history: %v", err)
	}
	if err := st.Upsert(SystemMetric{ID: "after", Name: "After"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	st.Close()

	// Reopen: the freelist is rebuilt from the tree, data intact.
	st, err = NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if st.db.Stats().FreePageN == 0 {
		t.Fatal("expected the rebuilt freelist to hold the pages freed by the deletes")
	}
	rows, err := st.GetTCPingResults("legacy", "1.1.1.1:53")
	if err != nil || len(rows) != 5000 {
		t.Fatalf("history after reopen: %d rows (%v)", len(rows), err)
	}
	if m, _ := st.Get("after"); m == nil {
		t.Fatal("record written before the reopen is missing")
	}
	st.Close()

	// Downgrade path: an older build (freelist syncing on) opens the file.
	older, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatalf("older build cannot open the file: %v", err)
	}
	defer older.Close()
	var n int
	if err := older.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).ForEach(func(_, _ []byte) error { n++; return nil })
	}); err != nil {
		t.Fatalf("older build read: %v", err)
	}
	if n < 2 {
		t.Fatalf("older build sees %d systems, want at least 2", n)
	}
	if err := older.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte("older"), []byte(fmt.Sprintf(`{"id":"older","name":"%s"}`, "Older")))
	}); err != nil {
		t.Fatalf("older build write: %v", err)
	}
}
