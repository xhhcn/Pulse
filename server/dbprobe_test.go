package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The database probe re-executes the running binary; under `go test` that is
// the test binary, which must behave like the server's main() when the probe
// variable is set.
func TestMain(m *testing.M) {
	runDBOpenProbeIfRequested()
	os.Exit(m.Run())
}

const (
	boltPageHeaderSize = 16
	boltLeafElemSize   = 16
	boltLeafPageFlag   = 0x02
)

// checkDB runs bbolt's consistency check on a file that still has a usable
// freelist view (an open RW handle has one in memory).
func checkDB(t *testing.T, db *bolt.DB) {
	t.Helper()
	var errs []string
	if err := db.View(func(tx *bolt.Tx) error {
		for err := range tx.Check() {
			errs = append(errs, err.Error())
		}
		return nil
	}); err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("consistency errors: %v", errs)
	}
}

// newestMetaFreelist returns the freelist page id recorded in the newer of
// the two meta pages (pgidNoFreelist when the freelist is not stored).
func newestMetaFreelist(t *testing.T, path string) uint64 {
	t.Helper()
	f, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pageSize := int(binary.LittleEndian.Uint32(f[boltPageHeaderSize+8:]))
	var bestTx, freelist uint64
	for i := 0; i < 2; i++ {
		m := f[i*pageSize+boltPageHeaderSize:]
		// magic, version, pageSize, flags (4×4) + root bucket (16) → freelist at 32
		fl := binary.LittleEndian.Uint64(m[32:])
		txid := binary.LittleEndian.Uint64(m[48:])
		if i == 0 || txid > bestTx {
			bestTx, freelist = txid, fl
		}
	}
	return freelist
}

// swapTwoHistoryKeys damages the file the way a torn or buggy write could:
// it swaps the keys of two neighbouring entries in a history leaf page, so
// the page's keys are no longer in order. Returns false if no suitable page
// was found.
func swapTwoHistoryKeys(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pageSize := int(binary.LittleEndian.Uint32(f[boltPageHeaderSize+8:]))
	for off := 2 * pageSize; off+pageSize <= len(f); off += pageSize {
		p := f[off : off+pageSize]
		if binary.LittleEndian.Uint16(p[8:]) != boltLeafPageFlag {
			continue
		}
		count := int(binary.LittleEndian.Uint16(p[10:]))
		for i := 0; i+1 < count && i < 8; i++ {
			e0 := boltPageHeaderSize + i*boltLeafElemSize
			e1 := e0 + boltLeafElemSize
			k0 := e0 + int(binary.LittleEndian.Uint32(p[e0+4:]))
			k1 := e1 + int(binary.LittleEndian.Uint32(p[e1+4:]))
			n0 := int(binary.LittleEndian.Uint32(p[e0+8:]))
			n1 := int(binary.LittleEndian.Uint32(p[e1+8:]))
			if n0 != n1 || n0 < 12 || k0+n0 > pageSize || k1+n1 > pageSize {
				continue
			}
			a, b := p[k0:k0+n0], p[k1:k1+n1]
			if a[10] != '_' || bytes.Equal(a, b) {
				continue // not a history key ("<10-digit ts>_...")
			}
			tmp := append([]byte(nil), a...)
			copy(a, b)
			copy(b, tmp)
			if err := os.WriteFile(path, f, 0600); err != nil {
				t.Fatal(err)
			}
			return true
		}
	}
	return false
}

func buildHistoryDB(t *testing.T, path string, rows int) {
	t.Helper()
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.Upsert(SystemMetric{ID: "keep", Name: "Keep me"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// One transaction, so every history page is reachable (no stale copies
	// left behind by copy-on-write in free pages).
	now := time.Now().UTC()
	if err := st.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tcpingBucket))
		for i := 0; i < rows; i++ {
			l := float64(i % 300)
			r := TCPingResult{ClientID: "keep", Target: "1.1.1.1:53", Latency: &l, Timestamp: now.Add(-time.Duration(rows-i) * time.Second)}
			if err := putTCPingResultIdempotent(b, r); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("fill: %v", err)
	}
	st.Close()
}

func runProbeChild(t *testing.T, path string) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), dbOpenProbeEnv+"="+path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		return 0, ""
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("probe child did not run: %v", err)
	}
	return ee.ExitCode(), stderr.String()
}

func TestPreflightLeavesAHealthyDatabaseAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")
	buildHistoryDB(t, path, 2000)
	before, _ := os.ReadFile(path)
	preflightDB(path)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("a healthy database must not be rewritten by the probe")
	}
	if m, _ := filepath.Glob(path + ".damaged-*"); len(m) != 0 {
		t.Fatalf("unexpected salvage artefacts: %v", m)
	}
}

func TestPreflightSalvagesADamagedTree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.db")
	buildHistoryDB(t, path, 3000)
	if fl := newestMetaFreelist(t, path); fl != 0xffffffffffffffff {
		t.Fatalf("the store must not persist the freelist (meta freelist=%d)", fl)
	}
	if !swapTwoHistoryKeys(t, path) {
		t.Fatal("no history leaf page found to damage")
	}
	// The damage is real: opening the file the way the server does kills
	// the process from inside bbolt.
	if code, out := runProbeChild(t, path); code != 2 || !strings.Contains(out, "go.etcd.io/bbolt") {
		t.Fatalf("expected the probe child to die in bbolt, got exit %d: %.300s", code, out)
	}

	preflightDB(path)

	damaged, _ := filepath.Glob(path + ".damaged-*")
	if len(damaged) != 1 {
		t.Fatalf("the damaged original must be kept aside, found %v", damaged)
	}
	if code, out := runProbeChild(t, path); code != 0 {
		t.Fatalf("the salvaged file must open cleanly, probe exit %d: %.300s", code, out)
	}
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore on the salvaged file: %v", err)
	}
	defer st.Close()
	checkDB(t, st.db)
	if m, _ := st.Get("keep"); m == nil || m.Name != "Keep me" {
		t.Fatalf("system record lost in salvage: %+v", m)
	}
	var n int
	st.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(tcpingBucket)).ForEach(func(_, _ []byte) error { n++; return nil })
	})
	if n != 3000 {
		t.Fatalf("salvaged history has %d rows, want 3000", n)
	}
}

// A file written by an older build with a large stored (multi-page) freelist
// switches to the unsynced mode cleanly: consistent, marker written, freelist
// rebuilt from the tree on reopen, and still readable by an older build.
func TestSwitchFromALargeStoredFreelist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	legacy, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	now := time.Now().UTC()
	var keys [][]byte
	if err := legacy.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{bucketName, configBucket, tcpingBucket, authBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		if err := tx.Bucket([]byte(bucketName)).Put([]byte("legacy"), []byte(`{"id":"legacy","name":"Legacy"}`)); err != nil {
			return err
		}
		b := tx.Bucket([]byte(tcpingBucket))
		for i := 0; i < 40000; i++ {
			l := float64(i % 300)
			r := TCPingResult{ClientID: "legacy", Target: "1.1.1.1:53", Latency: &l, Timestamp: now.Add(-time.Duration(40000-i) * time.Second)}
			if err := putTCPingResultIdempotent(b, r); err != nil {
				return err
			}
			keys = append(keys, tcpingResultKey(r, 0))
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Bulk delete in chunks, the way target removal does: the freed pages
	// end up on a stored, multi-page freelist.
	for i := 0; i < 36000; i += 3000 {
		chunk := keys[i : i+3000]
		if err := legacy.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(tcpingBucket))
			for _, k := range chunk {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("delete: %v", err)
		}
	}
	if free := legacy.Stats().FreePageN; free < 1000 {
		t.Fatalf("expected a large legacy freelist, got %d free pages", free)
	}
	legacy.Close()
	if fl := newestMetaFreelist(t, path); fl == 0xffffffffffffffff {
		t.Fatal("the legacy file must start with a stored freelist")
	}

	// The switch itself, in place: openBolt directly, without NewStore's
	// startup vacuum (which would rewrite a file this sparse and remove the
	// freelist being tested).
	db, err := openBolt(path)
	if err != nil {
		t.Fatalf("open in the new mode: %v", err)
	}
	checkDB(t, db)
	if err := (&Store{db: db}).Upsert(SystemMetric{ID: "after", Name: "After"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	checkDB(t, db)
	db.Close()
	if fl := newestMetaFreelist(t, path); fl != 0xffffffffffffffff {
		t.Fatalf("after the first commit the freelist must no longer be stored (meta freelist=%d)", fl)
	}

	db, err = openBolt(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if db.Stats().FreePageN < 1000 {
		t.Fatalf("the rebuilt freelist must hold the freed pages, got %d", db.Stats().FreePageN)
	}
	checkDB(t, db)
	rows, err := (&Store{db: db}).GetTCPingResults("legacy", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	// The 24 h window keeps only recent rows; the survivors of the bulk
	// delete are the newest 4000, all within it.
	if len(rows) != 4000 {
		t.Fatalf("history after the switch: %d rows, want 4000", len(rows))
	}
	db.Close()

	// An older build opens the file, writes, stores the freelist again and
	// stays consistent.
	older, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatalf("older build cannot open the file: %v", err)
	}
	if err := older.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte("older"), []byte(`{"id":"older","name":"Older"}`))
	}); err != nil {
		t.Fatalf("older build write: %v", err)
	}
	checkDB(t, older)
	older.Close()
	if fl := newestMetaFreelist(t, path); fl == 0xffffffffffffffff {
		t.Fatal("an older build must store the freelist again when it writes")
	}

	// And back on this build through the normal path (startup vacuum and
	// all): consistent, nothing lost.
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore after the downgrade: %v", err)
	}
	defer st.Close()
	checkDB(t, st.db)
	for _, id := range []string{"legacy", "after", "older"} {
		if m, _ := st.Get(id); m == nil {
			t.Fatalf("system %q missing after the round trip", id)
		}
	}
	if rows, _ := st.GetTCPingResults("legacy", "1.1.1.1:53"); len(rows) != 4000 {
		t.Fatalf("history after the round trip: %d rows, want 4000", len(rows))
	}
}
