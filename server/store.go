package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultDBPath    = "./data/metrics.db"
	bucketName       = "systems"
	tcpingBucket     = "tcping"
	configBucket     = "config"
	configKey        = "tcping"
	navbarConfigKey  = "navbar"
	privacyConfigKey = "privacy"
	authBucket       = "auth"
	passwordKey      = "admin_password"
)

// Store represents the persistent storage
type Store struct {
	db *bolt.DB
}

// openBolt opens the bbolt database with the safer FreelistMapType and a
// slightly more generous lock timeout. FreelistMapType uses a hashmap instead
// of a sorted array for the freelist, which is significantly more robust
// against the freelist-corruption bugs present in older bbolt versions and
// drastically reduces the probability of "invalid freelist page" panics after
// an ungraceful shutdown.
func openBolt(dbPath string) (*bolt.DB, error) {
	return bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout:      5 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
}

// isDBCorruptionError returns true when the error returned from bolt.Open
// looks like on-disk corruption that cannot be recovered by re-opening.
// We keep the match list intentionally conservative: we only want to auto
// quarantine on errors that are known to be unrecoverable. All other errors
// (timeout, permission denied, ...) are left to bubble up.
func isDBCorruptionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	corruptionSignatures := []string{
		"invalid freelist page",
		"invalid database",
		"meta page",
		"checksum",
		"unexpected EOF",
		"page flags",
		"invalid page type",
		"invalid leaf",
		"invalid branch",
	}
	for _, sig := range corruptionSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// quarantineCorruptDB renames the broken file aside with a timestamp suffix so
// that the service can start with a fresh database while still preserving the
// evidence for post-mortem inspection / manual recovery via `bbolt` CLI.
func quarantineCorruptDB(dbPath string, cause error) (string, error) {
	suffix := time.Now().UTC().Format("20060102T150405Z")
	backupPath := fmt.Sprintf("%s.corrupt-%s", dbPath, suffix)
	if err := os.Rename(dbPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to quarantine corrupt database (%v): %w", cause, err)
	}
	// bbolt also creates a .lock file next to the DB on some platforms; make a
	// best-effort cleanup so the fresh DB can acquire the lock.
	_ = os.Remove(dbPath + ".lock")
	return backupPath, nil
}

// NewStore creates or opens the database
func NewStore(dbPath string) (*Store, error) {
	// Use default path if not specified
	if dbPath == "" {
		dbPath = defaultDBPath
	}

	// Create data directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open database (creates if doesn't exist). If the on-disk file is
	// corrupted (e.g. "invalid freelist page" after an ungraceful shutdown),
	// quarantine it and start over with an empty DB so that the service can
	// still come up. The corrupt file is preserved as <path>.corrupt-<ts> for
	// manual recovery with the `bbolt` CLI.
	db, err := openBolt(dbPath)
	if err != nil {
		if isDBCorruptionError(err) {
			log.Printf("⚠️  Detected corrupt bbolt database at %s: %v", dbPath, err)
			backupPath, qerr := quarantineCorruptDB(dbPath, err)
			if qerr != nil {
				return nil, qerr
			}
			log.Printf("🗂️  Corrupt database moved aside to %s. Starting with a fresh database.", backupPath)
			db, err = openBolt(dbPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open database after quarantine: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to open database: %w", err)
		}
	}

	// Initialize buckets
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(configBucket))
		if err != nil {
			return fmt.Errorf("failed to create config bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(tcpingBucket))
		if err != nil {
			return fmt.Errorf("failed to create tcping bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(authBucket))
		if err != nil {
			return fmt.Errorf("failed to create auth bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("✅ Database initialized: %s", dbPath)

	store := &Store{db: db}

	// One-shot cleanup of orphan buckets left over from older code paths
	// (a v1 secondary-index experiment that was rolled back to the cursor-seek
	// design). The current binary never reads or writes these buckets, but
	// existing on-disk files can carry tens of megabytes of frozen index
	// pages from the previous code version. Dropping them frees the pages
	// to the freelist so the subsequent vacuum can reclaim them.
	if dropped, err := store.dropOrphanBuckets(); err != nil {
		log.Printf("⚠️  orphan-bucket cleanup failed (non-fatal): %v", err)
	} else if len(dropped) > 0 {
		log.Printf("🧹 Dropped orphan buckets/keys from previous versions: %s", strings.Join(dropped, ", "))
	}

	if removed, err := store.cleanupOldTCPingResults(); err != nil {
		log.Printf("⚠️  startup tcping cleanup failed (non-fatal): %v", err)
	} else if removed > 0 {
		log.Printf("🧹 Startup tcping cleanup: removed %d records older than 24h", removed)
	}

	// Online compaction. bbolt is append-only: when records are deleted the
	// pages go on the freelist but the file never shrinks on its own. On
	// long-running deployments with churny workloads (24h tcping window),
	// the file slowly accumulates fragmented free space and can grow to many
	// times the live-data size. Because bbolt mmaps the whole file into the
	// process address space, every bloat byte eventually becomes RSS as
	// cleanup scans and history queries touch the mapped pages — which is
	// what historically presented as "memory keeps growing after
	// systemctl restart until the box OOMs". Reclaiming the freelist on
	// startup keeps RSS bounded to the live data size + a small overhead.
	if newPath, before, after, err := store.maybeCompact(dbPath); err != nil {
		// Fatal sentinel: vacuum had to close the handle and couldn't reopen.
		// Continuing would crash on the next db.View, so abort startup cleanly
		// and let systemd restart us — the on-disk file is intact, just the
		// in-process handle is gone.
		if errors.Is(err, errCompactLeftStoreClosed) {
			return nil, fmt.Errorf("bbolt vacuum left store unusable, aborting startup: %w", err)
		}
		log.Printf("⚠️  bbolt vacuum failed (non-fatal, original DB preserved): %v", err)
	} else if after > 0 {
		log.Printf("🧯 bbolt vacuum: %.1f MB → %.1f MB (saved %.1f MB)",
			float64(before)/1024/1024,
			float64(after)/1024/1024,
			float64(before-after)/1024/1024)
		_ = newPath // already swapped in
	}

	// Log current data count
	count := store.Count()
	if count == 0 {
		log.Printf("📦 Database is empty - waiting for first metrics")
	} else {
		log.Printf("📊 Loaded %d existing systems from database", count)
	}

	return store, nil
}

// dropOrphanBuckets removes top-level buckets and config keys that the
// current code never touches. They were created by an earlier secondary-index
// experiment (see git history of the cursor-seek refactor) that was reverted
// in favour of timestamp-prefixed primary keys. The dropped pages return to
// the freelist and are reclaimed by maybeCompact below.
//
// The list is intentionally explicit (rather than "delete anything not in a
// known set") so that a future migration adding a new bucket cannot
// accidentally wipe data on rollback.
func (s *Store) dropOrphanBuckets() ([]string, error) {
	knownOrphanBuckets := []string{
		"tcping_by_client",
		"tcping_by_client_target",
	}
	knownOrphanConfigKeys := []string{
		"tcping_index_v1_ready",
	}

	var dropped []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range knownOrphanBuckets {
			if tx.Bucket([]byte(name)) != nil {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return fmt.Errorf("drop bucket %s: %w", name, err)
				}
				dropped = append(dropped, "bucket:"+name)
			}
		}
		if cb := tx.Bucket([]byte(configBucket)); cb != nil {
			for _, k := range knownOrphanConfigKeys {
				if cb.Get([]byte(k)) != nil {
					if err := cb.Delete([]byte(k)); err != nil {
						return fmt.Errorf("delete config key %s: %w", k, err)
					}
					dropped = append(dropped, "config:"+k)
				}
			}
		}
		return nil
	})
	return dropped, err
}

// liveDataBytes estimates how many bytes the bbolt file would occupy if it
// were perfectly compacted. We sum every bucket's leaf+branch in-use sizes;
// freelist pages and unused tail-end of the file are excluded by design.
func (s *Store) liveDataBytes() (int64, error) {
	var total int64
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			st := b.Stats()
			total += int64(st.LeafInuse + st.BranchInuse)
			return nil
		})
	})
	return total, err
}

// maybeCompact runs bolt.Compact() into a sibling temp file and atomically
// renames it over the live DB iff the live file is significantly larger
// than the in-use data. Atomic rename + retained-on-failure semantics make
// this safe to run unconditionally at every startup: on failure the original
// file is untouched and the service still comes up.
//
// Return values: (newPath, sizeBefore, sizeAfter, err). When no compaction is
// performed, sizeAfter == 0 and err == nil. Caller logs accordingly.
const (
	// Don't bother compacting databases under 16 MB — the savings aren't
	// worth the startup cost and the RSS impact is negligible.
	compactMinBytes int64 = 16 << 20
	// Compact whenever the file is more than this multiple of the live data.
	// 2× is generous: bbolt naturally keeps some slack for write throughput,
	// and we don't want to spin into a compact-loop on a healthy DB.
	compactRatio = 2.0
	// Cap the per-tx size to keep compaction's transient RAM footprint
	// bounded even on multi-GB databases.
	compactTxMaxBytes int64 = 64 << 20
)

func (s *Store) maybeCompact(dbPath string) (string, int64, int64, error) {
	st, err := os.Stat(dbPath)
	if err != nil {
		return "", 0, 0, err
	}
	sizeBefore := st.Size()
	if sizeBefore < compactMinBytes {
		return "", sizeBefore, 0, nil
	}

	live, err := s.liveDataBytes()
	if err != nil {
		return "", sizeBefore, 0, fmt.Errorf("live-data probe: %w", err)
	}
	if live <= 0 || float64(sizeBefore) < compactRatio*float64(live) {
		return "", sizeBefore, 0, nil
	}

	log.Printf("🧯 bbolt vacuum: file=%d live=%d (ratio %.1fx) — compacting...",
		sizeBefore, live, float64(sizeBefore)/float64(live))

	tmpPath := dbPath + ".compacting"
	// Clean up any leftover from a previous interrupted compaction.
	_ = os.Remove(tmpPath)

	dst, err := bolt.Open(tmpPath, 0600, &bolt.Options{
		Timeout:      5 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", sizeBefore, 0, fmt.Errorf("open temp db: %w", err)
	}

	if err := bolt.Compact(dst, s.db, compactTxMaxBytes); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmpPath)
		return "", sizeBefore, 0, fmt.Errorf("compact: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", sizeBefore, 0, fmt.Errorf("close temp db: %w", err)
	}

	// Close the original handle so we can atomically rename over it.
	// We must reopen afterwards to give the caller a usable Store.
	// Past this point, s.db has been closed: every failure branch MUST
	// either restore s.db to a working handle or return a sentinel error
	// (ErrCompactLeftStoreClosed) so the caller can fail fast instead of
	// crashing later on a dereferenced-nil bolt.DB. See NewStore for how
	// that contract is enforced.
	if err := s.db.Close(); err != nil {
		_ = os.Remove(tmpPath)
		// db.Close() failed — s.db may or may not be usable. Try to reopen
		// the original file so the caller still has a working store; if
		// that fails too, surface ErrCompactLeftStoreClosed.
		if reopened, rerr := openBolt(dbPath); rerr == nil {
			s.db = reopened
			return "", sizeBefore, 0, fmt.Errorf("close original db: %w", err)
		}
		return "", sizeBefore, 0, fmt.Errorf("%w (close original db: %v)", errCompactLeftStoreClosed, err)
	}

	if err := os.Rename(tmpPath, dbPath); err != nil {
		// Try to reopen the original so the service can still start
		// (worst case it stays bloated until next restart).
		if reopened, rerr := openBolt(dbPath); rerr == nil {
			s.db = reopened
			_ = os.Remove(tmpPath)
			return "", sizeBefore, 0, fmt.Errorf("atomic rename: %w", err)
		}
		_ = os.Remove(tmpPath)
		return "", sizeBefore, 0, fmt.Errorf("%w (rename failed and original could not be reopened: %v)", errCompactLeftStoreClosed, err)
	}

	reopened, err := openBolt(dbPath)
	if err != nil {
		// Rename succeeded but we can't open the new file. The compacted
		// content is on disk and valid, but s.db is closed — there is no
		// safe way to keep going in-process.
		return "", sizeBefore, 0, fmt.Errorf("%w (reopen compacted db: %v)", errCompactLeftStoreClosed, err)
	}
	s.db = reopened

	if newSt, err := os.Stat(dbPath); err == nil {
		return dbPath, sizeBefore, newSt.Size(), nil
	}
	return dbPath, sizeBefore, 0, nil
}

// errCompactLeftStoreClosed is returned by maybeCompact when it had to close
// the original bbolt handle but could not reopen any valid replacement. The
// Store is no longer usable; the caller (NewStore) MUST treat this as fatal
// and abort startup. Wrapping it via fmt.Errorf("%w ...", err) preserves
// errors.Is() matching for downstream checks.
var errCompactLeftStoreClosed = fmt.Errorf("bbolt vacuum left store handle closed; restart required")

// CompactBoltFileAfterClose runs the same heuristic as maybeCompact against a
// database file whose primary handle has already been bolt.DB.Close()'d —
// typical site is the graceful shutdown path in main() after HTTP has drained.
// Holding no open handles avoids lock conflicts and yields a shrunk on-disk
// file before the next process start so RSS from mmap stays bounded even when
// the previous run never reached NewStore()'s vacuum (crash/kill vs clean
// restart).
//
// It is intentionally best-effort: on any error the original metrics.db is
// left untouched. beforeOut/afterOut are file sizes on disk when compaction
// actually ran (afterOut==0 means skipped or unchanged).
func CompactBoltFileAfterClose(dbPath string) (beforeOut, afterOut int64, err error) {
	if dbPath == "" {
		return 0, 0, nil
	}

	st, err := os.Stat(dbPath)
	if err != nil {
		return 0, 0, err
	}
	beforeOut = st.Size()
	if beforeOut < compactMinBytes {
		return beforeOut, 0, nil
	}

	src, err := bolt.Open(dbPath, 0600, &bolt.Options{
		ReadOnly:     true,
		Timeout:      10 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		return beforeOut, 0, fmt.Errorf("open readonly for vacuum: %w", err)
	}

	var live int64
	viewErr := src.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			s := b.Stats()
			live += int64(s.LeafInuse + s.BranchInuse)
			return nil
		})
	})
	if viewErr != nil {
		_ = src.Close()
		return beforeOut, 0, viewErr
	}
	if live <= 0 || float64(beforeOut) < compactRatio*float64(live) {
		_ = src.Close()
		return beforeOut, 0, nil
	}

	log.Printf("🧯 offline bbolt vacuum: file=%d live=%d (ratio %.1fx) — compacting...",
		beforeOut, live, float64(beforeOut)/float64(live))

	tmpPath := dbPath + ".compacting_shutdown"
	_ = os.Remove(tmpPath)

	dst, err := bolt.Open(tmpPath, 0600, &bolt.Options{
		Timeout:      5 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		_ = src.Close()
		return beforeOut, 0, fmt.Errorf("open temp db for offline vacuum: %w", err)
	}

	if err := bolt.Compact(dst, src, compactTxMaxBytes); err != nil {
		_ = dst.Close()
		_ = src.Close()
		_ = os.Remove(tmpPath)
		return beforeOut, 0, fmt.Errorf("offline compact: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = src.Close()
		_ = os.Remove(tmpPath)
		return beforeOut, 0, err
	}
	if err := src.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return beforeOut, 0, err
	}

	if err := os.Rename(tmpPath, dbPath); err != nil {
		_ = os.Remove(tmpPath)
		return beforeOut, 0, fmt.Errorf("offline vacuum rename: %w", err)
	}

	st2, err := os.Stat(dbPath)
	if err != nil {
		return beforeOut, 0, err
	}
	return beforeOut, st2.Size(), nil
}

// Close closes the database
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Snapshot streams a consistent hot-backup of the entire bbolt database
// to the provided writer. Internally it runs inside a read-only
// transaction (db.View) and delegates to bbolt's built-in Tx.WriteTo,
// which produces a byte-identical copy of the on-disk file as it
// appeared at the moment the transaction began — safe to take while
// the server is live serving traffic, with no downtime and no risk of
// a half-written page ending up in the backup.
//
// The number of bytes written is returned so the caller can set
// Content-Length for streamed HTTP responses.
//
// The resulting file can be used as a drop-in replacement for
// data/metrics.db on a new host: stop the target container, swap the
// file, start it. See scripts/backup.sh and scripts/restore.sh for a
// turnkey migration workflow.
func (s *Store) Snapshot(w io.Writer) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not open")
	}
	var written int64
	err := s.db.View(func(tx *bolt.Tx) error {
		n, werr := tx.WriteTo(w)
		written = n
		return werr
	})
	return written, err
}

// Upsert inserts or updates a system metric
func (s *Store) Upsert(metric SystemMetric) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return putMetric(bucket, metric)
	})
}

// putMetric serialises metric and stores it under its ID inside bucket.
func putMetric(bucket *bolt.Bucket, metric SystemMetric) error {
	data, err := json.Marshal(metric)
	if err != nil {
		return fmt.Errorf("failed to marshal metric: %w", err)
	}
	if err := bucket.Put([]byte(metric.ID), data); err != nil {
		return fmt.Errorf("failed to put metric: %w", err)
	}
	return nil
}

// MarkOffline persists Alert=true for a system inside one write transaction
// and leaves every other field, UpdatedAt included, untouched. The previous
// implementation rewound UpdatedAt by 13 s through a full-record Upsert:
// the rewind made every later snapshot look older than what the browsers
// had already painted, so their freshness guard dropped the frames and the
// page froze until reload; and the Get + Upsert pair could overwrite a poll
// result or admin edit committed in between. buildMetricsSnapshot derives
// the offline state from the age of UpdatedAt anyway.
func (s *Store) MarkOffline(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		data := bucket.Get([]byte(id))
		if data == nil {
			return nil
		}
		var current SystemMetric
		if err := json.Unmarshal(data, &current); err != nil {
			return fmt.Errorf("failed to decode metric: %w", err)
		}
		if current.Alert {
			return nil
		}
		current.Alert = true
		return putMetric(bucket, current)
	})
}

// SetTCPingLatest records the newest server-driven tcping sample for one
// target, merging into the record as it is at commit time. It replaces a
// Get + full-record Upsert outside any transaction, which could clobber a
// poll result or an admin edit that landed in between. Unknown systems and
// samples older than the stored one are ignored.
func (s *Store) SetTCPingLatest(id, target string, sample TCPingTargetData) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		data := bucket.Get([]byte(id))
		if data == nil {
			return nil
		}
		var current SystemMetric
		if err := json.Unmarshal(data, &current); err != nil {
			return fmt.Errorf("failed to decode metric: %w", err)
		}
		if current.TCPingData == nil {
			current.TCPingData = make(map[string]TCPingTargetData)
		}
		if cur, ok := current.TCPingData[target]; ok && cur.Timestamp.After(sample.Timestamp) {
			return nil
		}
		current.TCPingData[target] = sample
		return putMetric(bucket, current)
	})
}

// mergeAdminOwned copies the fields only the admin may change from the
// record currently on disk into an agent-supplied metric. Agents compose
// their record from a snapshot read moments earlier, so without this an
// admin edit that lands between that read and the agent's write would be
// silently reverted (name, tags, order, secret, visibility toggles). The
// per-target "latest tcping" map is merged as well: an entry the agent only
// copied from an earlier read never overrides a newer stored one (a
// concurrent server-side tcping write is not lost), whereas a target this
// write carries a fresh sample for (dst.TCPingFresh) always wins, so a
// stored stamp that ended up in the future cannot freeze the card. Entries
// for targets that are no longer configured are dropped when the current
// target set (allowed) is known, so a write composed from a stale copy
// cannot resurrect a target the admin removed.
func mergeAdminOwned(dst *SystemMetric, current *SystemMetric, allowed map[string]struct{}) {
	dst.Name = current.Name
	dst.Tags = current.Tags
	dst.Order = current.Order
	dst.Secret = current.Secret
	dst.HideOnHome = current.HideOnHome
	dst.HideTCPing = current.HideTCPing
	for target, cur := range current.TCPingData {
		if _, fresh := dst.TCPingFresh[target]; fresh {
			continue
		}
		if mine, ok := dst.TCPingData[target]; !ok || cur.Timestamp.After(mine.Timestamp) {
			if dst.TCPingData == nil {
				dst.TCPingData = make(map[string]TCPingTargetData, len(current.TCPingData))
			}
			dst.TCPingData[target] = cur
		}
	}
	pruneTCPingMap(dst.TCPingData, allowed)
}

// pruneTCPingMap drops entries for targets outside allowed. A nil allowed
// set means the configured targets are unknown and nothing is dropped.
func pruneTCPingMap(data map[string]TCPingTargetData, allowed map[string]struct{}) {
	if allowed == nil {
		return
	}
	for target := range data {
		if _, ok := allowed[target]; !ok {
			delete(data, target)
		}
	}
}

// allowedTCPingTargets reads the configured tcping targets inside tx. It
// returns nil when no configuration is stored or it cannot be decoded, in
// which case callers keep every entry.
func allowedTCPingTargets(tx *bolt.Tx) map[string]struct{} {
	bucket := tx.Bucket([]byte(configBucket))
	if bucket == nil {
		return nil
	}
	data := bucket.Get([]byte(configKey))
	if data == nil {
		return nil
	}
	var cfg TCPingConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	allowed := make(map[string]struct{}, len(cfg.Targets))
	for _, t := range cfg.Targets {
		allowed[t.Address] = struct{}{}
	}
	return allowed
}

// putAgentMetric writes an agent-supplied record inside tx, taking the
// admin-owned fields from the stored record in the same transaction (see
// mergeAdminOwned). Unknown systems are stored as-is.
func putAgentMetric(tx *bolt.Tx, bucket *bolt.Bucket, metric SystemMetric) error {
	allowed := allowedTCPingTargets(tx)
	merged := false
	if data := bucket.Get([]byte(metric.ID)); data != nil {
		var current SystemMetric
		if err := json.Unmarshal(data, &current); err == nil {
			mergeAdminOwned(&metric, &current, allowed)
			merged = true
		}
	}
	if !merged {
		pruneTCPingMap(metric.TCPingData, allowed)
	}
	return putMetric(bucket, metric)
}

// UpdateOrders sets Order = index for every listed system inside one write
// transaction, touching only that field. The previous implementation did a
// Get + full-record Upsert per system: N fsyncs queued behind the agent
// writes (seconds for a hundred systems on a VPS disk) and a
// read-modify-write that could overwrite metrics a push had just stored.
func (s *Store) UpdateOrders(ids []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		for i, id := range ids {
			data := bucket.Get([]byte(id))
			if data == nil {
				continue
			}
			var metric SystemMetric
			if err := json.Unmarshal(data, &metric); err != nil {
				continue
			}
			if metric.Order == i {
				continue
			}
			metric.Order = i
			out, err := json.Marshal(metric)
			if err != nil {
				return fmt.Errorf("failed to marshal metric: %w", err)
			}
			if err := bucket.Put([]byte(id), out); err != nil {
				return fmt.Errorf("failed to put metric: %w", err)
			}
		}
		return nil
	})
}

// PruneTCPingTargets removes the given targets from every system's "latest
// tcping" map in one transaction (used when targets are deleted from the
// tcping config).
func (s *Store) PruneTCPingTargets(targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	removed := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		removed[t] = struct{}{}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		type change struct {
			key  []byte
			data []byte
		}
		var changes []change
		err := bucket.ForEach(func(k, v []byte) error {
			var metric SystemMetric
			if err := json.Unmarshal(v, &metric); err != nil || len(metric.TCPingData) == 0 {
				return nil
			}
			mutated := false
			for target := range metric.TCPingData {
				if _, gone := removed[target]; gone {
					delete(metric.TCPingData, target)
					mutated = true
				}
			}
			if !mutated {
				return nil
			}
			out, err := json.Marshal(metric)
			if err != nil {
				return err
			}
			changes = append(changes, change{key: append([]byte(nil), k...), data: out})
			return nil
		})
		if err != nil {
			return err
		}
		for _, c := range changes {
			if err := bucket.Put(c.key, c.data); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpsertFromAgent is Upsert for records produced from agent data (pull
// polling, legacy /api/metrics ingest). Admin-owned fields are taken from
// the stored record atomically; see putAgentMetric.
func (s *Store) UpsertFromAgent(metric SystemMetric) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		return putAgentMetric(tx, bucket, metric)
	})
}

// List returns all system metrics sorted by order
func (s *Store) List() ([]SystemMetric, error) {
	metrics := make([]SystemMetric, 0)

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var metric SystemMetric
			if err := json.Unmarshal(v, &metric); err != nil {
				log.Printf("⚠️ Failed to unmarshal metric %s: %v", string(k), err)
				return nil // Skip corrupted entry
			}
			metrics = append(metrics, metric)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by order field (ascending)
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Order < metrics[j].Order
	})

	return metrics, nil
}

// Get retrieves a specific system metric by ID
func (s *Store) Get(id string) (*SystemMetric, error) {
	var metric SystemMetric

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("metric not found")
		}

		return json.Unmarshal(data, &metric)
	})

	if err != nil {
		return nil, err
	}

	return &metric, nil
}

// Delete removes a system metric by ID
func (s *Store) Delete(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.Delete([]byte(id))
	})
}

// Count returns the number of systems in the database
func (s *Store) Count() int {
	count := 0
	s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket != nil {
			count = bucket.Stats().KeyN
		}
		return nil
	})
	return count
}

// DBPath returns the database file path from environment or default
func DBPath() string {
	if path := os.Getenv("DB_PATH"); path != "" {
		return path
	}
	return defaultDBPath
}

// TCPingResult represents a tcping result
type TCPingResult struct {
	ClientID  string    `json:"client_id"`
	Target    string    `json:"target"`  // Target address (e.g., "8.8.8.8:53")
	Latency   *float64  `json:"latency"` // Latency in milliseconds (nil for timeout/failure)
	Timestamp time.Time `json:"timestamp"`
	// ExactTimestamp is set by handleClientPush when Timestamp is the agent's
	// own unmodified measurement time. Only then does (timestamp, client,
	// target) identify one measurement, so only then may a batch write skip an
	// existing record as a re-send. Server-stamped or clock-adjusted samples
	// go through the sequence-number path and are never dropped.
	ExactTimestamp bool `json:"-"`
}

func tcpingResultKeyPrefix(result TCPingResult) string {
	return fmt.Sprintf("%d_%s_%09d_", result.Timestamp.Unix(), result.ClientID, result.Timestamp.Nanosecond())
}

// tcpingResultKey is the single definition of the on-disk key layout:
// "<unix-seconds>_<client>_<nanosecond>_<sequence>_<target>". Both writers
// below and the prefix scans in GetTCPingResults depend on it.
func tcpingResultKey(result TCPingResult, seq int) []byte {
	return []byte(fmt.Sprintf("%s%06d_%s", tcpingResultKeyPrefix(result), seq, result.Target))
}

func putTCPingResult(bucket *bolt.Bucket, result TCPingResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal tcping result: %w", err)
	}

	for seq := 0; seq < 1_000_000; seq++ {
		key := tcpingResultKey(result, seq)
		if bucket.Get(key) == nil {
			return bucket.Put(key, data)
		}
	}
	return fmt.Errorf("too many tcping results for %s/%s at %s", result.ClientID, result.Target, result.Timestamp.Format(time.RFC3339Nano))
}

// putTCPingResultIdempotent is putTCPingResult for agent-timestamped
// batches. An agent re-sends the same measurements when its push timed out
// after the server had already committed them, so an existing record with
// the identical (timestamp, client, target) key is that same measurement,
// not a second sample, and is left untouched. Server-stamped results
// (SaveTCPingResult) keep the sequence-number path because two genuinely
// distinct samples can share a wall-clock instant there.
func putTCPingResultIdempotent(bucket *bolt.Bucket, result TCPingResult) error {
	key := tcpingResultKey(result, 0)
	if bucket.Get(key) != nil {
		return nil
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal tcping result: %w", err)
	}
	return bucket.Put(key, data)
}

// SaveTCPingResult saves a tcping result
func (s *Store) SaveTCPingResult(result TCPingResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return putTCPingResult(bucket, result)
	})
}

// SaveClientPushBatch atomically writes the system metric and all tcping
// results from a single push in one bbolt transaction. Admin-owned fields
// are taken from the stored record inside the transaction (putAgentMetric).
func (s *Store) SaveClientPushBatch(metric SystemMetric, tcpingResults []TCPingResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		systems := tx.Bucket([]byte(bucketName))
		if systems == nil {
			return fmt.Errorf("systems bucket not found")
		}
		if err := putAgentMetric(tx, systems, metric); err != nil {
			return err
		}

		if len(tcpingResults) == 0 {
			return nil
		}
		tcping := tx.Bucket([]byte(tcpingBucket))
		if tcping == nil {
			return fmt.Errorf("tcping bucket not found")
		}
		for _, r := range tcpingResults {
			if r.Target == "" {
				continue
			}
			var err error
			if r.ExactTimestamp {
				err = putTCPingResultIdempotent(tcping, r)
			} else {
				err = putTCPingResult(tcping, r)
			}
			if err != nil {
				return fmt.Errorf("put tcping result: %w", err)
			}
		}
		return nil
	})
}

// GetTCPingResults returns all tcping results for a client within 24 hours.
// If target is provided, only returns results for that target.
//
// Uses the same cursor-seek strategy as CleanupOldTCPingResults: keys are
// formatted as "<unix-seconds>_<client>_<nanosecond>_<sequence>_<target>"
// (older records used "<unix-seconds>_<client>_<target>"). Unix seconds
// fit in 10 characters until year 2286, so bbolt's lexicographic iteration
// order matches numeric timestamp order. Seeking directly to the cutoff
// prefix and walking forward avoids unmarshalling potentially hundreds of
// thousands of older records on busy deployments.
//
// Within a single second the suffix order is `<client>_<target>`, so records
// for one client/target chunk together. We still emit a final sort below to
// guarantee strict timestamp ordering across sub-second writes that share a
// timestamp but differ in client / target — which keeps callers free to
// assume the result slice is sorted.
func (s *Store) GetTCPingResults(clientID string, target ...string) ([]TCPingResult, error) {
	results := make([]TCPingResult, 0, 256)
	cutoffTime := time.Now().Add(-24 * time.Hour)
	cutoffPrefix := []byte(fmt.Sprintf("%d_", cutoffTime.Unix()))
	filterTarget := ""
	if len(target) > 0 {
		filterTarget = target[0]
	}

	clientPrefix := []byte(clientID + "_")
	var targetSuffix []byte
	if filterTarget != "" {
		targetSuffix = []byte("_" + filterTarget)
	}
	tsPrefixLen := len(cutoffPrefix)

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		c := bucket.Cursor()
		// Seek lands on the smallest key >= cutoffPrefix. Every record
		// from here forward is within the 24-hour window. Records older
		// than the cutoff are skipped entirely without unmarshalling.
		for k, v := c.Seek(cutoffPrefix); k != nil; k, v = c.Next() {
			if len(k) <= tsPrefixLen {
				continue
			}
			afterTS := k[tsPrefixLen:]
			if !bytes.HasPrefix(afterTS, clientPrefix) {
				continue
			}
			if targetSuffix != nil && !bytes.HasSuffix(k, targetSuffix) {
				continue
			}

			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				continue // Skip corrupted entry
			}

			if result.ClientID != clientID {
				continue
			}
			if filterTarget != "" && result.Target != filterTarget {
				continue
			}

			// Defensive: if a writer ever bypassed the timestamp-prefix
			// key format, the seek-skip wouldn't catch it. Re-verify the
			// 24-h window from the actual timestamp field. We use
			// `!After(cutoffTime)` (i.e. <=) to preserve the original
			// strict-greater-than semantic of the previous full-scan
			// implementation, so the visible window is unchanged.
			if !result.Timestamp.After(cutoffTime) {
				continue
			}

			results = append(results, result)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Stabilise sub-second-tie ordering for callers that assume strict
	// ascending-by-timestamp. The slice is already nearly sorted, so the
	// constant factor is small.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	return results, nil
}

// tcpingDeleteChunk bounds how many history records one write transaction
// removes. bbolt has a single writer, so one huge delete transaction would
// stall every agent push for its whole duration; chunks keep each pause to
// a few milliseconds and let pushes interleave.
const tcpingDeleteChunk = 5000

// collectTCPingKeys walks the history bucket and returns the keys of the
// records selected by candidate (a cheap test on the key alone) and
// confirmed by verify (run on the decoded record). Keys embed the client id
// and target ("<ts>_<client>_..._<target>"), so the vast majority of records
// are rejected without a JSON decode; verification guards against prefix
// collisions such as client "a" vs "a_b".
func (s *Store) collectTCPingKeys(candidate func(k []byte) bool, verify func(r TCPingResult) bool) ([][]byte, error) {
	var keys [][]byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}
		return bucket.ForEach(func(k, v []byte) error {
			if !candidate(k) {
				return nil
			}
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				return nil // corrupted entry: left for the hourly cleaner
			}
			if verify(result) {
				keys = append(keys, append([]byte(nil), k...))
			}
			return nil
		})
	})
	return keys, err
}

// deleteTCPingKeys removes keys from the history bucket in bounded
// transactions (see tcpingDeleteChunk).
func (s *Store) deleteTCPingKeys(keys [][]byte) error {
	for start := 0; start < len(keys); start += tcpingDeleteChunk {
		end := start + tcpingDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		chunk := keys[start:end]
		if err := s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}
			for _, key := range chunk {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// DeleteTCPingResultsByTarget deletes all tcping results for a specific target.
func (s *Store) DeleteTCPingResultsByTarget(target string) error {
	suffix := []byte("_" + target)
	keys, err := s.collectTCPingKeys(
		func(k []byte) bool { return bytes.HasSuffix(k, suffix) },
		func(r TCPingResult) bool { return r.Target == target },
	)
	if err != nil {
		return err
	}
	return s.deleteTCPingKeys(keys)
}

// DeleteTCPingResultsByClient deletes all tcping results for a specific client.
func (s *Store) DeleteTCPingResultsByClient(clientID string) error {
	clientPrefix := []byte(clientID + "_")
	keys, err := s.collectTCPingKeys(
		func(k []byte) bool {
			// Skip the "<unix-seconds>_" prefix, then require "<client>_".
			i := bytes.IndexByte(k, '_')
			return i >= 0 && bytes.HasPrefix(k[i+1:], clientPrefix)
		},
		func(r TCPingResult) bool { return r.ClientID == clientID },
	)
	if err != nil {
		return err
	}
	return s.deleteTCPingKeys(keys)
}

// CleanupOldTCPingResults removes tcping results older than 24 hours.
//
// Keys start with "<unix-seconds>_" where the timestamp is always 10 digits
// until year 2286, so bbolt's lexicographic iteration order matches numeric
// timestamp order. We therefore stop iterating as soon as we encounter a
// record newer than the cutoff, avoiding a full-bucket scan of potentially
// hundreds of thousands of entries every hour on busy deployments.
func (s *Store) cleanupOldTCPingResults() (int, error) {
	cutoffTime := time.Now().Add(-24 * time.Hour)
	cutoffPrefix := []byte(fmt.Sprintf("%d_", cutoffTime.Unix()))
	var keysToDelete [][]byte

	// First pass: collect keys to delete using a cursor with early-exit.
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// Fast path: if the key's numeric prefix is already >= cutoff
			// prefix, every remaining key is newer too — stop iterating.
			// Compare only the 11-byte "<ts>_" prefix to avoid interpreting
			// the client-id / target suffix. Short keys (legacy / corrupt)
			// fall through to the JSON branch below.
			if len(k) >= len(cutoffPrefix) && bytes.Compare(k[:len(cutoffPrefix)], cutoffPrefix) >= 0 {
				return nil
			}

			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				// Corrupted entry, mark for deletion
				keysToDelete = append(keysToDelete, append([]byte(nil), k...))
				continue
			}

			if result.Timestamp.Before(cutoffTime) {
				keysToDelete = append(keysToDelete, append([]byte(nil), k...))
			}
		}
		return nil
	})

	if err != nil {
		return 0, err
	}

	// Second pass: delete old entries in bounded transactions so the hourly
	// cleaner never holds the write lock long enough to stall agent pushes.
	if err := s.deleteTCPingKeys(keysToDelete); err != nil {
		return 0, err
	}

	return len(keysToDelete), nil
}

func (s *Store) CleanupOldTCPingResults() error {
	_, err := s.cleanupOldTCPingResults()
	return err
}

// TCPingTargetEntry represents a single tcping target with name and address
type TCPingTargetEntry struct {
	Name    string `json:"name"`    // Display name for the target (e.g., "Google DNS")
	Address string `json:"address"` // Target address (e.g., "8.8.8.8:53")
}

// TCPingConfig represents the tcping configuration
type TCPingConfig struct {
	Targets      []TCPingTargetEntry `json:"targets"`       // List of target entries with name and address
	IntervalSecs int                 `json:"interval_secs"` // Polling interval in seconds
}

// GetTCPingConfig retrieves the tcping configuration
func (s *Store) GetTCPingConfig() (*TCPingConfig, error) {
	var config TCPingConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data := bucket.Get([]byte(configKey))
		if data == nil {
			// Return default config if not found: no targets, 60s interval
			config = TCPingConfig{
				Targets:      []TCPingTargetEntry{},
				IntervalSecs: 60,
			}
			return nil
		}

		// Try to unmarshal as new format first
		if err := json.Unmarshal(data, &config); err == nil {
			// Successfully unmarshaled as new format
			return nil
		}

		// Try to unmarshal as old format ([]string) for backward compatibility
		var oldTargets []string
		var oldConfig struct {
			Targets      []string `json:"targets"`
			IntervalSecs int      `json:"interval_secs"`
		}
		if err := json.Unmarshal(data, &oldConfig); err == nil {
			// Convert old format to new format
			config.IntervalSecs = oldConfig.IntervalSecs
			config.Targets = make([]TCPingTargetEntry, len(oldConfig.Targets))
			for i, addr := range oldConfig.Targets {
				config.Targets[i] = TCPingTargetEntry{
					Name:    addr, // Use address as default name
					Address: addr,
				}
			}
			return nil
		}

		// If both fail, try just the targets array
		if err := json.Unmarshal(data, &oldTargets); err == nil {
			// Convert old format to new format
			config.IntervalSecs = 60
			config.Targets = make([]TCPingTargetEntry, len(oldTargets))
			for i, addr := range oldTargets {
				config.Targets[i] = TCPingTargetEntry{
					Name:    addr, // Use address as default name
					Address: addr,
				}
			}
			return nil
		}

		// If all fail, return the original error
		return json.Unmarshal(data, &config)
	})

	if err != nil {
		return nil, err
	}

	if config.Targets == nil {
		config.Targets = []TCPingTargetEntry{}
	}

	return &config, nil
}

// SaveTCPingConfig saves the tcping configuration
func (s *Store) SaveTCPingConfig(config *TCPingConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		return bucket.Put([]byte(configKey), data)
	})
}

// CheckPasswordSet checks if a password has been set
func (s *Store) CheckPasswordSet() (bool, error) {
	var exists bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return nil
		}
		exists = bucket.Get([]byte(passwordKey)) != nil
		return nil
	})
	return exists, err
}

// SetPassword sets the admin password (hashed)
func (s *Store) SetPassword(password string) error {
	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		return bucket.Put([]byte(passwordKey), hashedPassword)
	})
}

// VerifyPassword verifies the admin password
func (s *Store) VerifyPassword(password string) (bool, error) {
	var hashedPassword []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		raw := bucket.Get([]byte(passwordKey))
		if raw == nil {
			return fmt.Errorf("password not set")
		}
		hashedPassword = append([]byte(nil), raw...)
		return nil
	})
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	return err == nil, nil
}

// GenerateAuthToken generates a random auth token
func GenerateAuthToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// NavbarConfig represents the navbar configuration
type NavbarConfig struct {
	Text         string `json:"text"`          // Custom text for navbar (default: "Pulse")
	Logo         string `json:"logo"`          // Custom logo URL or SVG (default: built-in SVG)
	SharedSecret string `json:"shared_secret"` // Shared secret for all clients
	CustomCSS    string `json:"custom_css"`    // Custom CSS styles for all pages
	CustomJS     string `json:"custom_js"`     // Custom JavaScript for all pages
	ShowTraffic  bool   `json:"show_traffic"`  // Show real-time and total traffic in detail dropdown
	ShowGlass    bool   `json:"show_glass"`    // Enable glassmorphism (frosted glass) visual effect
	HideTags     bool   `json:"hide_tags"`     // Hotaru-compatible: hide tag row on homepage
	HideCards    bool   `json:"hide_cards"`    // Hotaru-compatible: hide homepage card grid
}

// GetNavbarConfig retrieves the navbar configuration
func (s *Store) GetNavbarConfig() (*NavbarConfig, error) {
	var config NavbarConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data := bucket.Get([]byte(navbarConfigKey))
		if data == nil {
			// Return default config if not found
			config = NavbarConfig{
				Text:         "Pulse",
				Logo:         "", // Empty means use default SVG
				SharedSecret: "", // Will be generated if needed
			}
			return nil
		}

		return json.Unmarshal(data, &config)
	})

	if err != nil {
		return nil, err
	}

	// Generate shared secret if not set
	if config.SharedSecret == "" {
		// Generate new shared secret
		bytes := make([]byte, 12)
		if _, err := rand.Read(bytes); err == nil {
			config.SharedSecret = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
		} else {
			// Fallback to timestamp-based secret if crypto/rand fails
			config.SharedSecret = fmt.Sprintf("%x", time.Now().UnixNano())[:16]
		}
		// Persist the generated secret. Log failures explicitly: silently
		// swallowing the error used to mask situations where the DB was
		// read-only or full, which then caused every subsequent read to
		// regenerate a fresh secret and break already-registered clients.
		if err := s.SaveNavbarConfig(&config); err != nil {
			log.Printf("⚠️  Failed to persist generated shared secret: %v", err)
		}
	}

	return &config, nil
}

// SaveNavbarConfig saves the navbar configuration
func (s *Store) SaveNavbarConfig(config *NavbarConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		return bucket.Put([]byte(navbarConfigKey), data)
	})
}

// PrivacyConfig represents the privacy configuration
type PrivacyConfig struct {
	Enabled          bool      `json:"enabled"`            // Whether privacy mode is enabled
	ShareToken       string    `json:"share_token"`        // Temporary share token
	TokenExpires     time.Time `json:"token_expires"`      // Token expiration time
	ExpiresInSeconds int       `json:"expires_in_seconds"` // Saved expiration seconds value for UI
}

// GetPrivacyConfig retrieves the privacy configuration
func (s *Store) GetPrivacyConfig() (*PrivacyConfig, error) {
	var config PrivacyConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data := bucket.Get([]byte(privacyConfigKey))
		if data == nil {
			// Return default config if not found
			config = PrivacyConfig{
				Enabled:          false,
				ShareToken:       "",
				TokenExpires:     time.Time{},
				ExpiresInSeconds: 3600, // Default to 1 hour (3600 seconds)
			}
			return nil
		}

		return json.Unmarshal(data, &config)
	})

	if err != nil {
		return nil, err
	}

	return &config, nil
}

// SavePrivacyConfig saves the privacy configuration
func (s *Store) SavePrivacyConfig(config *PrivacyConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}

		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		return bucket.Put([]byte(privacyConfigKey), data)
	})
}
