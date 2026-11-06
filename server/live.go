package main

// live.go: the agents' live state in memory, written behind (since v1.3.70).
//
// v1.3.69 rewrites a server's whole record (about 1 KB of JSON, a 4 KB leaf
// page plus the branch, root and meta pages of its commit) on every push:
// 131 agents every 3 s made about 250 KB/s, 21 GB a day, of which the live
// numbers are nearly all. Here a push that carries no TCPing samples only
// updates memory; the records are written together once a minute
// (PULSE_LIVE_FLUSH), when a server goes offline, before a backup and at
// shutdown. TCPing samples are still committed before the push is answered
// (an agent drops what it was told is stored), now without the record and in
// groups (PULSE_TCPING_COMMIT_DELAY, default 2 s, instead of 100 ms).
//
// Readers see the memory: Store.Get and Store.List lay the newer in-memory
// copy of a record over the stored one, taking the admin's fields (name,
// tags, order, secret, visibility) and newer server-side TCPing entries from
// the stored record, exactly as putAgentMetric merges a push today.
//
// Storage health: a push that writes nothing cannot show that storage works.
// While storeHealth reports failing, pushes without samples are refused (500,
// not counted) as before, so rows still go offline and /healthz says 503; the
// flusher then probes storage every 5 s to notice the recovery.
//
// Lost on kill -9: up to one flush interval of live values (the "last seen"
// of a server that went offline is written when it goes offline). Nothing on
// a clean stop. TCPing history: nothing, as before.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var errStoreFailing = errors.New("storage is failing: push not accepted")

func durationFromEnv(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	return def
}

// liveFlushInterval: 0 turns the overlay off (v1.3.69 behaviour).
var liveFlushInterval = durationFromEnv("PULSE_LIVE_FLUSH", time.Minute)

type liveEntry struct {
	m     SystemMetric
	gen   uint64
	dirty bool
}

type liveOverlay struct {
	mu      sync.Mutex
	entries map[string]*liveEntry
	gen     uint64
	flushMu sync.Mutex
}

func newLiveOverlay() *liveOverlay { return &liveOverlay{entries: make(map[string]*liveEntry)} }

func copyTCPingData(in map[string]TCPingTargetData) map[string]TCPingTargetData {
	if in == nil {
		return nil
	}
	out := make(map[string]TCPingTargetData, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyFresh(in map[string]struct{}) map[string]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

// set keeps an agent-composed record (the last push wins, as the last commit
// did). TCPing entries the record has no fresh sample for keep the newer of
// the two copies (by sample time, as mergeAdminOwned), and the fresh set
// accumulates until the next flush. Nothing here compares UpdatedAt: the
// wall clock can step back (it did on xhh.li on 2026-11-06, by 2m15s), and an
// overlay ordered by it would freeze every row for as long.
func (l *liveOverlay) set(m SystemMetric) {
	n := m
	n.TCPingData = copyTCPingData(m.TCPingData)
	n.TCPingFresh = copyFresh(m.TCPingFresh)
	n.Tags = nil // admin-owned: always taken from the stored record
	l.mu.Lock()
	defer l.mu.Unlock()
	if old := l.entries[m.ID]; old != nil {
		for t, cur := range old.m.TCPingData {
			if _, fresh := n.TCPingFresh[t]; fresh {
				continue
			}
			if mine, ok := n.TCPingData[t]; !ok || cur.Timestamp.After(mine.Timestamp) {
				if n.TCPingData == nil {
					n.TCPingData = make(map[string]TCPingTargetData)
				}
				n.TCPingData[t] = cur
			}
		}
		if old.dirty {
			for t := range old.m.TCPingFresh {
				if n.TCPingFresh == nil {
					n.TCPingFresh = make(map[string]struct{})
				}
				n.TCPingFresh[t] = struct{}{}
			}
		}
	}
	l.gen++
	l.entries[m.ID] = &liveEntry{m: n, gen: l.gen, dirty: true}
}

// copyOf returns a private copy of id's entry.
func (l *liveOverlay) copyOf(id string) (SystemMetric, uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[id]
	if e == nil {
		return SystemMetric{}, 0, false
	}
	m := e.m
	m.TCPingData = copyTCPingData(e.m.TCPingData)
	m.TCPingFresh = copyFresh(e.m.TCPingFresh)
	return m, e.gen, true
}

// apply lays id's in-memory record over rec (read from the store). An entry
// is always newer than the stored agent fields: the paths that write agent
// data straight to the store (a poll, the legacy ingest, MarkOffline) drop it.
func (l *liveOverlay) apply(rec *SystemMetric, allowed func() map[string]struct{}) {
	if l == nil {
		return
	}
	m, _, ok := l.copyOf(rec.ID)
	if !ok {
		return
	}
	mergeAdminOwned(&m, rec, allowed())
	m.TCPingFresh = nil
	*rec = m
}

// dropIfGen drops id's entry unless a newer push replaced it.
func (l *liveOverlay) dropIfGen(id string, gen uint64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if e := l.entries[id]; e != nil && e.gen == gen {
		delete(l.entries, id)
	}
	l.mu.Unlock()
}

func (l *liveOverlay) drop(id string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.entries, id)
	l.mu.Unlock()
}

// markClean marks the entries written by a flush as stored, unless a newer
// push replaced them meanwhile.
func (l *liveOverlay) markClean(gens map[string]uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, gen := range gens {
		if e := l.entries[id]; e != nil && e.gen == gen {
			e.dirty = false
			e.m.TCPingFresh = nil
		}
	}
}

// lazyAllowed decodes the configured targets once, and only when needed.
func lazyAllowed(tx *bolt.Tx) func() map[string]struct{} {
	var once sync.Once
	var allowed map[string]struct{}
	return func() map[string]struct{} {
		once.Do(func() { allowed = allowedTCPingTargets(tx) })
		return allowed
	}
}

// saveLivePush is SaveClientPushBatch with the overlay on.
func (s *Store) saveLivePush(metric SystemMetric, tcpingResults []TCPingResult) error {
	rows := 0
	for _, r := range tcpingResults {
		if r.Target != "" {
			rows++
		}
	}
	if rows == 0 {
		if storeHealth.failing(time.Now()) {
			// Nothing of this push needs the disk, but while storage fails a
			// push does not count (v1.3.69): each one probes it instead, at
			// most one commit a second, so a recovery is seen at once.
			if err := s.probeShared(time.Now()); err != nil {
				return err
			}
			storeHealth.stored(time.Now())
		}
		exists := false
		_ = s.db.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket([]byte(bucketName)); b != nil {
				exists = b.Get([]byte(metric.ID)) != nil
			}
			return nil
		})
		if exists { // a server deleted meanwhile keeps its deletion
			s.live.set(metric)
		}
		return nil
	}
	err := s.db.Batch(func(tx *bolt.Tx) error {
		systems := tx.Bucket([]byte(bucketName))
		if systems == nil {
			return fmt.Errorf("systems bucket not found")
		}
		if systems.Get([]byte(metric.ID)) == nil {
			return nil // deleted while in flight: its samples go too
		}
		tcping := tx.Bucket([]byte(tcpingBucket))
		if tcping == nil {
			return fmt.Errorf("tcping bucket not found")
		}
		seqMemo := make(map[string]int)
		for _, r := range tcpingResults {
			if r.Target == "" {
				continue
			}
			var err error
			if r.ExactTimestamp {
				err = putTCPingResultIdempotent(tcping, r)
			} else {
				err = putTCPingResultFrom(tcping, r, seqMemo)
			}
			if err != nil {
				return fmt.Errorf("put tcping result: %w", err)
			}
		}
		return nil
	})
	if err == nil {
		s.live.set(metric)
	}
	return err
}

// FlushLive writes every record changed in memory since the last flush, in
// one transaction, and returns how many it wrote (0: no commit was made).
func (s *Store) FlushLive() (int, error) {
	if s.live == nil {
		return 0, nil
	}
	l := s.live
	l.flushMu.Lock()
	defer l.flushMu.Unlock()
	type item struct {
		m   SystemMetric
		gen uint64
	}
	l.mu.Lock()
	items := make([]item, 0, len(l.entries))
	for _, e := range l.entries {
		if e.dirty {
			m := e.m
			m.TCPingData = copyTCPingData(e.m.TCPingData)
			m.TCPingFresh = copyFresh(e.m.TCPingFresh)
			items = append(items, item{m, e.gen})
		}
	}
	l.mu.Unlock()
	if len(items) == 0 {
		return 0, nil
	}
	var gone []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		gone = gone[:0]
		systems := tx.Bucket([]byte(bucketName))
		if systems == nil {
			return fmt.Errorf("bucket not found")
		}
		allowed := allowedTCPingTargets(tx)
		for _, it := range items {
			data := systems.Get([]byte(it.m.ID))
			if data == nil {
				gone = append(gone, it.m.ID)
				continue
			}
			m := it.m
			var cur SystemMetric
			if err := json.Unmarshal(data, &cur); err == nil {
				mergeAdminOwned(&m, &cur, allowed)
			} else {
				pruneTCPingMap(m.TCPingData, allowed)
			}
			if err := putMetric(systems, m); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	gens := make(map[string]uint64, len(items))
	for _, it := range items {
		gens[it.m.ID] = it.gen
	}
	l.markClean(gens)
	for _, id := range gone {
		l.drop(id)
	}
	return len(items), nil
}

var probeState struct {
	sync.Mutex
	at  time.Time
	err error
}

// probeShared runs probeWrite unless one ran within the last second, whose
// result it returns (errStoreFailing when that one failed).
func (s *Store) probeShared(now time.Time) error {
	probeState.Lock()
	defer probeState.Unlock()
	if !probeState.at.IsZero() && now.Sub(probeState.at) < time.Second {
		if probeState.err != nil {
			return errStoreFailing
		}
		return nil
	}
	probeState.err = probeStorage(s, now)
	probeState.at = now
	return probeState.err
}

// probeStorage writes the probe (tests make it fail).
var probeStorage = func(s *Store, now time.Time) error { return s.probeWrite(now) }

// probeWrite is a small commit that shows whether storage takes writes; the
// flusher uses it while storage is failing and nothing else is written.
func (s *Store) probeWrite(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(configBucket))
		if b == nil {
			return fmt.Errorf("config bucket not found")
		}
		return b.Put([]byte("storage_probe"), []byte(now.UTC().Format(time.RFC3339Nano)))
	})
}

// startLiveFlush writes the in-memory records every liveFlushInterval, and
// probes storage every 5 s while it is failing.
func startLiveFlush(ctx context.Context, store *Store) {
	if store == nil || store.live == nil {
		return
	}
	for {
		wait := liveFlushInterval
		if storeHealth.failing(time.Now()) {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		failing := storeHealth.failing(time.Now())
		n, err := store.FlushLive()
		if err == nil && n == 0 && failing {
			err, n = probeStorage(store, time.Now()), 1
		}
		switch {
		case err != nil:
			storeHealth.failed(time.Now(), err)
		case n > 0:
			storeHealth.stored(time.Now())
		}
	}
}
