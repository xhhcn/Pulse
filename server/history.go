package main

// Resource history and the latency summary: two dashboard features behind
// 自定义设置 switches, both off by default (NavbarConfig.ResourceHistory and
// NavbarConfig.LatencyView).
//
// Resource history: from the server's start, each agent report adds its CPU,
// memory and disk percentages and network speeds to the server's sums for
// the current minute; once a minute the finished minutes are written as one
// averaged sample per server, and every ten minutes samples older than 24
// hours are removed. The switch only shows them (the 资源 tab, and
// GET /api/resource/history?client_id= answering), so a site that turns it
// on sees its last day at once. Storage: a "resource_history" bucket with
// one nested bucket per server, keyed by the minute (8-byte big endian),
// each value five float32 (20 bytes): about 45 bytes a sample on disk, some
// 8 MB for 131 servers' day (their TCPing history: about 85 MB); one write
// a minute.
//
// Latency summary: GET /api/tcping/summary answers every server's average
// latency and loss per TCPing target over the last hour, computed from the
// stored probes at most once a minute.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	resourceHistoryBucket = "resource_history"
	resourceHistoryWindow = 24 * time.Hour
	// a probe slower than this counts as lost, as the dashboard draws it
	tcpingLossThresholdMs = 1000.0
	latencySummaryWindow  = time.Hour
	latencySummaryTTL     = time.Minute
)

// ---------- the per-minute sums ----------

type resourceSums struct {
	cpu, mem, disk, in, out float64
	n                       int
}

type resourceKey struct {
	id     string
	minute int64
}

type resourceRecorder struct {
	mu   sync.Mutex
	sums map[resourceKey]*resourceSums
	// takenBefore: the minutes before it have been taken (written). A report
	// for one of them counts toward this minute instead: a push stamped
	// 12:00:59 whose save ended after 12:01:02 would otherwise start that
	// minute's sums again, and its one sample would overwrite the minute's
	// stored average.
	takenBefore int64
}

var resourceRec = &resourceRecorder{sums: make(map[resourceKey]*resourceSums)}

func (rr *resourceRecorder) reset() {
	rr.mu.Lock()
	rr.sums = make(map[resourceKey]*resourceSums)
	rr.takenBefore = 0
	rr.mu.Unlock()
}

// add counts one report of a server into its minute (or, when that minute
// was already written, into the first one not yet written).
func (rr *resourceRecorder) add(m SystemMetric, at time.Time) {
	if m.ID == "" {
		return
	}
	rr.mu.Lock()
	k := resourceKey{id: m.ID, minute: at.Unix() / 60}
	if k.minute < rr.takenBefore {
		k.minute = rr.takenBefore
	}
	s := rr.sums[k]
	if s == nil {
		s = &resourceSums{}
		rr.sums[k] = s
	}
	s.cpu += finiteOr0(m.CPU)
	s.mem += finiteOr0(m.Memory)
	s.disk += finiteOr0(m.Disk)
	s.in += finiteOr0(m.NetInMBps)
	s.out += finiteOr0(m.NetOutMBps)
	s.n++
	rr.mu.Unlock()
}

// forget drops a deleted server's unwritten minutes.
func (rr *resourceRecorder) forget(id string) {
	rr.mu.Lock()
	for k := range rr.sums {
		if k.id == id {
			delete(rr.sums, k)
		}
	}
	rr.mu.Unlock()
}

// take removes and averages every minute before `before`.
func (rr *resourceRecorder) take(before int64) []resourceSample {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if before > rr.takenBefore {
		rr.takenBefore = before
	}
	out := make([]resourceSample, 0, len(rr.sums))
	for k, s := range rr.sums {
		if k.minute >= before {
			continue
		}
		delete(rr.sums, k)
		if s.n == 0 {
			continue
		}
		n := float64(s.n)
		out = append(out, resourceSample{ID: k.id, Minute: k.minute, CPU: s.cpu / n, Mem: s.mem / n, Disk: s.disk / n, In: s.in / n, Out: s.out / n})
	}
	return out
}

func finiteOr0(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// ---------- storage ----------

type resourceSample struct {
	ID                      string
	Minute                  int64 // unix minutes
	CPU, Mem, Disk, In, Out float64
}

func resourceKeyBytes(minute int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(minute))
	return b
}

func encodeResourceValue(s resourceSample) []byte {
	b := make([]byte, 20)
	for i, v := range []float64{s.CPU, s.Mem, s.Disk, s.In, s.Out} {
		binary.LittleEndian.PutUint32(b[i*4:], math.Float32bits(float32(v)))
	}
	return b
}

func decodeResourceValue(b []byte) (cpu, mem, disk, in, out float64, ok bool) {
	if len(b) < 20 {
		return 0, 0, 0, 0, 0, false
	}
	f := func(i int) float64 { return float64(math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))) }
	return f(0), f(1), f(2), f(3), f(4), true
}

// SaveResourceSamples writes averaged minutes, one nested bucket per server.
// A server that no longer exists gets none (it was deleted meanwhile).
func (s *Store) SaveResourceSamples(samples []resourceSample) error {
	if len(samples) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		systems := tx.Bucket([]byte(bucketName))
		root, err := tx.CreateBucketIfNotExists([]byte(resourceHistoryBucket))
		if err != nil {
			return err
		}
		for _, sm := range samples {
			if systems == nil || systems.Get([]byte(sm.ID)) == nil {
				continue
			}
			b, err := root.CreateBucketIfNotExists([]byte(sm.ID))
			if err != nil {
				return err
			}
			// Each server's minutes only ever grow at the end: full pages
			// (bbolt splits at half by default, which left them half empty)
			b.FillPercent = 1
			if err := b.Put(resourceKeyBytes(sm.Minute), encodeResourceValue(sm)); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetResourceHistory returns one server's samples from `since`, oldest first.
func (s *Store) GetResourceHistory(clientID string, since time.Time) ([]resourceSample, error) {
	out := make([]resourceSample, 0, 1440)
	err := s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(resourceHistoryBucket))
		if root == nil {
			return nil
		}
		b := root.Bucket([]byte(clientID))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(resourceKeyBytes(since.Unix() / 60)); k != nil; k, v = c.Next() {
			if len(k) != 8 {
				continue
			}
			cpu, mem, disk, in, outv, ok := decodeResourceValue(v)
			if !ok {
				continue
			}
			out = append(out, resourceSample{ID: clientID, Minute: int64(binary.BigEndian.Uint64(k)), CPU: cpu, Mem: mem, Disk: disk, In: in, Out: outv})
		}
		return nil
	})
	return out, err
}

// PruneResourceHistory removes samples older than cutoff, and the buckets of
// servers that have none left.
func (s *Store) PruneResourceHistory(cutoff time.Time) error {
	limit := resourceKeyBytes(cutoff.Unix() / 60)
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(resourceHistoryBucket))
		if root == nil {
			return nil
		}
		var empty [][]byte
		err := root.ForEach(func(name, v []byte) error {
			if v != nil {
				return nil
			}
			b := root.Bucket(name)
			if b == nil {
				return nil
			}
			c := b.Cursor()
			for k, _ := c.First(); k != nil && bytes.Compare(k, limit) < 0; k, _ = c.First() {
				if err := c.Delete(); err != nil {
					return err
				}
			}
			if k, _ := b.Cursor().First(); k == nil {
				empty = append(empty, append([]byte(nil), name...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, name := range empty {
			if err := root.DeleteBucket(name); err != nil && err != bolt.ErrBucketNotFound {
				return err
			}
		}
		return nil
	})
}

// DeleteResourceHistory removes a server's samples (the server was deleted).
func (s *Store) DeleteResourceHistory(clientID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(resourceHistoryBucket))
		if root == nil {
			return nil
		}
		if err := root.DeleteBucket([]byte(clientID)); err != nil && err != bolt.ErrBucketNotFound {
			return err
		}
		return nil
	})
}

// flushResourceHistory writes the finished minutes and drops old samples.
func flushResourceHistory(store *Store, now time.Time) {
	samples := resourceRec.take(now.Unix() / 60)
	if len(samples) > 0 {
		if err := store.SaveResourceSamples(samples); err != nil {
			log.Printf("⚠️ resource history: %v", err)
		}
	}
	// what has aged out goes every ten minutes (one write a minute otherwise)
	if now.Minute()%10 == 0 {
		if err := store.PruneResourceHistory(now.Add(-resourceHistoryWindow)); err != nil {
			log.Printf("⚠️ resource history prune: %v", err)
		}
	}
}

// flushResourceHistoryAtExit writes what the shutdown would lose: the
// finished minutes not written yet and the current minute's average so far
// (after a quick restart the minute's later reports replace it). Called
// once no request can add a report and before the database closes.
func flushResourceHistoryAtExit(store *Store, now time.Time) {
	samples := resourceRec.take(now.Unix()/60 + 1)
	if len(samples) == 0 {
		return
	}
	if err := store.SaveResourceSamples(samples); err != nil {
		log.Printf("⚠️ resource history at exit: %v", err)
	}
}

// startResourceHistory writes each finished minute shortly after it ends.
func startResourceHistory(ctx context.Context, store *Store) {
	for {
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute + 2*time.Second)
		select {
		case <-ctx.Done():
			return
		case <-time.After(next.Sub(now)):
		}
		flushResourceHistory(store, time.Now())
	}
}

// ---------- reading rights (as the TCPing history) ----------

// publicReadAllowed: with privacy mode on, a signed-in admin or a valid,
// unexpired share link; otherwise anyone.
func publicReadAllowed(store *Store, r *http.Request) bool {
	privacyConfig, err := store.GetPrivacyConfig()
	if err != nil || !privacyConfig.Enabled {
		return true
	}
	if isAuthenticated(r) {
		return true
	}
	shareToken := r.URL.Query().Get("token")
	return shareToken != "" && privacyConfig.ShareToken != "" && secretEqual(shareToken, privacyConfig.ShareToken) &&
		!privacyConfig.TokenExpires.IsZero() && time.Now().Before(privacyConfig.TokenExpires)
}

func navbarSwitch(store *Store, pick func(*NavbarConfig) bool) bool {
	cfg, err := store.GetNavbarConfig()
	return err == nil && cfg != nil && pick(cfg)
}

// ---------- GET /api/resource/history ----------

type resourceHistoryResponse struct {
	Interval int          `json:"interval"` // seconds per sample
	Points   [][6]float64 `json:"points"`   // [unix seconds, cpu %, memory %, disk %, in MB/s, out MB/s]
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func handleGetResourceHistory(store *Store, w http.ResponseWriter, r *http.Request) {
	if !navbarSwitch(store, func(c *NavbarConfig) bool { return c.ResourceHistory }) {
		http.Error(w, "resource history is off", http.StatusNotFound)
		return
	}
	if !publicReadAllowed(store, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	// what the homepage shows only: a server hidden from it has no history here
	if sys, err := store.Get(clientID); err != nil || sys == nil || sys.HideOnHome {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}
	samples, err := store.GetResourceHistory(clientID, time.Now().Add(-resourceHistoryWindow))
	if err != nil {
		http.Error(w, "failed to read history", http.StatusInternalServerError)
		return
	}
	resp := resourceHistoryResponse{Interval: 60, Points: make([][6]float64, 0, len(samples))}
	for _, s := range samples {
		resp.Points = append(resp.Points, [6]float64{float64(s.Minute * 60), round(s.CPU, 2), round(s.Mem, 2), round(s.Disk, 2), round(s.In, 6), round(s.Out, 6)})
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------- GET /api/tcping/summary ----------

type latencyStat struct {
	Avg  *float64 `json:"avg"`  // mean of the answered probes (ms), null when none answered
	Loss float64  `json:"loss"` // % of the probes lost
	N    int      `json:"n"`    // probes in the window
}

type latencySummaryResponse struct {
	Window  int                               `json:"window"` // seconds
	At      time.Time                         `json:"at"`
	Servers map[string]map[string]latencyStat `json:"servers"` // server id → target address → stat
}

var latencySummaryCache struct {
	sync.Mutex
	at   time.Time
	body []byte
}

// computeLatencySummary walks the last hour of probes once (keys start with
// the unix second, so the walk starts at the window's first second). Only
// what the homepage shows is answered: servers that exist and are not hidden
// from it (hide_on_home) or showing no TCPing there (hide_tcping), and the
// targets configured now (a removed target's address stays private).
func (s *Store) computeLatencySummary(now time.Time) (latencySummaryResponse, error) {
	type acc struct {
		sum      float64
		ok, lost int
	}
	shown := make(map[string]bool)
	systems, err := s.List()
	if err != nil {
		return latencySummaryResponse{}, err
	}
	for _, m := range systems {
		if !m.HideOnHome && !m.HideTCPing {
			shown[m.ID] = true
		}
	}
	targets := make(map[string]bool)
	if cfg, cfgErr := s.GetTCPingConfig(); cfgErr == nil && cfg != nil {
		for _, t := range cfg.Targets {
			targets[t.Address] = true
		}
	}
	accs := make(map[string]map[string]*acc)
	from := []byte(fmt.Sprintf("%d_", now.Add(-latencySummaryWindow).Unix()))
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tcpingBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(from); k != nil; k, v = c.Next() {
			var res TCPingResult
			if err := json.Unmarshal(v, &res); err != nil || !shown[res.ClientID] || !targets[res.Target] {
				continue
			}
			byTarget := accs[res.ClientID]
			if byTarget == nil {
				byTarget = make(map[string]*acc)
				accs[res.ClientID] = byTarget
			}
			a := byTarget[res.Target]
			if a == nil {
				a = &acc{}
				byTarget[res.Target] = a
			}
			if res.Latency == nil || *res.Latency > tcpingLossThresholdMs || math.IsNaN(*res.Latency) {
				a.lost++
			} else {
				a.ok++
				a.sum += *res.Latency
			}
		}
		return nil
	})
	resp := latencySummaryResponse{Window: int(latencySummaryWindow / time.Second), At: now.UTC(), Servers: make(map[string]map[string]latencyStat, len(accs))}
	for id, byTarget := range accs {
		m := make(map[string]latencyStat, len(byTarget))
		for target, a := range byTarget {
			n := a.ok + a.lost
			st := latencyStat{N: n}
			if a.ok > 0 {
				v := round(a.sum/float64(a.ok), 2)
				st.Avg = &v
			}
			if n > 0 {
				st.Loss = round(float64(a.lost)*100/float64(n), 2)
			}
			m[target] = st
		}
		resp.Servers[id] = m
	}
	return resp, err
}

func handleGetLatencySummary(store *Store, w http.ResponseWriter, r *http.Request) {
	if !navbarSwitch(store, func(c *NavbarConfig) bool { return c.LatencyView }) {
		http.Error(w, "latency view is off", http.StatusNotFound)
		return
	}
	if !publicReadAllowed(store, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	latencySummaryCache.Lock()
	defer latencySummaryCache.Unlock()
	now := time.Now()
	if latencySummaryCache.body == nil || now.Sub(latencySummaryCache.at) >= latencySummaryTTL {
		resp, err := store.computeLatencySummary(now)
		if err != nil {
			http.Error(w, "failed to read probes", http.StatusInternalServerError)
			return
		}
		body, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "failed to encode", http.StatusInternalServerError)
			return
		}
		latencySummaryCache.at, latencySummaryCache.body = now, body
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(latencySummaryCache.body)
}
