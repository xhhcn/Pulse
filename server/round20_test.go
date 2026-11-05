package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clearLoginLimit forgets an address's attempts before and after a test.
func clearLoginLimit(t *testing.T, ip string) {
	t.Helper()
	clear := func() {
		loginAttemptsMu.Lock()
		delete(loginAttempts, rateLimitKey(ip))
		loginAttemptsMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

// countingLoginVerify replaces the password check with a slow, counted one.
func countingLoginVerify(t *testing.T, delay time.Duration, err error) *int32 {
	t.Helper()
	var calls int32
	old := loginVerify
	loginVerify = func(store *Store, password string) (bool, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(delay)
		if err != nil {
			return false, err
		}
		return password == "right-password", nil
	}
	t.Cleanup(func() { loginVerify = old })
	return &calls
}

func loginCode(store *Store, remote, password string) int {
	rr := httptest.NewRecorder()
	handleAuthLogin(store, rr, jsonRequest(http.MethodPost, "/api/auth/login", remote, map[string]string{"password": password}))
	return rr.Code
}

// Guesses sent at the same moment each take one of the address's five
// attempts: no more than five passwords are ever checked, and the address
// is then locked, even for the right password.
func TestLoginLimitHoldsForConcurrentGuesses(t *testing.T) {
	store := newTestStore(t)
	clearLoginLimit(t, "198.51.100.77")
	clearLoginLimit(t, "198.51.100.78")
	calls := countingLoginVerify(t, 40*time.Millisecond, nil)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var unauthorized int32
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if loginCode(store, "198.51.100.77:4000", fmt.Sprintf("guess-%02d", i)) == http.StatusUnauthorized {
				atomic.AddInt32(&unauthorized, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if n := atomic.LoadInt32(calls); n > loginMaxAttempts {
		t.Fatalf("%d passwords were checked in one burst; the limit is %d", n, loginMaxAttempts)
	}
	if unauthorized != 40 {
		t.Fatalf("%d of 40 wrong guesses were refused", unauthorized)
	}
	if code := loginCode(store, "198.51.100.77:4000", "right-password"); code != http.StatusUnauthorized {
		t.Fatalf("a locked address logged in: HTTP %d", code)
	}
	if code := loginCode(store, "198.51.100.78:4000", "right-password"); code != http.StatusOK {
		t.Fatalf("another address must not be locked: HTTP %d", code)
	}
}

// Sequential attempts behave as before: four wrong and the right one log
// in and clear the count; five wrong lock the address.
func TestLoginLimitSequentialAttempts(t *testing.T) {
	store := newTestStore(t)
	clearLoginLimit(t, "198.51.100.79")
	countingLoginVerify(t, 0, nil)
	for i := 0; i < 4; i++ {
		if code := loginCode(store, "198.51.100.79:4000", "wrong-password"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: HTTP %d", i, code)
		}
	}
	if code := loginCode(store, "198.51.100.79:4000", "right-password"); code != http.StatusOK {
		t.Fatalf("right password after four wrong: HTTP %d", code)
	}
	for i := 0; i < 5; i++ {
		if code := loginCode(store, "198.51.100.79:4000", "wrong-password"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: HTTP %d", i, code)
		}
	}
	if code := loginCode(store, "198.51.100.79:4000", "right-password"); code != http.StatusUnauthorized {
		t.Fatalf("five wrong passwords must lock the address: HTTP %d", code)
	}
	// A request the limiter refuses never reaches the password check.
	loginAttemptsMu.Lock()
	locked := time.Now().Before(loginAttempts[rateLimitKey("198.51.100.79")].lockedUntil)
	loginAttemptsMu.Unlock()
	if !locked {
		t.Fatal("the address is not marked locked")
	}
}

// A password that could not be checked (storage error) is not counted.
func TestLoginLimitStorageErrorIsNotAnAttempt(t *testing.T) {
	store := newTestStore(t)
	clearLoginLimit(t, "198.51.100.80")
	countingLoginVerify(t, 0, errors.New("disk on fire"))
	for i := 0; i < 8; i++ {
		if code := loginCode(store, "198.51.100.80:4000", "right-password"); code != http.StatusInternalServerError {
			t.Fatalf("attempt %d: HTTP %d", i, code)
		}
	}
	loginAttemptsMu.Lock()
	count := loginAttempts[rateLimitKey("198.51.100.80")].count
	loginAttemptsMu.Unlock()
	if count != 0 {
		t.Fatalf("storage errors counted as %d attempts", count)
	}
}

// Pushes arriving together share a commit (bbolt Batch) and every one of
// them is stored with its probes.
func TestPushBatchStoresConcurrentPushes(t *testing.T) {
	store := newTestStore(t)
	store.db.MaxBatchDelay = 30 * time.Millisecond
	const n = 60
	for i := 0; i < n; i++ {
		if err := store.Upsert(SystemMetric{ID: fmt.Sprintf("b%02d", i), Name: "B"}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().Add(-time.Second).UTC()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("b%02d", i)
			l := float64(i)
			results := []TCPingResult{
				{ClientID: id, Target: "1.1.1.1:443", Latency: &l, Timestamp: at, ExactTimestamp: true},
				{ClientID: id, Target: "8.8.8.8:53", Latency: nil, Timestamp: at, ExactTimestamp: true},
			}
			errs <- store.SaveClientPushBatch(SystemMetric{ID: id, CPU: float64(i), UpdatedAt: at}, results)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("push: %v", err)
		}
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("b%02d", i)
		m, err := store.Get(id)
		if err != nil || m == nil || m.CPU != float64(i) || m.Name != "B" {
			t.Fatalf("%s stored as %+v (%v)", id, m, err)
		}
		rows, err := store.GetTCPingResults(id)
		if err != nil || len(rows) != 2 {
			t.Fatalf("%s has %d probes (%v)", id, len(rows), err)
		}
	}
}

// A report stamped in a minute that was already written counts toward the
// first minute not written yet; it no longer replaces the written average.
func TestResourceRecorderLateReportKeepsWrittenMinute(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "late", Name: "Late"}); err != nil {
		t.Fatal(err)
	}
	resourceRec.reset()
	t.Cleanup(func() { resourceRec.reset() })
	m0 := time.Now().Truncate(time.Minute).Add(-3 * time.Minute)
	for i := 0; i < 19; i++ {
		resourceRec.add(SystemMetric{ID: "late", CPU: 10}, m0.Add(time.Duration(i)*3*time.Second))
	}
	if err := store.SaveResourceSamples(resourceRec.take(m0.Unix()/60 + 1)); err != nil {
		t.Fatal(err)
	}
	resourceRec.add(SystemMetric{ID: "late", CPU: 90}, m0.Add(59*time.Second)) // finished after the flush
	if err := store.SaveResourceSamples(resourceRec.take(m0.Unix()/60 + 2)); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetResourceHistory("late", m0.Add(-time.Minute))
	if err != nil || len(got) != 2 {
		t.Fatalf("history: %+v (%v)", got, err)
	}
	if got[0].Minute != m0.Unix()/60 || got[0].CPU != 10 {
		t.Fatalf("the written minute changed: %+v", got[0])
	}
	if got[1].Minute != m0.Unix()/60+1 || got[1].CPU != 90 {
		t.Fatalf("the late report should count toward the next minute: %+v", got[1])
	}
}

// At exit the unwritten minutes, the current one included, are written.
func TestResourceHistoryFlushAtExit(t *testing.T) {
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "exit", Name: "Exit"}); err != nil {
		t.Fatal(err)
	}
	resourceRec.reset()
	t.Cleanup(func() { resourceRec.reset() })
	now := time.Now()
	resourceRec.add(SystemMetric{ID: "exit", CPU: 30}, now.Add(-time.Minute))
	resourceRec.add(SystemMetric{ID: "exit", CPU: 50}, now)
	flushResourceHistoryAtExit(store, now)
	got, err := store.GetResourceHistory("exit", now.Add(-5*time.Minute))
	if err != nil || len(got) != 2 || got[0].CPU != 30 || got[1].CPU != 50 {
		t.Fatalf("history after exit: %+v (%v)", got, err)
	}
}

// since= answers only the client's probes after it, oldest first; an old,
// unreadable or missing since gets the whole day; privacy and unknown ids
// are answered as for the whole day.
func TestTCPingHistorySince(t *testing.T) {
	resetTCPingCacheForTest(t)
	store := newTestStore(t)
	for _, id := range []string{"s1", "s2"} {
		if err := store.Upsert(SystemMetric{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	for m := 30; m >= 1; m-- {
		for _, id := range []string{"s1", "s2"} {
			l := float64(m)
			if err := store.SaveTCPingResult(TCPingResult{ClientID: id, Target: "1.1.1.1:443", Latency: &l, Timestamp: now.Add(-time.Duration(m) * time.Minute)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	get := func(q string) (int, []TCPingResult) {
		rr := httptest.NewRecorder()
		handleGetTCPingHistory(store, rr, httptest.NewRequest(http.MethodGet, "/api/tcping/history?"+q, nil))
		var body TCPingHistoryResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return rr.Code, body.Results
	}
	since := now.Add(-5*time.Minute - 30*time.Second)
	code, rows := get(fmt.Sprintf("client_id=s1&since=%d", since.UnixMilli()))
	if code != http.StatusOK || len(rows) != 5 {
		t.Fatalf("since: HTTP %d, %d rows", code, len(rows))
	}
	for i, r := range rows {
		if r.ClientID != "s1" || !r.Timestamp.After(since) || (i > 0 && r.Timestamp.Before(rows[i-1].Timestamp)) {
			t.Fatalf("row %d: %+v", i, r)
		}
	}
	// exactly at a probe: that probe is not repeated
	if _, rows := get(fmt.Sprintf("client_id=s1&since=%d", now.Add(-2*time.Minute).UnixMilli())); len(rows) != 1 {
		t.Fatalf("since on a probe: %d rows", len(rows))
	}
	for _, q := range []string{
		fmt.Sprintf("client_id=s1&since=%d", now.Add(-20*time.Minute).UnixMilli()),
		"client_id=s1&since=yesterday",
		"client_id=s1",
	} {
		if code, rows := get(q); code != http.StatusOK || len(rows) != 30 {
			t.Fatalf("%s: HTTP %d, %d rows (want the whole day)", q, code, len(rows))
		}
	}
	if code, _ := get(fmt.Sprintf("client_id=nope&since=%d", since.UnixMilli())); code != http.StatusNotFound {
		t.Fatalf("unknown client with since: HTTP %d", code)
	}
	if code, _ := get(fmt.Sprintf("client_id=s1&target=evil.example%%3A1&since=%d", since.UnixMilli())); code != http.StatusBadRequest {
		t.Fatalf("unconfigured target with since: HTTP %d", code)
	}
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(fmt.Sprintf("client_id=s1&since=%d", since.UnixMilli())); code != http.StatusUnauthorized {
		t.Fatalf("privacy mode with since: HTTP %d", code)
	}
}

// Requests that miss the cache for one history at one stamp share a read;
// another stamp (a push landed meanwhile) reads again.
func TestTCPingHistoryMissesShareOneRead(t *testing.T) {
	var reads int32
	key := tcpingHistoryFlightKey{tcpingCacheKey{"c", ""}, tcpingCacheStamp{1, 7}}
	load := func() tcpingHistoryLoad {
		atomic.AddInt32(&reads, 1)
		time.Sleep(50 * time.Millisecond)
		return tcpingHistoryLoad{response: &TCPingHistoryResponse{}}
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := loadTCPingHistoryShared(key, load); got.response == nil || got.err != nil {
				t.Errorf("shared read: %+v", got)
			}
		}()
	}
	wg.Wait()
	if reads != 1 {
		t.Fatalf("20 concurrent misses made %d reads", reads)
	}
	other := key
	other.stamp.gen++
	loadTCPingHistoryShared(other, load)
	if reads != 2 {
		t.Fatalf("a newer stamp must read again (%d reads)", reads)
	}
	// a read that panics fails its waiters instead of leaving them blocked
	done := make(chan tcpingHistoryLoad, 1)
	go func() {
		defer func() { _ = recover() }()
		loadTCPingHistoryShared(key, func() tcpingHistoryLoad { time.Sleep(30 * time.Millisecond); panic("boom") })
	}()
	time.Sleep(5 * time.Millisecond)
	go func() { done <- loadTCPingHistoryShared(key, load) }()
	select {
	case got := <-done:
		if got.err == nil && got.response == nil {
			t.Fatalf("waiter of a failed read got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiter stayed blocked after the read panicked")
	}
}

// The stream's numbers are shortened; the stored ones are not.
func TestRoundForStream(t *testing.T) {
	m := []SystemMetric{{
		ID: "r", CPU: 0.33333333333333337, Memory: 38.21469221574475, Disk: 31.4,
		NetInMBps: 0.0004082120221976076, NetOutMBps: 1234.5678,
		TCPingData: map[string]TCPingTargetData{"t": {Latency: 140.457631}},
	}}
	roundForStream(m)
	got := m[0]
	if got.CPU != 0.33 || got.Memory != 38.21 || got.Disk != 31.4 || got.NetInMBps != 0.0004082 || got.NetOutMBps != 1235 || got.TCPingData["t"].Latency != 140.458 {
		t.Fatalf("rounded: %+v", got)
	}
	b, _ := json.Marshal(got)
	if len(b) == 0 || string(b) == "" {
		t.Fatal("marshal")
	}
	for _, c := range []struct{ in, want float64 }{{0, 0}, {1e-320, 1e-320}, {math.Inf(1), math.Inf(1)}, {0.012346, 0.01235}, {99999, 100000}} {
		if v := roundSignificant(c.in, 4); v != c.want && !(math.IsInf(v, 1) && math.IsInf(c.want, 1)) {
			t.Fatalf("roundSignificant(%v) = %v, want %v", c.in, v, c.want)
		}
	}

	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "keep", Name: "Keep", CPU: 0.33333333333333337}); err != nil {
		t.Fatal(err)
	}
	broadcastMetricsSnapshot(store, NewClientRegistry(), NewSSEBroker())
	if s, _ := store.Get("keep"); s == nil || s.CPU != 0.33333333333333337 {
		t.Fatalf("stored value changed: %+v", s)
	}
}
