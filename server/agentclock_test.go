package main

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// ── a day of pushes from agents with wrong clocks ───────────────────────────
//
// simulateAgent plays one agent as it behaves (client/main.go): a push every 3 s that
// takes the whole queue, a TCPing round every interval (start to start) whose
// samples are stamped at dial start on the agent's clock (realTime + offset)
// and queued when the probe ends (3 % lost: the 3 s timeout), the network's
// transit, a push now and then whose reply is lost after the server stored it
// (the agent times out after 8 s and sends the same samples again with the
// next ones), and optionally the server down for a while (pushes fail, the
// agent keeps its queue) and restarted (the server forgets its estimates).
// The server side is the push handler's: one shift per push, then idempotent
// storage for exact stamps and the sequence path otherwise, with the raw-batch
// signature check in front.

type simSample struct {
	id     int       // one measurement
	target int       // 0..2
	real   time.Time // when the probe started, real time
	stamp  time.Time // MeasuredAt: dial start on the agent's clock
	done   time.Time // when it is queued, real time
}

type simStored struct {
	at   time.Time
	id   int
	real time.Time
}

type simResult struct {
	stored     [3][]simStored
	duplicates int           // a measurement stored twice
	dropped    int           // samples the push handler would refuse (beyond 2 min ahead or a day old)
	maxErr     time.Duration // stored stamp − real dial start, worst case (after the first minutes and outside the outage)
	changes    int           // how often the shift applied to the agent's batches changed by more than 1 s
	maxChange  time.Duration // the largest such change
}

type simOptions struct {
	offset       time.Duration // agent clock − real clock
	interval     time.Duration
	hours        float64
	seed         int64
	useOldRule   bool
	outageAt     time.Duration // the server is down from here (0: never) ...
	outageFor    time.Duration // ... for this long, and restarted (estimates forgotten)
	lostReplyPct float64       // pushes whose reply is lost after the server stored them
	strict       bool          // judge the samples around the outage too
	serverStepAt time.Duration // the server's own clock steps by serverStep here (0: never)
	serverStep   time.Duration
}

// oldShift is the rule before agentClocks: each batch on its own.
func oldShift(now, newest time.Time, interval time.Duration) (time.Duration, bool) {
	if newest.IsZero() {
		return 0, false
	}
	skewPast := 2 * time.Minute
	if iv := 2 * interval; iv > skewPast {
		skewPast = iv
	}
	if d := now.Sub(newest); d > skewPast || d < -30*time.Second {
		return d, false
	}
	return 0, true
}

func simulateAgent(t *testing.T, o simOptions) simResult {
	t.Helper()
	rng := rand.New(rand.NewSource(o.seed))
	tracker := newAgentClockTracker()
	start := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Duration(o.hours * float64(time.Hour)))
	pushPhase := time.Duration(rng.Int63n(int64(3 * time.Second)))
	roundPhase := 4*time.Second + time.Duration(rng.Int63n(int64(time.Second)))

	var res simResult
	var queue []simSample
	var pending []simSample // created, not yet done
	nextRound := start.Add(roundPhase)
	nextID := 0
	type key struct {
		at     time.Time
		target int
	}
	exactKeys := map[key]bool{}
	storedIDs := map[int]bool{}
	var lastSig string
	var lastSigAt time.Time
	var lastShift time.Duration
	haveShift := false
	inOutage := func(at time.Time) bool {
		return o.outageAt > 0 && !at.Before(start.Add(o.outageAt)) && at.Before(start.Add(o.outageAt+o.outageFor))
	}
	restarted := false
	var lastReport time.Time // the system's stored UpdatedAt: survives a restart
	warm := start.Add(5 * time.Minute)
	for push := start.Add(pushPhase); push.Before(end); push = push.Add(3 * time.Second) {
		for !nextRound.After(push) { // rounds started before this push
			for tg := 0; tg < 3; tg++ {
				lat := time.Duration(20+rng.Intn(280)) * time.Millisecond
				if rng.Float64() < 0.03 {
					lat = 3 * time.Second
				}
				pending = append(pending, simSample{id: nextID, target: tg, real: nextRound, stamp: nextRound.Add(o.offset), done: nextRound.Add(lat)})
				nextID++
			}
			nextRound = nextRound.Add(o.interval + time.Duration(rng.Intn(3))*time.Millisecond)
		}
		still := pending[:0]
		for _, s := range pending {
			if !s.done.After(push) {
				queue = append(queue, s)
			} else {
				still = append(still, s)
			}
		}
		pending = still
		batch := queue
		queue = nil
		recv := push.Add(time.Duration(50+rng.Intn(350)) * time.Millisecond)
		// the server's clock: wall (steps with serverStep) and monotonic (never)
		serverWall := func(t time.Time) time.Time {
			if o.serverStepAt > 0 && !t.Before(start.Add(o.serverStepAt)) {
				return t.Add(o.serverStep)
			}
			return t
		}
		wall, mono := serverWall(recv), recv.Sub(start)
		if inOutage(recv) {
			queue = append(batch, queue...) // connection refused: kept for the next push
			continue
		}
		if o.outageAt > 0 && !restarted && !recv.Before(start.Add(o.outageAt+o.outageFor)) {
			tracker = newAgentClockTracker() // the server was restarted
			restarted = true
		}
		// the server's side of the push
		var newest time.Time
		for _, s := range batch {
			if s.stamp.After(newest) {
				newest = s.stamp
			}
		}
		var skew time.Duration
		var exact bool
		if o.useOldRule {
			skew, exact = oldShift(wall, newest, o.interval)
		} else {
			skew, exact = tracker.shiftAt("sim", wall, mono, newest, lastReport, int(o.interval/time.Second))
		}
		if len(batch) > 0 {
			if d := (skew - lastShift).Abs(); haveShift && d > time.Second && recv.After(warm) && (o.outageAt == 0 || recv.Before(start.Add(o.outageAt)) || recv.After(start.Add(o.outageAt+o.outageFor+3*o.interval))) {
				res.changes++
				if d > res.maxChange {
					res.maxChange = d
				}
			}
			lastShift, haveShift = skew, true
			sig := fmt.Sprint(batch)
			if sig == lastSig && recv.Sub(lastSigAt) < 10*time.Minute {
				batch = nil // tcpingBatchSeen
			}
			lastSig, lastSigAt = sig, recv
		}
		for _, s := range batch {
			at := s.stamp.Add(skew)
			if wall.Sub(at) > 24*time.Hour || at.After(wall.Add(maxTCPingFuture)) {
				res.dropped++
				continue
			}
			if exact {
				k := key{at, s.target}
				if exactKeys[k] {
					continue
				}
				exactKeys[k] = true
			}
			if storedIDs[s.id] {
				res.duplicates++
			}
			storedIDs[s.id] = true
			res.stored[s.target] = append(res.stored[s.target], simStored{at: at, id: s.id, real: s.real})
			nearOutage := o.outageAt > 0 && !o.strict && s.real.After(start.Add(o.outageAt-o.interval)) && s.real.Before(start.Add(o.outageAt+o.outageFor+3*o.interval))
			nearStep := o.serverStepAt > 0 && s.real.After(start.Add(o.serverStepAt-3*time.Minute)) && s.real.Before(start.Add(o.serverStepAt+3*time.Minute))
			if s.real.After(warm) && !nearOutage && !nearStep {
				// placed on the server's clock as it reads at the probe
				if e := at.Sub(serverWall(s.real)); e > res.maxErr || -e > res.maxErr {
					res.maxErr = time.Duration(math.Abs(float64(e)))
				}
			}
		}
		lastReport = wall
		if len(batch) > 0 && rng.Float64()*100 < o.lostReplyPct {
			// stored, but the agent never saw the reply: after its 8 s
			// timeout it sends these again with the next push
			queue = append(append([]simSample{}, batch...), queue...)
			push = push.Add(6 * time.Second)
		}
	}
	return res
}

// pairsAndGaps counts, per target, consecutive stored samples closer than half
// an interval (a doubled point) or further apart than 1.5 intervals (a missing
// one), outside the outage.
func pairsAndGaps(r simResult, o simOptions) (pairs, gaps int) {
	start := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	for _, list := range r.stored {
		sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
		for i := 1; i < len(list); i++ {
			if o.outageAt > 0 && !o.strict && list[i].real.After(start.Add(o.outageAt-2*o.interval)) && list[i].real.Before(start.Add(o.outageAt+o.outageFor+3*o.interval)) {
				continue
			}
			d := list[i].at.Sub(list[i-1].at)
			if d < o.interval/2 {
				pairs++
			} else if d > o.interval*3/2 {
				gaps++
			}
		}
	}
	return pairs, gaps
}

// The offsets measured on xhh.li on 2026-11-06 (agents 6 s to 100 s off, both
// ways), the ones that sat on the old rule's lines, and a few extremes.
var simOffsets = []time.Duration{
	-6 * time.Hour, -300 * time.Second, -121 * time.Second, -119 * time.Second, -101900 * time.Millisecond,
	-57500 * time.Millisecond, -46 * time.Second, -31 * time.Second, -25300 * time.Millisecond, -14100 * time.Millisecond,
	-9800 * time.Millisecond, -6100 * time.Millisecond, -5 * time.Second, -2500 * time.Millisecond, -1500 * time.Millisecond,
	0, 1200 * time.Millisecond, 2300 * time.Millisecond, 2600 * time.Millisecond, 5 * time.Second,
	14200 * time.Millisecond, 17500 * time.Millisecond, 23600 * time.Millisecond, 29 * time.Second, 31 * time.Second,
	34 * time.Second, 50 * time.Second, 78 * time.Second, 3 * time.Hour,
}

func TestAgentClockDayOfPushesKeepsEveryAgentsSamplesInPlace(t *testing.T) {
	for i, off := range simOffsets {
		o := simOptions{offset: off, interval: time.Minute, hours: 24, seed: int64(100 + i), lostReplyPct: 1}
		r := simulateAgent(t, o)
		pairs, gaps := pairsAndGaps(r, o)
		n := len(r.stored[0]) + len(r.stored[1]) + len(r.stored[2])
		// Kept stamps are off by the agent's own error, at most the synced
		// band; corrected ones by the wait of the sample the estimate came
		// from, a few seconds.
		// Corrections are adjusted now and then by the seconds a sample's
		// wait varies (the probe against the push every 3 s), never by more.
		limit := 6500 * time.Millisecond
		if pairs != 0 || gaps != 0 || r.duplicates != 0 || r.maxErr > limit || r.maxChange > 4*time.Second || r.changes > 30 || n < 3*1430 {
			t.Errorf("agent clock %v: pairs %d gaps %d duplicates %d worst placement %v changes %d (largest %v) samples %d", off, pairs, gaps, r.duplicates, r.maxErr, r.changes, r.maxChange, n)
		} else {
			t.Logf("agent clock %-9v worst placement %-7v corrections adjusted %2d times (largest %v)", off, r.maxErr.Round(10*time.Millisecond), r.changes, r.maxChange.Round(10*time.Millisecond))
		}
	}
}

func TestAgentClockOldRuleFailuresAreReproduced(t *testing.T) {
	// The simulation shows what was seen on xhh.li with the old rule: agents on
	// its lines flip (doubled and missing points), agents inside keep their error.
	flips := 0
	for i, off := range []time.Duration{-119 * time.Second, -121 * time.Second, 29 * time.Second, 31 * time.Second} {
		o := simOptions{offset: off, interval: time.Minute, hours: 24, seed: int64(200 + i), useOldRule: true, lostReplyPct: 1}
		r := simulateAgent(t, o)
		pairs, gaps := pairsAndGaps(r, o)
		if pairs+gaps > 0 {
			flips++
		}
	}
	if flips < 2 {
		t.Fatalf("the old rule should flip for agents on its lines, %d of 4 did", flips)
	}
	o := simOptions{offset: -101900 * time.Millisecond, interval: time.Minute, hours: 6, seed: 300, useOldRule: true}
	if r := simulateAgent(t, o); r.maxErr < 100*time.Second {
		t.Fatalf("the old rule kept an agent 102 s slow at its own time; worst placement %v", r.maxErr)
	}
}

func TestAgentClockServerRestartAndOutage(t *testing.T) {
	// The server is down 10 minutes and restarted: the agents' queued samples
	// arrive in one batch, the estimates are gone. Samples stay single and,
	// once the estimate is back (the next round), in place.
	for i, off := range []time.Duration{-101900 * time.Millisecond, -46 * time.Second, -1500 * time.Millisecond, 0, 2300 * time.Millisecond, 23600 * time.Millisecond, 78 * time.Second} {
		o := simOptions{offset: off, interval: time.Minute, hours: 6, seed: int64(400 + i), outageAt: 2 * time.Hour, outageFor: 10 * time.Minute, lostReplyPct: 1}
		r := simulateAgent(t, o)
		pairs, gaps := pairsAndGaps(r, o)
		if r.duplicates != 0 || pairs != 0 || gaps != 0 || r.maxErr > 6500*time.Millisecond {
			t.Errorf("agent clock %v: duplicates %d pairs %d gaps %d worst placement %v", off, r.duplicates, pairs, gaps, r.maxErr)
		}
	}
}

func TestAgentClockShortServerRestartLeavesNoTrace(t *testing.T) {
	// A deploy: the server is gone for 2 s and comes back without its
	// estimates. The stored time of each client's last report says its first
	// push is fresh, so even that push is placed by an estimate.
	for i, off := range simOffsets {
		o := simOptions{offset: off, interval: time.Minute, hours: 3, seed: int64(600 + i), outageAt: 90 * time.Minute, outageFor: 2 * time.Second, lostReplyPct: 1, strict: true}
		r := simulateAgent(t, o)
		pairs, gaps := pairsAndGaps(r, o)
		if r.duplicates != 0 || pairs != 0 || gaps != 0 || r.maxErr > 6500*time.Millisecond {
			t.Errorf("agent clock %v: duplicates %d pairs %d gaps %d worst placement %v", off, r.duplicates, pairs, gaps, r.maxErr)
		}
	}
}

func TestAgentClockServerClockStep(t *testing.T) {
	// The server's own clock steps (NTP fixing it): no sample may be dropped,
	// and after the step the samples sit on the new clock. On wall-clock ages
	// a step back of 135 s (xhh.li, 2026-11-06) made every push look older
	// than the last one for 135 s: no observation, the old correction kept,
	// and every sample landed past the 2 min bound and was dropped.
	for _, step := range []time.Duration{-135 * time.Second, 135 * time.Second, -30 * time.Second, -10 * time.Minute, time.Hour} {
		for i, off := range []time.Duration{0, -101900 * time.Millisecond, 23600 * time.Millisecond} {
			o := simOptions{offset: off, interval: time.Minute, hours: 2, seed: int64(700 + i), serverStepAt: time.Hour, serverStep: step, lostReplyPct: 1}
			r := simulateAgent(t, o)
			n := len(r.stored[0]) + len(r.stored[1]) + len(r.stored[2])
			if r.dropped != 0 || r.duplicates != 0 || r.maxErr > 6500*time.Millisecond || n < 3*118 {
				t.Errorf("server step %v, agent clock %v: dropped %d duplicates %d worst placement %v samples %d", step, off, r.dropped, r.duplicates, r.maxErr, n)
			}
		}
	}
	// the old wall-clock ages, for the record: the step back drops samples
	tr := newAgentClockTracker()
	at, newest := time.Date(2026, 11, 6, 1, 0, 0, 0, time.UTC), time.Time{}
	for i := 0; i < 40; i++ {
		at = at.Add(3 * time.Second)
		if i%20 == 19 {
			newest = at.Add(-time.Second)
		}
		tr.shiftAt("old", at, at.Sub(tr.epoch), newest, time.Time{}, 60)
	}
	// stepping the wall clock back while the monotonic one goes on: still fresh
	stepped := at.Add(3*time.Second - 135*time.Second)
	if _, ok := tr.correctionAt("old", stepped, at.Add(3*time.Second).Sub(tr.epoch), stepped.Add(-time.Second), time.Minute); !ok {
		t.Fatal("a stepped server clock lost the estimate")
	}
	if s := tr.clients["old"]; s.obs[len(s.obs)-1].off != time.Second {
		t.Fatalf("the push after the step must be an observation of 1 s, got %+v", s.obs)
	}
}

func TestAgentClockLongAndShortIntervals(t *testing.T) {
	for _, iv := range []time.Duration{5 * time.Second, 10 * time.Minute} {
		for i, off := range []time.Duration{-46 * time.Second, 0, 23600 * time.Millisecond} {
			o := simOptions{offset: off, interval: iv, hours: 12, seed: int64(500 + i), lostReplyPct: 1}
			if iv == 5*time.Second {
				o.hours = 2
			}
			r := simulateAgent(t, o)
			pairs, gaps := pairsAndGaps(r, o)
			if r.duplicates != 0 || pairs != 0 || gaps != 0 || r.maxErr > 6500*time.Millisecond {
				t.Errorf("interval %v, agent clock %v: duplicates %d pairs %d gaps %d worst placement %v", iv, off, r.duplicates, pairs, gaps, r.maxErr)
			}
		}
	}
}

// ── the tracker's rules one by one ──────────────────────────────────────────

func TestAgentClockFirstPushHasNoEstimate(t *testing.T) {
	tr := newAgentClockTracker()
	now := time.Now().UTC()
	if _, ok := tr.correction("a", now, now.Add(-time.Second), time.Minute); ok {
		t.Fatal("a first push cannot be judged: nothing says its samples are fresh")
	}
	// the next push, 3 s later, with a newer sample: an estimate
	if corr, ok := tr.correction("a", now.Add(3*time.Second), now.Add(2*time.Second), time.Minute); !ok || corr != 0 {
		t.Fatalf("a synced agent keeps its stamps: corr %v ok %v", corr, ok)
	}
}

func TestAgentClockResentSamplesAreNotObservations(t *testing.T) {
	tr := newAgentClockTracker()
	now := time.Now().UTC()
	tr.correction("a", now, time.Time{}, time.Minute)
	tr.correction("a", now.Add(3*time.Second), now.Add(2500*time.Millisecond), time.Minute) // fresh: 0.5 s
	// the same samples again 12 s later (a lost reply), nothing newer: no
	// observation, or the 9.5 s wait would look like a slow clock
	for i := 0; i < 5; i++ {
		tr.correction("a", now.Add(time.Duration(6+3*i)*time.Second), now.Add(2500*time.Millisecond), time.Minute)
	}
	if s := tr.clients["a"]; len(s.obs) != 1 || s.active {
		t.Fatalf("re-sent samples were taken as observations: %+v", s)
	}
}

func TestAgentClockBacklogAfterSilenceUsesTheEstimate(t *testing.T) {
	tr := newAgentClockTracker()
	now := time.Now().UTC()
	ahead := 40 * time.Second // the agent's clock
	tr.correction("a", now, time.Time{}, time.Minute)
	corr, ok := tr.correction("a", now.Add(3*time.Second), now.Add(3*time.Second+ahead-500*time.Millisecond), time.Minute)
	if !ok || corr > -39*time.Second || corr < -40*time.Second {
		t.Fatalf("40 s ahead: corr %v ok %v", corr, ok)
	}
	// 4 minutes without a push, then the backlog: not an observation (its
	// newest sample may have waited minutes), but the estimate still applies
	later := now.Add(4 * time.Minute)
	c2, ok := tr.correction("a", later, later.Add(ahead-50*time.Second), time.Minute)
	if !ok || c2 != corr {
		t.Fatalf("backlog after a silence: corr %v ok %v, want %v", c2, ok, corr)
	}
	if n := len(tr.clients["a"].obs); n != 1 {
		t.Fatalf("a backlog is no observation: %d", n)
	}
	// An hour later the estimate has expired: the per-batch rule decides.
	if _, ok := tr.correction("a", now.Add(time.Hour), now.Add(time.Hour+ahead), time.Minute); ok {
		t.Fatal("a stale estimate must not be used")
	}
}

func TestAgentClockFollowsAClockThatIsSet(t *testing.T) {
	tr := newAgentClockTracker()
	at := time.Now().UTC()
	// one TCPing round a minute, pushes every 3 s in between; off is the
	// agent's clock against the server's
	round := func(off time.Duration) time.Duration {
		for i := 0; i < 19; i++ {
			at = at.Add(3 * time.Second)
			tr.correction("a", at, time.Time{}, time.Minute)
		}
		at = at.Add(3 * time.Second)
		c, ok := tr.correction("a", at, at.Add(off-800*time.Millisecond), time.Minute)
		if !ok {
			t.Fatalf("no estimate at %v", off)
		}
		return c
	}
	for i := 0; i < 6; i++ {
		round(24 * time.Second) // 24 s fast
	}
	if c := round(24 * time.Second); c > -23*time.Second || c < -24*time.Second {
		t.Fatalf("24 s fast: corr %v", c)
	}
	// NTP sets it right: its samples now wait 24 s longer than the minimum
	// says, which a sample cannot: the old observations are dropped at once.
	if c := round(0); c != 0 {
		t.Fatalf("set right: corr %v, want 0", c)
	}
	// 30 s ahead: an observation below all others, followed at once
	if c := round(30 * time.Second); c > -29*time.Second || c < -30*time.Second {
		t.Fatalf("30 s fast: corr %v", c)
	}
	// set back by 10 minutes: its stamps are older than the newest seen, not
	// a re-send (a re-send is never older), followed at once
	if c := round(-570 * time.Second); c < 570*time.Second || c > 571*time.Second {
		t.Fatalf("set back 10 min: corr %v", c)
	}
	// a small step back (10 s): three rounds
	var c time.Duration
	for i := 0; i < 2; i++ {
		round(-570 * time.Second)
	}
	for i := 0; i < 3; i++ {
		c = round(-580 * time.Second)
	}
	if c < 580*time.Second || c > 581*time.Second {
		t.Fatalf("10 s further back: corr %v", c)
	}
}

func TestAgentClockBandEdgesDoNotFlip(t *testing.T) {
	// An estimate wandering across the band's edge changes the correction at
	// most once, by the edge (seconds), never back and forth.
	for _, base := range []time.Duration{-2 * time.Second, 6 * time.Second} {
		tr := newAgentClockTracker()
		rng := rand.New(rand.NewSource(7))
		at := time.Now().UTC()
		var last time.Duration
		changes := 0
		for i := 0; i < 500; i++ {
			at = at.Add(3 * time.Second)
			tr.correction("a", at, time.Time{}, time.Minute)
			at = at.Add(3 * time.Second)
			wait := base + time.Duration(rng.Intn(1200)-600)*time.Millisecond
			c, _ := tr.correction("a", at, at.Add(-wait), time.Minute)
			if i > 0 && c != last {
				changes++
			}
			last = c
		}
		if changes > 1 {
			t.Errorf("estimate around %v: the correction changed %d times", base, changes)
		}
	}
}

func TestAgentClockPushesOutOfOrder(t *testing.T) {
	tr := newAgentClockTracker()
	now := time.Now().UTC()
	tr.correction("a", now.Add(6*time.Second), time.Time{}, time.Minute)
	tr.correction("a", now.Add(3*time.Second), time.Time{}, time.Minute) // a slow request finishing late
	if got, want := tr.clients["a"].lastPush, now.Add(6*time.Second).Sub(tr.epoch); got != want {
		t.Fatalf("lastPush went back to %v (want %v)", got, want)
	}
	tr.forget("a")
	if _, ok := tr.clients["a"]; ok {
		t.Fatal("forget kept the client")
	}
}
