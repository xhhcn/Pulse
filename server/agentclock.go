package main

import (
	"sync"
	"time"
)

// Agent clocks are not to be trusted. Many hosts run without NTP: on xhh.li
// (2026-11) a sixth of the agents were 6 s to 100 s off, both early and late.
// A TCPing sample carries the agent's own MeasuredAt, so the server estimates
// each agent's clock offset and puts its samples on the server clock.
//
// An observation is the server's receive time less the newest MeasuredAt of a
// batch: the agent's offset plus how long that sample waited (the probe, the
// next push, the network). It can never be less than the offset, so the
// estimate is the smallest recent observation. It is taken only from a batch
// that cannot be a re-send or a backlog: the client's previous push arrived
// at most agentClockFreshPush ago, and the batch holds a sample newer than any
// the server has seen from it. That sample was taken after the previous push
// left the agent (each push takes the whole queue), so it waited seconds.
//
// The correction is sticky, so an agent's samples never jump between two
// placements. The rule it replaces shifted one batch at a time, onto the
// receive time, once its newest sample looked over 2 min old or 30 s ahead:
// an agent near either line moved back and forth by that much (a point doubled
// in one minute, missing in the next), and anything inside the lines kept the
// agent's error. Now an agent within the synced band keeps its own stamps; one
// outside is corrected by the estimate, which is kept until the estimate moves
// by more than agentClockStep and dropped only once the estimate is well inside
// the band again. One correction for all of an agent's batches also maps a
// re-sent batch onto the records of the first delivery, so it is not stored
// twice.
//
// The state is in memory. After a short restart, the stored time of a
// client's last report lets its first push count as fresh. Until an agent has
// an estimate (a new agent, or one back after a long silence), its batches
// follow the old per-batch rule.
const (
	agentClockFreshPush = 10 * time.Second
	agentClockWindow    = 5
	agentClockMaxAge    = 30 * time.Minute // at least; 5 intervals when longer
	// The synced band: the estimate of an agent whose clock is right is the
	// sample's wait, a few seconds (measured on xhh.li: −1.2 s to +5.3 s).
	agentClockSyncedEarly = -2 * time.Second
	agentClockSyncedLate  = 6 * time.Second
	// A correction is dropped only inside this narrower band.
	agentClockBackEarly = -1 * time.Second
	agentClockBackLate  = 4 * time.Second
	agentClockStep      = 2 * time.Second
	// The agent's clock was set back (an NTP fix of a fast clock), so the
	// earlier observations no longer apply: one observation this far above
	// their minimum (more than a fresh sample can wait, 14 s at most), or
	// three in a row agentClockSetBack above it.
	agentClockJump    = 20 * time.Second
	agentClockSetBack = 8 * time.Second
)

type agentClockObs struct {
	at  time.Time     // server time of the observation
	off time.Duration // receive time − newest MeasuredAt
}

type agentClockState struct {
	lastPush   time.Time // server time of the client's latest push
	lastNewest time.Time // newest MeasuredAt seen from the client (agent clock)
	obs        []agentClockObs
	corr       time.Duration
	active     bool
}

type agentClockTracker struct {
	mu      sync.Mutex
	clients map[string]*agentClockState
}

func newAgentClockTracker() *agentClockTracker {
	return &agentClockTracker{clients: make(map[string]*agentClockState)}
}

// agentClocks is the tracker of the push handler.
var agentClocks = newAgentClockTracker()

// correction is told about every push of a client, with or without samples
// (the freshness of the next push depends on it): now is the server's receive
// time and newest the batch's newest MeasuredAt, zero when there is none. It
// returns the offset to add to the batch's stamps, and ok false when the
// client has no estimate yet.
func (t *agentClockTracker) correction(clientID string, now, newest time.Time, interval time.Duration) (corr time.Duration, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.clients[clientID]
	if s == nil {
		s = &agentClockState{}
		t.clients[clientID] = s
	}
	since := now.Sub(s.lastPush)
	fresh := !s.lastPush.IsZero() && since >= 0 && since <= agentClockFreshPush
	// A newest stamp far below the newest seen (two rounds) is not a re-send
	// or a late request (seconds at most): the agent's clock went back.
	stepBack := 2 * interval
	if stepBack < 2*time.Minute {
		stepBack = 2 * time.Minute
	}
	setBack := !s.lastNewest.IsZero() && newest.Before(s.lastNewest.Add(-stepBack))
	if !newest.IsZero() && (newest.After(s.lastNewest) || setBack) {
		if fresh {
			off := now.Sub(newest)
			if len(s.obs) > 0 && off > minClockObs(s.obs)+agentClockJump {
				s.obs = s.obs[:0]
			}
			s.obs = append(s.obs, agentClockObs{at: now, off: off})
			if len(s.obs) > agentClockWindow {
				s.obs = append(s.obs[:0], s.obs[len(s.obs)-agentClockWindow:]...)
			}
		}
		s.lastNewest = newest
	}
	if now.After(s.lastPush) {
		s.lastPush = now
	}

	maxAge := agentClockMaxAge
	if a := 5 * interval; a > maxAge {
		maxAge = a
	}
	kept := s.obs[:0]
	for _, o := range s.obs {
		if now.Sub(o.at) <= maxAge {
			kept = append(kept, o)
		}
	}
	s.obs = kept
	if n := len(s.obs); n > 3 {
		earlier := minClockObs(s.obs[:n-3])
		if s.obs[n-3].off > earlier+agentClockSetBack && s.obs[n-2].off > earlier+agentClockSetBack && s.obs[n-1].off > earlier+agentClockSetBack {
			s.obs = append(s.obs[:0], s.obs[n-3:]...)
		}
	}
	if len(s.obs) == 0 {
		s.active, s.corr = false, 0
		return 0, false
	}

	est := minClockObs(s.obs)
	switch {
	case !s.active:
		if est < agentClockSyncedEarly || est > agentClockSyncedLate {
			s.active, s.corr = true, est.Round(time.Millisecond)
		}
	case est >= agentClockBackEarly && est <= agentClockBackLate:
		s.active, s.corr = false, 0
	case est-s.corr > agentClockStep || s.corr-est > agentClockStep:
		s.corr = est.Round(time.Millisecond)
	}
	return s.corr, true
}

// shift is the offset to add to the stamps of a client's push (newest is
// the batch's newest MeasuredAt, zero without samples; prevReport is the
// stored time of the client's previous report) and whether stored stamps map
// one to one from the agent's, so that a re-sent sample may be skipped as one
// already stored.
func (t *agentClockTracker) shift(clientID string, now, newest, prevReport time.Time, intervalSecs int) (skew time.Duration, exact bool) {
	interval := time.Duration(intervalSecs) * time.Second
	t.seed(clientID, prevReport)
	if corr, ok := t.correction(clientID, now, newest, interval); ok {
		return corr, true
	}
	if newest.IsZero() {
		return 0, false
	}
	// No estimate yet (a server start, or the agent's first push after a long
	// silence): the batch alone decides. Its newest stamp is seconds old on a
	// healthy clock, so one far older (or ahead) is skew and the whole batch is
	// shifted onto now. The "too old" bound scales with the configured
	// interval: with a 5 min interval the newest queued sample of a post-outage
	// backlog is legitimately up to 5 min old, and treating that as skew
	// shifted the whole backlog onto "now" and disabled idempotent storage.
	skewPast := 2 * time.Minute
	if iv := 2 * interval; iv > skewPast {
		skewPast = iv
	}
	if d := now.Sub(newest); d > skewPast || d < -30*time.Second {
		return d, false
	}
	return 0, true
}

// seed starts a client the tracker has not seen since the server started from
// the stored time of its previous report, so that its first push after a short
// restart counts as fresh and is placed by an estimate, not the old rule.
func (t *agentClockTracker) seed(clientID string, prevReport time.Time) {
	if prevReport.IsZero() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.clients[clientID]; !ok {
		t.clients[clientID] = &agentClockState{lastPush: prevReport}
	}
}

// forget drops a deleted client's state.
func (t *agentClockTracker) forget(clientID string) {
	t.mu.Lock()
	delete(t.clients, clientID)
	t.mu.Unlock()
}

func minClockObs(obs []agentClockObs) time.Duration {
	m := obs[0].off
	for _, o := range obs[1:] {
		if o.off < m {
			m = o.off
		}
	}
	return m
}
