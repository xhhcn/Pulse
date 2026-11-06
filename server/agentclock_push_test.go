package main

import (
	"testing"
	"time"
)

// Through the push handler: agents whose clocks are off by seconds to minutes
// get their samples placed on the server clock, always by the same amount, so
// a re-sent sample is not stored twice; an agent in sync keeps its stamps.

func setupClockTest(t *testing.T, id string) (*Store, *ClientRegistry, *IPCountryCache) {
	t.Helper()
	store := newTestStore(t)
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "cf", Address: "1.1.1.1:443"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: id, Name: id}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	return store, NewClientRegistry(), NewIPCountryCache()
}

func clockSample(at time.Time, latency float64) map[string]interface{} {
	return map[string]interface{}{"target": "1.1.1.1:443", "latency": latency, "success": true, "measured_at": at.Format(time.RFC3339Nano)}
}

func TestClientPushPlacesSkewedAgentsOnTheServerClock(t *testing.T) {
	for _, tc := range []struct {
		name string
		off  time.Duration // agent clock − server clock
	}{
		{"fast-24s", 24 * time.Second},
		{"fast-3s", 3 * time.Second},
		{"slow-100s", -100 * time.Second}, // kept at its own time before (inside the old 2 min line)
		{"slow-125s", -125 * time.Second},
		{"slow-6h", -6 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, registry, ipCache := setupClockTest(t, tc.name)
			pushTCPingBatch(t, store, registry, ipCache, tc.name, nil) // a push without samples
			first := time.Now().UTC().Add(tc.off - 800*time.Millisecond)
			pushTCPingBatch(t, store, registry, ipCache, tc.name, []map[string]interface{}{clockSample(first, 10)})
			pushed := time.Now().UTC()
			results, _ := store.GetTCPingResults(tc.name, "1.1.1.1:443")
			if len(results) != 1 {
				t.Fatalf("rows %d, want 1", len(results))
			}
			if d := pushed.Sub(results[0].Timestamp); d < -time.Second || d > 2*time.Second {
				t.Fatalf("stored at %v, %v before the push; want the server clock", results[0].Timestamp, d)
			}
			// The reply was lost: the agent sends the sample again with the
			// next one. The first is not stored twice; the second lands one
			// second after it, as on the agent.
			pushTCPingBatch(t, store, registry, ipCache, tc.name, []map[string]interface{}{clockSample(first, 10), clockSample(first.Add(time.Second), 11)})
			results, _ = store.GetTCPingResults(tc.name, "1.1.1.1:443")
			if len(results) != 2 {
				t.Fatalf("after the re-send: rows %d, want 2", len(results))
			}
			if d := results[1].Timestamp.Sub(results[0].Timestamp); d != time.Second {
				t.Fatalf("the two samples are %v apart, want 1 s", d)
			}
			m, _ := store.Get(tc.name)
			if got := m.TCPingData["1.1.1.1:443"]; got.Latency != 11 || !got.Timestamp.Equal(results[1].Timestamp) {
				t.Fatalf("latest = %+v, want the newer sample at its stored time", got)
			}
		})
	}
}

func TestClientPushInSyncAgentKeepsItsOwnStamps(t *testing.T) {
	store, registry, ipCache := setupClockTest(t, "synced")
	pushTCPingBatch(t, store, registry, ipCache, "synced", nil)
	at := time.Now().UTC().Add(-1500 * time.Millisecond)
	pushTCPingBatch(t, store, registry, ipCache, "synced", []map[string]interface{}{clockSample(at, 10)})
	pushTCPingBatch(t, store, registry, ipCache, "synced", []map[string]interface{}{clockSample(at, 10), clockSample(at.Add(time.Second), 11)})
	results, _ := store.GetTCPingResults("synced", "1.1.1.1:443")
	if len(results) != 2 || !results[0].Timestamp.Equal(at) || !results[1].Timestamp.Equal(at.Add(time.Second)) {
		t.Fatalf("an agent in sync keeps its exact stamps: %+v", results)
	}
}

func TestClientPushAgentOnTheOldLineDoesNotFlip(t *testing.T) {
	// 119 s slow with a wait of 0.2 s or 1.8 s: the old rule kept one sample
	// and moved the next by two minutes, back and forth. Now every sample is
	// moved by the same amount.
	store, registry, ipCache := setupClockTest(t, "edge")
	var measured []time.Time
	for i := 0; i < 8; i++ {
		pushTCPingBatch(t, store, registry, ipCache, "edge", nil)
		wait := 200 * time.Millisecond
		if i%2 == 1 {
			wait = 1800 * time.Millisecond
		}
		at := time.Now().UTC().Add(-119*time.Second - wait)
		measured = append(measured, at)
		pushTCPingBatch(t, store, registry, ipCache, "edge", []map[string]interface{}{clockSample(at, float64(10+i))})
	}
	results, _ := store.GetTCPingResults("edge", "1.1.1.1:443")
	if len(results) != len(measured) {
		t.Fatalf("rows %d, want %d", len(results), len(measured))
	}
	// the rounds here are milliseconds apart, so the stored order is not the
	// sent one: each sample is found by its latency (10 + its index)
	var shift time.Duration
	for _, r := range results {
		i := int(*r.Latency) - 10
		got := r.Timestamp.Sub(measured[i])
		if shift == 0 {
			shift = got
		}
		if got != shift {
			t.Fatalf("sample %d moved by %v, another by %v: one agent, one correction", i, got, shift)
		}
	}
	if shift < 118*time.Second || shift > 120*time.Second {
		t.Fatalf("correction %v, want about 119 s", shift)
	}
}
