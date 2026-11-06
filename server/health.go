package main

import (
	"log"
	"net/http"
	"sync"
	"time"
)

// storeHealth says whether agent pushes are being stored. A full (or failing)
// disk used to leave every server "online" with frozen numbers: a push counted
// as received before it was saved, a failed save logged nothing, and /healthz
// kept answering ok. Now a push only counts once it is stored, a failure is
// logged (once a minute), and /healthz answers 503 while they fail.
type storeHealthState struct {
	mu       sync.Mutex
	failedAt time.Time
	okAt     time.Time
	loggedAt time.Time
	failures int
}

var storeHealth storeHealthState

func (h *storeHealthState) stored(now time.Time) {
	h.mu.Lock()
	recovered := !h.failedAt.IsZero() && h.failedAt.After(h.okAt)
	n := h.failures
	h.okAt, h.failures = now, 0
	h.mu.Unlock()
	if recovered {
		log.Printf("✅ Agent pushes are stored again (after %d failed)", n)
	}
}

func (h *storeHealthState) failed(now time.Time, err error) {
	h.mu.Lock()
	h.failedAt = now
	h.failures++
	n := h.failures
	say := now.Sub(h.loggedAt) >= time.Minute
	if say {
		h.loggedAt = now
	}
	h.mu.Unlock()
	if say {
		log.Printf("⚠️  Agent pushes are not being stored (%d failed so far): %v", n, err)
	}
}

// failing: a push failed to be stored in the last minute and none has been
// stored since.
func (h *storeHealthState) failing(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.failedAt.IsZero() && h.failedAt.After(h.okAt) && now.Sub(h.failedAt) < time.Minute
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if storeHealth.failing(time.Now()) {
		// (the reason stays in the server's log: this endpoint is public)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "reason": "storage"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
