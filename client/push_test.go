package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNextPushWait(t *testing.T) {
	steps := []struct {
		outcome pushOutcome
		want    time.Duration
	}{
		{pushDelivered, 3 * time.Second},
		{pushFailed, 6 * time.Second},
		{pushFailed, 12 * time.Second},
		{pushFailed, 24 * time.Second},
		{pushFailed, 24 * time.Second}, // capped under the server's 30 s offline limit
		{pushDelivered, 3 * time.Second},
		{pushRejected, time.Minute},
		{pushFailed, 24 * time.Second}, // a failure after a rejection: not 2 min
		{pushRejected, time.Minute},
		{pushDelivered, 3 * time.Second},
	}
	wait := pushInterval
	for i, s := range steps {
		wait = nextPushWait(s.outcome, wait)
		if wait != s.want {
			t.Fatalf("step %d (%v): wait %v, want %v", i, s.outcome, wait, s.want)
		}
	}
}

func TestRefuseRedirectAway(t *testing.T) {
	mk := func(raw string) *http.Request { u, _ := url.Parse(raw); return &http.Request{URL: u} }
	via := []*http.Request{mk("https://xhh.li/api/clients/push")}
	if err := refuseRedirectAway(mk("https://xhh.li/api/v2/clients/push"), via); err != nil {
		t.Fatalf("same host must be followed: %v", err)
	}
	if err := refuseRedirectAway(mk("https://evil.example/collect"), via); err == nil {
		t.Fatal("a redirect to another host would re-send the body, and the body carries SECRET")
	}
	if err := refuseRedirectAway(mk("http://xhh.li/api/clients/push"), via); err == nil {
		t.Fatal("https → http must still be refused")
	}
	plain := []*http.Request{mk("http://10.0.0.5:8008/api/clients/push")}
	if err := refuseRedirectAway(mk("https://10.0.0.5:8008/api/clients/push"), plain); err != nil {
		t.Fatalf("http → https on the same host is an upgrade: %v", err)
	}
	for _, c := range []*http.Client{getPushHTTPClient(), getSharedHTTPClient()} {
		tr := c.Transport.(*http.Transport)
		if !tr.ForceAttemptHTTP2 {
			t.Fatal("the clients that talk to the server must attempt HTTP/2 (a custom DialContext turns it off)")
		}
		if c.CheckRedirect == nil {
			t.Fatal("no redirect policy")
		}
	}
}

// pushTestServer answers pushes with the status set last (0: never answers).
type pushTestServer struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	bodies []map[string]any
	hang   chan struct{}
}

func newPushTestServer(t *testing.T) *pushTestServer {
	t.Helper()
	p := &pushTestServer{status: http.StatusOK, hang: make(chan struct{})}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		p.mu.Lock()
		p.bodies = append(p.bodies, m)
		st := p.status
		p.mu.Unlock()
		if st == 0 {
			select {
			case <-p.hang:
			case <-r.Context().Done():
			}
			return
		}
		w.WriteHeader(st)
		if st == http.StatusOK {
			w.Write([]byte(`{"tcping_targets":[],"tcping_interval_secs":60}`))
		} else {
			w.Write([]byte("invalid secret"))
		}
	}))
	t.Cleanup(func() { close(p.hang); p.Server.Close() })
	return p
}

func (p *pushTestServer) set(status int) { p.mu.Lock(); p.status = status; p.mu.Unlock() }

// lastResults is how many TCPing results the last push carried.
func (p *pushTestServer) lastResults() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, _ := p.bodies[len(p.bodies)-1]["tcping_results"].([]any)
	return len(r)
}

func TestPushOnceOutcomesAndTheQueue(t *testing.T) {
	srv := newPushTestServer(t)
	oldBase, oldSecret := serverBase, secret
	serverBase, secret = srv.URL, "s3cret"
	defer func() { serverBase, secret = oldBase, oldSecret }()
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: refuseRedirectAway}
	queue := func(n int) {
		pendingTCPingResultsMu.Lock()
		pendingTCPingResults = nil
		for i := 0; i < n; i++ {
			pendingTCPingResults = append(pendingTCPingResults, ClientTCPingResult{Target: "1.1.1.1:443", Latency: float64(i), Success: true, MeasuredAt: time.Now()})
		}
		pendingTCPingResultsMu.Unlock()
	}
	queued := func() int {
		pendingTCPingResultsMu.Lock()
		defer pendingTCPingResultsMu.Unlock()
		return len(pendingTCPingResults)
	}

	queue(3)
	if o, d := pushOnce(client); o != pushDelivered || d != "" || queued() != 0 || srv.lastResults() != 3 {
		t.Fatalf("200: outcome %v %q, queue %d, carried %d", o, d, queued(), srv.lastResults())
	}
	srv.set(http.StatusServiceUnavailable)
	queue(3)
	if o, _ := pushOnce(client); o != pushFailed || queued() != 3 {
		t.Fatalf("503: outcome %v, queue %d (results must stay queued)", o, queued())
	}
	for _, st := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		srv.set(st)
		queue(3)
		o, d := pushOnce(client)
		if o != pushRejected || queued() != 0 || !strings.Contains(d, "invalid secret") || !strings.Contains(d, "HTTP ") {
			t.Fatalf("%d: outcome %v %q, queue %d (dropped on purpose, the reason kept for the log)", st, o, d, queued())
		}
	}
	srv.set(0) // hang: the client's timeout ends it
	queue(2)
	if o, d := pushOnce(client); o != pushFailed || queued() != 2 || d == "" {
		t.Fatalf("hang: outcome %v %q, queue %d", o, d, queued())
	}
	srv.set(http.StatusOK)
	if o, _ := pushOnce(client); o != pushDelivered || queued() != 0 || srv.lastResults() != 2 {
		t.Fatalf("after the hang: outcome %v, queue %d, carried %d (the backlog)", o, queued(), srv.lastResults())
	}
}

func TestPushLogSaysWhenPushesStopAndStart(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	t0 := time.Now()
	l := &pushLog{state: pushDelivered, since: t0}
	step := func(o pushOutcome, d string, at time.Duration) {
		l.note(o, d, nextPushWait(o, pushInterval), t0.Add(at))
	}
	step(pushDelivered, "", 0)
	if buf.Len() != 0 {
		t.Fatalf("delivered pushes are not logged: %q", buf.String())
	}
	step(pushFailed, "HTTP 503", 3*time.Second)
	step(pushFailed, "HTTP 503", 9*time.Second)
	step(pushFailed, "HTTP 503", 21*time.Second)
	if n := strings.Count(buf.String(), "Push failed"); n != 1 {
		t.Fatalf("a run of failures is logged once, got %d: %q", n, buf.String())
	}
	step(pushDelivered, "", 45*time.Second)
	if !strings.Contains(buf.String(), "reach the server again (after 3 failed") {
		t.Fatalf("recovery not logged: %q", buf.String())
	}
	buf.Reset()
	step(pushRejected, "HTTP 401: invalid secret", 50*time.Second)
	step(pushRejected, "HTTP 401: invalid secret", 110*time.Second)
	if n := strings.Count(buf.String(), "rejected the push"); n != 1 || !strings.Contains(buf.String(), "invalid secret") {
		t.Fatalf("a rejection is logged once with its reason: %q", buf.String())
	}
	step(pushRejected, "HTTP 401: invalid secret", 50*time.Second+time.Hour)
	if n := strings.Count(buf.String(), "rejected the push"); n != 2 {
		t.Fatalf("a lasting rejection is repeated hourly, got %d", n)
	}
}
