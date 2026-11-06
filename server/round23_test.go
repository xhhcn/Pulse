package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Every agent endpoint answers an unknown server ID as it answers a known one
// with a wrong (or missing) secret, so the IDs that exist cannot be listed.
func TestAgentEndpointsAnswerUnknownIDsLikeWrongSecrets(t *testing.T) {
	store := newTestStore(t)
	registry := NewClientRegistry()
	broker := NewSSEBroker()
	if err := store.Upsert(SystemMetric{ID: "7", Name: "seven", Secret: "right"}); err != nil {
		t.Fatal(err)
	}
	send := func(path, id, secret string) (int, string) {
		var body []byte
		switch path {
		case "/api/clients/register":
			body, _ = json.Marshal(map[string]interface{}{"id": id, "name": "x", "port": "9090", "secret": secret})
		case "/api/tcping":
			body, _ = json.Marshal(map[string]interface{}{"client_id": id, "target": "1.1.1.1:443", "latency": 12.5, "success": true})
		case "/api/metrics":
			// the legacy ingest of old agents: uptime and OS make it an agent's report
			body, _ = json.Marshal(map[string]interface{}{"id": id, "name": "x", "uptime": 3600, "os": "Debian"})
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		rr := httptest.NewRecorder()
		switch path {
		case "/api/clients/register":
			handleClientRegister(store, registry, rr, req)
		case "/api/tcping":
			handleTCPingResult(store, rr, req)
		case "/api/metrics":
			handleIngestMetric(store, broker, rr, req)
		}
		return rr.Code, rr.Body.String()
	}
	for _, path := range []string{"/api/clients/register", "/api/tcping", "/api/metrics"} {
		for _, secret := range []string{"wrong", ""} {
			c1, b1 := send(path, "7", secret)
			c2, b2 := send(path, "8", secret)
			if c1 != http.StatusUnauthorized || c1 != c2 || b1 != b2 {
				t.Fatalf("%s (secret %q): known id %d %q, unknown id %d %q", path, secret, c1, b1, c2, b2)
			}
		}
	}
	// the right secret still works on the legacy ingest
	body, _ := json.Marshal(map[string]interface{}{"id": "7", "name": "seven", "uptime": 3600, "os": "Debian"})
	req := httptest.NewRequest(http.MethodPost, "/api/metrics", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer right")
	rr := httptest.NewRecorder()
	handleIngestMetric(store, broker, rr, req)
	if rr.Code >= 400 {
		t.Fatalf("legacy ingest with the right secret: %d %s", rr.Code, rr.Body.String())
	}
}

// The day of resource minutes is served from a cache until a minute is
// written; then the next request reads the store again.
func TestResourceHistoryCacheFollowsNewMinutes(t *testing.T) {
	store := newTestStore(t)
	resourceRec.reset()
	invalidateResourceHistoryCache()
	t.Cleanup(func() { resourceRec.reset(); invalidateResourceHistoryCache() })
	setSwitches(t, store, true, false)
	if err := store.Upsert(SystemMetric{ID: "srv", Name: "srv"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Minute)
	var samples []resourceSample
	for i := 30; i >= 2; i-- {
		samples = append(samples, resourceSample{ID: "srv", Minute: now.Add(-time.Duration(i)*time.Minute).Unix() / 60, CPU: float64(i), Mem: 40, Disk: 30})
	}
	if err := store.SaveResourceSamples(samples); err != nil {
		t.Fatal(err)
	}
	get := func() string {
		rr := httptest.NewRecorder()
		handleGetResourceHistory(store, rr, httptest.NewRequest(http.MethodGet, "/api/resource/history?client_id=srv", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("history: %d %s", rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	first := get()
	if again := get(); again != first {
		t.Fatal("a second read of the same minutes must be the same body")
	}
	// a cached body is served even when the store would answer differently:
	// it is the cache, not a fresh read (a minute saved without the flush)
	if err := store.SaveResourceSamples([]resourceSample{{ID: "srv", Minute: now.Add(-2*time.Minute).Unix() / 60, CPU: 99, Mem: 40, Disk: 30}}); err != nil {
		t.Fatal(err)
	}
	if cached := get(); cached != first {
		t.Fatal("expected the cached body until the flush says the minutes changed")
	}
	// the flush writes the finished minute and drops the cache
	resourceRec.add(SystemMetric{ID: "srv", CPU: 77, Memory: 40, Disk: 30}, now.Add(-30*time.Second))
	flushResourceHistory(store, now.Add(5*time.Second))
	fresh := get()
	if fresh == first || !strings.Contains(fresh, "77") || !strings.Contains(fresh, "99") {
		t.Fatalf("after the flush the new minutes must show: %s", fresh[len(fresh)-200:])
	}
	// a deleted server's history goes (its waiting minutes, then the stored
	// ones, as the delete handler does), and with it its cached body
	forgetPendingResources("srv")
	if err := store.DeleteResourceHistory("srv"); err != nil {
		t.Fatal(err)
	}
	var resp resourceHistoryResponse
	if err := json.Unmarshal([]byte(get()), &resp); err != nil || len(resp.Points) != 0 {
		t.Fatalf("after the delete: %d points, %v", len(resp.Points), err)
	}
}

// The admin page's backup comes compressed when it asks (gz=1) and the
// client takes gzip; unpacked, it is the same database a plain download
// gives. Without gz=1 (scripts, migrate.sh) it stays plain.
func TestAdminBackupCompressedOnRequest(t *testing.T) {
	store := newTestStore(t)
	for i := 0; i < 50; i++ {
		if err := store.Upsert(SystemMetric{ID: fmt.Sprintf("s%d", i), Name: strings.Repeat("server ", 20)}); err != nil {
			t.Fatal(err)
		}
	}
	withAdminToken(t, "backup-admin")
	get := func(query, accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backup"+query, nil)
		req.Header.Set("Authorization", "Bearer backup-admin")
		if accept != "" {
			req.Header.Set("Accept-Encoding", accept)
		}
		rr := httptest.NewRecorder()
		handleAdminBackup(store, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("backup %s: %d %s", query, rr.Code, rr.Body.String())
		}
		return rr
	}
	plain := get("", "gzip")
	if plain.Header().Get("Content-Encoding") != "" {
		t.Fatal("without gz=1 the backup must stay plain (scripts read it as the database)")
	}
	if rr := get("?gz=1", ""); rr.Header().Get("Content-Encoding") != "" {
		t.Fatal("a client that does not take gzip gets it plain")
	}
	zipped := get("?gz=1", "gzip, deflate, br")
	if zipped.Header().Get("Content-Encoding") != "gzip" || zipped.Body.Len()*2 > plain.Body.Len() {
		t.Fatalf("gz=1: encoding %q, %d bytes vs %d plain", zipped.Header().Get("Content-Encoding"), zipped.Body.Len(), plain.Body.Len())
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	unpacked, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpacked, plain.Body.Bytes()) {
		t.Fatalf("unpacked backup differs from the plain one (%d vs %d bytes)", len(unpacked), plain.Body.Len())
	}
}

// A TCPing interval under 5 s is refused on save (it multiplies the history
// by up to 60); 5 s and a day are the bounds.
func TestTCPingIntervalBounds(t *testing.T) {
	store := newTestStore(t)
	withAdminToken(t, "test-admin-token")
	save := func(secs int64) int {
		rr := httptest.NewRecorder()
		handleSetTCPingConfig(store, NewSSEBroker(), NewClientRegistry(), rr, adminRequest(t, http.MethodPost, "/api/tcping/config", map[string]interface{}{"targets": []map[string]string{{"name": "cf", "address": "1.1.1.1:443"}}, "interval_secs": secs}))
		return rr.Code
	}
	for _, c := range []struct {
		secs int64
		want int
	}{{1, http.StatusBadRequest}, {4, http.StatusBadRequest}, {5, http.StatusOK}, {60, http.StatusOK}, {86400, http.StatusOK}, {86401, http.StatusBadRequest}} {
		if got := save(c.secs); got != c.want {
			t.Fatalf("interval %d s: %d, want %d", c.secs, got, c.want)
		}
	}
}
