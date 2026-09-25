package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"hash/crc32"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestAcceptsGzip(t *testing.T) {
	cases := map[string]bool{
		"":                          false,
		"gzip":                      true,
		"gzip, deflate, br, zstd":   true,
		"br;q=1.0, gzip;q=0.8":      true,
		"GZIP":                      true,
		"x-gzip":                    true,
		"gzip;q=0":                  false,
		"gzip; q=0.0, *":            false,
		"*":                         true,
		"*;q=0":                     false,
		"identity":                  false,
		"br, zstd":                  false,
		"gzip;q=0, gzip;q=0.5":      true,
		"deflate;q=1, gzip;q=bogus": false,
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			r.Header.Set("Accept-Encoding", header)
		}
		if got := acceptsGzip(r); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestCRC32Combine(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		a := make([]byte, rng.Intn(3000))
		b := make([]byte, rng.Intn(3000))
		rng.Read(a)
		rng.Read(b)
		want := crc32.ChecksumIEEE(append(append([]byte{}, a...), b...))
		if got := crc32Combine(crc32.ChecksumIEEE(a), crc32.ChecksumIEEE(b), int64(len(b))); got != want {
			t.Fatalf("combine(%d, %d bytes) = %08x, want %08x", len(a), len(b), got, want)
		}
	}
}

// Runs from different compressors, repeated and in any order, form one valid
// gzip member, and each run decodes completely before the next one arrives.
func TestDeflateRunsStreamAsOneGzipMember(t *testing.T) {
	big := strings.Repeat(`{"id":"x","cpu":12.5,"memory":40.1},`, 4000)
	texts := []string{sseConnectedEvent, "event: update\ndata: " + big + "\n\n", sseKeepalive, "event: update\ndata: {\"a\":1}\n\n"}
	order := []int{0, 1, 2, 1, 3, 2, 1}

	pr, pw := io.Pipe()
	next := make(chan struct{})
	go func() {
		s := &sseGzipStream{w: pw}
		for _, i := range order {
			<-next
			if err := s.writeRun(deflateRun(texts[i])); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		<-next
		if err := s.finish(); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.Close()
	}()

	next <- struct{}{} // header and the first run
	zr, err := gzip.NewReader(pr)
	if err != nil {
		t.Fatalf("gzip header: %v", err)
	}
	for k, i := range order {
		want := texts[i]
		got := make([]byte, len(want))
		done := make(chan error, 1)
		go func() { _, err := io.ReadFull(zr, got); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("run %d: %v", k, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("run %d did not decode on its own", k)
		}
		if string(got) != want {
			t.Fatalf("run %d decoded to the wrong text", k)
		}
		next <- struct{}{}
	}
	rest, err := io.ReadAll(zr)
	if err != nil || len(rest) != 0 {
		t.Fatalf("end of member: %d extra bytes, err %v (a bad trailer reads as a checksum error)", len(rest), err)
	}
}

func TestSSEUpdateRunIsSharedPerPayload(t *testing.T) {
	a := strings.Repeat("a", 5000)
	b := strings.Repeat("b", 5000)
	ra := sseUpdateRun(a)
	if sseUpdateRun(a) != ra {
		t.Fatal("the same payload must reuse its compressed run")
	}
	if sseUpdateRun(b) == ra {
		t.Fatal("different payloads must not share a run")
	}
	if ra.size != len("event: update\ndata: ")+len(a)+len("\n\n") {
		t.Fatalf("run size %d", ra.size)
	}
}

// A gzip-capable subscriber receives every event as soon as it is broadcast,
// and a stream the server ends (admission revoked) is a complete gzip member.
func TestSSEGzipStreamEndToEnd(t *testing.T) {
	old := sseReauthInterval
	sseReauthInterval = 50 * time.Millisecond
	t.Cleanup(func() { sseReauthInterval = old })
	if globalClientRegistry == nil {
		globalClientRegistry = NewClientRegistry()
	}
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "gz-1", Name: "One", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	broker := NewSSEBroker()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleSSE(store, broker, w, r) }))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("headers: %v", resp.Header)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip header: %v", err)
	}
	br := bufio.NewReader(zr)
	block := func() string {
		type res struct {
			s   string
			err error
		}
		ch := make(chan res, 1)
		go func() {
			var sb strings.Builder
			for {
				line, err := br.ReadString('\n')
				sb.WriteString(line)
				if err != nil {
					ch <- res{sb.String(), err}
					return
				}
				if line == "\n" {
					ch <- res{sb.String(), nil}
					return
				}
			}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("read: %v (after %q)", r.err, r.s)
			}
			return r.s
		case <-time.After(3 * time.Second):
			t.Fatal("event did not arrive")
		}
		return ""
	}
	if got := block(); got != "retry: 3000\n\n" {
		t.Fatalf("first block %q", got)
	}
	if got := block(); !strings.HasPrefix(got, "event: connected\n") {
		t.Fatalf("second block %q", got)
	}
	if got := block(); !strings.HasPrefix(got, "event: update\ndata: ") || !strings.Contains(got, `"gz-1"`) {
		t.Fatalf("prime %q", got)
	}
	// A broadcast reaches the client while the stream stays open.
	if err := store.Upsert(SystemMetric{ID: "gz-2", Name: "Two", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	broadcastMetricsSnapshot(store, globalClientRegistry, broker)
	if got := block(); !strings.Contains(got, `"gz-2"`) {
		t.Fatalf("broadcast %q", got)
	}
	// Revoke admission: the server ends the stream and closes the member.
	if err := store.SavePrivacyConfig(&PrivacyConfig{Enabled: true}); err != nil {
		t.Fatalf("SavePrivacyConfig: %v", err)
	}
	endc := make(chan error, 1)
	go func() { _, err := io.ReadAll(br); endc <- err }()
	select {
	case err := <-endc:
		if err != nil {
			t.Fatalf("stream did not end as a complete gzip member: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not end after admission was revoked")
	}
}

func TestSSEGzipOffOrNotAccepted(t *testing.T) {
	if globalClientRegistry == nil {
		globalClientRegistry = NewClientRegistry()
	}
	store := newTestStore(t)
	broker := NewSSEBroker()
	run := func(acceptEncoding string) *http.Response {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleSSE(store, broker, w, r) }))
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}
		resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		buf := make([]byte, len("retry: 3000"))
		if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "retry: 3000" {
			t.Fatalf("plain stream expected, got %q (%v)", buf, err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := run(""); resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("no Accept-Encoding must get a plain stream")
	}
	if resp := run("gzip;q=0"); resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("gzip;q=0 must get a plain stream")
	}
	old := sseGzipEnabled
	sseGzipEnabled = false
	t.Cleanup(func() { sseGzipEnabled = old })
	if resp := run("gzip"); resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("SSE_GZIP=off must get a plain stream")
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

func TestGzipAPIMiddleware(t *testing.T) {
	bigList := make([]map[string]interface{}, 300)
	for i := range bigList {
		bigList[i] = map[string]interface{}{"id": strconv.Itoa(i), "name": "server", "cpu": 12.5}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/big", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, bigList) })
	mux.HandleFunc("/api/small", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]int{"n": 1}) })
	mux.HandleFunc("/api/error", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusNotFound) })
	mux.HandleFunc("/api/binary", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(bytes.Repeat([]byte{7}, 5000))
	})
	mux.HandleFunc("/api/encoded", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(bytes.Repeat([]byte("x"), 5000))
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("/api/notmodified", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotModified) })
	mux.HandleFunc("/api/flushed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("early"))
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte("z"), 4000))
	})
	mux.HandleFunc("/api/flushfirst", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush through the wrapper: %v", err)
		}
		_, _ = w.Write(bytes.Repeat([]byte("q"), 4000))
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if _, wrapped := w.(*gzipResponseWriter); wrapped {
			t.Error("the event stream must not go through the gzip wrapper")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(bytes.Repeat([]byte("y"), 4000))
	})
	h := gzipAPIMiddleware(mux)
	do := func(method, path, ae string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}
	want, _ := json.Marshal(bigList)

	rr := do(http.MethodGet, "/api/big", "gzip, br")
	if rr.Header().Get("Content-Encoding") != "gzip" || rr.Header().Get("Vary") != "Accept-Encoding" || rr.Header().Get("Content-Length") != strconv.Itoa(rr.Body.Len()) {
		t.Fatalf("big JSON headers: %v (body %d)", rr.Header(), rr.Body.Len())
	}
	if got := bytes.TrimSpace(gunzip(t, rr.Body.Bytes())); !bytes.Equal(got, want) {
		t.Fatal("big JSON did not round-trip")
	}
	if rr.Body.Len() >= len(want)/2 {
		t.Fatalf("compressed %d of %d bytes", rr.Body.Len(), len(want))
	}
	if rr := do(http.MethodGet, "/api/big", ""); rr.Header().Get("Content-Encoding") != "" || !bytes.Equal(bytes.TrimSpace(rr.Body.Bytes()), want) {
		t.Fatal("no Accept-Encoding must get the plain body")
	}
	if rr := do(http.MethodGet, "/api/big", "gzip;q=0"); rr.Header().Get("Content-Encoding") != "" {
		t.Fatal("gzip;q=0 must get the plain body")
	}
	if rr := do(http.MethodHead, "/api/big", "gzip"); rr.Header().Get("Content-Encoding") != "" {
		t.Fatal("HEAD must pass through")
	}
	if rr := do(http.MethodGet, "/api/small", "gzip"); rr.Header().Get("Content-Encoding") != "" || strings.TrimSpace(rr.Body.String()) != `{"n":1}` || rr.Code != http.StatusOK {
		t.Fatalf("small JSON must be sent as is: %v %q", rr.Header(), rr.Body.String())
	}
	if rr := do(http.MethodGet, "/api/error", "gzip"); rr.Code != http.StatusNotFound || rr.Header().Get("Content-Encoding") != "" || strings.TrimSpace(rr.Body.String()) != "nope" {
		t.Fatalf("error: %d %v %q", rr.Code, rr.Header(), rr.Body.String())
	}
	if rr := do(http.MethodGet, "/api/binary", "gzip"); rr.Header().Get("Content-Encoding") != "" || rr.Header().Get("Vary") != "" || rr.Body.Len() != 5000 {
		t.Fatalf("binary: %v %d", rr.Header(), rr.Body.Len())
	}
	if rr := do(http.MethodGet, "/api/encoded", "gzip"); len(rr.Header().Values("Content-Encoding")) != 1 || len(gunzip(t, rr.Body.Bytes())) != 5000 {
		t.Fatalf("pre-encoded: %v", rr.Header())
	}
	if rr := do(http.MethodGet, "/api/notmodified", "gzip"); rr.Code != http.StatusNotModified || rr.Body.Len() != 0 || rr.Header().Get("Content-Encoding") != "" {
		t.Fatalf("304: %d %v", rr.Code, rr.Header())
	}
	if rr := do(http.MethodGet, "/api/flushed", "gzip"); rr.Header().Get("Content-Encoding") != "" || rr.Body.Len() != 4005 || !rr.Flushed {
		t.Fatalf("flushed: %v %d", rr.Header(), rr.Body.Len())
	}
	if rr := do(http.MethodGet, "/api/events", "gzip"); rr.Header().Get("Content-Encoding") != "" || rr.Body.Len() != 4000 {
		t.Fatalf("events: %v", rr.Header())
	}
	if rr := do(http.MethodGet, "/api/flushfirst", "gzip"); rr.Header().Get("Content-Encoding") != "" || rr.Body.Len() != 4000 || rr.Body.Bytes()[0] != 'q' || !rr.Flushed {
		t.Fatalf("flush before the first write: %v %d", rr.Header(), rr.Body.Len())
	}
	// A signed-in admin's responses are never compressed (see gzipAllowed).
	ra := httptest.NewRequest(http.MethodGet, "/api/big", nil)
	ra.Header.Set("Accept-Encoding", "gzip")
	ra.Header.Set("Authorization", "Bearer anything")
	rra := httptest.NewRecorder()
	h.ServeHTTP(rra, ra)
	if rra.Header().Get("Content-Encoding") != "" || !bytes.Equal(bytes.TrimSpace(rra.Body.Bytes()), want) {
		t.Fatalf("authorized request must get the plain body: %v", rra.Header())
	}

	old := httpGzipEnabled
	httpGzipEnabled = false
	t.Cleanup(func() { httpGzipEnabled = old })
	off := gzipAPIMiddleware(mux)
	r := httptest.NewRequest(http.MethodGet, "/api/big", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	rr = httptest.NewRecorder()
	off.ServeHTTP(rr, r)
	if rr.Header().Get("Content-Encoding") != "" {
		t.Fatal("HTTP_GZIP=off must disable API compression")
	}
}

func TestStandaloneHandlerServesGzip(t *testing.T) {
	js := []byte(strings.Repeat("console.log('pulse');\n", 200))
	html := []byte("<!doctype html><title>x</title>" + strings.Repeat("<p>row</p>", 300))
	admin := []byte("<!doctype html><title>admin</title>" + strings.Repeat("<p>admin</p>", 300))
	fsys := fstest.MapFS{
		"index.html":           {Data: html},
		"admin/index.html":     {Data: admin},
		"_astro/app.a1b2.js":   {Data: js},
		"_astro/tiny.c3d4.css": {Data: []byte("body{margin:0}")},
		"fonts/x.woff2":        {Data: bytes.Repeat([]byte{1, 2, 3}, 2000)},
	}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Api", "1") })
	h := newStandaloneHandler(fsys, api)
	do := func(method, path, ae, inm string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}

	rr := do(http.MethodGet, "/_astro/app.a1b2.js", "gzip, deflate, br", "")
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Encoding") != "gzip" || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("js gzip: %d %v", rr.Code, rr.Header())
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "immutable") || rr.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("js headers: %v", rr.Header())
	}
	if !bytes.Equal(gunzip(t, rr.Body.Bytes()), js) || rr.Header().Get("Content-Length") != strconv.Itoa(rr.Body.Len()) {
		t.Fatal("js body")
	}
	gzTag := rr.Header().Get("ETag")
	plain := do(http.MethodGet, "/_astro/app.a1b2.js", "", "")
	idTag := plain.Header().Get("ETag")
	if plain.Header().Get("Content-Encoding") != "" || !bytes.Equal(plain.Body.Bytes(), js) || plain.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("js identity: %v", plain.Header())
	}
	if gzTag == "" || idTag == "" || gzTag == idTag || gzTag != gzipETag(idTag) {
		t.Fatalf("tags: gzip %q identity %q", gzTag, idTag)
	}
	if rr := do(http.MethodGet, "/_astro/app.a1b2.js", "gzip", gzTag); rr.Code != http.StatusNotModified || rr.Body.Len() != 0 || rr.Header().Get("Content-Encoding") != "" {
		t.Fatalf("gzip revalidation: %d %v", rr.Code, rr.Header())
	}
	if rr := do(http.MethodGet, "/_astro/app.a1b2.js", "gzip", "W/"+gzTag); rr.Code != http.StatusNotModified {
		t.Fatalf("weak gzip revalidation: %d", rr.Code)
	}
	if rr := do(http.MethodGet, "/_astro/app.a1b2.js", "gzip", idTag); rr.Code != http.StatusOK || rr.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("identity tag must not validate the gzip representation: %d", rr.Code)
	}
	if rr := do(http.MethodGet, "/_astro/app.a1b2.js", "", idTag); rr.Code != http.StatusNotModified {
		t.Fatalf("identity revalidation: %d", rr.Code)
	}
	if rr := do(http.MethodHead, "/_astro/app.a1b2.js", "gzip", ""); rr.Code != http.StatusOK || rr.Body.Len() != 0 || rr.Header().Get("Content-Encoding") != "gzip" || rr.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d %v", rr.Code, rr.Header())
	}

	for path, want := range map[string][]byte{"/": html, "/admin": admin, "/admin/": admin, "/some/spa/route": html} {
		rr := do(http.MethodGet, path, "gzip", "")
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Encoding") != "gzip" || rr.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("%s: %d %v", path, rr.Code, rr.Header())
		}
		if rr.Header().Get("Cache-Control") != "no-cache, must-revalidate" || !bytes.Equal(gunzip(t, rr.Body.Bytes()), want) {
			t.Fatalf("%s: headers %v", path, rr.Header())
		}
		if again := do(http.MethodGet, path, "gzip", rr.Header().Get("ETag")); again.Code != http.StatusNotModified {
			t.Fatalf("%s revalidation: %d", path, again.Code)
		}
		if id := do(http.MethodGet, path, "", ""); id.Header().Get("Content-Encoding") != "" || !bytes.Equal(id.Body.Bytes(), want) {
			t.Fatalf("%s identity", path)
		}
	}

	if rr := do(http.MethodGet, "/_astro/tiny.c3d4.css", "gzip", ""); rr.Header().Get("Content-Encoding") != "" || rr.Body.String() != "body{margin:0}" {
		t.Fatalf("tiny css must be sent as is: %v", rr.Header())
	}
	if rr := do(http.MethodGet, "/fonts/x.woff2", "gzip", ""); rr.Header().Get("Content-Encoding") != "" || rr.Header().Get("Vary") != "" || rr.Body.Len() != 6000 {
		t.Fatalf("font must be sent as is: %v", rr.Header())
	}
	if rr := do(http.MethodGet, "/api/anything", "gzip", ""); rr.Header().Get("X-Api") != "1" {
		t.Fatal("API routes must reach the API handler")
	}
	if rr := do(http.MethodGet, "/../index.html", "gzip", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("traversal: %d", rr.Code)
	}
	if rr := do(http.MethodGet, "/missing.js", "gzip", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("missing asset: %d", rr.Code)
	}
	// FileServer's canonical redirects are the same for gzip clients.
	for _, path := range []string{"/index.html", "/admin/index.html", "/_astro/app.a1b2.js/"} {
		plain, gz := do(http.MethodGet, path, "", ""), do(http.MethodGet, path, "gzip", "")
		if plain.Code != http.StatusMovedPermanently || gz.Code != plain.Code || gz.Header().Get("Location") != plain.Header().Get("Location") {
			t.Fatalf("%s: identity %d %q, gzip %d %q", path, plain.Code, plain.Header().Get("Location"), gz.Code, gz.Header().Get("Location"))
		}
	}

	old := httpGzipEnabled
	httpGzipEnabled = false
	t.Cleanup(func() { httpGzipEnabled = old })
	if rr := do(http.MethodGet, "/_astro/app.a1b2.js", "gzip", ""); rr.Header().Get("Content-Encoding") != "" {
		t.Fatal("HTTP_GZIP=off must disable static compression")
	}
}

func TestTCPingHistoryServesTheCachedGzipCopy(t *testing.T) {
	resetTCPingCacheForTest(t)
	store := newTestStore(t)
	if err := store.SaveTCPingConfig(&TCPingConfig{Targets: []TCPingTargetEntry{{Name: "t", Address: "1.1.1.1:53"}}, IntervalSecs: 60}); err != nil {
		t.Fatalf("SaveTCPingConfig: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "h1", Name: "History"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	now := time.Now().UTC()
	for i := 0; i < 200; i++ {
		l := float64(20 + i%7)
		if err := store.SaveTCPingResult(TCPingResult{ClientID: "h1", Target: "1.1.1.1:53", Latency: &l, Timestamp: now.Add(-time.Duration(i) * time.Minute)}); err != nil {
			t.Fatalf("SaveTCPingResult: %v", err)
		}
	}
	h := gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleGetTCPingHistory(store, w, r) }))
	get := func(ae, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/tcping/history?client_id=h1&target=1.1.1.1%3A53", nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}
	miss := get("gzip", "") // builds and caches the response
	hit := get("gzip", "")
	plain := get("", "")
	for name, rr := range map[string]*httptest.ResponseRecorder{"miss": miss, "hit": hit} {
		if rr.Code != http.StatusOK || len(rr.Header().Values("Content-Encoding")) != 1 || rr.Header().Get("Content-Encoding") != "gzip" {
			t.Fatalf("%s: %d %v", name, rr.Code, rr.Header())
		}
		if rr.Header().Get("Content-Length") != strconv.Itoa(rr.Body.Len()) || rr.Header().Get("Vary") != "Accept-Encoding" {
			t.Fatalf("%s headers: %v", name, rr.Header())
		}
		if !bytes.Equal(gunzip(t, rr.Body.Bytes()), plain.Body.Bytes()) {
			t.Fatalf("%s does not decode to the plain body", name)
		}
	}
	entry, ok := getCachedTCPingEntry("h1", "1.1.1.1:53")
	if !ok || entry.GZ == nil || !bytes.Equal(hit.Body.Bytes(), entry.GZ) || !bytes.Equal(miss.Body.Bytes(), entry.GZ) {
		t.Fatal("both responses must be the gzip copy stored with the cache entry")
	}
	if entry.Size != len(entry.JSON)+len(entry.GZ) {
		t.Fatalf("entry size %d does not count the gzip copy", entry.Size)
	}
	if admin := get("gzip", "Bearer x"); admin.Header().Get("Content-Encoding") != "" || !bytes.Equal(admin.Body.Bytes(), plain.Body.Bytes()) {
		t.Fatalf("an authorized request must get the JSON: %v", admin.Header())
	}
	var decoded TCPingHistoryResponse
	if err := json.Unmarshal(plain.Body.Bytes(), &decoded); err != nil || len(decoded.Results) != 200 {
		t.Fatalf("plain body: %d results (%v)", len(decoded.Results), err)
	}
}

func TestSSEAdminStreamIsNotCompressed(t *testing.T) {
	if globalClientRegistry == nil {
		globalClientRegistry = NewClientRegistry()
	}
	const token = "compress-test-admin-token"
	authTokensMu.Lock()
	authTokens[token] = time.Now().Add(time.Hour)
	authTokensMu.Unlock()
	t.Cleanup(func() {
		authTokensMu.Lock()
		delete(authTokens, token)
		authTokensMu.Unlock()
	})
	store := newTestStore(t)
	broker := NewSSEBroker()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleSSE(store, broker, w, r) }))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events?admin_token="+token, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, len("retry: 3000"))
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "retry: 3000" || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("admin stream must be plain: %q %v %v", buf, resp.Header, err)
	}
}

func TestPublicMetricsBodyIsSharedAndDroppedOnBroadcast(t *testing.T) {
	if globalClientRegistry == nil {
		globalClientRegistry = NewClientRegistry()
	}
	invalidatePublicMetricsCache()
	t.Cleanup(invalidatePublicMetricsCache)
	store := newTestStore(t)
	for i := 0; i < 20; i++ {
		if err := store.Upsert(SystemMetric{ID: "pm-" + strconv.Itoa(i), Name: "Public metrics " + strconv.Itoa(i), IPv4: "198.51.100." + strconv.Itoa(i+1)}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	withAdminToken(t, "pm-admin")
	h := gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleListMetrics(store, w, r) }))
	get := func(ae, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}
	plain := get("", "")
	gz := get("gzip", "")
	if plain.Code != http.StatusOK || gz.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(gunzip(t, gz.Body.Bytes()), plain.Body.Bytes()) {
		t.Fatalf("public body: %d %v", plain.Code, gz.Header())
	}
	var list []SystemMetric
	if err := json.Unmarshal(plain.Body.Bytes(), &list); err != nil || len(list) != 20 {
		t.Fatalf("public list: %d (%v)", len(list), err)
	}
	if bytes.Contains(plain.Body.Bytes(), []byte("198.51.100.")) {
		t.Fatal("the anonymous body must not carry addresses")
	}
	// Reused within the TTL, even across a store write…
	if err := store.Upsert(SystemMetric{ID: "pm-new", Name: "Added"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if again := get("", ""); !bytes.Equal(again.Body.Bytes(), plain.Body.Bytes()) {
		t.Fatal("a request within the TTL must reuse the cached body")
	}
	// …until a broadcast goes out.
	broadcastMetricsSnapshot(store, globalClientRegistry, NewSSEBroker())
	if after := get("", ""); !bytes.Contains(after.Body.Bytes(), []byte(`"pm-new"`)) {
		t.Fatal("a broadcast must drop the cached body")
	}
	// The admin view is built per request and never compressed.
	admin := get("gzip", "pm-admin")
	if admin.Header().Get("Content-Encoding") != "" || !bytes.Contains(admin.Body.Bytes(), []byte("198.51.100.")) {
		t.Fatalf("admin view: %v", admin.Header())
	}
	// Another store (tests, or a reopen) never gets this store's body.
	other := newTestStore(t)
	rr := httptest.NewRecorder()
	handleListMetrics(other, rr, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if strings.TrimSpace(rr.Body.String()) != "[]" && strings.TrimSpace(rr.Body.String()) != "null" {
		t.Fatalf("a different store must not be served the cached body: %q", rr.Body.String())
	}
}

func TestGzipMiddlewareSendsPlainWhenEveryCompressorIsBusy(t *testing.T) {
	big := bytes.Repeat([]byte(`{"k":"value"},`), 400)
	h := gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(big)
	}))
	for i := 0; i < cap(gzipSlots); i++ {
		gzipSlots <- struct{}{}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if gzipBytes(big) != nil {
		t.Error("gzipBytes must not wait for a slot")
	}
	for i := 0; i < cap(gzipSlots); i++ {
		<-gzipSlots
	}
	if rr.Header().Get("Content-Encoding") != "" || !bytes.Equal(rr.Body.Bytes(), big) {
		t.Fatalf("busy compressors must mean a plain body: %v", rr.Header())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Header().Get("Content-Encoding") != "gzip" || len(gzipSlots) != 0 {
		t.Fatalf("free compressors: %v, %d slots held", rr.Header(), len(gzipSlots))
	}
}

func TestGzipMiddlewareSendsNothingAfterAPanic(t *testing.T) {
	h := gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("x"), 5000))
		panic(http.ErrAbortHandler)
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	func() {
		defer func() { _ = recover() }()
		h.ServeHTTP(rr, r)
	}()
	if rr.Body.Len() != 0 || rr.Result().Header.Get("Content-Length") != "" || len(gzipSlots) != 0 {
		t.Fatalf("a panicking handler must not produce a complete response: %d bytes, %v, %d slots held", rr.Body.Len(), rr.Result().Header, len(gzipSlots))
	}
}

func TestPublicMetricsInvalidationNeverWaits(t *testing.T) {
	publicMetricsCache.build.Lock() // a rebuild in progress
	done := make(chan struct{})
	go func() { invalidatePublicMetricsCache(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		publicMetricsCache.build.Unlock()
		t.Fatal("the broadcaster's invalidation must not wait for a rebuild")
	}
	publicMetricsCache.build.Unlock()

	// A body built before a broadcast is not served after it.
	if globalClientRegistry == nil {
		globalClientRegistry = NewClientRegistry()
	}
	store := newTestStore(t)
	if err := store.Upsert(SystemMetric{ID: "before", Name: "Before"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, _, err := publicMetricsBody(store); err != nil {
		t.Fatalf("publicMetricsBody: %v", err)
	}
	if err := store.Upsert(SystemMetric{ID: "after", Name: "After"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	invalidatePublicMetricsCache()
	body, _, err := publicMetricsBody(store)
	if err != nil || !bytes.Contains(body, []byte(`"after"`)) {
		t.Fatalf("after an invalidation the body must be rebuilt: %s (%v)", body, err)
	}
}

func TestTCPingCacheSkipsAnEntryInvalidatedWhileItWasBuilt(t *testing.T) {
	resetTCPingCacheForTest(t)
	resp := TCPingHistoryResponse{Results: []TCPingResult{{ClientID: "c1", Target: "t", Timestamp: time.Now().UTC()}}}

	stamp := tcpingCacheStampFor("c1")
	invalidateTCPingCache("c1") // an agent push lands during the build
	if storeTCPingCacheEntry("c1", "t", buildTCPingCacheEntry(resp), stamp) {
		t.Fatal("an entry built before the client's invalidation must not be stored")
	}
	stamp = tcpingCacheStampFor("c1")
	invalidateTCPingCache("c2") // another client's push does not matter
	if !storeTCPingCacheEntry("c1", "t", buildTCPingCacheEntry(resp), stamp) {
		t.Fatal("another client's invalidation must not block caching")
	}
	stamp = tcpingCacheStampFor("c1")
	clearAllTCPingCache()
	if storeTCPingCacheEntry("c1", "t", buildTCPingCacheEntry(resp), stamp) {
		t.Fatal("an entry built before a full clear must not be stored")
	}
	if _, ok := getCachedTCPingEntry("c1", "t"); ok {
		t.Fatal("the full clear must have emptied the cache")
	}
}
