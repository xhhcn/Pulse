package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Response compression.
//
// The server used to send every body uncompressed and left compression to
// whatever sits in front of it. Cloudflare compresses; the China CDN in front
// of the reference deployment does not, so visitors on that path downloaded
// the page script, the stylesheet, every /api/metrics and tcping history body
// and the live event stream at full size — about five times the compressed
// size, and the stream alone is ~35 KB/s per open tab. Compressing here fixes
// it for every CDN and for direct access:
//
//   - Embedded static files never change while the process runs, so each
//     compressible one is gzipped once, on first request, and kept.
//   - API responses of a compressible type and at least apiGzipMinSize bytes
//     are gzipped on the fly with pooled writers.
//   - The event stream is gzipped too, without a compressor per connection:
//     every event is compressed once into a self-contained run of deflate
//     blocks (see deflateRun) and the same bytes go to every subscriber that
//     receives that event.
//
// HTTP_GZIP=off disables the first two, SSE_GZIP=off the stream, in case a
// proxy in front mishandles compressed bodies. Admin authentication uses
// bearer tokens only (no cookies), so a cross-site page cannot make a browser
// fetch privileged responses; compressing them opens no BREACH-style oracle.

var (
	httpGzipEnabled = envEnabled("HTTP_GZIP")
	sseGzipEnabled  = envEnabled("SSE_GZIP")
)

// envEnabled reports whether an on-by-default switch is on: any value but
// 0 / false / off / no keeps it enabled.
func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// acceptsGzip reports whether the request's Accept-Encoding admits gzip:
// listed (or x-gzip) with a non-zero q, or covered by "*" when gzip itself
// is not listed.
func acceptsGzip(r *http.Request) bool {
	gzipQ, starQ := -1.0, -1.0
	for _, field := range r.Header.Values("Accept-Encoding") {
		for _, item := range strings.Split(field, ",") {
			coding, params, _ := strings.Cut(item, ";")
			q := 1.0
			for _, p := range strings.Split(params, ";") {
				k, v, ok := strings.Cut(p, "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
					f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
					if err != nil {
						f = 0
					}
					q = f
				}
			}
			switch strings.ToLower(strings.TrimSpace(coding)) {
			case "gzip", "x-gzip":
				if q > gzipQ {
					gzipQ = q
				}
			case "*":
				if q > starQ {
					starQ = q
				}
			}
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return starQ > 0
}

// compressibleType reports whether a Content-Type is text-like. The event
// stream is excluded: it is compressed by its own handler, event by event.
func compressibleType(contentType string) bool {
	ct, _, _ := strings.Cut(contentType, ";")
	ct = strings.ToLower(strings.TrimSpace(ct))
	switch {
	case ct == "text/event-stream":
		return false
	case strings.HasPrefix(ct, "text/"):
		return true
	case ct == "application/json", ct == "application/javascript", ct == "application/xml",
		ct == "image/svg+xml", strings.HasSuffix(ct, "+json"), strings.HasSuffix(ct, "+xml"):
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Static files

// staticGzipMinSize: smaller files are served as they are.
const staticGzipMinSize = 1024

type staticGzipEntry struct {
	once sync.Once
	body []byte // nil when the file is served uncompressed
}

// staticGzipper serves the gzip form of the files of one embedded bundle.
// Entries are only created for files that exist in the bundle, so the cache
// is bounded by it.
type staticGzipper struct {
	fsys  fs.FS
	cache sync.Map // path → *staticGzipEntry
}

// body returns the gzip form of a file, computing it on first use, or nil
// when the file is not compressible, too small, or does not shrink by at
// least 10 %.
func (z *staticGzipper) body(path string) []byte {
	if !httpGzipEnabled || !compressibleType(mime.TypeByExtension(filepath.Ext(path))) {
		return nil
	}
	v, _ := z.cache.LoadOrStore(path, &staticGzipEntry{})
	e := v.(*staticGzipEntry)
	e.once.Do(func() {
		raw, err := fs.ReadFile(z.fsys, path)
		if err != nil || len(raw) < staticGzipMinSize {
			return
		}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := zw.Write(raw); err != nil || zw.Close() != nil {
			return
		}
		if buf.Len() < len(raw)*9/10 {
			e.body = buf.Bytes()
		}
	})
	return e.body
}

// gzipETag is the validator of the gzip representation: the identity tag with
// a suffix, since each representation needs its own strong validator.
func gzipETag(tag string) string {
	if len(tag) < 2 || !strings.HasSuffix(tag, `"`) {
		return ""
	}
	return tag[:len(tag)-1] + `-gz"`
}

// serve answers a GET or HEAD for a file of the bundle with its gzip form
// when the client accepts gzip and the file has one; it reports whether it
// wrote the response. Every compressible file gets Vary: Accept-Encoding,
// compressed or not, so caches keep the two representations apart. The
// caller has already set Cache-Control; etag is the identity validator.
func (z *staticGzipper) serve(w http.ResponseWriter, r *http.Request, path, etag string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	body := z.body(path)
	if body == nil {
		return false
	}
	h := w.Header()
	h.Add("Vary", "Accept-Encoding")
	if !acceptsGzip(r) {
		return false
	}
	tag := gzipETag(etag)
	if tag != "" {
		h.Set("ETag", tag)
		if etagMatches(r.Header.Get("If-None-Match"), tag) {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	h.Set("Content-Type", mime.TypeByExtension(filepath.Ext(path)))
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// ---------------------------------------------------------------------------
// API responses

// apiGzipMinSize: bodies smaller than this are sent as they are.
const apiGzipMinSize = 1024

var gzipWriterPool = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
	return zw
}}

// gzipAPIMiddleware gzips API responses for clients that accept it. The event
// stream compresses itself; HEAD requests and bodies the handler encodes on
// its own pass through.
func gzipAPIMiddleware(next http.Handler) http.Handler {
	if !httpGzipEnabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/events" || r.Method == http.MethodHead || !acceptsGzip(r) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.finish()
		next.ServeHTTP(gw, r)
	})
}

// gzipResponseWriter holds back the status and the first apiGzipMinSize body
// bytes, then commits: compressed when the body reached that size and its
// type is compressible, unchanged otherwise.
type gzipResponseWriter struct {
	http.ResponseWriter
	status    int
	buf       []byte
	committed bool
	zw        *gzip.Writer
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.committed || g.status != 0 {
		return
	}
	if code < 200 {
		// Informational responses go out at once and are not the final status.
		g.ResponseWriter.WriteHeader(code)
		return
	}
	g.status = code
	if code == http.StatusNoContent || code == http.StatusNotModified {
		g.commit(false)
	}
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if g.status == 0 {
		g.status = http.StatusOK
	}
	if g.committed {
		if g.zw != nil {
			return g.zw.Write(p)
		}
		return g.ResponseWriter.Write(p)
	}
	g.buf = append(g.buf, p...)
	if len(g.buf) >= apiGzipMinSize {
		if err := g.commit(true); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// commit writes the header and the held-back bytes. large tells whether the
// body reached apiGzipMinSize.
func (g *gzipResponseWriter) commit(large bool) error {
	g.committed = true
	h := g.Header()
	if h.Get("Content-Type") == "" && len(g.buf) > 0 {
		h.Set("Content-Type", http.DetectContentType(g.buf))
	}
	compressible := g.status != http.StatusNoContent && g.status != http.StatusNotModified &&
		h.Get("Content-Encoding") == "" && compressibleType(h.Get("Content-Type"))
	if compressible {
		h.Add("Vary", "Accept-Encoding")
	}
	if compressible && large {
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length")
		g.ResponseWriter.WriteHeader(g.status)
		zw := gzipWriterPool.Get().(*gzip.Writer)
		zw.Reset(g.ResponseWriter)
		g.zw = zw
		_, err := zw.Write(g.buf)
		g.buf = nil
		return err
	}
	g.ResponseWriter.WriteHeader(g.status)
	var err error
	if len(g.buf) > 0 {
		_, err = g.ResponseWriter.Write(g.buf)
	}
	g.buf = nil
	return err
}

// finish commits a response that never reached the threshold and closes the
// gzip stream of one that did.
func (g *gzipResponseWriter) finish() {
	if !g.committed && g.status != 0 {
		_ = g.commit(false)
	}
	if g.zw != nil {
		_ = g.zw.Close()
		g.zw.Reset(io.Discard)
		gzipWriterPool.Put(g.zw)
		g.zw = nil
	}
}

// Flush commits what is held back (compressed only if it already reached the
// threshold) and pushes it to the client.
func (g *gzipResponseWriter) Flush() {
	if !g.committed && g.status != 0 {
		_ = g.commit(len(g.buf) >= apiGzipMinSize)
	}
	if g.zw != nil {
		_ = g.zw.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// ---------------------------------------------------------------------------
// Event stream

// sseConnectedEvent opens every stream: the reconnect delay browsers should
// use (must be the first line) and a hello event. sseKeepalive is the comment
// line that keeps idle proxies from closing the connection.
const (
	sseConnectedEvent = "retry: 3000\n\nevent: connected\ndata: {\"message\":\"Connected to updates stream\"}\n\n"
	sseKeepalive      = ": ping\n\n"
)

var (
	sseConnectedRun = sync.OnceValue(func() *deflatedRun { return deflateRun(sseConnectedEvent) })
	sseKeepaliveRun = sync.OnceValue(func() *deflatedRun { return deflateRun(sseKeepalive) })
)

// sseGzipHeader starts a gzip member: magic, deflate, no flags, no mtime,
// no extra flags, OS unknown.
var sseGzipHeader = []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff}

// deflatedRun is a piece of the event stream in compressed form, with what
// the gzip trailer needs to know about its uncompressed text.
type deflatedRun struct {
	data []byte
	crc  uint32 // CRC-32 (IEEE) of the uncompressed text
	size int    // length of the uncompressed text
}

var flateWriterPool = sync.Pool{New: func() any {
	fw, _ := flate.NewWriter(io.Discard, flate.DefaultCompression)
	return fw
}}

// deflateRun compresses the concatenation of parts into a self-contained run
// of deflate blocks: a fresh compressor, so nothing refers back to bytes
// before the run, ended by a sync flush, so the run ends byte-aligned and
// without a final block. Such runs can follow each other in any order inside
// one deflate stream, and each run decodes completely as soon as it has been
// received.
func deflateRun(parts ...string) *deflatedRun {
	var buf bytes.Buffer
	fw := flateWriterPool.Get().(*flate.Writer)
	fw.Reset(&buf)
	crc, size := uint32(0), 0
	for _, p := range parts {
		b := []byte(p)
		_, _ = fw.Write(b)
		crc = crc32.Update(crc, crc32.IEEETable, b)
		size += len(b)
	}
	_ = fw.Flush()
	fw.Reset(io.Discard)
	flateWriterPool.Put(fw)
	return &deflatedRun{data: buf.Bytes(), crc: crc, size: size}
}

// sseRunCache keeps the compressed form of the last few distinct update
// payloads. Every subscriber of a view is sent the same payload string, so
// the first one to write an update compresses it and the rest reuse it.
type sseCachedRun struct {
	payload string
	once    sync.Once
	run     *deflatedRun
}

var sseRunCache struct {
	mu   sync.Mutex
	runs [8]*sseCachedRun
	next int
}

// sseUpdateRun returns the compressed form of the update event carrying
// payload ("event: update\ndata: <payload>\n\n").
func sseUpdateRun(payload string) *deflatedRun {
	sseRunCache.mu.Lock()
	var c *sseCachedRun
	for _, r := range sseRunCache.runs {
		// Equal strings from the same broadcast share their bytes, which makes
		// this comparison cheap for the entry that matches.
		if r != nil && r.payload == payload {
			c = r
			break
		}
	}
	if c == nil {
		c = &sseCachedRun{payload: payload}
		sseRunCache.runs[sseRunCache.next] = c
		sseRunCache.next = (sseRunCache.next + 1) % len(sseRunCache.runs)
	}
	sseRunCache.mu.Unlock()
	c.once.Do(func() { c.run = deflateRun("event: update\ndata: ", payload, "\n\n") })
	return c.run
}

// sseGzipStream writes one connection's gzip member from deflated runs and
// keeps the checksum and length its trailer needs.
type sseGzipStream struct {
	w       io.Writer
	started bool
	crc     uint32
	size    uint32
}

func (s *sseGzipStream) writeRun(run *deflatedRun) error {
	if !s.started {
		if _, err := s.w.Write(sseGzipHeader); err != nil {
			return err
		}
		s.started = true
	}
	if _, err := s.w.Write(run.data); err != nil {
		return err
	}
	s.crc = crc32Combine(s.crc, run.crc, int64(run.size))
	s.size += uint32(run.size)
	return nil
}

// finish ends the member — an empty final block, then CRC-32 and length —
// so a stream the server closes on purpose is a complete gzip file.
func (s *sseGzipStream) finish() error {
	if !s.started {
		return nil
	}
	var t [10]byte
	t[0], t[1] = 0x03, 0x00 // final block, fixed Huffman, end-of-block
	binary.LittleEndian.PutUint32(t[2:], s.crc)
	binary.LittleEndian.PutUint32(t[6:], s.size)
	_, err := s.w.Write(t[:])
	return err
}

// crc32Combine returns the CRC-32 (IEEE) of A followed by B from the CRCs of
// A and B and the length of B (zlib's crc32_combine).
func crc32Combine(crcA, crcB uint32, lenB int64) uint32 {
	return crc32MultModP(crc32X2nModP(lenB, 3), crcA) ^ crcB
}

const crc32ReversedPoly = 0xedb88320

// crc32MultModP multiplies a(x) by b(x) modulo the CRC polynomial (reflected).
func crc32MultModP(a, b uint32) uint32 {
	m := uint32(1) << 31
	p := uint32(0)
	for {
		if a&m != 0 {
			p ^= b
			if a&(m-1) == 0 {
				break
			}
		}
		m >>= 1
		if b&1 != 0 {
			b = b>>1 ^ crc32ReversedPoly
		} else {
			b >>= 1
		}
	}
	return p
}

// crc32X2nTable[k] is x^(2^k) modulo the CRC polynomial.
var crc32X2nTable = func() (t [32]uint32) {
	p := uint32(1) << 30 // x^1
	t[0] = p
	for k := 1; k < 32; k++ {
		p = crc32MultModP(p, p)
		t[k] = p
	}
	return t
}()

// crc32X2nModP returns x^(n * 2^k) modulo the CRC polynomial.
func crc32X2nModP(n int64, k uint) uint32 {
	p := uint32(1) << 31 // x^0
	for n > 0 {
		if n&1 != 0 {
			p = crc32MultModP(crc32X2nTable[k&31], p)
		}
		n >>= 1
		k++
	}
	return p
}
