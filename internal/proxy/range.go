package proxy

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

// serveStats holds cumulative counters for the Range/partial-content streaming
// serve path (Task 75). They are process-local atomics, surfaced to Prometheus
// at scrape time via ServeMetrics so the metrics layer reads a single source of
// truth without the proxy importing it. All methods are safe for concurrent use.
type serveStats struct {
	rangeRequests  atomic.Int64 // inbound requests carrying a Range header
	partialServed  atomic.Int64 // responses answered 206 Partial Content
	unsatisfiable  atomic.Int64 // responses answered 416 Range Not Satisfiable
	spillToDisk    atomic.Int64 // non-seekable bodies spooled to a temp file to satisfy a range
	streamedBytes  atomic.Int64 // body bytes streamed to clients on the cache serve path
	digestMismatch atomic.Int64 // upstream streams rejected mid-fill for a content-digest mismatch
}

// ServeMetricsSnapshot is an immutable view of the streaming serve counters.
type ServeMetricsSnapshot struct {
	RangeRequests  int64
	PartialServed  int64
	Unsatisfiable  int64
	SpillToDisk    int64
	StreamedBytes  int64
	DigestMismatch int64
}

// ServeMetrics returns a snapshot of the Range/streaming serve counters for
// observability binding. It is safe to call concurrently with request serving.
func (g *Gateway) ServeMetrics() ServeMetricsSnapshot {
	s := g.serve
	if s == nil {
		return ServeMetricsSnapshot{}
	}
	return ServeMetricsSnapshot{
		RangeRequests:  s.rangeRequests.Load(),
		PartialServed:  s.partialServed.Load(),
		Unsatisfiable:  s.unsatisfiable.Load(),
		SpillToDisk:    s.spillToDisk.Load(),
		StreamedBytes:  s.streamedBytes.Load(),
		DigestMismatch: s.digestMismatch.Load(),
	}
}

// statusCapture wraps an http.ResponseWriter to record the final status code and
// the number of body bytes written. The cache serve path delegates RFC 7233
// range handling to http.ServeContent, which writes the status internally; this
// wrapper lets the gateway classify the outcome (206/416/200) for metrics
// afterwards. It forwards Flush so streaming is not buffered by the wrapper.
type statusCapture struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *statusCapture) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCapture) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusCapture) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// spoolToTemp drains r into an unlinked temporary file and returns it positioned
// at the start, so a non-seekable cache body (e.g. an object-storage stream) can
// satisfy a byte-range request via random access. The returned cleanup closes
// and removes the file and must be called when serving completes. Memory stays
// bounded: the body is copied to disk, never held in RAM.
func spoolToTemp(r io.Reader) (f *os.File, cleanup func(), err error) {
	tmp, err := os.CreateTemp("", "pullthrough-range-*")
	if err != nil {
		return nil, nil, err
	}
	name := tmp.Name()
	cleanup = func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := io.Copy(tmp, r); err != nil {
		cleanup()
		return nil, nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, err
	}
	return tmp, cleanup, nil
}

// digestVerifier wraps an upstream body and verifies its content digest
// incrementally as bytes are read on their way into the cache store. On EOF it
// compares the running hash against the expected digest and substitutes a
// mismatch error for the EOF when they differ, so the cache Put (which copies
// until EOF) fails and the entry is never committed. A tampered or truncated
// stream therefore cannot poison the cache. It implements io.ReadCloser,
// forwarding Close to the wrapped body so the gateway's loader contract (the
// cache closes the reader) is preserved.
type digestVerifier struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected []byte
	algo     string
	verified bool
	onFail   func()
}

// newDigestVerifier wraps src so the content streamed into the cache is verified
// against expectedDigest (formatted "algo:hexdigest", e.g. "sha256:ab12..."). It
// returns (src, false) unchanged when the digest is empty or its algorithm is
// not one the proxy verifies, so verification is strictly opt-in and never
// blocks a fill for an unknown scheme. onFail, when non-nil, is invoked once if
// the stream is rejected for a mismatch (for metrics).
func newDigestVerifier(src io.ReadCloser, expectedDigest string, onFail func()) (io.ReadCloser, bool) {
	algo, hexsum, ok := splitDigest(expectedDigest)
	if !ok {
		return src, false
	}
	var h hash.Hash
	switch algo {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "sha1":
		h = sha1.New()
	default:
		return src, false
	}
	want, err := hex.DecodeString(hexsum)
	if err != nil || len(want) != h.Size() {
		return src, false
	}
	return &digestVerifier{src: src, hash: h, expected: want, algo: algo, onFail: onFail}, true
}

func (v *digestVerifier) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
		v.hash.Write(p[:n])
	}
	if err == io.EOF && !v.verified {
		v.verified = true
		sum := v.hash.Sum(nil)
		if subtle.ConstantTimeCompare(sum, v.expected) != 1 {
			if v.onFail != nil {
				v.onFail()
			}
			return n, fmt.Errorf("proxy: cache fill aborted: %s digest mismatch (got %s, want %s)",
				v.algo, hex.EncodeToString(sum), hex.EncodeToString(v.expected))
		}
	}
	return n, err
}

func (v *digestVerifier) Close() error { return v.src.Close() }

// splitDigest parses a "algo:hexdigest" string into its lowercased algorithm and
// hex components. It reports false for an empty or malformed value.
func splitDigest(d string) (algo, hexsum string, ok bool) {
	i := strings.IndexByte(d, ':')
	if i <= 0 || i == len(d)-1 {
		return "", "", false
	}
	return strings.ToLower(d[:i]), d[i+1:], true
}
