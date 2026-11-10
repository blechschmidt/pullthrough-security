package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// fakeBackend serves a fixed body for a cacheable coordinate, with an optional
// expected content digest (so the cache-fill digest verifier can be exercised)
// and a configurable body factory (so a mid-stream abort can be simulated). It
// counts Fetch calls so a test can prove the cache absorbed (or did not absorb)
// a request.
type fakeBackend struct {
	name    string
	body    []byte
	digest  string
	media   string
	etag    string               // strong upstream ETag, persisted to cache metadata
	bodyFn  func() io.ReadCloser // overrides body when set
	fetches int32
}

func (b *fakeBackend) Name() string { return b.name }

func (b *fakeBackend) Resolve(_ context.Context, req *backends.Request) (*backends.Resolved, error) {
	return &backends.Resolved{
		Coordinate:  backends.Coordinate{Name: strings.TrimPrefix(req.Path, "/")},
		UpstreamURL: "https://example.test" + req.Path,
		CacheKey:    "fake:" + req.Path,
		Digest:      b.digest,
		MediaType:   b.media,
		Cacheable:   true,
	}, nil
}

func (b *fakeBackend) Fetch(_ context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	atomic.AddInt32(&b.fetches, 1)
	var content io.ReadCloser
	if b.bodyFn != nil {
		content = b.bodyFn()
	} else {
		content = io.NopCloser(bytes.NewReader(b.body))
	}
	hdr := http.Header{}
	if b.etag != "" {
		hdr.Set("ETag", b.etag)
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      int64(len(b.body)),
		MediaType: b.media,
		Header:    hdr,
		Status:    http.StatusOK,
	}, nil
}

func newGatewayWith(t *testing.T, c cache.Cache, b backends.Backend) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    c,
		Backends: registry,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

const rangeBody = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" // 26 bytes, index == letter position

// prime fills the cache with the artifact and returns the served ETag.
func prime(t *testing.T, g *Gateway, path string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("prime %s: status = %d (body %q)", path, rr.Code, rr.Body.String())
	}
	if ar := rr.Header().Get("Accept-Ranges"); ar != "bytes" {
		t.Errorf("prime %s: Accept-Ranges = %q, want bytes", path, ar)
	}
	return rr.Header().Get("ETag")
}

// TestServeRangePartialContent proves a satisfiable Range yields 206 with the
// correct slice, Content-Range, and Content-Length, served from the cache.
func TestServeRangePartialContent(t *testing.T) {
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test", body: []byte(rangeBody), media: "application/octet-stream"})
	prime(t, g, "/v1/test/pkg")

	req := httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil)
	req.Header.Set("Range", "bytes=5-9")
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rr.Code)
	}
	if got, want := rr.Body.String(), "FGHIJ"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got, want := rr.Header().Get("Content-Range"), "bytes 5-9/26"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if got, want := rr.Header().Get("Content-Length"), "5"; got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
	if m := g.ServeMetrics(); m.PartialServed != 1 || m.RangeRequests != 1 {
		t.Errorf("metrics = %+v, want PartialServed=1 RangeRequests=1", m)
	}
}

// TestServeRangeSuffixAndOpenEnded covers the suffix ("last N bytes") and
// open-ended ("from N to end") range forms.
func TestServeRangeSuffixAndOpenEnded(t *testing.T) {
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test", body: []byte(rangeBody)})
	prime(t, g, "/v1/test/pkg")

	cases := []struct {
		rangeHdr     string
		wantBody     string
		wantContentR string
	}{
		{"bytes=-4", "WXYZ", "bytes 22-25/26"},
		{"bytes=24-", "YZ", "bytes 24-25/26"},
		{"bytes=0-0", "A", "bytes 0-0/26"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil)
		req.Header.Set("Range", c.rangeHdr)
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusPartialContent {
			t.Errorf("%s: status = %d, want 206", c.rangeHdr, rr.Code)
			continue
		}
		if rr.Body.String() != c.wantBody {
			t.Errorf("%s: body = %q, want %q", c.rangeHdr, rr.Body.String(), c.wantBody)
		}
		if got := rr.Header().Get("Content-Range"); got != c.wantContentR {
			t.Errorf("%s: Content-Range = %q, want %q", c.rangeHdr, got, c.wantContentR)
		}
	}
}

// TestServeRangeUnsatisfiable proves an out-of-bounds range yields 416 with a
// "bytes */size" Content-Range and increments the unsatisfiable counter.
func TestServeRangeUnsatisfiable(t *testing.T) {
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test", body: []byte(rangeBody)})
	prime(t, g, "/v1/test/pkg")

	req := httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil)
	req.Header.Set("Range", "bytes=100-200")
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416", rr.Code)
	}
	if got, want := rr.Header().Get("Content-Range"), "bytes */26"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if m := g.ServeMetrics(); m.Unsatisfiable != 1 {
		t.Errorf("Unsatisfiable = %d, want 1", m.Unsatisfiable)
	}
}

// TestServeIfRange proves If-Range gates the partial response on the validator:
// a matching ETag yields 206, a stale one yields the full 200 body.
func TestServeIfRange(t *testing.T) {
	const strongETag = `"strong-v1"`
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test", body: []byte(rangeBody), etag: strongETag})
	etag := prime(t, g, "/v1/test/pkg")
	if etag != strongETag {
		t.Fatalf("served ETag = %q, want the strong upstream validator %q (If-Range requires strong comparison)", etag, strongETag)
	}

	// Matching validator -> partial content.
	req := httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil)
	req.Header.Set("Range", "bytes=0-3")
	req.Header.Set("If-Range", etag)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusPartialContent {
		t.Errorf("matching If-Range: status = %d, want 206", rr.Code)
	}
	if rr.Body.String() != "ABCD" {
		t.Errorf("matching If-Range: body = %q, want ABCD", rr.Body.String())
	}

	// Stale validator -> the whole representation (200), so the client discards
	// its partial copy and re-downloads.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil)
	req2.Header.Set("Range", "bytes=0-3")
	req2.Header.Set("If-Range", `"stale-etag"`)
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("stale If-Range: status = %d, want 200", rr2.Code)
	}
	if rr2.Body.String() != rangeBody {
		t.Errorf("stale If-Range: body = %q, want full body", rr2.Body.String())
	}
}

// roCloser is a forward-only ReadCloser: it deliberately exposes no Seek method
// so the serve path must spool to disk to satisfy a range.
type roCloser struct{ r io.Reader }

func (c roCloser) Read(p []byte) (int, error) { return c.r.Read(p) }
func (roCloser) Close() error                 { return nil }

// TestServeRangeSpillToDisk proves that when the cache body is forward-only, a
// range request is satisfied by spooling to a temp file, counted as a spill.
func TestServeRangeSpillToDisk(t *testing.T) {
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test"})

	entry := &cache.Entry{
		Stat: cache.Stat{
			Key:     "fake:/x",
			Size:    int64(len(rangeBody)),
			ModTime: time.Unix(1000, 0),
			Metadata: map[string]string{
				cache.MetaContentType: "application/octet-stream",
			},
		},
		Content: roCloser{r: strings.NewReader(rangeBody)},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/test/x", nil)
	req.Header.Set("Range", "bytes=2-4")
	rr := httptest.NewRecorder()
	g.serveEntry(rr, req, entry, "HIT")

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rr.Code)
	}
	if got, want := rr.Body.String(), "CDE"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if m := g.ServeMetrics(); m.SpillToDisk != 1 {
		t.Errorf("SpillToDisk = %d, want 1", m.SpillToDisk)
	}
}

// TestServeNonRangeNoSpill proves a plain (non-range) request over a forward-only
// body streams in full without spilling to disk.
func TestServeNonRangeNoSpill(t *testing.T) {
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test"})
	entry := &cache.Entry{
		Stat:    cache.Stat{Key: "fake:/y", Size: int64(len(rangeBody))},
		Content: roCloser{r: strings.NewReader(rangeBody)},
	}
	rr := httptest.NewRecorder()
	g.serveEntry(rr, httptest.NewRequest(http.MethodGet, "/v1/test/y", nil), entry, "HIT")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != rangeBody {
		t.Errorf("body = %q, want full body", rr.Body.String())
	}
	if m := g.ServeMetrics(); m.SpillToDisk != 0 {
		t.Errorf("SpillToDisk = %d, want 0 (no range, no spill)", m.SpillToDisk)
	}
	if m := g.ServeMetrics(); m.StreamedBytes != int64(len(rangeBody)) {
		t.Errorf("StreamedBytes = %d, want %d", m.StreamedBytes, len(rangeBody))
	}
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestDigestVerifierMatch proves a stream whose content matches the expected
// digest reads through cleanly to EOF.
func TestDigestVerifierMatch(t *testing.T) {
	payload := []byte("supply-chain payload")
	src := io.NopCloser(bytes.NewReader(payload))
	vr, on := newDigestVerifier(src, sha256Digest(payload), nil)
	if !on {
		t.Fatal("verifier should be enabled for a valid sha256 digest")
	}
	got, err := io.ReadAll(vr)
	if err != nil {
		t.Fatalf("ReadAll: unexpected error %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("verified bytes = %q, want %q", got, payload)
	}
}

// TestDigestVerifierMismatch proves a stream whose content does not match the
// expected digest surfaces an error at EOF and fires the onFail hook.
func TestDigestVerifierMismatch(t *testing.T) {
	payload := []byte("tampered payload")
	var failed int
	src := io.NopCloser(bytes.NewReader(payload))
	vr, on := newDigestVerifier(src, sha256Digest([]byte("the original payload")), func() { failed++ })
	if !on {
		t.Fatal("verifier should be enabled")
	}
	_, err := io.ReadAll(vr)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("ReadAll error = %v, want a digest mismatch", err)
	}
	if failed != 1 {
		t.Errorf("onFail called %d times, want 1", failed)
	}
}

// TestDigestVerifierDisabledForUnknownScheme proves verification is opt-in:
// empty or unsupported digests pass the body through unwrapped.
func TestDigestVerifierDisabledForUnknownScheme(t *testing.T) {
	for _, d := range []string{"", "md5:abcd", "sha256:not-hex", "garbage"} {
		src := io.NopCloser(strings.NewReader("x"))
		got, on := newDigestVerifier(src, d, nil)
		if on {
			t.Errorf("digest %q: verifier unexpectedly enabled", d)
		}
		if got != src {
			t.Errorf("digest %q: body should pass through unwrapped", d)
		}
	}
}

// TestCacheNotPoisonedOnDigestMismatch proves an end-to-end fill whose streamed
// bytes fail digest verification is refused and leaves nothing in the cache, so
// a subsequent request re-fetches rather than serving corrupt content.
func TestCacheNotPoisonedOnDigestMismatch(t *testing.T) {
	fsCache, err := cache.NewFilesystemCache(cache.FilesystemOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer fsCache.Close()

	body := []byte("PAYLOAD-BYTES")
	be := &fakeBackend{
		name:   "test",
		body:   body,
		digest: sha256Digest([]byte("DIFFERENT")), // deliberately wrong expected digest
	}
	g := newGatewayWith(t, fsCache, be)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("status = 200, want a fetch error: corrupt content must not be served")
	}

	// Nothing was committed to the cache.
	if _, err := fsCache.Get(context.Background(), "fake:/pkg"); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("cache.Get after mismatch = %v, want ErrNotFound (entry must not be committed)", err)
	}
	if m := g.ServeMetrics(); m.DigestMismatch < 1 {
		t.Errorf("DigestMismatch = %d, want >= 1", m.DigestMismatch)
	}

	// A second request re-fetches upstream (cache is still empty).
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil))
	if rr2.Code == http.StatusOK {
		t.Fatalf("second request status = 200, want a fetch error")
	}
	if got := atomic.LoadInt32(&be.fetches); got != 2 {
		t.Errorf("upstream fetched %d times, want 2 (nothing cached to absorb the retry)", got)
	}
}

// errReader yields n good bytes then fails, modeling an upstream connection that
// drops mid-transfer.
type errReader struct {
	data []byte
	pos  int
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.pos < len(e.data) {
		n := copy(p, e.data[e.pos:])
		e.pos += n
		return n, nil
	}
	return 0, fmt.Errorf("simulated upstream connection reset")
}

func (e *errReader) Close() error { return nil }

// TestAbortedStreamCacheIntegrity proves that an upstream body which fails
// mid-stream never produces a committed cache entry (the atomic write is rolled
// back), so a partial transfer cannot poison the content-addressable cache.
func TestAbortedStreamCacheIntegrity(t *testing.T) {
	fsCache, err := cache.NewFilesystemCache(cache.FilesystemOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer fsCache.Close()

	be := &fakeBackend{
		name:   "test",
		body:   make([]byte, 64), // Size hint; the body itself aborts early
		bodyFn: func() io.ReadCloser { return &errReader{data: []byte("HALF")} },
	}
	g := newGatewayWith(t, fsCache, be)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/test/pkg", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("status = 200, want a fetch error for the aborted stream")
	}
	if _, err := fsCache.Get(context.Background(), "fake:/pkg"); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("cache.Get after abort = %v, want ErrNotFound (partial stream must not commit)", err)
	}
}

// TestHeadAdvertisesRangeSupport proves a HEAD response advertises Accept-Ranges
// (and a Content-Length) so clients know they may issue ranged GETs.
func TestHeadAdvertisesRangeSupport(t *testing.T) {
	g := newGatewayWith(t, cache.NewMemoryCache(), &fakeBackend{name: "test", body: []byte(rangeBody)})
	prime(t, g, "/v1/test/pkg")

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodHead, "/v1/test/pkg", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Accept-Ranges = %q, want bytes", rr.Header().Get("Accept-Ranges"))
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD body must be empty, got %q", rr.Body.String())
	}
}
