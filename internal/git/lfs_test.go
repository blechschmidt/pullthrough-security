package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// oidOf returns the Git LFS object id (sha256 hex) of data.
func oidOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// lfsUpstream is a fake Git LFS server: it answers the batch API for the objects
// it holds and serves their bytes from a distinct storage path. storageHits
// counts object (not batch) fetches so tests can assert cache hit/miss behavior.
type lfsUpstream struct {
	srv         *httptest.Server
	blobs       map[string][]byte // oid -> content
	storageHits int32
	batchHits   int32
	// corrupt, when set for an oid, makes the storage endpoint serve different
	// bytes than the oid/size the batch API advertises (to exercise verification).
	corrupt map[string][]byte
}

func newLFSUpstream(t *testing.T, blobs map[string][]byte) *lfsUpstream {
	t.Helper()
	u := &lfsUpstream{blobs: blobs, corrupt: map[string][]byte{}}
	mux := http.NewServeMux()
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/storage/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&u.storageHits, 1)
		oid := strings.TrimPrefix(r.URL.Path, "/storage/")
		body := u.blobs[oid]
		if c, ok := u.corrupt[oid]; ok {
			body = c
		}
		if body == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	})
	// Batch endpoint: anything ending in /info/lfs/objects/batch.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/info/lfs/objects/batch") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		atomic.AddInt32(&u.batchHits, 1)
		var req lfsBatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := lfsBatchResponse{Transfer: "basic"}
		for _, obj := range req.Objects {
			body, ok := u.blobs[obj.OID]
			if !ok {
				resp.Objects = append(resp.Objects, lfsResponseObject{
					OID: obj.OID, Size: obj.Size,
					Error: &lfsObjectError{Code: 404, Message: "object does not exist"},
				})
				continue
			}
			resp.Objects = append(resp.Objects, lfsResponseObject{
				OID:  obj.OID,
				Size: int64(len(body)),
				Actions: map[string]lfsAction{
					"download": {Href: u.srv.URL + "/storage/" + obj.OID},
				},
			})
		}
		w.Header().Set("Content-Type", ctLFSJSON)
		_ = json.NewEncoder(w).Encode(resp)
	})
	t.Cleanup(u.srv.Close)
	return u
}

// newLFSBackend builds an LFS-enabled git backend pointed at the fake upstream.
func newLFSBackend(t *testing.T, baseURL string, c cache.Cache, opts LFSOptions) *Backend {
	t.Helper()
	opts.Enabled = true
	up, err := NewUpstream(UpstreamOptions{
		Name:   "gh",
		URL:    baseURL,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	b, err := NewBackend(BackendOptions{Upstream: up, Cache: c, Logger: discardLogger(), LFS: opts})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	return b
}

// doBatch posts a download batch request for the given oids/sizes to the proxy.
func doBatch(b *Backend, objects []lfsPointer) *httptest.ResponseRecorder {
	req := lfsBatchRequest{Operation: "download", Transfers: []string{"basic"}, Objects: objects}
	body, _ := json.Marshal(req)
	rr := httptest.NewRecorder()
	hr := httptest.NewRequest(http.MethodPost, "/v1/gh/o/r.git/info/lfs/objects/batch", bytes.NewReader(body))
	hr.Header.Set("Content-Type", ctLFSJSON)
	b.ServeBackendHTTP(rr, hr, "o/r.git/info/lfs/objects/batch")
	return rr
}

// doObject issues a GET (optionally with a Range) for an object through the proxy.
func doObject(b *Backend, oid string, size int64, rangeHdr string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	target := "/v1/gh/o/r.git/info/lfs/objects/" + oid + "?size=" + strconv.FormatInt(size, 10)
	hr := httptest.NewRequest(http.MethodGet, target, nil)
	if rangeHdr != "" {
		hr.Header.Set("Range", rangeHdr)
	}
	b.ServeBackendHTTP(rr, hr, "o/r.git/info/lfs/objects/"+oid)
	return rr
}

func TestLFSBatchNegotiationRewritesHrefs(t *testing.T) {
	blob := []byte("hello lfs world")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})

	rr := doBatch(b, []lfsPointer{{OID: oid, Size: int64(len(blob))}})
	if rr.Code != http.StatusOK {
		t.Fatalf("batch status = %d, body=%q", rr.Code, rr.Body.String())
	}
	var resp lfsBatchResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Transfer != "basic" {
		t.Errorf("transfer = %q, want basic", resp.Transfer)
	}
	if len(resp.Objects) != 1 {
		t.Fatalf("objects = %d, want 1", len(resp.Objects))
	}
	obj := resp.Objects[0]
	dl, ok := obj.Actions["download"]
	if !ok {
		t.Fatalf("no download action: %+v", obj)
	}
	// The href must point back at the proxy, not upstream storage, and carry size.
	if !strings.Contains(dl.Href, "/info/lfs/objects/"+oid) {
		t.Errorf("href not rewritten to proxy object url: %q", dl.Href)
	}
	if strings.Contains(dl.Href, "/storage/") {
		t.Errorf("href still points at upstream storage: %q", dl.Href)
	}
	if len(dl.Header) != 0 {
		t.Errorf("upstream auth header not stripped: %+v", dl.Header)
	}
	if obj.Size != int64(len(blob)) {
		t.Errorf("size = %d, want %d", obj.Size, len(blob))
	}
}

func TestLFSBatchRejectsUpload(t *testing.T) {
	up := newLFSUpstream(t, nil)
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})

	req := lfsBatchRequest{Operation: "upload", Objects: []lfsPointer{{OID: oidOf([]byte("x")), Size: 1}}}
	body, _ := json.Marshal(req)
	rr := httptest.NewRecorder()
	hr := httptest.NewRequest(http.MethodPost, "/v1/gh/o/r.git/info/lfs/objects/batch", bytes.NewReader(body))
	hr.Header.Set("Content-Type", ctLFSJSON)
	b.ServeBackendHTTP(rr, hr, "o/r.git/info/lfs/objects/batch")

	if rr.Code != http.StatusForbidden {
		t.Fatalf("upload status = %d, want 403", rr.Code)
	}
	if got := b.LFSMetrics().RejectedUpload; got != 1 {
		t.Errorf("RejectedUpload = %d, want 1", got)
	}
	if atomic.LoadInt32(&up.batchHits) != 0 {
		t.Errorf("upstream contacted for an upload request")
	}
}

func TestLFSObjectCacheMissThenHit(t *testing.T) {
	blob := bytes.Repeat([]byte("abcd"), 4096) // 16 KiB
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})

	// First request: miss → upstream fetch.
	first := doObject(b, oid, int64(len(blob)), "")
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, body=%q", first.Code, first.Body.String())
	}
	if !bytes.Equal(first.Body.Bytes(), blob) {
		t.Fatalf("first body mismatch (%d bytes)", first.Body.Len())
	}
	if got := atomic.LoadInt32(&up.storageHits); got != 1 {
		t.Fatalf("storage hits after miss = %d, want 1", got)
	}
	if got := first.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first X-Cache = %q, want MISS", got)
	}

	// Second request: hit → no upstream storage contact.
	second := doObject(b, oid, int64(len(blob)), "")
	if second.Code != http.StatusOK || !bytes.Equal(second.Body.Bytes(), blob) {
		t.Fatalf("second status=%d len=%d", second.Code, second.Body.Len())
	}
	if got := atomic.LoadInt32(&up.storageHits); got != 1 {
		t.Errorf("storage hits after hit = %d, want still 1 (served from cache)", got)
	}
	if got := second.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second X-Cache = %q, want HIT", got)
	}

	m := b.LFSMetrics()
	if m.CacheMisses != 1 || m.CacheHits != 1 {
		t.Errorf("metrics misses=%d hits=%d, want 1/1", m.CacheMisses, m.CacheHits)
	}
	if m.BytesFetched != int64(len(blob)) {
		t.Errorf("BytesFetched = %d, want %d", m.BytesFetched, len(blob))
	}
	if m.BytesServed != int64(2*len(blob)) {
		t.Errorf("BytesServed = %d, want %d", m.BytesServed, 2*len(blob))
	}
	if m.ObjectRequests != 2 {
		t.Errorf("ObjectRequests = %d, want 2", m.ObjectRequests)
	}
}

func TestLFSObjectOIDMismatchRejected(t *testing.T) {
	blob := []byte("the real content")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	// Storage serves tampered bytes that do not hash to the advertised oid.
	up.corrupt[oid] = []byte("TAMPERED content of a different length")

	c := cache.NewMemoryCache()
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{})

	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for oid mismatch; body=%q", rr.Code, rr.Body.String())
	}
	if got := b.LFSMetrics().OIDMismatches; got != 1 {
		t.Errorf("OIDMismatches = %d, want 1", got)
	}
	// Nothing must have been committed to the cache.
	if _, err := c.Stat(context.Background(), lfsCacheKey(oid)); err == nil {
		t.Errorf("corrupt object was cached; want absent")
	}
}

func TestLFSObjectSizeMismatchRejected(t *testing.T) {
	blob := []byte("twenty-byte content!")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := cache.NewMemoryCache()
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{})

	// Advertise the real oid but a wrong size hint; upstream batch echoes the real
	// length, so to force a size mismatch we make the upstream batch lie. Simpler:
	// have storage serve content that matches neither — covered by the OID test.
	// Here we assert that a correct object with a correct size passes and the
	// mismatch path is reachable via a direct verifier unit check.
	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("correct object status = %d, body=%q", rr.Code, rr.Body.String())
	}

	// Direct unit check of the verifier's size branch.
	vr := &lfsVerifyReader{
		src:          io.NopCloser(bytes.NewReader(blob)),
		hash:         sha256.New(),
		expectOID:    oid,
		declaredSize: int64(len(blob)) + 5, // wrong
		maxBytes:     1 << 20,
	}
	_, err := io.ReadAll(vr)
	if err == nil || !strings.Contains(err.Error(), "declared size") {
		t.Fatalf("verifier size branch err = %v, want size mismatch", err)
	}
}

func TestLFSObjectRangeRead(t *testing.T) {
	blob := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})

	// Warm the cache.
	if rr := doObject(b, oid, int64(len(blob)), ""); rr.Code != http.StatusOK {
		t.Fatalf("warm status = %d", rr.Code)
	}

	// bytes=5-14 -> "56789abcde"
	rr := doObject(b, oid, int64(len(blob)), "bytes=5-14")
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("range status = %d, want 206; body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != "56789abcde" {
		t.Errorf("range body = %q, want %q", got, "56789abcde")
	}
	if cr := rr.Header().Get("Content-Range"); cr != fmt.Sprintf("bytes 5-14/%d", len(blob)) {
		t.Errorf("Content-Range = %q", cr)
	}

	// Unsatisfiable range -> 416.
	rr = doObject(b, oid, int64(len(blob)), "bytes=9999-10000")
	if rr.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("unsatisfiable range status = %d, want 416", rr.Code)
	}
}

func TestLFSObjectInvalidOID(t *testing.T) {
	up := newLFSUpstream(t, nil)
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})
	rr := doObject(b, "not-a-valid-oid", 0, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid oid", rr.Code)
	}
}

func TestLFSObjectOversizeRejected(t *testing.T) {
	blob := bytes.Repeat([]byte("x"), 4096)
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{MaxObjectBytes: 1024})

	// Size hint already exceeds the cap → rejected before any upstream fetch.
	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rr.Code, rr.Body.String())
	}
	if atomic.LoadInt32(&up.storageHits) != 0 {
		t.Errorf("upstream storage contacted for an oversize object")
	}
}

// fakeGate is a test content gate that reports a fixed number of findings.
type fakeGate struct {
	findings  int
	lastOID   string
	lastBytes int
}

func (g *fakeGate) InspectLFSObject(_ context.Context, info LFSObjectInfo, content []byte) (int, error) {
	g.lastOID = info.OID
	g.lastBytes = len(content)
	return g.findings, nil
}

func TestLFSContentGateBlocks(t *testing.T) {
	blob := []byte("secret: AKIA_EXAMPLE_KEY")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := cache.NewMemoryCache()
	gate := &fakeGate{findings: 1}
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{BlockOnFindings: true, Gate: gate})

	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (blocked by gate); body=%q", rr.Code, rr.Body.String())
	}
	if gate.lastOID != oid || gate.lastBytes != len(blob) {
		t.Errorf("gate saw oid=%q bytes=%d, want %q/%d", gate.lastOID, gate.lastBytes, oid, len(blob))
	}
	m := b.LFSMetrics()
	if m.GateFindings != 1 || m.GateBlocked != 1 {
		t.Errorf("gate metrics findings=%d blocked=%d, want 1/1", m.GateFindings, m.GateBlocked)
	}
	// A blocked object must be evicted from the cache.
	if _, err := c.Stat(context.Background(), lfsCacheKey(oid)); err == nil {
		t.Errorf("blocked object left in cache")
	}
}

func TestLFSContentGateReportsWithoutBlocking(t *testing.T) {
	blob := []byte("secret-ish but not blocking")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	gate := &fakeGate{findings: 2}
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{BlockOnFindings: false, Gate: gate})

	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (served despite findings)", rr.Code)
	}
	m := b.LFSMetrics()
	if m.GateFindings != 2 || m.GateBlocked != 0 {
		t.Errorf("gate metrics findings=%d blocked=%d, want 2/0", m.GateFindings, m.GateBlocked)
	}
}

func TestLFSDisabledByDefault(t *testing.T) {
	// A backend without LFS enabled must 404 the LFS endpoints (falls through to
	// the unknown-endpoint handler).
	up, err := NewUpstream(UpstreamOptions{Name: "gh", URL: "https://example.com", Client: upstream.NewWithHTTPClient(http.DefaultClient, "t")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBackend(BackendOptions{Upstream: up, Cache: cache.NewMemoryCache(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	hr := httptest.NewRequest(http.MethodPost, "/v1/gh/o/r.git/info/lfs/objects/batch", strings.NewReader("{}"))
	b.ServeBackendHTTP(rr, hr, "o/r.git/info/lfs/objects/batch")
	if rr.Code != http.StatusNotFound {
		t.Errorf("LFS-disabled batch status = %d, want 404", rr.Code)
	}
}

func TestLFSObjectMissingUpstream(t *testing.T) {
	// Requesting an object the upstream does not have yields a bad gateway (the
	// batch API returns an object error).
	present := []byte("present")
	missing := []byte("missing object content")
	up := newLFSUpstream(t, map[string][]byte{oidOf(present): present})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})

	rr := doObject(b, oidOf(missing), int64(len(missing)), "")
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 for missing object", rr.Code)
	}
}

func TestSplitLFSEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		wantRepo string
		wantEP   lfsEndpoint
		wantOID  string
		wantOK   bool
	}{
		{"o/r.git/info/lfs/objects/batch", "o/r.git", lfsEndpointBatch, "", true},
		{"/o/r.git/info/lfs/objects/batch", "o/r.git", lfsEndpointBatch, "", true},
		{"o/r.git/info/lfs/objects/" + strings.Repeat("a", 64), "o/r.git", lfsEndpointObject, strings.Repeat("a", 64), true},
		{"info/lfs/objects/batch", "", lfsEndpointBatch, "", true},
		{"o/r.git/info/refs", "", lfsEndpointNone, "", false},
		{"o/r.git/git-upload-pack", "", lfsEndpointNone, "", false},
		{"o/r.git/info/lfs/objects/sub/dir", "", lfsEndpointNone, "", false},
	}
	for _, c := range cases {
		repo, ep, oid, ok := splitLFSEndpoint(c.in)
		if ok != c.wantOK || ep != c.wantEP || repo != c.wantRepo || oid != c.wantOID {
			t.Errorf("splitLFSEndpoint(%q) = (%q,%v,%q,%v), want (%q,%v,%q,%v)",
				c.in, repo, ep, oid, ok, c.wantRepo, c.wantEP, c.wantOID, c.wantOK)
		}
	}
}
