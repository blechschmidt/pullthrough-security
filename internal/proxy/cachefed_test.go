package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachefed"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newGatewayWithFed builds a gateway with a peer cache-federation layer wired in,
// proxying the given upstream.
func newGatewayWithFed(t *testing.T, baseURL string, fed *cachefed.Federation) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: baseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: registry,
		CacheFed: fed,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestCacheFedServesMissFromPeer proves that, on a local miss, the gateway's
// cacheable pull path consults the federation layer and — on a verified peer hit
// — serves the peer's bytes WITHOUT reaching the upstream.
func TestCacheFedServesMissFromPeer(t *testing.T) {
	const peerBody = "PEER-SERVED-ARTIFACT"
	sum := sha256.Sum256([]byte(peerBody))
	peerDigest := "sha256:" + hex.EncodeToString(sum[:])

	// A permissive sibling peer: it answers any authorized key request with the
	// artifact and its content digest.
	var peerHits int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer peer-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&peerHits, 1)
		w.Header().Set("X-Cachefed-Digest", peerDigest)
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, peerBody)
	}))
	defer peer.Close()

	// The upstream must never be hit when the peer serves the miss.
	var upstreamHits int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		_, _ = io.WriteString(w, "UPSTREAM-FALLBACK")
	}))
	defer up.Close()

	// RequireDigest:false lets the federation verify against the peer-advertised
	// digest for this logical (non-content-addressed) npm cache key.
	fed, err := cachefed.New(cachefed.Config{
		Enabled:       true,
		AuthToken:     "peer-token",
		RequireDigest: false,
		MaxPeerFanout: 1,
		Peers:         []cachefed.Peer{{Name: "sibling", URL: peer.URL}},
	}, cachefed.NewMetrics())
	if err != nil {
		t.Fatalf("cachefed.New: %v", err)
	}

	g := newGatewayWithFed(t, up.URL, fed)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != peerBody {
		t.Errorf("body = %q, want %q (served from peer)", rr.Body.String(), peerBody)
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 0 {
		t.Errorf("upstream was hit %d times; the peer should have satisfied the miss", n)
	}
	if n := atomic.LoadInt32(&peerHits); n == 0 {
		t.Error("the peer was never consulted on the miss")
	}
	if snap := fed.Metrics().Snapshot(); snap.Hits != 1 {
		t.Errorf("cachefed hits = %d, want 1", snap.Hits)
	}

	// A second request is a straight local cache hit (no peer, no upstream).
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
	if rr2.Code != http.StatusOK || rr2.Body.String() != peerBody {
		t.Fatalf("second request status=%d body=%q", rr2.Code, rr2.Body.String())
	}
	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("second X-Cache = %q, want HIT", rr2.Header().Get("X-Cache"))
	}
}

// TestCacheFedFallsThroughToUpstream proves that when no peer can satisfy the
// miss, the gateway fetches from the upstream as usual.
func TestCacheFedFallsThroughToUpstream(t *testing.T) {
	var upstreamHits int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "UPSTREAM-ARTIFACT")
	}))
	defer up.Close()

	// A peer that holds nothing (404 for every key).
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer peer-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer peer.Close()

	fed, err := cachefed.New(cachefed.Config{
		Enabled:       true,
		AuthToken:     "peer-token",
		RequireDigest: false,
		MaxPeerFanout: 1,
		Peers:         []cachefed.Peer{{Name: "sibling", URL: peer.URL}},
	}, cachefed.NewMetrics())
	if err != nil {
		t.Fatalf("cachefed.New: %v", err)
	}

	g := newGatewayWithFed(t, up.URL, fed)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-2.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "UPSTREAM-ARTIFACT" {
		t.Errorf("body = %q, want the upstream artifact", rr.Body.String())
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 1 {
		t.Errorf("upstream hits = %d, want 1 (peer miss must fall through)", n)
	}
	if snap := fed.Metrics().Snapshot(); snap.Misses != 1 {
		t.Errorf("cachefed misses = %d, want 1", snap.Misses)
	}
}

// TestCacheFedPeerHandlerRoute proves the gateway mounts the authenticated peer
// endpoint and serves its own already-cached content to a sibling.
func TestCacheFedPeerHandlerRoute(t *testing.T) {
	fed, err := cachefed.New(cachefed.Config{
		Enabled:   true,
		Serve:     true,
		AuthToken: "peer-token",
	}, cachefed.NewMetrics())
	if err != nil {
		t.Fatalf("cachefed.New: %v", err)
	}

	c := cache.NewMemoryCache()
	content := []byte("LOCALLY-CACHED-GATED-ARTIFACT")
	sum := sha256.Sum256(content)
	key := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := c.Put(httptest.NewRequest(http.MethodGet, "/", nil).Context(), key, readerOf(content), nil); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	registry := backends.NewRegistry()
	b, _ := httpbackend.New(httpbackend.Options{Name: "npm", BaseURL: "https://example.invalid", Client: upstream.NewWithHTTPClient(http.DefaultClient, "t")})
	_ = registry.Register(b)
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    c,
		Backends: registry,
		CacheFed: fed,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Authorized GET for the cached key returns the bytes.
	req := httptest.NewRequest(http.MethodGet, cachefed.BasePath+"?key="+keyEscape(key), nil)
	req.Header.Set("Authorization", "Bearer peer-token")
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("peer GET status = %d", rr.Code)
	}
	if rr.Body.String() != string(content) {
		t.Errorf("peer GET body = %q, want the cached content", rr.Body.String())
	}

	// Unauthorized request is rejected.
	req2 := httptest.NewRequest(http.MethodGet, cachefed.BasePath+"?key="+keyEscape(key), nil)
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("unauthorized peer GET status = %d, want 401", rr2.Code)
	}
}

func readerOf(b []byte) io.Reader { return &byteReader{b: b} }

type byteReader struct {
	b   []byte
	pos int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func keyEscape(k string) string {
	out := ""
	for _, c := range k {
		if c == ':' {
			out += "%3A"
			continue
		}
		out += string(c)
	}
	return out
}
