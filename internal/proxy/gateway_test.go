package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newGateway builds a Gateway whose single backend (named "npm") proxies the
// given upstream base URL through a fresh in-memory cache.
func newGateway(t *testing.T, baseURL string, creds upstream.Credentials) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:        "npm",
		BaseURL:     baseURL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		Credentials: creds,
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
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestSplitBackendPath(t *testing.T) {
	cases := []struct {
		in         string
		name, rest string
		ok         bool
	}{
		{"/v1/npm/lodash/-/lodash-4.17.21.tgz", "npm", "/lodash/-/lodash-4.17.21.tgz", true},
		{"/v1/npm", "npm", "/", true},
		{"/healthz", "", "", false},
		{"/v1/", "", "", false},
	}
	for _, c := range cases {
		name, rest, ok := splitBackendPath(c.in)
		if ok != c.ok || name != c.name || rest != c.rest {
			t.Errorf("splitBackendPath(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, name, rest, ok, c.name, c.rest, c.ok)
		}
	}
}

func TestHandleReady(t *testing.T) {
	g := newGateway(t, "https://registry.npmjs.org", upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("/readyz status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleBackendUnknown(t *testing.T) {
	g := newGateway(t, "https://registry.npmjs.org", upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/unknown/foo", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleBackendRejectsNonRead(t *testing.T) {
	g := newGateway(t, "https://registry.npmjs.org", upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/npm/foo", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
	if rr.Header().Get("Allow") == "" {
		t.Error("missing Allow header on 405")
	}
}

// TestCacheMissThenHit proves transparent upstream filling on a miss and that a
// second identical request is served from cache without a second upstream call.
func TestCacheMissThenHit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{})

	rr1 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr1, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request status = %d (body %q)", rr1.Code, rr1.Body.String())
	}
	if rr1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first X-Cache = %q, want MISS", rr1.Header().Get("X-Cache"))
	}
	if rr1.Body.String() != "ARTIFACT" {
		t.Errorf("first body = %q", rr1.Body.String())
	}

	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("second request status = %d", rr2.Code)
	}
	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("second X-Cache = %q, want HIT", rr2.Header().Get("X-Cache"))
	}
	if rr2.Body.String() != "ARTIFACT" {
		t.Errorf("second body = %q", rr2.Body.String())
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hit %d times, want 1 (cache should absorb the second read)", got)
	}
}

// TestConditional304FromCache proves the gateway answers a client's
// If-None-Match against a cached entry's ETag with 304, with no upstream call.
func TestConditional304FromCache(t *testing.T) {
	var hits int32
	const etag = `"v1-etag"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("ETag", etag)
		_, _ = io.WriteString(w, "DATA")
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{})

	// Prime the cache.
	rr1 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr1, httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil))
	if rr1.Header().Get("ETag") != etag {
		t.Fatalf("served ETag = %q, want %q", rr1.Header().Get("ETag"), etag)
	}

	// Revalidate with the matching validator.
	req := httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil)
	req.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNotModified {
		t.Errorf("status = %d, want 304", rr2.Code)
	}
	if rr2.Body.Len() != 0 {
		t.Errorf("304 response must have empty body, got %q", rr2.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hit %d times, want 1", got)
	}
}

func TestUpstream404Relayed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/missing.tgz", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 relayed from upstream", rr.Code)
	}
}

func TestHeadServesHeadersWithoutBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "BODYBYTES")
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodHead, "/v1/npm/x.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD response must have empty body, got %q", rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("Content-Type = %q", rr.Header().Get("Content-Type"))
	}
}

func TestCredentialsInjectedUpstream(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{Token: "proxy-token"})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if gotAuth != "Bearer proxy-token" {
		t.Errorf("upstream Authorization = %q, want injected proxy credentials", gotAuth)
	}
}

// TestInboundCredentialsNotForwarded proves the proxy injects only its own
// configured credentials and never relays a client's inbound Authorization.
func TestInboundCredentialsNotForwarded(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{Token: "proxy-token"})
	req := httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil)
	req.Header.Set("Authorization", "Bearer client-secret")
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)

	if gotAuth == "Bearer client-secret" {
		t.Errorf("client credentials must not be forwarded upstream; got %q", gotAuth)
	}
	if gotAuth != "Bearer proxy-token" {
		t.Errorf("upstream Authorization = %q, want the proxy's own credentials", gotAuth)
	}
}
