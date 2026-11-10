package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newCoalescingGateway builds a Gateway whose "npm" backend proxies baseURL
// through a fresh in-memory cache and the supplied coalescer.
func newCoalescingGateway(t *testing.T, baseURL string, cl *coalesce.Coalescer[*cache.Entry]) *Gateway {
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
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  registry,
		Coalescer: cl,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestNegativeCacheAbsorbsRepeated404 proves the negative cache prevents a
// thundering herd against a missing artifact: after the first upstream 404, the
// configured TTL absorbs subsequent requests, which are answered 404 without
// touching the upstream.
func TestNegativeCacheAbsorbsRepeated404(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "no such artifact", http.StatusNotFound)
	}))
	defer srv.Close()

	cl := NewCoalescer(coalesce.Config{Enabled: true, NegativeTTL: time.Minute})
	g := newCoalescingGateway(t, srv.URL, cl)

	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/missing.tgz", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("request %d: status = %d, want 404", i, rr.Code)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("upstream hit %d times, want 1 (negative cache should absorb the rest)", got)
	}
	if snap := cl.Metrics(); snap.NegativeHits != 4 {
		t.Fatalf("negative hits = %d, want 4", snap.NegativeHits)
	}
}

// TestConcurrentMissCoalescedToSingleFetch proves that a burst of concurrent
// requests for the same missing-from-cache artifact triggers exactly one
// upstream fetch, with every caller served the same bytes.
func TestConcurrentMissCoalescedToSingleFetch(t *testing.T) {
	var hits int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the upstream response open until all callers have joined
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "ARTIFACT-BYTES")
	}))
	defer srv.Close()

	cl := NewCoalescer(coalesce.Config{Enabled: true, NegativeTTL: time.Minute})
	g := newCoalescingGateway(t, srv.URL, cl)

	const n = 24
	var wg sync.WaitGroup
	wg.Add(n)
	codes := make([]int, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
			codes[i], bodies[i] = rr.Code, rr.Body.String()
		}(i)
	}

	// Wait until N-1 callers have coalesced onto the single in-flight fetch, then
	// let the upstream respond.
	deadline := time.Now().Add(3 * time.Second)
	for cl.Metrics().Coalesced < n-1 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d callers coalesced, want %d", cl.Metrics().Coalesced, n-1)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("upstream hit %d times, want exactly 1", got)
	}
	for i := 0; i < n; i++ {
		if codes[i] != http.StatusOK {
			t.Fatalf("caller %d: status = %d, want 200", i, codes[i])
		}
		if bodies[i] != "ARTIFACT-BYTES" {
			t.Fatalf("caller %d: body = %q, want shared artifact bytes", i, bodies[i])
		}
	}
}

// TestCoalesceTenantIsolation proves that a negative result observed under one
// tenant's auth scope never suppresses another tenant's (authorized) fetch: the
// coalesce/negative-cache key is partitioned by tenant.
func TestCoalesceTenantIsolation(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		// Deny the first caller (tenant A) but serve everyone else, so a shared
		// negative cache would wrongly deny tenant B too.
		if n == 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, "PRIVATE-ARTIFACT")
	}))
	defer srv.Close()

	cl := NewCoalescer(coalesce.Config{Enabled: true, NegativeTTL: time.Minute})
	g := newCoalescingGateway(t, srv.URL, cl)

	serve := func(team string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/npm/private.tgz", nil)
		ctx := auth.WithPrincipal(req.Context(), &auth.Principal{Subject: team + "-user", Team: team})
		g.handleBackend(rr, req.WithContext(ctx))
		return rr
	}

	// Tenant A is forbidden, which records a per-A-scope negative entry.
	if rr := serve("team-a"); rr.Code != http.StatusForbidden {
		t.Fatalf("tenant A: status = %d, want 403", rr.Code)
	}
	// Tenant B must not be shadowed by A's negative entry; it fetches and is served.
	if rr := serve("team-b"); rr.Code != http.StatusOK || rr.Body.String() != "PRIVATE-ARTIFACT" {
		t.Fatalf("tenant B: status = %d body = %q, want 200 with artifact (no cross-tenant negative shadowing)",
			rr.Code, rr.Body.String())
	}
}

// TestCoalesceKeyScopedByTenant verifies the key derivation directly: the same
// artifact path under different tenants yields different coalesce keys, while a
// repeated request for one tenant is stable.
func TestCoalesceKeyScopedByTenant(t *testing.T) {
	g := newCoalescingGateway(t, "https://example.test", nil)

	keyFor := func(team string) string {
		req := httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil)
		ctx := auth.WithPrincipal(req.Context(), &auth.Principal{Team: team})
		return g.coalesceKey(req.WithContext(ctx), "sha256:abc")
	}
	a, b := keyFor("team-a"), keyFor("team-b")
	if a == b {
		t.Fatalf("coalesce keys for distinct tenants collided: %q", a)
	}
	if a != keyFor("team-a") {
		t.Fatal("coalesce key is not stable for the same tenant")
	}

	// An unauthenticated request maps to the shared namespace.
	anon := g.coalesceKey(httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil), "sha256:abc")
	if anon != "_shared\x00sha256:abc" {
		t.Fatalf("anonymous coalesce key = %q, want shared-namespace key", anon)
	}
}

// TestClassifyUpstreamError covers the mapping from upstream failures to
// negative-caching verdicts.
func TestClassifyUpstreamError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		cache     bool
		retryable bool
		kind      string
	}{
		{"404", &backends.StatusError{Status: 404}, true, false, "not_found"},
		{"410", &backends.StatusError{Status: 410}, true, false, "gone"},
		{"401", &backends.StatusError{Status: 401}, true, false, "auth"},
		{"403", &backends.StatusError{Status: 403}, true, false, "auth"},
		{"429", &backends.StatusError{Status: 429}, true, true, "throttled"},
		{"503", &backends.StatusError{Status: 503}, true, true, "server"},
		{"400", &backends.StatusError{Status: 400}, false, false, ""},
		{"canceled", context.Canceled, false, false, ""},
		{"network", io.ErrUnexpectedEOF, true, true, "error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := classifyUpstreamError(c.err)
			if v.Cache != c.cache || v.Retryable != c.retryable || v.Kind != c.kind {
				t.Fatalf("classify(%v) = %+v, want cache=%v retryable=%v kind=%q",
					c.err, v, c.cache, c.retryable, c.kind)
			}
		})
	}
}

// TestMaxInflightSheds503 proves that exceeding the in-flight ceiling sheds the
// excess request with 503 instead of issuing another origin fetch.
func TestMaxInflightSheds503(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		_, _ = io.WriteString(w, "DATA")
	}))
	defer srv.Close()

	cl := NewCoalescer(coalesce.Config{Enabled: true, NegativeTTL: time.Minute, MaxInflight: 1})
	g := newCoalescingGateway(t, srv.URL, cl)

	// Occupy the single in-flight slot with a slow fetch for key A.
	done := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/a.tgz", nil))
		done <- rr.Code
	}()
	<-started

	// A distinct key B must be shed with 503 while A holds the slot.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/b.tgz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-capacity request: status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Errorf("503 response should carry a Retry-After header")
	}

	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("leader request: status = %d, want 200", code)
	}
	if snap := cl.Metrics(); snap.Overloaded != 1 {
		t.Fatalf("overloaded = %d, want 1", snap.Overloaded)
	}
}
