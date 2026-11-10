package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newRateLimitedGateway builds a gateway with no access control (so the tenant
// resolves to the empty default key) and the supplied limiter, fronting baseURL
// via an "npm" backend.
func newRateLimitedGateway(t *testing.T, baseURL string, lim *ratelimit.Limiter) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: baseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	_ = registry.Register(b)

	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		RateLimit:  lim,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return g
}

func TestGatewayRateLimitRPS(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()

	lim := ratelimit.New(ratelimit.Options{Default: ratelimit.Policy{RPS: 5, Burst: 2}})
	g := newRateLimitedGateway(t, srv.URL, lim)

	codes := make(map[int]int)
	var retryAfter string
	for i := 0; i < 6; i++ {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil))
		codes[rr.Code]++
		if rr.Code == http.StatusTooManyRequests {
			retryAfter = rr.Header().Get("Retry-After")
		}
	}
	if codes[http.StatusOK] != 2 {
		t.Fatalf("expected 2 OK (burst), got %d (codes=%v)", codes[http.StatusOK], codes)
	}
	if codes[http.StatusTooManyRequests] != 4 {
		t.Fatalf("expected 4 throttled, got %d (codes=%v)", codes[http.StatusTooManyRequests], codes)
	}
	if retryAfter == "" {
		t.Fatal("expected a Retry-After header on 429")
	}
	if secs, err := strconv.Atoi(retryAfter); err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer", retryAfter)
	}
}

func TestGatewayRateLimitByteQuota(t *testing.T) {
	srv := upstreamArtifact(t) // serves "ARTIFACT" (8 bytes)
	defer srv.Close()

	lim := ratelimit.New(ratelimit.Options{Default: ratelimit.Policy{ByteQuota: 8}})
	g := newRateLimitedGateway(t, srv.URL, lim)

	// First request succeeds and consumes the 8-byte quota.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/a.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rr.Code)
	}

	// Second request is rejected: quota exhausted.
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/b.tgz", nil))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("X-RateLimit-Limit"); got != string(ratelimit.LimitBytes) {
		t.Fatalf("X-RateLimit-Limit = %q, want %q", got, ratelimit.LimitBytes)
	}
}

func TestGatewayRateLimitDisabledIsNoop(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()
	g := newRateLimitedGateway(t, srv.URL, nil) // no limiter

	for i := 0; i < 20; i++ {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (rate limiting disabled)", i, rr.Code)
		}
	}
}

// TestGatewayRateLimitConcurrentRace drives the middleware from many goroutines
// under the race detector to confirm slots are released and no data races occur.
func TestGatewayRateLimitConcurrentRace(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()

	lim := ratelimit.New(ratelimit.Options{Default: ratelimit.Policy{MaxConcurrent: 4}})
	g := newRateLimitedGateway(t, srv.URL, lim)
	handler := g.routes()

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil))
		}()
	}
	wg.Wait()

	// Every request has completed, so no concurrency slots should remain held.
	if rows := lim.Metrics().Tenants; len(rows) == 1 && rows[0].InFlight != 0 {
		t.Fatalf("residual in-flight = %d, want 0", rows[0].InFlight)
	}
}
