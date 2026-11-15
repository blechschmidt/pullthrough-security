package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// slowUpstream serves "ARTIFACT" after a delay and records the most requests it
// saw in flight at once.
func slowUpstream(t *testing.T, delay time.Duration) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var cur, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := cur.Add(1)
		defer cur.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(delay)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	t.Cleanup(srv.Close)
	return srv, &peak
}

// burst sends n requests at once through handler and counts the status codes;
// it also returns the Retry-After of a 429.
func burst(handler http.Handler, n int, path func(i int) string) (map[int]int, string) {
	var mu sync.Mutex
	codes := map[int]int{}
	var retryAfter string
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path(i), nil))
			mu.Lock()
			codes[rr.Code]++
			if rr.Code == http.StatusTooManyRequests {
				retryAfter = rr.Header().Get("Retry-After")
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	return codes, retryAfter
}

// TestGatewayRateLimitQueuesABurst is Task 187's report: cargo fetched ~90
// index files at once through a personal link, the tenant's concurrency limit
// was 32, and every request over it was answered 429 at once — cargo before
// 1.89 does not retry a 429, so the build failed. Waiting for a slot serves the
// whole burst, never with more than the limit in flight upstream.
func TestGatewayRateLimitQueuesABurst(t *testing.T) {
	srv, peak := slowUpstream(t, 20*time.Millisecond)
	lim := ratelimit.New(ratelimit.Options{Default: ratelimit.Policy{MaxConcurrent: 4}, MaxWait: 10 * time.Second})
	g := newRateLimitedGateway(t, srv.URL, lim)

	codes, _ := burst(g.routes(), 40, func(i int) string { return "/v1/npm/pkg-" + strconv.Itoa(i) + ".tgz" })
	if codes[http.StatusOK] != 40 {
		t.Fatalf("codes %v, want all 40 served", codes)
	}
	if p := peak.Load(); p > 4 {
		t.Fatalf("%d requests reached the upstream at once, above the limit of 4", p)
	}
	snap := lim.Metrics()
	if snap.Delayed == 0 || snap.Throttled != 0 || snap.Waiting != 0 {
		t.Fatalf("snapshot after the burst: %+v", snap)
	}
}

// TestGatewayRateLimitConcurrencyRefusalCarriesRetryAfter: without a wait the
// same burst is refused over the limit, and the refusal tells a retrying
// client (cargo 1.89 and later honours it) when to come back.
func TestGatewayRateLimitConcurrencyRefusalCarriesRetryAfter(t *testing.T) {
	srv, _ := slowUpstream(t, 50*time.Millisecond)
	lim := ratelimit.New(ratelimit.Options{Default: ratelimit.Policy{MaxConcurrent: 2}})
	g := newRateLimitedGateway(t, srv.URL, lim)

	codes, retryAfter := burst(g.routes(), 10, func(i int) string { return "/v1/npm/pkg-" + strconv.Itoa(i) + ".tgz" })
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("codes %v, want refusals over the limit", codes)
	}
	if retryAfter != "1" {
		t.Fatalf("Retry-After %q on a concurrency refusal, want 1", retryAfter)
	}
}
