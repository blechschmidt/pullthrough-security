package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Benchmarks for the gateway request path against a stub upstream. They isolate
// the proxy's own per-request overhead (routing, backend resolution, cache
// lookup, response assembly) from real network latency by serving the upstream
// from an in-process httptest server. See docs/performance.md for baselines.

// benchUpstream returns an httptest server that serves a fixed body for any GET
// and counts how many times it was actually hit (so cache-hit benchmarks can
// assert the upstream stayed cold).
func benchUpstream(b *testing.B, body []byte) (*httptest.Server, *int64) {
	b.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	b.Cleanup(srv.Close)
	return srv, &hits
}

func benchGateway(b *testing.B, baseURL string) *Gateway {
	b.Helper()
	registry := backends.NewRegistry()
	be, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: baseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "bench/1"),
	})
	if err != nil {
		b.Fatal(err)
	}
	if err := registry.Register(be); err != nil {
		b.Fatal(err)
	}
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: registry,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		b.Fatal(err)
	}
	return g
}

// BenchmarkGatewayCacheHit measures steady-state hit serving: the artifact is
// pre-warmed, so every benchmarked request is served from cache and the upstream
// must stay cold. This is the dominant production path for popular artifacts.
func BenchmarkGatewayCacheHit(b *testing.B) {
	body := make([]byte, 64<<10)
	srv, hits := benchUpstream(b, body)
	g := benchGateway(b, srv.URL)
	handler := g.routes()

	const path = "/v1/npm/pkg-1.0.0.tgz"
	// Warm the cache with one real request.
	warm := httptest.NewRecorder()
	handler.ServeHTTP(warm, httptest.NewRequest(http.MethodGet, path, nil))
	if warm.Code != http.StatusOK {
		b.Fatalf("warm-up status = %d", warm.Code)
	}
	before := atomic.LoadInt64(hits)

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			b.Fatalf("status = %d", rr.Code)
		}
	}
	b.StopTimer()
	if got := atomic.LoadInt64(hits) - before; got != 0 {
		b.Fatalf("upstream was hit %d times during the cache-hit benchmark; expected 0", got)
	}
}

// BenchmarkGatewayCacheHitParallel measures concurrent hit serving — the
// realistic high-throughput shape where many clients read the same hot artifact.
func BenchmarkGatewayCacheHitParallel(b *testing.B) {
	body := make([]byte, 64<<10)
	srv, _ := benchUpstream(b, body)
	g := benchGateway(b, srv.URL)
	handler := g.routes()

	const path = "/v1/npm/pkg-1.0.0.tgz"
	warm := httptest.NewRecorder()
	handler.ServeHTTP(warm, httptest.NewRequest(http.MethodGet, path, nil))
	if warm.Code != http.StatusOK {
		b.Fatalf("warm-up status = %d", warm.Code)
	}

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusOK {
				b.Fatalf("status = %d", rr.Code)
			}
		}
	})
}

// BenchmarkGatewayCacheMiss measures cold-fill serving: each request targets a
// distinct key so the gateway fetches from the (in-process) upstream, fills the
// cache, and streams the result. This bounds throughput during cache warm-up or
// for long-tail, rarely-requested artifacts.
func BenchmarkGatewayCacheMiss(b *testing.B) {
	body := make([]byte, 8<<10)
	srv, _ := benchUpstream(b, body)
	g := benchGateway(b, srv.URL)
	handler := g.routes()

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := "/v1/npm/pkg-" + strconv.Itoa(i) + ".tgz"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			b.Fatalf("status = %d (body %q)", rr.Code, rr.Body.String())
		}
	}
}
