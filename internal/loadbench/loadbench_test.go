package loadbench

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newStub returns an httptest server that classifies requests the way the proxy
// does: the first request for a given path is a MISS, subsequent requests are
// HITs, and any path containing "absent" is a 404. It records per-path hit
// counts so coalescing/warmup behavior can be asserted.
func newStub() (*httptest.Server, *sync.Map) {
	var seen sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "absent") {
			w.Header().Set("X-Cache", "MISS")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n, _ := seen.LoadOrStore(path, new(int64))
		cnt := atomic.AddInt64(n.(*int64), 1)
		if cnt == 1 {
			w.Header().Set("X-Cache", "MISS")
		} else {
			w.Header().Set("X-Cache", "HIT")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(make([]byte, 1024))
	}))
	return srv, &seen
}

func TestRunCacheHitClassification(t *testing.T) {
	srv, _ := newStub()
	defer srv.Close()

	r, err := New(Config{
		BaseURL:     srv.URL,
		Targets:     []Target{{Path: "/v1/npm/hot.tgz"}},
		Concurrency: 4,
		Requests:    40,
		Warmup:      1, // fill the cache so measured requests are all hits
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 40 {
		t.Fatalf("total = %d, want 40", res.Total)
	}
	if res.Success != 40 {
		t.Fatalf("success = %d, want 40", res.Success)
	}
	// After the warmup MISS, every measured request must be a HIT.
	if res.CacheHits != 40 || res.CacheMisses != 0 {
		t.Fatalf("hits=%d misses=%d, want 40/0", res.CacheHits, res.CacheMisses)
	}
	if got := res.CacheHitRatio(); got != 1.0 {
		t.Fatalf("hit ratio = %v, want 1.0", got)
	}
	if res.Latency.Count != 40 {
		t.Fatalf("latency count = %d, want 40", res.Latency.Count)
	}
	if res.Latency.P50 <= 0 || res.Latency.Max < res.Latency.P50 {
		t.Fatalf("implausible latency stats: %+v", res.Latency)
	}
	if res.Bytes != 40*1024 {
		t.Fatalf("bytes = %d, want %d", res.Bytes, 40*1024)
	}
	if res.Throughput() <= 0 {
		t.Fatalf("throughput = %v, want > 0", res.Throughput())
	}
}

func TestRunCacheMissUniqueKeys(t *testing.T) {
	srv, seen := newStub()
	defer srv.Close()

	r, err := New(Config{
		BaseURL:     srv.URL,
		Targets:     []Target{{Template: "/v1/npm/pkg-%d.tgz"}},
		Concurrency: 8,
		Requests:    80,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 80 || res.CacheMisses != 80 {
		t.Fatalf("total=%d misses=%d, want 80/80 (every key unique)", res.Total, res.CacheMisses)
	}
	// Each synthesized key must have been requested exactly once.
	distinct := 0
	seen.Range(func(_, v any) bool {
		if atomic.LoadInt64(v.(*int64)) != 1 {
			t.Errorf("a key was requested more than once")
		}
		distinct++
		return true
	})
	if distinct != 80 {
		t.Fatalf("distinct keys = %d, want 80", distinct)
	}
}

func TestRunNegativeAnd404Tracking(t *testing.T) {
	srv, _ := newStub()
	defer srv.Close()

	r, err := New(Config{
		BaseURL:     srv.URL,
		Targets:     []Target{{Path: "/v1/npm/absent.tgz"}},
		Concurrency: 4,
		Requests:    20,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.NotFound != 20 {
		t.Fatalf("notFound = %d, want 20", res.NotFound)
	}
	// 404s are not errors and not successes.
	if res.Success != 0 || res.ClientErrors != 0 || res.ServerErrors != 0 {
		t.Fatalf("404s misclassified: success=%d 4xx=%d 5xx=%d", res.Success, res.ClientErrors, res.ServerErrors)
	}
	if res.StatusCodes[http.StatusNotFound] != 20 {
		t.Fatalf("status histogram 404 = %d, want 20", res.StatusCodes[http.StatusNotFound])
	}
}

func TestRunDurationMode(t *testing.T) {
	srv, _ := newStub()
	defer srv.Close()

	r, err := New(Config{
		BaseURL:     srv.URL,
		Targets:     []Target{{Path: "/v1/npm/hot.tgz"}},
		Concurrency: 4,
		Duration:    150 * time.Millisecond,
		Warmup:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Total == 0 {
		t.Fatal("duration run issued no requests")
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatalf("run returned before its duration elapsed")
	}
	if res.Elapsed < 150*time.Millisecond {
		t.Fatalf("elapsed = %v, want >= 150ms", res.Elapsed)
	}
}

func TestServerMetricsDelta(t *testing.T) {
	srv, _ := newStub()
	defer srv.Close()

	var calls int64
	sampler := func(ctx context.Context) (ServerMetrics, error) {
		// First call (before): baseline; second call (after): grown counters.
		if atomic.AddInt64(&calls, 1) == 1 {
			return ServerMetrics{CacheHits: 100, CacheMisses: 10, Coalesced: 5, Leads: 5}, nil
		}
		return ServerMetrics{CacheHits: 140, CacheMisses: 11, Coalesced: 8, Leads: 7, NegativeEntries: 3}, nil
	}

	r, err := New(Config{
		BaseURL:       srv.URL,
		Targets:       []Target{{Path: "/v1/npm/hot.tgz"}},
		Concurrency:   2,
		Requests:      10,
		Warmup:        1,
		ServerMetrics: sampler,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Server == nil {
		t.Fatalf("server delta missing; error=%q", res.ServerMetricsError)
	}
	if res.Server.CacheHits != 40 || res.Server.CacheMisses != 1 {
		t.Fatalf("delta hits/misses = %d/%d, want 40/1", res.Server.CacheHits, res.Server.CacheMisses)
	}
	if res.Server.Coalesced != 3 || res.Server.Leads != 2 {
		t.Fatalf("delta coalesced/leads = %d/%d, want 3/2", res.Server.Coalesced, res.Server.Leads)
	}
	if res.Server.NegativeEntries != 3 {
		t.Fatalf("negative entries (gauge) = %d, want 3", res.Server.NegativeEntries)
	}
}

func TestServerMetricsErrorReported(t *testing.T) {
	srv, _ := newStub()
	defer srv.Close()

	sampler := func(ctx context.Context) (ServerMetrics, error) {
		return ServerMetrics{}, fmt.Errorf("admin API unauthorized")
	}
	r, err := New(Config{
		BaseURL:       srv.URL,
		Targets:       []Target{{Path: "/v1/npm/hot.tgz"}},
		Concurrency:   1,
		Requests:      3,
		ServerMetrics: sampler,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Server != nil {
		t.Fatal("server delta should be absent when sampling failed")
	}
	if res.ServerMetricsError == "" {
		t.Fatal("expected ServerMetricsError to be set")
	}
}

func TestValidation(t *testing.T) {
	cases := []Config{
		{Targets: []Target{{Path: "/x"}}},            // missing BaseURL
		{BaseURL: "http://x"},                        // no targets
		{BaseURL: "http://x", Targets: []Target{{}}}, // empty target
		{BaseURL: "http://x", Targets: []Target{{Path: "/x"}}, Duration: -1},
	}
	for i, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestPercentile(t *testing.T) {
	s := make([]time.Duration, 100)
	for i := range s {
		s[i] = time.Duration(i+1) * time.Millisecond
	}
	// Nearest-rank: p50 -> rank ceil(0.5*100)=50 -> s[49]=50ms.
	if got := percentile(s, 0.50); got != 50*time.Millisecond {
		t.Errorf("p50 = %v, want 50ms", got)
	}
	if got := percentile(s, 0.90); got != 90*time.Millisecond {
		t.Errorf("p90 = %v, want 90ms", got)
	}
	if got := percentile(s, 0.99); got != 99*time.Millisecond {
		t.Errorf("p99 = %v, want 99ms", got)
	}
	if got := percentile(s, 1.0); got != 100*time.Millisecond {
		t.Errorf("p100 = %v, want 100ms", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("percentile(nil) = %v, want 0", got)
	}
}
