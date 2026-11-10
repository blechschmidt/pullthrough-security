package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

type recordingObserver struct {
	mu     sync.Mutex
	events []PullEvent
}

func (o *recordingObserver) ObservePull(ev PullEvent) {
	o.mu.Lock()
	o.events = append(o.events, ev)
	o.mu.Unlock()
}

func (o *recordingObserver) snapshot() []PullEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]PullEvent(nil), o.events...)
}

func newGatewayWithObserver(t *testing.T, baseURL string, obs PullObserver) *Gateway {
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
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:        cache.NewMemoryCache(),
		Backends:     registry,
		PullObserver: obs,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestPrewarmHandlerCachesAndObserverExcludesPrewarm proves (1) a pre-warm fetch
// fills the cache through the full gated pipeline, (2) the pull observer is NOT
// notified for the synthetic pre-warm request, and (3) a subsequent genuine
// client pull of the same artifact is a cache HIT and IS observed.
func TestPrewarmHandlerCachesAndObserverExcludesPrewarm(t *testing.T) {
	var upstreamHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	obs := &recordingObserver{}
	g := newGatewayWithObserver(t, srv.URL, obs)

	const path = "/v1/npm/pkg-1.0.0.tgz"

	// 1. Pre-warm the artifact through the pre-warm handler.
	rr := httptest.NewRecorder()
	g.PrewarmHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("prewarm fetch status = %d (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Cache") != "MISS" {
		t.Errorf("prewarm X-Cache = %q, want MISS", rr.Header().Get("X-Cache"))
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 1 {
		t.Fatalf("upstream hits after prewarm = %d, want 1", n)
	}
	if evs := obs.snapshot(); len(evs) != 0 {
		t.Fatalf("observer must not see synthetic pre-warm requests, saw %d", len(evs))
	}

	// 2. A genuine client pull of the same path is a HIT (served from the warmed
	// cache, no second upstream fetch) and IS observed.
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, path, nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("client pull status = %d", rr2.Code)
	}
	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("client X-Cache = %q, want HIT (prewarm should have filled the cache)", rr2.Header().Get("X-Cache"))
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 1 {
		t.Errorf("upstream hits after client pull = %d, want still 1 (served from warmed cache)", n)
	}

	evs := obs.snapshot()
	if len(evs) != 1 {
		t.Fatalf("observer should see exactly the one genuine client pull, saw %d", len(evs))
	}
	if evs[0].Backend != "npm" || evs[0].Path != path || !evs[0].CacheHit {
		t.Errorf("unexpected observed event %+v", evs[0])
	}
}
