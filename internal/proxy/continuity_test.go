package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/continuity"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// continuityStubResolver returns a fixed identity per coordinate name, mutated by
// the test to simulate a maintainer takeover.
type continuityStubResolver struct {
	byName map[string]continuity.Identity
}

func (r *continuityStubResolver) Publishers(_ context.Context, c continuity.Coordinate) (continuity.Identity, bool, error) {
	id, ok := r.byName[c.Name]
	if !ok {
		return continuity.Identity{}, false, nil
	}
	return id, true, nil
}

func newContinuityGateway(t *testing.T, upstreamURL string, svc *continuity.Service) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:        "npm",
		BaseURL:     upstreamURL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		Cacheable:   func(r *backends.Request) bool { return strings.Contains(r.Path, "/-/") },
		Coordinator: tarballCoordinator,
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Continuity: svc,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestContinuityGateBlocksMaintainerDrift(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	res := &continuityStubResolver{byName: map[string]continuity.Identity{
		"event-stream": {Maintainers: []string{"dominictarr"}},
	}}
	svc, err := continuity.New(continuity.Config{
		Resolver:           res,
		Cooldown:           24 * time.Hour,
		DefaultDisposition: continuity.DispositionBlock,
		Now:                func() time.Time { return time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("continuity.New: %v", err)
	}
	g := newContinuityGateway(t, srv.URL, svc)

	// First pull: TOFU establishes the trusted maintainer; artifact is served.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/event-stream/-/event-stream-3.3.5.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("first pull status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Continuity-Decision") != "first-use" {
		t.Errorf("expected first-use header, got %q", rr.Header().Get("X-Continuity-Decision"))
	}

	// A new maintainer takes over: the still-untrusted version is refused before
	// any upstream fetch.
	res.byName["event-stream"] = continuity.Identity{Maintainers: []string{"right9ctrl"}}
	hitsBefore := atomic.LoadInt32(&hits)
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/event-stream/-/event-stream-3.3.6.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("drift pull status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Continuity-Decision") != "block" {
		t.Errorf("missing X-Continuity-Decision=block header")
	}
	if got := atomic.LoadInt32(&hits) - hitsBefore; got != 0 {
		t.Errorf("upstream was contacted %d times for a blocked drift pull; want 0", got)
	}
}
