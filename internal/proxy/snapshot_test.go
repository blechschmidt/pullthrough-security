package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func newSnapshotGateway(t *testing.T, upstreamURL string, svc *snapshot.Service) *Gateway {
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
		Snapshot:   svc,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestSnapshotFreezeGate verifies the end-to-end pull-path behaviour: with the
// org frozen to a snapshot, a coordinate outside the frozen set is refused before
// any upstream fetch, while a coordinate in the set is served.
func TestSnapshotFreezeGate(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc, err := snapshot.New(snapshot.Config{Enabled: true, FreezeEnforceGate: true}, nil, nil)
	if err != nil {
		t.Fatalf("snapshot.New: %v", err)
	}
	// Capture a snapshot whose frozen set contains only left-pad@1.3.0.
	svc.Record(snapshot.Entry{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Digest: "sha256:abc"})
	m, err := svc.Take(snapshot.TakeOptions{Name: "baseline"})
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if _, err := svc.Freeze(snapshot.FreezeOptions{SnapshotID: m.ID, Mode: snapshot.FreezeModeBlock}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	g := newSnapshotGateway(t, srv.URL, svc)

	// An out-of-set version is refused before any upstream fetch.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-2.0.0.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("out-of-set status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Snapshot-Freeze") != "block" {
		t.Errorf("missing X-Snapshot-Freeze=block header")
	}
	if rr.Header().Get("X-Snapshot-Freeze-Code") != snapshot.CodeNotInSet {
		t.Errorf("code header = %q, want %q", rr.Header().Get("X-Snapshot-Freeze-Code"), snapshot.CodeNotInSet)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream contacted %d times; a frozen-out pull must not be fetched", got)
	}

	// The in-set version passes through to the upstream.
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("in-set version status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (the in-set pull)", got)
	}
}

// TestSnapshotGateDisabledByDefault verifies an unfrozen snapshot service never
// blocks a pull.
func TestSnapshotGateNoFreeze(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc, err := snapshot.New(snapshot.Config{Enabled: true, FreezeEnforceGate: true}, nil, nil)
	if err != nil {
		t.Fatalf("snapshot.New: %v", err)
	}
	g := newSnapshotGateway(t, srv.URL, svc)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-2.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no active freeze (body %q)", rr.Code, rr.Body.String())
	}
	// The served pull was recorded into the live state.
	if svc.LiveCount() != 1 {
		t.Errorf("LiveCount = %d, want 1 (the served pull should be recorded)", svc.LiveCount())
	}
}
