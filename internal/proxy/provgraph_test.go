package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newProvGraphGateway builds a gateway whose "npm" backend extracts coordinates
// and that ingests served artifacts into the given graph.
func newProvGraphGateway(t *testing.T, upstreamURL string, g *provgraph.Service) *Gateway {
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
	gw, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		ProvGraph:  g,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return gw
}

func TestProvGraphIngestsServedArtifact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	graph := provgraph.New(provgraph.Options{})
	g := newProvGraphGateway(t, srv.URL, graph)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good-pkg/-/good-pkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}

	// The served artifact must now be a version node in the graph.
	snap := graph.Snapshot()
	if snap.NodesByKind[string(provgraph.NodeVersion)] == 0 {
		t.Fatalf("expected at least one version node, got snapshot %+v", snap)
	}
	if snap.EventsIngested == 0 {
		t.Fatal("expected the served pull to be ingested")
	}
	// And it must be queryable by its coordinate.
	res, err := graph.ReverseDependencies("npm", "good-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("ReverseDependencies: %v", err)
	}
	if !res.Found {
		t.Errorf("served artifact good-pkg@1.0.0 not found in graph")
	}
}

func TestProvGraphDisabledIsNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	// newGateway wires no ProvGraph; serving must still succeed.
	g := newGateway(t, srv.URL, upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good-pkg/-/good-pkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("provgraph-disabled gateway should serve, got %d", rr.Code)
	}
}
