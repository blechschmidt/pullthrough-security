package proxy

import (
	"encoding/json"
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
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newNameguardGateway builds a gateway whose "npm" backend extracts coordinates
// and whose name guard uses the given config.
func newNameguardGateway(t *testing.T, upstreamURL string, cfg nameguard.Config) *Gateway {
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
		NameGuard:  nameguard.NewService(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))),
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestNameguardBlocksTyposquatPull(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newNameguardGateway(t, srv.URL, nameguard.Config{DetectHomoglyphs: true})

	rr := httptest.NewRecorder()
	// "expres" is one deletion from the popular "express".
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/expres/-/expres-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream was contacted %d times; a blocked typosquat must not be fetched", got)
	}
	if rr.Header().Get("X-Nameguard-Decision") != "block" {
		t.Errorf("missing X-Nameguard-Decision=block header")
	}

	var body nameguardError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v (raw %q)", err, rr.Body.String())
	}
	if body.Code != string(nameguard.KindTyposquat) {
		t.Errorf("error code = %q, want %q", body.Code, nameguard.KindTyposquat)
	}
	if body.DidYouMean != "express" {
		t.Errorf("didYouMean = %q, want express", body.DidYouMean)
	}
	if body.Package != "expres" || body.Reason == "" {
		t.Errorf("unexpected error body: %+v", body)
	}
}

func TestNameguardBlocksDependencyConfusion(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newNameguardGateway(t, srv.URL, nameguard.Config{
		InternalNamespaces: map[string][]string{"npm": {"acme-internal-lib"}},
		DetectHomoglyphs:   true,
	})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/acme-internal-lib/-/acme-internal-lib-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream contacted %d times; dependency-confusion pull must not be fetched", got)
	}
	var body nameguardError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if body.Code != string(nameguard.KindDependencyConfusion) {
		t.Errorf("error code = %q, want %q", body.Code, nameguard.KindDependencyConfusion)
	}
}

func TestNameguardAllowsCleanPull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newNameguardGateway(t, srv.URL, nameguard.Config{DetectHomoglyphs: true})

	rr := httptest.NewRecorder()
	// "express" is the legitimate popular package: it must pass cleanly.
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/express/-/express-4.18.0.tgz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ARTIFACT" {
		t.Errorf("body = %q, want ARTIFACT", rr.Body.String())
	}
	if rr.Header().Get("X-Nameguard-Decision") != "" {
		t.Errorf("clean pull should carry no nameguard decision header")
	}
}

func TestNameguardDisabledServesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	// newGateway wires no NameGuard, so even a blatant typosquat is served.
	g := newGateway(t, srv.URL, upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/expres/-/expres-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("nameguard-disabled gateway should serve, got %d", rr.Code)
	}
}
