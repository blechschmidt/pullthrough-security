package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newPolicyEngineGateway builds a gateway whose "npm" backend extracts
// coordinates and whose policy-as-code engine evaluates the given engine.
func newPolicyEngineGateway(t *testing.T, upstreamURL string, engine *policyengine.Engine) *Gateway {
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
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:        cache.NewMemoryCache(),
		Backends:     registry,
		PolicyEngine: engine,
		Ecosystems:   map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// engineWithBundle compiles a single inline bundle into an engine in the given
// mode. The artifact.name signal is seeded from the resolved coordinate, so a
// name-based rule fires without any other gate being wired.
func engineWithBundle(t *testing.T, mode policyengine.Mode, yaml string) *policyengine.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := policyengine.New(policyengine.Config{
		Dir:    dir,
		Mode:   mode,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("policyengine.New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

const denyEvilBundle = `
name: test
rules:
  - id: deny-evil
    when: input.artifact.name == "evil-pkg"
    action: deny
    message: blocked by test policy
`

func TestPolicyEngineGateBlocksPull(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newPolicyEngineGateway(t, srv.URL, engineWithBundle(t, policyengine.ModeEnforce, denyEvilBundle))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil-pkg/-/evil-pkg-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-PolicyEngine-Decision") != "deny" {
		t.Errorf("missing X-PolicyEngine-Decision=deny header (got %q)", rr.Header().Get("X-PolicyEngine-Decision"))
	}
	if !strings.Contains(rr.Body.String(), "deny-evil") {
		t.Errorf("expected matched rule id in body, got %q", rr.Body.String())
	}
}

func TestPolicyEngineGateAllowsCleanPull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newPolicyEngineGateway(t, srv.URL, engineWithBundle(t, policyengine.ModeEnforce, denyEvilBundle))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good-pkg/-/good-pkg-1.0.0.tgz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ARTIFACT" {
		t.Errorf("body = %q, want ARTIFACT", rr.Body.String())
	}
}

func TestPolicyEngineAuditModeAdmitsButFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newPolicyEngineGateway(t, srv.URL, engineWithBundle(t, policyengine.ModeAudit, denyEvilBundle))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil-pkg/-/evil-pkg-1.0.0.tgz", nil))

	// Audit (dry-run) mode admits the artifact even though the rule would deny.
	if rr.Code != http.StatusOK {
		t.Fatalf("audit mode should admit, got %d (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-PolicyEngine-Decision") != "audit-deny" {
		t.Errorf("expected X-PolicyEngine-Decision=audit-deny, got %q", rr.Header().Get("X-PolicyEngine-Decision"))
	}
}

func TestPolicyEngineGateDisabledServesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	// newGateway wires no PolicyEngine, so the accumulator is never attached and
	// every artifact is served.
	g := newGateway(t, srv.URL, upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil-pkg/-/evil-pkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("policy-engine-disabled gateway should serve, got %d", rr.Code)
	}
}
