package proxy

import (
	"context"
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
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// stubAssessor is a policy.AssessmentSource returning a fixed assessment.
type stubAssessor struct{ asmt policy.Assessment }

func (s stubAssessor) Assess(context.Context, policy.Artifact) (policy.Assessment, error) {
	return s.asmt, nil
}

// tarballCoordinator extracts the npm coordinate from a "/<name>/-/<name>-<v>.tgz"
// path, mirroring the pkgmgr extractor without importing it.
func tarballCoordinator(req *backends.Request) (backends.Coordinate, bool) {
	name, file, ok := strings.Cut(strings.TrimPrefix(req.Path, "/"), "/-/")
	if !ok {
		return backends.Coordinate{}, false
	}
	v := strings.TrimSuffix(file, ".tgz")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		v = strings.TrimPrefix(v, name[i+1:]+"-")
	} else {
		v = strings.TrimPrefix(v, name+"-")
	}
	return backends.Coordinate{Name: name, Version: v}, true
}

// newPolicyGateway builds a gateway whose "npm" backend extracts coordinates and
// whose policy engine uses the given config + assessment.
func newPolicyGateway(t *testing.T, upstreamURL string, cfg policy.Config, asmt policy.Assessment) *Gateway {
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
	engine := policy.New(cfg, stubAssessor{asmt: asmt}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Policy:     engine,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestPolicyBlocksArtifact(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	cfg := policy.Config{Default: policy.Rule{BlockAtRiskScore: 50}}
	asmt := policy.Assessment{Found: true, HasVerdict: true, RiskScore: 80, CommitSHA: "deadbeefcafe0001"}
	g := newPolicyGateway(t, srv.URL, cfg, asmt)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil/-/evil-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream was contacted %d times; blocked artifact must not be fetched", got)
	}
	if rr.Header().Get("X-Policy-Decision") != "block" {
		t.Errorf("missing X-Policy-Decision=block header")
	}
	if rr.Header().Get("X-Policy-Code") != "risk-score" {
		t.Errorf("X-Policy-Code = %q, want risk-score", rr.Header().Get("X-Policy-Code"))
	}

	var body policyError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v (raw %q)", err, rr.Body.String())
	}
	if body.Code != "risk-score" || body.RiskScore != 80 || body.Package != "evil" {
		t.Errorf("unexpected error body: %+v", body)
	}
	if body.Reason == "" {
		t.Error("error body has empty (non-actionable) reason")
	}
}

func TestPolicyAllowsCleanArtifact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	cfg := policy.Config{Default: policy.Rule{BlockAtRiskScore: 50}}
	asmt := policy.Assessment{Found: true, HasVerdict: true, RiskScore: 5}
	g := newPolicyGateway(t, srv.URL, cfg, asmt)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good/-/good-1.0.0.tgz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ARTIFACT" {
		t.Errorf("body = %q, want ARTIFACT", rr.Body.String())
	}
}

func TestPolicyWarnServesWithHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	cfg := policy.Config{Default: policy.Rule{WarnAtRiskScore: 30, BlockAtRiskScore: 90}}
	asmt := policy.Assessment{Found: true, HasVerdict: true, RiskScore: 50, CommitSHA: "abc123"}
	g := newPolicyGateway(t, srv.URL, cfg, asmt)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/warnpkg/-/warnpkg-1.0.0.tgz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warn serves)", rr.Code)
	}
	if rr.Header().Get("X-Policy-Decision") != "warn" {
		t.Errorf("X-Policy-Decision = %q, want warn", rr.Header().Get("X-Policy-Decision"))
	}
	if rr.Header().Get("X-Policy-Reason") == "" {
		t.Error("warn should carry an X-Policy-Reason header")
	}
}

// TestPolicySkipsIndexDocuments ensures non-artifact requests (no coordinate) are
// not gated, so package metadata still flows even under a strict policy.
func TestPolicySkipsIndexDocuments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"lodash"}`)
	}))
	defer srv.Close()

	// A policy that would block everything if applied.
	cfg := policy.Config{Default: policy.Rule{OnMissingProvenance: policy.ActionBlock}}
	g := newPolicyGateway(t, srv.URL, cfg, policy.Assessment{Found: false})

	rr := httptest.NewRecorder()
	// Packument path has no "/-/" so the coordinator yields no coordinate.
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/lodash", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("index document should not be gated, got status %d (body %q)", rr.Code, rr.Body.String())
	}
}

func TestPolicyDisabledServesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	// newGateway has no Policy configured.
	g := newGateway(t, srv.URL, upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/x/-/x-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("policy-disabled gateway should serve, got %d", rr.Code)
	}
}

func TestHeaderSafe(t *testing.T) {
	in := "line1\r\nInjected: evil\x00\x07 ok"
	out := headerSafe(in)
	if strings.ContainsAny(out, "\r\n\x00\x07") {
		t.Errorf("headerSafe left control chars: %q", out)
	}
}
