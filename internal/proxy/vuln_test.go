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
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// stubVulnScanner returns a fixed set of vulnerabilities for any SBOM.
type stubVulnScanner struct{ vulns []vulnscan.Vulnerability }

func (s stubVulnScanner) Name() string { return "stub" }
func (s stubVulnScanner) Scan(context.Context, *vulnscan.SBOM) ([]vulnscan.Vulnerability, error) {
	return s.vulns, nil
}

// newVulnGateway builds a gateway with an npm backend and a vulnerability service
// driven by the supplied scanner + gate config.
func newVulnGateway(t *testing.T, upstreamURL string, cfg vulnscan.Config, scanner vulnscan.Scanner) *Gateway {
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
	svc, err := vulnscan.NewService(cfg, scanner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	g, err := New(Dependencies{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:           cache.NewMemoryCache(),
		Backends:        registry,
		Vulnerabilities: svc,
		Ecosystems:      map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func criticalVuln() vulnscan.Vulnerability {
	return vulnscan.Vulnerability{
		ID: "CVE-2024-9999", Severity: vulnscan.SeverityCritical, CVSS: 9.8,
		Package: "evil", Version: "1.0.0", FixedVersions: []string{"1.0.1"},
	}
}

func TestVulnGateBlocksVulnerableArtifact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	cfg := vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, Action: policy.ActionBlock}
	g := newVulnGateway(t, srv.URL, cfg, stubVulnScanner{vulns: []vulnscan.Vulnerability{criticalVuln()}})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil/-/evil-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Vuln-Decision") != "block" {
		t.Errorf("X-Vuln-Decision = %q, want block", rr.Header().Get("X-Vuln-Decision"))
	}
	if rr.Body.String() == "ARTIFACT" {
		t.Error("vulnerable artifact body was served")
	}
	var body vulnError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v (raw %q)", err, rr.Body.String())
	}
	if body.Advisory != "CVE-2024-9999" || body.MaxSeverity != "critical" || body.Counts.Critical != 1 {
		t.Errorf("unexpected error body: %+v", body)
	}
}

func TestVulnGateQuarantineEvictsCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	cfg := vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, Action: policy.ActionQuarantine}
	g := newVulnGateway(t, srv.URL, cfg, stubVulnScanner{vulns: []vulnscan.Vulnerability{criticalVuln()}})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil/-/evil-1.0.0.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if rr.Header().Get("X-Vuln-Decision") != "quarantine" {
		t.Errorf("X-Vuln-Decision = %q, want quarantine", rr.Header().Get("X-Vuln-Decision"))
	}
	// The poisoned content must have been evicted from the cache.
	entries, _ := g.deps.Cache.(interface {
		Entries(context.Context) ([]cache.Stat, error)
	}).Entries(context.Background())
	if len(entries) != 0 {
		t.Errorf("quarantined artifact left %d cache entries, want 0", len(entries))
	}
}

func TestVulnGateWarnServesWithHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	v := vulnscan.Vulnerability{ID: "X", Severity: vulnscan.SeverityMedium, CVSS: 5.0, Package: "warnpkg", Version: "1.0.0"}
	cfg := vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, WarnSeverity: vulnscan.SeverityMedium, Action: policy.ActionBlock}
	g := newVulnGateway(t, srv.URL, cfg, stubVulnScanner{vulns: []vulnscan.Vulnerability{v}})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/warnpkg/-/warnpkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warn serves)", rr.Code)
	}
	if rr.Header().Get("X-Vuln-Decision") != "warn" {
		t.Errorf("X-Vuln-Decision = %q, want warn", rr.Header().Get("X-Vuln-Decision"))
	}
	if rr.Body.String() != "ARTIFACT" {
		t.Errorf("warn should still serve artifact, got %q", rr.Body.String())
	}
}

func TestVulnGateAllowsCleanArtifact(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	cfg := vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, Action: policy.ActionBlock}
	g := newVulnGateway(t, srv.URL, cfg, stubVulnScanner{vulns: nil})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good/-/good-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "ARTIFACT" {
		t.Errorf("clean artifact body = %q", rr.Body.String())
	}
	if rr.Header().Get("X-Vuln-Decision") != "allow" {
		t.Errorf("X-Vuln-Decision = %q, want allow", rr.Header().Get("X-Vuln-Decision"))
	}
}

// TestVulnGateSkipsIndexDocuments ensures non-artifact requests are not gated.
func TestVulnGateSkipsIndexDocuments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"lodash"}`)
	}))
	defer srv.Close()

	cfg := vulnscan.Config{FailSeverity: vulnscan.SeverityLow, Action: policy.ActionBlock}
	g := newVulnGateway(t, srv.URL, cfg, stubVulnScanner{vulns: []vulnscan.Vulnerability{criticalVuln()}})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/lodash", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("index document should not be gated, got %d (body %q)", rr.Code, rr.Body.String())
	}
}
