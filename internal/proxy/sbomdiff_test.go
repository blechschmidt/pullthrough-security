package proxy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// npmTarballWithDeps builds an npm tarball whose package.json declares the given
// dependencies, so the SBOM extractor produces dependency components for the
// drift diff.
func npmTarballWithDeps(name, version string, deps map[string]string) []byte {
	pkg := map[string]any{"name": name, "version": version, "license": "MIT", "dependencies": deps}
	body, _ := json.Marshal(pkg)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func newSbomDiffGateway(t *testing.T, svc *sbomdiff.Service) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:        "npm",
		BaseURL:     handlerURL,
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
		SbomDiff:   svc,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// handlerURL is set per-test before constructing the gateway (the httpbackend
// needs a concrete base URL).
var handlerURL string

func TestSbomDiffGateRecordsAndBlocksOnDrift(t *testing.T) {
	// v1: no dependencies. v2: a fan-out of dependencies in a never-before-seen
	// namespace — high drift.
	v1 := npmTarballWithDeps("demo", "1.0.0", map[string]string{})
	v2 := npmTarballWithDeps("demo", "2.0.0", map[string]string{
		"@evil/a": "1.0.0", "@evil/b": "1.0.0", "@evil/c": "1.0.0",
		"@evil/d": "1.0.0", "@evil/e": "1.0.0",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "1.0.0"):
			_, _ = w.Write(v1)
		default:
			_, _ = w.Write(v2)
		}
	}))
	defer srv.Close()
	handlerURL = srv.URL

	svc := sbomdiff.NewService(sbomdiff.Config{
		Enabled:              true,
		Action:               policy.ActionBlock,
		WarnThreshold:        10,
		BlockThreshold:       20,
		SignificantThreshold: 15,
	}, nil)

	g := newSbomDiffGateway(t, svc)

	// First pull establishes the baseline — must serve cleanly (nothing to diff).
	rr1 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr1, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-1.0.0.tgz", nil))
	if rr1.Code != http.StatusOK {
		t.Fatalf("v1 status = %d, want 200 (body %q)", rr1.Code, rr1.Body.String())
	}

	// Second pull introduces a large new dependency footprint — blocked.
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-2.0.0.tgz", nil))
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("v2 status = %d, want 403 (body %q)", rr2.Code, rr2.Body.String())
	}
	if dec := rr2.Header().Get("X-Sbom-Drift-Decision"); dec != "block" {
		t.Errorf("X-Sbom-Drift-Decision = %q, want block", dec)
	}

	var body sbomDriftError
	if err := json.Unmarshal(rr2.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v (raw %q)", err, rr2.Body.String())
	}
	if body.Code != "drift-block" {
		t.Errorf("code = %q, want drift-block", body.Code)
	}
	if body.AddedDeps != 5 {
		t.Errorf("addedDeps = %d, want 5", body.AddedDeps)
	}
	if body.NewNamespaces != 1 {
		t.Errorf("newNamespaces = %d, want 1 (@evil)", body.NewNamespaces)
	}

	m := svc.Metrics(0)
	if m.Observed != 2 || m.Compared != 1 || m.Blocked != 1 {
		t.Errorf("metrics = %+v, want observed=2 compared=1 blocked=1", m)
	}
}

func TestSbomDiffGateWarnHeadersOnMinorDrift(t *testing.T) {
	v1 := npmTarballWithDeps("calm", "1.0.0", map[string]string{"left-pad": "1.0.0"})
	v2 := npmTarballWithDeps("calm", "1.1.0", map[string]string{"left-pad": "1.0.0", "right-pad": "1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "1.0.0") {
			_, _ = w.Write(v1)
			return
		}
		_, _ = w.Write(v2)
	}))
	defer srv.Close()
	handlerURL = srv.URL

	// Action warn (never blocks); warn at a low threshold so a single added dep
	// annotates the response.
	svc := sbomdiff.NewService(sbomdiff.Config{
		Enabled:        true,
		Action:         policy.ActionWarn,
		WarnThreshold:  2,
		BlockThreshold: 90,
	}, nil)
	g := newSbomDiffGateway(t, svc)

	rr1 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr1, httptest.NewRequest(http.MethodGet, "/v1/npm/calm/-/calm-1.0.0.tgz", nil))
	if rr1.Code != http.StatusOK {
		t.Fatalf("v1 status = %d, want 200", rr1.Code)
	}

	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/npm/calm/-/calm-1.1.0.tgz", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("v2 status = %d, want 200 (warn never blocks); body %q", rr2.Code, rr2.Body.String())
	}
	if score := rr2.Header().Get("X-Sbom-Drift-Score"); score == "" {
		t.Errorf("expected X-Sbom-Drift-Score header on drift, got none")
	}
}
