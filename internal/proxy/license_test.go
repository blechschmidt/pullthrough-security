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
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// npmTarballWithLicense builds a minimal npm tarball whose package/package.json
// declares the given license expression.
func npmTarballWithLicense(t *testing.T, name, version, licenseExpr string) []byte {
	t.Helper()
	pkg := map[string]any{"name": name, "version": version}
	if licenseExpr != "" {
		pkg["license"] = licenseExpr
	}
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

// newLicenseGateway builds a gateway with an npm backend and a license service.
func newLicenseGateway(t *testing.T, upstreamURL string, svc *license.Service) *Gateway {
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
		License:    svc,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func licenseService(t *testing.T, cfg license.Config) *license.Service {
	t.Helper()
	svc, err := license.NewService(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("license.NewService: %v", err)
	}
	return svc
}

func TestLicenseGateBlocksDeniedLicense(t *testing.T) {
	tgz := npmTarballWithLicense(t, "copyleft", "1.0.0", "GPL-3.0-only")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tgz)
	}))
	defer srv.Close()

	svc := licenseService(t, license.Config{Base: license.PolicyConfig{
		Allow: []string{"MIT", "Apache-2.0"},
		Deny:  []string{"@strong-copyleft"},
	}})
	g := newLicenseGateway(t, srv.URL, svc)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/copyleft/-/copyleft-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-License-Decision") != "block" {
		t.Errorf("X-License-Decision = %q, want block", rr.Header().Get("X-License-Decision"))
	}
	var body licenseError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v (raw %q)", err, rr.Body.String())
	}
	if body.Code != "denied" || len(body.Findings) == 0 || body.Findings[0].License != "GPL-3.0-only" {
		t.Errorf("unexpected error body: %+v", body)
	}
	if m := svc.Metrics(); m.Denied != 1 {
		t.Errorf("denied metric = %d, want 1", m.Denied)
	}
}

func TestLicenseGateAllowsPermissiveLicense(t *testing.T) {
	tgz := npmTarballWithLicense(t, "good", "1.0.0", "MIT")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tgz)
	}))
	defer srv.Close()

	svc := licenseService(t, license.Config{Base: license.PolicyConfig{
		Allow: []string{"MIT", "Apache-2.0"},
		Deny:  []string{"@strong-copyleft"},
	}})
	g := newLicenseGateway(t, srv.URL, svc)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good/-/good-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-License-Decision") != "allow" {
		t.Errorf("X-License-Decision = %q, want allow", rr.Header().Get("X-License-Decision"))
	}
}

func TestLicenseGateFlagsUnknownLicense(t *testing.T) {
	// No license declared -> NOASSERTION -> flagged (warn), still served.
	tgz := npmTarballWithLicense(t, "mystery", "1.0.0", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tgz)
	}))
	defer srv.Close()

	svc := licenseService(t, license.Config{Base: license.PolicyConfig{Allow: []string{"MIT"}}})
	g := newLicenseGateway(t, srv.URL, svc)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/mystery/-/mystery-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warn serves)", rr.Code)
	}
	if got := rr.Header().Get("X-License-Decision"); got != "warn" {
		t.Errorf("X-License-Decision = %q, want warn", got)
	}
	if rr.Header().Get("X-License-Code") != "unknown" {
		t.Errorf("X-License-Code = %q, want unknown", rr.Header().Get("X-License-Code"))
	}
}
