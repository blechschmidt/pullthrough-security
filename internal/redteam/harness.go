package redteam

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// discardLogger is a no-op logger shared by every harness gateway: the harness
// asserts on HTTP verdicts, not log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tarballCoordinator extracts the npm coordinate from a "/<name>/-/<name>-<v>.tgz"
// path. It mirrors the pkgmgr extractor (and the proxy test helper of the same
// name) without importing either, so the harness can build a self-contained npm
// backend whose pulls resolve to concrete (name, version) coordinates that the
// admission gates can key on.
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

// upstreamFn is a stub upstream handler.
type upstreamFn func(w http.ResponseWriter, r *http.Request)

// gatewayBuilder bundles everything a scenario needs to construct a gateway
// fronting a single (npm) backend whose upstream is a deterministic stub, then
// to mutate the gateway dependencies to wire exactly the gate under test.
type gatewayBuilder struct {
	// upstream serves the synthetic artifact (a tarball, raw bytes, or an error)
	// on a cache miss. Name-based gates that refuse a pull before any fetch never
	// invoke it.
	upstream upstreamFn
	// configure mutates the proxy.Dependencies after the cache/backends are wired
	// but before the gateway is constructed, attaching the gate(s) under test.
	configure func(deps *proxy.Dependencies)
}

// build constructs an in-process gateway with one "npm" backend pointed at a
// freshly-started stub upstream, wires the gate(s) via configure, and returns a
// setup carrying a cleanup that stops the upstream server.
func (b gatewayBuilder) build() (*scenarioSetup, error) {
	srv := httptest.NewServer(http.HandlerFunc(b.upstream))

	registry := backends.NewRegistry()
	backend, err := httpbackend.New(httpbackend.Options{
		Name:        "npm",
		BaseURL:     srv.URL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "redteam/1"),
		Cacheable:   func(r *backends.Request) bool { return strings.Contains(r.Path, "/-/") },
		Coordinator: tarballCoordinator,
	})
	if err != nil {
		srv.Close()
		return nil, err
	}
	if err := registry.Register(backend); err != nil {
		srv.Close()
		return nil, err
	}

	deps := proxy.Dependencies{
		Logger:     discardLogger(),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Ecosystems: map[string]string{"npm": "npm"},
	}
	if b.configure != nil {
		b.configure(&deps)
	}

	g, err := proxy.New(deps, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		srv.Close()
		return nil, err
	}
	return &scenarioSetup{gateway: g, cleanup: srv.Close}, nil
}

// scenarioSetup is the realized environment for one scenario: a wired gateway,
// the request to issue against it, and a cleanup hook.
type scenarioSetup struct {
	gateway *proxy.Gateway
	request *http.Request
	cleanup func()
}

// npmPull builds the canonical npm tarball GET request for a coordinate.
func npmPull(name, version string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		"/v1/npm/"+name+"/-/"+name+"-"+version+".tgz", nil)
}

// serveRaw is a stub upstream that serves fixed bytes for any request — enough
// for content gates that inspect the artifact body or only need it cached.
func serveRaw(body []byte) upstreamFn {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}
}

// serveTarball serves a gzipped npm tarball.
func serveTarball(tgz []byte) upstreamFn {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tgz)
	}
}

// npmTarball builds a minimal npm package tarball ("package/package.json")
// carrying the supplied manifest fields (scripts, license, ...). It mirrors the
// fixtures the per-gate proxy tests use so the harness exercises the same
// extraction paths.
func npmTarball(manifest map[string]any) []byte {
	body, _ := json.Marshal(manifest)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "package/package.json",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// ----------------------------------------------------------------------------
// Deterministic stubs for the content gates that depend on an external oracle
// (a vuln database, a signature source, a provenance resolver, a rebuilder).
// Each is the smallest implementation that drives the gate to the intended
// verdict; none performs I/O.
// ----------------------------------------------------------------------------

// ensure the harness compiles against the gate interfaces even when a stub is
// referenced only from catalog.go.
var _ = context.Background
