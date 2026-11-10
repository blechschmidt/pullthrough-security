package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/extension"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// conformanceModulePath points at the extension package's prebuilt test fixture,
// reused here to drive the proxy gate to each outcome.
func conformanceModulePath() string {
	return filepath.Join("..", "extension", "testdata", "conformance_gate.wasm")
}

func newExtensionGateway(t *testing.T, mgr *extension.Manager) *Gateway {
	t.Helper()
	g, err := New(Dependencies{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  backends.NewRegistry(),
		Extension: mgr,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func extManager(t *testing.T, limits extension.Limits, failClosed bool) *extension.Manager {
	t.Helper()
	mgr, err := extension.NewManager(context.Background(), extension.Config{
		Enabled: true,
		Modules: []extension.ModuleConfig{{
			Name:       "conformance",
			Path:       conformanceModulePath(),
			FailClosed: failClosed,
			Limits:     limits,
		}},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !mgr.Snapshot().Modules[0].Loaded {
		t.Fatalf("module failed to load: %s", mgr.Snapshot().Modules[0].LoadError)
	}
	t.Cleanup(func() { mgr.Close(context.Background()) })
	return mgr
}

func extInput(name string) policyengine.Input {
	return policyengine.Input{Artifact: policyengine.ArtifactInput{
		Ecosystem: "npm", Backend: "npm", Name: name, Version: "1.0.0",
	}}
}

func TestExtensionGateBlocks(t *testing.T) {
	g := newExtensionGateway(t, extManager(t, extension.Limits{Timeout: 2 * time.Second}, false))
	rr := httptest.NewRecorder()
	ok := g.gateExtension(rr, reqWithSignals(extInput("ext-block-evil")), "npm", "npm")
	if ok {
		t.Fatal("expected the gate to block")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if rr.Header().Get("X-Extension-Decision") != "block" {
		t.Errorf("X-Extension-Decision = %q, want block", rr.Header().Get("X-Extension-Decision"))
	}
	if rr.Header().Get("X-Extension-Module") != "conformance" {
		t.Errorf("X-Extension-Module = %q, want conformance", rr.Header().Get("X-Extension-Module"))
	}
}

func TestExtensionGateWarnsButAdmits(t *testing.T) {
	g := newExtensionGateway(t, extManager(t, extension.Limits{Timeout: 2 * time.Second}, false))
	rr := httptest.NewRecorder()
	ok := g.gateExtension(rr, reqWithSignals(extInput("ext-warn-pkg")), "npm", "npm")
	if !ok {
		t.Fatal("warn must admit")
	}
	if rr.Header().Get("X-Extension-Decision") != "warn" {
		t.Errorf("X-Extension-Decision = %q, want warn", rr.Header().Get("X-Extension-Decision"))
	}
}

func TestExtensionGateAllows(t *testing.T) {
	g := newExtensionGateway(t, extManager(t, extension.Limits{Timeout: 2 * time.Second}, false))
	rr := httptest.NewRecorder()
	if !g.gateExtension(rr, reqWithSignals(extInput("ordinary-pkg")), "npm", "npm") {
		t.Fatal("ordinary artifact must be admitted")
	}
	if rr.Header().Get("X-Extension-Decision") != "allow" {
		t.Errorf("X-Extension-Decision = %q, want allow", rr.Header().Get("X-Extension-Decision"))
	}
}

func TestExtensionGateFailClosedTimeoutBlocks(t *testing.T) {
	g := newExtensionGateway(t, extManager(t, extension.Limits{Timeout: 150 * time.Millisecond}, true))
	rr := httptest.NewRecorder()
	if g.gateExtension(rr, reqWithSignals(extInput("ext-timeout-pkg")), "npm", "npm") {
		t.Fatal("fail-closed timeout must block")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestExtensionGateNilManagerAdmits(t *testing.T) {
	g := newExtensionGateway(t, nil)
	rr := httptest.NewRecorder()
	if !g.gateExtension(rr, reqWithSignals(extInput("ext-block-evil")), "npm", "npm") {
		t.Fatal("nil manager must admit")
	}
}

func TestExtensionGateNoSignalsAdmits(t *testing.T) {
	g := newExtensionGateway(t, extManager(t, extension.Limits{Timeout: 2 * time.Second}, false))
	rr := httptest.NewRecorder()
	// A request without the admission accumulator (e.g. accumulator not attached)
	// must be admitted rather than panicking.
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
	if !g.gateExtension(rr, r, "npm", "npm") {
		t.Fatal("missing signals must admit")
	}
}
