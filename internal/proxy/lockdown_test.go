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
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newLockdownGateway builds a gateway with two npm-ecosystem backends ("npm" and
// "mirror") so a test can prove a targeted block denies a coordinate regardless of
// which backend serves it, and wires the emergency-lockdown control.
func newLockdownGateway(t *testing.T, upstreamURL string, svc *lockdown.Service) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	for _, name := range []string{"npm", "mirror"} {
		b, err := httpbackend.New(httpbackend.Options{
			Name:        name,
			BaseURL:     upstreamURL,
			Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
			Cacheable:   func(r *backends.Request) bool { return strings.Contains(r.Path, "/-/") },
			Coordinator: tarballCoordinator,
		})
		if err != nil {
			t.Fatalf("httpbackend.New(%s): %v", name, err)
		}
		if err := registry.Register(b); err != nil {
			t.Fatalf("Register(%s): %v", name, err)
		}
	}
	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Lockdown:   svc,
		Ecosystems: map[string]string{"npm": "npm", "mirror": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func newLockdownService(t *testing.T) *lockdown.Service {
	t.Helper()
	svc, err := lockdown.New(lockdown.Config{Enabled: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("lockdown.New: %v", err)
	}
	return svc
}

// TestLockdownTargetedBlockDeniesCoordinateEverywhere proves a `block` lockdown
// refuses the targeted coordinate ahead of any upstream fetch — on every backend
// (the deny is org-wide, not backend-scoped) — while leaving other coordinates
// untouched.
func TestLockdownTargetedBlockDeniesCoordinateEverywhere(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc := newLockdownService(t)
	// Whole-package targeted block (no version): any version is denied.
	if _, err := svc.Engage(context.Background(), lockdown.EngageInput{
		Mode:       lockdown.ModeBlock,
		Reason:     "freshly disclosed malware, ahead of feed refresh",
		IncidentID: "INC-42",
		Targets:    []lockdown.Coordinate{{Ecosystem: "npm", Name: "evil-pkg"}},
	}); err != nil {
		t.Fatalf("Engage: %v", err)
	}

	g := newLockdownGateway(t, srv.URL, svc)

	// The targeted coordinate is denied on BOTH backends (everywhere).
	for _, backend := range []string{"npm", "mirror"} {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/"+backend+"/evil-pkg/-/evil-pkg-2.5.0.tgz", nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("[%s] status = %d, want 403 (body %q)", backend, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("X-Lockdown-Decision") != "block" {
			t.Errorf("[%s] missing X-Lockdown-Decision=block header", backend)
		}
		if rr.Header().Get("X-Lockdown-Incident") != "INC-42" {
			t.Errorf("[%s] incident header = %q, want INC-42", backend, rr.Header().Get("X-Lockdown-Incident"))
		}
		var body lockdownError
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("[%s] decoding error body: %v (raw %q)", backend, err, rr.Body.String())
		}
		if body.Code != lockdown.CodeBlocked || body.Mode != string(lockdown.ModeBlock) {
			t.Errorf("[%s] unexpected error body: %+v", backend, body)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream contacted %d times; a lockdown-blocked coordinate must never be fetched", got)
	}

	// A non-targeted coordinate is unaffected and served normally.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("clean pull status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream contacted %d times; the clean pull should fetch exactly once", got)
	}
}

// TestLockdownFreezeServesCacheButBlocksFetch proves a `freeze` lockdown serves an
// already-cached artifact but refuses any new upstream fetch (a cache miss).
func TestLockdownFreezeServesCacheButBlocksFetch(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc := newLockdownService(t)
	g := newLockdownGateway(t, srv.URL, svc)

	// 1) Before any lockdown: fetch left-pad once so it lands in the cache.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("warmup pull status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("warmup contacted upstream %d times, want 1", got)
	}

	// 2) Engage a freeze.
	if _, err := svc.Engage(context.Background(), lockdown.EngageInput{
		Mode:       lockdown.ModeFreeze,
		Reason:     "active incident: investigating a compromised upstream",
		IncidentID: "INC-7",
	}); err != nil {
		t.Fatalf("Engage freeze: %v", err)
	}

	// 3) The already-cached artifact is still served — from cache, without any new
	//    upstream fetch.
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("cached pull under freeze status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body != "ARTIFACT" {
		t.Errorf("cached pull body = %q, want ARTIFACT", body)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("freeze served a cache HIT but contacted upstream %d times; want still 1", got)
	}

	// 4) A NOT-cached artifact requires an upstream fetch, which the freeze forbids.
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/right-pad/-/right-pad-1.0.0.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("uncached pull under freeze status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Lockdown-Decision") != "freeze-block" {
		t.Errorf("missing X-Lockdown-Decision=freeze-block header (got %q)", rr.Header().Get("X-Lockdown-Decision"))
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("freeze blocked the cache MISS but contacted upstream %d times; want still 1", got)
	}

	// 5) Clearing the freeze restores normal fetching.
	if _, err := svc.Clear(context.Background(), lockdown.ClearInput{Reason: "incident resolved"}); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/right-pad/-/right-pad-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("post-clear pull status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("after clearing the freeze the miss should fetch; upstream hits = %d, want 2", got)
	}
}

// TestLockdownDisabledServesEverything confirms a nil lockdown dependency is a
// transparent no-op on the pull path.
func TestLockdownDisabledServesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	g := newLockdownGateway(t, srv.URL, nil)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when the lockdown control is disabled", rr.Code)
	}
}
