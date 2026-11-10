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
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newMalfeedGateway builds a gateway whose "npm" backend extracts coordinates
// and whose known-malicious gate is seeded with the given service.
func newMalfeedGateway(t *testing.T, upstreamURL string, svc *malfeed.Service) *Gateway {
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
		Malfeed:    svc,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestMalfeedBlocksKnownMaliciousPull(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{
			ID:          "MAL-2024-9999",
			Ecosystem:   "npm",
			Name:        "evil-stealer",
			AllVersions: true,
			Summary:     "credential stealer",
			Categories:  []string{"credential-stealer"},
			Source:      "test",
		}},
		InitialLoaded: true,
	})
	defer svc.Close()

	g := newMalfeedGateway(t, srv.URL, svc)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil-stealer/-/evil-stealer-1.0.0.tgz", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream was contacted %d times; a known-malicious pull must not be fetched", got)
	}
	if rr.Header().Get("X-Malfeed-Decision") != "block" {
		t.Errorf("missing X-Malfeed-Decision=block header")
	}
	if rr.Header().Get("X-Malfeed-Advisory") != "MAL-2024-9999" {
		t.Errorf("advisory header = %q, want MAL-2024-9999", rr.Header().Get("X-Malfeed-Advisory"))
	}

	var body malfeedError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v (raw %q)", err, rr.Body.String())
	}
	if body.Code != "malicious" || body.Advisory != "MAL-2024-9999" {
		t.Errorf("unexpected error body: %+v", body)
	}
	if body.Package != "evil-stealer" {
		t.Errorf("package = %q, want evil-stealer", body.Package)
	}
}

func TestMalfeedAllowsCleanPull(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{
			ID: "MAL-2024-9999", Ecosystem: "npm", Name: "evil-stealer", AllVersions: true, Source: "test",
		}},
		InitialLoaded: true,
	})
	defer svc.Close()

	g := newMalfeedGateway(t, srv.URL, svc)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream contacted %d times; a clean pull must be served", got)
	}
}

func TestMalfeedDisabledServesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	// No Malfeed dependency wired: even a name that would match is served.
	g := newMalfeedGateway(t, srv.URL, nil)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil-stealer/-/evil-stealer-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when the gate is disabled", rr.Code)
	}
}
