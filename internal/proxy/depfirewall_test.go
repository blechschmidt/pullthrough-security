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
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newDepFirewallGateway builds a gateway whose "npm" backend extracts (name,
// version) coordinates from tarball paths and whose dependency firewall uses the
// given service.
func newDepFirewallGateway(t *testing.T, upstreamURL string, svc *depfirewall.Service) *Gateway {
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
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:       cache.NewMemoryCache(),
		Backends:    registry,
		DepFirewall: svc,
		Ecosystems:  map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestDepFirewallBlocksOffPinPull(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	svc, err := depfirewall.NewService(depfirewall.Config{
		Rules: []depfirewall.Rule{{Ecosystem: "npm", Name: "left-pad", Pinned: []string{"1.3.0"}}},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	g := newDepFirewallGateway(t, srv.URL, svc)

	// An off-pin version is refused before any upstream fetch.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.4.0.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("upstream was contacted %d times; a blocked pull must not be fetched", got)
	}
	if rr.Header().Get("X-Depfirewall-Decision") != "block" {
		t.Errorf("missing X-Depfirewall-Decision=block header")
	}
	var body depFirewallError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v (raw %q)", err, rr.Body.String())
	}
	if body.Code != "not-pinned" || body.Version != "1.4.0" {
		t.Errorf("unexpected error body: %+v", body)
	}

	// The pinned version passes through to the upstream.
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("pinned version status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (the approved pull)", got)
	}
}
