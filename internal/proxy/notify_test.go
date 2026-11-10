package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// recordingEmitter captures the events emitted to it.
type recordingEmitter struct {
	mu     sync.Mutex
	events []notify.Event
}

func (e *recordingEmitter) Emit(_ context.Context, ev notify.Event) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
}

func (e *recordingEmitter) snapshot() []notify.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]notify.Event, len(e.events))
	copy(out, e.events)
	return out
}

// newPolicyGatewayWithNotify is newPolicyGateway plus a notify.Emitter.
func newPolicyGatewayWithNotify(t *testing.T, upstreamURL string, cfg policy.Config, asmt policy.Assessment, em notify.Emitter) *Gateway {
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
		Notify:     em,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestPolicyBlockEmitsNotification asserts a risk-score block produces a
// policy_block alert carrying the coordinate, code, and commit detail.
func TestPolicyBlockEmitsNotification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	em := &recordingEmitter{}
	cfg := policy.Config{Default: policy.Rule{BlockAtRiskScore: 50}}
	asmt := policy.Assessment{Found: true, HasVerdict: true, RiskScore: 80, CommitSHA: "deadbeefcafe0001"}
	g := newPolicyGatewayWithNotify(t, srv.URL, cfg, asmt, em)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil/-/evil-1.0.0.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}

	events := em.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 emitted event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != notify.EventPolicyBlock {
		t.Errorf("event type = %q, want policy_block", ev.Type)
	}
	if ev.Ecosystem != "npm" || !strings.Contains(ev.Artifact, "evil") {
		t.Errorf("event coordinate wrong: %+v", ev)
	}
	if ev.Fields["code"] != "risk-score" {
		t.Errorf("code field = %q, want risk-score", ev.Fields["code"])
	}
	if ev.Fields["commitSha"] != "deadbeefcafe0001" {
		t.Errorf("commitSha field = %q", ev.Fields["commitSha"])
	}
}

// TestProvenanceFailureEmitsSpecificEvent asserts a signature-required block is
// surfaced as the dedicated provenance_failure event, not a generic policy block.
func TestProvenanceFailureEmitsSpecificEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	em := &recordingEmitter{}
	cfg := policy.Config{Default: policy.Rule{RequireSignature: true}}
	asmt := policy.Assessment{Found: true, SignatureVerified: false}
	g := newPolicyGatewayWithNotify(t, srv.URL, cfg, asmt, em)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/evil/-/evil-1.0.0.tgz", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}

	events := em.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Type != notify.EventProvenanceFailure {
		t.Errorf("event type = %q, want provenance_failure", events[0].Type)
	}
}

// TestNoNotificationWhenAllowed asserts a clean artifact emits nothing.
func TestNoNotificationWhenAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	em := &recordingEmitter{}
	cfg := policy.Config{Default: policy.Rule{BlockAtRiskScore: 50}}
	asmt := policy.Assessment{Found: true, HasVerdict: true, RiskScore: 5}
	g := newPolicyGatewayWithNotify(t, srv.URL, cfg, asmt, em)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/good/-/good-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := em.snapshot(); len(got) != 0 {
		t.Errorf("expected no emitted events for a clean artifact, got %d", len(got))
	}
}
