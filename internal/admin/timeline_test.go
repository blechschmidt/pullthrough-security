package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
)

// stubAudit is a minimal AuditProvider seeding two records for one coordinate so
// the timeline endpoint has a correlated chain to reconstruct.
type stubAudit struct{ recs []audit.Record }

func (s *stubAudit) Records(ctx context.Context) ([]audit.Record, error) { return s.recs, nil }
func (s *stubAudit) TransparencyEnabled() bool                           { return true }

func newTestTimelineEngine() *timeline.Engine {
	at := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	au := &stubAudit{recs: []audit.Record{
		{Seq: 1, Hash: "h1", Event: audit.Event{Type: audit.EventPull, Time: at, Team: "acme", Subject: "alice", Ecosystem: "npm", Resource: "evil@1.0.0", Decision: audit.DecisionAllow}},
		{Seq: 2, Hash: "h2", Event: audit.Event{Type: audit.EventPolicy, Time: at.Add(time.Minute), Team: "acme", Subject: "alice", Ecosystem: "npm", Resource: "evil@1.0.0", Decision: audit.DecisionDeny, Reason: "policy:block"}},
	}}
	return timeline.New(timeline.Config{AdminPrefix: "/admin"}, timeline.Providers{Audit: au})
}

func TestTimelineEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/timeline?coordinate=evil@1.0.0", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when timeline engine absent, got %d", code)
	}
}

func TestTimelineEndpointRun(t *testing.T) {
	srv := newTestServer(t, Options{Timeline: newTestTimelineEngine()})
	var res timeline.Result
	if code := getJSON(t, srv, "/admin/api/timeline?coordinate=evil@1.0.0", "", &res); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if res.Returned != 2 {
		t.Fatalf("expected 2 correlated events, got %d", res.Returned)
	}
	// Chronological order.
	if res.Events[0].Time.After(res.Events[1].Time) {
		t.Error("events not chronologically ordered")
	}
	// The blocking policy decision carries a Merkle proof link.
	last := res.Events[1]
	if last.Proof == nil || last.Proof.AuditSeq != 2 {
		t.Errorf("expected proof for the policy decision, got %+v", last.Proof)
	}
}

func TestTimelineEndpointMissingSelector(t *testing.T) {
	srv := newTestServer(t, Options{Timeline: newTestTimelineEngine()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/timeline", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unscoped query, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "missing_selector") {
		t.Errorf("expected machine-readable code, got %s", rec.Body.String())
	}
}

func TestTimelineEndpointMarkdown(t *testing.T) {
	srv := newTestServer(t, Options{Timeline: newTestTimelineEngine()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/timeline?coordinate=evil@1.0.0&format=md", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Errorf("expected markdown content type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "# Incident timeline") {
		t.Errorf("missing markdown report header:\n%s", rec.Body.String())
	}
}

func TestTimelineEndpointInvalidParam(t *testing.T) {
	srv := newTestServer(t, Options{Timeline: newTestTimelineEngine()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/timeline?coordinate=evil@1.0.0&since=not-a-time", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a bad since param, got %d", rec.Code)
	}
}
