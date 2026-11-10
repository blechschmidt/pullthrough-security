package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// stubDossier is a minimal DossierInspector that echoes the requested scope back
// into a dossier, so the handler's parsing and rendering can be exercised.
type stubDossier struct{ lastQuery dossier.Query }

func (s *stubDossier) Build(ctx context.Context, q dossier.Query) *dossier.Dossier {
	s.lastQuery = q
	return &dossier.Dossier{
		Tenant:     q.Tenant,
		Ecosystem:  q.Ecosystem,
		Coordinate: q.Coordinate,
		Headline:   dossier.Headline{Verdict: dossier.VerdictBlock, Summary: "blocked", Reasons: []string{"unverified signature"}},
		Sources:    []dossier.SourceStatus{{Source: "findings", Status: dossier.StatusOK}},
	}
}

func (s *stubDossier) Sources() map[string]bool { return map[string]bool{"findings": true} }

func TestDossierEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/dossier?coordinate=evil@1.0.0", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when dossier absent, got %d", code)
	}
}

func TestDossierEndpointRequiresCoordinate(t *testing.T) {
	srv := newTestServer(t, Options{Dossier: &stubDossier{}})
	if code := getJSON(t, srv, "/admin/api/dossier?ecosystem=npm", "", nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 without a coordinate, got %d", code)
	}
}

func TestDossierEndpointJSON(t *testing.T) {
	stub := &stubDossier{}
	srv := newTestServer(t, Options{Dossier: stub})
	var d dossier.Dossier
	if code := getJSON(t, srv, "/admin/api/dossier?ecosystem=npm&coordinate=evil@1.0.0", "", &d); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if d.Coordinate != "evil@1.0.0" || d.Ecosystem != "npm" {
		t.Fatalf("scope not threaded through: %+v", d)
	}
	if d.Headline.Verdict != dossier.VerdictBlock {
		t.Errorf("expected block verdict, got %q", d.Headline.Verdict)
	}
	if stub.lastQuery.Ecosystem != "npm" || stub.lastQuery.Coordinate != "evil@1.0.0" {
		t.Errorf("builder received wrong query: %+v", stub.lastQuery)
	}
}

// TestDossierEndpointRealBuilder exercises the production path: a real
// dossier.Builder wired to a real findings store, through the admin handler.
func TestDossierEndpointRealBuilder(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	store.Record(seedDoc("acme", "lodash", "4.17.21")) // a critical vuln finding
	builder := dossier.New(dossier.Config{}, dossier.Providers{Findings: store})
	srv := newTestServer(t, Options{Dossier: builder})

	var d dossier.Dossier
	if code := getJSON(t, srv, "/admin/api/dossier?ecosystem=npm&coordinate=lodash@4.17.21", "", &d); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if d.Findings == nil || d.Findings.Blocking != 1 {
		t.Fatalf("expected 1 blocking finding, got %+v", d.Findings)
	}
	if d.Headline.Verdict != dossier.VerdictBlock {
		t.Errorf("expected block verdict from a blocking finding, got %q", d.Headline.Verdict)
	}
	// Sources that are not wired must report disabled, not error.
	var risk string
	for _, s := range d.Sources {
		if s.Source == "riskscore" {
			risk = s.Status
		}
	}
	if risk != dossier.StatusDisabled {
		t.Errorf("unwired riskscore should be disabled, got %q", risk)
	}
}

func TestDossierEndpointMarkdown(t *testing.T) {
	srv := newTestServer(t, Options{Dossier: &stubDossier{}})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/dossier?coordinate=evil@1.0.0&format=md", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("expected markdown content-type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "Security dossier") {
		t.Errorf("markdown body missing header: %s", rec.Body.String())
	}
}
