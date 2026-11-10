package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/compliance"
)

// fakeCompliance is a minimal ComplianceInspector backed by a fixed posture.
type fakeCompliance struct {
	svc        *compliance.Service
	recomputed int
}

func newFakeCompliance() *fakeCompliance {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	p := compliance.Posture{
		CapturedAt:              now,
		SigEnabled:              true,
		SigVerified:             100,
		ProvenanceEnabled:       true,
		ArtifactsTotal:          100,
		ArtifactsWithProvenance: 100,
		VulnEnabled:             true,
		VulnScans:               100,
		LicenseEnabled:          true,
		LicenseEvaluated:        100,
		LicenseAllowed:          100,
		SecretsEnabled:          true,
		SecretsDiffsScanned:     50,
		AuditEnabled:            true,
		AuditTransparency:       true,
		AuditLastSealUnix:       now.Add(-time.Minute).Unix(),
	}
	svc := compliance.New(compliance.Options{
		Source: compliance.PostureFunc(func() compliance.Posture { return p }),
		Config: compliance.Config{Version: "test", Now: func() time.Time { return now }},
	})
	return &fakeCompliance{svc: svc}
}

func (f *fakeCompliance) Latest() compliance.Scorecard { return f.svc.Latest() }
func (f *fakeCompliance) Recompute() compliance.Scorecard {
	f.recomputed++
	return f.svc.Recompute()
}
func (f *fakeCompliance) Export() (compliance.SignedReport, error) { return f.svc.Export() }
func (f *fakeCompliance) SignerKeyID() string                      { return f.svc.SignerKeyID() }

func TestComplianceJSON(t *testing.T) {
	srv := newTestServer(t, Options{Compliance: newFakeCompliance()})

	var card compliance.Scorecard
	if code := getJSON(t, srv, "/admin/api/compliance", "", &card); code != http.StatusOK {
		t.Fatalf("compliance status = %d", code)
	}
	if card.Status != compliance.StatusPass {
		t.Errorf("status = %q, want pass", card.Status)
	}
	if card.SLSA.BuildLevel != 3 {
		t.Errorf("slsa = %d, want 3", card.SLSA.BuildLevel)
	}
	if len(card.Controls) == 0 {
		t.Error("expected controls in report")
	}
}

func TestComplianceMarkdown(t *testing.T) {
	srv := newTestServer(t, Options{Compliance: newFakeCompliance()})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/compliance?format=markdown", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("content-type = %q, want text/markdown", ct)
	}
	if !strings.Contains(rec.Body.String(), "# Compliance Scorecard") {
		t.Error("markdown body missing heading")
	}
}

func TestComplianceHTML(t *testing.T) {
	srv := newTestServer(t, Options{Compliance: newFakeCompliance()})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/compliance/report.html", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Error("html body missing doctype")
	}
}

func TestComplianceExport(t *testing.T) {
	srv := newTestServer(t, Options{Compliance: newFakeCompliance()})

	var report compliance.SignedReport
	if code := getJSON(t, srv, "/admin/api/compliance/export", "", &report); code != http.StatusOK {
		t.Fatalf("export status = %d", code)
	}
	if report.Digest == "" {
		t.Error("exported report should carry a digest")
	}
	// No signer configured in the fake → unsigned but digested.
	if report.Signed() {
		t.Error("expected unsigned report from keyless service")
	}
}

func TestComplianceRefresh(t *testing.T) {
	fc := newFakeCompliance()
	srv := newTestServer(t, Options{Compliance: fc})

	req := httptest.NewRequest(http.MethodPost, "/admin/api/compliance/refresh", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d", rec.Code)
	}
	if fc.recomputed != 1 {
		t.Errorf("recompute count = %d, want 1", fc.recomputed)
	}
}

func TestComplianceDisabled(t *testing.T) {
	srv := newTestServer(t, Options{}) // no Compliance inspector

	var resp struct {
		Enabled bool `json:"enabled"`
	}
	if code := getJSON(t, srv, "/admin/api/compliance", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if resp.Enabled {
		t.Error("expected enabled:false when no inspector wired")
	}

	// HTML/export endpoints 404 when disabled.
	if code := getJSON(t, srv, "/admin/api/compliance/export", "", nil); code != http.StatusNotFound {
		t.Errorf("export status = %d, want 404", code)
	}
}
