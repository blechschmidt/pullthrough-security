package k8swebhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// stubBuilder is a dossierBuilder returning a canned dossier.
type stubBuilder struct{ d *dossier.Dossier }

func (s stubBuilder) Build(_ context.Context, _ dossier.Query) *dossier.Dossier { return s.d }

func TestBuilderSourceDistillsHeadline(t *testing.T) {
	d := &dossier.Dossier{Headline: dossier.Headline{Verdict: dossier.VerdictBlock, RiskScore: 88, RiskBand: "critical", Summary: "bad"}}
	src := NewBuilderSource(stubBuilder{d: d})
	v, err := src.Verdict(context.Background(), "", ParseImageRef("org/app:1.0"), "docker", true)
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if v.Decision != dossier.VerdictBlock || v.RiskScore != 88 || v.RiskBand != "critical" {
		t.Errorf("unexpected distilled verdict: %+v", v)
	}
}

func TestBuilderSourceWithRealBuilder(t *testing.T) {
	// A Builder with no providers yields an unknown verdict (no recorded signal),
	// which is exactly how an image never pulled through the proxy resolves.
	b := dossier.New(dossier.Config{}, dossier.Providers{})
	src := NewBuilderSource(b)
	v, err := src.Verdict(context.Background(), "", ParseImageRef("ghcr.io/org/never-seen:1.0"), "docker", true)
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if v.hasSignal() {
		t.Errorf("expected an unknown (no-signal) verdict, got %+v", v)
	}
}

func TestHTTPSourceRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/api/dossier" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("coordinate"); got != "org/app" {
			t.Errorf("coordinate = %q, want org/app", got)
		}
		if r.Header.Get("Authorization") != "Bearer t0ken" {
			t.Errorf("missing/incorrect bearer token: %q", r.Header.Get("Authorization"))
		}
		d := dossier.Dossier{Headline: dossier.Headline{Verdict: dossier.VerdictWarn, Summary: "flagged"}}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer srv.Close()

	src, err := NewHTTPSource(HTTPSourceConfig{BaseURL: srv.URL + "/admin", Token: "t0ken"})
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	v, err := src.Verdict(context.Background(), "", ParseImageRef("ghcr.io/org/app:1.0"), "docker", true)
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if v.Decision != dossier.VerdictWarn || v.Summary != "flagged" {
		t.Errorf("unexpected verdict: %+v", v)
	}
}
