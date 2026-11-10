package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/remediation"
)

// stubRemediation is a minimal RemediationInspector that records the request and
// returns a scripted advice.
type stubRemediation struct {
	enabled bool
	last    remediation.Request
	advice  *remediation.Advice
}

func (s *stubRemediation) Enabled() bool { return s.enabled }

func (s *stubRemediation) Advise(_ context.Context, req remediation.Request) (*remediation.Advice, error) {
	s.last = req
	return s.advice, nil
}

func TestRemediationEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/remediation/advise?ecosystem=npm&name=x&version=1.0.0", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when advisor absent, got %d", code)
	}
	// Present but not enabled → still 404.
	srv = newTestServer(t, Options{Remediation: &stubRemediation{enabled: false}})
	if code := getJSON(t, srv, "/admin/api/remediation/advise?ecosystem=npm&name=x&version=1.0.0", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when advisor disabled, got %d", code)
	}
}

func TestRemediationEndpointRequiresParams(t *testing.T) {
	srv := newTestServer(t, Options{Remediation: &stubRemediation{enabled: true}})
	for _, u := range []string{
		"/admin/api/remediation/advise?name=x&version=1.0.0",        // no ecosystem
		"/admin/api/remediation/advise?ecosystem=npm&name=x",        // no version
		"/admin/api/remediation/advise?ecosystem=npm&version=1.0.0", // no name
	} {
		if code := getJSON(t, srv, u, "", nil); code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d", u, code)
		}
	}
}

func TestRemediationEndpointJSON(t *testing.T) {
	stub := &stubRemediation{
		enabled: true,
		advice: &remediation.Advice{
			Ecosystem: "npm", Name: "lodash", CurrentVersion: "1.0.0", Coordinate: "npm/lodash@1.0.0",
			Status:  remediation.StatusSafeUpgrade,
			Summary: "upgrade to 1.1.0",
			Recommendation: &remediation.Recommendation{
				Version: "1.1.0", FixDescription: "Upgrade npm/lodash from 1.0.0 to 1.1.0.",
			},
		},
	}
	srv := newTestServer(t, Options{Remediation: stub})
	var adv remediation.Advice
	// name@version coordinate form, gate restriction, and prerelease flag.
	u := "/admin/api/remediation/advise?ecosystem=npm&name=lodash@1.0.0&gates=vulnscan,license&prerelease=true"
	if code := getJSON(t, srv, u, "", &adv); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if adv.Status != remediation.StatusSafeUpgrade || adv.Recommendation == nil || adv.Recommendation.Version != "1.1.0" {
		t.Fatalf("advice not threaded through: %+v", adv)
	}
	// The handler must have split name@version and parsed the gate restriction.
	if stub.last.Name != "lodash" || stub.last.Version != "1.0.0" {
		t.Fatalf("name/version parse wrong: %+v", stub.last)
	}
	if len(stub.last.Gates) != 2 || stub.last.Gates[0] != remediation.GateVuln {
		t.Fatalf("gate restriction parse wrong: %+v", stub.last.Gates)
	}
	if !stub.last.IncludePrerelease {
		t.Fatalf("prerelease flag not parsed")
	}
}

func TestRemediationEndpointTable(t *testing.T) {
	stub := &stubRemediation{
		enabled: true,
		advice: &remediation.Advice{
			Ecosystem: "npm", Name: "x", CurrentVersion: "1.0.0", Coordinate: "npm/x@1.0.0",
			Status: remediation.StatusNoSafeVersion, Summary: "no safe version",
		},
	}
	srv := newTestServer(t, Options{Remediation: stub})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/remediation/advise?ecosystem=npm&name=x&version=1.0.0&format=table", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Remediation advice: npm/x@1.0.0") {
		t.Fatalf("unexpected table body: %q", rec.Body.String())
	}
}
