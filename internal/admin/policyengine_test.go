package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func newPolicyEngine(t *testing.T) *policyengine.Engine {
	t.Helper()
	e, err := policyengine.New(policyengine.Config{IncludeDefaultBundle: true})
	if err != nil {
		t.Fatalf("policyengine.New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestPolicyEngineStatusEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{PolicyEngine: newPolicyEngine(t)})
	var resp policyEngineStatusResponse
	if code := getJSON(t, srv, "/admin/api/policyengine", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.Mode != "enforce" {
		t.Fatalf("unexpected status: %+v", resp)
	}
	if len(resp.Bundles) == 0 {
		t.Error("expected at least the default bundle")
	}
	if resp.Metrics.RulesLoaded == 0 {
		t.Error("expected rules loaded")
	}
}

func TestPolicyEngineStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/policyengine", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when engine absent, got %d", code)
	}
}

func TestPolicyEngineTestEndpointDeny(t *testing.T) {
	srv := newTestServer(t, Options{PolicyEngine: newPolicyEngine(t)})

	// An unresolved critical CVE on an unsigned artifact must be denied by the
	// default bundle.
	in := policyengine.Input{
		Artifact:  policyengine.ArtifactInput{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		Vuln:      &policyengine.VulnInput{Scanned: true, CriticalCount: 1, MaxSeverity: "critical"},
		Signature: &policyengine.SignatureInput{Checked: true},
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/policyengine/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp policyEngineTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Result.Decision.Action != policyengine.ActionDeny {
		t.Fatalf("expected deny, got %s (%q)", resp.Result.Decision.Action, resp.Result.Decision.Reason)
	}
	if resp.Result.EffectiveAction != policyengine.ActionDeny {
		t.Fatalf("enforce mode should block, got %s", resp.Result.EffectiveAction)
	}

	// The test endpoint must not have moved operational metrics.
	if got := srv.opts.PolicyEngine.Snapshot().Evaluations; got != 0 {
		t.Errorf("test endpoint must not record evaluations, got %d", got)
	}
}

func TestPolicyEngineTestEndpointBadBody(t *testing.T) {
	srv := newTestServer(t, Options{PolicyEngine: newPolicyEngine(t)})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/policyengine/test", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestPolicyEngineReloadEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{PolicyEngine: newPolicyEngine(t)})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/policyengine/reload", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp policyEngineReloadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Reloaded {
		t.Error("expected reloaded=true")
	}
}
