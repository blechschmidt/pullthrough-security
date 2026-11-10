package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// seededRecorder returns a recorder pre-loaded with one admitted and one blocked
// pull so the simulate endpoint has traffic to replay.
func seededRecorder(t *testing.T) *simreplay.Recorder {
	t.Helper()
	rec := simreplay.NewRecorder(simreplay.Config{Enabled: true, Capacity: 16, SampleRate: 1, Redact: true})
	// An admitted clean npm package.
	rec.Observe(policyengine.Input{
		Tenant:   "teamA",
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}, simreplay.Verdict{PolicyEnabled: true, PolicyAction: policyengine.ActionAllow, RiskEnabled: true, RiskBand: riskscore.BandLow})
	// A critical, unsigned package that the live config admitted (no threshold).
	rec.Observe(policyengine.Input{
		Tenant:    "teamB",
		Artifact:  policyengine.ArtifactInput{Ecosystem: "npm", Name: "evil", Version: "2.0.0"},
		Vuln:      &policyengine.VulnInput{Scanned: true, CriticalCount: 1, Total: 1, MaxSeverity: "critical"},
		Signature: &policyengine.SignatureInput{Checked: true},
	}, simreplay.Verdict{PolicyEnabled: true, PolicyAction: policyengine.ActionAllow, RiskEnabled: true, RiskBand: riskscore.BandLow})
	return rec
}

func TestSimReplayStatusEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{SimReplay: seededRecorder(t)})
	var st simreplay.Status
	if code := getJSON(t, srv, "/admin/api/simreplay", "", &st); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !st.Enabled || st.Buffered != 2 || st.Captured != 2 {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestSimReplayStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/simreplay", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when recorder absent, got %d", code)
	}
}

func TestSimReplayCaptureExport(t *testing.T) {
	srv := newTestServer(t, Options{SimReplay: seededRecorder(t)})
	var cap simreplay.Capture
	if code := getJSON(t, srv, "/admin/api/simreplay/capture", "", &cap); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if cap.Version != simreplay.CaptureVersion || len(cap.Records) != 2 {
		t.Fatalf("unexpected capture: %+v", cap)
	}
}

func postSimulate(t *testing.T, srv *Server, query, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/simreplay/simulate"+query, bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSimReplaySimulateFlipsToBlock(t *testing.T) {
	srv := newTestServer(t, Options{SimReplay: seededRecorder(t)})

	// Candidate: enforce the default bundle (denies critical+unsigned) and block on
	// high+ risk. The "evil" package should flip admit->block.
	candidate := `{"policyEngine":{"enabled":true,"mode":"enforce"},"riskScore":{"enabled":true,"thresholdBand":"high","thresholdAction":"block"}}`
	rec := postSimulate(t, srv, "?records=1", candidate)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	var rep simreplay.DiffReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Summary.Total != 2 {
		t.Fatalf("expected 2 replayed, got %d", rep.Summary.Total)
	}
	if rep.Summary.NowBlocked < 1 {
		t.Errorf("expected at least 1 newly-blocked pull, got %+v", rep.Summary)
	}
	// teamB owns the evil package; its blast radius must be non-zero.
	var foundB bool
	for _, td := range rep.Tenants {
		if td.Tenant == "teamB" {
			foundB = true
			if td.BlastRadius <= 0 {
				t.Errorf("teamB blast radius = %f, want > 0", td.BlastRadius)
			}
		}
	}
	if !foundB {
		t.Error("teamB missing from per-tenant diff")
	}
}

func TestSimReplaySimulateMarkdown(t *testing.T) {
	srv := newTestServer(t, Options{SimReplay: seededRecorder(t)})
	candidate := `{"policyEngine":{"enabled":true,"mode":"enforce"}}`
	rec := postSimulate(t, srv, "?format=markdown", candidate)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/markdown; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("# Policy & risk what-if simulation")) {
		t.Errorf("markdown body missing header:\n%s", rec.Body.String())
	}
}

func TestSimReplaySimulateBadConfig(t *testing.T) {
	srv := newTestServer(t, Options{SimReplay: seededRecorder(t)})

	// Empty body.
	if rec := postSimulate(t, srv, "", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty body: expected 400, got %d", rec.Code)
	}
	// Unknown field (typo).
	if rec := postSimulate(t, srv, "", "policyEngin: {}"); rec.Code != http.StatusBadRequest {
		t.Errorf("typo: expected 400, got %d", rec.Code)
	}
	// Valid YAML but enables no gate.
	if rec := postSimulate(t, srv, "", "{}"); rec.Code != http.StatusBadRequest {
		t.Errorf("no-gate: expected 400, got %d", rec.Code)
	}
}

func TestSimReplaySimulateDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := postSimulate(t, srv, "", `{"riskScore":{"enabled":true}}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when recorder absent, got %d", rec.Code)
	}
}

func TestSimReplayResetEndpoint(t *testing.T) {
	r := seededRecorder(t)
	srv := newTestServer(t, Options{SimReplay: r})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/simreplay/reset", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset code = %d", rec.Code)
	}
	if r.Status().Buffered != 0 {
		t.Errorf("buffer not cleared after reset: %d", r.Status().Buffered)
	}
}
