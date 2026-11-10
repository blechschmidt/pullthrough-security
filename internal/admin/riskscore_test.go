package admin

import (
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

func newRiskEngine(t *testing.T) *riskscore.Engine {
	t.Helper()
	e, err := riskscore.New(riskscore.Config{
		Enabled:   true,
		Threshold: riskscore.Threshold{Band: riskscore.BandHigh, Action: riskscore.ThresholdBlock},
	})
	if err != nil {
		t.Fatalf("riskscore.New: %v", err)
	}
	return e
}

func TestRiskScoreEndpoint(t *testing.T) {
	e := newRiskEngine(t)
	// Record a critical artifact so the snapshot has content to expose.
	e.ScoreAndRecord(riskscore.Subject{Input: policyengine.Input{
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		Vuln:     &policyengine.VulnInput{Scanned: true, MaxSeverity: "critical", CriticalCount: 1, Total: 1},
	}})

	srv := newTestServer(t, Options{RiskScore: e})
	var resp riskscore.Snapshot
	if code := getJSON(t, srv, "/admin/api/riskscore", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled {
		t.Error("expected enabled snapshot")
	}
	if resp.TotalScored != 1 {
		t.Fatalf("expected 1 scored, got %d", resp.TotalScored)
	}
	if resp.ByBand["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", resp.ByBand["critical"])
	}
	if len(resp.Recent) != 1 {
		t.Fatalf("expected 1 recent assessment, got %d", len(resp.Recent))
	}
	a := resp.Recent[0]
	if a.Score != 100 || a.Band != riskscore.BandCritical {
		t.Errorf("unexpected assessment: score=%d band=%s", a.Score, a.Band)
	}
	if !a.Block {
		t.Error("critical artifact should be blocked under block-above-high threshold")
	}
	// The explainable breakdown must be present for drill-down.
	if len(a.Contributions) == 0 {
		t.Error("expected explainable contributions in the assessment")
	}
}

func TestRiskScoreEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/riskscore", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when engine absent, got %d", code)
	}
}
