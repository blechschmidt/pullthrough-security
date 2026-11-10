package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// newRiskScoreGateway builds a minimal gateway wired only with the risk-scoring
// engine, sufficient to exercise the admission gate directly.
func newRiskScoreGateway(t *testing.T, engine *riskscore.Engine) *Gateway {
	t.Helper()
	g, err := New(Dependencies{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  backends.NewRegistry(),
		RiskScore: engine,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// reqWithSignals returns a request whose context carries an admission
// accumulator seeded with the given input, as the upstream gates would.
func reqWithSignals(in policyengine.Input) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/pkg/-/pkg-1.0.0.tgz", nil)
	sig := &admissionSignals{input: in}
	return r.WithContext(context.WithValue(r.Context(), signalsKey{}, sig))
}

func criticalInput() policyengine.Input {
	return policyengine.Input{
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Backend: "npm", Name: "evil", Version: "1.0.0"},
		Vuln:     &policyengine.VulnInput{Scanned: true, MaxSeverity: "critical", CriticalCount: 1, Total: 1},
	}
}

func TestRiskScoreGateBlocksHighRisk(t *testing.T) {
	engine, err := riskscore.New(riskscore.Config{
		Enabled:   true,
		Threshold: riskscore.Threshold{Band: riskscore.BandHigh, Action: riskscore.ThresholdBlock},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newRiskScoreGateway(t, engine)

	rr := httptest.NewRecorder()
	ok := g.gateRiskScore(rr, reqWithSignals(criticalInput()), "npm", "npm")
	if ok {
		t.Fatal("expected the gate to block a critical artifact")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if rr.Header().Get("X-Risk-Decision") != "block" {
		t.Errorf("missing X-Risk-Decision=block header, got %q", rr.Header().Get("X-Risk-Decision"))
	}
	if rr.Header().Get("X-Risk-Score") != "100" {
		t.Errorf("X-Risk-Score = %q, want 100", rr.Header().Get("X-Risk-Score"))
	}
	if !strings.Contains(rr.Body.String(), "risk-score") {
		t.Errorf("expected risk-score code in body, got %q", rr.Body.String())
	}
	// The block must be recorded for trend/metrics.
	if snap := engine.Snapshot(); snap.Blocked != 1 || snap.TotalScored != 1 {
		t.Errorf("expected 1 blocked / 1 scored, got blocked=%d scored=%d", snap.Blocked, snap.TotalScored)
	}
}

func TestRiskScoreGateWarnsButAdmits(t *testing.T) {
	engine, err := riskscore.New(riskscore.Config{
		Enabled:   true,
		Threshold: riskscore.Threshold{Band: riskscore.BandHigh, Action: riskscore.ThresholdWarn},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newRiskScoreGateway(t, engine)

	rr := httptest.NewRecorder()
	ok := g.gateRiskScore(rr, reqWithSignals(criticalInput()), "npm", "npm")
	if !ok {
		t.Fatal("warn mode must admit the artifact")
	}
	if rr.Header().Get("X-Risk-Decision") != "warn" {
		t.Errorf("expected X-Risk-Decision=warn, got %q", rr.Header().Get("X-Risk-Decision"))
	}
	if snap := engine.Snapshot(); snap.Warned != 1 || snap.Blocked != 0 {
		t.Errorf("expected 1 warned / 0 blocked, got warned=%d blocked=%d", snap.Warned, snap.Blocked)
	}
}

func TestRiskScoreGateObserveOnlyAdmits(t *testing.T) {
	// Default threshold action is off: a critical artifact is scored and recorded
	// but never blocked.
	engine, err := riskscore.New(riskscore.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	g := newRiskScoreGateway(t, engine)

	rr := httptest.NewRecorder()
	ok := g.gateRiskScore(rr, reqWithSignals(criticalInput()), "npm", "npm")
	if !ok {
		t.Fatal("observe-only mode must admit the artifact")
	}
	if rr.Header().Get("X-Risk-Score") != "100" {
		t.Errorf("score header should still be set in observe-only mode, got %q", rr.Header().Get("X-Risk-Score"))
	}
	if dec := rr.Header().Get("X-Risk-Decision"); dec != "" {
		t.Errorf("observe-only mode should not set a decision header, got %q", dec)
	}
	snap := engine.Snapshot()
	if snap.TotalScored != 1 || snap.Blocked != 0 || snap.Warned != 0 || snap.Crossings != 0 {
		t.Errorf("observe-only: expected scored-only, got %+v", snap)
	}
}

func TestRiskScoreGateNilEngineAdmits(t *testing.T) {
	g := newRiskScoreGateway(t, nil)
	rr := httptest.NewRecorder()
	if !g.gateRiskScore(rr, reqWithSignals(criticalInput()), "npm", "npm") {
		t.Fatal("nil engine must admit")
	}
}
