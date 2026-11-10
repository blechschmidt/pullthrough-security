package proxy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// TestCaptureSimReplayRecordsVerdict verifies the deferred capture hook projects
// the per-request policy and risk signals into a simreplay Verdict and records it.
func TestCaptureSimReplayRecordsVerdict(t *testing.T) {
	rec := simreplay.NewRecorder(simreplay.Config{Enabled: true, Capacity: 8, SampleRate: 1, Redact: true})
	g, err := New(Dependencies{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  backends.NewRegistry(),
		SimReplay: rec,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Seed an accumulator with an artifact plus a policy deny and a risk band, as
	// the gates would have during a request.
	in := policyengine.Input{
		Tenant:   "teamA",
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
	}
	r := reqWithSignals(in)
	s := signalsFrom(r.Context())
	s.policy = &findings.PolicySignal{
		Action: "deny", Reason: "blocked",
		Matches: []findings.PolicyMatch{{RuleID: "R1", Action: "deny"}},
	}
	s.risk = &findings.RiskSignal{Score: 90, Band: "critical", Action: "block", Exceeds: true}

	g.captureSimReplay(r)

	recs := rec.Records()
	if len(recs) != 1 {
		t.Fatalf("expected 1 captured record, got %d", len(recs))
	}
	got := recs[0]
	if got.Tenant != "teamA" || got.Coordinate != "evil@1.0.0" {
		t.Errorf("unexpected record identity: %+v", got)
	}
	if !got.Baseline.PolicyEnabled || got.Baseline.PolicyAction != policyengine.ActionDeny {
		t.Errorf("policy verdict not captured: %+v", got.Baseline)
	}
	if !got.Baseline.RiskEnabled || got.Baseline.RiskBand != riskscore.BandCritical || got.Baseline.RiskAction != riskscore.ThresholdBlock {
		t.Errorf("risk verdict not captured: %+v", got.Baseline)
	}
	if got.Baseline.Blocked() != true {
		t.Errorf("baseline should be blocked: %+v", got.Baseline)
	}
}

func TestCaptureSimReplaySkipsUnaddressable(t *testing.T) {
	rec := simreplay.NewRecorder(simreplay.Config{Enabled: true, Capacity: 8, SampleRate: 1})
	g, err := New(Dependencies{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  backends.NewRegistry(),
		SimReplay: rec,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No artifact name => unaddressable, must not be captured.
	r := reqWithSignals(policyengine.Input{Tenant: "t"})
	g.captureSimReplay(r)
	if len(rec.Records()) != 0 {
		t.Errorf("unaddressable pull must not be captured")
	}
}
