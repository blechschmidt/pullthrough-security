package riskscore

import (
	"math"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func newEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	cfg.Enabled = true
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// fixedClock returns a deterministic clock for Record stamping.
func fixedClock() func() time.Time {
	ts := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return ts }
}

func TestScoreCleanArtifactIsLowRisk(t *testing.T) {
	e := newEngine(t, Config{})
	in := policyengine.Input{
		Artifact:   policyengine.ArtifactInput{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		Vuln:       &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"},
		Signature:  &policyengine.SignatureInput{Checked: true, Verified: true, Attested: true},
		License:    &policyengine.LicenseInput{Evaluated: true, Action: "allow", Code: "ok", Allowed: true},
		Nameguard:  &policyengine.NameguardInput{Scanned: true},
		Secret:     &policyengine.SecretInput{Scanned: true},
		Provenance: &policyengine.ProvenanceInput{Found: true, Confidence: "attested"},
	}
	a := e.Score(Subject{Input: in})
	if a.Score != 0 {
		t.Fatalf("clean artifact should score 0, got %d", a.Score)
	}
	if a.Band != BandLow {
		t.Fatalf("clean artifact should be low band, got %s", a.Band)
	}
	if len(a.Contributions) != 6 {
		t.Fatalf("expected 6 contributions, got %d", len(a.Contributions))
	}
}

func TestVulnReachabilitySurfacedInDetail(t *testing.T) {
	e := newEngine(t, Config{})
	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Name: "evil", Version: "1.0.0"},
		Vuln: &policyengine.VulnInput{
			Scanned: true, MaxSeverity: "high", HighCount: 1, Total: 1,
			ReachabilityEnabled: true, ReachableCount: 0, UnreachableCount: 1, ReachSuppressed: 1,
		},
	}
	a := e.Score(Subject{Input: in})
	var vuln *Contribution
	for i := range a.Contributions {
		if a.Contributions[i].Signal == SignalVulnerability {
			vuln = &a.Contributions[i]
			break
		}
	}
	if vuln == nil {
		t.Fatal("vulnerability contribution missing")
	}
	if vuln.Detail["reachabilityEnabled"] != true {
		t.Errorf("reachabilityEnabled not surfaced: %v", vuln.Detail)
	}
	if vuln.Detail["unreachable"] != 1 || vuln.Detail["reachSuppressed"] != 1 {
		t.Errorf("reachability counts not surfaced: %v", vuln.Detail)
	}
}

func TestScoreCriticalVulnDominates(t *testing.T) {
	e := newEngine(t, Config{})
	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Name: "evil", Version: "1.0.0"},
		Vuln:     &policyengine.VulnInput{Scanned: true, MaxSeverity: "critical", CriticalCount: 1, Total: 1},
	}
	a := e.Score(Subject{Input: in})
	// Only one applicable signal at subscore 1.0 → composite must be 100.
	if a.Score != 100 {
		t.Fatalf("single critical vuln should score 100, got %d", a.Score)
	}
	if a.Band != BandCritical {
		t.Fatalf("expected critical band, got %s", a.Band)
	}
}

// TestExplainabilityPointsSumToScore is the core auditability invariant: the
// marginal points of every contribution sum to the composite score, and each
// Points == NormalizedWeight * Subscore * 100.
func TestExplainabilityPointsSumToScore(t *testing.T) {
	e := newEngine(t, Config{})
	in := policyengine.Input{
		Artifact:   policyengine.ArtifactInput{Name: "pkg", Version: "2.0.0"},
		Vuln:       &policyengine.VulnInput{Scanned: true, MaxSeverity: "high", HighCount: 2, Total: 2},
		Signature:  &policyengine.SignatureInput{Checked: true}, // unsigned
		License:    &policyengine.LicenseInput{Evaluated: true, Action: "warn", Code: "review"},
		Provenance: &policyengine.ProvenanceInput{Found: false},
	}
	a := e.Score(Subject{Input: in})

	var sumPoints, sumNorm float64
	for _, c := range a.Contributions {
		sumPoints += c.Points
		sumNorm += c.NormalizedWeight
		want := c.NormalizedWeight * c.Subscore * 100
		if math.Abs(want-c.Points) > 0.05 {
			t.Errorf("signal %s: Points=%.4f but NormalizedWeight*Subscore*100=%.4f", c.Signal, c.Points, want)
		}
	}
	if math.Abs(sumNorm-1.0) > 1e-3 { // per-contribution rounding to 4dp
		t.Errorf("normalized weights should sum to 1, got %.6f", sumNorm)
	}
	if math.Abs(sumPoints-float64(a.Score)) > 0.5 {
		t.Errorf("contribution points (%.3f) should sum to score (%d)", sumPoints, a.Score)
	}
	if a.Summary == "" {
		t.Error("expected a non-empty summary")
	}
}

// TestSkippedSignalsExcludedFromDenominator verifies that an absent gate neither
// inflates nor deflates the score: a single dirty signal scores the same whether
// or not other gates are absent.
func TestSkippedSignalsExcludedFromDenominator(t *testing.T) {
	e := newEngine(t, Config{})
	dirtyOnly := policyengine.Input{
		Vuln: &policyengine.VulnInput{Scanned: true, MaxSeverity: "critical", CriticalCount: 1, Total: 1},
	}
	a := e.Score(Subject{Input: dirtyOnly})
	if a.Score != 100 {
		t.Fatalf("lone critical signal should be 100 regardless of other absent gates, got %d", a.Score)
	}
	if len(a.Skipped) == 0 {
		t.Fatal("expected skipped signals to be reported for explainability")
	}
	foundVuln := false
	for _, s := range a.Skipped {
		if s == SignalVulnerability {
			foundVuln = true
		}
	}
	if foundVuln {
		t.Error("vulnerability was present and must not be listed as skipped")
	}
}

func TestWeightingOverridesChangeScore(t *testing.T) {
	// With the default weights, an unsigned-but-otherwise-clean artifact carries
	// some risk from the signature signal. Zeroing the signature weight (and
	// keeping only vuln) should drop the score to 0 for a clean vuln result.
	base := policyengine.Input{
		Vuln:      &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"},
		Signature: &policyengine.SignatureInput{Checked: true}, // unsigned, risky
	}
	def := newEngine(t, Config{})
	defScore := def.Score(Subject{Input: base}).Score
	if defScore == 0 {
		t.Fatalf("with default weights the unsigned signal should raise the score above 0")
	}

	// Re-weight to ignore signatures entirely.
	custom := newEngine(t, Config{Weights: Weights{Vulnerability: 1.0}})
	customScore := custom.Score(Subject{Input: base}).Score
	if customScore != 0 {
		t.Fatalf("zero signature weight should drop score to 0, got %d", customScore)
	}
}

func TestTenantOverrideThreshold(t *testing.T) {
	cfg := Config{
		Threshold: Threshold{Band: BandCritical, Action: ThresholdOff},
		TenantOverrides: map[string]TenantOverride{
			"strict": {Threshold: &Threshold{Band: BandMedium, Action: ThresholdBlock}},
		},
	}
	e := newEngine(t, cfg)
	in := policyengine.Input{
		Tenant:    "strict",
		Vuln:      &policyengine.VulnInput{Scanned: true, MaxSeverity: "high", HighCount: 1, Total: 1},
		Signature: &policyengine.SignatureInput{Checked: true, Verified: true, Attested: true},
	}
	a := e.Score(Subject{Input: in})
	if !a.Block {
		t.Fatalf("strict tenant should block a medium+ artifact (score=%d band=%s)", a.Score, a.Band)
	}

	// A different tenant inherits the lenient global threshold (off) → never blocks.
	in.Tenant = "default"
	b := e.Score(Subject{Input: in})
	if b.Block || b.Warn {
		t.Fatalf("default tenant should not block/warn under off global threshold, got action=%s", b.Action)
	}
}

func TestTenantWeightOverride(t *testing.T) {
	cfg := Config{
		TenantOverrides: map[string]TenantOverride{
			"vulnonly": {Weights: &Weights{Vulnerability: 1.0}},
		},
	}
	e := newEngine(t, cfg)
	in := policyengine.Input{
		Tenant:    "vulnonly",
		Vuln:      &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"},
		Signature: &policyengine.SignatureInput{Checked: true}, // unsigned
	}
	a := e.Score(Subject{Input: in})
	if a.Score != 0 {
		t.Fatalf("vulnonly tenant ignores signature weight; clean vuln → 0, got %d", a.Score)
	}
}

func TestQuarantineSignalRaisesScore(t *testing.T) {
	e := newEngine(t, Config{})
	in := policyengine.Input{Vuln: &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"}}
	clean := e.Score(Subject{Input: in})
	withQ := e.Score(Subject{Input: in, Quarantine: &QuarantineSignal{Quarantined: true, Advisory: "CVE-2026-1"}})
	if withQ.Score <= clean.Score {
		t.Fatalf("quarantine signal should raise the score (clean=%d withQ=%d)", clean.Score, withQ.Score)
	}
	// The quarantine contribution must be explained.
	found := false
	for _, c := range withQ.Contributions {
		if c.Signal == SignalQuarantine {
			found = true
			if c.Subscore <= 0 {
				t.Error("quarantine subscore should be positive")
			}
		}
	}
	if !found {
		t.Error("expected a quarantine contribution")
	}
}

func TestRecordAndSnapshot(t *testing.T) {
	e := newEngine(t, Config{Now: fixedClock(), HistorySize: 3})
	mk := func(sev string) Subject {
		return Subject{Input: policyengine.Input{
			Vuln: &policyengine.VulnInput{Scanned: true, MaxSeverity: sev, CriticalCount: boolToInt(sev == "critical"), Total: 1},
		}}
	}
	e.ScoreAndRecord(mk("critical"))
	e.ScoreAndRecord(mk("none"))
	e.ScoreAndRecord(mk("high"))
	e.ScoreAndRecord(mk("none"))

	snap := e.Snapshot()
	if snap.TotalScored != 4 {
		t.Fatalf("expected 4 scored, got %d", snap.TotalScored)
	}
	// History is bounded at 3, most-recent-first.
	if len(snap.Recent) != 3 {
		t.Fatalf("expected history bounded to 3, got %d", len(snap.Recent))
	}
	if snap.Recent[0].ScoredAt.IsZero() {
		t.Error("Record should stamp ScoredAt")
	}
	// Band counts present for all bands.
	for _, b := range []string{"low", "medium", "high", "critical"} {
		if _, ok := snap.ByBand[b]; !ok {
			t.Errorf("snapshot missing band %q", b)
		}
	}
	// Two "none" results land in low; a lone critical (100) and a lone high (75,
	// the critical cutoff) both land in critical.
	if snap.ByBand["low"] != 2 {
		t.Errorf("expected 2 low, got %d", snap.ByBand["low"])
	}
	if snap.ByBand["critical"] != 2 {
		t.Errorf("expected 2 critical, got %d", snap.ByBand["critical"])
	}
}

func TestThresholdCrossingCounted(t *testing.T) {
	e := newEngine(t, Config{Threshold: Threshold{Band: BandHigh, Action: ThresholdBlock}})
	e.ScoreAndRecord(Subject{Input: policyengine.Input{
		Vuln: &policyengine.VulnInput{Scanned: true, MaxSeverity: "critical", CriticalCount: 1, Total: 1},
	}})
	e.ScoreAndRecord(Subject{Input: policyengine.Input{
		Vuln: &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"},
	}})
	snap := e.Snapshot()
	if snap.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", snap.Blocked)
	}
	if snap.Crossings != 1 {
		t.Errorf("expected 1 threshold crossing, got %d", snap.Crossings)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
