package simreplay

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// fixedClock returns a deterministic clock for reproducible timestamps.
func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func inputFor(tenant, name string) policyengine.Input {
	return policyengine.Input{
		Tenant:   tenant,
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Name: name, Version: "1.0.0"},
	}
}

func verdict(policyAction policyengine.Action, band riskscore.Band, riskAction riskscore.ThresholdAction, matches ...VerdictMatch) Verdict {
	return Verdict{
		PolicyEnabled: true,
		PolicyAction:  policyAction,
		PolicyMatches: matches,
		RiskEnabled:   true,
		RiskBand:      band,
		RiskAction:    riskAction,
	}.finalize()
}

// --- Recorder -------------------------------------------------------------

func TestRecorderSamplingAndOrder(t *testing.T) {
	rec := NewRecorder(Config{Enabled: true, Capacity: 10, SampleRate: 2, Now: fixedClock()})
	for i := 0; i < 6; i++ {
		rec.Observe(inputFor("team", names[i]), Verdict{}.finalize())
	}
	got := rec.Records()
	// 1-in-2 sampling captures observations 0,2,4 -> names[0],[2],[4].
	if len(got) != 3 {
		t.Fatalf("expected 3 sampled records, got %d", len(got))
	}
	wantNames := []string{names[0], names[2], names[4]}
	for i, r := range got {
		if r.Coordinate != wantNames[i]+"@1.0.0" {
			t.Errorf("record %d: coordinate=%q want %q", i, r.Coordinate, wantNames[i]+"@1.0.0")
		}
		if r.Seq != int64(i) {
			t.Errorf("record %d: seq=%d want %d", i, r.Seq, i)
		}
	}
	st := rec.Status()
	if st.Observed != 6 || st.Captured != 3 || st.Buffered != 3 {
		t.Errorf("status = %+v, want observed=6 captured=3 buffered=3", st)
	}
}

var names = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"}

func TestRecorderRingWrapEvictsOldest(t *testing.T) {
	rec := NewRecorder(Config{Enabled: true, Capacity: 3, SampleRate: 1, Now: fixedClock()})
	for i := 0; i < 5; i++ {
		rec.Observe(inputFor("team", names[i]), Verdict{}.finalize())
	}
	got := rec.Records()
	if len(got) != 3 {
		t.Fatalf("expected ring capped at 3, got %d", len(got))
	}
	// The two oldest (a,b) were evicted; c,d,e remain in order.
	want := []string{"c@1.0.0", "d@1.0.0", "e@1.0.0"}
	for i, r := range got {
		if r.Coordinate != want[i] {
			t.Errorf("record %d: coordinate=%q want %q", i, r.Coordinate, want[i])
		}
	}
}

func TestRecorderDisabledAndNilSafe(t *testing.T) {
	var nilRec *Recorder
	nilRec.Observe(inputFor("t", "x"), Verdict{}) // must not panic
	if nilRec.Enabled() {
		t.Error("nil recorder must not be enabled")
	}
	if got := nilRec.Records(); got != nil {
		t.Error("nil recorder Records must be nil")
	}

	off := NewRecorder(Config{Enabled: false})
	off.Observe(inputFor("t", "x"), Verdict{})
	if len(off.Records()) != 0 {
		t.Error("disabled recorder must capture nothing")
	}
}

func TestRecorderReset(t *testing.T) {
	rec := NewRecorder(Config{Enabled: true, Capacity: 5, Now: fixedClock()})
	rec.Observe(inputFor("t", "x"), Verdict{})
	rec.Reset()
	st := rec.Status()
	if st.Observed != 0 || st.Captured != 0 || st.Buffered != 0 {
		t.Errorf("after reset status = %+v, want zeroed", st)
	}
}

// --- Redaction ------------------------------------------------------------

func TestRedactStripsSensitiveButPreservesScoringFields(t *testing.T) {
	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Name: "pkg", Version: "1.0.0"},
		Vuln:     &policyengine.VulnInput{Scanned: true, CriticalCount: 2, MaxSeverity: "critical"},
		Secret: &policyengine.SecretInput{
			Scanned: true, FindingCount: 1, Risk: 7, MaxSeverity: "high",
			Findings: []policyengine.SecretFinding{{RuleID: "aws-key", Severity: "high", File: "/srv/app/secrets.env"}},
		},
		Signature: &policyengine.SignatureInput{Checked: true, Verified: true, Identity: "ci@corp.example", Issuer: "https://oidc.corp"},
		Provenance: &policyengine.ProvenanceInput{
			Found: true, RiskScore: 4, RepositoryURL: "https://github.com/acme/private", CommitSHA: "deadbeef",
		},
	}
	out := Redact(in)

	// Sensitive fields cleared.
	if out.Secret.Findings[0].File != redactionPlaceholder {
		t.Errorf("secret file not redacted: %q", out.Secret.Findings[0].File)
	}
	if out.Signature.Identity != redactionPlaceholder || out.Signature.Issuer != redactionPlaceholder {
		t.Errorf("signature identity/issuer not redacted: %+v", out.Signature)
	}
	if out.Provenance.RepositoryURL != redactionPlaceholder || out.Provenance.CommitSHA != redactionPlaceholder {
		t.Errorf("provenance repo/commit not redacted: %+v", out.Provenance)
	}
	// Scoring-relevant fields preserved.
	if out.Vuln.CriticalCount != 2 || out.Secret.Risk != 7 || out.Secret.Findings[0].RuleID != "aws-key" {
		t.Errorf("scoring fields altered by redaction: %+v", out)
	}
	if !out.Signature.Verified {
		t.Error("signature trust boolean must be preserved")
	}
	// Original is untouched (deep copy).
	if in.Secret.Findings[0].File != "/srv/app/secrets.env" {
		t.Error("Redact mutated its argument")
	}
}

// --- Capture persistence --------------------------------------------------

func TestCaptureSaveLoadRoundTrip(t *testing.T) {
	rec := NewRecorder(Config{Enabled: true, Capacity: 5, SampleRate: 1, Redact: true, Now: fixedClock()})
	rec.Observe(inputFor("teamA", "x"), verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff))
	cap1 := rec.Capture()

	path := filepath.Join(t.TempDir(), "cap.json")
	if err := cap1.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cap2, err := LoadCapture(path)
	if err != nil {
		t.Fatalf("LoadCapture: %v", err)
	}
	if cap2.Version != CaptureVersion || len(cap2.Records) != 1 {
		t.Fatalf("roundtrip mismatch: %+v", cap2)
	}
	if cap2.Records[0].Coordinate != "x@1.0.0" {
		t.Errorf("coordinate lost: %q", cap2.Records[0].Coordinate)
	}
	if !cap2.Sampling.Redacted {
		t.Error("sampling metadata lost")
	}
}

func TestParseCaptureBareArray(t *testing.T) {
	recs := []Record{{Seq: 0, Input: inputFor("t", "x")}}
	raw, _ := json.Marshal(recs)
	c, err := ParseCapture(raw)
	if err != nil {
		t.Fatalf("ParseCapture: %v", err)
	}
	if len(c.Records) != 1 || c.Records[0].Coordinate != "x@1.0.0" {
		t.Errorf("bare array not normalized: %+v", c.Records)
	}
}

func TestParseCaptureRejectsUnknownVersion(t *testing.T) {
	if _, err := ParseCapture([]byte(`{"version":999,"records":[]}`)); err == nil {
		t.Fatal("expected error on unsupported version")
	}
}

// --- Candidate parsing ----------------------------------------------------

func TestParseCandidateYAMLAndJSON(t *testing.T) {
	yamlCfg := `
policyEngine:
  enabled: true
  mode: enforce
riskScore:
  enabled: true
  thresholdBand: high
  thresholdAction: block
`
	cfg, err := ParseCandidate([]byte(yamlCfg))
	if err != nil {
		t.Fatalf("ParseCandidate(yaml): %v", err)
	}
	if cfg.PolicyEngine == nil || !cfg.PolicyEngine.Enabled {
		t.Fatal("policy section not parsed")
	}
	if cfg.RiskScore == nil || cfg.RiskScore.ThresholdAction != "block" {
		t.Fatal("risk section not parsed")
	}

	jsonCfg := `{"riskScore":{"enabled":true,"thresholdBand":"medium","thresholdAction":"warn"}}`
	cfg2, err := ParseCandidate([]byte(jsonCfg))
	if err != nil {
		t.Fatalf("ParseCandidate(json): %v", err)
	}
	if cfg2.RiskScore.ThresholdBand != "medium" {
		t.Errorf("json band = %q", cfg2.RiskScore.ThresholdBand)
	}
}

func TestParseCandidateRejectsUnknownField(t *testing.T) {
	if _, err := ParseCandidate([]byte("policyEngin: {}")); err == nil {
		t.Fatal("expected error on unknown field (typo)")
	}
}

// --- BuildEvaluator -------------------------------------------------------

func TestBuildEvaluatorWithEngines(t *testing.T) {
	enabled := true
	cfg := CandidateConfig{
		PolicyEngine: &PolicyCandidate{Enabled: true, Mode: "enforce", IncludeDefaultBundle: &enabled},
		RiskScore:    &RiskCandidate{Enabled: true, ThresholdBand: "high", ThresholdAction: "block"},
	}
	ev, cleanup, err := BuildEvaluator(cfg)
	if err != nil {
		t.Fatalf("BuildEvaluator: %v", err)
	}
	defer func() { _ = cleanup() }()
	if ev.Policy == nil || ev.Risk == nil {
		t.Fatal("expected both engines built")
	}

	// A critical, unsigned artifact must be denied by the default bundle and score
	// in the critical band.
	in := policyengine.Input{
		Artifact:  policyengine.ArtifactInput{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		Vuln:      &policyengine.VulnInput{Scanned: true, CriticalCount: 1, Total: 1, MaxSeverity: "critical"},
		Signature: &policyengine.SignatureInput{Checked: true},
	}
	v := ev.Evaluate(in)
	if !v.Blocked() {
		t.Errorf("expected blocked verdict, got %+v", v)
	}
	if v.PolicyAction != policyengine.ActionDeny {
		t.Errorf("expected policy deny, got %s", v.PolicyAction)
	}
}

func TestBuildEvaluatorInlineBundle(t *testing.T) {
	bundle := `
rules:
  - id: block-all-npm
    when: 'input.artifact.ecosystem == "npm"'
    action: deny
    message: "no npm allowed"
`
	no := false
	cfg := CandidateConfig{
		PolicyEngine: &PolicyCandidate{Enabled: true, IncludeDefaultBundle: &no, InlineBundle: bundle},
	}
	ev, cleanup, err := BuildEvaluator(cfg)
	if err != nil {
		t.Fatalf("BuildEvaluator(inline): %v", err)
	}
	defer func() { _ = cleanup() }()
	v := ev.Evaluate(inputFor("t", "anything"))
	if v.PolicyAction != policyengine.ActionDeny {
		t.Errorf("inline bundle did not deny: %+v", v)
	}
}

func TestBuildEvaluatorNoGateError(t *testing.T) {
	if _, _, err := BuildEvaluator(CandidateConfig{}); err == nil {
		t.Fatal("expected error when no gate enabled")
	}
}

// --- Simulate / diff ------------------------------------------------------

type stubEval struct {
	fn func(policyengine.Input) Verdict
}

func (s stubEval) Evaluate(in policyengine.Input) Verdict { return s.fn(in) }

func TestRunDiffReport(t *testing.T) {
	records := []Record{
		{Seq: 0, Tenant: "A", Coordinate: "a@1", Input: inputFor("A", "a"),
			Baseline: verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)},
		{Seq: 1, Tenant: "A", Coordinate: "b@1", Input: inputFor("A", "b"),
			Baseline: verdict(policyengine.ActionAllow, riskscore.BandCritical, riskscore.ThresholdBlock)},
		{Seq: 2, Tenant: "B", Coordinate: "c@1", Input: inputFor("B", "c"),
			Baseline: verdict(policyengine.ActionAllow, riskscore.BandMedium, riskscore.ThresholdOff)},
		{Seq: 3, Tenant: "B", Coordinate: "d@1", Input: inputFor("B", "d"),
			Baseline: verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)},
	}

	candidate := stubEval{fn: func(in policyengine.Input) Verdict {
		switch in.Artifact.Name {
		case "a": // newly blocked by a new policy rule
			return verdict(policyengine.ActionDeny, riskscore.BandLow, riskscore.ThresholdOff,
				VerdictMatch{RuleID: "R1", Action: policyengine.ActionDeny})
		case "b": // newly admitted, risk band drops
			return verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)
		case "c": // band rises but still admitted
			return verdict(policyengine.ActionAllow, riskscore.BandHigh, riskscore.ThresholdOff)
		default: // unchanged
			return verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)
		}
	}}

	rep := Run(records, candidate, Options{IncludeRecords: true, OnlyChanged: true, Now: fixedClock()})

	s := rep.Summary
	if s.Total != 4 {
		t.Fatalf("total = %d want 4", s.Total)
	}
	if s.Flips != 2 || s.NowBlocked != 1 || s.NowAdmitted != 1 {
		t.Errorf("flips=%d nowBlocked=%d nowAdmitted=%d want 2/1/1", s.Flips, s.NowBlocked, s.NowAdmitted)
	}
	if s.BandShifts != 2 || s.BandUp != 1 || s.BandDown != 1 {
		t.Errorf("bandShifts=%d up=%d down=%d want 2/1/1", s.BandShifts, s.BandUp, s.BandDown)
	}
	if s.NewViolations != 1 {
		t.Errorf("newViolations=%d want 1", s.NewViolations)
	}
	if s.Changed != 3 || s.Unchanged != 1 {
		t.Errorf("changed=%d unchanged=%d want 3/1", s.Changed, s.Unchanged)
	}
	if s.BaselineBlocked != 1 || s.CandidateBlocked != 1 {
		t.Errorf("baselineBlocked=%d candidateBlocked=%d want 1/1", s.BaselineBlocked, s.CandidateBlocked)
	}

	// Per-tenant blast radius.
	byTenant := map[string]TenantDiff{}
	for _, td := range rep.Tenants {
		byTenant[td.Tenant] = td
	}
	if a := byTenant["A"]; a.Total != 2 || a.Changed != 2 || a.BlastRadius != 1.0 {
		t.Errorf("tenant A = %+v want total2 changed2 blast1.0", a)
	}
	if b := byTenant["B"]; b.Total != 2 || b.Changed != 1 || b.BlastRadius != 0.5 {
		t.Errorf("tenant B = %+v want total2 changed1 blast0.5", b)
	}

	// Only changed records are included (3 of 4).
	if len(rep.Records) != 3 {
		t.Fatalf("expected 3 changed records, got %d", len(rep.Records))
	}
	// The new deny rule must surface on record a.
	var found bool
	for _, d := range rep.Records {
		if d.Coordinate == "a@1" {
			found = true
			if len(d.NewDenyRules) != 1 || d.NewDenyRules[0] != "R1" {
				t.Errorf("record a newDenyRules = %v want [R1]", d.NewDenyRules)
			}
			if d.Flip != FlipNowBlocked {
				t.Errorf("record a flip = %q want now-blocked", d.Flip)
			}
		}
	}
	if !found {
		t.Error("changed record a not present")
	}
}

func TestRunDeterministic(t *testing.T) {
	records := []Record{
		{Seq: 0, Tenant: "A", Input: inputFor("A", "a"), Baseline: verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)},
		{Seq: 1, Tenant: "B", Input: inputFor("B", "b"), Baseline: verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)},
	}
	cand := stubEval{fn: func(in policyengine.Input) Verdict {
		return verdict(policyengine.ActionDeny, riskscore.BandLow, riskscore.ThresholdOff, VerdictMatch{RuleID: "R", Action: policyengine.ActionDeny})
	}}
	r1 := Run(records, cand, Options{IncludeRecords: true, Now: fixedClock()})
	r2 := Run(records, cand, Options{IncludeRecords: true, Now: fixedClock()})
	b1, _ := json.Marshal(r1)
	b2, _ := json.Marshal(r2)
	if string(b1) != string(b2) {
		t.Error("Run is not deterministic for identical inputs")
	}
}

func TestRunBaselineOverride(t *testing.T) {
	records := []Record{
		{Seq: 0, Tenant: "A", Input: inputFor("A", "a"),
			// Stored baseline says admitted, but the override baseline will say blocked.
			Baseline: verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)},
	}
	baseline := stubEval{fn: func(in policyengine.Input) Verdict {
		return verdict(policyengine.ActionDeny, riskscore.BandLow, riskscore.ThresholdOff, VerdictMatch{RuleID: "R", Action: policyengine.ActionDeny})
	}}
	candidate := stubEval{fn: func(in policyengine.Input) Verdict {
		return verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)
	}}
	rep := Run(records, candidate, Options{Baseline: baseline, Now: fixedClock()})
	// With the override baseline (blocked) vs candidate (admit) => now-admitted.
	if rep.Summary.NowAdmitted != 1 {
		t.Errorf("expected baseline override to produce 1 now-admitted, got %+v", rep.Summary)
	}
}

func TestMarkdownContainsSections(t *testing.T) {
	records := []Record{
		{Seq: 0, Tenant: "A", Coordinate: "a@1", Input: inputFor("A", "a"),
			Baseline: verdict(policyengine.ActionAllow, riskscore.BandLow, riskscore.ThresholdOff)},
	}
	cand := stubEval{fn: func(in policyengine.Input) Verdict {
		return verdict(policyengine.ActionDeny, riskscore.BandLow, riskscore.ThresholdOff, VerdictMatch{RuleID: "R1", Action: policyengine.ActionDeny})
	}}
	md := Run(records, cand, Options{IncludeRecords: true, Now: fixedClock()}).Markdown()
	for _, want := range []string{"# Policy & risk what-if simulation", "## Summary", "Per-tenant blast radius", "now-blocked"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n%s", want, md)
		}
	}
}
