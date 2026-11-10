package remediation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// fakeLister returns a scripted version list.
type fakeLister struct {
	versions []string
	err      error
}

func (f fakeLister) Versions(_ context.Context, _, _ string) ([]string, error) {
	return f.versions, f.err
}

// fakeEvaluator returns scripted findings per version.
type fakeEvaluator struct {
	byVersion map[string][]Finding
	err       map[string]error
}

func (f fakeEvaluator) Evaluate(_ context.Context, _ string, c Coordinate) (CandidateResult, error) {
	if f.err != nil {
		if e, ok := f.err[c.Version]; ok {
			return CandidateResult{Coordinate: c}, e
		}
	}
	return CandidateResult{Coordinate: c, Findings: f.byVersion[c.Version]}, nil
}

func vuln(id, sev string, blocking bool) Finding {
	return Finding{Gate: GateVuln, ID: id, Severity: sev, Blocking: blocking, Title: id}
}

func newTestAdvisor(versions []string, eval map[string][]Finding) *Advisor {
	return NewAdvisor(
		fakeLister{versions: versions},
		fakeEvaluator{byVersion: eval},
		WithClock(func() time.Time { return time.Unix(0, 0).UTC() }),
	)
}

func mustAdvise(t *testing.T, a *Advisor, req Request) *Advice {
	t.Helper()
	adv, err := a.Advise(context.Background(), req)
	if err != nil {
		t.Fatalf("Advise: %v", err)
	}
	return adv
}

// Case 1: a safe upgrade exists. The flagged version is blocked by a CVE; a
// newer version clears it with no residual or introduced finding.
func TestAdvise_SafeUpgradeFound(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
		map[string][]Finding{
			"1.0.0": {vuln("CVE-2024-0001", "high", true)},
			"1.0.1": {vuln("CVE-2024-0001", "high", true)}, // still vulnerable
			"1.1.0": {},                                    // clean → nearest safe
			"2.0.0": {},
		},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"})

	if adv.Status != StatusSafeUpgrade {
		t.Fatalf("status = %q, want %q", adv.Status, StatusSafeUpgrade)
	}
	if adv.Recommendation == nil {
		t.Fatal("expected a recommendation")
	}
	if got := adv.Recommendation.Version; got != "1.1.0" {
		t.Fatalf("recommended version = %q, want 1.1.0 (nearest safe)", got)
	}
	if len(adv.Recommendation.ResolvedFindings) != 1 || adv.Recommendation.ResolvedFindings[0].ID != "CVE-2024-0001" {
		t.Fatalf("resolved = %+v, want [CVE-2024-0001]", adv.Recommendation.ResolvedFindings)
	}
	if len(adv.Recommendation.ResidualFindings) != 0 {
		t.Fatalf("residual = %+v, want none", adv.Recommendation.ResidualFindings)
	}
	if len(adv.Recommendation.IntroducedFindings) != 0 {
		t.Fatalf("introduced = %+v, want none", adv.Recommendation.IntroducedFindings)
	}
	if !adv.Recommendation.Clean {
		t.Fatal("expected recommendation marked clean")
	}
	// The advisor must have stopped at the nearest safe version, not evaluated 2.0.0.
	if adv.VersionsConsidered != 2 {
		t.Fatalf("versionsConsidered = %d, want 2 (1.0.1, 1.1.0)", adv.VersionsConsidered)
	}
	if len(adv.FailingGates) != 1 || adv.FailingGates[0] != GateVuln {
		t.Fatalf("failingGates = %v, want [vulnscan]", adv.FailingGates)
	}
}

// Case 2: no safe version exists. Every newer version remains blocked.
func TestAdvise_NoSafeVersion(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "1.0.1", "1.1.0"},
		map[string][]Finding{
			"1.0.0": {vuln("CVE-2024-0001", "critical", true)},
			"1.0.1": {vuln("CVE-2024-0001", "critical", true)},
			"1.1.0": {vuln("CVE-2024-0002", "high", true)}, // different CVE, still blocked
		},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "pip", Name: "requests", Version: "1.0.0"})

	if adv.Status != StatusNoSafeVersion {
		t.Fatalf("status = %q, want %q", adv.Status, StatusNoSafeVersion)
	}
	if adv.Recommendation != nil {
		t.Fatalf("expected no recommendation, got %+v", adv.Recommendation)
	}
	if adv.VersionsConsidered != 2 {
		t.Fatalf("versionsConsidered = %d, want 2", adv.VersionsConsidered)
	}
	// Every candidate must be recorded in the ladder, each marked unsafe.
	if len(adv.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(adv.Candidates))
	}
	for _, c := range adv.Candidates {
		if c.Safe {
			t.Fatalf("candidate %s marked safe, want unsafe", c.Version)
		}
	}
}

// Case 3: the upgrade that clears the blocking CVE introduces a NEW non-blocking
// finding. It is still recommended (it clears the failing gate) but the
// introduced finding is surfaced.
func TestAdvise_UpgradeIntroducesNewFinding(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "1.2.0"},
		map[string][]Finding{
			"1.0.0": {vuln("CVE-2024-0001", "high", true)},
			// clears the blocking CVE but brings a new low-severity, non-blocking one
			"1.2.0": {vuln("CVE-2024-9999", "low", false)},
		},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "cargo", Name: "widget", Version: "1.0.0"})

	if adv.Status != StatusSafeUpgrade {
		t.Fatalf("status = %q, want %q", adv.Status, StatusSafeUpgrade)
	}
	rec := adv.Recommendation
	if rec == nil || rec.Version != "1.2.0" {
		t.Fatalf("recommendation = %+v, want version 1.2.0", rec)
	}
	if len(rec.ResolvedFindings) != 1 || rec.ResolvedFindings[0].ID != "CVE-2024-0001" {
		t.Fatalf("resolved = %+v, want [CVE-2024-0001]", rec.ResolvedFindings)
	}
	if len(rec.IntroducedFindings) != 1 || rec.IntroducedFindings[0].ID != "CVE-2024-9999" {
		t.Fatalf("introduced = %+v, want [CVE-2024-9999]", rec.IntroducedFindings)
	}
	if rec.Clean {
		t.Fatal("recommendation must not be marked clean (it introduced a finding)")
	}
	if len(rec.ResidualFindings) != 0 {
		t.Fatalf("residual = %+v, want none", rec.ResidualFindings)
	}
}

// A residual finding that persists across the upgrade must be reported as such.
func TestAdvise_ResidualFinding(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "1.1.0"},
		map[string][]Finding{
			"1.0.0": {vuln("CVE-A", "high", true), vuln("CVE-B", "low", false)},
			// clears the blocking CVE-A but the non-blocking CVE-B persists
			"1.1.0": {vuln("CVE-B", "low", false)},
		},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if adv.Status != StatusSafeUpgrade {
		t.Fatalf("status = %q, want safe-upgrade", adv.Status)
	}
	rec := adv.Recommendation
	if len(rec.ResolvedFindings) != 1 || rec.ResolvedFindings[0].ID != "CVE-A" {
		t.Fatalf("resolved = %+v, want [CVE-A]", rec.ResolvedFindings)
	}
	if len(rec.ResidualFindings) != 1 || rec.ResidualFindings[0].ID != "CVE-B" {
		t.Fatalf("residual = %+v, want [CVE-B]", rec.ResidualFindings)
	}
}

// When the flagged version has no blocking finding there is nothing to do.
func TestAdvise_AlreadySafe(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "2.0.0"},
		map[string][]Finding{"1.0.0": {vuln("CVE-X", "low", false)}},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if adv.Status != StatusAlreadySafe {
		t.Fatalf("status = %q, want already-safe", adv.Status)
	}
	if adv.Recommendation != nil {
		t.Fatal("already-safe must not recommend an upgrade")
	}
	if adv.VersionsConsidered != 0 {
		t.Fatalf("versionsConsidered = %d, want 0 (no ladder walked)", adv.VersionsConsidered)
	}
}

// When the registry exposes no newer version, the advisor reports no-candidates.
func TestAdvise_NoCandidates(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "0.9.0"}, // nothing newer than 1.0.0
		map[string][]Finding{"1.0.0": {vuln("CVE-X", "critical", true)}},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if adv.Status != StatusNoCandidates {
		t.Fatalf("status = %q, want no-candidates", adv.Status)
	}
	if adv.Recommendation != nil {
		t.Fatal("no-candidates must not recommend an upgrade")
	}
}

// The gate restriction lets a caller ignore an unrelated pre-existing finding
// when choosing a safe upgrade.
func TestAdvise_GateRestriction(t *testing.T) {
	// 1.1.0 clears the vuln but carries a (blocking) license finding. Restricting
	// consideration to the vuln gate should still recommend 1.1.0.
	eval := map[string][]Finding{
		"1.0.0": {vuln("CVE-1", "high", true)},
		"1.1.0": {{Gate: GateLicense, ID: "GPL-3.0-only", Blocking: true}},
	}
	a := newTestAdvisor([]string{"1.0.0", "1.1.0"}, eval)

	// Without restriction: 1.1.0 is not safe (license blocks) → no safe version.
	unrestricted := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if unrestricted.Status != StatusNoSafeVersion {
		t.Fatalf("unrestricted status = %q, want no-safe-version", unrestricted.Status)
	}
	// Restricted to the vuln gate: 1.1.0 clears the vuln → safe upgrade.
	restricted := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "x", Version: "1.0.0", Gates: []GateKind{GateVuln}})
	if restricted.Status != StatusSafeUpgrade {
		t.Fatalf("restricted status = %q, want safe-upgrade", restricted.Status)
	}
	if restricted.Recommendation.Version != "1.1.0" {
		t.Fatalf("restricted recommendation = %q, want 1.1.0", restricted.Recommendation.Version)
	}
}

// A transient per-candidate evaluation error must not abort the advisory; the
// advisor records the candidate as unsafe and keeps walking.
func TestAdvise_CandidateEvalErrorDoesNotAbort(t *testing.T) {
	a := NewAdvisor(
		fakeLister{versions: []string{"1.0.0", "1.1.0", "1.2.0"}},
		fakeEvaluator{
			byVersion: map[string][]Finding{
				"1.0.0": {vuln("CVE-1", "high", true)},
				"1.2.0": {}, // clean
			},
			err: map[string]error{"1.1.0": errors.New("upstream 500")},
		},
		WithClock(func() time.Time { return time.Unix(0, 0).UTC() }),
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if adv.Status != StatusSafeUpgrade {
		t.Fatalf("status = %q, want safe-upgrade", adv.Status)
	}
	if adv.Recommendation.Version != "1.2.0" {
		t.Fatalf("recommendation = %q, want 1.2.0 (skipped the erroring 1.1.0)", adv.Recommendation.Version)
	}
}

// A failure to evaluate the flagged (baseline) version is fatal — we cannot
// compute a delta against an unknown baseline.
func TestAdvise_BaselineErrorIsFatal(t *testing.T) {
	a := NewAdvisor(
		fakeLister{versions: []string{"1.0.0"}},
		fakeEvaluator{err: map[string]error{"1.0.0": errors.New("boom")}},
	)
	if _, err := a.Advise(context.Background(), Request{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); err == nil {
		t.Fatal("expected a fatal error when the baseline version cannot be evaluated")
	}
}

func TestAdvise_Validation(t *testing.T) {
	a := newTestAdvisor(nil, nil)
	cases := []Request{
		{Ecosystem: "", Name: "x", Version: "1"},
		{Ecosystem: "npm", Name: "", Version: "1"},
		{Ecosystem: "npm", Name: "x", Version: ""},
	}
	for _, req := range cases {
		if _, err := a.Advise(context.Background(), req); err == nil {
			t.Fatalf("expected validation error for %+v", req)
		}
	}
	// A nil advisor / unconfigured collaborators must error, not panic.
	var nilAdv *Advisor
	if _, err := nilAdv.Advise(context.Background(), Request{Ecosystem: "npm", Name: "x", Version: "1"}); err == nil {
		t.Fatal("expected error from nil advisor")
	}
}

// AnnotateDocument must attach a SARIF fix to exactly the findings the upgrade
// resolves, leaving residual findings untouched, so the SARIF export (Task 42)
// surfaces the suggested upgrade.
func TestAnnotateDocument(t *testing.T) {
	a := newTestAdvisor(
		[]string{"1.0.0", "1.1.0"},
		map[string][]Finding{
			"1.0.0": {vuln("CVE-RES", "high", true), vuln("CVE-KEEP", "low", false)},
			"1.1.0": {vuln("CVE-KEEP", "low", false)},
		},
	)
	adv := mustAdvise(t, a, Request{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"})

	doc := &findings.Document{
		Artifact: findings.Artifact{Ecosystem: "npm", Name: "lodash", Version: "1.0.0", Coordinate: "npm/lodash@1.0.0"},
		Findings: []findings.Finding{
			{RuleID: findings.RuleVulnerableDependency, Gate: findings.GateVulnscan, Identifier: "CVE-RES"},
			{RuleID: findings.RuleVulnerableDependency, Gate: findings.GateVulnscan, Identifier: "CVE-KEEP"},
		},
	}
	n := adv.AnnotateDocument(doc)
	if n != 1 {
		t.Fatalf("annotated %d findings, want 1 (only the resolved one)", n)
	}
	if doc.Findings[0].Fix == nil {
		t.Fatal("resolved finding CVE-RES must carry a fix")
	}
	if doc.Findings[0].Fix.Version != "1.1.0" {
		t.Fatalf("fix version = %q, want 1.1.0", doc.Findings[0].Fix.Version)
	}
	if doc.Findings[1].Fix != nil {
		t.Fatal("residual finding CVE-KEEP must NOT carry a fix")
	}

	// The fix must render into the SARIF result.
	log := doc.SARIF(findings.SARIFOptions{})
	var withFix int
	for _, res := range log.Runs[0].Results {
		if len(res.Fixes) > 0 {
			withFix++
			if res.Fixes[0].Description == nil || res.Fixes[0].Description.Text == "" {
				t.Fatal("SARIF fix missing description")
			}
		}
	}
	if withFix != 1 {
		t.Fatalf("SARIF results with a fix = %d, want 1", withFix)
	}
}
