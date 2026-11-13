package dossier

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/remediation"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

var testNow = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

type stubFindings struct{ docs []findings.Document }

func (s *stubFindings) Documents(tenant, q string) []findings.Document {
	out := make([]findings.Document, 0, len(s.docs))
	for _, d := range s.docs {
		if tenant != "" && d.Tenant != tenant {
			continue
		}
		out = append(out, d)
	}
	return out
}

type stubRisk struct{ a []riskscore.Assessment }

func (s *stubRisk) Enabled() bool                           { return true }
func (s *stubRisk) Recent(limit int) []riskscore.Assessment { return s.a }

type stubVuln struct {
	reports     []*vulnscan.Report
	quarantined map[string]bool
}

func (s *stubVuln) Reports() []*vulnscan.Report { return s.reports }
func (s *stubVuln) IsQuarantined(d string) bool { return s.quarantined[d] }

type stubSig struct{ reports []*sigverify.Report }

func (s *stubSig) Reports() []*sigverify.Report { return s.reports }

type stubProvgraph struct {
	path provgraph.PathResult
	dep  provgraph.DepResult
}

func (s *stubProvgraph) PathToCommit(eco, name, version string) (provgraph.PathResult, error) {
	if !strings.EqualFold(name, "evil") {
		return provgraph.PathResult{}, nil
	}
	return s.path, nil
}
func (s *stubProvgraph) ReverseDependencies(eco, name, version string) (provgraph.DepResult, error) {
	if !strings.EqualFold(name, "evil") {
		return provgraph.DepResult{}, nil
	}
	return s.dep, nil
}

type stubRebuild struct{ results []rebuildverify.Result }

func (s *stubRebuild) Enabled() bool                           { return true }
func (s *stubRebuild) Recent(limit int) []rebuildverify.Result { return s.results }

type stubApprovals struct{ reqs []approvals.Request }

func (s *stubApprovals) Enabled() bool { return true }
func (s *stubApprovals) List(status string, limit int) []approvals.Request {
	if status == "" {
		return s.reqs
	}
	out := []approvals.Request{}
	for _, r := range s.reqs {
		if string(r.Status) == status {
			out = append(out, r)
		}
	}
	return out
}

type stubTimeline struct{ res timeline.Result }

func (s *stubTimeline) Query(ctx context.Context, q timeline.Query) (timeline.Result, error) {
	return s.res, nil
}

type stubSbomDrift struct {
	coord string
	diff  *sbomdiff.Diff
}

func (s *stubSbomDrift) Enabled() bool { return true }
func (s *stubSbomDrift) DiffLatest(tenant, eco, coord string) (*sbomdiff.Diff, bool) {
	if s.diff == nil || !strings.EqualFold(coord, s.coord) {
		return nil, false
	}
	return s.diff, true
}

type stubAttest struct{ b *attestbundle.Bundle }

func (s *stubAttest) Get(tenant, pkg string) (*attestbundle.Bundle, bool) {
	if s.b == nil || !strings.EqualFold(pkg, s.b.Coordinate) {
		return nil, false
	}
	return s.b, true
}

func fullProviders() Providers {
	return Providers{
		Findings: &stubFindings{docs: []findings.Document{{
			Tenant: "acme",
			Artifact: findings.Artifact{
				Ecosystem: "npm", Name: "evil", Version: "1.0.0",
				Coordinate: "npm/evil@1.0.0", Digest: "sha256:abc", Backend: "npmjs",
				CommitSHA: "deadbeef", RepositoryURL: "https://github.com/evil/evil",
			},
			Findings: []findings.Finding{
				{RuleID: "PT-SIGVERIFY", Gate: findings.GateSigverify, Severity: findings.SeverityHigh, Level: findings.LevelError, Title: "unverified signature"},
				{RuleID: "PT-LICENSE-DENIED", Gate: findings.GateLicense, Severity: findings.SeverityHigh, Level: findings.LevelError, Title: "denied license", Identifier: "GPL-3.0-only"},
			},
			GeneratedAt: testNow.Add(-time.Hour),
		}}},
		Risk: &stubRisk{a: []riskscore.Assessment{{
			Tenant:   "acme",
			Artifact: riskscore.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Coordinate: "evil@1.0.0"},
			Score:    82, Band: riskscore.BandCritical, Block: true, Warn: true,
			Summary:  "high vuln density",
			ScoredAt: testNow.Add(-30 * time.Minute),
		}}},
		Vuln: &stubVuln{
			reports: []*vulnscan.Report{{
				Digest:   "sha256:abc",
				Artifact: vulnscan.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
				Counts:   vulnscan.SeverityCounts{Critical: 2, High: 1},
				MaxCVSS:  9.8, MaxSeverity: vulnscan.SeverityCritical,
				Vulnerabilities: []vulnscan.Vulnerability{{ID: "CVE-2026-0001"}, {ID: "CVE-2026-0002"}},
				ScannedAt:       testNow.Add(-2 * time.Hour),
			}},
			quarantined: map[string]bool{"sha256:abc": true},
		},
		Sigverify: &stubSig{reports: []*sigverify.Report{{
			Artifact:          sigverify.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:abc"},
			VerifiedSignature: false, Source: "npm",
		}}},
		Provgraph: &stubProvgraph{
			path: provgraph.PathResult{Artifact: "evil@1.0.0", Found: true, CommitSHA: "deadbeef"},
			dep:  provgraph.DepResult{Found: true, Total: 12, Direct: 3},
		},
		Rebuild: &stubRebuild{results: []rebuildverify.Result{{
			Ecosystem: "npm", Name: "evil", Version: "1.0.0", Coordinate: "evil@1.0.0",
			Verdict: rebuildverify.VerdictMismatch, Mismatch: true, Done: true, ComputedAt: testNow.Add(-time.Hour),
		}}},
		SbomDrift: &stubSbomDrift{coord: "evil", diff: &sbomdiff.Diff{
			Ecosystem: "npm", Coordinate: "evil",
			From: sbomdiff.VersionRef{Version: "0.9.0"}, To: sbomdiff.VersionRef{Version: "1.0.0"},
			AddedDeps: []sbomdiff.Dep{{}, {}}, DriftScore: 47.5, Significant: true,
		}},
		Attest: &stubAttest{b: &attestbundle.Bundle{
			Digest: "sha256:bundle", PredicateType: "https://slsa.dev/provenance/v1",
			SubjectDigest: "sha256:abc", KeyID: "key-1", Coordinate: "evil@1.0.0", Tenant: "acme",
		}},
		Approvals: &stubApprovals{reqs: []approvals.Request{{
			ID: "AP-1", Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0", Gate: "vulnscan",
			Status: approvals.StatusApproved, GrantedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(time.Hour),
		}}},
		Timeline: &stubTimeline{res: timeline.Result{
			Total: 1, Returned: 1,
			Events: []timeline.Event{{
				Time: testNow.Add(-time.Hour), Source: timeline.SourceAudit, Category: timeline.CategoryVerdict,
				Decision: "block", Coordinate: "evil@1.0.0", Summary: "blocked at admission",
				Proof: &timeline.ProofRef{AuditSeq: 7},
			}},
		}},
		Remediation: &stubRemediation{advice: &remediation.Advice{
			Status:             remediation.StatusSafeUpgrade,
			VersionsConsidered: 2,
			Recommendation: &remediation.Recommendation{
				Version:          "1.1.0",
				FixDescription:   "Upgrade npm/evil from 1.0.0 to 1.1.0 to resolve CVE-2026-0001.",
				ResolvedFindings: []remediation.Finding{{Gate: remediation.GateVuln, ID: "CVE-2026-0001"}},
			},
		}},
		Suppressions:   fullSuppressionLedger(),
		LLMPackageScan: fullLLMScan(),
		Releases: stubReleases{refs: []ReleaseRef{
			{Repo: "widgets", Commit: "c0ffee0000000000000000000000000000000000", State: "current", Tags: []string{"v2.0"}, Version: "1.0.0", Status: "pinned", FullyPinned: true},
			{Repo: "widgets", Commit: "decaf00000000000000000000000000000000000", State: "historical", FormerTags: []string{"v1.0"}, Version: "1.0.0", Status: "refused"},
		}},
		RepositoryScans: stubRepoScans{refs: []RepoScanRef{
			{Repo: "widgets", Commit: "c0ffee0000000000000000000000000000000000", Kind: "release", Tags: []string{"v2.0"},
				Version: "1.0.0", Verdict: "malicious", Model: "model-x", Confidence: 0.97, ScannedAt: testNow,
				Digest: "sha256:abc", Files: []string{"package-lock.json:12"}, Pinned: true},
			{Repo: "widgets", Commit: "beef000000000000000000000000000000000000", Kind: "head", Ref: "main", Current: true,
				Version: "1.0.0", Verdict: "unscanned", UnscannedCode: "budget-exhausted", Files: []string{"package-lock.json:12"}},
		}},
	}
}

type stubRepoScans struct{ refs []RepoScanRef }

func (s stubRepoScans) RepositoryScansOf(_ context.Context, tenant, ecosystem, name, version string) ([]RepoScanRef, error) {
	if tenant != "acme" || ecosystem != "npm" || name != "evil" {
		return nil, nil
	}
	return s.refs, nil
}

// fullSuppressionLedger seeds a ledger with one suppression for the test
// coordinate so the suppression-history panel is populated.
func fullSuppressionLedger() *findings.SuppressionLedger {
	l := findings.NewSuppressionLedger(findings.SuppressionLedgerOptions{Now: func() time.Time { return testNow }})
	l.Record(context.Background(), findings.SuppressionRecord{
		Tenant: "acme", Coordinate: "evil@1.0.0", Digest: "sha256:abc",
		Category: findings.CategoryVulnerability, Identifier: "CVE-2026-0003",
		Gate: findings.GateVEX, Mechanism: findings.MechanismVEX, Actor: "vex:not_affected",
		Justification: "not affected: vulnerable code path not reachable", Locator: "CVE-2026-0003@evil@1.0.0",
	})
	return l
}

// stubRemediation is a scripted remediation advisor for the dossier tests.
type stubRemediation struct {
	advice *remediation.Advice
}

func (s *stubRemediation) Enabled() bool { return true }

func (s *stubRemediation) Advise(_ context.Context, _ remediation.Request) (*remediation.Advice, error) {
	return s.advice, nil
}

func buildTest(t *testing.T, p Providers, q Query) *Dossier {
	t.Helper()
	b := New(Config{Now: func() time.Time { return testNow }}, p)
	return b.Build(context.Background(), q)
}

func TestBuildFullDossier(t *testing.T) {
	d := buildTest(t, fullProviders(), Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0"})

	if d.Coordinate != "evil@1.0.0" || d.Name != "evil" || d.Version != "1.0.0" {
		t.Fatalf("identity wrong: %+v", d)
	}
	if d.Digest != "sha256:abc" {
		t.Errorf("digest not backfilled from findings/vuln: %q", d.Digest)
	}
	if d.Headline.Verdict != VerdictBlock || !d.Headline.Blocking {
		t.Errorf("expected BLOCK headline, got %+v", d.Headline)
	}
	if d.Headline.RiskScore != 82 || d.Headline.RiskBand != "critical" {
		t.Errorf("headline risk wrong: %+v", d.Headline)
	}
	if d.Vulns == nil || d.Vulns.Critical != 2 || !d.Vulns.Quarantined {
		t.Errorf("vuln section wrong: %+v", d.Vulns)
	}
	if len(d.Vulns.CVEs) != 2 {
		t.Errorf("expected 2 CVEs, got %v", d.Vulns.CVEs)
	}
	if d.Signature == nil || d.Signature.Verified {
		t.Errorf("signature should be unverified: %+v", d.Signature)
	}
	if d.License == nil || d.License.Disposition != "denied" {
		t.Errorf("license should be denied: %+v", d.License)
	}
	if d.Provenance == nil || d.Provenance.SourceCommit != "deadbeef" || d.Provenance.DownstreamPaths != 12 {
		t.Errorf("provenance wrong: %+v", d.Provenance)
	}
	if d.Reproduce == nil || !d.Reproduce.Mismatch {
		t.Errorf("repro should be mismatch: %+v", d.Reproduce)
	}
	if d.Approvals == nil || d.Approvals.Active != 1 {
		t.Errorf("approvals wrong: %+v", d.Approvals)
	}
	if d.Timeline == nil || !d.Timeline.Provable || d.Timeline.Events[0].AuditSeq != 7 {
		t.Errorf("timeline wrong: %+v", d.Timeline)
	}
	if d.SuggestedFix == nil || d.SuggestedFix.RecommendedVersion != "1.1.0" || d.SuggestedFix.Resolved != 1 {
		t.Errorf("suggested fix wrong: %+v", d.SuggestedFix)
	}
	if d.Suppression == nil || d.Suppression.Total != 1 || d.Suppression.ByMechanism["vex"] != 1 {
		t.Errorf("suppression history wrong: %+v", d.Suppression)
	}
	if d.LLMPackageScan == nil || d.LLMPackageScan.Disposition != "malicious" || !d.LLMPackageScan.Refused {
		t.Errorf("LLM package-scan section wrong: %+v", d.LLMPackageScan)
	}
	if r := d.Releases; r == nil || r.Total != 2 || r.Current != 1 || r.Pinned != 1 {
		t.Errorf("releases section wrong: %+v", d.Releases)
	}
	if rs := d.RepositoryScans; rs == nil || rs.Total != 2 || rs.Flagged != 1 || rs.Unscanned != 1 {
		t.Errorf("repository scans section wrong: %+v", d.RepositoryScans)
	}
	if d.Partial {
		t.Errorf("dossier should not be partial: %+v", d.Sources)
	}
	// Every wired source must report ok (none disabled/empty here).
	for _, s := range d.Sources {
		if s.Status == StatusDisabled {
			t.Errorf("source %s unexpectedly disabled", s.Source)
		}
	}

	md := d.Markdown()
	for _, want := range []string{"Security dossier: npm/evil@1.0.0", "**Verdict:** BLOCK", "CVE-2026-0001", "deadbeef", "denied", "## Suppression history", "vex:not_affected", "## Shipped in releases", "widgets @ c0ffee000000",
		"## Dependency scans in repositories", "release · version 1.0.0 · malicious · model-x", "head main (head) · version 1.0.0 · unscanned (budget-exhausted)", "`package-lock.json:12`"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestBuildPartialWhenDisabled(t *testing.T) {
	// Only findings wired; everything else disabled.
	p := Providers{Findings: fullProviders().Findings}
	d := buildTest(t, p, Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0"})

	if d.Findings == nil {
		t.Fatal("findings should be present")
	}
	if d.Risk != nil || d.Vulns != nil {
		t.Errorf("disabled sources must be absent")
	}
	var disabled int
	for _, s := range d.Sources {
		if s.Status == StatusDisabled {
			disabled++
		}
	}
	if disabled == 0 {
		t.Error("expected some sources reported disabled")
	}
	// A disabled (not timed-out) source must not flag the dossier partial.
	if d.Partial {
		t.Error("disabled sources should not make the dossier partial")
	}
}

func TestNoMatchYieldsEmptySections(t *testing.T) {
	d := buildTest(t, fullProviders(), Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "innocent@9.9.9"})
	if d.Findings != nil || d.Vulns != nil || d.Risk != nil {
		t.Errorf("unmatched coordinate should have no sections")
	}
	if d.Headline.Verdict != VerdictUnknown {
		t.Errorf("expected unknown verdict, got %q", d.Headline.Verdict)
	}
	// The wired sources should report empty, not disabled.
	for _, s := range d.Sources {
		if s.Source == "findings" && s.Status != StatusEmpty {
			t.Errorf("findings should be empty for unmatched coord, got %q", s.Status)
		}
	}
}

func TestVersionScoping(t *testing.T) {
	// Name-only query aggregates; a versioned query that doesn't match excludes.
	p := fullProviders()
	d := buildTest(t, p, Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "evil"})
	if d.Vulns == nil {
		t.Error("name-only query should match any version")
	}
	d2 := buildTest(t, p, Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "evil", Version: "2.0.0"})
	if d2.Vulns != nil {
		t.Error("version 2.0.0 should not match the 1.0.0 report")
	}
}

func TestEmptyCoordinate(t *testing.T) {
	d := buildTest(t, fullProviders(), Query{Tenant: "acme", Ecosystem: "npm"})
	if d.Headline.Verdict != VerdictUnknown {
		t.Errorf("empty coordinate should be unknown, got %+v", d.Headline)
	}
	if len(d.Sources) != 0 {
		t.Errorf("no fan-out expected for empty coordinate")
	}
}

func TestSourceTimeoutMarksPartial(t *testing.T) {
	// A timeline provider that blocks past the source timeout should be reported
	// as a timeout and flip Partial, without hanging the build.
	p := fullProviders()
	p.Timeline = blockingTimeline{}
	b := New(Config{Now: func() time.Time { return testNow }, SourceTimeout: 50 * time.Millisecond}, p)
	d := b.Build(context.Background(), Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0"})
	if !d.Partial {
		t.Fatal("expected partial dossier on source timeout")
	}
	var sawTimeout bool
	for _, s := range d.Sources {
		if s.Source == "timeline" && s.Status == StatusTimeout {
			sawTimeout = true
		}
	}
	if !sawTimeout {
		t.Errorf("timeline should report timeout: %+v", d.Sources)
	}
	// The rest of the dossier must still be populated.
	if d.Vulns == nil || d.Risk == nil {
		t.Error("other sections should still render when one source times out")
	}
}

type blockingTimeline struct{}

func (blockingTimeline) Query(ctx context.Context, q timeline.Query) (timeline.Result, error) {
	<-ctx.Done()
	return timeline.Result{}, ctx.Err()
}

// stubReleases answers "shipped in release X" from a fixed list, scoped to the
// acme tenant.
type stubReleases struct{ refs []ReleaseRef }

func (s stubReleases) ReleasesShipping(_ context.Context, tenant, ecosystem, name, version string) ([]ReleaseRef, error) {
	if tenant != "acme" || ecosystem != "npm" || name != "evil" {
		return nil, nil
	}
	return s.refs, nil
}
