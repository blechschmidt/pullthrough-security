package findings

import (
	"testing"
)

// baseDoc is a minimal document for dedup tests.
func baseDoc(findingsIn ...Finding) *Document {
	return &Document{
		Tenant: "acme",
		Artifact: Artifact{
			Name:       "lodash",
			Version:    "4.17.4",
			Digest:     "sha256:abc",
			Coordinate: "lodash@4.17.4",
		},
		Findings: findingsIn,
	}
}

func TestDeduplicate_CollapsesCrossGateSecret(t *testing.T) {
	// The same credential in the same file is reported by secretscan and by the
	// content-analysis gate (whose sub-category is "secret"). They must collapse.
	d := baseDoc(
		Finding{
			RuleID: RuleExposedSecret, Gate: GateSecretscan, Severity: SeverityHigh,
			Identifier: "aws-access-key", Title: "secret",
			Location: Location{Coordinate: "lodash@4.17.4", File: "config.js", Line: 12},
		},
		Finding{
			RuleID: RuleSuspiciousContent, Gate: GateContentScan, Severity: SeverityMedium,
			Identifier: "content", Title: "suspicious",
			Location:   Location{Coordinate: "lodash@4.17.4", File: "config.js", Line: 12},
			Properties: map[string]any{"category": "secret"},
		},
	)
	stats := d.Deduplicate()
	if stats.Input != 2 || stats.Output != 1 || stats.Collapsed != 1 {
		t.Fatalf("stats = %+v, want 2 in / 1 out / 1 collapsed", stats)
	}
	if len(d.Findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(d.Findings))
	}
	f := d.Findings[0]
	// Representative is the stronger (High secretscan) finding.
	if f.Gate != GateSecretscan || f.Severity != SeverityHigh {
		t.Errorf("representative = %s/%s, want secretscan/high", f.Gate, f.Severity)
	}
	if len(f.Sources) != 2 {
		t.Fatalf("sources = %d, want 2 (both gates preserved)", len(f.Sources))
	}
	gates := map[Gate]bool{}
	for _, s := range f.Sources {
		gates[s.Gate] = true
	}
	if !gates[GateSecretscan] || !gates[GateContentScan] {
		t.Errorf("sources missing a gate: %+v", f.Sources)
	}
	if stats.CollapsedByCategory[CategorySecret] != 1 {
		t.Errorf("collapsedByCategory[secret] = %d, want 1", stats.CollapsedByCategory[CategorySecret])
	}
}

func TestDeduplicate_CollapsesVulnAndKeepsFix(t *testing.T) {
	// Same CVE on the same component from the scanner (no fix) and the remediation
	// advisor (carrying a fix). They collapse; the fix survives.
	d := baseDoc(
		Finding{
			RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityCritical,
			Identifier: "CVE-2021-23337", Title: "vuln",
			Location: Location{Coordinate: "lodash@4.17.4"},
		},
		Finding{
			RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityCritical,
			Identifier: "CVE-2021-23337", Title: "vuln+fix",
			Location: Location{Coordinate: "lodash@4.17.4"},
			Fix:      &SuggestedFix{Description: "Upgrade to 4.17.21", Version: "4.17.21"},
		},
	)
	stats := d.Deduplicate()
	if stats.Output != 1 {
		t.Fatalf("output = %d, want 1", stats.Output)
	}
	if d.Findings[0].Fix == nil || d.Findings[0].Fix.Version != "4.17.21" {
		t.Errorf("fix not preserved on merged finding: %+v", d.Findings[0].Fix)
	}
}

func TestDeduplicate_DistinctFindingsNotCollapsed(t *testing.T) {
	d := baseDoc(
		Finding{RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityHigh, Identifier: "CVE-1", Location: Location{Coordinate: "lodash@4.17.4"}},
		Finding{RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityHigh, Identifier: "CVE-2", Location: Location{Coordinate: "lodash@4.17.4"}},
		Finding{RuleID: RuleExposedSecret, Gate: GateSecretscan, Severity: SeverityHigh, Identifier: "k", Location: Location{Coordinate: "lodash@4.17.4", File: "a.js", Line: 1}},
	)
	stats := d.Deduplicate()
	if stats.Collapsed != 0 || stats.Output != 3 {
		t.Fatalf("stats = %+v, want 0 collapsed / 3 out", stats)
	}
	// Every finding gets a single-element Source for uniform provenance.
	for _, f := range d.Findings {
		if len(f.Sources) != 1 {
			t.Errorf("finding %s has %d sources, want 1", f.Identifier, len(f.Sources))
		}
	}
}

func TestDeduplicate_DifferentDigestNotCollapsed(t *testing.T) {
	// A sub-component vuln keyed to a different coordinate must not collapse with
	// the top-level one even under the same category.
	d := baseDoc(
		Finding{RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityHigh, Identifier: "CVE-9", Location: Location{Coordinate: "lodash@4.17.4"}},
		Finding{RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityHigh, Identifier: "CVE-9", Location: Location{Coordinate: "transitive@1.0.0"}},
	)
	if stats := d.Deduplicate(); stats.Collapsed != 0 {
		t.Fatalf("collapsed = %d, want 0 (different component coordinate)", stats.Collapsed)
	}
}

func TestDeduplicate_NonSuppressedWinsOverSuppressed(t *testing.T) {
	d := baseDoc(
		Finding{RuleID: RuleVulnerableDependency, Gate: GateVEX, Severity: SeverityInfo, Suppressed: true, Identifier: "CVE-7", Location: Location{Coordinate: "lodash@4.17.4"}},
		Finding{RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityInfo, Identifier: "CVE-7", Location: Location{Coordinate: "lodash@4.17.4"}},
	)
	d.Deduplicate()
	if len(d.Findings) != 1 {
		t.Fatalf("len = %d, want 1", len(d.Findings))
	}
	if d.Findings[0].Suppressed {
		t.Errorf("merged finding suppressed; a live detection should dominate")
	}
}

func TestDeduplicate_Idempotent(t *testing.T) {
	d := baseDoc(
		Finding{RuleID: RuleExposedSecret, Gate: GateSecretscan, Severity: SeverityHigh, Identifier: "k", Location: Location{Coordinate: "lodash@4.17.4", File: "a.js", Line: 1}},
		Finding{RuleID: RuleSuspiciousContent, Gate: GateContentScan, Severity: SeverityMedium, Location: Location{Coordinate: "lodash@4.17.4", File: "a.js", Line: 1}, Properties: map[string]any{"category": "secret"}},
	)
	d.Deduplicate()
	first := len(d.Findings)
	s2 := d.Deduplicate()
	if len(d.Findings) != first || s2.Collapsed != 0 {
		t.Errorf("second pass changed result: len %d->%d, collapsed %d", first, len(d.Findings), s2.Collapsed)
	}
}
