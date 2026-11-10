package findings

import (
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func findingsByRule(d Document, ruleID string) []Finding {
	var out []Finding
	for _, f := range d.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func TestFromInputVulnAndVEX(t *testing.T) {
	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Name: "pkg", Version: "1.0.0"},
		Vuln: &policyengine.VulnInput{
			Scanned: true, Scanner: "osv", Total: 2,
			Findings: []policyengine.VulnFinding{
				{ID: "CVE-1", Severity: "critical", CVSS: 9.1, Package: "pkg", Version: "1.0.0", Fixed: []string{"1.0.1"}},
				{ID: "CVE-2", Severity: "high", Package: "pkg", Version: "1.0.0", Suppressed: true, VEXStatus: "not_affected"},
			},
		},
	}
	d := FromInput(in, Options{})

	vulns := findingsByRule(d, RuleVulnerableDependency)
	if len(vulns) != 1 {
		t.Fatalf("want 1 vulnerable-dependency finding, got %d", len(vulns))
	}
	if vulns[0].Level != LevelError {
		t.Errorf("critical CVE should be error level, got %s", vulns[0].Level)
	}
	if vulns[0].Identifier != "CVE-1" {
		t.Errorf("identifier = %q", vulns[0].Identifier)
	}

	vex := findingsByRule(d, RuleSuppressedVuln)
	if len(vex) != 1 {
		t.Fatalf("want 1 suppressed finding, got %d", len(vex))
	}
	if !vex[0].Suppressed {
		t.Error("VEX finding should be marked suppressed")
	}
	if vex[0].Level != LevelNote {
		t.Errorf("suppressed finding should be note level, got %s", vex[0].Level)
	}
}

func TestFromInputVulnReachability(t *testing.T) {
	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Name: "pkg", Version: "1.0.0"},
		Vuln: &policyengine.VulnInput{
			Scanned: true, Scanner: "osv", Total: 2, ReachabilityEnabled: true,
			Findings: []policyengine.VulnFinding{
				// Reachable critical: annotated, gates normally.
				{ID: "CVE-R", Severity: "critical", CVSS: 9.1, Package: "dep-a", Version: "1.0.0", Reachability: "reachable"},
				// Unreachable, suppressed by policy: emitted as a SARIF suppression (note).
				{ID: "CVE-U", Severity: "critical", CVSS: 9.0, Package: "dep-b", Version: "2.0.0", Reachability: "unreachable", ReachSuppressed: true},
			},
		},
	}
	d := FromInput(in, Options{})

	vulns := findingsByRule(d, RuleVulnerableDependency)
	if len(vulns) != 2 {
		t.Fatalf("want 2 vulnerable-dependency findings, got %d", len(vulns))
	}
	var reachable, suppressed *Finding
	for i := range vulns {
		switch vulns[i].Identifier {
		case "CVE-R":
			reachable = &vulns[i]
		case "CVE-U":
			suppressed = &vulns[i]
		}
	}
	if reachable == nil || suppressed == nil {
		t.Fatalf("missing findings: reachable=%v suppressed=%v", reachable, suppressed)
	}
	if reachable.Properties["reachability"] != "reachable" {
		t.Errorf("reachable finding missing reachability property: %v", reachable.Properties)
	}
	if reachable.Suppressed {
		t.Error("reachable finding must not be suppressed")
	}
	if reachable.Level != LevelError {
		t.Errorf("reachable critical should be error, got %s", reachable.Level)
	}
	if suppressed.Properties["reachability"] != "unreachable" {
		t.Errorf("suppressed finding missing reachability property: %v", suppressed.Properties)
	}
	if !suppressed.Suppressed {
		t.Error("unreachable-suppressed finding should be marked suppressed")
	}
	if suppressed.Level != LevelNote {
		t.Errorf("suppressed finding should be note level, got %s", suppressed.Level)
	}
	if suppressed.Justification == "" {
		t.Error("suppressed finding should carry a justification")
	}
}

func TestFromInputSignatureSkippedWhenVerified(t *testing.T) {
	in := policyengine.Input{
		Artifact:  policyengine.ArtifactInput{Name: "pkg", Version: "1"},
		Signature: &policyengine.SignatureInput{Checked: true, Verified: true},
	}
	d := FromInput(in, Options{})
	if got := findingsByRule(d, RuleUnverifiedSignature); len(got) != 0 {
		t.Errorf("verified signature should produce no finding, got %d", len(got))
	}
}

func TestFromInputSignatureUnverified(t *testing.T) {
	in := policyengine.Input{
		Artifact:  policyengine.ArtifactInput{Name: "pkg", Version: "1"},
		Signature: &policyengine.SignatureInput{Checked: true, Source: "npm", Error: "no attestation"},
	}
	d := FromInput(in, Options{})
	got := findingsByRule(d, RuleUnverifiedSignature)
	if len(got) != 1 {
		t.Fatalf("want 1 unverified-signature finding, got %d", len(got))
	}
	if got[0].Level != LevelError {
		t.Errorf("default unverified signature should be error, got %s", got[0].Level)
	}
}

func TestFromInputNameguardKinds(t *testing.T) {
	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Name: "reqeusts"},
		Nameguard: &policyengine.NameguardInput{
			Scanned: true, FindingCount: 3,
			Findings: []policyengine.NameguardFinding{
				{Kind: "typosquat", Severity: "high", Name: "reqeusts", Similar: "requests", Distance: 1},
				{Kind: "dependency-confusion", Severity: "critical", Name: "reqeusts", Similar: "internal"},
				{Kind: "homoglyph", Severity: "medium", Name: "reqeusts"},
			},
		},
	}
	d := FromInput(in, Options{})
	for _, rule := range []string{RuleTyposquat, RuleDependencyConfusion, RuleHomoglyph} {
		if len(findingsByRule(d, rule)) != 1 {
			t.Errorf("expected one finding for rule %s", rule)
		}
	}
}

func TestFromInputRiskOnlyWhenExceeds(t *testing.T) {
	in := policyengine.Input{Artifact: policyengine.ArtifactInput{Name: "pkg", Version: "1"}}
	d := FromInput(in, Options{Risk: &RiskSignal{Score: 30, Band: "low", Exceeds: false}})
	if got := findingsByRule(d, RuleRiskThreshold); len(got) != 0 {
		t.Errorf("non-exceeding risk should produce no finding, got %d", len(got))
	}
	d = FromInput(in, Options{Risk: &RiskSignal{Score: 90, Band: "critical", Exceeds: true, Action: "block"}})
	got := findingsByRule(d, RuleRiskThreshold)
	if len(got) != 1 {
		t.Fatalf("exceeding risk should produce a finding, got %d", len(got))
	}
	if got[0].Level != LevelError {
		t.Errorf("critical band risk should be error, got %s", got[0].Level)
	}
}

func TestFromInputPolicyMatches(t *testing.T) {
	in := policyengine.Input{Artifact: policyengine.ArtifactInput{Name: "pkg", Version: "1"}}
	d := FromInput(in, Options{Policy: &PolicySignal{
		Action: "deny",
		Matches: []PolicyMatch{
			{RuleID: "r1", Action: "deny", Reason: "bad"},
			{RuleID: "r2", Action: "allow"},
			{RuleID: "r3", Action: "warn", Reason: "meh"},
		},
	}})
	got := findingsByRule(d, RulePolicyViolation)
	if len(got) != 2 {
		t.Fatalf("allow matches should be skipped; want 2 findings, got %d", len(got))
	}
}

func TestHasBlocking(t *testing.T) {
	in, opts := richInput()
	d := FromInput(in, opts)
	if !d.HasBlocking() {
		t.Error("rich input should have blocking findings")
	}
	counts := d.Counts()
	if counts[SeverityCritical] == 0 {
		t.Error("expected at least one critical (non-suppressed) finding")
	}
}

func TestGeneratedAtPreserved(t *testing.T) {
	in := policyengine.Input{Artifact: policyengine.ArtifactInput{Name: "pkg", Version: "1"}}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := FromInput(in, Options{GeneratedAt: ts})
	if !d.GeneratedAt.Equal(ts) {
		t.Errorf("GeneratedAt = %v, want %v", d.GeneratedAt, ts)
	}
}
