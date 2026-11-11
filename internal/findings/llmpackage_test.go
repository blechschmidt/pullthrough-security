package findings

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func llmInput(l *policyengine.LLMPackageInput) policyengine.Input {
	return policyengine.Input{
		Tenant:     "acme",
		Artifact:   policyengine.ArtifactInput{Ecosystem: "npm", Backend: "npmjs", Name: "evil-pad", Version: "1.0.0", Digest: "sha256:abc"},
		LLMPackage: l,
	}
}

func TestLLMPackageRulesAreInTheCatalog(t *testing.T) {
	gates := map[Gate]bool{}
	for _, g := range CatalogGates() {
		gates[g] = true
	}
	if !gates[GateLLMPkgScan] {
		t.Fatalf("gate %q is not among the catalog gates", GateLLMPkgScan)
	}
	want := map[string]Level{
		RuleLLMMaliciousPackage:  LevelError,
		RuleLLMSuspiciousPackage: LevelWarning,
		RuleLLMScanIncomplete:    LevelNote,
	}
	rules := RulesForGate(GateLLMPkgScan)
	if len(rules) != len(want) {
		t.Fatalf("RulesForGate(%s) = %d rules, want %d", GateLLMPkgScan, len(rules), len(want))
	}
	for _, r := range rules {
		level, ok := want[r.ID]
		if !ok {
			t.Errorf("unexpected rule %q", r.ID)
			continue
		}
		if r.Default != level || r.Gate != GateLLMPkgScan || r.Short == "" || r.Full == "" || r.HelpText == "" {
			t.Errorf("rule %q = %+v", r.ID, r)
		}
		if !strings.HasPrefix(r.ID, "llmpkgscan/") || !strings.Contains(r.HelpURI, "#llm-") {
			t.Errorf("rule %q: id / help anchor = %q", r.ID, r.HelpURI)
		}
	}
}

func TestFromInputLLMPackage(t *testing.T) {
	d := FromInput(llmInput(&policyengine.LLMPackageInput{
		Scanned: true, Verdict: "malicious", Confidence: 0.97, Disposition: "malicious", Action: "block",
		Model: "model-x", Mode: "tools", VerifiedEvidence: 1, Truncated: true,
		Injection: true, InjectionRules: []string{"ignore-instructions"},
		Findings: []policyengine.LLMPackageFinding{
			{RuleID: RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical",
				Title: "LLM content scan: package judged malicious (confidence 0.97)", Detail: "Reasons stated by the model: runs a remote script.",
				File: "package/scripts/setup.js", Line: 2},
			{RuleID: RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical",
				Title: "LLM content scan: package judged malicious (confidence 0.97)", File: "package/index.js", Line: 9},
			{RuleID: RuleLLMSuspiciousPackage, Category: "prompt-injection", Severity: "high",
				Title: "Package content addresses the scanner (prompt injection)", File: "package/README.md", Line: 3},
			{RuleID: "llmpkgscan/some-future-rule", Category: "archive-anomaly", Severity: "high", Title: "Archive is built to attack an extractor"},
		},
	}), Options{})

	if len(d.Findings) != 4 {
		t.Fatalf("findings = %d, want 4: %+v", len(d.Findings), d.Findings)
	}
	for _, f := range d.Findings {
		if f.Gate != GateLLMPkgScan {
			t.Errorf("finding gate = %q", f.Gate)
		}
		if _, known := catalog[f.RuleID]; !known {
			t.Errorf("finding carries a rule id outside the catalog: %q", f.RuleID)
		}
	}

	mal := findingsByRule(d, RuleLLMMaliciousPackage)
	if len(mal) != 2 {
		t.Fatalf("malicious findings = %d, want one per cited location", len(mal))
	}
	first := mal[0]
	if first.Severity != SeverityCritical || first.Level != LevelError {
		t.Errorf("severity/level = %s/%s", first.Severity, first.Level)
	}
	if first.Location.File != "package/scripts/setup.js" || first.Location.Line != 2 || first.Location.Coordinate == "" {
		t.Errorf("location = %+v", first.Location)
	}
	if first.Identifier != "malicious-package" {
		t.Errorf("identifier = %q, want the finding category", first.Identifier)
	}
	if !strings.HasPrefix(first.Message, first.Title) || !strings.Contains(first.Message, "Reasons stated by the model:") {
		t.Errorf("message = %q", first.Message)
	}
	for key, want := range map[string]any{
		"category": "malicious-package", "disposition": "malicious", "model": "model-x", "mode": "tools",
		"verdict": "malicious", "confidence": 0.97, "verifiedEvidence": 1, "truncated": true,
	} {
		if got := first.Properties[key]; got != want {
			t.Errorf("properties[%s] = %#v, want %#v", key, got, want)
		}
	}
	if _, has := first.Properties["unscannedCode"]; has {
		t.Error("a scanned artifact's finding carries an unscanned code")
	}
	// A finding without model detail is its title alone — no dangling separator.
	if mal[1].Message != mal[1].Title {
		t.Errorf("message without detail = %q", mal[1].Message)
	}

	// The injection finding and the unknown rule both land on the suspicious rule
	// (an id outside the catalog must not reach a SARIF consumer).
	sus := findingsByRule(d, RuleLLMSuspiciousPackage)
	if len(sus) != 2 {
		t.Fatalf("suspicious findings = %d, want 2", len(sus))
	}
	if sus[0].Identifier != "prompt-injection" || sus[0].Severity != SeverityHigh || sus[0].Level != LevelError {
		t.Errorf("injection finding = %+v", sus[0])
	}
	if sus[1].Identifier != "archive-anomaly" || sus[1].Location.File != "" {
		t.Errorf("anomaly finding = %+v", sus[1])
	}
	if !d.HasBlocking() {
		t.Error("a malicious verdict must be a blocking finding")
	}
}

func TestFromInputLLMPackageQuietCases(t *testing.T) {
	for name, l := range map[string]*policyengine.LLMPackageInput{
		"no signal":         nil,
		"benign":            {Scanned: true, Verdict: "benign", Disposition: "benign", Confidence: 0.9, Model: "m"},
		"provider outage":   {Disposition: "unscanned", Unscanned: true, UnscannedCode: "provider-error"},
		"budget exhausted":  {Disposition: "unscanned", Unscanned: true, UnscannedCode: "budget-exhausted"},
		"below a threshold": {Scanned: true, Verdict: "suspicious", Disposition: "benign", Confidence: 0.2},
	} {
		if d := FromInput(llmInput(l), Options{}); len(d.Findings) != 0 {
			t.Errorf("%s: %d findings, want none: %+v", name, len(d.Findings), d.Findings)
		}
	}
}

func TestFromInputLLMPackageScanIncomplete(t *testing.T) {
	d := FromInput(llmInput(&policyengine.LLMPackageInput{
		Disposition: "unscanned", Unscanned: true, UnscannedCode: "oversized", ContentAttributable: true, Risk: 25,
		Findings: []policyengine.LLMPackageFinding{{
			RuleID: RuleLLMScanIncomplete, Category: "scan-incomplete", Severity: "low",
			Title:  "Package was not examined by the LLM content scan (oversized)",
			Detail: "the artifact is larger than the scan size limit",
		}},
	}), Options{})
	inc := findingsByRule(d, RuleLLMScanIncomplete)
	if len(inc) != 1 {
		t.Fatalf("scan-incomplete findings = %d, want 1: %+v", len(inc), d.Findings)
	}
	f := inc[0]
	if f.Level != LevelNote || f.Severity != SeverityLow {
		t.Errorf("an unexamined artifact is a note, not a failure: %s/%s", f.Severity, f.Level)
	}
	if f.Properties["unscannedCode"] != "oversized" {
		t.Errorf("properties = %v", f.Properties)
	}
	if _, has := f.Properties["verdict"]; has {
		t.Error("an unscanned artifact's finding claims a verdict")
	}
	if d.HasBlocking() {
		t.Error("scan-incomplete must not fail a build by itself")
	}
}

// Two citations in one file are two findings; the LLM's finding and the static
// content scan's finding at the same place are different statements and both
// survive de-duplication.
func TestLLMPackageFindingsDeduplicate(t *testing.T) {
	in := llmInput(&policyengine.LLMPackageInput{
		Scanned: true, Verdict: "malicious", Disposition: "malicious", Confidence: 0.9,
		Findings: []policyengine.LLMPackageFinding{
			{RuleID: RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical", Title: "t", File: "package/a.js", Line: 2},
			{RuleID: RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical", Title: "t", File: "package/a.js", Line: 2},
			{RuleID: RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical", Title: "t", File: "package/a.js", Line: 40},
		},
	})
	in.ContentScan = &policyengine.ContentScanInput{Scanned: true, FindingCount: 1, MaxSeverity: "high",
		Findings: []policyengine.ContentScanFinding{{RuleID: "dynamic-exec", Category: "dynamic-exec", Severity: "high", File: "package/a.js", Line: 2}}}
	d := FromInput(in, Options{})
	stats := d.Deduplicate()
	if stats.Collapsed != 1 || stats.CollapsedByCategory[CategoryLLMVerdict] != 1 {
		t.Errorf("dedup stats = %+v, want exactly the repeated citation collapsed", stats)
	}
	if got := len(findingsByRule(d, RuleLLMMaliciousPackage)); got != 2 {
		t.Errorf("LLM findings after dedup = %d, want 2 (two distinct lines)", got)
	}
	if got := len(findingsByRule(d, RuleSuspiciousContent)); got != 1 {
		t.Errorf("content-scan findings after dedup = %d, want 1 (a different statement about the same line)", got)
	}
}

func TestLLMPackageFindingsRenderAsSARIF(t *testing.T) {
	d := FromInput(llmInput(&policyengine.LLMPackageInput{
		Scanned: true, Verdict: "malicious", Disposition: "malicious", Confidence: 0.97, Model: "model-x",
		Findings: []policyengine.LLMPackageFinding{
			{RuleID: RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical", Title: "LLM content scan: package judged malicious (confidence 0.97)",
				File: "package/scripts/setup.js", Line: 2},
		},
	}), Options{GeneratedAt: fixedTime})
	raw, err := json.Marshal(d.SARIF(SARIFOptions{ToolVersion: "test"}))
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	out := string(raw)
	for _, want := range []string{
		`"ruleId":"llmpkgscan/malicious-package"`,
		`"level":"error"`,
		`"LLMMaliciousPackage"`,
		`package/scripts/setup.js`,
		`"startLine":2`,
		`#llm-malicious-package`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("SARIF is missing %s:\n%s", want, out)
		}
	}
}
