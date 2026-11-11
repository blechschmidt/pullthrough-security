package policyengine

import (
	"testing"
)

func llmPackageDoc(t *testing.T, l *LLMPackageInput) map[string]any {
	t.Helper()
	doc := Input{Artifact: ArtifactInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}, Tenant: "prod", LLMPackage: l}.Document()
	sec, ok := doc["llmPackageScan"].(map[string]any)
	if l == nil {
		if ok {
			t.Fatalf("llmPackageScan present in the document without a signal: %v", sec)
		}
		return nil
	}
	if !ok {
		t.Fatalf("llmPackageScan missing from the document: %v", doc)
	}
	return sec
}

func TestLLMPackageInputDocument(t *testing.T) {
	// No signal: the key is absent, so has(input.llmPackageScan) is false.
	llmPackageDoc(t, nil)

	sec := llmPackageDoc(t, &LLMPackageInput{
		Scanned: true, Verdict: "malicious", Confidence: 0.97, Disposition: "malicious", Action: "block",
		Cached: true, Model: "m", Mode: "tools", Truncated: true,
		Injection: true, InjectionRules: []string{"ignore-instructions"}, StructuralRisk: true,
		EvidenceCount: 3, VerifiedEvidence: 2, FindingCount: 2, MaxSeverity: "critical", Risk: 99,
		Findings: []LLMPackageFinding{
			{RuleID: "llmpkgscan/malicious-package", Category: "malicious-package", Severity: "critical", Title: "t", Detail: "model text", File: "package/a.js", Line: 7},
			{RuleID: "llmpkgscan/suspicious-package", Category: "prompt-injection", Severity: "high", File: "package/README.md", Line: 3},
		},
	})
	for key, want := range map[string]any{
		"scanned": true, "verdict": "malicious", "confidence": 0.97, "disposition": "malicious",
		"malicious": true, "suspicious": false, "action": "block", "cached": true, "model": "m", "mode": "tools",
		"truncated": true, "injection": true, "structuralRisk": true,
		"evidenceCount": int64(3), "verifiedEvidence": int64(2),
		"unscanned": false, "unscannedCode": "", "contentAttributable": false,
		"findingCount": int64(2), "hasFindings": true, "maxSeverity": "critical", "risk": int64(99),
	} {
		if got := sec[key]; got != want {
			t.Errorf("llmPackageScan.%s = %#v, want %#v", key, got, want)
		}
	}
	rules, _ := sec["injectionRules"].([]any)
	if len(rules) != 1 || rules[0] != "ignore-instructions" {
		t.Errorf("injectionRules = %#v", sec["injectionRules"])
	}
	findings, _ := sec["findings"].([]any)
	if len(findings) != 2 {
		t.Fatalf("findings = %#v", sec["findings"])
	}
	first, _ := findings[0].(map[string]any)
	if first["ruleId"] != "llmpkgscan/malicious-package" || first["category"] != "malicious-package" ||
		first["severity"] != "critical" || first["file"] != "package/a.js" || first["line"] != int64(7) {
		t.Errorf("finding = %#v", first)
	}
	// The model's prose is not exposed to rules: a policy decides on categories,
	// not on text the package under review could have shaped.
	if _, leaked := first["detail"]; leaked {
		t.Error("a finding's free-text detail is exposed to policy rules")
	}
	if _, leaked := first["title"]; leaked {
		t.Error("a finding's title is exposed to policy rules")
	}

	suspicious := llmPackageDoc(t, &LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "suspicious"})
	if suspicious["suspicious"] != true || suspicious["malicious"] != false || suspicious["hasFindings"] != false {
		t.Errorf("suspicious document = %v", suspicious)
	}
	unscanned := llmPackageDoc(t, &LLMPackageInput{Disposition: "unscanned", Unscanned: true, UnscannedCode: "oversized", ContentAttributable: true, Risk: 25})
	if unscanned["scanned"] != false || unscanned["unscanned"] != true || unscanned["unscannedCode"] != "oversized" ||
		unscanned["contentAttributable"] != true || unscanned["malicious"] != false || unscanned["risk"] != int64(25) {
		t.Errorf("unscanned document = %v", unscanned)
	}
}

// The rules the documentation offers evaluate as described.
func TestLLMPackageRulesEvaluate(t *testing.T) {
	bundle := &Bundle{
		Name: "llm",
		Rules: []Rule{
			{ID: "no-suspicious-packages", When: `has(input.llmPackageScan) && input.llmPackageScan.suspicious`, Action: ActionDeny},
			{ID: "no-unscannable-packages", When: `has(input.llmPackageScan) && input.llmPackageScan.unscanned && input.llmPackageScan.contentAttributable`, Action: ActionDeny},
			{ID: "full-coverage-in-prod", When: `input.tenant == "prod" && has(input.llmPackageScan) && input.llmPackageScan.truncated`, Action: ActionDeny},
			{ID: "confident-malicious", When: `has(input.llmPackageScan) && input.llmPackageScan.verdict == "malicious" && input.llmPackageScan.confidence >= 0.9`, Action: ActionDeny},
			{ID: "injection-is-a-warning", When: `has(input.llmPackageScan) && input.llmPackageScan.injection`, Action: ActionWarn},
		},
	}
	rs, err := CompileRuleSet([]*Bundle{bundle}, CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for name, tc := range map[string]struct {
		tenant string
		in     *LLMPackageInput
		action Action
		rule   string
	}{
		"no signal":                 {"prod", nil, ActionAllow, ""},
		"benign":                    {"prod", &LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign"}, ActionAllow, ""},
		"suspicious":                {"dev", &LLMPackageInput{Scanned: true, Verdict: "suspicious", Disposition: "suspicious"}, ActionDeny, "no-suspicious-packages"},
		"made itself unscannable":   {"dev", &LLMPackageInput{Unscanned: true, UnscannedCode: "oversized", ContentAttributable: true}, ActionDeny, "no-unscannable-packages"},
		"provider outage":           {"dev", &LLMPackageInput{Unscanned: true, UnscannedCode: "provider-error"}, ActionAllow, ""},
		"truncated in prod":         {"prod", &LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign", Truncated: true}, ActionDeny, "full-coverage-in-prod"},
		"truncated elsewhere":       {"dev", &LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign", Truncated: true}, ActionAllow, ""},
		"confident malicious":       {"dev", &LLMPackageInput{Scanned: true, Verdict: "malicious", Confidence: 0.95, Disposition: "malicious"}, ActionDeny, "confident-malicious"},
		"unsure malicious":          {"dev", &LLMPackageInput{Scanned: true, Verdict: "malicious", Confidence: 0.5, Disposition: "suspicious"}, ActionDeny, "no-suspicious-packages"},
		"injection without verdict": {"dev", &LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign", Injection: true}, ActionWarn, "injection-is-a-warning"},
	} {
		in := Input{Artifact: ArtifactInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}, Tenant: tc.tenant, LLMPackage: tc.in}
		dec := rs.evaluate(tc.tenant, in.Document())
		if len(dec.Errors) != 0 {
			t.Errorf("%s: rule errors %+v", name, dec.Errors)
		}
		if dec.Action != tc.action {
			t.Errorf("%s: action = %s, want %s (matches %+v)", name, dec.Action, tc.action, dec.Matches)
			continue
		}
		if tc.rule != "" {
			found := false
			for _, m := range dec.Matches {
				if m.RuleID == tc.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: rule %q did not match (matches %+v)", name, tc.rule, dec.Matches)
			}
		}
	}
}
