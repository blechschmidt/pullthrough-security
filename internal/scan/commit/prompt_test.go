package commit

import "testing"

func TestParseVerdictPlainJSON(t *testing.T) {
	in := `{"riskScore": 80, "malicious": true, "rationale": "drops a reverse shell",
	"findings": [{"category":"malicious_code","severity":"critical","title":"reverse shell","detail":"x","file":"a.sh","line":3,"confidence":0.9}]}`
	v, err := parseVerdict(in)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if v.RiskScore != 80 || !v.Malicious {
		t.Errorf("score/malicious = %d/%v, want 80/true", v.RiskScore, v.Malicious)
	}
	if len(v.Findings) != 1 || v.Findings[0].Category != CategoryMaliciousCode {
		t.Fatalf("findings not parsed correctly: %+v", v.Findings)
	}
}

func TestParseVerdictFencedWithProse(t *testing.T) {
	in := "Sure, here is my analysis:\n```json\n{\"riskScore\": 5, \"malicious\": false, \"findings\": []}\n```\nLet me know!"
	v, err := parseVerdict(in)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if v.RiskScore != 5 || v.Malicious {
		t.Errorf("score/malicious = %d/%v, want 5/false", v.RiskScore, v.Malicious)
	}
}

func TestParseVerdictSanitizesUntrustedValues(t *testing.T) {
	in := `{"riskScore": 999, "findings":[{"category":"wat","severity":"apocalyptic","confidence":7.5,"line":-4}]}`
	v, err := parseVerdict(in)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if v.RiskScore != 100 {
		t.Errorf("riskScore clamp = %d, want 100", v.RiskScore)
	}
	f := v.Findings[0]
	if f.Category != CategoryUnknown {
		t.Errorf("unknown category = %q, want %q", f.Category, CategoryUnknown)
	}
	if f.Severity != "info" {
		t.Errorf("unknown severity coerced to %q, want info", f.Severity)
	}
	if f.Confidence != 1 {
		t.Errorf("confidence clamp = %v, want 1", f.Confidence)
	}
	if f.Line != 0 {
		t.Errorf("negative line = %d, want 0", f.Line)
	}
}

func TestParseVerdictNoJSON(t *testing.T) {
	if _, err := parseVerdict("I cannot help with that."); err == nil {
		t.Fatal("expected error when response has no JSON object")
	}
}

func TestExtractJSONObjectBalancesBraces(t *testing.T) {
	in := `prefix {"a": "}", "b": {"c": 1}} suffix`
	got := extractJSONObject(in)
	want := `{"a": "}", "b": {"c": 1}}`
	if got != want {
		t.Errorf("extractJSONObject = %q, want %q", got, want)
	}
}

func TestBuildUserPromptIncludesPartMarker(t *testing.T) {
	c := &Commit{SHA: "abc", Message: "subj"}
	p := buildUserPrompt(c, DiffChunk{Index: 1, Total: 3, Files: []FileDiff{{Path: "x", Patch: "@@\n+1\n"}}})
	if !contains(p, "part 2 of 3") {
		t.Errorf("multi-chunk prompt missing part marker:\n%s", p)
	}
	single := buildUserPrompt(c, DiffChunk{Index: 0, Total: 1})
	if contains(single, "part 1 of 1") {
		t.Errorf("single-chunk prompt should not have a part marker:\n%s", single)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
