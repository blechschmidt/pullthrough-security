package notify

import "testing"

func TestSeverityOrdering(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Error("critical should be >= high")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("low should not be >= high")
	}
	if !SeverityHigh.AtLeast(SeverityHigh) {
		t.Error("high should be >= high")
	}
	// An unknown value ranks as info so it cannot satisfy a high floor.
	if Severity("bogus").AtLeast(SeverityLow) {
		t.Error("unknown severity should rank as info")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]Severity{
		"":         SeverityInfo,
		"CRITICAL": SeverityCritical,
		" High ":   SeverityHigh,
		"medium":   SeverityMedium,
		"weird":    SeverityInfo,
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidSeverityAndEventType(t *testing.T) {
	for _, s := range []string{"", "low", "high", "critical"} {
		if !ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = false", s)
		}
	}
	if ValidSeverity("enormous") {
		t.Error("ValidSeverity(enormous) should be false")
	}
	for _, et := range AllEventTypes() {
		if !ValidEventType(string(et)) {
			t.Errorf("ValidEventType(%q) = false", et)
		}
	}
	if ValidEventType("test") {
		t.Error("the synthetic test type is not a routable event type")
	}
	if ValidEventType("made_up") {
		t.Error("ValidEventType(made_up) should be false")
	}
}

func TestConstructorsSetTypeAndSeverity(t *testing.T) {
	if ev := PolicyBlockEvent("npm", "b", "x@1", "denylist", "no"); ev.Type != EventPolicyBlock || ev.Severity != SeverityHigh {
		t.Errorf("PolicyBlockEvent = %+v", ev)
	}
	if ev := ProvenanceFailureEvent("npm", "b", "x@1", "signature-required", "bad"); ev.Type != EventProvenanceFailure {
		t.Errorf("ProvenanceFailureEvent type = %q", ev.Type)
	}
	if ev := VulnerabilityEvent(SeverityCritical, "npm", "b", "x@1", "CVE-1", "block", "bad"); ev.Severity != SeverityCritical {
		t.Errorf("VulnerabilityEvent severity = %q", ev.Severity)
	}
	if ev := QuarantineEvent(SeverityHigh, "npm", "b", "x@1", "CVE-1", "q"); ev.Type != EventQuarantine {
		t.Errorf("QuarantineEvent type = %q", ev.Type)
	}
	if ev := RescanRegressionEvent(SeverityHigh, "npm", "x@1", "CVE-1", "drift"); ev.Type != EventRescanRegression {
		t.Errorf("RescanRegressionEvent type = %q", ev.Type)
	}
	if ev := TestEvent(); ev.Type != EventTest {
		t.Errorf("TestEvent type = %q", ev.Type)
	}
}

func TestCommitScanEventMaliciousTitleAndFields(t *testing.T) {
	ev := CommitScanEvent(SeverityCritical, "github.com/acme/repo", "abcdef1234567890", 95, true, "backdoor")
	if ev.Type != EventCommitScan {
		t.Errorf("type = %q", ev.Type)
	}
	if ev.Title != "Malicious commit detected" {
		t.Errorf("title = %q", ev.Title)
	}
	if ev.Fields["malicious"] != "true" {
		t.Errorf("malicious field = %q", ev.Fields["malicious"])
	}
	if ev.Fields["riskScore"] != "95" {
		t.Errorf("riskScore field = %q", ev.Fields["riskScore"])
	}
	// The commit field is abbreviated.
	if ev.Fields["commit"] != "abcdef123456" {
		t.Errorf("commit field = %q, want abbreviated", ev.Fields["commit"])
	}
}

func TestWithFieldIgnoresEmpty(t *testing.T) {
	ev := Event{}.WithField("", "v").WithField("k", "").WithField("real", "x")
	if len(ev.Fields) != 1 || ev.Fields["real"] != "x" {
		t.Errorf("Fields = %+v, want only real=x", ev.Fields)
	}
}
