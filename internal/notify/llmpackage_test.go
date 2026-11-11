package notify

import (
	"strings"
	"testing"
)

func TestLLMPackageScanEventIsRoutable(t *testing.T) {
	if EventLLMPackageScan != "llm_package_scan" {
		t.Errorf("event type = %q", EventLLMPackageScan)
	}
	if !ValidEventType("llm_package_scan") || !ValidEventType(" LLM_Package_Scan ") {
		t.Error("llm_package_scan must be a routable event type")
	}
	found := false
	for _, et := range AllEventTypes() {
		if et == EventLLMPackageScan {
			found = true
		}
	}
	if !found {
		t.Error("llm_package_scan is not listed among the event types")
	}
}

func TestLLMPackageScanEvent(t *testing.T) {
	for _, tc := range []struct {
		disposition, action string
		title               string
	}{
		{"malicious", "block", "Package blocked: LLM content scan judged it malicious"},
		{"malicious", "quarantine", "Package blocked: LLM content scan judged it malicious"},
		{"malicious", "annotate", "LLM content scan judged a package malicious"},
		{"suspicious", "quarantine", "Package held for review: LLM content scan judged it suspicious"},
		{"suspicious", "block", "LLM content scan judged a package suspicious"},
		{"suspicious", "annotate", "LLM content scan judged a package suspicious"},
		{"unscanned", "fail-closed", "Package could not be examined by the LLM content scan"},
		{"something-new", "block", "LLM content scan flagged a package"},
	} {
		ev := LLMPackageScanEvent(SeverityHigh, "npm", "npmjs", "evil-pad@1.0.0", tc.disposition, tc.action, "model-x", 0.9666, "the proxy's own sentence")
		if ev.Title != tc.title {
			t.Errorf("%s/%s: title = %q, want %q", tc.disposition, tc.action, ev.Title, tc.title)
		}
		if ev.Type != EventLLMPackageScan || ev.Severity != SeverityHigh || ev.Ecosystem != "npm" ||
			ev.Backend != "npmjs" || ev.Artifact != "evil-pad@1.0.0" || ev.Summary != "the proxy's own sentence" {
			t.Errorf("%s/%s: event = %+v", tc.disposition, tc.action, ev)
		}
		for key, want := range map[string]string{
			"disposition": tc.disposition, "action": tc.action, "model": "model-x", "confidence": "0.97",
		} {
			if got := ev.Fields[key]; got != want {
				t.Errorf("%s/%s: fields[%s] = %q, want %q", tc.disposition, tc.action, key, got, want)
			}
		}
	}
}

func TestLLMPackageBudgetEvent(t *testing.T) {
	tenant := LLMPackageBudgetEvent("tenant", "team-a", true)
	if tenant.Type != EventCostBudget || tenant.Severity != SeverityMedium {
		t.Errorf("tenant fail-open event = %+v", tenant)
	}
	if !strings.Contains(tenant.Summary, "tenant team-a") || !strings.Contains(tenant.Summary, "fail-open") ||
		tenant.Fields["scope"] != "tenant" || tenant.Fields["tenant"] != "team-a" {
		t.Errorf("tenant event summary/fields = %q / %v", tenant.Summary, tenant.Fields)
	}

	global := LLMPackageBudgetEvent("global", "", false)
	if global.Severity != SeverityHigh {
		t.Errorf("refusing unscanned pulls is the more severe mode: severity = %s", global.Severity)
	}
	if !strings.Contains(global.Summary, "global") || !strings.Contains(global.Summary, "fail-closed") ||
		global.Fields["scope"] != "global" || global.Fields["tenant"] != "(none)" {
		t.Errorf("global event summary/fields = %q / %v", global.Summary, global.Fields)
	}
	if !strings.Contains(global.Title, "package-scan") {
		t.Errorf("title = %q: it must be distinguishable from the commit-scan budget alert", global.Title)
	}
}
