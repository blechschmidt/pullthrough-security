package siem

import (
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

func sampleDocument() findings.Document {
	return findings.Document{
		Tenant: "team-a",
		Artifact: findings.Artifact{
			Ecosystem:  "npm",
			Backend:    "npmjs",
			Name:       "lodash",
			Version:    "1.0.0",
			Coordinate: "npm/lodash@1.0.0",
		},
		GeneratedAt: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Findings: []findings.Finding{
			{
				RuleID:     "vulnscan/CVE",
				Gate:       findings.GateVulnscan,
				Severity:   findings.SeverityCritical,
				Level:      findings.LevelError,
				Identifier: "CVE-2026-0001",
				Title:      "Critical RCE",
				Message:    "remote code execution in lodash",
				Location:   findings.Location{Coordinate: "npm/lodash@1.0.0"},
			},
			{
				RuleID:   "license/denied",
				Gate:     findings.GateLicense,
				Severity: findings.SeverityMedium,
				Level:    findings.LevelWarning,
				Title:    "Disallowed license",
				Message:  "GPL-3.0 is not on the allowlist",
			},
		},
	}
}

func sampleAuditRecord() audit.Record {
	return audit.Record{
		Seq:      42,
		PrevHash: "abc",
		Hash:     "def",
		Event: audit.Event{
			Type:       audit.EventPolicy,
			Time:       time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC),
			Subject:    "svc-ci",
			Team:       "team-a",
			Method:     "GET",
			Backend:    "npmjs",
			Ecosystem:  "npm",
			Resource:   "lodash@1.0.0",
			RemoteAddr: "10.0.0.5",
			Status:     403,
			Decision:   audit.DecisionDeny,
			Reason:     "policy block: critical CVE",
			Detail:     map[string]any{"ruleId": "no-critical", "score": 95},
		},
	}
}

func TestEventFromAuditRecord(t *testing.T) {
	e := EventFromAuditRecord(sampleAuditRecord())
	if e.Source != SourceAudit {
		t.Fatalf("source = %q, want audit", e.Source)
	}
	if e.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want high (policy deny)", e.Severity)
	}
	if e.Category != string(audit.EventPolicy) {
		t.Fatalf("category = %q", e.Category)
	}
	if e.Outcome != string(audit.DecisionDeny) {
		t.Fatalf("outcome = %q, want deny", e.Outcome)
	}
	if e.Fields["seq"] != "42" {
		t.Fatalf("seq field = %q, want 42", e.Fields["seq"])
	}
	if e.Fields["hash"] != "def" || e.Fields["prevHash"] != "abc" {
		t.Fatalf("chain fields not preserved: %+v", e.Fields)
	}
	if e.Fields["status"] != "403" {
		t.Fatalf("status field = %q, want 403", e.Fields["status"])
	}
	if e.Fields["detail.ruleId"] != "no-critical" {
		t.Fatalf("detail.ruleId = %q", e.Fields["detail.ruleId"])
	}
	if e.Fields["detail.score"] != "95" {
		t.Fatalf("detail.score = %q, want 95", e.Fields["detail.score"])
	}
}

func TestEventFromFinding(t *testing.T) {
	doc := sampleDocument()
	e := EventFromFinding(doc, doc.Findings[0])
	if e.Source != SourceFinding {
		t.Fatalf("source = %q, want finding", e.Source)
	}
	if e.Severity != SeverityCritical {
		t.Fatalf("severity = %q, want critical", e.Severity)
	}
	if e.Category != "vulnscan" {
		t.Fatalf("category = %q, want vulnscan", e.Category)
	}
	if e.Subject != "team-a" {
		t.Fatalf("subject = %q, want team-a", e.Subject)
	}
	if e.Fields["identifier"] != "CVE-2026-0001" {
		t.Fatalf("identifier = %q", e.Fields["identifier"])
	}
	if e.Fields["coordinate"] != "npm/lodash@1.0.0" {
		t.Fatalf("coordinate = %q", e.Fields["coordinate"])
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Fatal("critical should be >= high")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Fatal("low should not be >= high")
	}
	if NormalizeSeverity("bogus") != SeverityInfo {
		t.Fatal("unknown severity should normalize to info")
	}
	if !ValidSeverity("") || !ValidSeverity("critical") || ValidSeverity("nope") {
		t.Fatal("ValidSeverity wrong")
	}
}
