package redteam

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestSuite_NoRegressions is the CI regression gate (Task 76). It runs the full
// synthetic attack catalog end-to-end through in-process gateways and fails if
// any scenario does not meet its assertion — most importantly, if any
// expect-block attack regresses to "admitted" (a defense silently going
// block→admit). This is the test the CI job runs.
func TestSuite_NoRegressions(t *testing.T) {
	rep, err := Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Total == 0 {
		t.Fatal("empty scenario catalog")
	}
	t.Logf("red-team suite: %d total, %d passed, %d failed, %d regressions",
		rep.Total, rep.Passed, rep.Failed, rep.Regressions)

	for _, res := range rep.Results {
		if res.Pass {
			continue
		}
		if res.Regression {
			t.Errorf("REGRESSION %s [%s]: %s (status %d, fired %q)",
				res.Scenario, res.ExpectedGate, res.Detail, res.Status, res.FiredGate)
			continue
		}
		t.Errorf("FAIL %s [%s]: %s (status %d, fired %q)",
			res.Scenario, res.ExpectedGate, res.Detail, res.Status, res.FiredGate)
	}
}

// TestEveryScenario_IsExercised guards against a scenario silently being dropped
// from the catalog: the count and the unique-ID invariant are part of the
// contract, and every expect-block scenario must name a gate the detector knows.
func TestEveryScenario_IsExercised(t *testing.T) {
	scenarios := Scenarios()
	if len(scenarios) < 13 {
		t.Fatalf("catalog has %d scenarios, expected at least 13", len(scenarios))
	}
	seen := map[string]bool{}
	known := map[string]bool{}
	for _, gh := range blockHeaders {
		known[gh.gate] = true
	}
	for _, sc := range scenarios {
		if sc.ID == "" || sc.Name == "" || sc.ExpectedGate == "" {
			t.Errorf("scenario %+v has empty required fields", sc)
		}
		if seen[sc.ID] {
			t.Errorf("duplicate scenario ID %q", sc.ID)
		}
		seen[sc.ID] = true

		accept := sc.AcceptGates
		if len(accept) == 0 {
			accept = []string{sc.ExpectedGate}
		}
		for _, g := range accept {
			if !known[g] {
				t.Errorf("scenario %q accepts gate %q with no known decision header", sc.ID, g)
			}
		}
	}
}

// TestCategoryCoverage asserts the catalog covers every attack class the task
// requires, so a future edit cannot quietly remove a whole category.
func TestCategoryCoverage(t *testing.T) {
	required := []string{
		"typosquat", "dependency-confusion", "known-malicious", "version-pin-violation",
		"version-cooldown", "missing-signature", "forged-provenance", "install-hook",
		"embedded-secret", "critical-cve", "vex-suppression", "license-violation",
		"reproducible-build-mismatch",
	}
	have := map[string]bool{}
	for _, sc := range Scenarios() {
		have[sc.Category] = true
	}
	for _, c := range required {
		if !have[c] {
			t.Errorf("missing required attack category %q", c)
		}
	}
}

// TestReportRenders checks the JSON and Markdown emitters produce non-empty,
// well-formed output (the formats `ptctl redteam` serves).
func TestReportRenders(t *testing.T) {
	rep, err := Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	js, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var round Report
	if err := json.Unmarshal(js, &round); err != nil {
		t.Fatalf("JSON round-trip: %v", err)
	}
	if round.Total != rep.Total {
		t.Errorf("JSON total = %d, want %d", round.Total, rep.Total)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "red-team gate-efficacy report") {
		t.Errorf("Markdown missing header:\n%s", md)
	}
	for _, res := range rep.Results {
		if !strings.Contains(md, res.Name) {
			t.Errorf("Markdown missing scenario %q", res.Name)
		}
	}
}
