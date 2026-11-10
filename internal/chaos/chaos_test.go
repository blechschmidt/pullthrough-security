package chaos

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestResilienceGuarantees is the table-driven resilience gate: it runs every
// guarantee in the catalog and fails on any violation. The catalog is the table
// — adding a Guarantee adds a subtest automatically, and the same catalog is
// what the documented resilience matrix (docs/resilience.md) is generated from,
// so the documentation can never silently drift from the verified behavior.
func TestResilienceGuarantees(t *testing.T) {
	for _, g := range Guarantees() {
		g := g
		t.Run(g.ID, func(t *testing.T) {
			t.Parallel()
			if err := g.verify(context.Background()); err != nil {
				t.Errorf("[%s] %s\n  condition:   %s\n  expectation: %s\n  deviation:   %v",
					g.Dependency, g.ID, g.Condition, g.Expectation, err)
			}
		})
	}
}

// TestCatalogIsWellFormed guards the catalog's contract: unique IDs, every field
// populated, and coverage of each dependency class the task requires.
func TestCatalogIsWellFormed(t *testing.T) {
	gs := Guarantees()
	if len(gs) < 10 {
		t.Fatalf("catalog has %d guarantees, expected at least 10", len(gs))
	}
	seen := map[string]bool{}
	deps := map[string]bool{}
	for _, g := range gs {
		if g.ID == "" || g.Dependency == "" || g.Condition == "" || g.Expectation == "" || g.Mechanism == "" {
			t.Errorf("guarantee %q has an empty required field: %+v", g.ID, g)
		}
		if g.verify == nil {
			t.Errorf("guarantee %q has no verifier", g.ID)
		}
		if seen[g.ID] {
			t.Errorf("duplicate guarantee ID %q", g.ID)
		}
		seen[g.ID] = true
		deps[g.Dependency] = true
	}
	for _, want := range []string{DepUpstream, DepStorage, DepScanner} {
		if !deps[want] {
			t.Errorf("catalog does not cover required dependency %q", want)
		}
	}
}

// TestRunReportsAllPass asserts Run upholds every guarantee and tallies cleanly.
func TestRunReportsAllPass(t *testing.T) {
	rep, err := Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Total != len(Guarantees()) {
		t.Errorf("report total = %d, want %d", rep.Total, len(Guarantees()))
	}
	if rep.Failed != 0 {
		for _, res := range rep.Results {
			if !res.Pass {
				t.Errorf("guarantee %s violated: %s", res.ID, res.Detail)
			}
		}
	}
	if rep.Passed != rep.Total {
		t.Errorf("passed = %d, want %d", rep.Passed, rep.Total)
	}
}

// TestReportRenders checks the JSON round-trips and the Markdown matrix names
// every guarantee (the formats an operator / CI consumes).
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
	if round.Total != rep.Total || round.Passed != rep.Passed {
		t.Errorf("JSON round-trip mismatch: %+v vs %+v", round, rep)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "resilience matrix") {
		t.Errorf("Markdown missing header:\n%s", md)
	}
	for _, g := range Guarantees() {
		if !strings.Contains(md, g.ID) {
			t.Errorf("Markdown missing guarantee %q", g.ID)
		}
	}
}
