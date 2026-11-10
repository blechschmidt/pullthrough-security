package findings

import (
	"encoding/json"
	"testing"
)

// validateSARIF asserts the structural conformance of a rendered log against the
// SARIF 2.1.0 object model the proxy relies on. It is intentionally a hand-rolled
// validator (no external JSON-schema dependency, consistent with the project's
// dependency-light, offline-friendly philosophy) that checks the invariants
// GitHub/GitLab ingestion requires: the $schema/version header, a named tool
// driver, every result referencing a defined rule by id and a valid in-range
// index, a valid level enum, and at least one location.
func validateSARIF(t *testing.T, log Log) {
	t.Helper()

	if log.Schema != SARIFSchema {
		t.Errorf("$schema = %q, want %q", log.Schema, SARIFSchema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) == 0 {
		t.Fatal("log has no runs")
	}
	validLevels := map[string]bool{"error": true, "warning": true, "note": true, "none": true}

	for ri, run := range log.Runs {
		if run.Tool.Driver.Name == "" {
			t.Errorf("run[%d] driver has no name", ri)
		}
		// Build the rule-id -> index map and assert ids are unique and configs valid.
		ruleByID := map[string]int{}
		for i, rule := range run.Tool.Driver.Rules {
			if rule.ID == "" {
				t.Errorf("run[%d] rule[%d] has empty id", ri, i)
			}
			if _, dup := ruleByID[rule.ID]; dup {
				t.Errorf("run[%d] duplicate rule id %q", ri, rule.ID)
			}
			ruleByID[rule.ID] = i
			if rule.DefaultConfiguration != nil && !validLevels[rule.DefaultConfiguration.Level] {
				t.Errorf("run[%d] rule %q default level %q invalid", ri, rule.ID, rule.DefaultConfiguration.Level)
			}
		}
		for i, res := range run.Results {
			if res.RuleID == "" {
				t.Errorf("run[%d] result[%d] has empty ruleId", ri, i)
			}
			idx, ok := ruleByID[res.RuleID]
			if !ok {
				t.Errorf("run[%d] result[%d] ruleId %q has no matching rule", ri, i, res.RuleID)
			} else if res.RuleIndex != idx {
				t.Errorf("run[%d] result[%d] ruleIndex = %d, but rule %q is at index %d", ri, i, res.RuleIndex, res.RuleID, idx)
			}
			if !validLevels[res.Level] {
				t.Errorf("run[%d] result[%d] level %q invalid", ri, i, res.Level)
			}
			if res.Message.Text == "" {
				t.Errorf("run[%d] result[%d] has empty message", ri, i)
			}
			if len(res.Locations) == 0 {
				t.Errorf("run[%d] result[%d] has no locations", ri, i)
			}
			for li, loc := range res.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI == "" {
					t.Errorf("run[%d] result[%d] location[%d] physicalLocation has empty uri", ri, i, li)
				}
			}
		}
	}

	// The rendered log must round-trip through encoding/json without loss, since
	// that is exactly how it is served and consumed.
	b, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["$schema"] != SARIFSchema {
		t.Errorf("round-tripped $schema = %v", back["$schema"])
	}
}
