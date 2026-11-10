package gatedoc

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// TestCatalogCoversEveryFindingsGate anchors the gate reference to the findings
// SARIF rule catalog: every gate that owns a rule there must be documented here
// exactly once. A new gate+rule added to internal/findings without a matching
// gatedoc entry fails this test, so new gates stay documented.
func TestCatalogCoversEveryFindingsGate(t *testing.T) {
	documented := map[findings.Gate]int{}
	for _, g := range catalog {
		if g.FindingsGate != "" {
			documented[g.FindingsGate]++
		}
	}
	for _, fg := range findings.CatalogGates() {
		switch documented[fg] {
		case 0:
			t.Errorf("findings gate %q has SARIF rules but no gatedoc catalog entry; add it to internal/gatedoc", fg)
		case 1:
			// exactly one — good
		default:
			t.Errorf("findings gate %q is documented by %d gatedoc entries; expected exactly one", fg, documented[fg])
		}
	}
}

// TestFindingsGatesResolve ensures every entry that claims to be findings-backed
// actually owns at least one rule in the catalog (catching a typo or a removed
// rule), and that such an entry carries no redundant curated categories (the
// generator derives them live).
func TestFindingsGatesResolve(t *testing.T) {
	for _, g := range catalog {
		if g.FindingsGate == "" {
			if len(g.Categories) == 0 {
				t.Errorf("decision-only gate %q must document its Categories", g.Name)
			}
			continue
		}
		if len(findings.RulesForGate(g.FindingsGate)) == 0 {
			t.Errorf("gate %q references findings gate %q which owns no catalog rule", g.Name, g.FindingsGate)
		}
		if len(g.Categories) != 0 {
			t.Errorf("findings-backed gate %q must leave Categories empty (categories are derived from the rule catalog)", g.Name)
		}
		if len(g.RuleIDs()) == 0 {
			t.Errorf("findings-backed gate %q derived no SARIF rule ids", g.Name)
		}
	}
}

// TestConfigPathsResolve ties every documented config path back to the live
// config schema, so a renamed or removed gate config key fails the build rather
// than leaving the reference silently wrong.
func TestConfigPathsResolve(t *testing.T) {
	for _, g := range catalog {
		if !config.YAMLPathExists(g.ConfigPath) {
			t.Errorf("gate %q documents config path %q which does not resolve in the config schema", g.Name, g.ConfigPath)
		}
	}
}

// TestCatalogWellFormed checks structural invariants: unique names, non-empty
// required fields, and at least one action per gate.
func TestCatalogWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range catalog {
		if g.Name == "" {
			t.Error("catalog entry with empty Name")
			continue
		}
		if seen[g.Name] {
			t.Errorf("duplicate gate name %q", g.Name)
		}
		seen[g.Name] = true
		if g.Package == "" {
			t.Errorf("gate %q missing Package", g.Name)
		}
		if !strings.HasPrefix(g.Package, "internal/") {
			t.Errorf("gate %q package %q is not under internal/", g.Name, g.Package)
		}
		if g.Trigger == "" {
			t.Errorf("gate %q missing Trigger", g.Name)
		}
		if len(g.Actions) == 0 {
			t.Errorf("gate %q documents no actions", g.Name)
		}
		if g.Summary == "" {
			t.Errorf("gate %q missing Summary", g.Name)
		}
		if g.MetricPrefix != "" && !strings.HasPrefix(g.MetricPrefix, "pullthrough_") {
			t.Errorf("gate %q metric prefix %q does not start with pullthrough_", g.Name, g.MetricPrefix)
		}
	}
}

// TestGenerateReferenceDeterministic ensures repeated renders are byte-identical
// (no map iteration leaks into the output) so the staleness gate is stable.
func TestGenerateReferenceDeterministic(t *testing.T) {
	first := GenerateReference()
	for i := 0; i < 5; i++ {
		if got := GenerateReference(); got != first {
			t.Fatalf("GenerateReference is non-deterministic on run %d", i)
		}
	}
	if !strings.Contains(first, "# Admission gate reference (generated)") {
		t.Error("rendered reference missing expected header")
	}
	// Every gate name must appear in the rendered table.
	for _, name := range sortedNames() {
		if !strings.Contains(first, "`"+name+"`") {
			t.Errorf("rendered reference does not mention gate %q", name)
		}
	}
	// Every derived SARIF rule id must appear.
	for _, g := range catalog {
		for _, id := range g.RuleIDs() {
			if !strings.Contains(first, "`"+id+"`") {
				t.Errorf("rendered reference missing SARIF rule id %q for gate %q", id, g.Name)
			}
		}
	}
}
