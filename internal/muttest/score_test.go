package muttest

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mkBaseline(total PackageScore, pkgs map[string]PackageScore) *Baseline {
	b := &Baseline{
		SchemaVersion: BaselineSchemaVersion,
		CapturedAt:    time.Now().UTC(),
		Tool:          "test",
		Seed:          1,
		Operators:     DefaultOperators(),
		Total:         total,
		Packages:      pkgs,
	}
	b.Total.recompute()
	for k, v := range b.Packages {
		v.recompute()
		b.Packages[k] = v
	}
	return b
}

func TestScoreRecompute(t *testing.T) {
	s := PackageScore{Killed: 8, Survived: 2, Invalid: 5}
	s.recompute()
	if s.Scored != 10 {
		t.Fatalf("scored = %d, want 10", s.Scored)
	}
	if s.Pct != 80 {
		t.Fatalf("pct = %v, want 80", s.Pct)
	}
	// A package with no scored mutants is 100% (nothing could survive).
	z := PackageScore{Invalid: 3}
	z.recompute()
	if z.Pct != 100 {
		t.Fatalf("empty score pct = %v, want 100", z.Pct)
	}
}

func TestCompareTotalRegression(t *testing.T) {
	base := mkBaseline(PackageScore{Killed: 80, Survived: 20}, map[string]PackageScore{
		"p/a": {Killed: 80, Survived: 20},
	})
	// Current drops to 76% total: a 4-point drop.
	cur := mkBaseline(PackageScore{Killed: 76, Survived: 24}, map[string]PackageScore{
		"p/a": {Killed: 76, Survived: 24},
	})

	// Within tolerance (5 pts): pass.
	r := Compare(base, cur, Policy{AllowedTotalDropPct: 5})
	if r.Regressed() {
		t.Errorf("expected pass within 5pt tolerance, report:\n%s", r.Format(0))
	}
	// Tight tolerance (2 pts): fail.
	r = Compare(base, cur, Policy{AllowedTotalDropPct: 2})
	if !r.Regressed() {
		t.Errorf("expected regression under 2pt tolerance")
	}
	if r.RegressionCount() < 1 {
		t.Errorf("expected at least 1 regression counted")
	}
}

func TestCompareCriticalFloor(t *testing.T) {
	base := mkBaseline(PackageScore{Killed: 90, Survived: 10}, map[string]PackageScore{
		"p/sig": {Killed: 70, Survived: 30}, // 70%
	})
	cur := mkBaseline(PackageScore{Killed: 90, Survived: 10}, map[string]PackageScore{
		"p/sig": {Killed: 70, Survived: 30}, // still 70%, total unchanged
	})
	// Floor of 80% on p/sig must fail even though nothing regressed vs baseline.
	r := Compare(base, cur, Policy{AllowedTotalDropPct: 5, CriticalFloors: map[string]float64{"p/sig": 80}})
	if !r.Regressed() {
		t.Fatalf("expected floor violation to fail the gate")
	}
	fv := r.FloorViolations()
	if len(fv) != 1 || fv[0].Package != "p/sig" {
		t.Fatalf("expected 1 floor violation on p/sig, got %+v", fv)
	}
}

func TestCompareRemovedCriticalPackage(t *testing.T) {
	base := mkBaseline(PackageScore{Killed: 90, Survived: 10}, map[string]PackageScore{
		"p/sig": {Killed: 90, Survived: 10},
	})
	cur := mkBaseline(PackageScore{Killed: 0, Survived: 0, Invalid: 1}, map[string]PackageScore{
		"p/other": {Killed: 1, Survived: 0},
	})
	r := Compare(base, cur, Policy{AllowedTotalDropPct: 100, CriticalFloors: map[string]float64{"p/sig": 50}})
	if !r.Regressed() {
		t.Fatalf("a removed critical package must fail the gate")
	}
	var found bool
	for _, p := range r.Packages {
		if p.Package == "p/sig" && p.State == "removed" && p.FloorViolated {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected p/sig to be reported removed + floor-violated")
	}
}

func TestComparePerPackageDrop(t *testing.T) {
	base := mkBaseline(PackageScore{Killed: 100, Survived: 0}, map[string]PackageScore{
		"p/a": {Killed: 100, Survived: 0}, // 100%
		"p/b": {Killed: 100, Survived: 0}, // 100%
	})
	// p/b collapses to 50% but the total stays high enough to pass the total gate.
	cur := mkBaseline(PackageScore{Killed: 150, Survived: 50}, map[string]PackageScore{
		"p/a": {Killed: 100, Survived: 0},
		"p/b": {Killed: 50, Survived: 50},
	})
	r := Compare(base, cur, Policy{AllowedTotalDropPct: 50, AllowedPackageDropPct: 10})
	if !r.Regressed() {
		t.Fatalf("expected per-package drop gate to fail on p/b")
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	b := mkBaseline(PackageScore{Killed: 42, Survived: 8}, map[string]PackageScore{
		"p/a": {Killed: 42, Survived: 8},
	})
	b.CriticalFloors = map[string]float64{"p/a": 70}
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "mutation-baseline.json")
	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if got.Total.Pct != b.Total.Pct {
		t.Errorf("total pct mismatch: %v vs %v", got.Total.Pct, b.Total.Pct)
	}
	if got.CriticalFloors["p/a"] != 70 {
		t.Errorf("critical floor not round-tripped: %+v", got.CriticalFloors)
	}
}

func TestFromRun(t *testing.T) {
	run := &RunResult{
		Seed:      7,
		Operators: []string{OpROR, OpLCR},
		Packages: []PackageRun{
			{Package: "p/a", Killed: 9, Survived: 1, Invalid: 2},
			{Package: "p/b", Killed: 5, Survived: 5, Invalid: 0},
		},
	}
	b := FromRun(run)
	if b.Total.Killed != 14 || b.Total.Survived != 6 {
		t.Fatalf("total tally wrong: %+v", b.Total)
	}
	if b.Total.Pct != 70 {
		t.Fatalf("total pct = %v, want 70", b.Total.Pct)
	}
	if b.Packages["p/a"].Pct != 90 {
		t.Fatalf("p/a pct = %v, want 90", b.Packages["p/a"].Pct)
	}
}

func TestMarkdownAndFormatSmoke(t *testing.T) {
	base := mkBaseline(PackageScore{Killed: 80, Survived: 20}, map[string]PackageScore{
		"p/a": {Killed: 80, Survived: 20},
	})
	cur := mkBaseline(PackageScore{Killed: 70, Survived: 30}, map[string]PackageScore{
		"p/a": {Killed: 70, Survived: 30},
	})
	r := Compare(base, cur, Policy{AllowedTotalDropPct: 2})
	r.Survivors = []MutantResult{{Mutant: Mutant{ID: "abc123", File: "p/a/x.go", Line: 10, Col: 4, Operator: OpROR, Original: "<", Mutated: "<="}, Status: StatusSurvived}}

	md := r.Markdown(10)
	if !strings.Contains(md, "Mutation guard") || !strings.Contains(md, "abc123") {
		t.Errorf("markdown missing expected content:\n%s", md)
	}
	txt := r.Format(10)
	if !strings.Contains(txt, "RESULT: FAIL") || !strings.Contains(txt, "Surviving mutants") {
		t.Errorf("format missing expected content:\n%s", txt)
	}
}
