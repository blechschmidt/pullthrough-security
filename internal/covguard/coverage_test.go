package covguard

import (
	"path/filepath"
	"strings"
	"testing"
)

const sampleProfile = `mode: count
github.com/acme/proj/internal/cache/cache.go:10.1,12.2 3 1
github.com/acme/proj/internal/cache/cache.go:14.1,16.2 2 0
github.com/acme/proj/internal/proxy/proxy.go:20.1,21.2 1 5
github.com/acme/proj/internal/proxy/proxy.go:22.1,23.2 1 0
github.com/acme/proj/internal/proxy/serve.go:30.1,31.2 2 1
`

func TestParseProfile(t *testing.T) {
	b, err := ParseProfile(strings.NewReader(sampleProfile))
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if b.Mode != "count" {
		t.Errorf("mode = %q, want count", b.Mode)
	}
	// cache: 3 covered of 5; proxy: 1+2=3 covered of 1+1+2=4.
	cache := b.Packages["github.com/acme/proj/internal/cache"]
	if cache.Covered != 3 || cache.Total != 5 {
		t.Errorf("cache = %+v, want covered 3 total 5", cache)
	}
	if got := cache.Pct; got != 60 {
		t.Errorf("cache pct = %v, want 60", got)
	}
	proxy := b.Packages["github.com/acme/proj/internal/proxy"]
	if proxy.Covered != 3 || proxy.Total != 4 {
		t.Errorf("proxy = %+v, want covered 3 total 4", proxy)
	}
	// total: 6 covered of 9 = 66.66%.
	if b.Total.Covered != 6 || b.Total.Total != 9 {
		t.Errorf("total = %+v, want covered 6 total 9", b.Total)
	}
	if b.Total.Pct < 66.6 || b.Total.Pct > 66.7 {
		t.Errorf("total pct = %v, want ~66.67", b.Total.Pct)
	}
}

func TestParseProfileErrors(t *testing.T) {
	cases := map[string]string{
		"no mode header":  "github.com/x/y.go:1.1,2.2 1 1\n",
		"empty":           "mode: set\n",
		"bad stmt count":  "mode: set\ngithub.com/x/y.go:1.1,2.2 x 1\n",
		"too few fields":  "mode: set\ngithub.com/x/y.go:1.1,2.2 1\n",
		"no colon in pos": "mode: set\ngithubxygo 1 1\n",
	}
	for name, in := range cases {
		if _, err := ParseProfile(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	b, err := ParseProfile(strings.NewReader(sampleProfile))
	if err != nil {
		t.Fatal(err)
	}
	b.CriticalFloors = map[string]float64{"github.com/acme/proj/internal/cache": 50}
	path := filepath.Join(t.TempDir(), "sub", "coverage-baseline.json")
	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if got.Total != b.Total {
		t.Errorf("total mismatch: %+v vs %+v", got.Total, b.Total)
	}
	if got.CriticalFloors["github.com/acme/proj/internal/cache"] != 50 {
		t.Errorf("floors not round-tripped: %+v", got.CriticalFloors)
	}
}

func TestDecodeBaselineSchemaMismatch(t *testing.T) {
	_, err := DecodeBaseline(strings.NewReader(`{"schemaVersion":999,"packages":{"x":{"coveredStatements":1,"totalStatements":1}}}`))
	if err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("want schema version error, got %v", err)
	}
}

// makeBaseline builds a baseline from package->pct with a fixed 100-statement
// denominator so percentages map cleanly to counts.
func makeBaseline(total float64, pkgs map[string]float64) *Baseline {
	b := &Baseline{SchemaVersion: BaselineSchemaVersion, Packages: map[string]Coverage{}}
	b.Total = Coverage{Covered: int(total), Total: 100}
	b.Total.recompute()
	for name, pct := range pkgs {
		c := Coverage{Covered: int(pct), Total: 100}
		c.recompute()
		b.Packages[name] = c
	}
	return b
}

func TestCompareTotalGate(t *testing.T) {
	base := makeBaseline(80, map[string]float64{"a": 80})
	// Drop of exactly the allowance is tolerated.
	cur := makeBaseline(79, map[string]float64{"a": 79})
	rep := Compare(base, cur, Policy{AllowedTotalDropPct: 1})
	if rep.Total.Regressed {
		t.Errorf("drop of exactly 1pt should be tolerated: %+v", rep.Total)
	}
	if rep.Regressed() {
		t.Errorf("report should pass")
	}

	// A drop beyond the allowance fails.
	cur2 := makeBaseline(78, map[string]float64{"a": 78})
	rep2 := Compare(base, cur2, Policy{AllowedTotalDropPct: 1})
	if !rep2.Total.Regressed || !rep2.Regressed() {
		t.Errorf("2pt drop with 1pt budget should fail: %+v", rep2.Total)
	}
	if rep2.RegressionCount() != 1 {
		t.Errorf("regression count = %d, want 1", rep2.RegressionCount())
	}

	// An improvement never regresses.
	cur3 := makeBaseline(90, map[string]float64{"a": 90})
	if Compare(base, cur3, Policy{AllowedTotalDropPct: 1}).Regressed() {
		t.Errorf("improvement should not regress")
	}
}

func TestCompareCriticalFloor(t *testing.T) {
	base := makeBaseline(80, map[string]float64{"crit": 85, "other": 70})
	cur := makeBaseline(80, map[string]float64{"crit": 74, "other": 70})
	policy := Policy{AllowedTotalDropPct: 5, CriticalFloors: map[string]float64{"crit": 75}}
	rep := Compare(base, cur, policy)
	if !rep.Regressed() {
		t.Fatalf("critical package below floor should fail")
	}
	fv := rep.FloorViolations()
	if len(fv) != 1 || fv[0].Package != "crit" {
		t.Fatalf("want one floor violation on crit, got %+v", fv)
	}
	// At the floor exactly is allowed.
	cur2 := makeBaseline(80, map[string]float64{"crit": 75, "other": 70})
	if Compare(base, cur2, policy).Regressed() {
		t.Errorf("exactly at floor should pass")
	}
}

func TestCompareCriticalRemoved(t *testing.T) {
	base := makeBaseline(80, map[string]float64{"crit": 85})
	cur := makeBaseline(80, map[string]float64{"other": 85})
	policy := Policy{AllowedTotalDropPct: 50, CriticalFloors: map[string]float64{"crit": 75}}
	rep := Compare(base, cur, policy)
	if !rep.Regressed() {
		t.Fatalf("removed critical package should fail")
	}
	var removed *PackageDelta
	for i := range rep.Packages {
		if rep.Packages[i].Package == "crit" {
			removed = &rep.Packages[i]
		}
	}
	if removed == nil || removed.State != "removed" || !removed.FloorViolated {
		t.Fatalf("crit should be a removed floor violation: %+v", removed)
	}
}

func TestComparePackageDropGate(t *testing.T) {
	base := makeBaseline(80, map[string]float64{"a": 90, "b": 70})
	cur := makeBaseline(80, map[string]float64{"a": 80, "b": 70})
	// Without the per-package gate, a single-package drop does not fail.
	if Compare(base, cur, Policy{AllowedTotalDropPct: 5}).Regressed() {
		t.Errorf("per-package drop should not fail when gate is off")
	}
	// With a 5pt per-package gate, a's 10pt drop fails.
	rep := Compare(base, cur, Policy{AllowedTotalDropPct: 5, AllowedPackageDropPct: 5})
	if !rep.Regressed() {
		t.Errorf("per-package drop beyond gate should fail")
	}
}

func TestCompareNewAndDrops(t *testing.T) {
	base := makeBaseline(80, map[string]float64{"a": 90, "b": 60})
	cur := makeBaseline(80, map[string]float64{"a": 85, "b": 60, "c": 40})
	rep := Compare(base, cur, Policy{AllowedTotalDropPct: 5})
	// Sorted biggest-drop first: a dropped 5pts and should lead.
	if rep.Packages[0].Package != "a" || rep.Packages[0].DeltaPct != -5 {
		t.Errorf("expected a (-5) first, got %+v", rep.Packages[0])
	}
	// c is new.
	var newPkg *PackageDelta
	for i := range rep.Packages {
		if rep.Packages[i].Package == "c" {
			newPkg = &rep.Packages[i]
		}
	}
	if newPkg == nil || newPkg.State != "new" {
		t.Fatalf("c should be new: %+v", newPkg)
	}
	drops := rep.drops(0)
	if len(drops) != 1 || drops[0].Package != "a" {
		t.Errorf("expected one drop (a), got %+v", drops)
	}
}

func TestFormatAndMarkdown(t *testing.T) {
	base := makeBaseline(80, map[string]float64{"a": 90, "crit": 85})
	cur := makeBaseline(76, map[string]float64{"a": 70, "crit": 70})
	policy := Policy{AllowedTotalDropPct: 1, CriticalFloors: map[string]float64{"crit": 75}}
	rep := Compare(base, cur, policy)
	txt := rep.Format(10)
	if !strings.Contains(txt, "RESULT: FAIL") {
		t.Errorf("text report should FAIL:\n%s", txt)
	}
	if !strings.Contains(txt, "floor violations") {
		t.Errorf("text report should mention floor violations:\n%s", txt)
	}
	md := rep.Markdown(10)
	if !strings.Contains(md, "❌ FAIL") || !strings.Contains(md, "Total coverage") {
		t.Errorf("markdown missing expected content:\n%s", md)
	}
}
