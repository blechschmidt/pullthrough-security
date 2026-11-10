package muttest

import "testing"

// committedBaselinePath is the repo's mutation baseline, relative to this
// package directory.
const committedBaselinePath = "../../mutation/mutation-baseline.json"

// TestCommittedBaselineDecodes guards mutation/mutation-baseline.json against
// drift that would make the `make mutation` CI gate fail to load it — the
// mutation-score analogue of covguard's committed-baseline guard.
func TestCommittedBaselineDecodes(t *testing.T) {
	b, err := LoadBaseline(committedBaselinePath)
	if err != nil {
		t.Fatalf("LoadBaseline(%s): %v", committedBaselinePath, err)
	}

	if b.SchemaVersion != BaselineSchemaVersion {
		t.Errorf("schema version = %d, want %d", b.SchemaVersion, BaselineSchemaVersion)
	}
	if len(b.Operators) == 0 {
		t.Error("baseline records no operators")
	}
	if b.MaxPerPackage < 0 {
		t.Errorf("maxPerPackage = %d, want >= 0", b.MaxPerPackage)
	}

	// Total and per-package scores must be sane percentages consistent with their
	// killed/scored counts.
	checkScore := func(name string, s PackageScore) {
		if s.Pct < 0 || s.Pct > 100 {
			t.Errorf("%s: score %.2f%% out of range", name, s.Pct)
		}
		if s.Killed < 0 || s.Survived < 0 || s.Invalid < 0 {
			t.Errorf("%s: negative tally %+v", name, s)
		}
		if s.Scored != s.Killed+s.Survived {
			t.Errorf("%s: scored %d != killed+survived %d", name, s.Scored, s.Killed+s.Survived)
		}
	}
	checkScore("total", b.Total)
	if len(b.Packages) == 0 {
		t.Fatal("baseline contains no packages")
	}
	for name, ps := range b.Packages {
		checkScore(name, ps)
	}

	// The highest-risk gate packages must be represented so a dropped target is
	// caught rather than silently un-tested.
	for _, want := range []string{
		"github.com/blechschmidt/pullthrough-security/internal/vulnscan",
		"github.com/blechschmidt/pullthrough-security/internal/sigverify",
		"github.com/blechschmidt/pullthrough-security/internal/policyengine",
	} {
		if _, ok := b.Packages[want]; !ok {
			t.Errorf("baseline missing critical gate package %s", want)
		}
	}

	// Every critical floor must reference a package that is in the baseline and
	// must sit at or below that package's recorded score — otherwise the gate is
	// pre-failed and can never pass.
	for pkg, floor := range b.CriticalFloors {
		if floor <= 0 || floor > 100 {
			t.Errorf("critical floor for %s = %.2f, want in (0,100]", pkg, floor)
		}
		ps, ok := b.Packages[pkg]
		if !ok {
			t.Errorf("critical floor set for %s, which is not in the baseline", pkg)
			continue
		}
		if floor > ps.Pct+1e-9 {
			t.Errorf("critical floor for %s (%.1f%%) exceeds its baseline score (%.1f%%): gate is pre-failed", pkg, floor, ps.Pct)
		}
	}
}
