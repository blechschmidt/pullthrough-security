package prewarm

import (
	"context"
	"testing"
	"time"
)

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in         string
		ok         bool
		maj        int
		min        int
		pat        int
		prerelease bool
	}{
		{"1.2.3", true, 1, 2, 3, false},
		{"v1.2.3", true, 1, 2, 3, false},
		{"1.2", true, 1, 2, 0, false},
		{"1.2.3-rc1", true, 1, 2, 3, true},
		{"1.2.3+build5", true, 1, 2, 3, false},
		{"2023.1.0", true, 2023, 1, 0, false},
		{"not-a-version", false, 0, 0, 0, false},
		{"", false, 0, 0, 0, false},
		{"1", false, 0, 0, 0, false},
	}
	for _, c := range cases {
		sv, ok := parseSemver(c.in)
		if ok != c.ok {
			t.Errorf("parseSemver(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if sv.major != c.maj || sv.minor != c.min || sv.patch != c.pat || sv.prerelease != c.prerelease {
			t.Errorf("parseSemver(%q)=%+v, want %d.%d.%d pre=%v", c.in, sv, c.maj, c.min, c.pat, c.prerelease)
		}
	}
}

func TestSemverGreaterPrefersStable(t *testing.T) {
	stable, _ := parseSemver("1.2.3")
	pre, _ := parseSemver("1.2.3-rc1")
	if !stable.greater(pre) {
		t.Errorf("stable 1.2.3 should outrank pre-release 1.2.3-rc1")
	}
	if pre.greater(stable) {
		t.Errorf("pre-release should not outrank stable at equal precedence")
	}
}

func fooStats(pulls int, lastPull time.Time, versions ...string) CoordStats {
	cs := CoordStats{Backend: "pip", Ecosystem: "pip", Name: "foo", Tenant: "acme", Pulls: pulls, LastPull: lastPull}
	for _, v := range versions {
		cs.Versions = append(cs.Versions, VersionStat{Version: v, Path: "/v1/pip/foo-" + v + ".tar.gz", Pulls: 1, LastPull: lastPull})
	}
	return cs
}

func TestPredictPatchAndMinor(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 2, PatchLookahead: 2, PredictMinor: true}, nil)
	targets := p.Predict(context.Background(), now, []CoordStats{fooStats(5, now, "1.2.2", "1.2.3")})

	got := map[string]Reason{}
	for _, tg := range targets {
		got[tg.Version] = tg.Reason
		if tg.Path != "/v1/pip/foo-"+tg.Version+".tar.gz" {
			t.Errorf("target %s has wrong path %q", tg.Version, tg.Path)
		}
		if tg.Tenant != "acme" {
			t.Errorf("target %s lost tenant: %q", tg.Version, tg.Tenant)
		}
	}
	if got["1.2.4"] != ReasonPatchRelease {
		t.Errorf("want 1.2.4 patch-release, got %v / %+v", got["1.2.4"], got)
	}
	if got["1.2.5"] != ReasonPatchRelease {
		t.Errorf("want 1.2.5 patch-release, got %+v", got)
	}
	if got["1.3.0"] != ReasonMinorRelease {
		t.Errorf("want 1.3.0 minor-release, got %+v", got)
	}
	if _, dup := got["1.2.3"]; dup {
		t.Errorf("must not predict an already-observed version 1.2.3")
	}
}

func TestPredictRespectsMinPulls(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 10, PatchLookahead: 1}, nil)
	targets := p.Predict(context.Background(), now, []CoordStats{fooStats(3, now, "1.2.3")})
	if len(targets) != 0 {
		t.Errorf("coordinate below MinPulls should yield no targets, got %+v", targets)
	}
}

func TestPredictRespectsRecencyWindow(t *testing.T) {
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	stale := now.Add(-30 * 24 * time.Hour)
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 1, PatchLookahead: 1, RecencyWindow: 7 * 24 * time.Hour}, nil)
	targets := p.Predict(context.Background(), now, []CoordStats{fooStats(5, stale, "1.2.3")})
	if len(targets) != 0 {
		t.Errorf("stale coordinate should be filtered out, got %+v", targets)
	}
}

func TestPredictSkipsWhenVersionNotInPath(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cs := CoordStats{
		Backend: "pip", Ecosystem: "pip", Name: "foo", Pulls: 5, LastPull: now,
		Versions: []VersionStat{{Version: "1.2.3", Path: "/v1/pip/foo-opaque-hash.whl", Pulls: 5, LastPull: now}},
	}
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 1, PatchLookahead: 1}, nil)
	if targets := p.Predict(context.Background(), now, []CoordStats{cs}); len(targets) != 0 {
		t.Errorf("must not guess a path that does not embed the version, got %+v", targets)
	}
}

func TestPredictMaxCandidates(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 1, PatchLookahead: 5, PredictMinor: true, MaxCandidates: 2}, nil)
	targets := p.Predict(context.Background(), now, []CoordStats{fooStats(5, now, "1.2.3")})
	if len(targets) != 2 {
		t.Fatalf("want 2 targets (capped), got %d", len(targets))
	}
}

// fakeDepSource returns a fixed dependency list for any coordinate.
type fakeDepSource struct{ deps []Coordinate }

func (f fakeDepSource) Dependencies(_ context.Context, _ Coordinate) []Coordinate { return f.deps }

func TestPredictTransitiveDepsFromHistoryPathTemplate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// The top-level package app depends on lib==2.0.0. lib has been pulled before
	// at 1.9.0, so the predictor can borrow its learned path template.
	app := CoordStats{Backend: "npm", Ecosystem: "npm", Name: "app", Pulls: 5, LastPull: now,
		Versions: []VersionStat{{Version: "1.0.0", Path: "/v1/npm/app/-/app-1.0.0.tgz", Pulls: 5, LastPull: now}}}
	lib := CoordStats{Backend: "npm", Ecosystem: "npm", Name: "lib", Pulls: 1, LastPull: now,
		Versions: []VersionStat{{Version: "1.9.0", Path: "/v1/npm/lib/-/lib-1.9.0.tgz", Pulls: 1, LastPull: now}}}

	deps := fakeDepSource{deps: []Coordinate{{Ecosystem: "npm", Name: "lib", Version: "2.0.0"}}}
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 100, TransitiveDeps: true}, deps) // MinPulls high → only transitive strategy fires

	targets := p.Predict(context.Background(), now, []CoordStats{app, lib})
	var found *Target
	for i := range targets {
		if targets[i].Name == "lib" && targets[i].Version == "2.0.0" {
			found = &targets[i]
		}
	}
	if found == nil {
		t.Fatalf("expected transitive dep lib@2.0.0, got %+v", targets)
	}
	if found.Reason != ReasonTransitiveDep {
		t.Errorf("want reason transitive-dep, got %v", found.Reason)
	}
	if found.Path != "/v1/npm/lib/-/lib-2.0.0.tgz" {
		t.Errorf("want substituted path, got %q", found.Path)
	}
	if found.Backend != "npm" {
		t.Errorf("want backend npm, got %q", found.Backend)
	}
}

func TestPredictTransitiveDepSkipsUnknownAndObserved(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lib := CoordStats{Backend: "npm", Ecosystem: "npm", Name: "lib", Pulls: 1, LastPull: now,
		Versions: []VersionStat{{Version: "2.0.0", Path: "/v1/npm/lib/-/lib-2.0.0.tgz", Pulls: 1, LastPull: now}}}

	// Dep points at an already-observed version (2.0.0) and an unknown package.
	deps := fakeDepSource{deps: []Coordinate{
		{Ecosystem: "npm", Name: "lib", Version: "2.0.0"},     // already observed → skip
		{Ecosystem: "npm", Name: "unknown", Version: "1.0.0"}, // never pulled → no path → skip
	}}
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 100, TransitiveDeps: true}, deps)
	if targets := p.Predict(context.Background(), now, []CoordStats{lib}); len(targets) != 0 {
		t.Errorf("want no transitive targets, got %+v", targets)
	}
}

func TestPredictNilDepSourceNoPanic(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := NewHeuristicPredictor(HeuristicConfig{MinPulls: 1, PatchLookahead: 1, TransitiveDeps: true}, nil)
	_ = p.Predict(context.Background(), now, []CoordStats{fooStats(5, now, "1.2.3")})
}
