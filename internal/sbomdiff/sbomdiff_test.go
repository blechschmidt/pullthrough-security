package sbomdiff

import (
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// stubLicense is a deterministic LicenseDispositioner: it returns the
// disposition keyed by the lowercased license token.
type stubLicense map[string]string

func (s stubLicense) Disposition(_, expression string) string {
	if d, ok := s[expression]; ok {
		return d
	}
	return "allowed"
}

func snap(version string, deps []Dep, vulns []VulnRef, primaryLicense string) Snapshot {
	return Snapshot{
		Ecosystem:      "npm",
		Coordinate:     "left-pad",
		Version:        version,
		PrimaryLicense: primaryLicense,
		Deps:           deps,
		Vulns:          vulns,
		ObservedAt:     time.Unix(0, 0).UTC(),
	}
}

func TestComputeDependencyDelta(t *testing.T) {
	from := snap("1.0.0", []Dep{
		{Name: "a", Version: "1.0.0", Namespace: "@org"},
		{Name: "b", Version: "2.0.0", Namespace: "@org"},
	}, nil, "MIT")
	to := snap("1.1.0", []Dep{
		{Name: "b", Version: "2.1.0", Namespace: "@org"}, // bumped
		{Name: "c", Version: "3.0.0", Namespace: "@new"}, // added, new namespace
	}, nil, "MIT")

	d := compute(from, to, computeOptions{weights: DefaultWeights(), significant: 40})

	if len(d.AddedDeps) != 1 || d.AddedDeps[0].Name != "c" {
		t.Fatalf("expected c added, got %+v", d.AddedDeps)
	}
	if len(d.RemovedDeps) != 1 || d.RemovedDeps[0].Name != "a" {
		t.Fatalf("expected a removed, got %+v", d.RemovedDeps)
	}
	if len(d.VersionBumps) != 1 || d.VersionBumps[0].Name != "b" || d.VersionBumps[0].Direction != "up" {
		t.Fatalf("expected b bumped up, got %+v", d.VersionBumps)
	}
	if len(d.NewNamespaces) != 1 || d.NewNamespaces[0] != "@new" {
		t.Fatalf("expected @new namespace, got %+v", d.NewNamespaces)
	}
}

func TestComputeDeterministicOrder(t *testing.T) {
	// Same content in different component order must yield the identical diff.
	from := snap("1.0.0", []Dep{{Name: "z"}, {Name: "a"}}, nil, "MIT")
	toA := snap("2.0.0", []Dep{{Name: "z"}, {Name: "a"}, {Name: "m"}, {Name: "b"}}, nil, "MIT")
	toB := snap("2.0.0", []Dep{{Name: "b"}, {Name: "m"}, {Name: "a"}, {Name: "z"}}, nil, "MIT")

	d1 := compute(from, toA, computeOptions{weights: DefaultWeights(), significant: 40})
	d2 := compute(from, toB, computeOptions{weights: DefaultWeights(), significant: 40})

	if d1.DriftScore != d2.DriftScore {
		t.Fatalf("non-deterministic score: %v vs %v", d1.DriftScore, d2.DriftScore)
	}
	if d1.Markdown() != d2.Markdown() {
		t.Fatalf("non-deterministic markdown:\n%s\n---\n%s", d1.Markdown(), d2.Markdown())
	}
	if len(d1.AddedDeps) != 2 || d1.AddedDeps[0].Name != "b" || d1.AddedDeps[1].Name != "m" {
		t.Fatalf("added deps not sorted: %+v", d1.AddedDeps)
	}
}

func TestNewLicensesAndDisposition(t *testing.T) {
	from := snap("1.0.0", []Dep{{Name: "a", License: "MIT"}}, nil, "MIT")
	to := snap("1.1.0", []Dep{
		{Name: "a", License: "MIT"},
		{Name: "b", License: "GPL-3.0-only"},
		{Name: "c", License: "MPL-2.0"},
	}, nil, "MIT")

	disp := stubLicense{"GPL-3.0-only": "denied", "MPL-2.0": "review"}
	d := compute(from, to, computeOptions{weights: DefaultWeights(), significant: 40, license: disp})

	if len(d.NewLicenses) != 2 {
		t.Fatalf("expected 2 new licenses, got %+v", d.NewLicenses)
	}
	// Sorted by license token: GPL-3.0-only then MPL-2.0.
	if d.NewLicenses[0].License != "GPL-3.0-only" || d.NewLicenses[0].Disposition != "denied" {
		t.Fatalf("unexpected first new license: %+v", d.NewLicenses[0])
	}
	if d.NewLicenses[1].License != "MPL-2.0" || d.NewLicenses[1].Disposition != "review" {
		t.Fatalf("unexpected second new license: %+v", d.NewLicenses[1])
	}
	// A denied + review license should drive a high score.
	if d.DriftScore < DefaultWeights().NewLicenseDeny {
		t.Fatalf("expected denied license to dominate score, got %v", d.DriftScore)
	}
}

func TestNetNewVulnerabilities(t *testing.T) {
	from := snap("1.0.0", []Dep{{Name: "a"}}, []VulnRef{{ID: "CVE-2020-1", Severity: "high"}}, "MIT")
	to := snap("1.1.0", []Dep{{Name: "a"}}, []VulnRef{
		{ID: "CVE-2020-1", Severity: "high"}, // carried over, not net-new
		{ID: "CVE-2024-9", Severity: "critical"},
	}, "MIT")

	d := compute(from, to, computeOptions{weights: DefaultWeights(), significant: 40})
	if len(d.NewVulnerabilities) != 1 || d.NewVulnerabilities[0].ID != "CVE-2024-9" {
		t.Fatalf("expected only CVE-2024-9 net-new, got %+v", d.NewVulnerabilities)
	}
	if d.DriftScore < DefaultWeights().VulnCritical {
		t.Fatalf("expected critical vuln to dominate score, got %v", d.DriftScore)
	}
	if !d.Significant {
		t.Fatalf("expected significant drift")
	}
}

func TestScoreClampedTo100(t *testing.T) {
	var deps []Dep
	var vulns []VulnRef
	for i := 0; i < 50; i++ {
		vulns = append(vulns, VulnRef{ID: "CVE-X-" + itoa(i), Severity: "critical"})
		deps = append(deps, Dep{Name: "dep" + itoa(i), Namespace: "ns" + itoa(i)})
	}
	from := snap("1.0.0", nil, nil, "MIT")
	to := snap("2.0.0", deps, vulns, "MIT")
	d := compute(from, to, computeOptions{weights: DefaultWeights(), significant: 40})
	if d.DriftScore != 100 {
		t.Fatalf("expected score clamped to 100, got %v", d.DriftScore)
	}
}

func TestStoreRecordAndBaseline(t *testing.T) {
	st := NewStore(3, 10)

	if _, ok := st.Record(snap("1.0.0", []Dep{{Name: "a"}}, nil, "MIT")); ok {
		t.Fatal("first record should have no prior")
	}
	prior, ok := st.Record(snap("1.1.0", []Dep{{Name: "a"}, {Name: "b"}}, nil, "MIT"))
	if !ok || prior.Version != "1.0.0" {
		t.Fatalf("expected prior 1.0.0, got %v ok=%v", prior.Version, ok)
	}

	// Re-pull of same version replaces in place, returns prior of different version.
	prior, ok = st.Record(snap("1.1.0", []Dep{{Name: "a"}, {Name: "b"}}, nil, "MIT"))
	if !ok || prior.Version != "1.0.0" {
		t.Fatalf("re-pull: expected prior 1.0.0, got %v ok=%v", prior.Version, ok)
	}
	if got := st.History("", "npm", "left-pad"); len(got) != 2 {
		t.Fatalf("expected 2 versions retained, got %d", len(got))
	}

	// Bounded to 3 versions.
	st.Record(snap("1.2.0", nil, nil, "MIT"))
	st.Record(snap("1.3.0", nil, nil, "MIT"))
	hist := st.History("", "npm", "left-pad")
	if len(hist) != 3 {
		t.Fatalf("expected history bounded to 3, got %d", len(hist))
	}
	if hist[0].Version != "1.1.0" {
		t.Fatalf("expected oldest dropped (1.0.0), got oldest=%s", hist[0].Version)
	}
}

func TestStoreCoordinateEviction(t *testing.T) {
	st := NewStore(4, 2)
	for _, c := range []string{"a", "b", "c"} {
		st.Record(Snapshot{Ecosystem: "npm", Coordinate: c, Version: "1.0.0"})
	}
	if st.Len() != 2 {
		t.Fatalf("expected coordinate store bounded to 2, got %d", st.Len())
	}
	// "a" should have been evicted (least-recently-updated).
	if _, ok := st.Snapshot("", "npm", "a", "1.0.0"); ok {
		t.Fatal("expected coordinate a evicted")
	}
}

func TestServiceObserveDriftAction(t *testing.T) {
	svc := NewService(Config{
		Enabled:              true,
		Action:               policy.ActionQuarantine,
		WarnThreshold:        10,
		BlockThreshold:       50,
		SignificantThreshold: 30,
	}, nil)

	// First version: baseline, no comparison.
	res := svc.Observe(snap("1.0.0", []Dep{{Name: "a"}}, nil, "MIT"))
	if res.Compared {
		t.Fatal("first observe should not compare")
	}

	// Second version introduces a critical vuln → high drift → quarantine.
	res = svc.Observe(snap("1.1.0", []Dep{{Name: "a"}}, []VulnRef{{ID: "CVE-1", Severity: "critical"}}, "MIT"))
	if !res.Compared {
		t.Fatal("expected comparison")
	}
	if res.Action != policy.ActionQuarantine {
		t.Fatalf("expected quarantine action, got %s (score %v)", res.Action, res.Diff.DriftScore)
	}
	if !res.Significant {
		t.Fatal("expected significant")
	}

	m := svc.Metrics(0)
	if m.Observed != 2 || m.Compared != 1 || m.Significant != 1 || m.Quarantined != 1 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
	if len(m.RecentDrifts) != 1 {
		t.Fatalf("expected 1 recent drift, got %d", len(m.RecentDrifts))
	}
}

func TestServiceDiffOnDemand(t *testing.T) {
	svc := NewService(Config{Enabled: true}, nil)
	svc.Observe(snap("1.0.0", []Dep{{Name: "a"}}, nil, "MIT"))
	svc.Observe(snap("2.0.0", []Dep{{Name: "a"}, {Name: "b"}}, nil, "MIT"))

	d, ok := svc.Diff("", "npm", "left-pad", "1.0.0", "2.0.0")
	if !ok {
		t.Fatal("expected on-demand diff to resolve")
	}
	if len(d.AddedDeps) != 1 || d.AddedDeps[0].Name != "b" {
		t.Fatalf("unexpected diff: %+v", d.AddedDeps)
	}
	if _, ok := svc.Diff("", "npm", "left-pad", "1.0.0", "9.9.9"); ok {
		t.Fatal("expected missing version to fail")
	}
}

func TestBuildSnapshotFromSBOM(t *testing.T) {
	art := vulnscan.Artifact{Ecosystem: "npm", Name: "@scope/pkg", Version: "1.0.0"}
	sbom, err := vulnscan.Extract(art, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// Inject a dependency component to exercise the reducer.
	sbom.Components = append(sbom.Components, vulnscan.Component{
		Type: "library", Group: "@dep", Name: "lib", Version: "2.0.0",
		PURL: "pkg:npm/@dep/lib@2.0.0",
	})

	s := BuildSnapshot(SnapshotInput{
		Ecosystem: "npm", Coordinate: "@scope/pkg", Version: "1.0.0",
	}, sbom, []vulnscan.Vulnerability{{ID: "CVE-1", Severity: vulnscan.SeverityHigh, Package: "lib"}})

	if len(s.Deps) != 1 {
		t.Fatalf("expected 1 dependency (primary excluded), got %+v", s.Deps)
	}
	if s.Deps[0].Name != "@dep/lib" || s.Deps[0].Namespace != "@dep" {
		t.Fatalf("unexpected dep: %+v", s.Deps[0])
	}
	if len(s.Vulns) != 1 || s.Vulns[0].ID != "CVE-1" {
		t.Fatalf("unexpected vulns: %+v", s.Vulns)
	}
}

func TestDisabledServiceInert(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Fatal("nil service should be disabled")
	}
	if res := svc.Observe(snap("1.0.0", nil, nil, "")); res.Compared {
		t.Fatal("nil service observe should be inert")
	}
	off := NewService(Config{Enabled: false}, nil)
	if res := off.Observe(snap("1.0.0", nil, nil, "")); res.Compared {
		t.Fatal("disabled service observe should be inert")
	}
}
