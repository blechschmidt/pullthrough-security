package testset

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"testing"
)

// TestValidateCorpus asserts the embedded corpus is complete and internally
// consistent (every supported ecosystem covered, every declared file present
// and non-empty, every pull well-formed).
func TestValidateCorpus(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatalf("corpus failed validation:\n%v", err)
	}
}

// TestCorpusCoversEverySupportedEcosystem checks the catalog exactly matches the
// supported-ecosystem set.
func TestCorpusCoversEverySupportedEcosystem(t *testing.T) {
	got := map[string]bool{}
	for _, id := range Ecosystems() {
		got[id] = true
	}
	for _, eco := range supportedEcosystems {
		if !got[eco] {
			t.Errorf("no fixture for supported ecosystem %q", eco)
		}
	}
	if len(got) != len(supportedEcosystems) {
		t.Errorf("fixture count = %d, supported = %d", len(got), len(supportedEcosystems))
	}
}

// TestFixturesDeclareRealDependency asserts each fixture's primary manifest
// actually references the real dependency it claims — i.e. the corpus is a real
// build, not a stub that names a dependency it never uses.
func TestFixturesDeclareRealDependency(t *testing.T) {
	for _, f := range Corpus() {
		f := f
		t.Run(f.ID, func(t *testing.T) {
			// The dependency's distinctive token: the last path/colon segment of
			// its name (e.g. "commons-lang3" from "org.apache.commons:commons-lang3").
			name := f.Dep.Name
			if i := strings.LastIndexAny(name, "/:"); i >= 0 {
				name = name[i+1:]
			}
			found := false
			for _, file := range f.Files {
				b, err := f.Open(file)
				if err != nil {
					t.Fatalf("Open(%q): %v", file, err)
				}
				if strings.Contains(string(b), name) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no corpus file references dependency token %q", name)
			}
		})
	}
}

// TestNpmManifestParses spot-checks that a representative manifest is valid in
// its native format (catches a corrupt corpus file).
func TestNpmManifestParses(t *testing.T) {
	var f Fixture
	for _, c := range Corpus() {
		if c.ID == "npm" {
			f = c
		}
	}
	b, err := f.Open("package.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var manifest struct {
		Name         string            `json:"name"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatalf("package.json is not valid JSON: %v", err)
	}
	if manifest.Dependencies["is-number"] != f.Dep.Version {
		t.Errorf("package.json dep is-number = %q, want %q", manifest.Dependencies["is-number"], f.Dep.Version)
	}
}

// TestPullPathsWellFormed asserts every pull path begins with its mount and that
// the mount backend is the fixture's backend.
func TestPullPathsWellFormed(t *testing.T) {
	for _, f := range Corpus() {
		for _, p := range f.Pulls {
			prefix := "/v1/" + f.Backend + "/"
			if !strings.HasPrefix(p.Path, prefix) {
				t.Errorf("%s: pull %q does not start with %q", f.ID, p.Path, prefix)
			}
			clean := path.Clean(strings.SplitN(p.Path, "?", 2)[0])
			if clean == "." || clean == "/" {
				t.Errorf("%s: pull path %q cleans to root", f.ID, p.Path)
			}
		}
	}
}

// TestRunEndToEnd drives every fixture's representative pulls through a real
// in-process gateway and asserts each ecosystem routes, serves, and (for
// artifact pulls) caches — the headline property of the test set.
func TestRunEndToEnd(t *testing.T) {
	rep := Run(context.Background())
	if rep.ValidationError != "" {
		t.Fatalf("validation error: %s", rep.ValidationError)
	}
	if !rep.Complete {
		t.Fatal("report not marked complete")
	}
	if rep.Total != len(supportedEcosystems) {
		t.Fatalf("ran %d fixtures, want %d", rep.Total, len(supportedEcosystems))
	}
	for _, f := range rep.Fixtures {
		if !f.Pass {
			for _, p := range f.Pulls {
				if !p.ok() {
					t.Errorf("%s: pull %s %s failed: status=%d %s", f.ID, p.Method, p.Path, p.Status, p.Detail)
				}
			}
		}
		// Each fixture (except git) must have proven an artifact served from cache.
		if f.ID != "git" {
			cachedProven := false
			for _, p := range f.Pulls {
				if p.Kind == string(KindArtifact) && p.Cached != nil && *p.Cached {
					cachedProven = true
				}
			}
			if !cachedProven {
				t.Errorf("%s: no artifact pull proven served-from-cache", f.ID)
			}
		}
	}
	if !rep.OK() {
		t.Errorf("overall report not OK: passed=%d failed=%d total=%d", rep.Passed, rep.Failed, rep.Total)
	}
}

// TestReportRenders checks both renderers produce output and round-trip JSON.
func TestReportRenders(t *testing.T) {
	rep := Run(context.Background())
	md := rep.Markdown()
	if !strings.Contains(md, "Ecosystem Test-Set Coverage") {
		t.Error("markdown missing header")
	}
	b, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var round Report
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("JSON round-trip: %v", err)
	}
	if round.Total != rep.Total {
		t.Errorf("round-trip total = %d, want %d", round.Total, rep.Total)
	}
}
