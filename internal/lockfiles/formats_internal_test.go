package lockfiles

import (
	"path/filepath"
	"testing"
)

// TestEveryFormatIsDescribed: each parser's format has a description, and
// every description belongs to a parser.
func TestEveryFormatIsDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range DefaultRegistry().All() {
		key := p.Type() + "/" + p.Format()
		seen[key] = true
		info, ok := formatInfo[key]
		if !ok {
			t.Errorf("%s has no description in formatInfo", key)
			continue
		}
		if info.Files == "" || info.Read == "" || info.Digests == "" {
			t.Errorf("%s: the description leaves files, read or digests empty", key)
		}
		if info.Digests != DigestsAll && info.NoDigest == "" {
			t.Errorf("%s: entries can lack a digest, but no reason is given for them", key)
		}
	}
	for key := range formatInfo {
		if !seen[key] {
			t.Errorf("formatInfo describes %s, which no parser reads", key)
		}
	}
	for _, k := range DigestKinds() {
		if !k.PinsContent && k.Unverified == "" {
			t.Errorf("digest kind %q pins nothing but gives no reason", k.Of)
		}
	}
}

// TestFormatClaimsHoldForTheFixtures holds the format table to the golden
// fixtures: a format said to record no digest yields none, one said to
// record a digest for every entry yields no unverified registry or URL entry,
// one said to record Git dependencies has a fixture with one and one not
// said to has none.
func TestFormatClaimsHoldForTheFixtures(t *testing.T) {
	type tally struct{ deps, withDigest, unverifiedNonGit, git int }
	byFormat := map[string]*tally{}
	for _, name := range fixtureNames(t) {
		for _, f := range parseFixture(t, filepath.Join("testdata/fixtures", name)) {
			key := f.Type + "/" + f.Format
			tl := byFormat[key]
			if tl == nil {
				tl = &tally{}
				byFormat[key] = tl
			}
			for _, d := range f.Dependencies {
				tl.deps++
				if len(d.Digests) > 0 {
					tl.withDigest++
				}
				if d.Source == SourceGit {
					tl.git++
				} else if d.Unverified {
					tl.unverifiedNonGit++
				}
			}
		}
	}
	for _, info := range DefaultRegistry().Formats() {
		key := info.Type + "/" + info.Format
		tl := byFormat[key]
		if key == "go/go.sum" || key == "terraform/*.tf overrides" {
			continue // merged into the dependencies of the go.mod, or of the .tf files, next to it
		}
		if tl == nil || tl.deps == 0 {
			t.Errorf("%s: no fixture yields a dependency of the format", key)
			continue
		}
		switch info.Digests {
		case DigestsNone:
			if tl.withDigest > 0 {
				t.Errorf("%s is described as recording no digest, but %d fixture dependencies have one", key, tl.withDigest)
			}
		case DigestsAll:
			if tl.unverifiedNonGit > 0 {
				t.Errorf("%s is described as recording a digest for every entry, but %d fixture dependencies are unverified", key, tl.unverifiedNonGit)
			}
		}
		if info.GitSources && tl.git == 0 {
			t.Errorf("%s is described as recording Git dependencies, but no fixture shows one", key)
		}
		if !info.GitSources && tl.git > 0 {
			t.Errorf("%s records Git dependencies (%d in the fixtures) but is not described so", key, tl.git)
		}
	}
}
