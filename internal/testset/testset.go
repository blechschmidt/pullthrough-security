// Package testset is a reusable test set — a corpus of real, minimal software
// builds — for every package/artifact ecosystem the pull-through proxy fronts
// (Task 99).
//
// Each fixture is a native, buildable minimal project: an npm package.json plus
// index.js, a Cargo.toml plus main.rs, a Maven pom.xml, a Dockerfile, a Helm
// Chart.yaml, and so on. Every project declares exactly one tiny, well-known,
// real upstream dependency, together with the representative gateway pull
// path(s) that building or installing the project triggers through the proxy
// (an index/metadata fetch and an artifact download). The corpus files are the
// literal "real minimal software builds"; the catalog of pull paths maps each
// build to the concrete requests it makes against a `/v1/<backend>/…` mount.
//
// The corpus is embedded via go:embed so it travels with the binary and the
// test suite. The package offers three things on top of it:
//
//   - Corpus()   enumerates the fixtures as structured data (files, dependency,
//     build command, representative pulls).
//   - Validate() asserts the corpus is complete (covers every supported
//     ecosystem) and internally consistent (every declared file exists in the
//     embedded tree; every pull path is well-formed under its mount).
//   - Run()/Harness drives each fixture's representative pulls end-to-end through
//     a real in-process proxy.Gateway fronted by a deterministic stub upstream,
//     asserting that each ecosystem routes and that artifact pulls are served
//     from cache on a repeat fetch — i.e. the pull-through path actually works
//     for every ecosystem, with no network.
//
// It is a test/validation asset, not a production code path: nothing here runs
// on the live pull path. It is exercised by the package's own tests and exposed
// on demand via `ptctl testset`.
package testset

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// corpusFS embeds the full corpus of minimal real builds. The `all:` prefix
// keeps dotfiles and otherwise-ignored names (there are none today, but it
// future-proofs the tree).
//
//go:embed all:testdata/corpus
var corpusFS embed.FS

// corpusRoot is the embed path prefix every fixture directory sits under.
const corpusRoot = "testdata/corpus"

// PullKind classifies a representative request a build makes through the proxy.
type PullKind string

const (
	// KindIndex is a metadata/index/discovery fetch (registry index, Simple
	// index, GOPROXY .info, Docker manifest, Helm index.yaml, git ref
	// advertisement, …). These are typically revalidated rather than cached
	// immutably, so the harness asserts only that they route and serve.
	KindIndex PullKind = "index"
	// KindArtifact is an immutable content download (a tarball, wheel, crate,
	// module zip, nupkg, jar, gem, blob, …). These are content-addressable and
	// cacheable, so the harness additionally asserts a repeat fetch is served
	// from cache without a second upstream hit.
	KindArtifact PullKind = "artifact"
)

// Dependency is the single real upstream coordinate a fixture declares.
type Dependency struct {
	// Name is the ecosystem-native package/coordinate name (e.g. "is-number",
	// "org.apache.commons:commons-lang3", "library/alpine").
	Name string `json:"name"`
	// Version is the pinned version the build resolves.
	Version string `json:"version"`
}

// Coordinate renders the dependency as "name@version" for display.
func (d Dependency) Coordinate() string {
	if d.Version == "" {
		return d.Name
	}
	return d.Name + "@" + d.Version
}

// Pull is one representative request a build issues against the proxy, expressed
// as a gateway path under the fixture's `/v1/<backend>/` mount.
type Pull struct {
	// Kind classifies the request (index vs artifact).
	Kind PullKind `json:"kind"`
	// Method is the HTTP method the client uses; empty means GET.
	Method string `json:"method,omitempty"`
	// Path is the gateway path, always beginning with "/v1/<backend>/".
	Path string `json:"path"`
	// Desc is a short human description of what the build is fetching.
	Desc string `json:"desc"`
}

// method returns the effective HTTP method (GET when unset).
func (p Pull) method() string {
	if p.Method == "" {
		return "GET"
	}
	return p.Method
}

// Fixture is one minimal real build and the pull-through behavior it exercises.
type Fixture struct {
	// ID is the stable, sortable fixture identifier (e.g. "npm", "pip").
	ID string `json:"id"`
	// Ecosystem is the human ecosystem label.
	Ecosystem string `json:"ecosystem"`
	// Backend is the proxy backend mount name the build's requests route to
	// (the "<backend>" in "/v1/<backend>/"). Multiple ecosystems can share a
	// backend type; this is the mount used by the fixture.
	Backend string `json:"backend"`
	// Summary describes the build.
	Summary string `json:"summary"`
	// BuildCmd is the exact command a developer runs to drive the build/install
	// (and therefore the pulls) — e.g. "npm install".
	BuildCmd string `json:"buildCmd"`
	// Dir is the corpus directory, relative to the embedded corpus root.
	Dir string `json:"dir"`
	// Files are the project files present in Dir, relative to Dir.
	Files []string `json:"files"`
	// Dep is the single real upstream dependency the build resolves.
	Dep Dependency `json:"dependency"`
	// Pulls are the representative gateway requests the build triggers.
	Pulls []Pull `json:"pulls"`
}

// mount returns the "/v1/<backend>/" prefix for the fixture.
func (f Fixture) mount() string { return "/v1/" + f.Backend + "/" }

// Open returns the embedded contents of a fixture file (path relative to the
// fixture Dir).
func (f Fixture) Open(name string) ([]byte, error) {
	return corpusFS.ReadFile(corpusRoot + "/" + f.Dir + "/" + name)
}

// Corpus returns the full catalog of fixtures, sorted by ID. The returned slice
// is freshly built on each call and safe for the caller to mutate.
func Corpus() []Fixture {
	out := make([]Fixture, len(catalog))
	copy(out, catalog)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Ecosystems returns the sorted set of fixture IDs in the corpus.
func Ecosystems() []string {
	ids := make([]string, 0, len(catalog))
	for _, f := range catalog {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

// Validate checks the corpus is complete and internally consistent:
//
//   - every supported ecosystem (supportedEcosystems) has exactly one fixture;
//   - IDs are unique and non-empty;
//   - every declared file exists in the embedded corpus tree and is non-empty;
//   - every fixture directory's on-disk files are all declared (no stragglers);
//   - every pull path is well-formed and sits under the fixture's mount;
//   - every fixture declares at least one artifact pull and a real dependency.
//
// It returns a joined error describing all problems, or nil when the corpus is
// sound.
func Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	seen := map[string]bool{}
	for _, f := range catalog {
		switch {
		case f.ID == "":
			add("fixture with empty ID (ecosystem %q)", f.Ecosystem)
			continue
		case seen[f.ID]:
			add("duplicate fixture ID %q", f.ID)
			continue
		}
		seen[f.ID] = true
		validateFixture(f, add)
	}

	// Completeness: every supported ecosystem must be covered.
	for _, eco := range supportedEcosystems {
		if !seen[eco] {
			add("missing fixture for supported ecosystem %q", eco)
		}
	}
	// Reverse: no fixture for an unknown ecosystem.
	supported := map[string]bool{}
	for _, e := range supportedEcosystems {
		supported[e] = true
	}
	for id := range seen {
		if !supported[id] {
			add("fixture %q is not in the supported-ecosystem set", id)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("testset corpus invalid:\n  - %s", strings.Join(problems, "\n  - "))
}

func validateFixture(f Fixture, add func(string, ...any)) {
	if f.Dir == "" {
		add("fixture %q has no Dir", f.ID)
		return
	}
	dirPath := corpusRoot + "/" + f.Dir

	// Declared files must exist and be non-empty.
	declared := map[string]bool{}
	for _, name := range f.Files {
		declared[name] = true
		b, err := corpusFS.ReadFile(dirPath + "/" + name)
		if err != nil {
			add("fixture %q: declared file %q not found in corpus (%v)", f.ID, name, err)
			continue
		}
		if len(b) == 0 {
			add("fixture %q: declared file %q is empty", f.ID, name)
		}
	}
	if len(f.Files) == 0 {
		add("fixture %q: declares no files", f.ID)
	}

	// On-disk files must all be declared (catch a file added to the corpus but
	// not to the catalog).
	walkErr := fs.WalkDir(corpusFS, dirPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, dirPath+"/")
		if !declared[rel] {
			add("fixture %q: corpus file %q is not declared in Files", f.ID, rel)
		}
		return nil
	})
	if walkErr != nil {
		add("fixture %q: walking corpus dir: %v", f.ID, walkErr)
	}

	// Dependency must be real.
	if strings.TrimSpace(f.Dep.Name) == "" {
		add("fixture %q: empty dependency name", f.ID)
	}
	if strings.TrimSpace(f.BuildCmd) == "" {
		add("fixture %q: empty build command", f.ID)
	}

	// Pulls must be well-formed and under the mount.
	if len(f.Pulls) == 0 {
		add("fixture %q: declares no pulls", f.ID)
	}
	artifacts := 0
	for i, p := range f.Pulls {
		switch p.Kind {
		case KindIndex, KindArtifact:
		default:
			add("fixture %q pull #%d: invalid kind %q", f.ID, i, p.Kind)
		}
		if p.Kind == KindArtifact {
			artifacts++
		}
		if !strings.HasPrefix(p.Path, f.mount()) {
			add("fixture %q pull #%d: path %q is not under mount %q", f.ID, i, p.Path, f.mount())
		}
		// Reject empty path segments, ignoring the scheme separator and any query.
		pathOnly := p.Path
		if q := strings.IndexByte(pathOnly, '?'); q >= 0 {
			pathOnly = pathOnly[:q]
		}
		if strings.Contains(pathOnly, "//") && !strings.Contains(pathOnly, "://") {
			add("fixture %q pull #%d: path %q contains an empty segment", f.ID, i, p.Path)
		}
	}
	// Every ecosystem must exercise a cacheable artifact download, except git,
	// whose clone is an inherently non-cacheable pack negotiation rather than a
	// content-addressable artifact fetch.
	if artifacts == 0 && f.ID != "git" {
		add("fixture %q: declares no artifact pull (a cacheable content download)", f.ID)
	}
}
