package lockfiles

import "sort"

// Coverage is how the lock files of one upstream type are covered.
type Coverage struct {
	// Type is the upstream type.
	Type string `json:"type"`
	// Formats are the formats with a parser.
	Formats []string `json:"formats,omitempty"`
	// Reason is why the type has no parser, when it has none.
	Reason string `json:"reason,omitempty"`
	// Unparsed names the ecosystem's lock-file formats that are not parsed,
	// when it has any.
	Unparsed []string `json:"unparsed,omitempty"`
}

// noParser is the explicit entry of every upstream type without a parser: why
// there is none, and which lock-file formats the ecosystem has that are not
// read. A type the configuration accepts must have either a parser or an entry
// here (see coverage_test.go), so a backend added later cannot be left out of
// the lock-file scan without someone deciding so — and saying why.
var noParser = map[string]Coverage{
	"git": {Reason: "no lock-file format: a repository pins another repository with a submodule, " +
		"a commit ID stored as a tree entry (a gitlink) next to the URL in .gitmodules — not a file a " +
		"parser reads. The tree walk records submodules separately (Report.Submodules)."},
	"apt": {Reason: "no lock-file format: Debian packages are installed from repository indexes at " +
		"build time; version pins in a Dockerfile's apt-get line are commands, not a lock file."},
	"yum": {Reason: "no lock-file format: RPM packages are installed from repository metadata at build " +
		"time; dnf has no lock file in general use."},
	"generic": {Reason: "no lock-file format: a generic upstream serves whatever routes its operator " +
		"declares, so there is no format to know in advance."},
	"huggingface": {Reason: "no lock-file format: models and datasets are named by repository and " +
		"revision in code or configuration, not in a lock file of the Hub's."},
	"openvsx": {Reason: "no lock-file format: an editor's extensions are installed by ID; " +
		".vscode/extensions.json recommends extensions without versions."},
	"nix": {Reason: "no lock-file format for the binary cache: flake.lock pins flake inputs " +
		"(source repositories by revision and NAR hash), not the store paths the binary cache serves.",
		Unparsed: []string{"flake.lock (inputs only)"}},
	"homebrew": {Reason: "no lock-file format in current use: a Brewfile names formulae without " +
		"versions, and `brew bundle` no longer writes Brewfile.lock.json."},
	"helm": {Reason: "Chart.lock pins chart dependencies by version, with a digest of the requirements; " +
		"not parsed yet.", Unparsed: []string{"Chart.lock"}},
	"terraform": {Reason: ".terraform.lock.hcl pins provider versions and package hashes; not parsed yet.",
		Unparsed: []string{".terraform.lock.hcl"}},
	"conan": {Reason: "conan.lock pins recipe revisions; not parsed yet.", Unparsed: []string{"conan.lock"}},
	"swift": {Reason: "Package.resolved pins package versions and revisions; not parsed yet.",
		Unparsed: []string{"Package.resolved"}},
	"dart": {Reason: "pubspec.lock pins package versions and archive hashes; not parsed yet.",
		Unparsed: []string{"pubspec.lock"}},
	"conda": {Reason: "conda-lock files, pixi.lock and @EXPLICIT spec files pin package URLs and " +
		"hashes; not parsed yet.", Unparsed: []string{"conda-lock.yml", "pixi.lock", "@EXPLICIT spec files"}},
	"cran": {Reason: "renv.lock pins R package versions; not parsed yet.", Unparsed: []string{"renv.lock"}},
	"hex": {Reason: "mix.lock pins Hex package versions and checksums; not parsed yet.",
		Unparsed: []string{"mix.lock"}},
	"bazel": {Reason: "MODULE.bazel.lock records the resolved module graph; not parsed yet.",
		Unparsed: []string{"MODULE.bazel.lock"}},
	"julia": {Reason: "Manifest.toml pins package versions and git tree hashes; not parsed yet.",
		Unparsed: []string{"Manifest.toml"}},
	"cpan": {Reason: "cpanfile.snapshot (Carton) pins distribution versions; not parsed yet.",
		Unparsed: []string{"cpanfile.snapshot"}},
	"jsr": {Reason: "deno.lock pins JSR package versions and integrity hashes; not parsed yet.",
		Unparsed: []string{"deno.lock"}},
	"hackage": {Reason: "cabal.project.freeze and stack.yaml.lock pin package versions; not parsed yet.",
		Unparsed: []string{"cabal.project.freeze", "stack.yaml.lock"}},
	"ansible": {Reason: "ansible-galaxy has no lock file; a requirements.yml can pin exact collection " +
		"versions, which is not parsed yet.", Unparsed: []string{"requirements.yml (exact pins)"}},
	"puppet": {Reason: "Puppet has no lock file; a Puppetfile (r10k) can pin exact module versions, " +
		"which is not parsed yet.", Unparsed: []string{"Puppetfile (exact pins)"}},
}

// CoverageFor returns the coverage of an upstream type (aliases resolved) by
// the default registry, and false for a type nothing is known about.
func CoverageFor(upstreamType string) (Coverage, bool) {
	return coverageFor(DefaultRegistry(), CanonicalType(upstreamType))
}

func coverageFor(r *Registry, t string) (Coverage, bool) {
	if ps := r.byType[t]; len(ps) > 0 {
		c := Coverage{Type: t}
		for _, p := range ps {
			c.Formats = append(c.Formats, p.Format())
		}
		if np, ok := noParser[t]; ok {
			c.Unparsed = np.Unparsed
		}
		return c, true
	}
	if np, ok := noParser[t]; ok {
		np.Type = t
		return np, true
	}
	return Coverage{}, false
}

// CoverageTable returns the coverage of every upstream type with a parser or a
// no-parser entry, sorted by type.
func CoverageTable() []Coverage {
	r := DefaultRegistry()
	types := map[string]bool{}
	for t := range r.byType {
		types[t] = true
	}
	for t := range noParser {
		types[t] = true
	}
	out := make([]Coverage, 0, len(types))
	for t := range types {
		c, _ := coverageFor(r, t)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
