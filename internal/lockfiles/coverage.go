package lockfiles

import (
	"sort"
	"strings"
)

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
	// Note says what else covers the type: for "git", the formats whose Git
	// dependencies are fetched through a Git upstream too.
	Note string `json:"note,omitempty"`
	// Details describe the formats with a parser, in Formats' order.
	Details []FormatInfo `json:"details,omitempty"`
}

// noParser is the explicit entry of every upstream type without a parser: why
// there is none. A type the configuration accepts must have either a parser or
// an entry here (see coverage_test.go), so a backend added later cannot be left
// out of the lock-file scan without someone deciding so — and saying why. An
// entry for a type that has a parser fails a test.
var noParser = map[string]Coverage{
	"apt": {Reason: "no lock-file format: Debian packages are installed from repository indexes at " +
		"build time; version pins in a Dockerfile's apt-get line are commands, not a lock file."},
	"yum": {Reason: "no lock-file format: RPM packages are installed from repository metadata at build " +
		"time; dnf has no lock file in general use."},
	"generic": {Reason: "no lock-file format: a generic upstream serves whatever routes its operator " +
		"declares, so there is no format to know in advance. Remote modules of deno.lock are recorded as " +
		"dependencies of this type."},
	"huggingface": {Reason: "no declared manifest in general use: models and datasets are referenced by " +
		"repository and revision in code (from_pretrained(…, revision=…)) or in each serving tool's own " +
		"configuration (KServe storageUri, vLLM --revision). The .metadata files `hf download --local-dir` " +
		"writes are a git-ignored download cache that does not record the repository, and DVC's .dvc files " +
		"are DVC's own format."},
	"openvsx": {Reason: "no lock-file format: .vscode/extensions.json recommends extension IDs " +
		"(publisher.name), and its schema allows no version or hash. devcontainer.json can name an exact " +
		"version (publisher.name@1.2.3) but records no hash, and devcontainer-lock.json pins Features, not " +
		"extensions."},
}

// unparsedFormats names, for an upstream type that has parsers, the lock-file
// formats of its ecosystem that are not read.
var unparsedFormats = map[string][]string{
	"npm":   {"bun.lock", "bun.lockb"},
	"pip":   {"pylock.toml (PEP 751)"},
	"nuget": {"paket.lock"},
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
			c.Details = append(c.Details, describe(p))
		}
		c.Unparsed = unparsedFormats[t]
		if t == "git" {
			var others []string
			for _, f := range gitSourceFormats(r) {
				if f != ".gitmodules" {
					others = append(others, f)
				}
			}
			if len(others) > 0 {
				c.Note = "Git dependencies recorded in other lock files (source git, pinned by commit) are fetched from a Git repository too: " +
					strings.Join(others, ", ") + "."
			}
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
