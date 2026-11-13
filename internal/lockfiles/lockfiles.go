package lockfiles

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Dependency is one exact dependency a lock file pins.
type Dependency struct {
	// Type is the upstream type the dependency is fetched through: "npm",
	// "pip", "cargo", "go", "nuget", "maven", "rubygems", "composer", "docker"
	// (the types of config.UpstreamTypes).
	Type string `json:"type"`
	// Name is the package's name, spelled the way the proxy's backend for the
	// type names it: as written for npm, Cargo, Go, Composer and RubyGems;
	// PEP 503-normalised for pip ("charset-normalizer"); lower-cased for NuGet;
	// "group:artifact" for Maven; the repository path for Docker
	// ("library/alpine").
	Name string `json:"name"`
	// Version is the exact version as the lock file records it. For a RubyGems
	// platform gem it carries the platform ("1.16.7-x86_64-linux"), which names
	// a separate artifact; for Docker it is the manifest digest.
	Version string `json:"version"`
	// ID is what the ecosystem identifies the package by when its name and
	// version do not say it all: a Julia package's UUID (two registries may
	// each have a package of the name), a Conan reference's user and channel
	// ("zlib/1.3.1@acme/stable"), the author path of a CPAN distribution
	// ("E/ET/ETHER/Try-Tiny-0.31.tar.gz") — which is what a client fetches.
	ID string `json:"id,omitempty"`
	// Digests are the integrity values the lock file records for the
	// dependency. None when the format records none (gradle.lockfile, pom.xml,
	// a go.mod without its go.sum).
	Digests []Digest `json:"digests,omitempty"`
	// Registry is where the lock file says the dependency comes from: a
	// registry or index base URL, or for Source "git" the repository URL.
	// Empty when the lock file does not say, in which case the client's
	// configured default applies. When the lock file pointed at this proxy,
	// Registry is the upstream's own URL (Upstream names it), or the proxy's
	// token-free mount of the upstream when that URL is not known.
	Registry string `json:"registry,omitempty"`
	// URL is the download URL the lock file records for the artifact, when it
	// records one: credentials, query and fragment removed, and in the proxy's
	// canonical token-free form when it pointed at the proxy.
	URL string `json:"url,omitempty"`
	// Upstream is the proxy upstream the lock file's URL points at, when the
	// lock file was resolved through this proxy.
	Upstream string `json:"upstream,omitempty"`
	// Source is how the dependency is fetched: "" from a registry, "git" from a
	// repository (Revision is the commit), "url" from a direct download URL.
	Source string `json:"source,omitempty"`
	// Revision is the commit a Source "git" dependency is pinned to.
	Revision string `json:"revision,omitempty"`
	// Dev marks a dependency the lock file records as development-only.
	Dev bool `json:"dev,omitempty"`
	// Unverified is set when nothing the lock file records pins the
	// dependency's content: no digest of the artifact (or of a manifest that
	// hashes it) and, for a Git dependency, no commit ID. UnverifiedReason
	// says why: the format records no digest at all (renv.lock, a
	// Puppetfile, gradle.lockfile), this entry has none where others may (a
	// requirement without --hash), or what is hashed is only a document next
	// to the artifact (a go.mod). Later stages must treat such a dependency
	// as unverified — its version names an artifact, but nothing in the lock
	// file checks the bytes served for it. A digest is never made up.
	Unverified       bool   `json:"unverified,omitempty"`
	UnverifiedReason string `json:"unverifiedReason,omitempty"`
	// File is the lock file's path in the repository (slash-separated) and Line
	// the 1-based line the dependency's entry starts on.
	File string `json:"file"`
	Line int    `json:"line"`
}

// Sources a dependency can be fetched from (Dependency.Source).
const (
	SourceRegistry = ""
	SourceGit      = "git"
	SourceURL      = "url"
)

// Key identifies the dependency within one lock file: duplicates (the same
// package version at two places in a node_modules tree, or in two target
// frameworks) collapse onto one entry.
func (d Dependency) Key() string {
	return strings.Join([]string{d.Type, d.Name, d.Version, d.ID, d.Source, d.Registry, d.Revision}, "\x00")
}

// Digest is an integrity value a lock file records.
type Digest struct {
	// Algorithm is the hash function: "sha1", "sha256", "sha384", "sha512",
	// "md5", or "h1" (the directory hash of Go modules and Terraform
	// providers: a SHA-256 over the sorted SHA-256 sums of the files).
	Algorithm string `json:"algorithm"`
	// Value is the digest in lower-case hex, or for "h1" the base64 text as
	// written.
	Value string `json:"value"`
	// Of says what was hashed when it is not simply the artifact the registry
	// serves for the coordinate: a distribution file name (a Python package
	// has a wheel per platform and an sdist, each with its own hash), "go.mod"
	// for the hash of a Go module's go.mod, "yarn-cache" for Yarn Berry's
	// checksum of the archive in its own cache, "git-tree" for the hash of a
	// Git tree object, "nar" for Nix's hash of a source tree's archive
	// serialisation. DigestKinds lists every value with its meaning.
	Of string `json:"of,omitempty"`
}

// String returns "<algorithm>:<value>", with " (<of>)" when Of is set.
func (d Digest) String() string {
	s := d.Algorithm + ":" + d.Value
	if d.Of != "" {
		s += " (" + d.Of + ")"
	}
	return s
}

// Result is what a parser reads from one file.
type Result struct {
	// FormatVersion is the version of the format the file declares
	// ("3" for package-lock.json v3), when it declares one.
	FormatVersion string
	// Dependencies are the exact dependencies the file pins. File is filled in
	// by the caller; Type defaults to the parser's.
	Dependencies []Dependency
	// Warnings describe entries the parser understood but did not turn into a
	// dependency (a range instead of a pin, a local path, an unresolvable
	// property) or could not read. They name packages, never quote URLs.
	Warnings []string

	// submodules are the submodules a .gitmodules file declares. They become
	// dependencies once the tree's gitlinks say which commit each is pinned
	// to (joinSubmodules).
	submodules []submoduleDecl
	// parsedAs is the parser whose format a file turned out to be in, when a
	// file name two formats share was read as the other one (Rye's pip
	// requirements.lock under Helm's name).
	parsedAs Parser
	// extra is what a parser keeps of a file for its Merger (the module
	// blocks of a Terraform file).
	extra any
	// overflow is set when the file names more than MaxDependenciesPerFile
	// dependencies; the file is then refused (see add).
	overflow bool
}

// MaxDependenciesPerFile bounds the dependencies one lock file may name. A
// format of one short line per dependency (requirements.txt, go.sum, a
// gradle.lockfile) lets a few megabytes name hundreds of thousands, each held
// as a Dependency several times the size of its line: without a bound, a
// hostile lock file in a repository the proxy scans (Task 180) is a memory
// exhaustion attack on the proxy. The largest real lock files hold a few ten
// thousand.
const MaxDependenciesPerFile = 100_000

// add appends a dependency, unless the file has reached the bound: from then
// on the file is marked and its further dependencies dropped, and parseOne
// refuses the whole file. What a parser goes on to read of the file is
// garbage the collector reclaims, so the live memory of a file stays bounded.
func (r *Result) add(d Dependency) {
	if len(r.Dependencies) >= MaxDependenciesPerFile {
		r.overflow = true
		return
	}
	r.Dependencies = append(r.Dependencies, d)
}

func (r *Result) warnf(format string, args ...any) {
	if len(r.Warnings) < maxWarnings {
		r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
	} else if len(r.Warnings) == maxWarnings {
		r.Warnings = append(r.Warnings, "further warnings omitted")
	}
}

// maxWarnings bounds the warnings kept per file.
const maxWarnings = 200

// Parser reads one lock-file format. Implementations must be safe for
// concurrent use and must be pure: no network, no file system, no processes.
type Parser interface {
	// Type is the upstream type of the dependencies the format pins.
	Type() string
	// Format names the format, e.g. "package-lock.json".
	Format() string
	// Detect reports whether the file at path — slash-separated, relative to
	// the repository root — is in this format. It decides from the path alone.
	Detect(path string) bool
	// Parse reads one file's content. Any input is possible; a file that is
	// not in the format is an error, not a panic.
	Parse(data []byte) (*Result, error)
}

// Merger is implemented by a parser whose format is one half of a pair of
// files in the same directory: go.sum holds the hashes of the modules go.mod
// selects. Merge is called with the outcome of every file in the directory,
// after each was parsed, and may move information between them.
type Merger interface {
	Merge(files []*File)
}

// Registry holds the parsers, keyed by upstream type, in detection order.
type Registry struct {
	parsers []Parser
	byType  map[string][]Parser
}

// NewRegistry returns a registry of the given parsers. Detection tries them in
// order. Two parsers of the same format are an error.
func NewRegistry(parsers ...Parser) (*Registry, error) {
	r := &Registry{byType: map[string][]Parser{}}
	seen := map[string]bool{}
	for _, p := range parsers {
		if p == nil || p.Type() == "" || p.Format() == "" {
			return nil, fmt.Errorf("lockfiles: a parser needs a type and a format")
		}
		key := p.Type() + "/" + p.Format()
		if seen[key] {
			return nil, fmt.Errorf("lockfiles: two parsers for %s", key)
		}
		seen[key] = true
		r.parsers = append(r.parsers, p)
		r.byType[p.Type()] = append(r.byType[p.Type()], p)
	}
	return r, nil
}

// defaultRegistry is the registry of every built-in parser.
var defaultRegistry = func() *Registry {
	r, err := NewRegistry(builtinParsers()...)
	if err != nil {
		panic(err)
	}
	return r
}()

// DefaultRegistry returns the registry of the built-in parsers.
func DefaultRegistry() *Registry { return defaultRegistry }

// Parsers returns the parsers of an upstream type (aliases resolved).
func (r *Registry) Parsers(upstreamType string) []Parser {
	return append([]Parser(nil), r.byType[CanonicalType(upstreamType)]...)
}

// All returns every parser, in detection order.
func (r *Registry) All() []Parser { return append([]Parser(nil), r.parsers...) }

// Types returns the upstream types that have a parser, sorted.
func (r *Registry) Types() []string {
	out := make([]string, 0, len(r.byType))
	for t := range r.byType {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Detect returns the parser for the file at p, or nil when it is not a lock
// file any parser knows.
func (r *Registry) Detect(p string) Parser {
	for _, parser := range r.parsers {
		if parser.Detect(p) {
			return parser
		}
	}
	return nil
}

// typeAliases maps the alternative names the configuration accepts for an
// upstream type to the type (config.UpstreamTypes lists both).
var typeAliases = map[string]string{"deb": "apt", "rpm": "yum", "pub": "dart"}

// CanonicalType resolves an upstream type alias ("deb" → "apt").
func CanonicalType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if c, ok := typeAliases[t]; ok {
		return c
	}
	return t
}

// baseName returns the last element of a slash-separated path ("" for a path
// ending in "/", which names a directory).
func baseName(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

// dirName returns the directory of a slash-separated path ("" for the root).
func dirName(p string) string {
	d := path.Dir(p)
	if d == "." || d == "/" {
		return ""
	}
	return d
}
