package locate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// Version listing (Task 182): the maintenance updater asks, for a dependency a
// lock file pins, which versions its registry offers. The listing is read
// through the proxy — the gated pipeline, as the system principal of the
// repository's tenant — from the same upstream the dependency is located
// through (SelectUpstream): a newer version is only ever looked for where the
// pinned one came from.
//
// What a listing carries besides the versions depends on the registry's
// metadata: npm packuments and Cargo index files state each version's declared
// dependencies, which is what the updater compares to decide whether a version
// can replace another without the dependency graph being resolved again
// (Release.Fingerprint). A Go module's versions come from its @v/list; its
// requirements are in each version's go.mod (ModFile). Python distributions
// are listed from the project's simple page; their requirements are read from
// the JSON API (PythonRequirements).

// Release is one version a registry lists for a package.
type Release struct {
	// Version is the version as the registry spells it.
	Version string `json:"version"`
	// Yanked reports that the registry withdrew the version (a yanked crate, a
	// Python release all of whose files are yanked): resolvers skip it unless
	// it is pinned exactly, and the updater never proposes one.
	Yanked bool `json:"yanked,omitempty"`
	// Deprecated is the registry's deprecation message (npm), if any.
	Deprecated string `json:"deprecated,omitempty"`
	// Published is when the registry says the version was published; zero
	// when the listing does not say.
	Published time.Time `json:"published,omitzero"`
	// Requires are the dependencies the version declares, when the listing
	// states them (npm, Cargo).
	Requires []Requirement `json:"requires,omitempty"`
	// Fingerprint identifies everything a resolver — and, for npm, a lock
	// entry — reads of the version besides its name, version and digests: its
	// dependencies of every kind, features, platform constraints. Two versions
	// with the same fingerprint can replace each other in a lock file without
	// the graph changing. Empty when the listing does not carry the data.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Integrity are the digests the registry metadata states for the version's
	// artifact (npm dist.integrity, Cargo cksum). They are compared with the
	// bytes the proxy fetches, never used in their place.
	Integrity []lockfiles.Digest `json:"integrity,omitempty"`
}

// Requirement is one dependency a version declares.
type Requirement struct {
	// Name is the dependency's name (for a renamed Cargo dependency, the
	// package's own name).
	Name string `json:"name"`
	// Constraint is the requirement as the metadata spells it ("^1.2.0").
	Constraint string `json:"constraint"`
	// Kind is "" (normal), "dev", "build", "peer" or "optional".
	Kind string `json:"kind,omitempty"`
}

// Listing is what a registry offers for one package.
type Listing struct {
	// Upstream is the upstream the listing was read through; Document the
	// backend-relative path of the document read.
	Upstream string `json:"upstream"`
	Document string `json:"document"`
	// Releases are the versions listed, in the registry's order.
	Releases []Release `json:"releases"`
}

// Release returns the listed release of a version.
func (l *Listing) Release(version string) (Release, bool) {
	for _, r := range l.Releases {
		if r.Version == version {
			return r, true
		}
	}
	return Release{}, false
}

// listers are the types whose versions can be listed, by canonical type.
var listers = map[string]func(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) (*Listing, error){
	"npm":   listNPM,
	"pip":   listPip,
	"cargo": listCargo,
	"go":    listGo,
}

// Listable reports whether versions of an upstream type can be listed.
func Listable(t string) bool {
	_, ok := listers[lockfiles.CanonicalType(t)]
	return ok
}

// ListableTypes returns the types whose versions can be listed, sorted.
func ListableTypes() []string {
	out := make([]string, 0, len(listers))
	for t := range listers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// maxListedReleases bounds the releases one listing holds: a registry that
// answers with more is not read further (the newest are what matter, and every
// one of them is held in memory with its requirements).
const maxListedReleases = 20000

// ListVersions reads the versions the registry dep came from offers for it.
func ListVersions(ctx context.Context, env Env, dep lockfiles.Dependency) (*Listing, error) {
	t := lockfiles.CanonicalType(dep.Type)
	if dep.Source != lockfiles.SourceRegistry {
		return nil, unsupported("only registry dependencies have newer versions to list; this one is fetched from %s", sourceLabel(dep.Source))
	}
	list, ok := listers[t]
	if !ok {
		return nil, unsupported("listing the versions of %s packages is not implemented", t)
	}
	if strings.TrimSpace(dep.Name) == "" || strings.ContainsAny(dep.Name, "\x00\r\n?#") {
		return nil, fmt.Errorf("locate: %q is not a package name", dep.Name)
	}
	up, _, err := SelectUpstream(env, dep)
	if err != nil {
		return nil, err
	}
	l, err := list(ctx, env, dep, up)
	if err != nil {
		return nil, err
	}
	l.Upstream = up.Name
	return l, nil
}

func sourceLabel(src string) string {
	switch src {
	case lockfiles.SourceGit:
		return "a Git repository"
	case lockfiles.SourceURL:
		return "a direct URL"
	}
	return src
}

// --- npm ----------------------------------------------------------------------

// npmLockFields are the fields of a version's manifest that npm copies into a
// package-lock entry, or that decide how the tree is resolved and installed.
// A version can replace another in place only when all of them are equal.
var npmLockFields = []string{
	"dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta",
	"bundleDependencies", "bundledDependencies", "os", "cpu", "libc", "engines", "bin",
	"license", "funding", "hasInstallScript", "deprecated", "gypfile",
}

// npmInstallScripts are the lifecycle scripts that make npm record
// hasInstallScript.
var npmInstallScripts = []string{"preinstall", "install", "postinstall"}

// listNPM reads the packument "/<name>" (pkgmgr npmClassify: metadata).
func listNPM(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) (*Listing, error) {
	if err := requireName(dep.Name); err != nil {
		return nil, err
	}
	p := "/" + dep.Name
	doc, err := fetchDocument(ctx, env, up, p, "application/json")
	if err != nil {
		return nil, err
	}
	l, err := ParseNPMPackument(doc.Body)
	if err != nil {
		return nil, fmt.Errorf("locate: reading the packument of %s: %w", dep.Name, err)
	}
	l.Document = p
	return l, nil
}

// ParseNPMPackument reads the versions of an npm packument.
func ParseNPMPackument(body []byte) (*Listing, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	var versions map[string]json.RawMessage
	if raw, ok := top["versions"]; ok {
		if err := json.Unmarshal(raw, &versions); err != nil {
			return nil, fmt.Errorf("versions: %w", err)
		}
	}
	times := map[string]string{}
	if raw, ok := top["time"]; ok {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) == nil {
			for k, v := range m {
				var s string
				if json.Unmarshal(v, &s) == nil {
					times[k] = s
				}
			}
		}
	}
	if len(versions) > maxListedReleases {
		return nil, fmt.Errorf("the packument lists %d versions, more than the %d read", len(versions), maxListedReleases)
	}
	l := &Listing{}
	for v, raw := range versions {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			continue // a version entry that is not an object names nothing installable
		}
		r := Release{Version: v}
		if t, err := time.Parse(time.RFC3339, times[v]); err == nil {
			r.Published = t
		}
		if d, ok := fields["deprecated"]; ok {
			var s string
			if json.Unmarshal(d, &s) == nil {
				r.Deprecated = s
			}
		}
		for _, kind := range []struct{ field, kind string }{
			{"dependencies", ""}, {"optionalDependencies", "optional"}, {"peerDependencies", "peer"},
		} {
			var m map[string]string
			if raw, ok := fields[kind.field]; ok && json.Unmarshal(raw, &m) == nil {
				names := sortedKeys(m)
				for _, n := range names {
					r.Requires = append(r.Requires, Requirement{Name: n, Constraint: m[n], Kind: kind.kind})
				}
			}
		}
		if raw, ok := fields["dist"]; ok {
			var dist struct {
				Integrity string `json:"integrity"`
				Shasum    string `json:"shasum"`
			}
			if json.Unmarshal(raw, &dist) == nil {
				r.Integrity = sriDigests(dist.Integrity)
				if len(dist.Shasum) == 40 {
					r.Integrity = append(r.Integrity, lockfiles.Digest{Algorithm: "sha1", Value: strings.ToLower(dist.Shasum)})
				}
			}
		}
		r.Fingerprint = npmFingerprint(fields)
		l.Releases = append(l.Releases, r)
	}
	sort.Slice(l.Releases, func(i, j int) bool { return l.Releases[i].Version < l.Releases[j].Version })
	return l, nil
}

// npmFingerprint digests the fields of a version manifest npm reads into its
// lock file or its resolution. JSON objects are re-encoded with sorted keys,
// so a registry's key order does not make two equal manifests differ.
func npmFingerprint(fields map[string]json.RawMessage) string {
	canon := map[string]any{}
	for _, f := range npmLockFields {
		raw, ok := fields[f]
		if !ok {
			continue
		}
		var v any
		if json.Unmarshal(raw, &v) == nil && v != nil {
			canon[f] = v
		}
	}
	// npm derives hasInstallScript from the scripts when the registry does
	// not state it.
	if _, ok := canon["hasInstallScript"]; !ok {
		var scripts map[string]any
		if raw, ok := fields["scripts"]; ok && json.Unmarshal(raw, &scripts) == nil {
			for _, s := range npmInstallScripts {
				if _, has := scripts[s]; has {
					canon["hasInstallScript"] = true
				}
			}
		}
	}
	return fingerprint(canon)
}

// sriDigests reads a Subresource Integrity value ("sha512-<base64> sha1-…").
func sriDigests(sri string) []lockfiles.Digest {
	var out []lockfiles.Digest
	for _, part := range strings.Fields(sri) {
		algo, b64, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		switch algo = strings.ToLower(algo); algo {
		case "sha1", "sha256", "sha384", "sha512":
			out = append(out, lockfiles.Digest{Algorithm: algo, Value: hex.EncodeToString(raw)})
		}
	}
	return out
}

// --- Cargo --------------------------------------------------------------------

// cargoIndexPath is a crate's file in the sparse index (RFC 2789): the
// lower-cased name below "1/", "2/", "3/<c>/" or "<cc>/<cc>/".
func cargoIndexPath(name string) (string, error) {
	n := strings.ToLower(name)
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", fmt.Errorf("locate: %q is not a crate name", name)
		}
	}
	switch len(n) {
	case 0:
		return "", errors.New("locate: empty crate name")
	case 1:
		return "/1/" + n, nil
	case 2:
		return "/2/" + n, nil
	case 3:
		return "/3/" + n[:1] + "/" + n, nil
	}
	return "/" + n[:2] + "/" + n[2:4] + "/" + n, nil
}

// listCargo reads the crate's sparse-index file (pkgmgr cargoIsIndexFile).
func listCargo(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) (*Listing, error) {
	p, err := cargoIndexPath(dep.Name)
	if err != nil {
		return nil, err
	}
	doc, err := fetchDocument(ctx, env, up, p, "")
	if err != nil {
		return nil, err
	}
	l, err := ParseCargoIndex(doc.Body, dep.Name)
	if err != nil {
		return nil, fmt.Errorf("locate: reading the index file of %s: %w", dep.Name, err)
	}
	l.Document = p
	return l, nil
}

// cargoIndexLine is one version of a crate in the index.
type cargoIndexLine struct {
	Name     string            `json:"name"`
	Vers     string            `json:"vers"`
	Deps     []json.RawMessage `json:"deps"`
	Cksum    string            `json:"cksum"`
	Features json.RawMessage   `json:"features"`
	Feat2    json.RawMessage   `json:"features2"`
	Yanked   bool              `json:"yanked"`
	Links    json.RawMessage   `json:"links"`
	Rust     json.RawMessage   `json:"rust_version"`
}

// cargoDep is one dependency of an index line.
type cargoDep struct {
	Name            string   `json:"name"`
	Req             string   `json:"req"`
	Features        []string `json:"features"`
	Optional        bool     `json:"optional"`
	DefaultFeatures *bool    `json:"default_features"`
	Target          *string  `json:"target"`
	Kind            string   `json:"kind"`
	Registry        *string  `json:"registry"`
	Package         *string  `json:"package"`
}

// maxIndexBytes bounds an index document the listing reads.
const maxIndexBytes = 64 << 20

// ParseCargoIndex reads a crate's sparse-index file: one JSON object per line.
// Lines naming another crate are ignored.
func ParseCargoIndex(body []byte, name string) (*Listing, error) {
	if len(body) > maxIndexBytes {
		return nil, fmt.Errorf("the index file is larger than %d bytes", maxIndexBytes)
	}
	l := &Listing{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e cargoIndexLine
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("an index line is not JSON: %w", err)
		}
		if !strings.EqualFold(strings.ReplaceAll(e.Name, "_", "-"), strings.ReplaceAll(name, "_", "-")) || e.Vers == "" {
			continue
		}
		if len(l.Releases) >= maxListedReleases {
			return nil, fmt.Errorf("the index lists more than %d versions", maxListedReleases)
		}
		r := Release{Version: e.Vers, Yanked: e.Yanked}
		if len(e.Cksum) == 64 {
			r.Integrity = []lockfiles.Digest{{Algorithm: "sha256", Value: strings.ToLower(e.Cksum)}}
		}
		canonDeps := make([]any, 0, len(e.Deps))
		for _, raw := range e.Deps {
			var d cargoDep
			if err := json.Unmarshal(raw, &d); err != nil {
				return nil, fmt.Errorf("%s %s: a dependency is not an object: %w", e.Name, e.Vers, err)
			}
			pkg := d.Name
			if d.Package != nil && *d.Package != "" {
				pkg = *d.Package
			}
			kind := d.Kind
			if kind == "normal" {
				kind = ""
			}
			r.Requires = append(r.Requires, Requirement{Name: pkg, Constraint: d.Req, Kind: kind})
			var v any
			if json.Unmarshal(raw, &v) == nil {
				canonDeps = append(canonDeps, v)
			}
		}
		// The fingerprint covers what cargo's resolver reads of the version:
		// its dependencies (with their features, kinds and targets, in a
		// canonical order), its features, and links.
		sort.Slice(canonDeps, func(i, j int) bool { return fingerprint(canonDeps[i]) < fingerprint(canonDeps[j]) })
		canon := map[string]any{"deps": canonDeps}
		for k, raw := range map[string]json.RawMessage{"features": e.Features, "features2": e.Feat2, "links": e.Links} {
			var v any
			if len(raw) > 0 && json.Unmarshal(raw, &v) == nil && v != nil {
				if m, ok := v.(map[string]any); ok && len(m) == 0 {
					continue
				}
				canon[k] = v
			}
		}
		r.Fingerprint = fingerprint(canon)
		l.Releases = append(l.Releases, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return l, nil
}

// --- Go -----------------------------------------------------------------------

// listGo reads "/<module>/@v/list" (pkgmgr goClassify: metadata). The list
// holds the module's tagged versions; pseudo-versions are never listed, and a
// module pinned at one has no newer tagged version to find there unless it
// was tagged since.
func listGo(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) (*Listing, error) {
	mod, err := goEscape(dep.Name)
	if err != nil {
		return nil, err
	}
	p := "/" + mod + "/@v/list"
	doc, err := fetchDocument(ctx, env, up, p, "")
	if err != nil {
		return nil, err
	}
	l := &Listing{Document: p}
	for _, line := range strings.Split(string(doc.Body), "\n") {
		v := strings.TrimSpace(line)
		if v == "" || strings.ContainsAny(v, " \t") {
			continue
		}
		if len(l.Releases) >= maxListedReleases {
			return nil, fmt.Errorf("locate: the module lists more than %d versions", maxListedReleases)
		}
		l.Releases = append(l.Releases, Release{Version: v})
	}
	// A module withdraws versions with retract directives in the go.mod of
	// its latest version, which the go command reads; the listing does not
	// say. A retracted version is treated as yanked.
	var modDoc Document
	var lastErr error
	tried := 0
	for _, latest := range latestGoVersions(l.Releases) {
		if tried == 3 {
			break
		}
		tried++
		ver, err := goEscape(latest)
		if err != nil {
			return nil, err
		}
		modDoc, lastErr = fetchDocument(ctx, env, up, "/"+mod+"/@v/"+ver+".mod", "")
		if lastErr == nil || modDoc.Status != 404 {
			break
		}
	}
	if tried == 0 {
		return l, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("locate: reading the retractions of %s (the go.mod of its latest version): %w", dep.Name, lastErr)
	}
	retracted := GoModRetractions(modDoc.Body)
	for i := range l.Releases {
		if retracted(l.Releases[i].Version) {
			l.Releases[i].Yanked = true
		}
	}
	return l, nil
}

// latestGoVersions orders the versions whose go.mod the go command reads a
// module's retractions from, most likely first: its latest version is the
// highest release (not "+incompatible", which a module with a go.mod does not
// have), else the highest pre-release. The next ones are what is tried when
// the proxy has no go.mod of the first.
func latestGoVersions(rels []Release) []string {
	sch, _ := versions.For("go")
	var vs []versions.Version
	for _, r := range rels {
		if v, err := sch.Parse(r.Version); err == nil {
			vs = append(vs, v)
		}
	}
	rank := func(v versions.Version) int {
		switch {
		case strings.HasSuffix(v.String(), "+incompatible"):
			return 0
		case v.Prerelease():
			return 1
		}
		return 2
	}
	sort.SliceStable(vs, func(i, j int) bool {
		if ri, rj := rank(vs[i]), rank(vs[j]); ri != rj {
			return ri > rj
		}
		return sch.Compare(vs[i], vs[j]) > 0
	})
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.String()
	}
	return out
}

// GoModRetractions reads the retract directives of a go.mod — single versions
// ("retract v1.0.1") and closed intervals ("retract [v1.0.0, v1.0.5]"), in
// blocks or alone — and returns whether a version is retracted.
func GoModRetractions(mod []byte) func(version string) bool {
	sch, _ := versions.For("go")
	type interval struct{ lo, hi versions.Version }
	var spans []interval
	add := func(args string) {
		args = strings.TrimSpace(args)
		if strings.HasPrefix(args, "[") && strings.HasSuffix(args, "]") {
			lo, hi, ok := strings.Cut(strings.Trim(args, "[]"), ",")
			if !ok {
				return
			}
			l, err1 := sch.Parse(strings.TrimSpace(lo))
			h, err2 := sch.Parse(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil {
				spans = append(spans, interval{l, h})
			}
			return
		}
		if v, err := sch.Parse(strings.Trim(args, `"`)); err == nil {
			spans = append(spans, interval{v, v})
		}
	}
	block := false
	for _, raw := range strings.Split(string(mod), "\n") {
		line := raw
		if c := strings.Index(line, "//"); c >= 0 {
			line = line[:c]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case block && line == ")":
			block = false
		case block:
			add(line)
		case line == "retract (":
			block = true
		case strings.HasPrefix(line, "retract "):
			if rest := strings.TrimSpace(strings.TrimPrefix(line, "retract ")); rest == "(" {
				block = true
			} else {
				add(rest)
			}
		}
		if len(spans) > 10_000 {
			break
		}
	}
	return func(version string) bool {
		v, err := sch.Parse(version)
		if err != nil {
			return false
		}
		for _, sp := range spans {
			if sch.Compare(v, sp.lo) >= 0 && sch.Compare(v, sp.hi) <= 0 {
				return true
			}
		}
		return false
	}
}

// ModFile reads the go.mod of a module version through the proxy
// ("/<module>/@v/<version>.mod"), for its requirements.
func ModFile(ctx context.Context, env Env, dep lockfiles.Dependency, version string) ([]byte, error) {
	up, _, err := SelectUpstream(env, dep)
	if err != nil {
		return nil, err
	}
	mod, err := goEscape(dep.Name)
	if err != nil {
		return nil, err
	}
	ver, err := goEscape(version)
	if err != nil {
		return nil, err
	}
	doc, err := fetchDocument(ctx, env, up, "/"+mod+"/@v/"+ver+".mod", "")
	if err != nil {
		return nil, err
	}
	return doc.Body, nil
}

// GoModRequires reads the require directives of a go.mod: module path → the
// version required, and a fingerprint of them. Comments are dropped; a
// malformed line is an error (the caller then cannot show that the graph is
// unchanged, and does not try).
func GoModRequires(mod []byte) (map[string]string, string, error) {
	reqs := map[string]string{}
	block := ""
	for i, raw := range strings.Split(string(mod), "\n") {
		line := raw
		if c := strings.Index(line, "//"); c >= 0 {
			line = line[:c]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		verb, args := f[0], f[1:]
		if block != "" {
			if f[0] == ")" {
				block = ""
				continue
			}
			verb, args = block, f
		} else if len(args) == 1 && args[0] == "(" {
			block = verb
			continue
		}
		if verb != "require" {
			continue
		}
		if len(args) != 2 {
			return nil, "", fmt.Errorf("go.mod line %d: a require directive without a module and a version", i+1)
		}
		path, ver := strings.Trim(args[0], `"`), strings.Trim(args[1], `"`)
		if path == "" || ver == "" {
			return nil, "", fmt.Errorf("go.mod line %d: an empty module path or version", i+1)
		}
		reqs[path] = ver
	}
	return reqs, fingerprint(reqs), nil
}

// --- pip ----------------------------------------------------------------------

// listPip reads the project's simple page (PEP 503/691) and groups its files
// by version (from the file names). A version all of whose files are yanked
// (PEP 592) is yanked.
func listPip(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) (*Listing, error) {
	name := pipNormalize(dep.Name)
	page := "/simple/" + segment(name) + "/"
	doc, err := fetchDocument(ctx, env, up, page, "application/vnd.pypi.simple.v1+json, text/html;q=0.1")
	if err != nil {
		return nil, err
	}
	files, err := parseSimplePage(doc)
	if err != nil {
		return nil, fmt.Errorf("locate: reading the simple page of %s: %w", name, err)
	}
	type acc struct {
		version         string
		files, yanked   int
		canonical       string
		hashes          []lockfiles.Digest
		requiresPython  string
		requiresPyConfl bool
	}
	byVersion := map[string]*acc{}
	var order []string
	for _, f := range files {
		v, ok := pipFileVersion(name, f.Filename)
		if !ok {
			continue
		}
		c := pipCanonicalVersion(v)
		a := byVersion[c]
		if a == nil {
			if len(byVersion) >= maxListedReleases {
				return nil, fmt.Errorf("locate: the simple page lists more than %d versions", maxListedReleases)
			}
			a = &acc{version: v, canonical: c}
			byVersion[c] = a
			order = append(order, c)
		}
		a.files++
		if f.Yanked {
			a.yanked++
		}
		if f.SHA256 != "" {
			a.hashes = append(a.hashes, lockfiles.Digest{Algorithm: "sha256", Value: f.SHA256, Of: f.Filename})
		}
	}
	l := &Listing{Document: page}
	for _, c := range order {
		a := byVersion[c]
		l.Releases = append(l.Releases, Release{Version: a.version, Yanked: a.files > 0 && a.yanked == a.files, Integrity: a.hashes})
	}
	return l, nil
}

// PythonRequirements reads the requirements a Python release declares
// (Requires-Dist) from the registry's JSON API ("/pypi/<project>/<version>/json",
// pkgmgr pipClassify: metadata), with a fingerprint of them. known is false
// when the registry does not state them (an index without the JSON API, a
// release whose metadata it does not carry).
func PythonRequirements(ctx context.Context, env Env, dep lockfiles.Dependency, version string) (reqs []string, fp string, known bool, err error) {
	up, _, err := SelectUpstream(env, dep)
	if err != nil {
		return nil, "", false, err
	}
	name := pipNormalize(dep.Name)
	doc, err := fetchDocument(ctx, env, up, "/pypi/"+segment(name)+"/"+segment(version)+"/json", "application/json")
	if err != nil {
		if doc.Status == 404 {
			return nil, "", false, nil
		}
		return nil, "", false, err
	}
	var body struct {
		Info struct {
			Version      string   `json:"version"`
			RequiresDist []string `json:"requires_dist"`
		} `json:"info"`
	}
	if err := json.Unmarshal(doc.Body, &body); err != nil {
		return nil, "", false, fmt.Errorf("locate: reading the JSON metadata of %s %s: %w", name, version, err)
	}
	if !pipSameVersion(body.Info.Version, version) {
		return nil, "", false, nil
	}
	reqs = append([]string(nil), body.Info.RequiresDist...)
	norm := make([]string, len(reqs))
	for i, r := range reqs {
		norm[i] = strings.Join(strings.Fields(r), " ")
	}
	sort.Strings(norm)
	return reqs, fingerprint(norm), true, nil
}

// --- shared -------------------------------------------------------------------

// requireName fails an npm name that cannot be a path below the registry.
func requireName(name string) error {
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "\x00\r\n?#%\\") {
			return fmt.Errorf("locate: %q is not a registry name", name)
		}
	}
	if strings.Count(name, "/") > 1 || (strings.Contains(name, "/") && !strings.HasPrefix(name, "@")) {
		return fmt.Errorf("locate: %q is not an npm package name", name)
	}
	if _, err := url.Parse("/" + name); err != nil {
		return fmt.Errorf("locate: %q is not a registry name", name)
	}
	return nil
}

// fingerprint digests a JSON-encodable value: encoding/json writes map keys
// sorted, so equal values give equal fingerprints.
func fingerprint(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
