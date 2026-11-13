// Package locate turns a dependency a lock file pins into the requests that
// fetch its artifacts through the proxy (Task 180).
//
// The repository tracker pins a release's dependencies by fetching each of them
// through the proxy's own gated serve pipeline, exactly as a client would. A
// lock file says what a dependency is — type, name, exact version, sometimes a
// download URL, often digests — but not where on the proxy it is served. That
// is the backends' business: each parses a request path into a coordinate.
// This package is the inverse: for a dependency it chooses the configured
// upstream to fetch through (the one the lock file's registry names, never
// another registry's package of the same name), and builds the backend-relative
// paths of its artifacts. Where the path cannot be built from the lock file
// alone it reads the registry's index through the proxy first (a PyPI simple
// page, a NuGet service index, a Maven POM, an OCI image index).
//
// Every artifact carries the digests the lock file records for it, so the
// fetched bytes can be checked against what the lock file pins (see Checker).
// A dependency no locator can fetch is reported with an UnsupportedError that
// says why; the release it belongs to is then not fully pinned.
package locate

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// Upstream is a configured upstream a dependency can be fetched through.
type Upstream struct {
	// Name is the upstream's name: the "<name>" of /v1/<name>/.
	Name string
	// Type is its upstream type ("npm", "pip", …; aliases allowed).
	Type string
	// URLs are the upstream's base URL followed by its mirrors' URLs.
	URLs []string
	// Settings are the backend settings (filesUrl, downloadUrl, oci, …).
	Settings map[string]string
}

// Artifact is one object of a dependency to fetch and pin.
type Artifact struct {
	// Upstream is the configured upstream to fetch through.
	Upstream string `json:"upstream"`
	// Path is the backend-relative request path, with a leading "/".
	Path string `json:"path"`
	// Accept is the Accept header to send, when the protocol needs one.
	Accept string `json:"accept,omitempty"`
	// Role says what the object is to the dependency: "package" (the
	// artifact itself), "file" (one of several distribution files),
	// "go.mod", "pom", "manifest", "index", "config", "layer".
	Role string `json:"role"`
	// File is the distribution file's name, when the protocol has one.
	File string `json:"file,omitempty"`
	// Expect are the lock file's digests of this object. Checker holds the
	// fetched bytes to them.
	Expect []lockfiles.Digest `json:"expect,omitempty"`
	// Optional marks an object the dependency is complete without (a Go
	// module's .info document).
	Optional bool `json:"optional,omitempty"`
	// Fallback is a path to try when Path answers 404 (a CRAN package that
	// has moved to the archive).
	Fallback string `json:"fallback,omitempty"`
	// Error, when set, says why an object the lock file names could not be
	// located (a distribution file its index does not list); it is recorded
	// as a failure rather than fetched.
	Error string `json:"error,omitempty"`
}

// Plan is the outcome of locating one dependency.
type Plan struct {
	// Upstream is the upstream chosen.
	Upstream string `json:"upstream"`
	// Artifacts are the objects to fetch, in order.
	Artifacts []Artifact `json:"artifacts"`
	// Notes explain choices a reader might question (which of several
	// upstreams was taken, which files of a release were selected).
	Notes []string `json:"notes,omitempty"`
}

// UnsupportedError reports a dependency this package cannot fetch through the
// proxy, and why.
type UnsupportedError struct{ Reason string }

func (e *UnsupportedError) Error() string { return e.Reason }

// unsupported returns an UnsupportedError.
func unsupported(format string, args ...any) error {
	return &UnsupportedError{Reason: fmt.Sprintf(format, args...)}
}

// IsUnsupported reports whether err says the dependency cannot be fetched
// through the proxy at all (as opposed to a fetch that failed).
func IsUnsupported(err error) bool {
	var u *UnsupportedError
	return errors.As(err, &u)
}

// RefusedError is returned (wrapped) by a Fetcher when an admission gate
// refused an index document: the dependency is then refused, not failed.
type RefusedError struct {
	Gate   string
	Code   string
	Reason string
}

func (e *RefusedError) Error() string {
	msg := "refused by " + e.Gate
	if e.Code != "" {
		msg += " (" + e.Code + ")"
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// Document is a metadata document fetched through the proxy.
type Document struct {
	Status      int
	ContentType string
	Body        []byte
}

// Fetcher reads a metadata document (an index) through the proxy. It goes
// through the same gated pipeline as any request.
type Fetcher interface {
	FetchDocument(ctx context.Context, upstream, path, accept string) (Document, error)
}

// Platform is an operating system and architecture ("linux", "amd64"), with an
// optional variant ("v8").
type Platform struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Variant string `json:"variant,omitempty"`
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Arch
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// ParsePlatform reads "os/arch[/variant]".
func ParsePlatform(s string) (Platform, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return Platform{}, fmt.Errorf("locate: platform %q is not os/arch[/variant]", s)
	}
	p := Platform{OS: strings.ToLower(parts[0]), Arch: strings.ToLower(parts[1])}
	if len(parts) == 3 {
		p.Variant = strings.ToLower(parts[2])
	}
	return p, nil
}

// DefaultMaxArtifacts bounds the objects one dependency may expand to.
const DefaultMaxArtifacts = 256

// Env is what locating needs besides the dependency.
type Env struct {
	// Upstreams are the configured upstreams.
	Upstreams []Upstream
	// Prefer maps an upstream type to the upstream a repository's
	// dependencies of that type are fetched through, overriding the choice by
	// registry.
	Prefer map[string]string
	// Fetch reads index documents; without it, dependencies whose paths need
	// an index are unsupported.
	Fetch Fetcher
	// Platforms selects the platforms of multi-platform artifacts (container
	// image indexes, Terraform providers). Empty means every platform an
	// image index lists, and linux/amd64 for Terraform providers.
	Platforms []Platform
	// MaxArtifacts bounds the objects one dependency expands to; zero is
	// DefaultMaxArtifacts.
	MaxArtifacts int
}

func (e Env) maxArtifacts() int {
	if e.MaxArtifacts <= 0 {
		return DefaultMaxArtifacts
	}
	return e.MaxArtifacts
}

// locator builds the plan of one dependency type.
type locator func(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error)

// locators are the supported dependency types, by canonical upstream type.
var locators = map[string]locator{
	"npm":       locateNPM,
	"pip":       locatePip,
	"cargo":     locateCargo,
	"go":        locateGo,
	"nuget":     locateNuGet,
	"maven":     locateMaven,
	"rubygems":  locateRubyGems,
	"docker":    locateDocker,
	"helm":      locateHelm,
	"dart":      locateDart,
	"hex":       locateHex,
	"hackage":   locateHackage,
	"puppet":    locatePuppet,
	"ansible":   locateAnsible,
	"swift":     locateSwift,
	"conda":     locateConda,
	"cran":      locateCRAN,
	"cpan":      locateCPAN,
	"julia":     locateJulia,
	"terraform": locateTerraform,
	"homebrew":  locateHomebrew,
	"bazel":     locateBazel,
}

// unsupportedTypes say why a dependency type has no locator.
var unsupportedTypes = map[string]string{
	"git":         "Git dependencies are served from the proxy's Git mirrors, not its package cache, and have no cache object to pin",
	"composer":    "Composer serves distributions under a path built from the package metadata's dist reference, which composer.lock does not carry in a form the proxy can address yet",
	"conan":       "Conan binary packages are addressed by package ID and revision, which conan.lock does not record",
	"jsr":         "JSR packages are sets of module files listed in a version manifest; fetching them through the proxy is not implemented yet",
	"nix":         "Nix flake inputs are fetched from their source repositories, not from a Nix binary cache",
	"apt":         "Debian package paths come from the repository's Packages index; no lock file names them",
	"yum":         "RPM package paths come from the repository's primary.xml; no lock file names them",
	"openvsx":     "no lock-file format pins Open VSX extensions",
	"huggingface": "no lock-file format pins Hugging Face models",
	"generic":     "a generic upstream's paths are defined by its own route configuration",
}

// Supported reports whether dependencies of upstream type t can be located, and
// when not, why.
func Supported(t string) (bool, string) {
	ct := lockfiles.CanonicalType(t)
	if _, ok := locators[ct]; ok {
		return true, ""
	}
	if why, ok := unsupportedTypes[ct]; ok {
		return false, why
	}
	return false, fmt.Sprintf("dependencies of type %q cannot be fetched through the proxy", ct)
}

// SupportedTypes returns the upstream types with a locator, sorted.
func SupportedTypes() []string {
	out := make([]string, 0, len(locators))
	for t := range locators {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// UnsupportedTypes returns the upstream types without a locator and the reason,
// keyed by type.
func UnsupportedTypes() map[string]string {
	out := make(map[string]string, len(unsupportedTypes))
	for k, v := range unsupportedTypes {
		out[k] = v
	}
	return out
}

// Locate plans the fetch of dep's artifacts.
func Locate(ctx context.Context, env Env, dep lockfiles.Dependency) (*Plan, error) {
	t := lockfiles.CanonicalType(dep.Type)
	if dep.Source == lockfiles.SourceGit {
		return nil, unsupported("%s", unsupportedTypes["git"])
	}
	loc, ok := locators[t]
	if !ok {
		_, why := Supported(t)
		return nil, &UnsupportedError{Reason: why}
	}
	up, notes, err := SelectUpstream(env, dep)
	if err != nil {
		return nil, err
	}
	arts, more, err := loc(ctx, env, dep, up)
	if err != nil {
		return nil, err
	}
	if len(arts) == 0 {
		return nil, fmt.Errorf("locate: no artifact found for %s %s@%s", t, dep.Name, dep.Version)
	}
	if max := env.maxArtifacts(); len(arts) > max {
		return nil, fmt.Errorf("locate: %s %s@%s expands to %d objects, more than the limit of %d",
			t, dep.Name, dep.Version, len(arts), max)
	}
	for i := range arts {
		arts[i].Upstream = up.Name
		if arts[i].Error != "" {
			continue
		}
		if !strings.HasPrefix(arts[i].Path, "/") {
			arts[i].Path = "/" + arts[i].Path
		}
		// A path built from a lock file's names and URLs — untrusted input —
		// must stay a plain path once decoded: no query, fragment or control
		// character an upstream URL would read differently, no dot segment.
		if !validLocatedPath(arts[i].Path) {
			arts[i].Error = "the lock file's entry does not name a valid registry path"
		}
	}
	return &Plan{Upstream: up.Name, Artifacts: arts, Notes: append(notes, more...)}, nil
}

// SelectUpstream chooses the configured upstream dep is fetched through.
//
// The rules, in order: the upstream the lock file names when it was resolved
// through this proxy; the upstream the repository is configured to use for
// the type; otherwise an upstream of the type whose URL is the registry the
// lock file names (or, when it names none, any upstream of the type). A
// dependency whose registry no upstream fronts is unsupported — fetching a
// package of the same name from another registry would pin a different
// package.
func SelectUpstream(env Env, dep lockfiles.Dependency) (Upstream, []string, error) {
	t := lockfiles.CanonicalType(dep.Type)
	var candidates []Upstream
	for _, up := range env.Upstreams {
		if lockfiles.CanonicalType(up.Type) == t {
			candidates = append(candidates, up)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	byName := func(name string) (Upstream, bool) {
		for _, up := range candidates {
			if up.Name == name {
				return up, true
			}
		}
		return Upstream{}, false
	}

	if dep.Upstream != "" {
		up, ok := byName(dep.Upstream)
		if !ok {
			return Upstream{}, nil, unsupported("the lock file was resolved through upstream %q, which is not a configured %s upstream", dep.Upstream, t)
		}
		return up, nil, nil
	}
	if name := env.Prefer[t]; name != "" {
		up, ok := byName(name)
		if !ok {
			return Upstream{}, nil, unsupported("the repository fetches %s dependencies through upstream %q, which is not a configured %s upstream", t, name, t)
		}
		var notes []string
		if dep.Registry != "" && !registryMatches(t, up, dep.Registry) {
			notes = append(notes, fmt.Sprintf("the lock file names registry %s; fetched through %q as the repository is configured", registryLabel(dep.Registry), name))
		}
		return up, notes, nil
	}
	if len(candidates) == 0 {
		return Upstream{}, nil, unsupported("no %s upstream is configured", t)
	}
	where := dep.Registry
	if dep.Source == lockfiles.SourceURL && where == "" {
		where = dep.URL
	}
	if where == "" {
		// The lock file does not say where the package came from. With one
		// upstream of the type there is one answer; with several, taking
		// one would be a guess — a private package's name looked up in a
		// public registry is how dependency confusion works.
		if len(candidates) > 1 {
			names := make([]string, len(candidates))
			for i, up := range candidates {
				names[i] = up.Name
			}
			return Upstream{}, nil, unsupported("the lock file does not name the registry, and %d %s upstreams could serve it (%s): set the repository's upstreams.%s to choose",
				len(candidates), t, strings.Join(names, ", "), t)
		}
		return candidates[0], nil, nil
	}
	var matching []Upstream
	for _, up := range candidates {
		if registryMatches(t, up, where) {
			matching = append(matching, up)
		}
	}
	if len(matching) == 0 {
		return Upstream{}, nil, unsupported("no configured %s upstream fronts the registry the lock file names (%s)", t, registryLabel(where))
	}
	var notes []string
	if len(matching) > 1 {
		// Several front the registry the lock file names: any serves the
		// same packages.
		notes = append(notes, fmt.Sprintf("%d %s upstreams front %s; chose %q (set the repository's upstreams.%s to choose)", len(matching), t, registryLabel(where), matching[0].Name, t))
	}
	return matching[0], notes, nil
}

// equivalentHosts groups the hosts one public registry is known by: a lock
// file written against any of them names the same packages.
var equivalentHosts = map[string][][]string{
	"cargo":     {{"github.com/rust-lang/crates.io-index", "index.crates.io", "crates.io", "static.crates.io"}},
	"npm":       {{"registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"}},
	"pip":       {{"pypi.org", "pypi.python.org", "files.pythonhosted.org"}},
	"rubygems":  {{"rubygems.org", "index.rubygems.org", "rubygems.global.ssl.fastly.net"}},
	"nuget":     {{"api.nuget.org", "www.nuget.org", "nuget.org"}},
	"maven":     {{"repo.maven.apache.org", "repo1.maven.org", "central.maven.org", "repo.maven.org"}},
	"docker":    {{"registry-1.docker.io", "docker.io", "index.docker.io", "registry.hub.docker.com"}},
	"go":        {{"proxy.golang.org"}},
	"dart":      {{"pub.dev", "pub.dartlang.org"}},
	"hex":       {{"repo.hex.pm", "hex.pm"}},
	"terraform": {{"registry.terraform.io"}, {"registry.opentofu.org"}},
	"ansible":   {{"galaxy.ansible.com"}},
	"puppet":    {{"forgeapi.puppet.com", "forge.puppet.com", "forgeapi.puppetlabs.com"}},
	"cran":      {{"cloud.r-project.org", "cran.r-project.org", "cran.rstudio.com", "packagemanager.posit.co"}},
	"cpan":      {{"www.cpan.org", "cpan.metacpan.org", "cpan.org"}},
	"conda":     {{"conda.anaconda.org", "repo.anaconda.com"}},
	"bazel":     {{"bcr.bazel.build"}},
	"hackage":   {{"hackage.haskell.org"}},
	"homebrew":  {{"ghcr.io", "formulae.brew.sh"}},
	"julia":     {{"pkg.julialang.org"}},
}

// hostPath reduces a registry or upstream URL to "host/path": lower-case host,
// no scheme, credentials, query, trailing slash or ".git". Docker's
// "registry+https://…"-style prefixes and Cargo's "sparse+" are dropped.
func hostPath(raw string) (host, p string) {
	raw = strings.TrimSpace(raw)
	for _, pfx := range []string{"registry+", "sparse+", "git+"} {
		raw = strings.TrimPrefix(raw, pfx)
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != "443" && port != "80" {
		host += ":" + port
	}
	p = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
	return host, strings.TrimRight(p, "/")
}

// registryMatches reports whether an upstream fronts the registry a lock file
// names: the same host with one path a prefix of the other at a segment
// boundary (an index at "/simple" of an upstream at "/"), or two hosts one
// public registry is known by.
func registryMatches(t string, up Upstream, registry string) bool {
	rh, rp := hostPath(registry)
	if rh == "" {
		return false
	}
	for _, u := range up.URLs {
		uh, upth := hostPath(u)
		if uh == "" {
			continue
		}
		if uh == rh && (pathPrefix(rp, upth) || pathPrefix(upth, rp)) {
			return true
		}
		for _, group := range equivalentHosts[t] {
			if inGroup(group, uh, upth) && inGroup(group, rh, rp) {
				return true
			}
		}
	}
	return false
}

// pathPrefix reports whether prefix is p or a leading run of p's segments.
func pathPrefix(p, prefix string) bool {
	if prefix == "" || p == prefix {
		return true
	}
	return strings.HasPrefix(p, prefix+"/")
}

// inGroup reports whether host+path is one of the group's entries ("host" or
// "host/path").
func inGroup(group []string, host, p string) bool {
	for _, g := range group {
		gh, gp, _ := strings.Cut(g, "/")
		if gh != host {
			continue
		}
		if gp == "" || pathPrefix(strings.TrimPrefix(p, "/"), gp) {
			return true
		}
	}
	return false
}

// registryLabel renders a registry for a reason: its host and path only, never
// credentials or a query.
func registryLabel(raw string) string {
	h, p := hostPath(raw)
	if h == "" {
		return "an unrecognised location"
	}
	return h + p
}

// relativeTo returns the part of a URL beneath one of the upstream's URLs
// ("base+rest"), when it is beneath one.
func relativeTo(up Upstream, raw string) (string, bool) {
	rh, rp := hostPath(raw)
	if rh == "" {
		return "", false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	escaped := strings.TrimSuffix(u.EscapedPath(), "/")
	for _, base := range up.URLs {
		bh, bp := hostPath(base)
		if bh != rh || !pathPrefix(rp, bp) || rp == bp {
			continue
		}
		rest := strings.TrimPrefix(escaped, bp)
		if !strings.HasPrefix(rest, "/") {
			continue
		}
		return rest, true
	}
	return "", false
}

// proxyPath maps a URL an index document handed out — rewritten by the backend
// to point back through the proxy ("<public>/v1/<upstream>/…" or the
// root-relative "/v1/<upstream>/…") — to the backend-relative path. A URL still
// pointing at the upstream itself is mapped by base+rest.
func proxyPath(up Upstream, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	mount := "/v1/" + up.Name + "/"
	if i := strings.Index(u.EscapedPath(), mount); i >= 0 {
		rest := u.EscapedPath()[i+len(mount)-1:]
		if rest != "/" {
			return rest, true
		}
	}
	if u.Host != "" {
		return relativeTo(up, raw)
	}
	return "", false
}

// digestsOf returns the dependency's digests of the given kinds (Digest.Of).
func digestsOf(dep lockfiles.Dependency, of ...string) []lockfiles.Digest {
	var out []lockfiles.Digest
	for _, d := range dep.Digests {
		for _, o := range of {
			if d.Of == o {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// setting returns an upstream setting or def.
func (up Upstream) setting(key, def string) string {
	if v := strings.TrimSpace(up.Settings[key]); v != "" {
		return v
	}
	return def
}

// validLocatedPath reports whether a located path, decoded, is a plain path.
func validLocatedPath(p string) bool {
	dec, err := url.PathUnescape(p)
	if err != nil || !strings.HasPrefix(dec, "/") {
		return false
	}
	for _, r := range dec {
		if r < 0x20 || r == 0x7f || r == '?' || r == '#' || r == '\\' {
			return false
		}
	}
	for _, seg := range strings.Split(dec[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
