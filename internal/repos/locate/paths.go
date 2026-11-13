package locate

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// This file holds the locators whose paths follow from the lock file alone.
// Each comment names the backend function that parses the path back into the
// coordinate; locate_test.go holds every locator to it.

// requireCoordinate fails a dependency without a name or version.
func requireCoordinate(dep lockfiles.Dependency) error {
	if strings.TrimSpace(dep.Name) == "" || strings.TrimSpace(dep.Version) == "" {
		return fmt.Errorf("locate: the dependency has no name or no version")
	}
	if strings.ContainsAny(dep.Name+dep.Version, "\x00\r\n?#") || strings.Contains(dep.Version, "/") {
		return fmt.Errorf("locate: the dependency's name or version contains characters no registry path does")
	}
	for _, seg := range strings.Split(dep.Name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("locate: the dependency's name %q is not a registry name", dep.Name)
		}
	}
	return nil
}

// segment escapes one path segment.
func segment(s string) string { return url.PathEscape(s) }

// npm: "/<name>/-/<short>-<version>.tgz" (pkgmgr npmCoordinate). A tarball URL
// the lock file records beneath the upstream is used as it is: a package may
// publish a tarball under another file name.
func locateNPM(_ context.Context, _ Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	p := ""
	if dep.URL != "" {
		if rest, ok := proxyPath(up, dep.URL); ok && strings.Contains(rest, "/-/") && strings.HasSuffix(rest, ".tgz") {
			p = rest
		}
	}
	if p == "" {
		short := dep.Name[strings.LastIndex(dep.Name, "/")+1:]
		p = "/" + dep.Name + "/-/" + short + "-" + dep.Version + ".tgz"
	}
	return []Artifact{{Path: p, Role: "package", File: path.Base(p), Expect: digestsOf(dep, "")}}, nil, nil
}

// cargo: "/api/v1/crates/<name>/<version>/download" (pkgmgr cargoCoordinate).
func locateCargo(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	p := "/api/v1/crates/" + segment(dep.Name) + "/" + segment(dep.Version) + "/download"
	return []Artifact{{Path: p, Role: "package", File: dep.Name + "-" + dep.Version + ".crate", Expect: digestsOf(dep, "")}}, nil, nil
}

// goEscape applies the module proxy protocol's case encoding: an upper-case
// letter becomes "!" and its lower-case form.
func goEscape(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '!' || r > unicode.MaxASCII:
			return "", fmt.Errorf("locate: %q cannot be escaped for the module proxy", s)
		case unicode.IsUpper(r):
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

// go: "/<module>/@v/<version>.{info,mod,zip}" (pkgmgr goCoordinate), case-escaped.
// A module go.sum hashes only by its go.mod is one the build does not download:
// its go.mod is pinned, its code is not.
func locateGo(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	mod, err := goEscape(dep.Name)
	if err != nil {
		return nil, nil, err
	}
	ver, err := goEscape(dep.Version)
	if err != nil {
		return nil, nil, err
	}
	base := "/" + mod + "/@v/" + ver
	zipDigests := digestsOf(dep, "")
	modDigests := digestsOf(dep, "go.mod")
	arts := []Artifact{
		{Path: base + ".info", Role: "info", Optional: true},
		{Path: base + ".mod", Role: "go.mod", Expect: modDigests},
	}
	if len(zipDigests) == 0 && len(modDigests) > 0 {
		return arts, []string{"go.sum hashes only this module's go.mod: the build reads it but does not download the module's code, so only the go.mod is pinned"}, nil
	}
	arts = append(arts, Artifact{Path: base + ".zip", Role: "package", File: path.Base(dep.Name) + "@" + dep.Version + ".zip", Expect: zipDigests})
	return arts, nil, nil
}

// rubygems: "/gems/<name>-<version>.gem" (rubygems path.go), the version
// carrying the platform as Gemfile.lock spells it.
func locateRubyGems(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	file := dep.Name + "-" + dep.Version + ".gem"
	return []Artifact{{Path: "/gems/" + segment(file), Role: "package", File: file, Expect: digestsOf(dep, "")}}, nil, nil
}

// dart: "/api/archives/<name>-<version>.tar.gz" — the path the backend
// rewrites every archive_url to (dart path.go).
func locateDart(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	file := dep.Name + "-" + dep.Version + ".tar.gz"
	return []Artifact{{Path: "/api/archives/" + segment(file), Role: "package", File: file, Expect: digestsOf(dep, "")}}, nil, nil
}

// hex: "/tarballs/<name>-<version>.tar" (hex path.go). mix.lock's outer
// checksum is the tarball's SHA-256; its inner checksum is not of the bytes.
func locateHex(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	file := dep.Name + "-" + dep.Version + ".tar"
	return []Artifact{{Path: "/tarballs/" + segment(file), Role: "package", File: file, Expect: digestsOf(dep, "")}}, nil, nil
}

// hackage: "/package/<n>-<v>/<n>-<v>.tar.gz" (hackage path.go).
func locateHackage(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	id := dep.Name + "-" + dep.Version
	return []Artifact{{Path: "/package/" + segment(id) + "/" + segment(id+".tar.gz"), Role: "package", File: id + ".tar.gz", Expect: digestsOf(dep, "")}}, nil, nil
}

// forgeSlug splits a Puppet or Ansible "owner/name" (or "owner-name") name.
func forgeSlug(name string) (owner, mod string, ok bool) {
	if o, m, found := strings.Cut(name, "/"); found {
		return o, m, o != "" && m != "" && !strings.Contains(m, "/")
	}
	if o, m, found := strings.Cut(name, "-"); found {
		return o, m, o != "" && m != ""
	}
	return "", "", false
}

// puppet: "/v3/files/<owner>-<name>-<version>.tar.gz" (puppet path.go).
func locatePuppet(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	owner, mod, ok := forgeSlug(dep.Name)
	if !ok {
		return nil, nil, fmt.Errorf("locate: %q is not a Forge module name (owner/name)", dep.Name)
	}
	file := owner + "-" + mod + "-" + dep.Version + ".tar.gz"
	return []Artifact{{Path: "/v3/files/" + segment(file), Role: "package", File: file, Expect: digestsOf(dep, "")}}, nil, nil
}

// ansible: "/api/v3/plugin/ansible/content/<repo>/collections/artifacts/
// <ns>-<name>-<version>.tar.gz" (ansible path.go). The distribution repository
// is "published" on Galaxy; the "repository" setting names another.
func locateAnsible(_ context.Context, _ Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	ns, name, found := strings.Cut(dep.Name, ".")
	if !found || ns == "" || name == "" {
		return nil, nil, fmt.Errorf("locate: %q is not an Ansible collection name (namespace.name)", dep.Name)
	}
	repo := up.setting("repository", "published")
	file := ns + "-" + name + "-" + dep.Version + ".tar.gz"
	p := "/api/v3/plugin/ansible/content/" + segment(repo) + "/collections/artifacts/" + segment(file)
	return []Artifact{{Path: p, Role: "package", File: file, Expect: digestsOf(dep, "")}}, nil, nil
}

// swift: "/<scope>/<name>/<version>.zip" with the registry's zip media type
// (swift path.go). Only registry pins have a scope; source-control pins are
// Git dependencies.
func locateSwift(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	scope, name, found := strings.Cut(dep.Name, ".")
	if !found || scope == "" || name == "" {
		return nil, nil, unsupported("Swift package %q is not a registry identity (scope.name); source-control pins are Git dependencies", dep.Name)
	}
	p := "/" + segment(scope) + "/" + segment(name) + "/" + segment(dep.Version) + ".zip"
	return []Artifact{{Path: p, Role: "package", File: name + "-" + dep.Version + ".zip", Accept: "application/vnd.swift.registry.v1+zip", Expect: digestsOf(dep, "")}}, nil, nil
}

// conda: the lock file records each package's URL; the path is that URL
// beneath the channel the upstream fronts (conda path.go).
func locateConda(_ context.Context, _ Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	if dep.URL == "" {
		return nil, nil, unsupported("the lock file records no download URL for conda package %s; its build string is needed to name the file", dep.Name)
	}
	rest, ok := proxyPath(up, dep.URL)
	if !ok {
		return nil, nil, unsupported("conda package %s is downloaded from %s, which upstream %q does not front", dep.Name, registryLabel(dep.URL), up.Name)
	}
	return []Artifact{{Path: rest, Role: "package", File: path.Base(rest), Expect: digestsOf(dep, "")}}, nil, nil
}

// cran: "/src/contrib/<p>_<v>.tar.gz" while the version is current, then
// "/src/contrib/Archive/<p>/<p>_<v>.tar.gz" (cran path.go). Which applies is
// only known by asking, so the archive path is the fallback.
func locateCRAN(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	file := dep.Name + "_" + dep.Version + ".tar.gz"
	return []Artifact{{
		Path: "/src/contrib/" + segment(file), Role: "package", File: file, Expect: digestsOf(dep, ""),
		Fallback: "/src/contrib/Archive/" + segment(dep.Name) + "/" + segment(file),
	}}, nil, nil
}

// cpan: "/authors/id/<A>/<AB>/<AUTHOR>/<file>" (cpan path.go); the lock file's
// ID is the distribution's author path ("E/ET/ETHER/Try-Tiny-0.31.tar.gz").
func locateCPAN(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	id := strings.Trim(strings.TrimPrefix(strings.TrimSpace(dep.ID), "authors/id/"), "/")
	parts := strings.Split(id, "/")
	if len(parts) < 4 {
		return nil, nil, unsupported("the lock file records no author path for CPAN distribution %s", dep.Name)
	}
	for _, s := range parts {
		if s == "" || s == "." || s == ".." {
			return nil, nil, fmt.Errorf("locate: %q is not a CPAN author path", dep.ID)
		}
	}
	escaped := make([]string, len(parts))
	for i, s := range parts {
		escaped[i] = segment(s)
	}
	return []Artifact{{Path: "/authors/id/" + strings.Join(escaped, "/"), Role: "package", File: parts[len(parts)-1], Expect: digestsOf(dep, "")}}, nil, nil
}

// julia: "/package/<uuid>/<git-tree-sha1>" (julia path.go); the backend checks
// the tree hash in the path, so the version is not needed.
func locateJulia(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	tree := digestsOf(dep, "git-tree")
	if dep.ID == "" || len(tree) == 0 {
		return nil, nil, unsupported("the manifest records no UUID or git-tree-sha1 for Julia package %s", dep.Name)
	}
	p := "/package/" + segment(strings.ToLower(dep.ID)) + "/" + segment(strings.ToLower(tree[0].Value))
	return []Artifact{{Path: p, Role: "package", File: dep.Name + "@" + dep.Version}}, []string{"the backend verifies the package against the git-tree-sha1 in its path"}, nil
}

// bazel: "/modules/<name>/<version>/archive" — the path source.json's url is
// rewritten to (bazel path.go); the backend checks the archive against the
// integrity source.json names.
func locateBazel(_ context.Context, _ Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	p := "/modules/" + segment(dep.Name) + "/" + segment(dep.Version) + "/archive"
	return []Artifact{{Path: p, Role: "package", File: dep.Name + "-" + dep.Version}}, []string{"the backend verifies the archive against the integrity its source.json records"}, nil
}

// helm: "/-/<chart>/<version>/<chart>-<version>.tgz", the form the backend
// rewrites index.yaml's chart URLs to (helm rewrite.go). Chart.lock's digest is
// of its dependency list, not of a chart.
func locateHelm(_ context.Context, _ Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	if strings.EqualFold(up.setting("oci", ""), "true") {
		return nil, nil, unsupported("upstream %q serves Helm charts as OCI artifacts; pin them through the docker type", up.Name)
	}
	file := dep.Name + "-" + dep.Version + ".tgz"
	p := "/-/" + segment(dep.Name) + "/" + segment(dep.Version) + "/" + segment(file)
	return []Artifact{{Path: p, Role: "package", File: file}}, []string{"the backend verifies the chart against the digest its repository index records"}, nil
}

// homebrew: Brewfile.lock.json records each bottle's URL on the bottle
// registry; the native path is that URL's path (homebrew path.go).
func locateHomebrew(_ context.Context, _ Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if dep.URL == "" {
		return nil, nil, unsupported("the lock file records no bottle URL for formula %s", dep.Name)
	}
	u, err := url.Parse(dep.URL)
	if err != nil || !strings.HasPrefix(u.EscapedPath(), "/v2/") || !strings.Contains(u.EscapedPath(), "/blobs/sha256:") {
		return nil, nil, unsupported("the bottle URL of formula %s is not a registry blob URL", dep.Name)
	}
	registry := up.setting("bottleRegistryUrl", "https://ghcr.io")
	if h, _ := hostPath(registry); h != "" {
		if dh, _ := hostPath(dep.URL); dh != h {
			return nil, nil, unsupported("the bottle of formula %s is downloaded from %s, not the bottle registry upstream %q fronts", dep.Name, registryLabel(dep.URL), up.Name)
		}
	}
	return []Artifact{{Path: u.EscapedPath(), Role: "package", File: path.Base(u.Path), Expect: digestsOf(dep, "")}}, nil, nil
}

// terraform: a provider's "/v1/providers/<ns>/<type>/<version>/download/<os>/
// <arch>/zip" per platform (terraform path.go). The lock file's "zh:" hashes
// cover every platform's zip of the release; each fetched zip must be one of
// them. Modules are not locked by .terraform.lock.hcl.
func locateTerraform(_ context.Context, env Env, dep lockfiles.Dependency, _ Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	parts := strings.Split(strings.Trim(dep.Name, "/"), "/")
	if len(parts) == 3 {
		parts = parts[1:] // "registry.terraform.io/hashicorp/aws"
	}
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil, unsupported("%q is not a Terraform provider address (namespace/type)", dep.Name)
	}
	platforms := env.Platforms
	if len(platforms) == 0 {
		platforms = []Platform{{OS: "linux", Arch: "amd64"}}
	}
	zips := digestsOf(dep, "terraform-zip")
	var arts []Artifact
	for _, pl := range platforms {
		p := "/v1/providers/" + segment(parts[0]) + "/" + segment(parts[1]) + "/" + segment(dep.Version) +
			"/download/" + segment(pl.OS) + "/" + segment(pl.Arch) + "/zip"
		arts = append(arts, Artifact{Path: p, Role: "package", File: fmt.Sprintf("terraform-provider-%s_%s_%s_%s.zip", parts[1], dep.Version, pl.OS, pl.Arch), Expect: zips})
	}
	return arts, []string{fmt.Sprintf("provider zips pinned for %d platform(s)", len(arts))}, nil
}
