package lockfiles

import (
	"errors"
	"strings"
)

// juliaManifest reads Julia's Manifest.toml: every package of the
// environment, with its UUID, version and git-tree-sha1 — the SHA-1 of the
// Git tree of the package's source, which Pkg checks whatever the package
// was fetched from (a package server's tarball, or a clone). Two layouts:
//
//	format 2.0   manifest_format = "2.0", packages under [[deps.<name>]]
//	format 1.0   packages as top-level [[<name>]] tables (Julia before 1.7)
//
// A package added from a repository records its "repo-url" and the branch or
// commit it tracks ("repo-rev"); one that is developed in place records a
// "path" and is not fetched; a standard library has no tree hash and ships
// with Julia.
type juliaManifest struct{}

func (juliaManifest) Type() string   { return "julia" }
func (juliaManifest) Format() string { return "Manifest.toml" }

// Detect accepts Manifest.toml, JuliaManifest.toml and the version-specific
// Manifest-v1.11.toml forms.
func (juliaManifest) Detect(path string) bool {
	name := baseName(path)
	for _, base := range []string{"Manifest", "JuliaManifest"} {
		if name == base+".toml" {
			return true
		}
		if rest, ok := strings.CutPrefix(name, base+"-v"); ok {
			if v, ok := strings.CutSuffix(rest, ".toml"); ok && v != "" && strings.Trim(v, "0123456789.") == "" {
				return true
			}
		}
	}
	return false
}

func (juliaManifest) Parse(data []byte) (*Result, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	res := &Result{FormatVersion: doc.str("manifest_format")}
	deps := doc.table("deps")
	switch {
	case res.FormatVersion != "" || deps != nil:
		if res.FormatVersion == "" {
			res.FormatVersion = "2.0"
		}
		if deps == nil {
			return res, nil
		}
		for _, name := range deps.keys {
			for _, pkg := range deps.tables(name) {
				if d, ok := juliaDependency(res, name, pkg); ok {
					res.add(d)
				}
			}
		}
	default:
		// Format 1.0: every top-level key is a package's array of tables.
		for _, name := range doc.keys {
			v := doc.get(name)
			if v.kind != tkArray {
				if name == "julia_version" || name == "project_hash" {
					continue
				}
				return nil, errors.New("not a Julia manifest: top-level key " + quoteName(name) + " is not a package")
			}
			res.FormatVersion = "1.0"
			for _, pkg := range doc.tables(name) {
				if d, ok := juliaDependency(res, name, pkg); ok {
					res.add(d)
				}
			}
		}
	}
	return res, nil
}

func juliaDependency(res *Result, name string, pkg *tomlTable) (Dependency, bool) {
	tree := pkg.str("git-tree-sha1")
	switch {
	case pkg.str("path") != "":
		res.warnf("%s: developed from a local path, not fetched", name)
		return Dependency{}, false
	case tree == "" && pkg.str("repo-url") == "":
		return Dependency{}, false // a standard library, part of Julia
	}
	d := Dependency{Name: name, Version: pkg.str("version"), ID: strings.ToLower(pkg.str("uuid")), Line: pkg.line}
	dg, ok := hexDigest("sha1", tree, "git-tree")
	if ok {
		d.Digests = append(d.Digests, dg)
	}
	if repo := pkg.str("repo-url"); repo != "" {
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(repo)
		if rev := pkg.str("repo-rev"); isCommitID(rev) {
			d.Revision = strings.ToLower(rev)
		}
		if strings.HasPrefix(d.Registry, "/") || strings.HasPrefix(d.Registry, ".") {
			res.warnf("%s: tracks a repository on the local file system, not fetched", name)
			return Dependency{}, false
		}
	}
	if d.Version == "" && ok {
		d.Version = dg.Value // a package without a version is named by its tree
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: %s: no usable name or version", pkg.line, name)
		return Dependency{}, false
	}
	if !juliaUUID(d.ID) {
		res.warnf("line %d: %s: no usable uuid", pkg.line, name)
		return Dependency{}, false
	}
	return d, true
}

// juliaUUID reports whether s is a UUID in its canonical text form.
func juliaUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i : i+1]) {
				return false
			}
		}
	}
	return true
}

// quoteName quotes a name from a lock file for an error message, bounded.
func quoteName(s string) string {
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return "\"" + strings.ToValidUTF8(s, "?") + "\""
}
