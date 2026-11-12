package lockfiles

import (
	"errors"
	"strings"
)

// cargoLock reads Cargo.lock (TOML). Every crate is a [[package]] with its
// source — "registry+<index>", "sparse+<index>" or "git+<repo>?…#<commit>";
// no source is a crate of the workspace itself — and, from format v2 on, its
// SHA-256 checksum inline. Format v1 kept the checksums in [metadata], under
// keys "checksum <name> <version> (<source>)".
type cargoLock struct{}

func (cargoLock) Type() string            { return "cargo" }
func (cargoLock) Format() string          { return "Cargo.lock" }
func (cargoLock) Detect(path string) bool { return baseName(path) == "Cargo.lock" }

func (cargoLock) Parse(data []byte) (*Result, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	legacy := map[string]string{} // "<name> <version> (<source>)" → checksum
	if meta := doc.table("metadata"); meta != nil {
		for _, k := range meta.keys {
			if rest, ok := strings.CutPrefix(k, "checksum "); ok {
				legacy[rest] = meta.str(k)
			}
		}
	}
	switch v := doc.get("version"); {
	case v != nil && v.kind == tkInteger:
		res.FormatVersion = v.str
	case len(legacy) > 0:
		res.FormatVersion = "1"
	}
	pkgs := doc.tables("package")
	if pkgs == nil && doc.get("version") == nil && doc.get("metadata") == nil {
		return nil, errors.New("not a Cargo.lock: no [[package]]")
	}
	for _, pkg := range pkgs {
		name, version, source := pkg.str("name"), pkg.str("version"), pkg.str("source")
		if !validPackageName(name) || !validVersion(version) {
			res.warnf("line %d: a package without a usable name or version", pkg.line)
			continue
		}
		if source == "" {
			continue // a crate of this workspace (or a path dependency)
		}
		d := Dependency{Name: name, Version: version, Line: pkg.line}
		kind, loc, _ := strings.Cut(source, "+")
		switch kind {
		case "registry", "sparse":
			d.Registry = cleanURL(loc)
		case "git":
			gs := parseGitURL(loc)
			d.Source, d.Registry, d.Revision = SourceGit, gs.repo, gs.revision
		default:
			res.warnf("%s %s: unrecognised source kind %q", name, version, kind)
			continue
		}
		checksum := pkg.str("checksum")
		if checksum == "" {
			checksum = legacy[name+" "+version+" ("+source+")"]
		}
		if dg, ok := hexDigest("sha256", checksum, ""); ok {
			d.Digests = append(d.Digests, dg)
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}
