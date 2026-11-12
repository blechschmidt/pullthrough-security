package lockfiles

import (
	"encoding/json"
	"errors"
	"strings"
)

// npmLock reads package-lock.json and npm-shrinkwrap.json (the same format,
// published with a package). Version 1 nests dependencies under
// "dependencies"; versions 2 and 3 list every installed package under
// "packages", keyed by its path in node_modules — version 2 carries both, and
// "packages" wins.
type npmLock struct{ file string }

func (p npmLock) Type() string   { return "npm" }
func (p npmLock) Format() string { return p.file }
func (p npmLock) Detect(path string) bool {
	return baseName(path) == p.file
}

func (p npmLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	var packages, legacy []Dependency
	sawPackages := false
	err := doc.object(func(key string, line int) error {
		switch key {
		case "lockfileVersion":
			var n json.RawMessage
			if err := doc.value(&n); err != nil {
				return err
			}
			res.FormatVersion = strings.Trim(string(n), `"`)
			return nil
		case "packages":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			// A repeated key keeps its last value, as npm's JSON.parse does.
			sawPackages = true
			byPath := map[string]int{}
			packages = nil
			return doc.object(func(installPath string, line int) error {
				e, err := doc.fields()
				if err != nil || e == nil {
					return err
				}
				d, ok := npmPackageDependency(res, installPath, line, e)
				if i, dup := byPath[installPath]; dup {
					packages[i] = Dependency{} // superseded
				}
				if ok {
					byPath[installPath] = len(packages)
					packages = append(packages, d)
				}
				return nil
			})
		case "dependencies":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			var err error
			legacy, err = npmLegacyDependencies(doc, res)
			return err
		default:
			return doc.skip()
		}
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if sawPackages {
		res.Dependencies = dropSuperseded(packages)
	} else {
		res.Dependencies = legacy
	}
	if res.FormatVersion == "" && !sawPackages && legacy == nil {
		return nil, errors.New("not an npm lock file: no lockfileVersion, packages or dependencies")
	}
	return res, nil
}

// npmPackageDependency turns a "packages" entry into a dependency. The root
// ("") is the project itself; an entry outside node_modules is a workspace's
// own folder; a link points at one; a bundled package ships inside its parent's
// tarball. None of those is fetched.
func npmPackageDependency(res *Result, installPath string, line int, e jsonFields) (Dependency, bool) {
	if installPath == "" || e.flag("link") || e.flag("inBundle") {
		return Dependency{}, false
	}
	i := strings.LastIndex(installPath, "node_modules/")
	if i < 0 {
		return Dependency{}, false
	}
	name := installPath[i+len("node_modules/"):]
	if n := e.str("name"); n != "" {
		name = n
	}
	if !validPackageName(name) {
		res.warnf("line %d: an entry has no usable package name", line)
		return Dependency{}, false
	}
	return npmDependency(res, name, e.str("version"), e.str("resolved"), e.str("integrity"), e.flag("dev"), line)
}

// dropSuperseded removes the entries a repeated key replaced.
func dropSuperseded(deps []Dependency) []Dependency {
	out := deps[:0]
	for _, d := range deps {
		if d.Name != "" {
			out = append(out, d)
		}
	}
	return out
}

// npmDependency builds a dependency from what an npm lock file records for it.
func npmDependency(res *Result, name, version, resolved, integrity string, dev bool, line int) (Dependency, bool) {
	d := Dependency{Name: name, Version: version, Dev: dev, Line: line, Digests: sriDigests(integrity)}
	switch {
	case strings.HasPrefix(resolved, "file:") || strings.HasPrefix(resolved, "link:"):
		res.warnf("%s: installed from a local path, not fetched", name)
		return Dependency{}, false
	case isGitSpec(resolved):
		gs := parseGitURL(resolved)
		d.Source, d.Registry, d.Revision = SourceGit, gs.repo, gs.revision
		if d.Version == "" {
			d.Version = gs.revision
		}
	case isHTTPURL(resolved):
		d.URL = cleanURL(resolved)
		if base, ok := npmRegistryBase(resolved, name); ok {
			d.Registry = base
		} else {
			d.Source = SourceURL // a tarball URL, not a registry's "/<name>/-/" download
		}
	case resolved != "":
		res.warnf("%s %s: unrecognised resolved location", name, version)
	}
	if !validVersion(d.Version) {
		res.warnf("%s: no version recorded", name)
		return Dependency{}, false
	}
	return d, true
}

// isGitSpec reports whether an npm/Yarn location is a Git repository.
func isGitSpec(s string) bool {
	l := strings.ToLower(s)
	for _, p := range []string{"git+", "git://", "github:", "gitlab:", "bitbucket:"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// npmLegacyDependencies reads a lockfileVersion 1 "dependencies" object,
// recursing into the nested ones. A name repeated in one object keeps its last
// entry (and that entry's nested dependencies), as npm's JSON.parse does.
func npmLegacyDependencies(doc *jsonDoc, res *Result) ([]Dependency, error) {
	type group struct{ deps []Dependency }
	var order []string
	groups := map[string]*group{}
	err := doc.object(func(name string, line int) error {
		if doc.peekKind() != '{' {
			return doc.skip()
		}
		var version, resolved, integrity string
		var dev, bundled bool
		var nested []Dependency
		err := doc.object(func(field string, _ int) error {
			var err error
			switch field {
			case "version":
				version, err = doc.stringValue()
			case "resolved":
				resolved, err = doc.stringValue()
			case "integrity":
				integrity, err = doc.stringValue()
			case "dev":
				dev, err = doc.boolValue()
			case "bundled":
				bundled, err = doc.boolValue()
			case "dependencies":
				if doc.peekKind() != '{' {
					return doc.skip()
				}
				nested, err = npmLegacyDependencies(doc, res)
			default:
				err = doc.skip()
			}
			return err
		})
		if err != nil {
			return err
		}
		g := &group{deps: nested}
		if _, seen := groups[name]; !seen {
			order = append(order, name)
		}
		groups[name] = g
		if bundled {
			return nil
		}
		realName := name
		// An alias: the version names the real package ("npm:string-width@4.2.3").
		if rest, ok := strings.CutPrefix(version, "npm:"); ok {
			if n, v, ok := splitNameAtLast(rest); ok {
				realName, version = n, v
			}
		}
		switch {
		case isGitSpec(version):
			// A Git dependency: the version is the repository location.
			if resolved == "" {
				resolved = version
			}
			version = ""
		case isHTTPURL(version):
			// A tarball URL dependency (npm 6 writes the URL as the version).
			if resolved == "" {
				resolved = version
			}
			version = npmTarballVersion(realName, version)
		case strings.HasPrefix(version, "file:"):
			resolved = version
		}
		if !validPackageName(realName) {
			res.warnf("line %d: an entry has no usable package name", line)
			return nil
		}
		if d, ok := npmDependency(res, realName, version, resolved, integrity, dev, line); ok {
			g.deps = append([]Dependency{d}, g.deps...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []Dependency
	for _, name := range order {
		out = append(out, groups[name].deps...)
	}
	return out, nil
}

// npmTarballVersion takes the version of a tarball URL dependency from the
// file name ("…/foo-1.2.3.tgz" for foo is 1.2.3), or the file name without
// its extension when the name does not say.
func npmTarballVersion(name, url string) string {
	file := fileNameOf(url)
	for _, ext := range []string{".tgz", ".tar.gz"} {
		file = strings.TrimSuffix(file, ext)
	}
	short := name[strings.LastIndex(name, "/")+1:]
	if v, ok := strings.CutPrefix(file, short+"-"); ok && v != "" {
		return v
	}
	return file
}
