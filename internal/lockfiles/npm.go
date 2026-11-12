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

// npmPackageEntry is an entry of "packages" (v2, v3).
type npmPackageEntry struct {
	Name      lenientString `json:"name"`
	Version   lenientString `json:"version"`
	Resolved  lenientString `json:"resolved"`
	Integrity lenientString `json:"integrity"`
	Link      lenientBool   `json:"link"`
	Dev       lenientBool   `json:"dev"`
	InBundle  lenientBool   `json:"inBundle"`
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
			sawPackages = true
			return doc.object(func(installPath string, line int) error {
				var e npmPackageEntry
				if doc.peekKind() != '{' {
					return doc.skip()
				}
				if err := doc.value(&e); err != nil {
					return err
				}
				if d, ok := npmPackageDependency(res, installPath, line, e); ok {
					packages = append(packages, d)
				}
				return nil
			})
		case "dependencies":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			return npmLegacyDependencies(doc, res, &legacy)
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
		res.Dependencies = packages
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
func npmPackageDependency(res *Result, installPath string, line int, e npmPackageEntry) (Dependency, bool) {
	if installPath == "" || bool(e.Link) || bool(e.InBundle) {
		return Dependency{}, false
	}
	i := strings.LastIndex(installPath, "node_modules/")
	if i < 0 {
		return Dependency{}, false
	}
	name := installPath[i+len("node_modules/"):]
	if e.Name != "" {
		name = string(e.Name)
	}
	if !validPackageName(name) {
		res.warnf("line %d: an entry has no usable package name", line)
		return Dependency{}, false
	}
	return npmDependency(res, name, string(e.Version), string(e.Resolved), string(e.Integrity), bool(e.Dev), line)
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
		d.Registry = npmRegistryBase(resolved, name)
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
// recursing into the nested ones.
func npmLegacyDependencies(doc *jsonDoc, res *Result, out *[]Dependency) error {
	return doc.object(func(name string, line int) error {
		if doc.peekKind() != '{' {
			return doc.skip()
		}
		var version, resolved, integrity string
		var dev, bundled bool
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
				var b lenientBool
				err = doc.value(&b)
				dev = bool(b)
			case "bundled":
				var b lenientBool
				err = doc.value(&b)
				bundled = bool(b)
			case "dependencies":
				if doc.peekKind() != '{' {
					return doc.skip()
				}
				return npmLegacyDependencies(doc, res, out)
			default:
				err = doc.skip()
			}
			return err
		})
		if err != nil || bundled {
			return err
		}
		realName := name
		// An alias: the version names the real package ("npm:string-width@4.2.3").
		if rest, ok := strings.CutPrefix(version, "npm:"); ok {
			if n, v, ok := splitNameAtLast(rest); ok {
				realName, version = n, v
			}
		}
		// A Git dependency: the version is the repository location.
		if isGitSpec(version) {
			if resolved == "" {
				resolved = version
			}
			version = ""
		}
		if strings.HasPrefix(version, "file:") {
			resolved = version
		}
		if !validPackageName(realName) {
			res.warnf("line %d: an entry has no usable package name", line)
			return nil
		}
		if d, ok := npmDependency(res, realName, version, resolved, integrity, dev, line); ok {
			*out = append(*out, d)
		}
		return nil
	})
}
