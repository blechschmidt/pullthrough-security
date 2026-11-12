package lockfiles

import "strings"

// composerLock reads Composer's composer.lock: "packages" and
// "packages-dev", each package with its version, the commit it was built from
// ("reference") and its dist archive — whose "shasum" (SHA-1) Packagist
// leaves empty for archives GitHub builds on demand.
type composerLock struct{}

func (composerLock) Type() string            { return "composer" }
func (composerLock) Format() string          { return "composer.lock" }
func (composerLock) Detect(path string) bool { return baseName(path) == "composer.lock" }

func (composerLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	sections := map[string][]Dependency{}
	sawPackages := false
	err := doc.object(func(key string, _ int) error {
		if key != "packages" && key != "packages-dev" {
			return doc.skip()
		}
		if doc.peekKind() != '[' {
			return doc.skip()
		}
		sawPackages = true
		dev := key == "packages-dev"
		var deps []Dependency // a repeated section replaces the earlier one
		err := doc.array(func(_, line int) error {
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			var name, version string
			var source, dist jsonFields
			nameLine := line
			err := doc.object(func(field string, fline int) error {
				var err error
				switch field {
				case "name":
					name, err = doc.stringValue()
					nameLine = fline
				case "version":
					version, err = doc.stringValue()
				case "source":
					source, err = doc.fields()
				case "dist":
					dist, err = doc.fields()
				default:
					err = doc.skip()
				}
				return err
			})
			if err != nil {
				return err
			}
			if d, ok := composerDependency(res, name, version, source, dist, dev, nameLine); ok {
				deps = append(deps, d)
			}
			return nil
		})
		sections[key] = deps
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if !sawPackages {
		return nil, errNotFormat("composer.lock", "no packages")
	}
	res.Dependencies = append(sections["packages"], sections["packages-dev"]...)
	return res, nil
}

func composerDependency(res *Result, name, version string, source, dist jsonFields, dev bool, line int) (Dependency, bool) {
	if !validPackageName(name) || !validVersion(version) {
		res.warnf("line %d: a package without a usable name or version", line)
		return Dependency{}, false
	}
	if dist.str("type") == "path" || source.str("type") == "path" {
		res.warnf("%s: installed from a local path, not fetched", name)
		return Dependency{}, false
	}
	d := Dependency{Name: name, Version: version, Dev: dev, Line: line}
	for _, ref := range []string{dist.str("reference"), source.str("reference")} {
		if isCommitID(ref) {
			d.Revision = strings.ToLower(ref)
			break
		}
	}
	switch {
	case isHTTPURL(dist.str("url")):
		d.URL = cleanURL(dist.str("url"))
	case source.str("type") == "git" && dist.str("url") == "":
		// Installed from source only: the repository is where it comes from.
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(source.str("url"))
	}
	if dg, ok := hexDigest("sha1", dist.str("shasum"), ""); ok {
		d.Digests = append(d.Digests, dg)
	}
	return d, true
}
