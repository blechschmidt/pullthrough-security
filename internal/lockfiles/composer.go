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

type composerLocation struct {
	Type      lenientString `json:"type"`
	URL       lenientString `json:"url"`
	Reference lenientString `json:"reference"`
	Shasum    lenientString `json:"shasum"`
}

func (composerLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
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
		return doc.array(func(_, line int) error {
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			var name, version string
			var source, dist composerLocation
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
					if doc.peekKind() != '{' {
						return doc.skip()
					}
					err = doc.value(&source)
				case "dist":
					if doc.peekKind() != '{' {
						return doc.skip()
					}
					err = doc.value(&dist)
				default:
					err = doc.skip()
				}
				return err
			})
			if err != nil {
				return err
			}
			if d, ok := composerDependency(res, name, version, source, dist, dev, nameLine); ok {
				res.Dependencies = append(res.Dependencies, d)
			}
			return nil
		})
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
	return res, nil
}

func composerDependency(res *Result, name, version string, source, dist composerLocation, dev bool, line int) (Dependency, bool) {
	if !validPackageName(name) || !validVersion(version) {
		res.warnf("line %d: a package without a usable name or version", line)
		return Dependency{}, false
	}
	if dist.Type == "path" || source.Type == "path" {
		res.warnf("%s: installed from a local path, not fetched", name)
		return Dependency{}, false
	}
	d := Dependency{Name: name, Version: version, Dev: dev, Line: line}
	for _, ref := range []lenientString{dist.Reference, source.Reference} {
		if isCommitID(string(ref)) {
			d.Revision = strings.ToLower(string(ref))
			break
		}
	}
	switch {
	case isHTTPURL(string(dist.URL)):
		d.URL = cleanURL(string(dist.URL))
	case source.Type == "git" && dist.URL == "":
		// Installed from source only: the repository is where it comes from.
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(string(source.URL))
	}
	if dg, ok := hexDigest("sha1", string(dist.Shasum), ""); ok {
		d.Digests = append(d.Digests, dg)
	}
	return d, true
}
