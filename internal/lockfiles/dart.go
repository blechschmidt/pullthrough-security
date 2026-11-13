package lockfiles

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// pubspecLock reads pub's pubspec.lock (Dart and Flutter). Every package has
// its "source" — hosted (a registry: pub.dev or the "url" its description
// names), git, path or sdk — its version, and whether the project depends on
// it directly ("direct main", "direct dev", "direct overridden") or only
// transitively. From Dart 2.19 on a hosted package's description records the
// SHA-256 of its archive; files written before that record none.
type pubspecLock struct{}

func (pubspecLock) Type() string            { return "dart" }
func (pubspecLock) Format() string          { return "pubspec.lock" }
func (pubspecLock) Detect(path string) bool { return baseName(path) == "pubspec.lock" }

func (pubspecLock) Parse(data []byte) (*Result, error) {
	m, err := readYAMLLock(data, "pubspec.lock")
	if err != nil {
		return nil, err
	}
	res := &Result{}
	if m == nil {
		return res, nil
	}
	packages := yamlGet(m, "packages")
	if packages == nil && yamlGet(m, "sdks") == nil {
		return nil, errNotFormat("pubspec.lock", "no packages and no sdks")
	}
	yamlPairs(packages, func(key string, keyNode, entry *yaml.Node) {
		if d, ok := pubDependency(res, key, keyNode.Line, entry); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	})
	return res, nil
}

func pubDependency(res *Result, key string, line int, entry *yaml.Node) (Dependency, bool) {
	if yamlMapping(entry) == nil {
		res.warnf("line %d: %s: not a package entry", line, key)
		return Dependency{}, false
	}
	source := yamlScalar(yamlGet(entry, "source"))
	version := yamlScalar(yamlGet(entry, "version"))
	desc := yamlGet(entry, "description")
	d := Dependency{Name: key, Version: version, Line: line,
		Dev: yamlScalar(yamlGet(entry, "dependency")) == "direct dev"}
	switch source {
	case "hosted":
		if name := yamlScalar(yamlGet(desc, "name")); name != "" {
			d.Name = name
		}
		if u := yamlScalar(yamlGet(desc, "url")); u != "" {
			d.Registry = cleanURL(u)
		}
		if dg, ok := hexDigest("sha256", yamlScalar(yamlGet(desc, "sha256")), ""); ok {
			d.Digests = append(d.Digests, dg)
		} else {
			d.UnverifiedReason = "pubspec.lock records no sha256 for this package (pub writes one from Dart 2.19 on)"
		}
	case "git":
		gs := parseGitURL(yamlScalar(yamlGet(desc, "url")))
		d.Source, d.Registry = SourceGit, gs.repo
		if rev := yamlScalar(yamlGet(desc, "resolved-ref")); isCommitID(rev) {
			d.Revision = strings.ToLower(rev)
		}
	case "path":
		res.warnf("%s: from a local path, not fetched", key)
		return Dependency{}, false
	case "sdk":
		return Dependency{}, false // part of the Dart or Flutter SDK
	default:
		res.warnf("%s: from a %q source, which this parser does not read", key, source)
		return Dependency{}, false
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: %s: no usable name or version", line, key)
		return Dependency{}, false
	}
	return d, true
}
