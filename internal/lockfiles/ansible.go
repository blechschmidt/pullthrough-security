package lockfiles

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// ansibleRequirements reads ansible-galaxy's requirements.yml. Ansible has
// no lock file; a requirements file pins a collection or role when it names
// one exact version ("8.6.0" or "==8.6.0") — a range, "*" or no version is a
// warning, not a dependency. Its two layouts:
//
//	collections: / roles:   lists of names ("ns.name", "ns.name:1.2.3") or
//	                        mappings (name, version, type, source, src, scm)
//	a top-level list        roles only, the older format
//
// A collection or role from Galaxy is named "namespace.name"; one from a Git
// repository (type git, or a role whose src is a repository) is a Git
// dependency, pinned when its version is a commit; a "url" collection is a
// direct download. The file records no hash of anything: Galaxy publishes a
// collection artifact's SHA-256, the requirements file does not.
type ansibleRequirements struct{}

func (ansibleRequirements) Type() string { return "ansible" }

// omitEmpty: Helm 2 charts name their dependency list requirements.yaml too.
func (ansibleRequirements) omitEmpty() bool { return true }
func (ansibleRequirements) Format() string  { return "requirements.yml" }
func (ansibleRequirements) Detect(path string) bool {
	name := baseName(path)
	return name == "requirements.yml" || name == "requirements.yaml"
}

const ansibleNoDigest = "requirements.yml records no hash (Galaxy publishes the artifact's SHA-256, the requirements file does not)"

func (ansibleRequirements) Parse(data []byte) (*Result, error) {
	n, err := readYAMLDoc(data, "requirements.yml")
	if err != nil {
		return nil, err
	}
	res := &Result{}
	switch {
	case n == nil:
		return res, nil
	case n.Kind == yaml.SequenceNode:
		for _, e := range n.Content {
			if d, ok := ansibleRole(res, e); ok {
				res.add(d)
			}
		}
	case n.Kind == yaml.MappingNode:
		collections, roles := yamlGet(n, "collections"), yamlGet(n, "roles")
		if collections == nil && roles == nil {
			if yamlGet(n, "dependencies") != nil {
				// Helm 2's requirements.yaml, which pins nothing (its
				// requirements.lock does, and is read as a Chart.lock).
				return res, nil
			}
			return nil, errNotFormat("requirements.yml", "neither collections nor roles")
		}
		for _, e := range yamlSeq(collections) {
			if d, ok := ansibleCollection(res, e); ok {
				res.add(d)
			}
		}
		for _, e := range yamlSeq(roles) {
			if d, ok := ansibleRole(res, e); ok {
				res.add(d)
			}
		}
	default:
		return nil, errNotFormat("requirements.yml", "neither a list nor a mapping")
	}
	return res, nil
}

func ansibleCollection(res *Result, e *yaml.Node) (Dependency, bool) {
	var name, version, typ, source string
	if s := yamlScalar(e); s != "" {
		name, version, _ = strings.Cut(s, ":")
		if strings.Contains(name, "://") || strings.HasPrefix(name, "git+") || strings.HasPrefix(name, "git@") {
			name, version = s, "" // a URL, not "name:version"
		}
	} else {
		name, version = yamlScalar(yamlGet(e, "name")), yamlScalar(yamlGet(e, "version"))
		typ, source = yamlScalar(yamlGet(e, "type")), yamlScalar(yamlGet(e, "source"))
	}
	line := e.Line
	switch typ {
	case "", "galaxy":
		if strings.Contains(name, "://") {
			res.warnf("line %d: a collection named by a URL without a type", line)
			return Dependency{}, false
		}
		v, ok := ansibleExactVersion(version)
		if !ok {
			res.warnf("line %d: collection %s is not pinned to one version", line, quoteName(name))
			return Dependency{}, false
		}
		d := Dependency{Name: name, Version: v, Line: line, UnverifiedReason: ansibleNoDigest}
		if isHTTPURL(source) {
			d.Registry = cleanURL(source)
		}
		if !ansibleName(d.Name) {
			res.warnf("line %d: not a collection name", line)
			return Dependency{}, false
		}
		return d, true
	case "git":
		// ansible-galaxy's parse_scm: a ",ref" after the URL wins over the
		// version.
		repo, ref, hasRef := strings.Cut(name, ",")
		if !hasRef {
			ref = version
		}
		return ansibleGit(res, repo, ref, "", line)
	case "url":
		if !isHTTPURL(name) {
			res.warnf("line %d: a url collection without an HTTP URL", line)
			return Dependency{}, false
		}
		d := Dependency{Source: SourceURL, URL: cleanURL(name), Line: line, UnverifiedReason: ansibleNoDigest}
		// A collection artifact is "<namespace>-<name>-<version>.tar.gz".
		file := fileNameOf(d.URL)
		if ns, rest, ok := strings.Cut(strings.TrimSuffix(file, ".tar.gz"), "-"); ok {
			if coll, v, ok := strings.Cut(rest, "-"); ok && ansibleName(ns+"."+coll) {
				d.Name, d.Version = ns+"."+coll, v
			}
		}
		if d.Name == "" {
			d.Name, d.Version = file, file
		}
		if version != "" {
			d.Version = version
		}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a url collection without a usable file name", line)
			return Dependency{}, false
		}
		return d, true
	case "file", "dir", "subdirs":
		res.warnf("line %d: a collection from the local file system, not fetched", line)
		return Dependency{}, false
	}
	res.warnf("line %d: a collection of type %q, which this parser does not read", line, typ)
	return Dependency{}, false
}

func ansibleRole(res *Result, e *yaml.Node) (Dependency, bool) {
	line := e.Line
	var name, src, version, scm string
	if s := yamlScalar(e); s != "" {
		// "src[,version[,name]]", as `ansible-galaxy role install` reads it.
		parts := strings.Split(s, ",")
		src = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			name = strings.TrimSpace(parts[2])
		}
	} else {
		if yamlGet(e, "include") != nil {
			res.warnf("line %d: includes another requirements file, read on its own if the scan finds it", line)
			return Dependency{}, false
		}
		name, src = yamlScalar(yamlGet(e, "name")), yamlScalar(yamlGet(e, "src"))
		version, scm = yamlScalar(yamlGet(e, "version")), yamlScalar(yamlGet(e, "scm"))
		if r := yamlScalar(yamlGet(e, "role")); r != "" && src == "" {
			src = r // the oldest form: "role: owner.name"
		}
	}

	if src == "" {
		src = name
	}
	// ansible-galaxy's role_yaml_parse: a GitHub http(s) URL that is no
	// tarball is a Git source even without "scm", "git+" sets it, and any
	// other URL is downloaded as an archive.
	lowerSrc := strings.ToLower(src)
	if strings.Contains(lowerSrc, "github.com") && strings.Contains(lowerSrc, "http") && !strings.Contains(src, "+") && !strings.HasSuffix(lowerSrc, ".tar.gz") {
		scm = "git"
	}
	if s, ok := strings.CutPrefix(src, "git+"); ok {
		src, scm = s, "git"
	}
	if scm == "git" || strings.Contains(src, "://") || strings.HasPrefix(src, "git@") {
		if scm != "" && scm != "git" {
			res.warnf("line %d: a role from a %s repository, which this parser does not read", line, scm)
			return Dependency{}, false
		}
		if scm != "git" {
			d := Dependency{Name: name, Source: SourceURL, URL: cleanURL(src), Line: line, UnverifiedReason: ansibleNoDigest}
			if d.Name == "" {
				d.Name = fileNameOf(d.URL)
			}
			d.Version = fileNameOf(d.URL) // the archive names the release
			if version != "" {
				d.Version = version
			}
			if !validPackageName(d.Name) || !validVersion(d.Version) {
				res.warnf("line %d: a role archive without a usable file name", line)
				return Dependency{}, false
			}
			return d, true
		}
		return ansibleGit(res, src, version, name, line)
	}
	v, ok := ansibleExactVersion(version)
	if !ok {
		res.warnf("line %d: role %s is not pinned to one version", line, quoteName(src))
		return Dependency{}, false
	}
	if !ansibleName(src) {
		res.warnf("line %d: not a role name", line)
		return Dependency{}, false
	}
	return Dependency{Name: src, Version: v, Line: line, UnverifiedReason: ansibleNoDigest}, true
}

// ansibleGit reads a collection or role from a Git repository, pinned to ref.
func ansibleGit(res *Result, repo, ref, name string, line int) (Dependency, bool) {
	repo = strings.TrimSpace(repo)
	if !strings.Contains(repo, "://") && !strings.HasPrefix(repo, "git@") {
		res.warnf("line %d: a Git source that is not a repository URL", line)
		return Dependency{}, false
	}
	d := Dependency{Name: name, Source: SourceGit, Registry: cleanGitRepoURL(repo), Line: line}
	if d.Name == "" {
		d.Name = strings.TrimSuffix(fileNameOf(d.Registry), ".git")
	}
	ref = strings.TrimSpace(ref)
	switch {
	case isCommitID(ref):
		d.Revision, d.Version = strings.ToLower(ref), strings.ToLower(ref)
	case ref != "" && ref != "*":
		d.Version = ref // a tag or a branch: unverified
	default:
		res.warnf("line %d: %s from a Git repository without a version, which follows the default branch", line, quoteName(d.Name))
		return Dependency{}, false
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: a Git source without a usable name or version", line)
		return Dependency{}, false
	}
	return d, true
}

// ansibleExactVersion returns the version a requirement pins: "1.2.3" or
// "==1.2.3". A range, "*" or nothing pins none.
func ansibleExactVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "=="); ok {
		v = strings.TrimSpace(rest)
	}
	if v == "" || strings.ContainsAny(v, "<>=!*, ") || !validVersion(v) {
		return "", false
	}
	return v, true
}

// ansibleName: "namespace.name", each part letters, digits and underscores.
func ansibleName(s string) bool {
	ns, name, ok := strings.Cut(s, ".")
	if !ok || strings.Contains(name, ".") {
		return false
	}
	for _, part := range []string{ns, name} {
		if part == "" || len(part) > 128 {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}
