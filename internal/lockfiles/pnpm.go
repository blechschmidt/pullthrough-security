package lockfiles

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmLock reads pnpm-lock.yaml. Every package pnpm installs has an entry
// under "packages", keyed by name and version — and the key's spelling is
// what changed between format versions:
//
//	5.x   /@scope/name/1.2.3_peer@4.5.6
//	6.x   /@scope/name@1.2.3(peer@4.5.6)
//	9.x   @scope/name@1.2.3            (peer variants moved to "snapshots")
//
// A package that is not from the registry also records its name and version
// in fields of its own, which win over the key.
type pnpmLock struct{}

func (pnpmLock) Type() string            { return "npm" }
func (pnpmLock) Format() string          { return "pnpm-lock.yaml" }
func (pnpmLock) Detect(path string) bool { return baseName(path) == "pnpm-lock.yaml" }

// maxYAMLDocuments bounds the documents read from one lock file.
const maxYAMLDocuments = 16

// Parse reads every document of the file: when a project pins its package
// manager ("packageManager" in package.json), pnpm 10 and later write two —
// the package manager's own installation first, then the project's lock file
// — and both are packages pnpm downloads.
func (pnpmLock) Parse(data []byte) (*Result, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	res := &Result{}
	documents := 0
	for {
		var root yaml.Node
		err := dec.Decode(&root)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, yamlError(err)
		}
		documents++
		if documents > maxYAMLDocuments {
			return nil, errors.New("pnpm-lock.yaml: too many YAML documents")
		}
		m := yamlMapping(&root)
		if m == nil {
			return nil, errors.New("pnpm-lock.yaml: not a YAML mapping")
		}
		version := yamlScalar(yamlGet(m, "lockfileVersion"))
		if version == "" {
			return nil, errors.New("pnpm-lock.yaml: no lockfileVersion")
		}
		if res.FormatVersion == "" {
			res.FormatVersion = version
		}
		major, _ := strconv.Atoi(strings.SplitN(strings.Trim(version, `'"`), ".", 2)[0])
		packages := yamlMapping(yamlGet(m, "packages"))
		if packages == nil {
			continue
		}
		for i := 0; i+1 < len(packages.Content); i += 2 {
			key, entry := packages.Content[i], yamlMapping(packages.Content[i+1])
			if entry == nil {
				continue
			}
			if d, ok := pnpmDependency(res, key, entry, major); ok {
				res.Dependencies = append(res.Dependencies, d)
			}
		}
	}
	if documents == 0 {
		return nil, errors.New("pnpm-lock.yaml: empty")
	}
	return res, nil
}

// pnpmKey splits a package key into name and version.
func pnpmKey(key string, major int) (name, version string) {
	k := strings.TrimPrefix(key, "/")
	if major > 0 && major < 6 {
		i := strings.LastIndex(k, "/")
		if i <= 0 {
			return "", ""
		}
		name, version = k[:i], k[i+1:]
		if j := strings.IndexByte(version, '_'); j > 0 {
			version = version[:j]
		}
		return name, version
	}
	if i := strings.IndexByte(k, '('); i > 0 {
		k = k[:i]
	}
	name, version, _ = splitNameAt(k)
	return name, version
}

func pnpmDependency(res *Result, key, entry *yaml.Node, major int) (Dependency, bool) {
	name, version := pnpmKey(yamlScalar(key), major)
	if n := yamlScalar(yamlGet(entry, "name")); n != "" {
		name = n
	}
	keyVersion := version
	if v := yamlScalar(yamlGet(entry, "version")); v != "" {
		version = v
	}
	if !validPackageName(name) {
		res.warnf("line %d: an entry has no usable package name", key.Line)
		return Dependency{}, false
	}
	resolution := yamlMapping(yamlGet(entry, "resolution"))
	if yamlGet(resolution, "directory") != nil || yamlScalar(yamlGet(resolution, "type")) == "directory" {
		return Dependency{}, false // a local folder
	}
	d := Dependency{
		Name:    name,
		Version: version,
		Line:    key.Line,
		Dev:     yamlScalar(yamlGet(entry, "dev")) == "true",
		Digests: sriDigests(yamlScalar(yamlGet(resolution, "integrity"))),
	}
	tarball := yamlScalar(yamlGet(resolution, "tarball"))
	switch {
	case yamlScalar(yamlGet(resolution, "type")) == "git":
		gs := parseGitURL(yamlScalar(yamlGet(resolution, "repo")))
		d.Source, d.Registry = SourceGit, gs.repo
		if commit := yamlScalar(yamlGet(resolution, "commit")); isCommitID(commit) {
			d.Revision = strings.ToLower(commit)
		}
	case strings.HasPrefix(tarball, "file:"):
		res.warnf("%s: installed from a local path, not fetched", name)
		return Dependency{}, false
	case isCodeloadTarball(tarball):
		owner, repo, commit := codeloadParts(tarball)
		d.Source, d.Registry, d.Revision, d.URL = SourceGit, "https://github.com/"+owner+"/"+repo, commit, cleanURL(tarball)
	case isHTTPURL(tarball):
		d.URL = cleanURL(tarball)
		if isHTTPURL(keyVersion) {
			d.Source = SourceURL // a dependency on a tarball URL, not a registry
		} else {
			d.Registry = npmRegistryBase(tarball, name)
		}
	case tarball != "":
		res.warnf("%s: unrecognised tarball location", name)
	}
	if !validVersion(d.Version) {
		res.warnf("%s: no version recorded", name)
		return Dependency{}, false
	}
	return d, true
}
