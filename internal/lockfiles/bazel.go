package lockfiles

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// moduleBazelLock reads Bazel's MODULE.bazel.lock (Bzlmod). Its layout
// changed with lockFileVersion:
//
//	13 and later (Bazel 7.2+)   "registryFileHashes": the SHA-256 of every
//	                            registry file resolution read — the
//	                            MODULE.bazel of every module version visited,
//	                            and the source.json of every version selected
//	up to 6 (Bazel 6, 7.0, 7.1) "moduleDepGraph": every selected module with
//	                            its "repoSpec" — the archive's URLs and
//	                            Subresource Integrity, or a Git repository
//
// In the newer layout a module version is a dependency when its source.json
// is hashed: only selected versions are fetched, the others were read for
// version selection only. The source.json names the archive and its
// integrity, so its hash pins the archive (Digest.Of "source.json"); the
// MODULE.bazel hash pins only the module's declaration ("MODULE.bazel").
// The repositories module extensions generate ("moduleExtensions") are not
// read, nor does the lock file record which modules are dev dependencies.
type moduleBazelLock struct{}

func (moduleBazelLock) Type() string            { return "bazel" }
func (moduleBazelLock) Format() string          { return "MODULE.bazel.lock" }
func (moduleBazelLock) Detect(path string) bool { return baseName(path) == "MODULE.bazel.lock" }

func (moduleBazelLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	type hashed struct {
		url, hash string
		line      int
	}
	var files []hashed
	var graph []denoEntry
	var yanked []string
	sawContent := false
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "lockFileVersion":
			v, err := jsonScalar(doc)
			res.FormatVersion = v
			return err
		case "registryFileHashes":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawContent = true
			files = nil
			seen := map[string]bool{}
			return doc.object(func(u string, line int) error {
				// Bazel reads the lock file with Gson, which refuses a key
				// given twice in a map.
				if seen[u] {
					return fmt.Errorf("MODULE.bazel.lock line %d: a registry file is hashed twice", line)
				}
				seen[u] = true
				h, err := doc.stringValue()
				if err == nil {
					files = append(files, hashed{url: u, hash: h, line: line})
				}
				return err
			})
		case "moduleDepGraph":
			sawContent = true
			entries, err := denoPackages(doc)
			graph = entries
			return err
		case "selectedYankedVersions":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			yanked = nil
			return doc.object(func(k string, _ int) error {
				yanked = append(yanked, k)
				return doc.skip()
			})
		}
		return doc.skip()
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if res.FormatVersion == "" && !sawContent {
		return nil, errNotFormat("MODULE.bazel.lock", "no lockFileVersion")
	}
	// A Bazel reads only the layout of its own lockFileVersion: up to 10
	// the moduleDepGraph, from 11 (Bazel 7.2) the registry file hashes. The
	// other layout's section is refused rather than read.
	lockVersion, err := strconv.Atoi(res.FormatVersion)
	switch {
	case err != nil:
		return nil, fmt.Errorf("MODULE.bazel.lock lockFileVersion %s is not a number", quoteName(res.FormatVersion))
	case lockVersion >= 11 && graph != nil:
		return nil, errors.New("MODULE.bazel.lock with a moduleDepGraph, which its lockFileVersion does not have")
	case lockVersion < 11 && files != nil:
		return nil, errors.New("MODULE.bazel.lock with registryFileHashes, which its lockFileVersion does not have")
	}

	// Newer layout: group the hashed registry files by module version.
	type module struct {
		registry, name, version string
		source, decl            Digest
		line                    int
	}
	byKey := map[string]*module{}
	var keys []string
	for _, f := range files {
		registry, name, version, file, ok := bazelRegistryFile(f.url)
		if !ok {
			continue // bazel_registry.json, metadata, patches
		}
		key := registry + "\x00" + name + "\x00" + version
		m := byKey[key]
		if m == nil {
			m = &module{registry: registry, name: name, version: version, line: f.line}
			byKey[key] = m
			keys = append(keys, key)
		}
		dg, ok := hexDigest("sha256", f.hash, file)
		if !ok {
			continue // "not found", or not a digest
		}
		switch file {
		case "source.json":
			m.source = dg
			m.line = f.line
		case "MODULE.bazel":
			m.decl = dg
		}
	}
	for _, k := range keys {
		m := byKey[k]
		if m.source.Value == "" {
			continue // read for version selection, not fetched
		}
		d := Dependency{Name: m.name, Version: m.version, Registry: m.registry, Line: m.line, Digests: []Digest{m.source}}
		if m.decl.Value != "" {
			d.Digests = append(d.Digests, m.decl)
		}
		if validPackageName(d.Name) && validVersion(d.Version) {
			res.add(d)
		}
	}

	// Older layout: the selected modules with their repository specs.
	for _, e := range graph {
		if e.key == "<root>" {
			continue
		}
		if d, ok := bazelGraphModule(res, e); ok {
			res.add(d)
		}
	}
	sort.Strings(yanked)
	for _, y := range yanked {
		res.warnf("%s is a yanked version, selected all the same", quoteName(y))
	}
	return res, nil
}

// bazelRegistryFile splits "<registry>/modules/<name>/<version>/<file>",
// counting from the end: a module may itself be named "modules".
func bazelRegistryFile(u string) (registry, name, version, file string, ok bool) {
	if !isHTTPURL(u) {
		return "", "", "", "", false
	}
	parts := strings.Split(u, "/")
	n := len(parts)
	if n < 5 || parts[n-4] != "modules" || parts[n-3] == "" || parts[n-2] == "" {
		return "", "", "", "", false
	}
	switch parts[n-1] {
	case "MODULE.bazel", "source.json":
	default:
		return "", "", "", "", false
	}
	registry = strings.Join(parts[:n-4], "/")
	if originOf(registry) == "" {
		return "", "", "", "", false // no host before "/modules/"
	}
	return cleanURL(registry), parts[n-3], parts[n-2], parts[n-1], true
}

// bazelGraphModule reads a module of the older moduleDepGraph.
func bazelGraphModule(res *Result, e denoEntry) (Dependency, bool) {
	name, version := e.fields.str("name"), e.fields.str("version")
	spec := e.fields.obj("repoSpec")
	if spec == nil {
		return Dependency{}, false // a module built into Bazel (bazel_tools@_)
	}
	attrs := spec.obj("attributes")
	d := Dependency{Name: name, Version: version, Line: e.line}
	switch rule := spec.str("ruleClassName"); rule {
	case "http_archive":
		urls := attrs.strs("urls")
		if len(urls) == 0 && attrs.str("url") != "" {
			urls = []string{attrs.str("url")}
		}
		if len(urls) > 0 && isHTTPURL(urls[0]) {
			d.URL = cleanURL(urls[0])
		}
		d.Digests = sriDigests(attrs.str("integrity"))
		if dg, ok := hexDigest("sha256", attrs.str("sha256"), ""); ok {
			d.Digests = append(d.Digests, dg)
		}
	case "git_repository":
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(attrs.str("remote"))
		if c := attrs.str("commit"); isCommitID(c) {
			d.Revision = strings.ToLower(c)
		}
	case "local_repository", "new_local_repository":
		res.warnf("%s: a local repository, not fetched", quoteName(e.key))
		return Dependency{}, false
	default:
		res.warnf("%s: a repository rule this parser does not read", quoteName(e.key))
		return Dependency{}, false
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		if d.Revision != "" && validPackageName(d.Name) {
			d.Version = d.Revision // a module overridden by a commit has no version
		} else {
			res.warnf("%s: no usable name or version", quoteName(e.key))
			return Dependency{}, false
		}
	}
	return d, true
}
