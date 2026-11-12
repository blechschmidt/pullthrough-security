package lockfiles

import (
	"bytes"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// yarnLock reads yarn.lock in both of its formats: Yarn Classic's own syntax
// ("# yarn lockfile v1") and Yarn Berry's YAML (a "__metadata" entry).
type yarnLock struct{}

func (yarnLock) Type() string            { return "npm" }
func (yarnLock) Format() string          { return "yarn.lock" }
func (yarnLock) Detect(path string) bool { return baseName(path) == "yarn.lock" }

func (yarnLock) Parse(data []byte) (*Result, error) {
	if isYarnBerry(data) {
		return parseYarnBerry(data)
	}
	return parseYarnClassic(data)
}

// isYarnBerry reports whether a yarn.lock is Berry's: it has a top-level
// "__metadata" key.
func isYarnBerry(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("__metadata:")) || bytes.HasPrefix(line, []byte(`"__metadata":`)) {
			return true
		}
	}
	return false
}

// yarnEntry is what a Classic entry records.
type yarnEntry struct {
	specs                        []string
	version, resolved, integrity string
	line                         int
}

// parseYarnClassic reads Yarn Classic's format: an entry per resolved package,
// keyed by the specifiers that resolved to it, with indented fields.
//
//	"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
//	  version "7.12.13"
//	  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc…"
//	  integrity sha512-…
//	  dependencies:
//	    "@babel/highlight" "^7.12.13"
func parseYarnClassic(data []byte) (*Result, error) {
	res := &Result{FormatVersion: "1"}
	var cur *yarnEntry
	flush := func() {
		if cur == nil {
			return
		}
		if d, ok := yarnClassicDependency(res, cur); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
		cur = nil
	}
	sawHeader := false
	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			if strings.Contains(trimmed, "yarn lockfile v1") {
				sawHeader = true
			}
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			flush()
			if !strings.HasSuffix(trimmed, ":") {
				return nil, errors.New("yarn.lock: line " + strconv.Itoa(lineNo) + ": expected an entry")
			}
			specs, err := yarnSpecs(strings.TrimSuffix(trimmed, ":"))
			if err != nil {
				return nil, errors.New("yarn.lock: line " + strconv.Itoa(lineNo) + ": " + err.Error())
			}
			cur = &yarnEntry{specs: specs, line: lineNo}
		case indent == 2 && cur != nil:
			key, value, _ := strings.Cut(trimmed, " ")
			v, err := yarnValue(strings.TrimSpace(value))
			if err != nil {
				return nil, errors.New("yarn.lock: line " + strconv.Itoa(lineNo) + ": " + err.Error())
			}
			switch strings.Trim(key, `"`) {
			case "version":
				cur.version = v
			case "resolved":
				cur.resolved = v
			case "integrity":
				cur.integrity = v
			}
		}
		// Deeper lines are an entry's dependency lists.
	}
	flush()
	if !sawHeader && len(res.Dependencies) == 0 {
		return nil, errors.New("not a yarn.lock: no \"# yarn lockfile v1\" header and no entries")
	}
	return res, nil
}

// yarnSpecs splits an entry key into its specifiers.
func yarnSpecs(key string) ([]string, error) {
	var specs []string
	for _, part := range splitOutsideQuotes(key, ',') {
		s, err := yarnValue(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		if s != "" {
			specs = append(specs, s)
		}
	}
	if len(specs) == 0 {
		return nil, errors.New("entry without specifiers")
	}
	return specs, nil
}

// yarnValue unquotes a Classic value: quoted values use JSON-style escapes.
func yarnValue(s string) (string, error) {
	if strings.HasPrefix(s, `"`) {
		v, err := strconv.Unquote(s)
		if err != nil {
			return "", errors.New("malformed quoted value")
		}
		return v, nil
	}
	return s, nil
}

// splitOutsideQuotes splits s at sep, except inside double quotes.
func splitOutsideQuotes(s string, sep byte) []string {
	var parts []string
	inQuote, escaped := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == sep && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// yarnSpecName returns the package a specifier names: "lodash@^4" names
// lodash, the alias "string-width-cjs@npm:string-width@^4.2.0" names
// string-width.
func yarnSpecName(spec string) (name, rng string) {
	name, rng, ok := splitNameAt(spec)
	if !ok {
		return spec, ""
	}
	if real, ok := strings.CutPrefix(rng, "npm:"); ok {
		if n, r, ok := splitNameAtLast(real); ok {
			return n, r
		}
		if !strings.Contains(real, "@") || strings.HasPrefix(real, "@") && strings.Count(real, "@") == 1 {
			// "npm:<range>" without a name keeps the alias name.
			return name, real
		}
	}
	return name, rng
}

func yarnClassicDependency(res *Result, e *yarnEntry) (Dependency, bool) {
	name, rng := yarnSpecName(e.specs[0])
	if !validPackageName(name) {
		res.warnf("line %d: an entry has no usable package name", e.line)
		return Dependency{}, false
	}
	if strings.HasPrefix(rng, "file:") || strings.HasPrefix(rng, "link:") || strings.HasPrefix(e.resolved, "file:") {
		res.warnf("%s: installed from a local path, not fetched", name)
		return Dependency{}, false
	}
	d := Dependency{Name: name, Version: e.version, Line: e.line, Digests: sriDigests(e.integrity)}
	resolved, frag, _ := strings.Cut(e.resolved, "#")
	switch {
	case isCodeloadTarball(resolved):
		// A GitHub dependency, resolved by Classic to an archive of a commit.
		owner, repo, commit := codeloadParts(resolved)
		d.Source, d.Registry, d.Revision, d.URL = SourceGit, "https://github.com/"+owner+"/"+repo, commit, cleanURL(resolved)
	case isGitSpec(e.resolved) || isGitSpec(rng):
		loc := e.resolved
		if loc == "" {
			loc = rng
		}
		gs := parseGitURL(loc)
		d.Source, d.Registry, d.Revision = SourceGit, gs.repo, gs.revision
	case isHTTPURL(resolved):
		d.URL = cleanURL(resolved)
		d.Registry = npmRegistryBase(resolved, name)
		if sha1, ok := hexDigest("sha1", frag, ""); ok {
			d.Digests = append(d.Digests, sha1)
		}
	}
	if !validVersion(d.Version) {
		res.warnf("%s: no version recorded", name)
		return Dependency{}, false
	}
	return d, true
}

// isCodeloadTarball reports whether u is a GitHub archive download.
func isCodeloadTarball(u string) bool {
	return strings.HasPrefix(u, "https://codeload.github.com/")
}

// codeloadParts splits "https://codeload.github.com/<owner>/<repo>/tar.gz/<ref>".
func codeloadParts(u string) (owner, repo, commit string) {
	parts := strings.Split(strings.TrimPrefix(u, "https://codeload.github.com/"), "/")
	if len(parts) >= 4 {
		owner, repo = parts[0], parts[1]
		if isCommitID(parts[3]) {
			commit = strings.ToLower(parts[3])
		}
	}
	return owner, repo, commit
}

// parseYarnBerry reads Berry's YAML lock file. Every entry has a
// "resolution": "<name>@<protocol>:<reference>". The npm: protocol is the
// registry; workspace:, file:, link:, portal: and exec: are local; patch: is a
// patched copy of a package that has an entry of its own; a URL of a Git
// host is a Git dependency.
func parseYarnBerry(data []byte) (*Result, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, yamlError(err)
	}
	m := yamlMapping(&root)
	if m == nil {
		return nil, errors.New("yarn.lock: not a YAML mapping")
	}
	res := &Result{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		if key.Value == "__metadata" {
			if meta := yamlMapping(val); meta != nil {
				res.FormatVersion = yamlScalar(yamlGet(meta, "version"))
			}
			continue
		}
		entry := yamlMapping(val)
		if entry == nil {
			continue
		}
		if d, ok := yarnBerryDependency(res, key, entry); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	return res, nil
}

func yarnBerryDependency(res *Result, key, entry *yaml.Node) (Dependency, bool) {
	resolution := yamlScalar(yamlGet(entry, "resolution"))
	name, ref, ok := splitNameAt(resolution)
	if !ok || !validPackageName(name) {
		res.warnf("line %d: an entry has no usable resolution", key.Line)
		return Dependency{}, false
	}
	protocol, reference, _ := strings.Cut(ref, ":")
	d := Dependency{Name: name, Version: yamlScalar(yamlGet(entry, "version")), Line: key.Line}
	switch {
	case protocol == "npm":
		if d.Version == "" {
			d.Version = reference
		}
	case protocol == "workspace", protocol == "file", protocol == "link", protocol == "portal", protocol == "exec":
		return Dependency{}, false // the project's own packages, or local ones
	case protocol == "patch":
		return Dependency{}, false // the unpatched package has its own entry
	case isGitSpec(ref) || strings.Contains(ref, ".git#") || strings.Contains(ref, "#commit="):
		gs := parseGitURL(ref)
		d.Source, d.Registry, d.Revision = SourceGit, gs.repo, gs.revision
	case protocol == "https" || protocol == "http":
		if unescaped, err := url.PathUnescape(ref); err == nil {
			ref = unescaped
		}
		d.Source, d.URL = SourceURL, cleanURL(ref)
	default:
		res.warnf("%s: unrecognised resolution protocol %q", name, protocol)
		return Dependency{}, false
	}
	if checksum := yamlScalar(yamlGet(entry, "checksum")); checksum != "" {
		// "<cache key>/<sha512 hex>" (Yarn 4) or the bare hex (earlier): the
		// hash of the zip archive Yarn keeps in its cache, not of the tarball.
		if _, hexValue, found := strings.Cut(checksum, "/"); found {
			checksum = hexValue
		}
		if dg, ok := hexDigest("sha512", checksum, "yarn-cache"); ok {
			d.Digests = append(d.Digests, dg)
		}
	}
	if !validVersion(d.Version) {
		res.warnf("%s: no version recorded", name)
		return Dependency{}, false
	}
	return d, true
}
