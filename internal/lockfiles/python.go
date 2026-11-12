package lockfiles

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Python lock files: requirements.txt pinned with == (and --hash), and the
// lock files of Pipenv, Poetry, uv and PDM. A Python package has one artifact
// per platform (wheels) plus a source archive, each with its own hash, so a
// dependency carries one digest per file, named by Digest.Of where the lock
// file names the file.

// pyNormalize returns a project name normalised as PEP 503 does (and the
// pip backend keys packages): lower case, runs of "-", "_", "." as one "-".
func pyNormalize(name string) string {
	return pySeparators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

var pySeparators = regexp.MustCompile(`[-_.]+`)

// pyNameRE matches a valid project name (PEP 508).
var pyNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// pyFileVersion extracts the version from a distribution file name: a wheel
// ("name-1.2.3-py3-none-any.whl") or a source archive ("name-1.2.3.tar.gz").
func pyFileVersion(file string) string {
	switch {
	case strings.HasSuffix(file, ".whl"):
		parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
		if len(parts) >= 5 {
			return parts[1]
		}
	default:
		for _, ext := range []string{".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz"} {
			if base, ok := strings.CutSuffix(file, ext); ok {
				if i := strings.LastIndexByte(base, '-'); i > 0 {
					return base[i+1:]
				}
			}
		}
	}
	return ""
}

// --- requirements.txt --------------------------------------------------------

// requirementsTxt reads pip requirements files: only exact pins ("==" or
// "===") are dependencies; a range, a local path or an editable checkout is a
// warning. Includes (-r, -c) are not followed — the walk finds those files on
// its own when they are named like requirements files.
type requirementsTxt struct{}

func (requirementsTxt) Type() string   { return "pip" }
func (requirementsTxt) Format() string { return "requirements.txt" }

// Detect accepts requirements.txt, requirements-*.txt / requirements_*.txt,
// *-requirements.txt, constraints.txt and *.txt files in a "requirements"
// directory.
func (requirementsTxt) Detect(path string) bool {
	name := strings.ToLower(baseName(path))
	if !strings.HasSuffix(name, ".txt") {
		return false
	}
	stem := strings.TrimSuffix(name, ".txt")
	switch {
	case stem == "requirements" || stem == "constraints":
		return true
	case strings.HasPrefix(stem, "requirements-") || strings.HasPrefix(stem, "requirements_") || strings.HasPrefix(stem, "requirements."):
		return true
	case strings.HasSuffix(stem, "-requirements") || strings.HasSuffix(stem, "_requirements"):
		return true
	}
	dir := strings.ToLower(baseName(dirName(path)))
	return dir == "requirements" || dir == "requirements.d"
}

// reqLineRE splits a requirement: name, extras, specifier, the rest.
var reqLineRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)

func (requirementsTxt) Parse(data []byte) (*Result, error) {
	if strings.IndexByte(string(data), 0) >= 0 {
		return nil, errors.New("requirements file contains a NUL byte")
	}
	res := &Result{}
	index := ""
	for _, ll := range logicalLines(string(data)) {
		line := stripReqComment(ll.text)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			opt, value := reqOption(line)
			switch opt {
			case "-i", "--index-url":
				index = cleanURL(value)
			case "-r", "--requirement", "-c", "--constraint":
				res.warnf("line %d: includes another requirements file, read on its own if the scan finds it", ll.line)
			case "-e", "--editable":
				if d, ok := reqVCS(res, value, ll.line); ok {
					res.Dependencies = append(res.Dependencies, d)
				} else {
					res.warnf("line %d: an editable install from a local path, not fetched", ll.line)
				}
			}
			continue
		}
		if d, ok := reqRequirement(res, line, index, ll.line); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	return res, nil
}

// logicalLine is a line with its continuations ("\" at the end) joined.
type logicalLine struct {
	text string
	line int
}

func logicalLines(s string) []logicalLine {
	var out []logicalLine
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(s, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if cur.Len() == 0 {
			start = i + 1
		}
		if strings.HasSuffix(raw, "\\") {
			cur.WriteString(strings.TrimSuffix(raw, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(raw)
		out = append(out, logicalLine{text: cur.String(), line: start})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, logicalLine{text: cur.String(), line: start})
	}
	return out
}

// stripReqComment removes a comment: "#" at the start of a line or after
// whitespace ("#egg=" in a URL is not a comment).
func stripReqComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
}

// reqOption splits "--opt=value" / "--opt value" / "-o value".
func reqOption(line string) (opt, value string) {
	opt, value, found := strings.Cut(line, "=")
	if found && !strings.ContainsAny(opt, " \t") {
		return opt, strings.TrimSpace(value)
	}
	f := strings.Fields(line)
	opt = f[0]
	if len(f) > 1 {
		value = f[1]
	}
	return opt, value
}

// reqVCS reads a VCS location ("git+https://github.com/o/r@<rev>#egg=name").
func reqVCS(res *Result, loc string, line int) (Dependency, bool) {
	if !strings.HasPrefix(loc, "git+") {
		return Dependency{}, false
	}
	name := ""
	if _, frag, ok := strings.Cut(loc, "#"); ok {
		for _, kv := range strings.Split(frag, "&") {
			if v, ok := strings.CutPrefix(kv, "egg="); ok {
				name = v
			}
		}
	}
	base, _, _ := strings.Cut(loc, "#")
	rev := ""
	// "@<rev>" after the path (not the "git@" of an ssh URL).
	if i := strings.LastIndexByte(base, '@'); i > strings.LastIndexByte(base, '/') {
		base, rev = base[:i], base[i+1:]
	}
	if !pyNameRE.MatchString(name) {
		res.warnf("line %d: a VCS requirement without a project name (#egg=)", line)
		return Dependency{}, false
	}
	d := Dependency{Name: pyNormalize(name), Source: SourceGit, Registry: cleanGitRepoURL(base), Line: line}
	if isCommitID(rev) {
		d.Revision = strings.ToLower(rev)
		d.Version = d.Revision
	} else {
		res.warnf("line %d: %s is pinned to %q, not to a commit", line, d.Name, rev)
		return Dependency{}, false
	}
	return d, true
}

// reqRequirement reads one requirement line.
func reqRequirement(res *Result, line, index string, lineNo int) (Dependency, bool) {
	// Options after the requirement: --hash=…, --global-option, ….
	var hashes []Digest
	fields := strings.Fields(line)
	var spec []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "--hash") {
			v := strings.TrimPrefix(strings.TrimPrefix(f, "--hash"), "=")
			if v == "" && i+1 < len(fields) {
				i++
				v = fields[i]
			}
			if d, ok := prefixedDigest(v, ""); ok {
				hashes = append(hashes, d)
			}
			continue
		}
		if strings.HasPrefix(f, "--") {
			continue
		}
		spec = append(spec, f)
	}
	text := strings.Join(spec, " ")
	if i := strings.IndexByte(text, ';'); i >= 0 {
		text = strings.TrimSpace(text[:i]) // environment markers
	}
	m := reqLineRE.FindStringSubmatch(text)
	if m == nil {
		res.warnf("line %d: not a requirement this parser understands", lineNo)
		return Dependency{}, false
	}
	name, rest := pyNormalize(m[1]), strings.TrimSpace(m[3])
	if direct, ok := strings.CutPrefix(rest, "@"); ok {
		return reqDirect(res, name, strings.TrimSpace(direct), hashes, lineNo)
	}
	op, version := "", ""
	switch {
	case strings.HasPrefix(rest, "==="):
		op, version = "===", strings.TrimSpace(rest[3:])
	case strings.HasPrefix(rest, "=="):
		op, version = "==", strings.TrimSpace(rest[2:])
	}
	if op == "" || version == "" || strings.ContainsAny(version, ",<>!~*= ") {
		res.warnf("line %d: %s is not pinned to an exact version", lineNo, name)
		return Dependency{}, false
	}
	return Dependency{Name: name, Version: version, Registry: index, Digests: hashes, Line: lineNo}, true
}

// reqDirect reads "name @ <url>".
func reqDirect(res *Result, name, loc string, hashes []Digest, lineNo int) (Dependency, bool) {
	if strings.HasPrefix(loc, "git+") {
		return reqVCS(res, loc+"#egg="+name, lineNo)
	}
	if !isHTTPURL(loc) {
		res.warnf("line %d: %s is installed from a local path, not fetched", lineNo, name)
		return Dependency{}, false
	}
	if _, frag, ok := strings.Cut(loc, "#"); ok {
		if d, ok := prefixedDigest(frag, ""); ok {
			hashes = append(hashes, d)
		}
	}
	file := fileNameOf(loc)
	version := pyFileVersion(file)
	if version == "" {
		res.warnf("line %d: %s: the version of %s cannot be told from its file name", lineNo, name, "the download")
		return Dependency{}, false
	}
	for i := range hashes {
		hashes[i].Of = file
	}
	return Dependency{Name: name, Version: version, Source: SourceURL, URL: cleanURL(loc), Digests: hashes, Line: lineNo}, true
}

// --- Pipfile.lock --------------------------------------------------------------

// pipfileLock reads Pipenv's Pipfile.lock: JSON, "default" and "develop"
// sections keyed by project name, each entry with "==version", its hashes and
// the name of the index (from "_meta.sources") it comes from.
type pipfileLock struct{}

func (pipfileLock) Type() string            { return "pip" }
func (pipfileLock) Format() string          { return "Pipfile.lock" }
func (pipfileLock) Detect(path string) bool { return baseName(path) == "Pipfile.lock" }

type pipfileEntry struct {
	Version lenientString  `json:"version"`
	Hashes  lenientStrings `json:"hashes"`
	Index   lenientString  `json:"index"`
	Git     lenientString  `json:"git"`
	Ref     lenientString  `json:"ref"`
	File    lenientString  `json:"file"`
	Path    lenientString  `json:"path"`
}

type pipfileSource struct {
	Name lenientString `json:"name"`
	URL  lenientString `json:"url"`
}

func (pipfileLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	type pending struct {
		name  string
		entry pipfileEntry
		line  int
		dev   bool
	}
	var entries []pending
	sources := map[string]string{}
	firstSource := ""
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "_meta":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			return doc.object(func(field string, _ int) error {
				switch field {
				case "pipfile-spec":
					var v any
					if err := doc.value(&v); err != nil {
						return err
					}
					res.FormatVersion = fmt.Sprint(v)
					return nil
				case "sources":
					var list []pipfileSource
					if doc.peekKind() != '[' {
						return doc.skip()
					}
					if err := doc.value(&list); err != nil {
						return err
					}
					for _, s := range list {
						if s.URL == "" {
							continue
						}
						sources[string(s.Name)] = string(s.URL)
						if firstSource == "" {
							firstSource = string(s.URL)
						}
					}
					return nil
				}
				return doc.skip()
			})
		case "default", "develop":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			dev := key == "develop"
			return doc.object(func(name string, line int) error {
				if doc.peekKind() != '{' {
					return doc.skip()
				}
				var e pipfileEntry
				if err := doc.value(&e); err != nil {
					return err
				}
				entries = append(entries, pending{name: name, entry: e, line: line, dev: dev})
				return nil
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
	for _, p := range entries {
		name := pyNormalize(p.name)
		if !pyNameRE.MatchString(p.name) {
			res.warnf("line %d: an entry has no usable project name", p.line)
			continue
		}
		e := p.entry
		d := Dependency{Name: name, Dev: p.dev, Line: p.line}
		for _, h := range e.Hashes {
			if dg, ok := prefixedDigest(h, ""); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		switch {
		case e.Git != "":
			gs := parseGitURL(string(e.Git))
			d.Source, d.Registry = SourceGit, gs.repo
			if isCommitID(string(e.Ref)) {
				d.Revision = strings.ToLower(string(e.Ref))
			}
			d.Version = strings.TrimPrefix(string(e.Version), "==")
			if d.Version == "" {
				d.Version = d.Revision
			}
		case e.File != "" && isHTTPURL(string(e.File)):
			d.Source, d.URL = SourceURL, cleanURL(string(e.File))
			d.Version = pyFileVersion(fileNameOf(string(e.File)))
		case e.Path != "" || e.File != "":
			res.warnf("%s: installed from a local path, not fetched", name)
			continue
		default:
			v := string(e.Version)
			switch {
			case strings.HasPrefix(v, "==="):
				v = v[3:]
			case strings.HasPrefix(v, "=="):
				v = v[2:]
			default:
				res.warnf("%s is not pinned to an exact version", name)
				continue
			}
			d.Version = v
			if url, ok := sources[string(e.Index)]; ok {
				d.Registry = cleanURL(url)
			} else if firstSource != "" {
				d.Registry = cleanURL(firstSource)
			}
		}
		if !validVersion(d.Version) {
			res.warnf("%s: no version recorded", name)
			continue
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}

// --- poetry.lock -----------------------------------------------------------------

// poetryLock reads Poetry's poetry.lock (TOML): a [[package]] table per
// project with its files and their hashes — in [metadata.files] before
// lock-version 2.0 — and a [package.source] table for anything not from PyPI.
type poetryLock struct{}

func (poetryLock) Type() string            { return "pip" }
func (poetryLock) Format() string          { return "poetry.lock" }
func (poetryLock) Detect(path string) bool { return baseName(path) == "poetry.lock" }

func (poetryLock) Parse(data []byte) (*Result, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	meta := doc.table("metadata")
	res.FormatVersion = meta.str("lock-version")
	// Before lock-version 2.0 the files are listed per project name.
	legacyFiles := map[string][]*tomlTable{}
	if files := meta.table("files"); files != nil {
		for _, k := range files.keys {
			legacyFiles[pyNormalize(k)] = files.tables(k)
		}
	}
	pkgs := doc.tables("package")
	if pkgs == nil && meta == nil {
		return nil, errors.New("not a poetry.lock: no [[package]] and no [metadata]")
	}
	for _, pkg := range pkgs {
		raw := pkg.str("name")
		if !pyNameRE.MatchString(raw) {
			res.warnf("line %d: a package has no usable name", pkg.line)
			continue
		}
		name := pyNormalize(raw)
		d := Dependency{Name: name, Version: pkg.str("version"), Line: pkg.line}
		if pkg.str("category") == "dev" {
			d.Dev = true
		}
		if groups := pkg.strings("groups"); len(groups) > 0 && !containsString(groups, "main") {
			d.Dev = true
		}
		files := pkg.tables("files")
		if pkg.get("files") == nil {
			files = legacyFiles[name]
		}
		for _, f := range files {
			if dg, ok := prefixedDigest(f.str("hash"), f.str("file")); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		if src := pkg.table("source"); src != nil {
			switch src.str("type") {
			case "git":
				d.Source, d.Registry = SourceGit, cleanGitRepoURL(src.str("url"))
				if rev := src.str("resolved_reference"); isCommitID(rev) {
					d.Revision = strings.ToLower(rev)
				}
			case "legacy", "explicit", "supplemental", "primary", "":
				d.Registry = cleanURL(src.str("url"))
			case "url":
				d.Source, d.URL = SourceURL, cleanURL(src.str("url"))
			case "directory", "file":
				res.warnf("%s: installed from a local path, not fetched", name)
				continue
			default:
				res.warnf("%s: unrecognised source type %q", name, src.str("type"))
				continue
			}
		}
		if !validVersion(d.Version) {
			res.warnf("%s: no version recorded", name)
			continue
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- uv.lock ---------------------------------------------------------------------

// uvLock reads uv's uv.lock (TOML): a [[package]] per project version with
// its source — a registry, a Git repository, a URL, or the project's own
// folders — and its sdist and wheels with their hashes.
type uvLock struct{}

func (uvLock) Type() string            { return "pip" }
func (uvLock) Format() string          { return "uv.lock" }
func (uvLock) Detect(path string) bool { return baseName(path) == "uv.lock" }

func (uvLock) Parse(data []byte) (*Result, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	if v := doc.get("version"); v != nil && v.kind == tkInteger {
		res.FormatVersion = v.str
		if r := doc.get("revision"); r != nil && r.kind == tkInteger {
			res.FormatVersion += " (revision " + r.str + ")"
		}
	}
	pkgs := doc.tables("package")
	if pkgs == nil && res.FormatVersion == "" {
		return nil, errors.New("not a uv.lock: no version and no [[package]]")
	}
	for _, pkg := range pkgs {
		raw := pkg.str("name")
		if !pyNameRE.MatchString(raw) {
			res.warnf("line %d: a package has no usable name", pkg.line)
			continue
		}
		name := pyNormalize(raw)
		d := Dependency{Name: name, Version: pkg.str("version"), Line: pkg.line}
		src := pkg.table("source")
		switch {
		case src == nil:
			res.warnf("%s: no source recorded", name)
			continue
		case src.str("registry") != "":
			if r := src.str("registry"); isHTTPURL(r) {
				d.Registry = cleanURL(r)
			} else {
				d.Registry = "" // a registry in a local folder
			}
		case src.str("git") != "":
			gs := parseGitURL(src.str("git"))
			d.Source, d.Registry, d.Revision = SourceGit, gs.repo, gs.revision
		case src.str("url") != "":
			d.Source, d.URL = SourceURL, cleanURL(src.str("url"))
		default:
			// editable, virtual, directory, path: the project's own folders.
			continue
		}
		if sd := pkg.table("sdist"); sd != nil {
			if dg, ok := prefixedDigest(sd.str("hash"), fileNameOf(sd.str("url")+sd.str("path"))); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		for _, w := range pkg.tables("wheels") {
			if dg, ok := prefixedDigest(w.str("hash"), fileNameOf(w.str("url")+w.str("path")+w.str("filename"))); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		if !validVersion(d.Version) {
			res.warnf("%s: no version recorded", name)
			continue
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}

// --- pdm.lock --------------------------------------------------------------------

// pdmLock reads PDM's pdm.lock (TOML): a [[package]] per project with its
// groups and files — in [metadata.files], keyed "<name> <version>", before
// lock_version 4.3.
type pdmLock struct{}

func (pdmLock) Type() string            { return "pip" }
func (pdmLock) Format() string          { return "pdm.lock" }
func (pdmLock) Detect(path string) bool { return baseName(path) == "pdm.lock" }

func (pdmLock) Parse(data []byte) (*Result, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	meta := doc.table("metadata")
	res.FormatVersion = meta.str("lock_version")
	legacyFiles := map[string][]*tomlTable{}
	if files := meta.table("files"); files != nil {
		for _, k := range files.keys {
			n, v, ok := strings.Cut(k, " ")
			if ok {
				legacyFiles[pyNormalize(n)+" "+v] = files.tables(k)
			}
		}
	}
	pkgs := doc.tables("package")
	if pkgs == nil && meta == nil {
		return nil, errors.New("not a pdm.lock: no [[package]] and no [metadata]")
	}
	for _, pkg := range pkgs {
		raw := pkg.str("name")
		if !pyNameRE.MatchString(raw) {
			res.warnf("line %d: a package has no usable name", pkg.line)
			continue
		}
		name := pyNormalize(raw)
		d := Dependency{Name: name, Version: pkg.str("version"), Line: pkg.line}
		if groups := pkg.strings("groups"); len(groups) > 0 && !containsString(groups, "default") {
			d.Dev = true
		}
		switch {
		case pkg.str("git") != "":
			d.Source, d.Registry = SourceGit, cleanGitRepoURL(pkg.str("git"))
			if rev := pkg.str("revision"); isCommitID(rev) {
				d.Revision = strings.ToLower(rev)
			}
		case pkg.str("url") != "":
			d.Source, d.URL = SourceURL, cleanURL(pkg.str("url"))
		case pkg.str("path") != "" || pkg.get("editable") != nil:
			res.warnf("%s: installed from a local path, not fetched", name)
			continue
		}
		files := pkg.tables("files")
		if pkg.get("files") == nil {
			files = legacyFiles[name+" "+d.Version]
		}
		for _, f := range files {
			of := f.str("file")
			if of == "" {
				of = fileNameOf(f.str("url"))
			}
			if dg, ok := prefixedDigest(f.str("hash"), of); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		if !validVersion(d.Version) {
			res.warnf("%s: no version recorded", name)
			continue
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}
