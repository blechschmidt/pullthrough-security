package lockfiles

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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
	if name == "requirements-dev.lock" {
		return true // Rye's; its requirements.lock is read through requirementsLock
	}
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
	forEachLogicalLine(string(data), func(ll logicalLine) {
		line := stripReqComment(ll.text)
		if line == "" {
			return
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
					res.add(d)
				} else {
					res.warnf("line %d: an editable install from a local path, not fetched", ll.line)
				}
			}
			return
		}
		if d, ok := reqRequirement(res, line, index, ll.line); ok {
			res.add(d)
		}
	})
	return res, nil
}

// logicalLine is a line with its continuations ("\" at the end) joined.
type logicalLine struct {
	text string
	line int
}

// forEachLogicalLine calls fn for every logical line of s that is not blank,
// exactly as pip reads a requirements file (pip/_internal/req/req_file.py,
// preprocess): the text is split as Python's str.splitlines splits it; a line
// ending in "\\" is joined with the next — unless it is a comment line —
// with the backslashes stripped from its ends; then comments are removed and
// the line stripped. Reading it any other way is a parser differential: a
// requirement pip installs that the scan does not see (a lone "\r" or "\f"
// separating two requirements, a comment line ending in a backslash).
func forEachLogicalLine(s string, fn func(logicalLine)) {
	var cur strings.Builder
	primary, joining := 0, false
	emit := func(text string, n int) {
		if text = pyStripComment(text); text != "" {
			fn(logicalLine{text: text, line: n})
		}
	}
	for it := newPyLineIter(s); ; {
		line, n, more := it.next()
		if !more {
			break
		}
		comment := pyCommentLine(line)
		if !strings.HasSuffix(line, "\\") || comment {
			if comment {
				line = " " + line // pip: "this ensures comments are always matched later"
			}
			if joining {
				cur.WriteString(line)
				emit(cur.String(), primary)
				cur.Reset()
				joining = false
			} else {
				emit(line, n)
			}
			continue
		}
		if !joining {
			primary, joining = n, true
		}
		cur.WriteString(strings.Trim(line, "\\"))
	}
	if joining {
		emit(cur.String(), primary)
	}
}

// pyLineIter walks lines as Python's str.splitlines yields them: split at
// \n, \r, \r\n, \v, \f, \x1c, \x1d, \x1e, U+0085, U+2028 and U+2029, with no
// empty line after a final break. Each line is reported with the number of
// the editor line it starts on — lines counted at "\n", as every location the
// scan reports is — not its index among pip's lines.
type pyLineIter struct {
	s        string
	pos      int
	newlines int // "\n" before pos
}

func newPyLineIter(s string) *pyLineIter { return &pyLineIter{s: s} }

func (it *pyLineIter) next() (string, int, bool) {
	if it.pos >= len(it.s) {
		return "", 0, false
	}
	rest := it.s[it.pos:]
	n := it.newlines + 1
	for i, r := range rest {
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			it.advance(i + utf8.RuneLen(r))
			return rest[:i], n, true
		case '\r':
			step := 1
			if i+1 < len(rest) && rest[i+1] == '\n' {
				step = 2
			}
			it.advance(i + step)
			return rest[:i], n, true
		}
	}
	it.advance(len(rest))
	return rest, n, true
}

// advance moves past k bytes, counting the "\n" among them.
func (it *pyLineIter) advance(k int) {
	it.newlines += strings.Count(it.s[it.pos:it.pos+k], "\n")
	it.pos += k
}

// pySpace is Python's str.isspace for one character: Unicode white space and
// the separators \x1c to \x1f.
func pySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pyCommentLine is pip's COMMENT_RE.match: the line starts with "#",
// optionally after white space.
func pyCommentLine(line string) bool {
	t := strings.TrimLeftFunc(line, pySpace)
	return strings.HasPrefix(t, "#")
}

// pyStripComment is pip's COMMENT_RE.sub("", line).strip(): a comment is
// "#" at the start of the line or after white space, and runs to the end.
func pyStripComment(line string) string {
	prev := rune(-1)
	for i, r := range line {
		if r == '#' && (prev == -1 || pySpace(prev)) {
			line = line[:i]
			break
		}
		prev = r
	}
	return strings.TrimFunc(line, pySpace)
}

// stripReqComment removes a comment: "#" at the start of a line or after
// whitespace ("#egg=" in a URL is not a comment).
func stripReqComment(s string) string {
	return pyStripComment(s)
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

func (pipfileLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	type pending struct {
		name  string
		entry jsonFields
		line  int
		dev   bool
	}
	// A repeated key keeps its last value, as Pipenv's json.load does: a
	// section, and a package within a section.
	sections := map[string][]pending{}
	sources := map[string]string{}
	firstSource := ""
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "_meta":
			meta, err := doc.fields()
			if err != nil || meta == nil {
				return err
			}
			if v, ok := meta["pipfile-spec"]; ok {
				res.FormatVersion = strings.Trim(string(v), `"`)
			}
			sources, firstSource = map[string]string{}, ""
			var list []map[string]json.RawMessage
			if json.Unmarshal(meta["sources"], &list) == nil {
				for _, src := range list {
					f := jsonFields(src)
					if f.str("url") == "" {
						continue
					}
					sources[f.str("name")] = f.str("url")
					if firstSource == "" {
						firstSource = f.str("url")
					}
				}
			}
			return nil
		case "default", "develop":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			dev := key == "develop"
			var entries []pending
			byName := map[string]int{}
			err := doc.object(func(name string, line int) error {
				e, err := doc.fields()
				if err != nil || e == nil {
					return err
				}
				if i, dup := byName[name]; dup {
					entries[i].entry = nil // superseded
				}
				byName[name] = len(entries)
				entries = append(entries, pending{name: name, entry: e, line: line, dev: dev})
				return nil
			})
			sections[key] = entries
			return err
		}
		return doc.skip()
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	for _, p := range append(sections["default"], sections["develop"]...) {
		if p.entry == nil {
			continue
		}
		name := pyNormalize(p.name)
		if !pyNameRE.MatchString(p.name) {
			res.warnf("line %d: an entry has no usable project name", p.line)
			continue
		}
		e := p.entry
		d := Dependency{Name: name, Dev: p.dev, Line: p.line}
		for _, h := range e.strs("hashes") {
			if dg, ok := prefixedDigest(h, ""); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		switch {
		case e.str("git") != "":
			gs := parseGitURL(e.str("git"))
			d.Source, d.Registry = SourceGit, gs.repo
			if isCommitID(e.str("ref")) {
				d.Revision = strings.ToLower(e.str("ref"))
			}
			d.Version = strings.TrimPrefix(e.str("version"), "==")
			if d.Version == "" {
				d.Version = d.Revision
			}
		case e.str("file") != "" && isHTTPURL(e.str("file")):
			d.Source, d.URL = SourceURL, cleanURL(e.str("file"))
			d.Version = pyFileVersion(fileNameOf(e.str("file")))
		case e.str("path") != "" || e.str("file") != "":
			res.warnf("%s: installed from a local path, not fetched", name)
			continue
		default:
			v := e.str("version")
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
			if url, ok := sources[e.str("index")]; ok {
				d.Registry = cleanURL(url)
			} else if firstSource != "" {
				d.Registry = cleanURL(firstSource)
			}
		}
		if !validVersion(d.Version) {
			res.warnf("%s: no version recorded", name)
			continue
		}
		res.add(d)
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
		res.add(d)
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
		res.add(d)
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
		res.add(d)
	}
	return res, nil
}
