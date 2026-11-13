package update

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// requirementsUpdater rewrites pip requirements files — what pip-compile and
// `uv pip compile` write, and what people write by hand. A pin of a changed
// project at the old version ("name==version", extras, markers and comments
// as they are) moves to the new version; where it lists --hash options, they
// are all replaced by the SHA-256 of each distribution file of the new
// version, laid out as before: one per continuation line with the original
// indentation, or in a row on the requirement's own line. A pin without
// hashes stays without. Lines are read as internal/lockfiles reads them
// (backslash continuations joined, comments cut), so that what is rewritten
// is exactly what the scan saw.
type requirementsUpdater struct{}

func (requirementsUpdater) Key() string { return "pip/requirements.txt" }

// pipChange is a change with what its requirements get.
type pipChange struct {
	Change
	// hashes are the new version's file digests, sorted as pip-compile sorts
	// them; hashesErr says why there are none, which fails a requirement
	// that lists hashes.
	hashes    []string
	hashesErr error
	matched   int
}

// maxRequirementLines bounds the physical lines of one requirement the
// rewrite takes apart: one per hash, and a release has a few hundred files
// at most.
const maxRequirementLines = 10_000

func (requirementsUpdater) Apply(lockPath string, files map[string][]byte, changes []Change) (map[string][]byte, error) {
	data, ok := files[lockPath]
	if !ok {
		return nil, fmt.Errorf("%s is not among the files", lockPath)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("the requirements file contains a NUL byte")
	}
	// A pin's version may not hold what internal/lockfiles refuses in one
	// (",<>!~*= "): the rewritten pin must read as a pin.
	if err := checkChanges("pip", changes, func(s string) bool { return tokenOf(s, "._-") }, func(s string) bool { return tokenOf(s, "._+-") }); err != nil {
		return nil, err
	}
	r := &reqRewrite{data: data, byName: map[string][]*pipChange{}}
	var all []*pipChange
	for _, c := range changes {
		pc := &pipChange{Change: c}
		pc.hashes, pc.hashesErr = pipHashes(c)
		n := pyNormalize(c.Name)
		for _, other := range r.byName[n] {
			if other.From == c.From {
				return nil, fmt.Errorf("two changes of %s %s", n, c.From)
			}
		}
		r.byName[n] = append(r.byName[n], pc)
		all = append(all, pc)
	}
	if err := r.run(); err != nil {
		return nil, err
	}
	for _, c := range all {
		if c.matched == 0 {
			return nil, fmt.Errorf("%s==%s is not in the requirements file", c.Name, c.From)
		}
	}
	out, err := splice(data, r.edits)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{lockPath: out}, nil
}

// pipHashes returns the SHA-256 of each file of the new version, sorted and
// without repeats, as pip-compile lists them.
func pipHashes(c Change) ([]string, error) {
	files := c.ArtifactsOf("file")
	if len(files) == 0 {
		return nil, fmt.Errorf("%s %s: the change carries no file artifacts to hash", c.Name, c.To)
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range files {
		v, err := sha256Of(c, a)
		if err != nil {
			return nil, err
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}

// pyNormalize returns a project name normalised as PEP 503 does.
func pyNormalize(name string) string {
	return pySeparators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

var pySeparators = regexp.MustCompile(`[-_.]+`)

// reqLineRE splits a requirement as internal/lockfiles does: name, extras,
// the rest.
var reqLineRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)

// reqRewrite collects the edits of one requirements file.
type reqRewrite struct {
	data   []byte
	byName map[string][]*pipChange
	edits  []edit
}

// run reads the file's logical lines — physical lines joined where one ends
// in a backslash, the backslash replaced by a blank — and rewrites the pins
// of changed projects.
func (r *reqRewrite) run() error {
	if err := pipLineBreaks(r.data); err != nil {
		return err
	}
	var b strings.Builder
	first := -1 // where the logical line being joined starts
	// A byte order mark is not content: pip decodes it away, and so does
	// internal/lockfiles. It stays where it is.
	start := 0
	if bytes.HasPrefix(r.data, []byte("\xef\xbb\xbf")) {
		start = 3
	}
	for off := start; ; {
		l, ok := nextLine(r.data, off)
		if !ok {
			break
		}
		off = l.next
		content := r.data[l.start:l.end]
		if first < 0 {
			first = l.start
		}
		if bytes.HasSuffix(content, []byte(`\`)) {
			b.Write(content[:len(content)-1])
			b.WriteByte(' ')
			continue
		}
		b.Write(content)
		if err := r.logical(b.String(), first); err != nil {
			return err
		}
		b.Reset()
		first = -1
	}
	if first >= 0 {
		return r.logical(b.String(), first)
	}
	return nil
}

// pipLineBreaks refuses a file pip reads other lines in than
// internal/lockfiles: pip splits lines as Python's str.splitlines does (a
// lone carriage return, a vertical tab, a form feed, U+0085, U+2028 … end a
// line) and does not join a line that holds a comment to the next, however
// it ends. A requirement hidden from the scan that way would be hidden from
// the rewrite's check too.
func pipLineBreaks(data []byte) error {
	for i, c := range data {
		switch {
		case c == '\v' || c == '\f' || (c >= 0x1c && c <= 0x1e),
			c == '\r' && (i+1 == len(data) || data[i+1] != '\n'):
			return errors.New("the requirements file breaks lines where pip and the scan read it differently")
		}
	}
	for _, sep := range []string{"\u0085", "\u2028", "\u2029"} {
		if bytes.Contains(data, []byte(sep)) {
			return errors.New("the requirements file breaks lines where pip and the scan read it differently")
		}
	}
	for off := 0; off < len(data); {
		l, _ := nextLine(data, off)
		off = l.next
		line := data[l.start:l.end]
		if _, _, commented := stripReqComment(string(line)); commented && bytes.HasSuffix(line, []byte(`\`)) {
			return errors.New("a comment line of the requirements file ends in a backslash, which pip and the scan read differently")
		}
	}
	return nil
}

// field is a blank-separated word of a logical line: text[start:end].
type field struct{ start, end int }

// logical rewrites one logical line if it pins a changed project. Most lines
// do not: their project name is read without taking the line apart.
func (r *reqRewrite) logical(text string, first int) error {
	start, end, commented := stripReqComment(text)
	line := text[start:end]
	if line == "" || line[0] == '-' {
		return nil
	}
	cs := r.byName[pyNormalize(reqName(line))]
	if len(cs) == 0 {
		return nil
	}
	// The words of the line: options (a --hash option's value may be the next
	// word) and the requirement's own.
	fields := fieldsOf(line, start)
	isHash := make([]bool, len(fields))
	var spec []field
	hashes, apart, unreadable := 0, false, false
	for i := 0; i < len(fields); i++ {
		f := text[fields[i].start:fields[i].end]
		switch {
		case strings.HasPrefix(f, "--hash"):
			isHash[i] = true
			hashes++
			unreadable = unreadable || !readableHash(strings.TrimPrefix(f, "--hash="))
			if !strings.HasPrefix(f, "--hash=") || f == "--hash=" {
				apart = true
				if strings.TrimPrefix(strings.TrimPrefix(f, "--hash"), "=") == "" && i+1 < len(fields) {
					i++
					isHash[i] = true
				}
			}
		case strings.HasPrefix(f, "--"):
		default:
			spec = append(spec, fields[i])
		}
	}
	c, vAt, err := pinOf(text, spec, cs)
	if err != nil || c == nil {
		return err
	}
	c.matched++
	if apart || unreadable {
		return fmt.Errorf("%s==%s: a --hash option in a form the updater does not rewrite", c.Name, c.From)
	}
	parts, err := r.parts(first)
	if err != nil {
		return err
	}
	if len(parts.lines) > 1 && commented {
		return fmt.Errorf("%s==%s: a comment inside a requirement continued over several lines", c.Name, c.From)
	}
	vs, ok := parts.fileOffset(vAt)
	if !ok || !bytes.Equal(r.data[vs:min(len(r.data), vs+len(c.From))], []byte(c.From)) {
		return fmt.Errorf("%s==%s: the version is not where the requirement says", c.Name, c.From)
	}
	r.edits = append(r.edits, edit{vs, vs + len(c.From), c.To})
	if hashes == 0 {
		return nil
	}
	if c.hashesErr != nil {
		return c.hashesErr
	}
	return r.rehash(c, parts, fields, isHash)
}

// pinOf finds the change a requirement pins, and where its version is in the
// logical line. The requirement is read as internal/lockfiles reads it: its
// words but the options, joined; the markers after ";" cut; then name,
// extras and "==version". A changed project pinned at another version is
// left alone (a pin for other environment markers); in any other form — a
// range, "===", a direct reference — it is not rewritten.
func pinOf(text string, spec []field, cs []*pipChange) (*pipChange, int, error) {
	var b strings.Builder
	starts := make([]int, len(spec))
	for i, f := range spec {
		if i > 0 {
			b.WriteByte(' ')
		}
		starts[i] = b.Len()
		b.WriteString(text[f.start:f.end])
	}
	joined := b.String()
	if i := strings.IndexByte(joined, ';'); i >= 0 {
		joined = strings.TrimSpace(joined[:i])
	}
	m := reqLineRE.FindStringSubmatchIndex(joined)
	if m == nil {
		return nil, 0, nil
	}
	name := joined[m[2]:m[3]]
	rest := joined[m[6]:m[7]]
	restAt := m[6] + len(rest) - len(strings.TrimLeftFunc(rest, unicode.IsSpace))
	rest = strings.TrimSpace(rest)
	switch {
	case strings.HasPrefix(rest, "@"):
		return nil, 0, fmt.Errorf("%s: a direct reference, not a pin the updater rewrites", name)
	case strings.HasPrefix(rest, "==="):
		return nil, 0, fmt.Errorf("%s: an arbitrary-equality (===) pin, not one the updater rewrites", name)
	case !strings.HasPrefix(rest, "=="):
		return nil, 0, fmt.Errorf("%s: not pinned to an exact version", name)
	}
	after := rest[2:]
	version := strings.TrimSpace(after)
	if version == "" || strings.ContainsAny(version, ",<>!~*= ") {
		return nil, 0, fmt.Errorf("%s: not pinned to an exact version", name)
	}
	var c *pipChange
	for _, cand := range cs {
		if cand.From == version {
			c = cand
		}
	}
	if c == nil {
		return nil, 0, nil
	}
	at := restAt + 2 + len(after) - len(strings.TrimLeftFunc(after, unicode.IsSpace))
	// The version lies within one word: map it back to the logical line.
	for i := len(spec) - 1; i >= 0; i-- {
		if starts[i] <= at {
			return c, spec[i].start + at - starts[i], nil
		}
	}
	return nil, 0, errors.New("internal error: a version outside the requirement")
}

// rehash replaces the hash options of a requirement by the new version's.
func (r *reqRewrite) rehash(c *pipChange, rp *reqParts, fields []field, isHash []bool) error {
	parts := rp.lines
	opts := make([]string, len(c.hashes))
	for i, h := range c.hashes {
		opts[i] = "--hash=sha256:" + h
	}
	// The file offsets of each word and the physical line it is on.
	type placed struct {
		start, end, part int
	}
	ps := make([]placed, len(fields))
	for i, f := range fields {
		s, ok1 := rp.fileOffset(f.start)
		e, ok2 := rp.fileOffset(f.end - 1)
		if !ok1 || !ok2 {
			return errors.New("internal error: a word outside the requirement")
		}
		ps[i] = placed{s, e + 1, rp.index(f.start)}
	}
	var hs []placed
	for i, p := range ps {
		if isHash[i] {
			hs = append(hs, p)
		}
	}

	if len(parts) == 1 {
		// All on one line: the hash options must stand together.
		firstHash := -1
		for i := range ps {
			if isHash[i] {
				if firstHash >= 0 && !isHash[i-1] {
					return fmt.Errorf("%s==%s: hash options interleaved with other words", c.Name, c.From)
				}
				if firstHash < 0 {
					firstHash = i
				}
			}
		}
		sep := " "
		if len(hs) >= 2 {
			sep = string(r.data[hs[0].end:hs[1].start])
		}
		r.edits = append(r.edits, edit{hs[0].start, hs[len(hs)-1].end, strings.Join(opts, sep)})
		return nil
	}

	// One hash option per continuation line, the requirement on the first.
	perPart := make([]int, len(parts))
	for i, p := range ps {
		perPart[p.part]++
		if isHash[i] != (p.part > 0) {
			return fmt.Errorf("%s==%s: hash options laid out in a way the updater does not rewrite", c.Name, c.From)
		}
	}
	for k := 1; k < len(parts); k++ {
		if perPart[k] != 1 {
			return fmt.Errorf("%s==%s: hash options laid out in a way the updater does not rewrite", c.Name, c.From)
		}
	}
	last := len(parts) - 1
	for k := 1; k <= last; k++ {
		h, p := hs[k-1], parts[k]
		before := r.data[p.start:h.start]
		after := bytes.TrimSuffix(r.data[h.end:p.end], []byte(`\`))
		if len(bytes.Trim(before, " \t")) != 0 || len(bytes.Trim(after, " \t")) != 0 {
			return fmt.Errorf("%s==%s: hash options laid out in a way the updater does not rewrite", c.Name, c.From)
		}
	}
	indent := string(r.data[parts[1].start:hs[0].start])
	cont, eol := ` \`, parts[0].eol(r.data)
	if last > 1 {
		cont, eol = string(r.data[hs[0].end:parts[1].end]), parts[1].eol(r.data)
	}
	tail := string(r.data[hs[last-1].end:parts[last].end])
	var b strings.Builder
	for j, o := range opts {
		b.WriteString(indent)
		b.WriteString(o)
		if j < len(opts)-1 {
			b.WriteString(cont)
			b.WriteString(eol)
		} else {
			b.WriteString(tail)
		}
	}
	r.edits = append(r.edits, edit{parts[1].start, parts[last].end, b.String()})
	return nil
}

// reqParts are the physical lines of a logical line, with where each one's
// content starts in the logical line's text: each contributes its content,
// a continuation backslash replaced by the blank that joins it to the next.
type reqParts struct {
	lines []textLine
	at    []int
}

// parts returns the physical lines of the logical line starting at first.
func (r *reqRewrite) parts(first int) (*reqParts, error) {
	p := &reqParts{}
	pos := 0
	for off := first; ; {
		l, ok := nextLine(r.data, off)
		if !ok {
			return p, nil
		}
		p.lines = append(p.lines, l)
		p.at = append(p.at, pos)
		pos += l.end - l.start
		if len(p.lines) > maxRequirementLines {
			return nil, fmt.Errorf("a requirement continued over more than %d lines", maxRequirementLines)
		}
		if !bytes.HasSuffix(r.data[l.start:l.end], []byte(`\`)) {
			return p, nil
		}
		off = l.next
	}
}

// index returns the physical line an offset of the logical line's text is on.
func (p *reqParts) index(at int) int {
	return sort.Search(len(p.at), func(i int) bool { return p.at[i] > at }) - 1
}

// fileOffset maps an offset of the logical line's text to the file.
func (p *reqParts) fileOffset(at int) (int, bool) {
	i := p.index(at)
	if i < 0 || at-p.at[i] >= p.lines[i].end-p.lines[i].start {
		return 0, false
	}
	return p.lines[i].start + at - p.at[i], true
}

// stripReqComment cuts a comment — "#" at the start or after a blank, as
// internal/lockfiles and pip see one — and the blanks around what is left,
// returning its bounds in s and whether a comment was cut.
func stripReqComment(s string) (start, end int, commented bool) {
	cut := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			cut, commented = i, true
			break
		}
	}
	t := s[:cut]
	l := strings.TrimLeftFunc(t, unicode.IsSpace)
	start = len(t) - len(l)
	return start, start + len(strings.TrimRightFunc(l, unicode.IsSpace)), commented
}

// fieldsOf splits s as strings.Fields does, returning the words' bounds
// shifted by base.
func fieldsOf(s string, base int) []field {
	var out []field
	start := -1
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		if unicode.IsSpace(r) {
			if start >= 0 {
				out = append(out, field{base + start, base + i})
				start = -1
			}
		} else if start < 0 {
			start = i
		}
		i += w
	}
	if start >= 0 {
		out = append(out, field{base + start, base + len(s)})
	}
	return out
}

// reqName returns the project name a requirement line starts with, as
// internal/lockfiles reads it: the first word that is not an option (a
// --hash option's value may be the next word), up to the first byte a name
// cannot hold. It reads no further into the line.
func reqName(line string) string {
	skipNext := false
	for i := 0; i < len(line); {
		r, w := utf8.DecodeRuneInString(line[i:])
		if unicode.IsSpace(r) {
			i += w
			continue
		}
		j := i
		for j < len(line) {
			r, w := utf8.DecodeRuneInString(line[j:])
			if unicode.IsSpace(r) {
				break
			}
			j += w
		}
		f := line[i:j]
		i = j
		switch {
		case skipNext:
			skipNext = false
		case strings.HasPrefix(f, "--hash"):
			skipNext = strings.TrimPrefix(strings.TrimPrefix(f, "--hash"), "=") == ""
		case strings.HasPrefix(f, "--"):
		default:
			n := 0
			for n < len(f) && (isAlnum(f[n]) || (n > 0 && strings.IndexByte("._-", f[n]) >= 0)) {
				n++
			}
			return f[:n]
		}
	}
	return ""
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
