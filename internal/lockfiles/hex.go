package lockfiles

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// mixLock reads Mix's mix.lock: an Elixir map from each dependency's
// application name to a tuple saying where it comes from.
//
//	"jason": {:hex, :jason, "1.4.4", "<inner>", [:mix], [deps], "hexpm", "<outer>"},
//	"dep":   {:git, "https://github.com/o/r.git", "<commit>", [tag: "v1"]},
//
// Older Hex wrote shorter :hex tuples — without the outer checksum, without
// the repository, at first without the managers and requirements. The outer
// checksum is the SHA-256 of the release tarball; the inner one hashes what
// the tarball holds (its VERSION, metadata.config and contents.tar.gz).
//
// Mix evaluates mix.lock as Elixir code. This parser reads only literals —
// maps, tuples, lists, keywords, atoms, strings, numbers — and refuses a file
// with anything else (a call, a variable, string interpolation): what such a
// file pins is decided when it runs, not when it is read. mix.lock does not
// record which dependencies are development-only.
type mixLock struct{}

func (mixLock) Type() string            { return "hex" }
func (mixLock) Format() string          { return "mix.lock" }
func (mixLock) Detect(path string) bool { return baseName(path) == "mix.lock" }

// hexRepositories maps the Hex repository names a lock file records to their
// URLs. Organisations of hex.pm are "hexpm:<organisation>".
var hexRepositories = map[string]string{"hexpm": "https://repo.hex.pm"}

func (mixLock) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("mix.lock is not valid UTF-8")
	}
	if len(data) > maxTreeInput {
		return nil, errTreeInputTooLarge
	}
	p := &exParser{s: string(data), line: 1}
	p.skipSpace()
	if p.eof() {
		return &Result{}, nil // an empty lock file: no dependencies
	}
	if !strings.HasPrefix(p.s[p.pos:], "%{") {
		if err := p.skip(); err != nil {
			return nil, fmt.Errorf("mix.lock line %d: %w", p.line, err)
		}
		return nil, errors.New("not a mix.lock: not an Elixir map")
	}
	p.pos += 2
	res := &Result{}
	seen := map[string]bool{}
	err := p.mapEntries(func(key *exTerm) error {
		// Mix looks a dependency up by its atom (lock[app]): an entry keyed
		// by anything else pins nothing.
		if key == nil || key.kind != exAtom {
			res.warnf("line %d: an entry not keyed by an atom, which Mix never looks up", p.line)
			return p.skip()
		}
		if seen[key.text] {
			// Elixir's map literal keeps the last value of a repeated key, but
			// no Mix writes one: refuse the file rather than pick.
			return fmt.Errorf("the key %q is repeated", key.text)
		}
		seen[key.text] = true
		p.skipSpace()
		if p.peek() != '{' {
			res.warnf("line %d: %s: not a lock entry this parser understands", key.line, key.text)
			return p.skip()
		}
		p.pos++
		items, err := p.tupleScalars(8)
		if err != nil {
			return err
		}
		if d, ok := mixDependency(res, key.text, items, key.line); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("mix.lock line %d: %w", p.line, err)
	}
	p.skipSpace()
	if !p.eof() {
		return nil, fmt.Errorf("mix.lock line %d: data after the map", p.line)
	}
	return res, nil
}

// mixDependency reads one lock entry's tuple: its first elements, scalars
// as read and anything else as an exList placeholder.
func mixDependency(res *Result, key string, items []*exTerm, line int) (Dependency, bool) {
	if len(items) == 0 || items[0].kind != exAtom {
		res.warnf("line %d: %s: not a lock entry this parser understands", line, key)
		return Dependency{}, false
	}
	switch items[0].text {
	case "hex":
		return mixHex(res, key, items, line)
	case "git":
		return mixGit(res, key, items, line)
	}
	res.warnf("line %d: %s: from a %s source, which this parser does not read", line, key, items[0].text)
	return Dependency{}, false
}

// mixHex reads {:hex, :name, "version", inner, managers, deps, repo, outer}.
func mixHex(res *Result, key string, items []*exTerm, line int) (Dependency, bool) {
	str := func(i int) string {
		if i < len(items) && items[i].kind == exString {
			return items[i].text
		}
		return ""
	}
	name := key
	if len(items) > 1 && (items[1].kind == exAtom || items[1].kind == exString) {
		name = items[1].text // the package's name in the repository, as Hex's to_string reads it
	}
	d := Dependency{Name: name, Version: str(2), Line: line}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: %s: no usable package name or version", line, key)
		return Dependency{}, false
	}
	if dg, ok := hexDigest("sha256", str(7), ""); ok {
		d.Digests = append(d.Digests, dg)
	}
	if dg, ok := hexDigest("sha256", str(3), "hex-inner"); ok {
		d.Digests = append(d.Digests, dg)
	}
	repo := str(6)
	if repo == "" && len(items) <= 6 {
		repo = "hexpm" // tuples older than the repository field are hex.pm's
	}
	switch org, isOrg := strings.CutPrefix(repo, "hexpm:"); {
	case hexRepositories[repo] != "":
		d.Registry = hexRepositories[repo]
	case isOrg && validPackageName(org):
		d.Registry = "https://repo.hex.pm/repos/" + org
	default:
		res.warnf("line %d: %s: from the Hex repository %q, whose URL the lock file does not record", line, key, repo)
	}
	return d, true
}

// mixGit reads {:git, "url", "commit", opts}.
func mixGit(res *Result, key string, items []*exTerm, line int) (Dependency, bool) {
	if len(items) < 3 || items[1].kind != exString || items[2].kind != exString {
		res.warnf("line %d: %s: a git entry without a URL or revision", line, key)
		return Dependency{}, false
	}
	gs := parseGitURL(items[1].text)
	d := Dependency{Name: key, Source: SourceGit, Registry: gs.repo, Line: line, Version: items[2].text}
	if rev := items[2].text; isCommitID(rev) {
		d.Revision = strings.ToLower(rev)
		d.Version = d.Revision
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: %s: a git entry without a usable revision", line, key)
		return Dependency{}, false
	}
	if d.Revision == "" {
		d.UnverifiedReason = "mix.lock records a ref for this Git dependency that is not a full commit ID"
	}
	return d, true
}

// exKind is the kind of an Elixir literal.
type exKind int

const (
	exAtom exKind = iota
	exString
	exNumber
	exList // a list, tuple or map: its content is skipped, not kept
)

// exTerm is a scalar Elixir literal — an atom (true, false and nil are
// atoms), a string, a number — or a placeholder for a collection.
type exTerm struct {
	kind exKind
	text string // an atom's name, a string's value, a number's text
	line int
}

// maxExDepth bounds the nesting of collections.
const maxExDepth = 64

// exParser reads Elixir literals. It keeps only the scalars it is asked for;
// collections are skipped without being built, so memory does not grow with
// what a lock entry's requirement lists hold.
type exParser struct {
	s     string
	pos   int
	line  int
	depth int
}

var errExCode = errors.New("Elixir code, not a literal: the file holds something that runs when Mix reads it")

func (p *exParser) eof() bool { return p.pos >= len(p.s) }

func (p *exParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.pos]
}

// skipSpace skips blanks, line breaks and comments.
func (p *exParser) skipSpace() {
	for !p.eof() {
		switch c := p.s[p.pos]; c {
		case '\n':
			p.line++
			p.pos++
		case ' ', '\t', '\r':
			p.pos++
		case '#':
			for !p.eof() && p.s[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

// enter bounds nesting.
func (p *exParser) enter() error {
	p.depth++
	if p.depth > maxExDepth {
		return errors.New("nested too deeply")
	}
	return nil
}

// skip consumes one literal of any kind without keeping it.
func (p *exParser) skip() error {
	p.skipSpace()
	switch c := p.peek(); {
	case c == '%':
		if p.pos+1 < len(p.s) && p.s[p.pos+1] == '{' {
			p.pos += 2
			return p.mapEntries(func(*exTerm) error { return p.skip() })
		}
		return errExCode // a struct or a sigil
	case c == '{' || c == '[':
		p.pos++
		return p.seq(map[byte]byte{'{': '}', '[': ']'}[c], c == '[', func() error { return p.skip() })
	}
	_, err := p.scalar(false)
	return err
}

// tupleScalars reads a tuple's elements after its "{": the first max are
// returned (a collection as an exList placeholder), the rest skipped.
func (p *exParser) tupleScalars(max int) ([]*exTerm, error) {
	var items []*exTerm
	err := p.seq('}', false, func() error {
		p.skipSpace()
		line := p.line
		switch c := p.peek(); {
		case c == '{' || c == '[' || c == '%':
			if err := p.skip(); err != nil {
				return err
			}
			if len(items) < max {
				items = append(items, &exTerm{kind: exList, line: line})
			}
			return nil
		}
		t, err := p.scalar(len(items) < max)
		if err == nil && len(items) < max {
			items = append(items, t)
		}
		return err
	})
	return items, err
}

// seq reads the elements of a tuple or list up to close, calling elem for
// each. A list may hold keywords ("tag: \"v1\""), whose values elem reads.
func (p *exParser) seq(close byte, list bool, elem func() error) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer func() { p.depth-- }()
	for {
		p.skipSpace()
		if p.peek() == close {
			p.pos++
			return nil
		}
		if list {
			if _, err := p.keyword(); err != nil {
				return err
			}
		}
		if err := elem(); err != nil {
			return err
		}
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case close:
		default:
			return fmt.Errorf("expected ',' or %q", string(close))
		}
	}
}

// mapEntries reads a map's entries after its "%{" — `key => value`, or
// keyword style `"key": value` / `key: value` — calling fn with each key
// (nil when it is not a scalar) to read the value.
func (p *exParser) mapEntries(fn func(key *exTerm) error) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer func() { p.depth-- }()
	for {
		p.skipSpace()
		if p.peek() == '}' {
			p.pos++
			return nil
		}
		k, err := p.keyword()
		if err != nil {
			return err
		}
		if k == nil {
			switch c := p.peek(); {
			case c == '{' || c == '[' || c == '%':
				err = p.skip()
			default:
				k, err = p.scalar(true)
			}
			if err != nil {
				return err
			}
			p.skipSpace()
			if !strings.HasPrefix(p.s[p.pos:], "=>") {
				return errors.New("expected '=>' in a map")
			}
			p.pos += 2
		}
		if err := fn(k); err != nil {
			return err
		}
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
		default:
			return errors.New("expected ',' or '}' in a map")
		}
	}
}

// keyword reads a keyword key — `name:` or `"name":` followed by a blank —
// as an atom; it returns nil (and consumes nothing) for anything else.
func (p *exParser) keyword() (*exTerm, error) {
	start, line := p.pos, p.line
	var name string
	switch c := p.peek(); {
	case c == '"':
		p.pos++
		s, err := p.quoted(true)
		if err != nil {
			return nil, err
		}
		name = s
	case isExIdentStart(c):
		name = p.ident()
	default:
		return nil, nil
	}
	if p.peek() != ':' || p.pos+1 >= len(p.s) || !isExBlank(p.s[p.pos+1]) {
		p.pos, p.line = start, line
		return nil, nil
	}
	p.pos++
	return &exTerm{kind: exAtom, text: name, line: line}, nil
}

// scalar reads an atom, a string, a number, true, false or nil. With keep
// false it returns nil and allocates nothing.
func (p *exParser) scalar(keep bool) (*exTerm, error) {
	p.skipSpace()
	if p.eof() {
		return nil, errors.New("unexpected end of the file")
	}
	line := p.line
	var kind exKind
	var text string
	switch c := p.peek(); {
	case c == '"':
		p.pos++
		s, err := p.quoted(keep)
		if err != nil {
			return nil, err
		}
		kind, text = exString, s
	case c == ':':
		p.pos++
		if p.peek() == '"' {
			p.pos++
			s, err := p.quoted(keep)
			if err != nil {
				return nil, err
			}
			kind, text = exAtom, s
			break
		}
		if !isExIdentStart(p.peek()) {
			return nil, errExCode // an operator atom (:+) or something else
		}
		start := p.pos
		p.ident()
		if c := p.peek(); c == '?' || c == '!' {
			p.pos++
		}
		kind, text = exAtom, p.s[start:p.pos]
	case c >= '0' && c <= '9' || c == '-':
		n := exNumberLen(p.s[p.pos:])
		if n == 0 {
			return nil, errExCode
		}
		m := p.s[p.pos : p.pos+n]
		p.pos += n
		if p.pos < len(p.s) && (isExIdentStart(p.s[p.pos]) || p.s[p.pos] >= '0' && p.s[p.pos] <= '9' || p.s[p.pos] == '.') {
			return nil, errExCode // "1e5", "1.x": not an Elixir number
		}
		kind, text = exNumber, m
	case isExIdentStart(c):
		start := p.pos
		switch word := p.ident(); word {
		case "true", "false", "nil":
			kind, text = exAtom, word
		default:
			p.pos = start
			return nil, errExCode // a variable, a call, an alias
		}
	default:
		return nil, errExCode
	}
	if !keep {
		return nil, nil
	}
	return &exTerm{kind: kind, text: text, line: line}, nil
}

// ident reads an identifier: letters, digits, "_", "@" after the first.
func (p *exParser) ident() string {
	start := p.pos
	for !p.eof() {
		c := p.s[p.pos]
		if !(isExIdentStart(c) || c >= '0' && c <= '9' || c == '@') {
			break
		}
		p.pos++
	}
	return p.s[start:p.pos]
}

// quoted reads a double-quoted string after its opening quote; with keep
// false it checks the string and returns "". Interpolation ("#{…}") is code,
// and refused.
func (p *exParser) quoted(keep bool) (string, error) {
	var b strings.Builder
	n := 0
	for {
		if p.eof() {
			return "", errors.New("unterminated string")
		}
		c := p.s[p.pos]
		p.pos++
		switch c {
		case '"':
			return b.String(), nil
		case '\n':
			p.line++
		case '#':
			if p.peek() == '{' {
				return "", errExCode
			}
		case '\\':
			if p.eof() {
				return "", errors.New("unterminated string")
			}
			e := p.s[p.pos]
			p.pos++
			switch e {
			case 'n':
				c = '\n'
			case 't':
				c = '\t'
			case 'r':
				c = '\r'
			case '"', '\\', '#':
				c = e
			default:
				// Unicode and other escapes do not occur in lock files.
				return "", errors.New("an escape this parser does not read")
			}
		}
		n++
		if n > 64<<10 {
			return "", errors.New("string too long")
		}
		if keep {
			b.WriteByte(c)
		}
	}
}

// exNumberLen returns the length of the Elixir number at the start of s, or
// 0: an integer (decimal with "_" between digits, 0x, 0o, 0b) or a float,
// which needs digits on both sides of the point and takes an exponent only
// after them. A minus sign may lead.
func exNumberLen(s string) int {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	// run reads a digit, then digits each optionally after one "_".
	run := func(i int, digit func(byte) bool) int {
		if i >= len(s) || !digit(s[i]) {
			return -1
		}
		for i++; i < len(s); {
			switch {
			case digit(s[i]):
				i++
			case s[i] == '_' && i+1 < len(s) && digit(s[i+1]):
				i += 2
			default:
				return i
			}
		}
		return i
	}
	dec := func(c byte) bool { return c >= '0' && c <= '9' }
	if i+1 < len(s) && s[i] == '0' {
		var digit func(byte) bool
		switch s[i+1] {
		case 'x':
			digit = func(c byte) bool { return dec(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
		case 'o':
			digit = func(c byte) bool { return c >= '0' && c <= '7' }
		case 'b':
			digit = func(c byte) bool { return c == '0' || c == '1' }
		}
		if digit != nil {
			if j := run(i+2, digit); j > 0 {
				return j
			}
			return 0
		}
	}
	j := run(i, dec)
	if j < 0 {
		return 0
	}
	if j+1 < len(s) && s[j] == '.' && dec(s[j+1]) {
		j = run(j+1, dec)
		if j < len(s) && (s[j] == 'e' || s[j] == 'E') {
			k := j + 1
			if k < len(s) && (s[k] == '+' || s[k] == '-') {
				k++
			}
			if e := run(k, dec); e > 0 {
				j = e
			}
		}
	}
	return j
}

func isExIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isExBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
