package lockfiles

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file is a TOML reader for the lock files written in TOML — Cargo.lock,
// poetry.lock, uv.lock, pdm.lock — which records the line every table and
// value starts on. It implements TOML 1.0 (and the multi-line inline tables of
// TOML 1.1), strictly enough to refuse a document that redefines a key or a
// table, with bounds on nesting. Date-times are kept as text; nothing here
// needs their value.

// tomlKind is the type of a TOML value.
type tomlKind int

const (
	tkString tomlKind = iota
	tkInteger
	tkFloat
	tkBool
	tkDatetime
	tkArray
	tkTable
)

// tomlValue is one TOML value.
type tomlValue struct {
	kind tomlKind
	// str is a string's value, or the text of a number or date-time.
	str  string
	b    bool
	arr  []*tomlValue
	tab  *tomlTable
	line int
	// aot marks an array of tables built by [[headers]].
	aot bool
}

// tomlTable is a table, keeping its keys in document order.
type tomlTable struct {
	keys []string
	vals map[string]*tomlValue
	line int
	// defined: the table had its own [header]; implicit tables are created by
	// a longer header or a dotted key. inline: an inline table, closed to
	// additions. dotted: created by a dotted key, which a [header] may not
	// define again.
	defined, inline, dotted bool
}

func newTOMLTable(line int) *tomlTable {
	return &tomlTable{vals: map[string]*tomlValue{}, line: line}
}

// get returns the value of key, or nil.
func (t *tomlTable) get(key string) *tomlValue {
	if t == nil {
		return nil
	}
	return t.vals[key]
}

func (t *tomlTable) set(key string, v *tomlValue) {
	if _, ok := t.vals[key]; !ok {
		t.keys = append(t.keys, key)
	}
	t.vals[key] = v
}

// str returns the string value of key, or "".
func (t *tomlTable) str(key string) string {
	if v := t.get(key); v != nil && v.kind == tkString {
		return v.str
	}
	return ""
}

// table returns the table value of key, or nil.
func (t *tomlTable) table(key string) *tomlTable {
	if v := t.get(key); v != nil && v.kind == tkTable {
		return v.tab
	}
	return nil
}

// tables returns the tables of an array (of tables, or of inline tables) at
// key.
func (t *tomlTable) tables(key string) []*tomlTable {
	v := t.get(key)
	if v == nil || v.kind != tkArray {
		return nil
	}
	var out []*tomlTable
	for _, e := range v.arr {
		if e.kind == tkTable {
			out = append(out, e.tab)
		}
	}
	return out
}

// strings returns the string elements of an array at key (a lone string as a
// one-element list).
func (t *tomlTable) strings(key string) []string {
	v := t.get(key)
	if v == nil {
		return nil
	}
	if v.kind == tkString {
		return []string{v.str}
	}
	if v.kind != tkArray {
		return nil
	}
	var out []string
	for _, e := range v.arr {
		if e.kind == tkString {
			out = append(out, e.str)
		}
	}
	return out
}

// Limits of the reader. Every table and value counts against a budget of
// one per four bytes of input (real lock files have one per ten bytes or
// more), and tables — the costly nodes — against one per thirty-two.
const (
	maxTOMLDepth = 64
)

type tomlParser struct {
	data   []byte
	pos    int
	line   int
	root   *tomlTable
	cur    *tomlTable
	depth  int
	count  int // tables and values made
	tables int // tables made
}

// parseTOML parses a TOML document.
func parseTOML(data []byte) (*tomlTable, error) {
	if len(data) > maxTreeInput {
		return nil, errTreeInputTooLarge
	}
	if !utf8.Valid(data) {
		return nil, errors.New("TOML document is not valid UTF-8")
	}
	p := &tomlParser{data: data, line: 1, root: newTOMLTable(1)}
	p.root.defined = true
	p.cur = p.root
	if err := p.document(); err != nil {
		return nil, fmt.Errorf("TOML line %d: %w", p.line, err)
	}
	return p.root, nil
}

func (p *tomlParser) eof() bool { return p.pos >= len(p.data) }

func (p *tomlParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.data[p.pos]
}

func (p *tomlParser) peekAt(n int) byte {
	if p.pos+n >= len(p.data) {
		return 0
	}
	return p.data[p.pos+n]
}

// skipSpace skips blanks (not line breaks).
func (p *tomlParser) skipSpace() {
	for !p.eof() && (p.data[p.pos] == ' ' || p.data[p.pos] == '\t') {
		p.pos++
	}
}

// skipComment skips a comment up to (not including) the line break.
func (p *tomlParser) skipComment() error {
	if p.peek() != '#' {
		return nil
	}
	for !p.eof() && p.data[p.pos] != '\n' {
		c := p.data[p.pos]
		if (c < 0x20 && c != '\t' && c != '\r') || c == 0x7f {
			return errors.New("control character in a comment")
		}
		p.pos++
	}
	return nil
}

// newline consumes a line break ("\n" or "\r\n"); false if there is none.
func (p *tomlParser) newline() bool {
	if p.peek() == '\n' {
		p.pos++
		p.line++
		return true
	}
	if p.peek() == '\r' && p.peekAt(1) == '\n' {
		p.pos += 2
		p.line++
		return true
	}
	return false
}

// skipBlank skips blanks, comments and line breaks.
func (p *tomlParser) skipBlank() error {
	for {
		p.skipSpace()
		if err := p.skipComment(); err != nil {
			return err
		}
		if !p.newline() {
			return nil
		}
	}
}

// endOfLine requires the rest of the line to be blank or a comment.
func (p *tomlParser) endOfLine() error {
	p.skipSpace()
	if err := p.skipComment(); err != nil {
		return err
	}
	if p.eof() || p.newline() {
		return nil
	}
	return errors.New("unexpected text after a value")
}

func (p *tomlParser) document() error {
	for {
		if err := p.skipBlank(); err != nil {
			return err
		}
		if p.eof() {
			return nil
		}
		var err error
		if p.peek() == '[' {
			err = p.header()
		} else {
			err = p.keyValue(p.cur)
			if err == nil {
				err = p.endOfLine()
			}
		}
		if err != nil {
			return err
		}
	}
}

// header reads "[table]" or "[[array.of.tables]]".
func (p *tomlParser) header() error {
	line := p.line
	p.pos++ // [
	array := false
	if p.peek() == '[' {
		array = true
		p.pos++
	}
	p.skipSpace()
	keys, err := p.key()
	if err != nil {
		return err
	}
	p.skipSpace()
	if p.peek() != ']' {
		return errors.New("table header is not closed")
	}
	p.pos++
	if array {
		if p.peek() != ']' {
			return errors.New("array-of-tables header is not closed")
		}
		p.pos++
	}
	if err := p.endOfLine(); err != nil {
		return err
	}

	// Walk to the parent of the last key, creating implicit tables; an
	// array of tables on the way is entered at its last element.
	t := p.root
	for _, k := range keys[:len(keys)-1] {
		v := t.get(k)
		switch {
		case v == nil:
			nt, err := p.newTable(line)
			if err != nil {
				return err
			}
			t.set(k, &tomlValue{kind: tkTable, tab: nt, line: line})
			t = nt
		case v.kind == tkTable && !v.tab.inline:
			t = v.tab
		case v.kind == tkArray && v.aot && len(v.arr) > 0:
			t = v.arr[len(v.arr)-1].tab
		default:
			return fmt.Errorf("key %q is not a table", k)
		}
	}
	last := keys[len(keys)-1]
	v := t.get(last)
	if array {
		switch {
		case v == nil:
			v = &tomlValue{kind: tkArray, aot: true, line: line}
			t.set(last, v)
		case v.kind == tkArray && v.aot:
		default:
			return fmt.Errorf("key %q is not an array of tables", last)
		}
		nt, err := p.newTable(line)
		if err != nil {
			return err
		}
		nt.defined = true
		v.arr = append(v.arr, &tomlValue{kind: tkTable, tab: nt, line: line})
		p.cur = nt
		return nil
	}
	switch {
	case v == nil:
		nt, err := p.newTable(line)
		if err != nil {
			return err
		}
		nt.defined = true
		t.set(last, &tomlValue{kind: tkTable, tab: nt, line: line})
		p.cur = nt
	case v.kind == tkTable && !v.tab.defined && !v.tab.inline && !v.tab.dotted:
		v.tab.defined = true
		v.tab.line = line
		p.cur = v.tab
	default:
		return fmt.Errorf("table %q is defined twice", last)
	}
	return nil
}

// counted bounds the number of keys and values in a document.
func (p *tomlParser) counted() error {
	p.count++
	if p.count > len(p.data)/4+4096 {
		return errors.New("too many values for the size of the document")
	}
	return nil
}

// newTable makes a table, counted against the budgets.
func (p *tomlParser) newTable(line int) (*tomlTable, error) {
	p.tables++
	if p.tables > len(p.data)/32+1024 {
		return nil, errors.New("too many tables for the size of the document")
	}
	if err := p.counted(); err != nil {
		return nil, err
	}
	return newTOMLTable(line), nil
}

// key reads a dotted key.
func (p *tomlParser) key() ([]string, error) {
	var keys []string
	for {
		p.skipSpace()
		k, err := p.simpleKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
		if len(keys) > maxTOMLDepth {
			return nil, errors.New("key has too many parts")
		}
		p.skipSpace()
		if p.peek() != '.' {
			return keys, nil
		}
		p.pos++
	}
}

func (p *tomlParser) simpleKey() (string, error) {
	switch p.peek() {
	case '"':
		if p.peekAt(1) == '"' && p.peekAt(2) == '"' {
			return "", errors.New("a multi-line string cannot be a key")
		}
		return p.basicString()
	case '\'':
		if p.peekAt(1) == '\'' && p.peekAt(2) == '\'' {
			return "", errors.New("a multi-line string cannot be a key")
		}
		return p.literalString()
	}
	start := p.pos
	for !p.eof() {
		c := p.data[p.pos]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			p.pos++
			continue
		}
		break
	}
	if p.pos == start {
		return "", errors.New("expected a key")
	}
	return string(p.data[start:p.pos]), nil
}

// keyValue reads "key = value" into t.
func (p *tomlParser) keyValue(t *tomlTable) error {
	line := p.line
	keys, err := p.key()
	if err != nil {
		return err
	}
	p.skipSpace()
	if p.peek() != '=' {
		return errors.New("expected '=' after a key")
	}
	p.pos++
	p.skipSpace()
	v, err := p.value()
	if err != nil {
		return err
	}
	v.line = line
	for _, k := range keys[:len(keys)-1] {
		cur := t.get(k)
		switch {
		case cur == nil:
			nt, err := p.newTable(line)
			if err != nil {
				return err
			}
			nt.dotted = true
			t.set(k, &tomlValue{kind: tkTable, tab: nt, line: line})
			t = nt
		case cur.kind == tkTable && !cur.tab.inline && (cur.tab.dotted || !cur.tab.defined):
			t = cur.tab
		default:
			return fmt.Errorf("key %q cannot be extended", k)
		}
	}
	last := keys[len(keys)-1]
	if t.get(last) != nil {
		return fmt.Errorf("key %q is defined twice", last)
	}
	t.set(last, v)
	return p.counted()
}

// value reads any value.
func (p *tomlParser) value() (*tomlValue, error) {
	line := p.line
	switch c := p.peek(); {
	case c == '"':
		var s string
		var err error
		if p.peekAt(1) == '"' && p.peekAt(2) == '"' {
			s, err = p.multiBasicString()
		} else {
			s, err = p.basicString()
		}
		return &tomlValue{kind: tkString, str: s, line: line}, err
	case c == '\'':
		var s string
		var err error
		if p.peekAt(1) == '\'' && p.peekAt(2) == '\'' {
			s, err = p.multiLiteralString()
		} else {
			s, err = p.literalString()
		}
		return &tomlValue{kind: tkString, str: s, line: line}, err
	case c == '[':
		return p.array()
	case c == '{':
		return p.inlineTable()
	case c == 0:
		return nil, errors.New("expected a value")
	}
	return p.scalar()
}

func (p *tomlParser) enter() error {
	p.depth++
	if p.depth > maxTOMLDepth {
		return errors.New("values nested too deeply")
	}
	return nil
}

func (p *tomlParser) array() (*tomlValue, error) {
	v := &tomlValue{kind: tkArray, line: p.line}
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.pos++ // [
	for {
		if err := p.skipBlank(); err != nil {
			return nil, err
		}
		if p.peek() == ']' {
			p.pos++
			break
		}
		e, err := p.value()
		if err != nil {
			return nil, err
		}
		v.arr = append(v.arr, e)
		if err := p.counted(); err != nil {
			return nil, err
		}
		if err := p.skipBlank(); err != nil {
			return nil, err
		}
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			p.depth--
			return v, nil
		default:
			return nil, errors.New("expected ',' or ']' in an array")
		}
	}
	p.depth--
	return v, nil
}

// inlineTable reads "{ k = v, … }". Line breaks and a trailing comma are
// accepted (TOML 1.1).
func (p *tomlParser) inlineTable() (*tomlValue, error) {
	line := p.line
	t, err := p.newTable(line)
	if err != nil {
		return nil, err
	}
	t.defined = true
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.pos++ // {
	for {
		if err := p.skipBlank(); err != nil {
			return nil, err
		}
		if p.peek() == '}' {
			p.pos++
			break
		}
		if err := p.keyValue(t); err != nil {
			return nil, err
		}
		if err := p.skipBlank(); err != nil {
			return nil, err
		}
		if p.peek() == ',' {
			p.pos++
			continue
		}
		if p.peek() == '}' {
			p.pos++
			break
		}
		return nil, errors.New("expected ',' or '}' in an inline table")
	}
	p.depth--
	sealInline(t)
	return &tomlValue{kind: tkTable, tab: t, line: line}, nil
}

// sealInline closes an inline table, and the tables its dotted keys made, to
// later additions.
func sealInline(t *tomlTable) {
	t.inline = true
	for _, v := range t.vals {
		if v.kind == tkTable && v.tab.dotted {
			sealInline(v.tab)
		}
	}
}

// basicString reads a "string".
func (p *tomlParser) basicString() (string, error) {
	p.pos++ // "
	var b strings.Builder
	for {
		if p.eof() {
			return "", errors.New("string is not closed")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return b.String(), nil
		case c == '\\':
			if err := p.escape(&b); err != nil {
				return "", err
			}
		case c == '\n' || c == '\r':
			return "", errors.New("line break in a string")
		case (c < 0x20 && c != '\t') || c == 0x7f:
			return "", errors.New("control character in a string")
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

// multiBasicString reads a """string""".
func (p *tomlParser) multiBasicString() (string, error) {
	p.pos += 3
	p.newline() // a line break right after the delimiter is not part of it
	var b strings.Builder
	for {
		if p.eof() {
			return "", errors.New("multi-line string is not closed")
		}
		c := p.data[p.pos]
		switch {
		case c == '"' && p.peekAt(1) == '"' && p.peekAt(2) == '"':
			p.pos += 3
			// Up to two quotes may sit right before the closing delimiter.
			for i := 0; i < 2 && p.peek() == '"'; i++ {
				b.WriteByte('"')
				p.pos++
			}
			return b.String(), nil
		case c == '\\':
			// A backslash at the end of a line trims the line break and the
			// blanks after it.
			q := p.pos + 1
			for q < len(p.data) && (p.data[q] == ' ' || p.data[q] == '\t') {
				q++
			}
			if q < len(p.data) && (p.data[q] == '\n' || (p.data[q] == '\r' && q+1 < len(p.data) && p.data[q+1] == '\n')) {
				p.pos = q
				for {
					p.skipSpace()
					if !p.newline() {
						break
					}
				}
				continue
			}
			if err := p.escape(&b); err != nil {
				return "", err
			}
		case c == '\n':
			b.WriteByte('\n')
			p.pos++
			p.line++
		case c == '\r' && p.peekAt(1) == '\n':
			b.WriteByte('\n')
			p.pos += 2
			p.line++
		case (c < 0x20 && c != '\t') || c == 0x7f:
			return "", errors.New("control character in a string")
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

// escape reads a backslash escape into b.
func (p *tomlParser) escape(b *strings.Builder) error {
	p.pos++ // \
	if p.eof() {
		return errors.New("string is not closed")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case 'b':
		b.WriteByte('\b')
	case 't':
		b.WriteByte('\t')
	case 'n':
		b.WriteByte('\n')
	case 'f':
		b.WriteByte('\f')
	case 'r':
		b.WriteByte('\r')
	case 'e':
		b.WriteByte(0x1b)
	case '"':
		b.WriteByte('"')
	case '\\':
		b.WriteByte('\\')
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if p.pos+n > len(p.data) {
			return errors.New("short unicode escape")
		}
		r, err := strconv.ParseUint(string(p.data[p.pos:p.pos+n]), 16, 32)
		if err != nil || !utf8.ValidRune(rune(r)) {
			return errors.New("invalid unicode escape")
		}
		p.pos += n
		b.WriteRune(rune(r))
	default:
		return errors.New("invalid escape sequence")
	}
	return nil
}

// literalString reads a 'string'.
func (p *tomlParser) literalString() (string, error) {
	p.pos++ // '
	start := p.pos
	for {
		if p.eof() {
			return "", errors.New("string is not closed")
		}
		c := p.data[p.pos]
		switch {
		case c == '\'':
			s := string(p.data[start:p.pos])
			p.pos++
			return s, nil
		case c == '\n' || c == '\r':
			return "", errors.New("line break in a string")
		case (c < 0x20 && c != '\t') || c == 0x7f:
			return "", errors.New("control character in a string")
		}
		p.pos++
	}
}

// multiLiteralString reads a ”'string”'.
func (p *tomlParser) multiLiteralString() (string, error) {
	p.pos += 3
	p.newline()
	var b strings.Builder
	for {
		if p.eof() {
			return "", errors.New("multi-line string is not closed")
		}
		c := p.data[p.pos]
		switch {
		case c == '\'' && p.peekAt(1) == '\'' && p.peekAt(2) == '\'':
			p.pos += 3
			for i := 0; i < 2 && p.peek() == '\''; i++ {
				b.WriteByte('\'')
				p.pos++
			}
			return b.String(), nil
		case c == '\n':
			b.WriteByte('\n')
			p.pos++
			p.line++
		case c == '\r' && p.peekAt(1) == '\n':
			b.WriteByte('\n')
			p.pos += 2
			p.line++
		case (c < 0x20 && c != '\t') || c == 0x7f:
			return "", errors.New("control character in a string")
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

// scalar reads a boolean, number or date-time.
func (p *tomlParser) scalar() (*tomlValue, error) {
	line := p.line
	start := p.pos
	for !p.eof() {
		c := p.data[p.pos]
		if c == ' ' || c == '\t' || c == ',' || c == ']' || c == '}' || c == '#' || c == '\n' || c == '\r' {
			// A date-time may separate date and time by one space.
			if c == ' ' && isTOMLDate(string(p.data[start:p.pos])) && p.pos+3 < len(p.data) &&
				isDigit(p.data[p.pos+1]) && isDigit(p.data[p.pos+2]) && p.data[p.pos+3] == ':' {
				p.pos++
				continue
			}
			break
		}
		p.pos++
	}
	text := string(p.data[start:p.pos])
	switch {
	case text == "true" || text == "false":
		return &tomlValue{kind: tkBool, b: text == "true", line: line}, nil
	case isTOMLInteger(text):
		return &tomlValue{kind: tkInteger, str: text, line: line}, nil
	case isTOMLFloat(text):
		return &tomlValue{kind: tkFloat, str: text, line: line}, nil
	case isTOMLDatetime(text):
		return &tomlValue{kind: tkDatetime, str: text, line: line}, nil
	}
	return nil, errors.New("invalid value")
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// digitsWithUnderscores reports whether s is digits of the given base, with
// single underscores between digits.
func digitsWithUnderscores(s string, isDig func(byte) bool) bool {
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			if s[i-1] == '_' {
				return false
			}
			continue
		}
		if !isDig(s[i]) {
			return false
		}
	}
	return true
}

func isTOMLInteger(s string) bool {
	if len(s) > 2 && s[0] == '0' {
		switch s[1] {
		case 'x':
			return digitsWithUnderscores(s[2:], func(c byte) bool {
				return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			})
		case 'o':
			return digitsWithUnderscores(s[2:], func(c byte) bool { return c >= '0' && c <= '7' })
		case 'b':
			return digitsWithUnderscores(s[2:], func(c byte) bool { return c == '0' || c == '1' })
		}
	}
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	if len(s) > 1 && s[0] == '0' {
		return false // no leading zeros
	}
	return digitsWithUnderscores(s, isDigit)
}

func isTOMLFloat(s string) bool {
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	if s == "inf" || s == "nan" {
		return true
	}
	mant, exp, hasExp := strings.Cut(strings.ToLower(s), "e")
	intPart, frac, hasFrac := strings.Cut(mant, ".")
	if !hasExp && !hasFrac {
		return false
	}
	if !digitsWithUnderscores(intPart, isDigit) || (len(intPart) > 1 && intPart[0] == '0') {
		return false
	}
	if hasFrac && !digitsWithUnderscores(frac, isDigit) {
		return false
	}
	if hasExp {
		if exp != "" && (exp[0] == '+' || exp[0] == '-') {
			exp = exp[1:]
		}
		if !digitsWithUnderscores(exp, isDigit) {
			return false
		}
	}
	return true
}

// isTOMLDate reports whether s is a full date, "YYYY-MM-DD".
func isTOMLDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, c := range []byte(s) {
		if i != 4 && i != 7 && !isDigit(c) {
			return false
		}
	}
	return true
}

// isTOMLDatetime accepts the shapes of TOML's dates, times and date-times;
// the values are not checked further.
func isTOMLDatetime(s string) bool {
	if isTOMLDate(s) {
		return true
	}
	if len(s) > 10 && isTOMLDate(s[:10]) && (s[10] == 'T' || s[10] == 't' || s[10] == ' ') {
		return isTOMLTime(s[11:], true)
	}
	return isTOMLTime(s, false)
}

func isTOMLTime(s string, offsetAllowed bool) bool {
	if len(s) < 8 || s[2] != ':' || s[5] != ':' {
		return false
	}
	for _, i := range []int{0, 1, 3, 4, 6, 7} {
		if !isDigit(s[i]) {
			return false
		}
	}
	rest := s[8:]
	if strings.HasPrefix(rest, ".") {
		j := 1
		for j < len(rest) && isDigit(rest[j]) {
			j++
		}
		if j == 1 {
			return false
		}
		rest = rest[j:]
	}
	switch {
	case rest == "":
		return true
	case !offsetAllowed:
		return false
	case rest == "Z" || rest == "z":
		return true
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-') && rest[3] == ':':
		return isDigit(rest[1]) && isDigit(rest[2]) && isDigit(rest[4]) && isDigit(rest[5])
	}
	return false
}
