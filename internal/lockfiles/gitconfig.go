package lockfiles

import (
	"errors"
	"fmt"
	"strings"
)

// gitConfigEntry is one variable of a file in git's configuration syntax.
type gitConfigEntry struct {
	// section is the section name, lower-cased; sub the subsection, as
	// written (subsections are case-sensitive), hasSub whether there is one.
	section, sub string
	hasSub       bool
	// key is the variable name, lower-cased; value its value (a variable
	// without "=" is a boolean true, read as "").
	key, value string
	// headerLine is the line of the section header, line the variable's.
	headerLine, line int
}

// maxGitConfigEntries bounds the variables read from one file.
const maxGitConfigEntries = 100_000

var errGitConfigTooLarge = errors.New("more variables than a configuration file has")

// parseGitConfig reads a file in git's configuration syntax as git's own
// parser (config.c) does: "[section]", "[section \"subsection\"]" and the
// old "[section.subsection]" headers; "name = value" with "#" and ";"
// comments, double quotes, the escapes \\ \" \n \t \b, and a backslash at the
// end of a line continuing the value. What git refuses is an error naming
// the line, as git's "bad config line" does.
func parseGitConfig(s string) ([]gitConfigEntry, error) {
	p := &gitConfigParser{s: s, line: 1}
	return p.parse()
}

type gitConfigParser struct {
	s    string
	pos  int
	line int
}

// next returns the next character, "\r\n" read as "\n", and '\n' at the end
// of the input (git's get_next_char).
func (p *gitConfigParser) next() byte {
	if p.pos >= len(p.s) {
		p.pos = len(p.s) + 1
		return '\n'
	}
	c := p.s[p.pos]
	p.pos++
	if c == '\r' && p.pos < len(p.s) && p.s[p.pos] == '\n' {
		c = '\n'
		p.pos++
	}
	if c == '\n' {
		p.line++
	}
	return c
}

func (p *gitConfigParser) eof() bool { return p.pos >= len(p.s) }

func (p *gitConfigParser) bad(line int) error {
	return fmt.Errorf("bad config line %d", line)
}

// gitConfigSpace: git's own isspace() — space, tab, line feed and carriage
// return; not the C library's, which also has \v and \f.
func gitConfigSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func gitConfigKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func gitConfigAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func (p *gitConfigParser) parse() ([]gitConfigEntry, error) {
	var out []gitConfigEntry
	section, sub, hasSub, headerLine := "", "", false, 0
	for {
		if p.eof() {
			return out, nil
		}
		line := p.line
		c := p.next()
		switch {
		case c == '\n':
			continue
		case gitConfigSpace(c):
			continue
		case c == '#' || c == ';':
			for !p.eof() {
				if p.next() == '\n' {
					break
				}
			}
			continue
		case c == '[':
			var err error
			section, sub, hasSub, err = p.header()
			if err != nil {
				return nil, p.bad(line)
			}
			headerLine = line
			continue
		case !gitConfigAlpha(c):
			return nil, p.bad(line)
		}
		key, value, err := p.variable(c)
		if err != nil {
			return nil, p.bad(line)
		}
		if section == "" {
			return nil, p.bad(line) // a variable before any section
		}
		if len(out) == maxGitConfigEntries {
			return nil, errGitConfigTooLarge
		}
		out = append(out, gitConfigEntry{section: section, sub: sub, hasSub: hasSub, key: key, value: value, headerLine: headerLine, line: line})
	}
}

// header reads a section header after its "[".
func (p *gitConfigParser) header() (section, sub string, hasSub bool, err error) {
	var name strings.Builder
	for {
		c := p.next()
		switch {
		case c == '\n':
			return "", "", false, errors.New("incomplete header")
		case gitConfigSpace(c):
			return p.extendedHeader(name.String())
		case c == ']':
			full := strings.ToLower(name.String())
			if full == "" {
				return "", "", false, errors.New("empty section name")
			}
			// "[section.subsection]": the old syntax, lower-cased whole.
			if i := strings.IndexByte(full, '.'); i >= 0 {
				return full[:i], full[i+1:], true, nil
			}
			return full, "", false, nil
		case !gitConfigKeyChar(c) && c != '.':
			return "", "", false, errors.New("bad section name")
		}
		name.WriteByte(c)
		if name.Len() > 1024 {
			return "", "", false, errors.New("section name too long")
		}
	}
}

// extendedHeader reads `"subsection"]` after a section name and blanks.
func (p *gitConfigParser) extendedHeader(section string) (string, string, bool, error) {
	if section == "" {
		return "", "", false, errors.New("empty section name")
	}
	c := p.next()
	for c != '\n' && gitConfigSpace(c) {
		c = p.next()
	}
	if c != '"' {
		return "", "", false, errors.New("subsection not quoted")
	}
	var sub strings.Builder
	for {
		c := p.next()
		if c == '\n' {
			return "", "", false, errors.New("incomplete subsection")
		}
		if c == '"' {
			break
		}
		if c == '\\' {
			c = p.next()
			if c == '\n' {
				return "", "", false, errors.New("incomplete subsection")
			}
		}
		sub.WriteByte(c)
		if sub.Len() > 4096 {
			return "", "", false, errors.New("subsection too long")
		}
	}
	if p.next() != ']' {
		return "", "", false, errors.New("header not closed")
	}
	// "[a.b \"c\"]" is variable prefix "a.b.c": the section is "a", the
	// subsection "b.c" (the part of the base name lower-cased, as git does).
	section = strings.ToLower(section)
	if base, rest, ok := strings.Cut(section, "."); ok {
		return base, rest + "." + sub.String(), true, nil
	}
	return section, sub.String(), true, nil
}

// variable reads "name [= value]" from its first character.
func (p *gitConfigParser) variable(first byte) (string, string, error) {
	var name strings.Builder
	name.WriteByte(first)
	c := p.next()
	for gitConfigKeyChar(c) {
		name.WriteByte(c)
		if name.Len() > 1024 {
			return "", "", errors.New("variable name too long")
		}
		c = p.next()
	}
	for c != '\n' && (c == ' ' || c == '\t') {
		c = p.next()
	}
	key := strings.ToLower(name.String())
	switch c {
	case '\n':
		return key, "", nil
	case '=':
		value, err := p.value()
		return key, value, err
	}
	// Anything else — a comment after a boolean variable included — is a
	// line git refuses.
	return "", "", errors.New("bad variable")
}

// value reads a value up to the end of its (possibly continued) line, as
// git's parse_value does: blanks before the value and after it are dropped,
// blanks inside it kept as they are.
func (p *gitConfigParser) value() (string, error) {
	var b strings.Builder
	quote, comment := false, false
	trim := -1 // length to cut back to when only blanks follow
	for {
		c := p.next()
		if c == '\n' {
			if quote {
				return "", errors.New("unterminated quote")
			}
			s := b.String()
			if trim >= 0 {
				s = s[:trim]
			}
			return s, nil
		}
		if comment {
			continue
		}
		if gitConfigSpace(c) && !quote {
			if trim < 0 {
				trim = b.Len()
			}
			if b.Len() > 0 {
				b.WriteByte(c)
			}
			continue
		}
		if !quote && (c == ';' || c == '#') {
			comment = true
			continue
		}
		trim = -1
		if c == '\\' {
			c = p.next()
			switch c {
			case '\n':
				continue
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			case 'n':
				c = '\n'
			case '\\', '"':
			default:
				return "", errors.New("unknown escape")
			}
			b.WriteByte(c)
			continue
		}
		if c == '"' {
			quote = !quote
			continue
		}
		b.WriteByte(c)
		if b.Len() > 64<<10 {
			return "", errors.New("value too long")
		}
	}
}
