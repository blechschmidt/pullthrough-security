package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jsonScanner reads a JSON document where it stands, keeping the byte span of
// the values it reads, so that a value can be replaced without encoding the
// document again: a lock file written by its package manager keeps its
// formatting, its key order and every byte not replaced. It reads the whole
// grammar strictly — a document encoding/json refuses is refused — in time
// linear in the document's size.
type jsonScanner struct {
	data  []byte
	pos   int
	depth int
	// keyAt is the span of the key of the object member being read.
	keyAt span
}

// maxJSONNesting is encoding/json's own bound on nesting: a document it reads
// is read here too.
const maxJSONNesting = 10000

// span is the bytes of a value: data[start:end], quotation marks included.
type span struct{ start, end int }

func (s *jsonScanner) errorf(format string, args ...any) error {
	return fmt.Errorf("JSON document, offset %d: %s", s.pos, fmt.Sprintf(format, args...))
}

// ws skips whitespace.
func (s *jsonScanner) ws() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// peek returns the first byte of the next value, or 0 at the end.
func (s *jsonScanner) peek() byte {
	s.ws()
	if s.pos < len(s.data) {
		return s.data[s.pos]
	}
	return 0
}

// object reads an object, calling fn with each member's key; fn must read
// the member's value (skip, str, object, field).
func (s *jsonScanner) object(fn func(key string) error) error {
	if s.peek() != '{' {
		return s.errorf("an object was expected")
	}
	s.pos++
	if s.depth++; s.depth > maxJSONNesting {
		return s.errorf("nested too deeply")
	}
	if s.peek() == '}' {
		s.pos++
		s.depth--
		return nil
	}
	for {
		if s.peek() != '"' {
			return s.errorf("an object key was expected")
		}
		sp, err := s.str()
		if err != nil {
			return err
		}
		key, err := s.text(sp)
		if err != nil {
			return err
		}
		if s.peek() != ':' {
			return s.errorf("a colon was expected")
		}
		s.pos++
		s.keyAt = sp
		if err := fn(key); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.pos++
		case '}':
			s.pos++
			s.depth--
			return nil
		default:
			return s.errorf("a comma or the end of the object was expected")
		}
	}
}

// array reads an array, skipping its elements.
func (s *jsonScanner) array() error {
	if s.peek() != '[' {
		return s.errorf("an array was expected")
	}
	s.pos++
	if s.depth++; s.depth > maxJSONNesting {
		return s.errorf("nested too deeply")
	}
	if s.peek() == ']' {
		s.pos++
		s.depth--
		return nil
	}
	for {
		if err := s.skip(); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.pos++
		case ']':
			s.pos++
			s.depth--
			return nil
		default:
			return s.errorf("a comma or the end of the array was expected")
		}
	}
}

// skip reads any value.
func (s *jsonScanner) skip() error {
	switch c := s.peek(); {
	case c == '{':
		return s.object(func(string) error { return s.skip() })
	case c == '[':
		return s.array()
	case c == '"':
		_, err := s.str()
		return err
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	default:
		return s.errorf("a value was expected")
	}
}

func (s *jsonScanner) literal(word string) error {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(word)) {
		return s.errorf("a value was expected")
	}
	s.pos += len(word)
	return nil
}

// number reads -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?.
func (s *jsonScanner) number() error {
	digits := func() int {
		n := 0
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			s.pos++
			n++
		}
		return n
	}
	if s.data[s.pos] == '-' {
		s.pos++
	}
	if s.pos < len(s.data) && s.data[s.pos] == '0' {
		s.pos++
	} else if digits() == 0 {
		return s.errorf("a malformed number")
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if digits() == 0 {
			return s.errorf("a malformed number")
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if digits() == 0 {
			return s.errorf("a malformed number")
		}
	}
	return nil
}

// str reads a string and returns its span.
func (s *jsonScanner) str() (span, error) {
	if s.peek() != '"' {
		return span{}, s.errorf("a string was expected")
	}
	start := s.pos
	i := s.pos + 1
	for i < len(s.data) {
		switch c := s.data[i]; {
		case c == '"':
			s.pos = i + 1
			return span{start, i + 1}, nil
		case c == '\\':
			if i+1 >= len(s.data) {
				return span{}, s.errorf("an unterminated string")
			}
			switch s.data[i+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i += 2
			case 'u':
				if i+6 > len(s.data) || !isHex4(s.data[i+2:i+6]) {
					return span{}, s.errorf("a malformed escape")
				}
				i += 6
			default:
				return span{}, s.errorf("a malformed escape")
			}
		case c < 0x20:
			return span{}, s.errorf("a control character in a string")
		default:
			i++
		}
	}
	return span{}, s.errorf("an unterminated string")
}

func isHex4(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// text decodes the string at sp as encoding/json decodes it — which is what
// internal/lockfiles reads the lock file with: escapes resolved, invalid
// UTF-8 replaced.
func (s *jsonScanner) text(sp span) (string, error) {
	raw := s.data[sp.start:sp.end]
	plain := true
	for _, c := range raw[1 : len(raw)-1] {
		if c == '\\' || c >= 0x80 {
			plain = false
			break
		}
	}
	if plain {
		return string(raw[1 : len(raw)-1]), nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", errors.New("JSON document: a malformed string")
	}
	return v, nil
}

// end checks that nothing but whitespace follows the document. (peek's 0
// cannot tell: a NUL byte is data too.)
func (s *jsonScanner) end() error {
	s.ws()
	if s.pos < len(s.data) {
		return s.errorf("data after the document")
	}
	return nil
}

// jsonField is what an object member of interest holds. A member that occurs
// twice keeps its last value, as JavaScript's JSON.parse (and so npm) and
// internal/lockfiles read it, and is marked: a rewrite of such an entry would
// have to guess which occurrence counts.
type jsonField struct {
	present  bool
	repeated bool
	isString bool
	isTrue   bool
	at       span
	value    string
}

// field reads the member's value into f.
func (s *jsonScanner) field(f *jsonField) error {
	if f.present {
		f.repeated = true
	}
	*f = jsonField{present: true, repeated: f.repeated}
	switch s.peek() {
	case '"':
		sp, err := s.str()
		if err != nil {
			return err
		}
		v, err := s.text(sp)
		if err != nil {
			return err
		}
		f.isString, f.at, f.value = true, sp, v
		return nil
	case 't':
		if err := s.literal("true"); err != nil {
			return err
		}
		f.isTrue = true
		return nil
	default:
		return s.skip()
	}
}

// jsonString encodes s the way JavaScript's JSON.stringify does, which npm
// writes its lock files with: only quotation marks, backslashes and control
// characters are escaped.
func jsonString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
