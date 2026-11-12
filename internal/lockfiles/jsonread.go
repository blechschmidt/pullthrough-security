package lockfiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// lineIndex turns byte offsets into 1-based line numbers.
type lineIndex struct {
	starts []int // offset at which each line starts
}

func newLineIndex(data []byte) *lineIndex {
	li := &lineIndex{starts: []int{0}}
	for i, c := range data {
		if c == '\n' {
			li.starts = append(li.starts, i+1)
		}
	}
	return li
}

// line returns the line holding the byte at off.
func (li *lineIndex) line(off int) int {
	if off < 0 {
		return 1
	}
	return sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > off })
}

// jsonDoc reads a JSON document as a stream, keeping track of where each key
// and array element starts, so that a lock file's entries can be attributed
// to their lines without building a tree of the whole document.
type jsonDoc struct {
	data  []byte
	dec   *json.Decoder
	lines *lineIndex
	depth int
}

// maxJSONDepth bounds how deeply the readers in this package recurse into a
// document (encoding/json bounds its own decoding separately).
const maxJSONDepth = 512

var errJSONDepth = errors.New("JSON document nested too deeply")

func newJSONDoc(data []byte) *jsonDoc {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return &jsonDoc{data: data, dec: dec, lines: newLineIndex(data)}
}

// object reads an object, calling fn for every member with the member's key
// and the line the key is on. fn must consume the member's value (value,
// skip, object or array).
func (j *jsonDoc) object(fn func(key string, line int) error) error {
	if err := j.expect('{'); err != nil {
		return err
	}
	j.depth++
	if j.depth > maxJSONDepth {
		return errJSONDepth
	}
	for j.dec.More() {
		tok, err := j.dec.Token()
		if err != nil {
			return syntaxError(err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("JSON object key is not a string")
		}
		line := j.lines.line(int(j.dec.InputOffset()) - 1)
		if err := fn(key, line); err != nil {
			return err
		}
	}
	j.depth--
	return j.expect('}')
}

// array reads an array, calling fn for every element with its index and the
// line it starts on. fn must consume the element.
func (j *jsonDoc) array(fn func(i, line int) error) error {
	if err := j.expect('['); err != nil {
		return err
	}
	j.depth++
	if j.depth > maxJSONDepth {
		return errJSONDepth
	}
	for i := 0; j.dec.More(); i++ {
		if err := fn(i, j.lines.line(j.valueStart())); err != nil {
			return err
		}
	}
	j.depth--
	return j.expect(']')
}

// valueStart returns the offset of the next value: past the separator and
// whitespace the decoder may still be in front of.
func (j *jsonDoc) valueStart() int {
	off := int(j.dec.InputOffset())
	for off < len(j.data) {
		switch j.data[off] {
		case ' ', '\t', '\r', '\n', ',', ':':
			off++
			continue
		}
		break
	}
	return off
}

// peekKind returns the first byte of the next value ('{', '[', '"', …), or 0
// at the end of the input.
func (j *jsonDoc) peekKind() byte {
	off := j.valueStart()
	if off >= len(j.data) {
		return 0
	}
	return j.data[off]
}

// boolValue decodes the next value: true, or false for anything else.
func (j *jsonDoc) boolValue() (bool, error) {
	var raw json.RawMessage
	if err := j.value(&raw); err != nil {
		return false, err
	}
	return bytes.Equal(bytes.TrimSpace(raw), []byte("true")), nil
}

// value decodes the next value into v.
func (j *jsonDoc) value(v any) error {
	if err := j.dec.Decode(v); err != nil {
		return syntaxError(err)
	}
	return nil
}

// skip consumes the next value.
func (j *jsonDoc) skip() error { return j.value(&discard{}) }

// stringValue decodes the next value if it is a string, and skips it
// otherwise, returning "".
func (j *jsonDoc) stringValue() (string, error) {
	if j.peekKind() != '"' {
		return "", j.skip()
	}
	var s string
	err := j.value(&s)
	return s, err
}

func (j *jsonDoc) expect(d json.Delim) error {
	tok, err := j.dec.Token()
	if err != nil {
		return syntaxError(err)
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return fmt.Errorf("JSON document: expected %q", string(d))
	}
	return nil
}

// end checks that nothing but whitespace follows the document.
func (j *jsonDoc) end() error {
	if _, err := j.dec.Token(); err == nil {
		return errors.New("JSON document: data after the top-level value")
	}
	return nil
}

// syntaxError describes a decoding error without quoting the input: the
// messages of encoding/json name types and offsets, which are kept, but an
// UnmarshalTypeError can carry a field path built from document keys.
func syntaxError(err error) error {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("JSON syntax error at offset %d", se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Errorf("JSON value of the wrong type (%s where %s was expected) at offset %d", te.Value, te.Type, te.Offset)
	}
	if errors.Is(err, errJSONDepth) {
		return err
	}
	return fmt.Errorf("JSON document: %w", err)
}

// jsonFields is a JSON object's members by exact key. A key that appears
// twice keeps its last value — what JavaScript's JSON.parse, Python's json and
// PHP's json_decode do, and so what npm, Pipenv, Composer and NuGet read.
// Decoding into a Go struct would not do: encoding/json matches field names
// ignoring case, so {"resolved": a, "Resolved": b} would show the scanner b
// while npm installs a.
type jsonFields map[string]json.RawMessage

// fields decodes the next value as an object's members; anything but an
// object is skipped and yields nil.
func (j *jsonDoc) fields() (jsonFields, error) {
	if j.peekKind() != '{' {
		return nil, j.skip()
	}
	var m map[string]json.RawMessage
	if err := j.value(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// str returns the member's string value, or "" when it is absent or not a
// string.
func (f jsonFields) str(key string) string {
	raw, ok := f[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// flag reports whether the member is true.
func (f jsonFields) flag(key string) bool {
	return bytes.Equal(bytes.TrimSpace(f[key]), []byte("true"))
}

// strs returns the member's string elements (a lone string as one).
func (f jsonFields) strs(key string) []string {
	raw, ok := f[key]
	if !ok {
		return nil
	}
	var l lenientStrings
	_ = l.UnmarshalJSON(raw)
	return l
}

// obj returns the member as an object's members, or nil.
func (f jsonFields) obj(key string) jsonFields {
	raw, ok := f[key]
	if !ok {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// discard is a JSON value that is read and dropped.
type discard struct{}

func (*discard) UnmarshalJSON([]byte) error { return nil }

// lenientStrings decodes an array of strings (non-strings dropped), a single
// string as a one-element list, and anything else as nothing.
type lenientStrings []string

func (s *lenientStrings) UnmarshalJSON(b []byte) error {
	var list []json.RawMessage
	if json.Unmarshal(b, &list) == nil {
		out := make([]string, 0, len(list))
		for _, raw := range list {
			var v string
			if json.Unmarshal(raw, &v) == nil {
				out = append(out, v)
			}
		}
		*s = out
		return nil
	}
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = []string{one}
		return nil
	}
	*s = nil
	return nil
}
