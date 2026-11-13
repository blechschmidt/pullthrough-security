package lockfiles

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file is a reader for the native syntax of HCL 2 — what Terraform and
// OpenTofu read .tf files and .terraform.lock.hcl in — that keeps the
// structure (blocks with their labels, attributes) and the value of an
// expression only when it is a literal: a string without template sequences,
// or a tuple of such strings. Every other expression is skipped, its
// brackets, strings, templates and heredocs followed so that the skipping
// ends where HCL ends the expression. A body that repeats an attribute is an
// error, as it is to HCL.

// hclBody is a body: the attributes and blocks kept (parseHCL), and how many
// of each it had.
type hclBody struct {
	attrs                 map[string]*hclAttr
	order                 []string
	blocks                []*hclBlock
	attrCount, blockCount int
}

// hclBlock is a block: its type, labels and body.
type hclBlock struct {
	typ    string
	labels []string
	body   *hclBody
	line   int
}

// hclAttr is an attribute, with its value when that is a literal.
type hclAttr struct {
	line int
	// str is the value of a literal string (isStr), list those of a tuple of
	// literal strings (isList).
	str    string
	isStr  bool
	list   []string
	isList bool
}

// hclTokKind is the kind of a token.
type hclTokKind int

const (
	htEOF hclTokKind = iota
	htNewline
	htIdent
	htString   // a quoted string without template sequences
	htNumber   //
	htHeredoc  // a heredoc (a template, never a literal here)
	htPunct    // anything else: "=", "{", "}", "[", "]", "(", ")", ",", operators
	htTemplate // a quoted string with a template sequence
)

type hclTok struct {
	kind hclTokKind
	text string // an identifier, a string's value, a punctuation mark
	line int
}

// Bounds of the reader.
const (
	maxHCLDepth = 64
	// maxHCLLiteralTokens bounds the tokens of an expression kept while it
	// may still be a literal: a tuple of strings longer than this is not a
	// lock file's list of hashes.
	maxHCLLiteralTokens = 1 << 16
)

type hclLexer struct {
	s    string
	pos  int
	line int
}

// parseHCL reads a file's top-level body. Only the top-level blocks whose
// type is in keep are kept, with their own attributes; every other block is
// read — so a file HCL refuses is refused here — and dropped, so that memory
// stays proportional to what is kept rather than to the file.
func parseHCL(data []byte, keep ...string) (*hclBody, error) {
	if len(data) > maxTreeInput {
		return nil, errTreeInputTooLarge
	}
	if !utf8.Valid(data) {
		return nil, errors.New("HCL file is not valid UTF-8")
	}
	p := &hclParser{lx: &hclLexer{s: string(data), line: 1}, keep: map[string]bool{}}
	for _, k := range keep {
		p.keep[k] = true
	}
	if err := p.advance(); err != nil {
		return nil, fmt.Errorf("HCL line %d: %w", p.lx.line, err)
	}
	body, err := p.body(0)
	if err != nil {
		return nil, fmt.Errorf("HCL line %d: %w", p.tok.line, err)
	}
	return body, nil
}

func (lx *hclLexer) peekAt(n int) byte {
	if lx.pos+n >= len(lx.s) {
		return 0
	}
	return lx.s[lx.pos+n]
}

func (lx *hclLexer) next() (hclTok, error) {
	for lx.pos < len(lx.s) {
		c := lx.s[lx.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			lx.pos++
			continue
		case c == '#' || c == '/' && lx.peekAt(1) == '/':
			for lx.pos < len(lx.s) && lx.s[lx.pos] != '\n' {
				lx.pos++
			}
			continue
		case c == '/' && lx.peekAt(1) == '*':
			end := strings.Index(lx.s[lx.pos+2:], "*/")
			if end < 0 {
				return hclTok{}, errors.New("unterminated comment")
			}
			comment := lx.s[lx.pos : lx.pos+2+end+2]
			lx.line += strings.Count(comment, "\n")
			lx.pos += len(comment)
			continue
		}
		break
	}
	if lx.pos >= len(lx.s) {
		return hclTok{kind: htEOF, line: lx.line}, nil
	}
	line := lx.line
	c := lx.s[lx.pos]
	switch {
	case c == '\n':
		lx.pos++
		lx.line++
		return hclTok{kind: htNewline, line: line}, nil
	case c == '"':
		lx.pos++
		value, literal, err := lx.quoted()
		if err != nil {
			return hclTok{}, err
		}
		if !literal {
			return hclTok{kind: htTemplate, line: line}, nil
		}
		return hclTok{kind: htString, text: value, line: line}, nil
	case c == '<' && lx.peekAt(1) == '<' && (isHCLIdentStart(lx.peekAt(2)) || lx.peekAt(2) == '-' && isHCLIdentStart(lx.peekAt(3))):
		if err := lx.heredoc(); err != nil {
			return hclTok{}, err
		}
		return hclTok{kind: htHeredoc, line: line}, nil
	case isHCLIdentStart(c):
		start := lx.pos
		for lx.pos < len(lx.s) && isHCLIdentChar(lx.s[lx.pos]) {
			lx.pos++
		}
		return hclTok{kind: htIdent, text: lx.s[start:lx.pos], line: line}, nil
	case c >= '0' && c <= '9':
		start := lx.pos
		for lx.pos < len(lx.s) && (isHCLIdentChar(lx.s[lx.pos]) || lx.s[lx.pos] == '.') {
			lx.pos++
		}
		return hclTok{kind: htNumber, text: lx.s[start:lx.pos], line: line}, nil
	}
	for _, op := range []string{"==", "!=", "<=", ">=", "&&", "||", "=>", "..."} {
		if strings.HasPrefix(lx.s[lx.pos:], op) {
			lx.pos += len(op)
			return hclTok{kind: htPunct, text: op, line: line}, nil
		}
	}
	if strings.IndexByte("{}[]()=,.:?!*/%+-<>", c) >= 0 {
		lx.pos++
		return hclTok{kind: htPunct, text: lx.s[lx.pos-1 : lx.pos], line: line}, nil
	}
	return hclTok{}, fmt.Errorf("unexpected character %q", string(c))
}

// quoted reads a quoted template after its opening quote. literal is false
// when it holds a template sequence ("${…}", "%{…}"), whose value is not
// known before Terraform evaluates it. A literal's value is a slice of the
// input when it has no escapes.
func (lx *hclLexer) quoted() (string, bool, error) {
	start := lx.pos
	var b *strings.Builder // made at the first escape
	literal := true
	for {
		if lx.pos >= len(lx.s) {
			return "", false, errors.New("unterminated string")
		}
		c := lx.s[lx.pos]
		switch {
		case c == '"':
			lx.pos++
			if b == nil {
				return lx.s[start : lx.pos-1], literal, nil
			}
			return b.String(), literal, nil
		case c == '\n':
			return "", false, errors.New("a line break inside a quoted string")
		case (c == '$' || c == '%') && lx.peekAt(1) == c && lx.peekAt(2) == '{':
			b = lx.builder(b, start)
			b.WriteString(string(c) + "{") // "$${" is a literal "${"
			lx.pos += 3
		case (c == '$' || c == '%') && lx.peekAt(1) == '{':
			lx.pos += 2
			if err := lx.skipTemplate(0); err != nil {
				return "", false, err
			}
			literal = false
			b = lx.builder(b, start)
		case c == '\\':
			b = lx.builder(b, start)
			r, err := lx.escape()
			if err != nil {
				return "", false, err
			}
			b.WriteString(r)
		default:
			if b != nil {
				b.WriteByte(c)
			}
			lx.pos++
		}
		if b != nil && b.Len() > 64<<10 || b == nil && lx.pos-start > 64<<10 {
			return "", false, errors.New("string too long")
		}
	}
}

// builder returns b, or a new builder holding the string read so far.
func (lx *hclLexer) builder(b *strings.Builder, start int) *strings.Builder {
	if b != nil {
		return b
	}
	b = &strings.Builder{}
	b.WriteString(lx.s[start:lx.pos])
	return b
}

// escape reads a backslash escape inside a quoted string.
func (lx *hclLexer) escape() (string, error) {
	e := lx.peekAt(1)
	lx.pos += 2
	switch e {
	case 'n':
		return "\n", nil
	case 'r':
		return "\r", nil
	case 't':
		return "\t", nil
	case '"':
		return "\"", nil
	case '\\':
		return "\\", nil
	case 'u', 'U':
		n := 4
		if e == 'U' {
			n = 8
		}
		if lx.pos+n > len(lx.s) {
			return "", errors.New("short unicode escape")
		}
		v, err := strconv.ParseUint(lx.s[lx.pos:lx.pos+n], 16, 32)
		if err != nil || !utf8.ValidRune(rune(v)) {
			return "", errors.New("bad unicode escape")
		}
		lx.pos += n
		return string(rune(v)), nil
	}
	return "", errors.New("unknown escape")
}

// skipTemplate skips a template sequence's content after its "${" or "%{",
// up to its closing brace: nested braces, strings (with their own
// templates) and heredocs are followed.
func (lx *hclLexer) skipTemplate(depth int) error {
	if depth > maxHCLDepth {
		return errors.New("templates nested too deeply")
	}
	braces := 1
	for lx.pos < len(lx.s) {
		c := lx.s[lx.pos]
		switch {
		case c == '\n':
			lx.line++
			lx.pos++
		case c == '{':
			braces++
			lx.pos++
		case c == '}':
			braces--
			lx.pos++
			if braces == 0 {
				return nil
			}
		case c == '"':
			lx.pos++
			if err := lx.skipQuoted(depth + 1); err != nil {
				return err
			}
		case c == '<' && lx.peekAt(1) == '<' && (isHCLIdentStart(lx.peekAt(2)) || lx.peekAt(2) == '-'):
			if err := lx.heredoc(); err != nil {
				return err
			}
		default:
			lx.pos++
		}
	}
	return errors.New("unterminated template sequence")
}

// skipQuoted skips a quoted string inside a template sequence.
func (lx *hclLexer) skipQuoted(depth int) error {
	for lx.pos < len(lx.s) {
		c := lx.s[lx.pos]
		switch {
		case c == '"':
			lx.pos++
			return nil
		case c == '\n':
			return errors.New("a line break inside a quoted string")
		case c == '\\':
			lx.pos += 2
		case (c == '$' || c == '%') && lx.peekAt(1) == c && lx.peekAt(2) == '{':
			lx.pos += 3
		case (c == '$' || c == '%') && lx.peekAt(1) == '{':
			lx.pos += 2
			if err := lx.skipTemplate(depth + 1); err != nil {
				return err
			}
		default:
			lx.pos++
		}
	}
	return errors.New("unterminated string")
}

// heredoc skips a heredoc from its "<<": "<<EOT" or "<<-EOT", the rest of
// the line, then lines up to one that is the marker alone (after blanks for
// the "-" form, which Terraform also accepts without it).
func (lx *hclLexer) heredoc() error {
	lx.pos += 2
	if lx.peekAt(0) == '-' {
		lx.pos++
	}
	start := lx.pos
	for lx.pos < len(lx.s) && isHCLIdentChar(lx.s[lx.pos]) {
		lx.pos++
	}
	marker := lx.s[start:lx.pos]
	if marker == "" {
		return errors.New("a heredoc without a marker")
	}
	nl := strings.IndexByte(lx.s[lx.pos:], '\n')
	if nl < 0 || strings.TrimSpace(strings.TrimSuffix(lx.s[lx.pos:lx.pos+nl], "\r")) != "" {
		return errors.New("a heredoc marker not at the end of its line")
	}
	lx.pos += nl + 1
	lx.line++
	for lx.pos < len(lx.s) {
		end := strings.IndexByte(lx.s[lx.pos:], '\n')
		var line string
		if end < 0 {
			line = lx.s[lx.pos:]
		} else {
			line = lx.s[lx.pos : lx.pos+end]
		}
		if strings.TrimSpace(strings.TrimSuffix(line, "\r")) == marker {
			lx.pos += len(line) // the newline after the marker ends the attribute
			return nil
		}
		if end < 0 {
			break
		}
		lx.pos += end + 1
		lx.line++
	}
	return errors.New("unterminated heredoc")
}

func isHCLIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= 0x80
}

func isHCLIdentChar(c byte) bool {
	return isHCLIdentStart(c) || c >= '0' && c <= '9' || c == '-'
}

// hclParser reads bodies from the lexer's tokens, one token ahead.
type hclParser struct {
	lx    *hclLexer
	tok   hclTok
	depth int
	keep  map[string]bool
}

func (p *hclParser) advance() error {
	t, err := p.lx.next()
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *hclParser) skipNewlines() error {
	for p.tok.kind == htNewline {
		if err := p.advance(); err != nil {
			return err
		}
	}
	return nil
}

func (p *hclParser) isPunct(s string) bool { return p.tok.kind == htPunct && p.tok.text == s }

// body reads attributes and blocks up to EOF (level 0) or up to the "}" of a
// block. At level 0 the blocks of the kept types are returned with their
// attributes; a kept block's body (level 1) keeps its attributes; anything
// deeper is read and dropped.
func (p *hclParser) body(level int) (*hclBody, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxHCLDepth {
		return nil, errors.New("blocks nested too deeply")
	}
	b := &hclBody{attrs: map[string]*hclAttr{}}
	seen := map[string]bool{}
	for {
		if err := p.skipNewlines(); err != nil {
			return nil, err
		}
		t := p.tok
		switch {
		case t.kind == htEOF:
			if level > 0 {
				return nil, errors.New("a block is not closed")
			}
			return b, nil
		case p.isPunct("}"):
			if level == 0 {
				return nil, errors.New("unexpected '}'")
			}
			return b, nil
		case t.kind != htIdent:
			return nil, errors.New("expected an attribute or a block")
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.isPunct("=") {
			if err := p.advance(); err != nil {
				return nil, err
			}
			attr, err := p.expression()
			if err != nil {
				return nil, err
			}
			attr.line = t.line
			if seen[t.text] {
				return nil, fmt.Errorf("the attribute %q is defined twice", t.text)
			}
			seen[t.text] = true
			b.attrCount++
			if level == 1 {
				b.attrs[t.text] = attr
				b.order = append(b.order, t.text)
			}
			continue
		}
		blk := &hclBlock{typ: t.text, line: t.line}
		kept := level == 0 && p.keep[t.text]
		for {
			if p.tok.kind == htString || p.tok.kind == htIdent {
				if kept && len(blk.labels) < 8 {
					blk.labels = append(blk.labels, p.tok.text)
				}
				if err := p.advance(); err != nil {
					return nil, err
				}
				continue
			}
			if p.isPunct("{") {
				if err := p.advance(); err != nil {
					return nil, err
				}
				break
			}
			return nil, errors.New("expected a block label or '{'")
		}
		innerLevel := 2
		if kept {
			innerLevel = 1
		}
		inner, err := p.body(innerLevel)
		if err != nil {
			return nil, err
		}
		if err := p.advance(); err != nil { // the closing "}"
			return nil, err
		}
		b.blockCount++
		if kept {
			blk.body = inner
			b.blocks = append(b.blocks, blk)
		}
		if p.tok.kind != htNewline && p.tok.kind != htEOF && !p.isPunct("}") {
			return nil, errors.New("a block must end its line")
		}
	}
}

// expression reads an attribute's expression, up to the end of its line at
// bracket depth zero (or the "}" closing a one-line block), and keeps its
// value when it is a literal string or a tuple of literal strings. Tokens
// are kept only while the expression can still be such a literal.
func (p *hclParser) expression() (*hclAttr, error) {
	depth := 0
	var toks []hclTok
	literal := true
	for {
		t := p.tok
		switch {
		case t.kind == htEOF:
			if depth > 0 {
				return nil, errors.New("an expression is not closed")
			}
			return literalAttr(toks, literal), nil
		case t.kind == htNewline && depth == 0:
			return literalAttr(toks, literal), nil
		case t.kind == htPunct && (t.text == "(" || t.text == "[" || t.text == "{"):
			depth++
			if depth > maxHCLDepth {
				return nil, errors.New("an expression nested too deeply")
			}
		case t.kind == htPunct && (t.text == ")" || t.text == "]" || t.text == "}"):
			if depth == 0 {
				if t.text == "}" {
					return literalAttr(toks, literal), nil // the end of a one-line block
				}
				return nil, errors.New("unbalanced brackets")
			}
			depth--
		}
		if literal && t.kind != htNewline {
			switch {
			case t.kind == htString, t.kind == htPunct && (t.text == "[" || t.text == "]" || t.text == ","):
				if len(toks) < maxHCLLiteralTokens {
					toks = append(toks, t)
				} else {
					literal, toks = false, nil
				}
			default:
				literal, toks = false, nil
			}
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
	}
}

// literalAttr evaluates an expression's tokens (line breaks left out) when
// they are a literal string, or a tuple of literal strings with an optional
// trailing comma.
func literalAttr(toks []hclTok, literal bool) *hclAttr {
	a := &hclAttr{}
	if !literal {
		return a
	}
	if len(toks) == 1 && toks[0].kind == htString {
		a.str, a.isStr = toks[0].text, true
		return a
	}
	if len(toks) < 2 || toks[0].kind != htPunct || toks[0].text != "[" ||
		toks[len(toks)-1].kind != htPunct || toks[len(toks)-1].text != "]" {
		return a
	}
	inner := toks[1 : len(toks)-1]
	var list []string
	for i := 0; i < len(inner); i++ {
		if inner[i].kind != htString {
			return a
		}
		list = append(list, inner[i].text)
		if i+1 < len(inner) {
			if inner[i+1].kind != htPunct || inner[i+1].text != "," {
				return a
			}
			i++
		}
	}
	a.list, a.isList = list, true
	return a
}
