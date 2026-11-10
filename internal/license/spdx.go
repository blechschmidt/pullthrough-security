// Package license implements the proxy's license-compliance admission gate
// (Task 28). As artifacts are pulled through the proxy it reads the per-component
// license identifiers carried in the artifact's SBOM (the CycloneDX document the
// vulnscan subsystem already generates), parses each declared SPDX license
// expression (supporting the AND / OR / WITH operators and the "+" or-later
// suffix), and evaluates it against an operator-configured allow / deny / review
// policy with per-tenant overrides. An artifact whose effective license is denied
// is blocked (or warned/quarantined per policy); an unknown / NOASSERTION license
// is flagged for review; and a license that changed across versions of the same
// package (license drift) is surfaced as a high-signal supply-chain risk.
//
// The package is dependency-free beyond the standard library and the shared
// internal/policy action vocabulary, so it can be exercised in isolation and runs
// fully offline (no network access is performed): the SPDX catalog and policy are
// entirely local, which suits air-gapped deployments.
package license

import (
	"fmt"
	"sort"
	"strings"
)

// maxExpressionTokens bounds the number of tokens the SPDX parser will accept.
// The recursive-descent parser nests one stack frame per parenthesis/operator,
// so an adversarial SBOM carrying a license field of deeply nested parentheses
// ("((((((...))))))") could otherwise exhaust the goroutine stack. Real SPDX
// expressions are tiny; a few thousand tokens is far beyond any legitimate one
// while keeping recursion depth safely bounded.
const maxExpressionTokens = 4096

// Expression is a parsed SPDX license expression. The zero value is empty
// (IsZero reports true) and represents an undeclared / NOASSERTION license.
type Expression struct {
	root spdxNode
	text string // canonical rendering of the parsed tree
}

// spdxNode is a node in the parsed SPDX expression tree: either a single license
// (licenseNode) or a binary AND/OR operator (opNode).
type spdxNode interface{ isNode() }

// licenseNode is a single SPDX license identifier, optionally carrying the
// "+" (or-later) suffix and a "WITH <exception>" clause.
type licenseNode struct {
	id        string // SPDX license id without the trailing '+', e.g. "Apache-2.0"
	orLater   bool   // the '+' operator was present (e.g. "Apache-2.0+")
	exception string // SPDX exception id following WITH, if any
}

func (licenseNode) isNode() {}

// opNode is a binary AND or OR combination of two sub-expressions.
type opNode struct {
	op          string // "AND" or "OR"
	left, right spdxNode
}

func (opNode) isNode() {}

// token kinds produced by the tokenizer.
type tokenKind int

const (
	tIdent tokenKind = iota
	tOp
	tLParen
	tRParen
)

type token struct {
	kind tokenKind
	text string
}

// ParseExpression parses an SPDX license expression. It accepts the operators
// AND, OR and WITH (case-insensitively), parenthesized grouping, and the trailing
// "+" or-later suffix on a license id. License identifiers are preserved verbatim
// (case is normalized only when compared against the catalog/policy). An empty or
// whitespace-only input is a NOASSERTION and yields an error so the caller can
// distinguish "undeclared" from "declared but unparsable".
func ParseExpression(s string) (Expression, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Expression{}, fmt.Errorf("license: empty SPDX expression")
	}
	toks, err := tokenize(raw)
	if err != nil {
		return Expression{}, err
	}
	if len(toks) == 0 {
		return Expression{}, fmt.Errorf("license: empty SPDX expression")
	}
	if len(toks) > maxExpressionTokens {
		return Expression{}, fmt.Errorf("license: SPDX expression too long (%d tokens, limit %d)", len(toks), maxExpressionTokens)
	}
	p := &parser{toks: toks}
	root, err := p.parseOr()
	if err != nil {
		return Expression{}, err
	}
	if p.pos != len(p.toks) {
		return Expression{}, fmt.Errorf("license: unexpected trailing token %q in expression %q", p.toks[p.pos].text, raw)
	}
	return Expression{root: root, text: render(root)}, nil
}

// IsZero reports whether the expression is empty (NOASSERTION).
func (e Expression) IsZero() bool { return e.root == nil }

// String renders the expression in a canonical, fully-parenthesized-where-needed
// form so equivalent inputs print identically.
func (e Expression) String() string {
	if e.root == nil {
		return ""
	}
	return e.text
}

// Licenses returns the distinct license identifiers referenced anywhere in the
// expression, sorted for determinism. The "+" suffix and WITH exception are not
// included in the returned ids.
func (e Expression) Licenses() []string {
	if e.root == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	walk(e.root, func(n licenseNode) {
		if !seen[n.id] {
			seen[n.id] = true
			out = append(out, n.id)
		}
	})
	sort.Strings(out)
	return out
}

// walk visits every license leaf of the tree.
func walk(n spdxNode, fn func(licenseNode)) {
	switch t := n.(type) {
	case licenseNode:
		fn(t)
	case opNode:
		walk(t.left, fn)
		walk(t.right, fn)
	}
}

// --- tokenizer --------------------------------------------------------------

// tokenize splits an SPDX expression into tokens. Identifiers run over the SPDX
// id character set (letters, digits and '-', '.', '+', ':', '_'); parentheses are
// single-character tokens; the words AND, OR and WITH (any case) are operators.
func tokenize(s string) ([]token, error) {
	var toks []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tLParen, text: "("})
			i++
		case c == ')':
			toks = append(toks, token{kind: tRParen, text: ")"})
			i++
		case isIdentChar(c):
			j := i
			for j < len(s) && isIdentChar(s[j]) {
				j++
			}
			word := s[i:j]
			i = j
			switch strings.ToUpper(word) {
			case "AND", "OR", "WITH":
				toks = append(toks, token{kind: tOp, text: strings.ToUpper(word)})
			default:
				toks = append(toks, token{kind: tIdent, text: word})
			}
		default:
			return nil, fmt.Errorf("license: unexpected character %q in SPDX expression", string(c))
		}
	}
	return toks, nil
}

// isIdentChar reports whether c is part of an SPDX license/exception identifier.
func isIdentChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '+' || c == ':' || c == '_':
		return true
	default:
		return false
	}
}

// --- recursive-descent parser ----------------------------------------------
//
// Grammar (precedence, loosest to tightest): OR < AND < WITH, with parentheses
// overriding. This matches the SPDX specification (Annex D / §SPDX license
// expressions) where OR binds least tightly and WITH binds to a single license.

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) peekOp(op string) bool {
	t := p.peek()
	return t != nil && t.kind == tOp && t.text == op
}

func (p *parser) next() *token {
	t := p.peek()
	if t != nil {
		p.pos++
	}
	return t
}

func (p *parser) parseOr() (spdxNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peekOp("OR") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = opNode{op: "OR", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (spdxNode, error) {
	left, err := p.parseWith()
	if err != nil {
		return nil, err
	}
	for p.peekOp("AND") {
		p.next()
		right, err := p.parseWith()
		if err != nil {
			return nil, err
		}
		left = opNode{op: "AND", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseWith() (spdxNode, error) {
	n, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	if p.peekOp("WITH") {
		p.next()
		t := p.peek()
		if t == nil || t.kind != tIdent {
			return nil, fmt.Errorf("license: expected an exception identifier after WITH")
		}
		p.next()
		ln, ok := n.(licenseNode)
		if !ok {
			return nil, fmt.Errorf("license: WITH must follow a single license, not a group")
		}
		ln.exception = t.text
		n = ln
	}
	return n, nil
}

func (p *parser) parsePrimary() (spdxNode, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("license: unexpected end of SPDX expression")
	}
	switch t.kind {
	case tLParen:
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if c := p.peek(); c == nil || c.kind != tRParen {
			return nil, fmt.Errorf("license: expected ')' to close a group")
		}
		p.next()
		return inner, nil
	case tIdent:
		p.next()
		id := t.text
		orLater := false
		if strings.HasSuffix(id, "+") {
			orLater = true
			id = strings.TrimSuffix(id, "+")
		}
		if id == "" {
			return nil, fmt.Errorf("license: empty license identifier")
		}
		return licenseNode{id: id, orLater: orLater}, nil
	default:
		return nil, fmt.Errorf("license: unexpected token %q", t.text)
	}
}

// --- rendering --------------------------------------------------------------

// render produces a canonical textual form of the tree, parenthesizing an OR
// child of an AND so precedence is unambiguous.
func render(n spdxNode) string {
	switch t := n.(type) {
	case licenseNode:
		var b strings.Builder
		b.WriteString(t.id)
		if t.orLater {
			b.WriteByte('+')
		}
		if t.exception != "" {
			b.WriteString(" WITH ")
			b.WriteString(t.exception)
		}
		return b.String()
	case opNode:
		l := render(t.left)
		r := render(t.right)
		if t.op == "AND" {
			l = parenIfOr(t.left, l)
			r = parenIfOr(t.right, r)
		}
		return l + " " + t.op + " " + r
	default:
		return ""
	}
}

// parenIfOr wraps a rendered child in parentheses when it is an OR node, so it
// is not mis-associated under a tighter-binding AND.
func parenIfOr(n spdxNode, rendered string) string {
	if op, ok := n.(opNode); ok && op.op == "OR" {
		return "(" + rendered + ")"
	}
	return rendered
}
