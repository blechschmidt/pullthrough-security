// Package policyengine evaluates externally-authored, declarative admission
// rules against a structured input document aggregating the signals produced by
// the proxy's existing security gates (vulnerability findings, VEX status,
// license verdicts, signature/attestation results, secret-scan risk, nameguard
// score, and provenance association).
//
// Rather than depend on a large external policy runtime (OPA/Rego or cel-go and
// its transitive protobuf/antlr dependencies), this package embeds a small,
// self-contained, pure-Go evaluator for a curated subset of the CEL expression
// language. Keeping the evaluator hermetic matters for a supply-chain-security
// product whose own dependency surface is part of its threat model, and for the
// air-gapped deployment mode (Task 17) where build- and run-time dependency
// fetching is undesirable.
//
// The supported language is intentionally a strict, side-effect-free subset:
// boolean/arithmetic/relational operators, the ternary conditional, the `in`
// membership operator, member and index access over the input document, and a
// fixed set of pure functions (has, size, lower, upper, string, int, double,
// contains, startsWith, endsWith, matches) usable in both free and method-call
// form. There are no user-defined functions, loops, or comprehensions, so an
// adversarially-authored rule cannot loop or recurse unboundedly.
package policyengine

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Program is a compiled expression ready for repeated evaluation against
// different input documents. It is immutable and safe for concurrent use.
type Program struct {
	src  string
	root node
}

// Compile parses and type-checks (structurally) a CEL-subset expression source
// into a reusable Program. A compile error is returned for malformed syntax; it
// does not evaluate the expression, so it cannot fail on missing input fields.
func Compile(src string) (*Program, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, fmt.Errorf("policyengine: lex %q: %w", src, err)
	}
	p := &parser{toks: toks, src: src}
	root, err := p.parseExpression()
	if err != nil {
		return nil, fmt.Errorf("policyengine: parse %q: %w", src, err)
	}
	if p.cur().kind != tokEOF {
		return nil, fmt.Errorf("policyengine: parse %q: unexpected trailing token %q", src, p.cur().text)
	}
	return &Program{src: src, root: root}, nil
}

// Source returns the original expression text.
func (p *Program) Source() string { return p.src }

// EvalBool evaluates the program against the document and coerces the result to
// a boolean. A non-boolean result is an error; this is the form admission rules
// use, where a `when` clause must yield a definite true/false.
func (p *Program) EvalBool(doc map[string]any) (bool, error) {
	v, err := p.Eval(doc)
	if err != nil {
		// A predicate that resolves entirely to an absent field is treated as a
		// clean false rather than an error, so `input.license.denied` on a
		// license-less input is usable without an explicit has() guard.
		if _, ok := err.(errMissing); ok {
			return false, nil
		}
		return false, err
	}
	// A null result (e.g. a guarded access that bottomed out) is also false.
	if v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("policyengine: expression %q did not evaluate to a boolean (got %T)", p.src, v)
	}
	return b, nil
}

// Eval evaluates the program against the document, returning the raw value.
func (p *Program) Eval(doc map[string]any) (v any, err error) {
	// Guard against any unexpected evaluator panic (e.g. a pathological input
	// shape) so a single malformed rule can never crash the admission path.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("policyengine: evaluation panicked on %q: %v", p.src, r)
		}
	}()
	ev := &evaluator{root: doc}
	return ev.eval(p.root)
}

// --- lexer ------------------------------------------------------------------

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokInt
	tokFloat
	tokString
	tokIdent
	tokOp     // operators and punctuation
	tokKwTrue // true/false/null/in handled as keywords below
	tokKwFalse
	tokKwNull
	tokKwIn
)

type token struct {
	kind tokenKind
	text string
}

func lex(src string) ([]token, error) {
	var toks []token
	i := 0
	n := len(src)
	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c >= '0' && c <= '9':
			start := i
			isFloat := false
			for i < n && (src[i] >= '0' && src[i] <= '9') {
				i++
			}
			if i < n && src[i] == '.' && i+1 < n && src[i+1] >= '0' && src[i+1] <= '9' {
				isFloat = true
				i++
				for i < n && (src[i] >= '0' && src[i] <= '9') {
					i++
				}
			}
			if i < n && (src[i] == 'e' || src[i] == 'E') {
				isFloat = true
				i++
				if i < n && (src[i] == '+' || src[i] == '-') {
					i++
				}
				for i < n && (src[i] >= '0' && src[i] <= '9') {
					i++
				}
			}
			kind := tokInt
			if isFloat {
				kind = tokFloat
			}
			toks = append(toks, token{kind, src[start:i]})
		case c == '"' || c == '\'':
			s, ni, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokString, s})
			i = ni
		case isIdentStart(c):
			start := i
			for i < n && isIdentPart(src[i]) {
				i++
			}
			word := src[start:i]
			switch word {
			case "true":
				toks = append(toks, token{tokKwTrue, word})
			case "false":
				toks = append(toks, token{tokKwFalse, word})
			case "null":
				toks = append(toks, token{tokKwNull, word})
			case "in":
				toks = append(toks, token{tokKwIn, word})
			default:
				toks = append(toks, token{tokIdent, word})
			}
		default:
			op, ni, err := lexOperator(src, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokOp, op})
			i = ni
		}
	}
	toks = append(toks, token{tokEOF, ""})
	return toks, nil
}

func lexString(src string, i int) (string, int, error) {
	quote := src[i]
	i++
	var b strings.Builder
	for i < len(src) {
		c := src[i]
		if c == '\\' {
			if i+1 >= len(src) {
				return "", 0, fmt.Errorf("policyengine: unterminated escape in string literal")
			}
			esc := src[i+1]
			switch esc {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case '\'':
				b.WriteByte('\'')
			default:
				b.WriteByte(esc)
			}
			i += 2
			continue
		}
		if c == quote {
			return b.String(), i + 1, nil
		}
		b.WriteByte(c)
		i++
	}
	return "", 0, fmt.Errorf("policyengine: unterminated string literal")
}

func lexOperator(src string, i int) (string, int, error) {
	two := ""
	if i+1 < len(src) {
		two = src[i : i+2]
	}
	switch two {
	case "==", "!=", "<=", ">=", "&&", "||":
		return two, i + 2, nil
	}
	switch src[i] {
	case '+', '-', '*', '/', '%', '<', '>', '!', '(', ')', '[', ']', '.', ',', '?', ':':
		return string(src[i]), i + 1, nil
	}
	return "", 0, fmt.Errorf("policyengine: unexpected character %q", string(src[i]))
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// --- AST --------------------------------------------------------------------

type node interface{}

type litNode struct{ val any }
type identNode struct{ name string }
type memberNode struct {
	recv node
	name string
}
type indexNode struct {
	recv  node
	index node
}
type callNode struct {
	fn   string // function name (or method name)
	recv node   // non-nil for method-call form
	args []node
}
type unaryNode struct {
	op  string
	val node
}
type binaryNode struct {
	op          string
	left, right node
}
type ternaryNode struct {
	cond, then, els node
}
type listNode struct{ elems []node }

// --- parser -----------------------------------------------------------------

type parser struct {
	toks []token
	pos  int
	src  string
}

func (p *parser) cur() token  { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) expectOp(op string) error {
	t := p.cur()
	if t.kind != tokOp || t.text != op {
		return fmt.Errorf("expected %q, got %q", op, t.text)
	}
	p.pos++
	return nil
}

func (p *parser) parseExpression() (node, error) { return p.parseTernary() }

func (p *parser) parseTernary() (node, error) {
	cond, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.cur().kind == tokOp && p.cur().text == "?" {
		p.next()
		then, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if err := p.expectOp(":"); err != nil {
			return nil, err
		}
		els, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		return &ternaryNode{cond, then, els}, nil
	}
	return cond, nil
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tokOp && p.cur().text == "||" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binaryNode{"||", left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tokOp && p.cur().text == "&&" {
		p.next()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = &binaryNode{"&&", left, right}
	}
	return left, nil
}

func (p *parser) parseComparison() (node, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}
	for {
		t := p.cur()
		if t.kind == tokKwIn {
			p.next()
			right, err := p.parseAdditive()
			if err != nil {
				return nil, err
			}
			left = &binaryNode{"in", left, right}
			continue
		}
		if t.kind == tokOp {
			switch t.text {
			case "==", "!=", "<", "<=", ">", ">=":
				p.next()
				right, err := p.parseAdditive()
				if err != nil {
					return nil, err
				}
				left = &binaryNode{t.text, left, right}
				continue
			}
		}
		return left, nil
	}
}

func (p *parser) parseAdditive() (node, error) {
	left, err := p.parseMultiplicative()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tokOp && (p.cur().text == "+" || p.cur().text == "-") {
		op := p.next().text
		right, err := p.parseMultiplicative()
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op, left, right}
	}
	return left, nil
}

func (p *parser) parseMultiplicative() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tokOp && (p.cur().text == "*" || p.cur().text == "/" || p.cur().text == "%") {
		op := p.next().text
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op, left, right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	t := p.cur()
	if t.kind == tokOp && (t.text == "!" || t.text == "-") {
		p.next()
		val, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &unaryNode{t.text, val}, nil
	}
	return p.parsePostfix()
}

func (p *parser) parsePostfix() (node, error) {
	expr, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.cur()
		if t.kind == tokOp && t.text == "." {
			p.next()
			id := p.cur()
			if id.kind != tokIdent {
				return nil, fmt.Errorf("expected identifier after '.', got %q", id.text)
			}
			p.next()
			// Method-call form: recv.name(args)
			if p.cur().kind == tokOp && p.cur().text == "(" {
				args, err := p.parseArgs()
				if err != nil {
					return nil, err
				}
				expr = &callNode{fn: id.text, recv: expr, args: args}
				continue
			}
			expr = &memberNode{recv: expr, name: id.text}
			continue
		}
		if t.kind == tokOp && t.text == "[" {
			p.next()
			idx, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp("]"); err != nil {
				return nil, err
			}
			expr = &indexNode{recv: expr, index: idx}
			continue
		}
		return expr, nil
	}
}

func (p *parser) parseArgs() ([]node, error) {
	if err := p.expectOp("("); err != nil {
		return nil, err
	}
	var args []node
	if p.cur().kind == tokOp && p.cur().text == ")" {
		p.next()
		return args, nil
	}
	for {
		arg, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if p.cur().kind == tokOp && p.cur().text == "," {
			p.next()
			continue
		}
		break
	}
	if err := p.expectOp(")"); err != nil {
		return nil, err
	}
	return args, nil
}

func (p *parser) parsePrimary() (node, error) {
	t := p.cur()
	switch t.kind {
	case tokInt:
		p.next()
		v, err := strconv.ParseInt(t.text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q", t.text)
		}
		return &litNode{v}, nil
	case tokFloat:
		p.next()
		v, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float %q", t.text)
		}
		return &litNode{v}, nil
	case tokString:
		p.next()
		return &litNode{t.text}, nil
	case tokKwTrue:
		p.next()
		return &litNode{true}, nil
	case tokKwFalse:
		p.next()
		return &litNode{false}, nil
	case tokKwNull:
		p.next()
		return &litNode{nil}, nil
	case tokIdent:
		p.next()
		// Free function call form: ident(args)
		if p.cur().kind == tokOp && p.cur().text == "(" {
			args, err := p.parseArgs()
			if err != nil {
				return nil, err
			}
			return &callNode{fn: t.text, args: args}, nil
		}
		return &identNode{t.text}, nil
	case tokOp:
		switch t.text {
		case "(":
			p.next()
			inner, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			return inner, nil
		case "[":
			return p.parseList()
		}
	}
	return nil, fmt.Errorf("unexpected token %q", t.text)
}

func (p *parser) parseList() (node, error) {
	if err := p.expectOp("["); err != nil {
		return nil, err
	}
	var elems []node
	if p.cur().kind == tokOp && p.cur().text == "]" {
		p.next()
		return &listNode{elems}, nil
	}
	for {
		e, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		elems = append(elems, e)
		if p.cur().kind == tokOp && p.cur().text == "," {
			p.next()
			continue
		}
		break
	}
	if err := p.expectOp("]"); err != nil {
		return nil, err
	}
	return &listNode{elems}, nil
}

// --- evaluator --------------------------------------------------------------

// errMissing is a sentinel signalling that a member/index access targeted an
// absent key. It is consumed by has() (which maps it to false) and otherwise
// surfaces values as nil so that, e.g., `input.signature.verified` on a
// signature-less input yields a clean false rather than an error.
type errMissing struct{ path string }

func (e errMissing) Error() string { return "missing field: " + e.path }

type evaluator struct {
	root map[string]any
}

func (ev *evaluator) eval(n node) (any, error) {
	switch x := n.(type) {
	case *litNode:
		return x.val, nil
	case *identNode:
		if x.name == "input" {
			return ev.root, nil
		}
		v, ok := ev.root[x.name]
		if !ok {
			return nil, errMissing{x.name}
		}
		return v, nil
	case *listNode:
		out := make([]any, 0, len(x.elems))
		for _, e := range x.elems {
			v, err := ev.eval(e)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case *memberNode:
		recv, err := ev.evalPresence(x.recv)
		if err != nil {
			return nil, err
		}
		m, ok := recv.(map[string]any)
		if !ok {
			if recv == nil {
				return nil, errMissing{x.name}
			}
			return nil, fmt.Errorf("cannot access field %q on %T", x.name, recv)
		}
		v, ok := m[x.name]
		if !ok {
			return nil, errMissing{x.name}
		}
		return v, nil
	case *indexNode:
		return ev.evalIndex(x)
	case *unaryNode:
		return ev.evalUnary(x)
	case *binaryNode:
		return ev.evalBinary(x)
	case *ternaryNode:
		c, err := ev.evalBoolOperand(x.cond)
		if err != nil {
			return nil, err
		}
		if c {
			return ev.eval(x.then)
		}
		return ev.eval(x.els)
	case *callNode:
		return ev.evalCall(x)
	}
	return nil, fmt.Errorf("unknown node type %T", n)
}

// evalPresence evaluates a receiver, mapping a missing-field result to a nil
// value rather than an error so chained accesses degrade gracefully.
func (ev *evaluator) evalPresence(n node) (any, error) {
	v, err := ev.eval(n)
	if err != nil {
		if _, ok := err.(errMissing); ok {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

func (ev *evaluator) evalIndex(x *indexNode) (any, error) {
	recv, err := ev.eval(x.recv)
	if err != nil {
		return nil, err
	}
	idx, err := ev.eval(x.index)
	if err != nil {
		return nil, err
	}
	switch c := recv.(type) {
	case []any:
		i, ok := toInt(idx)
		if !ok {
			return nil, fmt.Errorf("list index must be an integer, got %T", idx)
		}
		if i < 0 || i >= int64(len(c)) {
			return nil, fmt.Errorf("list index %d out of range (len %d)", i, len(c))
		}
		return c[i], nil
	case map[string]any:
		key, ok := idx.(string)
		if !ok {
			return nil, fmt.Errorf("map index must be a string, got %T", idx)
		}
		v, ok := c[key]
		if !ok {
			return nil, errMissing{key}
		}
		return v, nil
	}
	return nil, fmt.Errorf("cannot index %T", recv)
}

func (ev *evaluator) evalUnary(x *unaryNode) (any, error) {
	switch x.op {
	case "!":
		b, err := ev.evalBoolOperand(x.val)
		if err != nil {
			return nil, err
		}
		return !b, nil
	case "-":
		v, err := ev.eval(x.val)
		if err != nil {
			return nil, err
		}
		switch n := v.(type) {
		case int64:
			return -n, nil
		case float64:
			return -n, nil
		}
		return nil, fmt.Errorf("unary '-' requires a number, got %T", v)
	}
	return nil, fmt.Errorf("unknown unary operator %q", x.op)
}

func (ev *evaluator) evalBinary(x *binaryNode) (any, error) {
	// Short-circuiting logical operators.
	switch x.op {
	case "&&":
		l, err := ev.evalBoolOperand(x.left)
		if err != nil {
			return nil, err
		}
		if !l {
			return false, nil
		}
		return ev.evalBoolOperand(x.right)
	case "||":
		l, err := ev.evalBoolOperand(x.left)
		if err != nil {
			return nil, err
		}
		if l {
			return true, nil
		}
		return ev.evalBoolOperand(x.right)
	}

	left, err := ev.eval(x.left)
	if err != nil {
		return nil, err
	}
	right, err := ev.eval(x.right)
	if err != nil {
		return nil, err
	}

	switch x.op {
	case "==":
		return equals(left, right), nil
	case "!=":
		return !equals(left, right), nil
	case "in":
		return member(left, right)
	case "<", "<=", ">", ">=":
		return compare(x.op, left, right)
	case "+", "-", "*", "/", "%":
		return arithmetic(x.op, left, right)
	}
	return nil, fmt.Errorf("unknown binary operator %q", x.op)
}

// evalBoolOperand evaluates n and coerces a missing-field result to false so
// that logical expressions over absent inputs behave intuitively.
func (ev *evaluator) evalBoolOperand(n node) (bool, error) {
	v, err := ev.eval(n)
	if err != nil {
		if _, ok := err.(errMissing); ok {
			return false, nil
		}
		return false, err
	}
	if v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expected boolean, got %T", v)
	}
	return b, nil
}

func (ev *evaluator) evalCall(x *callNode) (any, error) {
	// has() is special: it tests presence without erroring on missing fields.
	if x.fn == "has" && x.recv == nil {
		if len(x.args) != 1 {
			return nil, fmt.Errorf("has() takes exactly one argument")
		}
		v, err := ev.eval(x.args[0])
		if err != nil {
			if _, ok := err.(errMissing); ok {
				return false, nil
			}
			return nil, err
		}
		return v != nil, nil
	}

	args := make([]any, 0, len(x.args)+1)
	if x.recv != nil {
		rv, err := ev.eval(x.recv)
		if err != nil {
			return nil, err
		}
		args = append(args, rv)
	}
	for _, a := range x.args {
		v, err := ev.eval(a)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	return callFunction(x.fn, args)
}

// --- value helpers ----------------------------------------------------------

func toInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		if n == math.Trunc(n) {
			return int64(n), true
		}
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func equals(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	// Numeric equality across int/float.
	if af, aok := toFloat(a); aok {
		if bf, bok := toFloat(b); bok {
			return af == bf
		}
		return false
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !equals(av[i], bv[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func member(needle, haystack any) (any, error) {
	switch h := haystack.(type) {
	case []any:
		for _, e := range h {
			if equals(needle, e) {
				return true, nil
			}
		}
		return false, nil
	case map[string]any:
		key, ok := needle.(string)
		if !ok {
			return false, fmt.Errorf("'in' over a map requires a string key, got %T", needle)
		}
		_, ok = h[key]
		return ok, nil
	}
	return nil, fmt.Errorf("'in' requires a list or map on the right-hand side, got %T", haystack)
}

func compare(op string, a, b any) (any, error) {
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return nil, fmt.Errorf("cannot compare string with %T", b)
		}
		return cmpResult(op, strings.Compare(as, bs)), nil
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if !aok || !bok {
		return nil, fmt.Errorf("cannot compare %T with %T", a, b)
	}
	switch {
	case af < bf:
		return cmpResult(op, -1), nil
	case af > bf:
		return cmpResult(op, 1), nil
	default:
		return cmpResult(op, 0), nil
	}
}

func cmpResult(op string, c int) bool {
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	}
	return false
}

func arithmetic(op string, a, b any) (any, error) {
	// String concatenation.
	if op == "+" {
		if as, ok := a.(string); ok {
			bs, ok := b.(string)
			if !ok {
				return nil, fmt.Errorf("cannot add string and %T", b)
			}
			return as + bs, nil
		}
	}
	ai, aIsInt := a.(int64)
	bi, bIsInt := b.(int64)
	if aIsInt && bIsInt {
		switch op {
		case "+":
			return ai + bi, nil
		case "-":
			return ai - bi, nil
		case "*":
			return ai * bi, nil
		case "/":
			if bi == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return ai / bi, nil
		case "%":
			if bi == 0 {
				return nil, fmt.Errorf("modulo by zero")
			}
			return ai % bi, nil
		}
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if !aok || !bok {
		return nil, fmt.Errorf("arithmetic requires numbers, got %T and %T", a, b)
	}
	switch op {
	case "+":
		return af + bf, nil
	case "-":
		return af - bf, nil
	case "*":
		return af * bf, nil
	case "/":
		if bf == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return af / bf, nil
	case "%":
		return nil, fmt.Errorf("modulo requires integer operands")
	}
	return nil, fmt.Errorf("unknown arithmetic operator %q", op)
}

// callFunction dispatches the fixed set of built-in functions. Method-call form
// (recv.fn(args)) arrives here with the receiver as args[0].
func callFunction(name string, args []any) (any, error) {
	switch name {
	case "size":
		if len(args) != 1 {
			return nil, fmt.Errorf("size() takes one argument")
		}
		switch c := args[0].(type) {
		case string:
			return int64(len(c)), nil
		case []any:
			return int64(len(c)), nil
		case map[string]any:
			return int64(len(c)), nil
		case nil:
			return int64(0), nil
		}
		return nil, fmt.Errorf("size() requires a string, list, or map, got %T", args[0])
	case "lower":
		s, err := strArg(name, args, 1)
		if err != nil {
			return nil, err
		}
		return strings.ToLower(s), nil
	case "upper":
		s, err := strArg(name, args, 1)
		if err != nil {
			return nil, err
		}
		return strings.ToUpper(s), nil
	case "string":
		if len(args) != 1 {
			return nil, fmt.Errorf("string() takes one argument")
		}
		return toStringValue(args[0]), nil
	case "int":
		if len(args) != 1 {
			return nil, fmt.Errorf("int() takes one argument")
		}
		if i, ok := toInt(args[0]); ok {
			return i, nil
		}
		if s, ok := args[0].(string); ok {
			i, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("int(%q): %w", s, err)
			}
			return i, nil
		}
		return nil, fmt.Errorf("int() cannot convert %T", args[0])
	case "double":
		if len(args) != 1 {
			return nil, fmt.Errorf("double() takes one argument")
		}
		if f, ok := toFloat(args[0]); ok {
			return f, nil
		}
		if s, ok := args[0].(string); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if err != nil {
				return nil, fmt.Errorf("double(%q): %w", s, err)
			}
			return f, nil
		}
		return nil, fmt.Errorf("double() cannot convert %T", args[0])
	case "contains":
		return strBinary(name, args, strings.Contains)
	case "startsWith":
		return strBinary(name, args, strings.HasPrefix)
	case "endsWith":
		return strBinary(name, args, strings.HasSuffix)
	case "matches":
		if len(args) != 2 {
			return nil, fmt.Errorf("matches() takes a string and a pattern")
		}
		s, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("matches() receiver must be a string, got %T", args[0])
		}
		pat, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("matches() pattern must be a string, got %T", args[1])
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("matches() invalid pattern %q: %w", pat, err)
		}
		return re.MatchString(s), nil
	}
	return nil, fmt.Errorf("unknown function %q", name)
}

func strArg(name string, args []any, n int) (string, error) {
	if len(args) != n {
		return "", fmt.Errorf("%s() takes %d argument(s)", name, n)
	}
	s, ok := args[0].(string)
	if !ok {
		return "", fmt.Errorf("%s() requires a string, got %T", name, args[0])
	}
	return s, nil
}

func strBinary(name string, args []any, fn func(string, string) bool) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("%s() takes two strings", name)
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("%s() receiver must be a string, got %T", name, args[0])
	}
	sub, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("%s() argument must be a string, got %T", name, args[1])
	}
	return fn(s, sub), nil
}

func toStringValue(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case float64:
		return strconv.FormatFloat(s, 'g', -1, 64)
	}
	return fmt.Sprintf("%v", v)
}
