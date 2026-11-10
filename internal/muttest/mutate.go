// Package muttest implements a self-contained, deterministic mutation-testing
// harness and a committed test-quality gate for the proxy's highest-risk
// admission-gate packages (vulnscan, sigverify, policyengine, riskscore,
// depfirewall, and the content gates). It is the fault-detection analogue of
// the statement-coverage gate (internal/covguard, Task 117): where coverage
// asks "did a test execute this line?", mutation testing asks the sharper
// question "would a test actually *fail* if this line's behavior were wrong?".
//
// The engine seeds small, behavior-changing faults ("mutants") into a package's
// source — flipping comparison and logical operators, swapping boolean
// constants, negating conditions, and so on — then recompiles the package's
// test binary and runs it. A mutant that makes the suite fail is "killed" (the
// tests caught the fault); a mutant the suite still passes is a "survivor" (a
// gap in fault detection). The mutation score is killed / (killed + survived).
//
// The whole harness is built on the Go standard library (go/ast, go/parser,
// go/token and the `go` toolchain) with no third-party mutation tool, so it is
// reproducible and has no external binary dependency. Enumeration is stably
// ordered and any sampling is seeded, so a given (seed, package, mutant cap)
// always produces the same mutant set and therefore a stable CI gate.
package muttest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Operator keys. Each models a class of real defect the admission gates must be
// protected against — an inverted comparison, a swapped boolean connective, a
// flipped constant, or a negated guard condition.
const (
	// OpROR replaces a relational/equality operator (==, !=, <, <=, >, >=) with a
	// boundary- or negation-shifted operator. Models off-by-one and inverted
	// threshold checks (e.g. a severity or cooldown comparison).
	OpROR = "ROR"
	// OpLCR replaces a logical connective (&& <-> ||). Models a gate that ANDs
	// conditions it should OR (or vice versa).
	OpLCR = "LCR"
	// OpAOR replaces an arithmetic operator (+, -, *, /, %). Models miscomputed
	// scores, counts, and sizes.
	OpAOR = "AOR"
	// OpBool swaps a boolean constant (true <-> false). Models an allow/deny
	// default or a "scanned"/"verified" flag stuck at the wrong value.
	OpBool = "BOOL"
	// OpCond negates an `if` condition (cond -> !(cond)). Models a guard that
	// admits exactly what it should block — the canonical admission-gate fault.
	OpCond = "COND"
	// OpNeg removes a unary logical negation (!x -> x). Models a dropped "not".
	OpNeg = "NEG"
	// OpIncDec swaps ++ <-> -- in an increment/decrement statement.
	OpIncDec = "INCDEC"
)

// DefaultOperators is the operator set enabled when none is specified. It is the
// curated, high-signal set for security-gate logic: relational, logical,
// arithmetic, boolean-constant, condition-negation, not-removal and inc/dec.
func DefaultOperators() []string {
	return []string{OpROR, OpLCR, OpAOR, OpBool, OpCond, OpNeg, OpIncDec}
}

// AllOperators returns every operator key the engine understands.
func AllOperators() []string { return DefaultOperators() }

// relationalMut maps a relational/equality token to its replacement tokens.
var relationalMut = map[token.Token][]token.Token{
	token.EQL: {token.NEQ},
	token.NEQ: {token.EQL},
	token.LSS: {token.LEQ, token.GEQ},
	token.LEQ: {token.LSS, token.GTR},
	token.GTR: {token.GEQ, token.LEQ},
	token.GEQ: {token.GTR, token.LSS},
}

// logicalMut maps a logical connective to its replacement.
var logicalMut = map[token.Token][]token.Token{
	token.LAND: {token.LOR},
	token.LOR:  {token.LAND},
}

// arithMut maps an arithmetic operator to its replacement(s).
var arithMut = map[token.Token][]token.Token{
	token.ADD: {token.SUB},
	token.SUB: {token.ADD},
	token.MUL: {token.QUO},
	token.QUO: {token.MUL},
	token.REM: {token.MUL},
}

// Edit is a single byte-range splice into the original source of one file. A
// mutant applies one or more non-overlapping edits atomically.
type Edit struct {
	Start       int    // inclusive byte offset into the file's original source
	End         int    // exclusive byte offset
	Replacement string // text to splice in place of [Start,End)
}

// Mutant is one candidate fault seeded into a single source file. Mutation is
// text-based (exact byte-range splices from AST token positions) rather than
// AST re-printing, so an applied mutant touches only the mutated token(s) and
// never reformats the surrounding file.
type Mutant struct {
	ID       string `json:"id"`       // stable short hash, used for the equivalent-mutant ignore list
	Package  string `json:"package"`  // full import path of the owning package
	File     string `json:"file"`     // module-relative source file path
	Line     int    `json:"line"`     // 1-based line of the mutated token
	Col      int    `json:"col"`      // 1-based column
	Operator string `json:"operator"` // operator key (OpROR, OpLCR, ...)
	Original string `json:"original"` // original token/snippet
	Mutated  string `json:"mutated"`  // mutated token/snippet

	absFile string // absolute path, for on-disk mutation
	offset  int    // byte offset of the primary token, for stable ordering
	edits   []Edit // the byte splices that realize this mutant
}

// Edits returns the byte splices that realize the mutant (read-only accessor
// used by the engine to apply/restore).
func (m Mutant) Edits() []Edit { return m.edits }

// AbsFile returns the absolute path of the file the mutant lives in.
func (m Mutant) AbsFile() string { return m.absFile }

// Describe renders a one-line, human-readable description for reports.
func (m Mutant) Describe() string {
	return fmt.Sprintf("%s:%d:%d [%s] %s -> %s", m.File, m.Line, m.Col, m.Operator, m.Original, m.Mutated)
}

// computeID derives a stable identifier from the mutant's semantic coordinates.
// It intentionally excludes byte offsets so two runs over identical source
// agree; it necessarily shifts when the surrounding code changes (line/col
// move), which callers treat the same way they treat any line-anchored note.
func computeID(importPath, relFile string, line, col int, op, from, to string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d|%s|%s|%s", importPath, relFile, line, col, op, from, to)))
	return hex.EncodeToString(h[:])[:12]
}

// EnumerateFile parses a single Go source file and returns every mutant the
// enabled operators can seed into it, in stable (offset, operator, mutated)
// order. importPath is the owning package's import path; relFile is the
// module-relative path recorded on each mutant. enabled is the set of enabled
// operator keys.
func EnumerateFile(absPath, importPath, relFile string, enabled map[string]bool) ([]Mutant, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, absPath, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", relFile, err)
	}

	// Pre-pass: collect identifier positions that are NOT value uses of the
	// predeclared true/false — selector fields/methods (x.Sel) and declaration
	// names (struct fields, parameters, named results, vars) — so an identifier
	// that merely happens to be named true/false is never mutated as a boolean
	// constant (which would only ever yield a compile error or a rename).
	skipIdent := map[token.Pos]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if node.Sel != nil {
				skipIdent[node.Sel.Pos()] = true
			}
		case *ast.Field:
			for _, name := range node.Names {
				skipIdent[name.Pos()] = true
			}
		case *ast.ValueSpec:
			for _, name := range node.Names {
				skipIdent[name.Pos()] = true
			}
		}
		return true
	})

	var out []Mutant
	add := func(op string, primaryPos token.Pos, original, mutated string, edits []Edit) {
		pos := fset.Position(primaryPos)
		m := Mutant{
			Package:  importPath,
			File:     relFile,
			Line:     pos.Line,
			Col:      pos.Column,
			Operator: op,
			Original: original,
			Mutated:  mutated,
			absFile:  absPath,
			offset:   pos.Offset,
			edits:    edits,
		}
		m.ID = computeID(importPath, relFile, pos.Line, pos.Column, op, original, mutated)
		out = append(out, m)
	}

	tokenLen := func(t token.Token) int { return len(t.String()) }

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			opOff := fset.Position(node.OpPos).Offset
			from := node.Op.String()
			var reps []token.Token
			var key string
			switch {
			case isRelational(node.Op):
				reps, key = relationalMut[node.Op], OpROR
			case isLogical(node.Op):
				reps, key = logicalMut[node.Op], OpLCR
			case isArith(node.Op):
				reps, key = arithMut[node.Op], OpAOR
			}
			if enabled[key] {
				for _, r := range reps {
					to := r.String()
					add(key, node.OpPos, from, to, []Edit{{Start: opOff, End: opOff + tokenLen(node.Op), Replacement: to}})
				}
			}
		case *ast.UnaryExpr:
			if node.Op == token.NOT && enabled[OpNeg] {
				off := fset.Position(node.OpPos).Offset
				// Remove the leading '!' only; the operand text is untouched.
				add(OpNeg, node.OpPos, "!", "", []Edit{{Start: off, End: off + 1, Replacement: ""}})
			}
		case *ast.IncDecStmt:
			if enabled[OpIncDec] {
				off := fset.Position(node.TokPos).Offset
				to := token.INC.String()
				if node.Tok == token.INC {
					to = token.DEC.String()
				}
				add(OpIncDec, node.TokPos, node.Tok.String(), to, []Edit{{Start: off, End: off + 2, Replacement: to}})
			}
		case *ast.Ident:
			if enabled[OpBool] && (node.Name == "true" || node.Name == "false") && !skipIdent[node.Pos()] {
				off := fset.Position(node.Pos()).Offset
				to := "false"
				if node.Name == "false" {
					to = "true"
				}
				add(OpBool, node.Pos(), node.Name, to, []Edit{{Start: off, End: off + len(node.Name), Replacement: to}})
			}
		case *ast.IfStmt:
			if enabled[OpCond] && node.Cond != nil {
				start := fset.Position(node.Cond.Pos()).Offset
				end := fset.Position(node.Cond.End()).Offset
				orig := string(src[start:end])
				// Wrap the whole condition: `if cond` -> `if !(cond)`.
				edits := []Edit{
					{Start: start, End: start, Replacement: "!("},
					{Start: end, End: end, Replacement: ")"},
				}
				add(OpCond, node.Cond.Pos(), orig, "!("+orig+")", edits)
			}
		}
		return true
	})

	sortMutants(out)
	return out, nil
}

func isRelational(t token.Token) bool {
	switch t {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	}
	return false
}

func isLogical(t token.Token) bool { return t == token.LAND || t == token.LOR }

func isArith(t token.Token) bool {
	switch t {
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM:
		return true
	}
	return false
}

// sortMutants orders mutants deterministically: by file, then source offset,
// then operator, then mutated text. This fixes the enumeration order so seeded
// sampling and reports are reproducible.
func sortMutants(ms []Mutant) {
	sort.Slice(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.offset != b.offset {
			return a.offset < b.offset
		}
		if a.Operator != b.Operator {
			return a.Operator < b.Operator
		}
		return a.Mutated < b.Mutated
	})
}

// Apply returns src with the mutant's edits spliced in. The input slice is not
// modified. Edits are applied right-to-left so earlier offsets stay valid.
func Apply(src []byte, m Mutant) []byte {
	edits := append([]Edit(nil), m.edits...)
	sort.Slice(edits, func(i, j int) bool { return edits[i].Start > edits[j].Start })
	out := append([]byte(nil), src...)
	for _, e := range edits {
		if e.Start < 0 || e.End > len(out) || e.Start > e.End {
			continue // defensive: never splice out of range
		}
		spliced := make([]byte, 0, len(out)-(e.End-e.Start)+len(e.Replacement))
		spliced = append(spliced, out[:e.Start]...)
		spliced = append(spliced, e.Replacement...)
		spliced = append(spliced, out[e.End:]...)
		out = spliced
	}
	return out
}

// goSourceFiles lists the non-test Go source files in a package directory,
// sorted for determinism. Files with the _test.go suffix are excluded because
// mutating test code would be meaningless.
func goSourceFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	sort.Strings(files)
	return files, nil
}
