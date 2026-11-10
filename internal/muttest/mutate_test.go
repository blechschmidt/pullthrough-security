package muttest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempGo writes src to a temp .go file and returns its path.
func writeTempGo(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatalf("write temp go: %v", err)
	}
	return p
}

func enabledAll() map[string]bool {
	set := map[string]bool{}
	for _, op := range DefaultOperators() {
		set[op] = true
	}
	return set
}

func countOp(ms []Mutant, op string) int {
	n := 0
	for _, m := range ms {
		if m.Operator == op {
			n++
		}
	}
	return n
}

func TestEnumerateOperators(t *testing.T) {
	src := `package p

func f(a, b int, ok bool) int {
	if a < b && ok {
		return a + b
	}
	if !ok {
		return 0
	}
	flag := true
	_ = flag
	a++
	return a - b
}
`
	p := writeTempGo(t, src)
	ms, err := EnumerateFile(p, "example.com/p", "p/sample.go", enabledAll())
	if err != nil {
		t.Fatalf("EnumerateFile: %v", err)
	}
	// ROR on `a < b` yields two replacements (<=, >=).
	if got := countOp(ms, OpROR); got < 2 {
		t.Errorf("expected >=2 ROR mutants, got %d", got)
	}
	// LCR on `&&`.
	if got := countOp(ms, OpLCR); got != 1 {
		t.Errorf("expected 1 LCR mutant, got %d", got)
	}
	// AOR on `a + b` and `a - b`: each has one replacement.
	if got := countOp(ms, OpAOR); got != 2 {
		t.Errorf("expected 2 AOR mutants, got %d", got)
	}
	// BOOL on `true`.
	if got := countOp(ms, OpBool); got != 1 {
		t.Errorf("expected 1 BOOL mutant, got %d", got)
	}
	// NEG on `!ok`.
	if got := countOp(ms, OpNeg); got != 1 {
		t.Errorf("expected 1 NEG mutant, got %d", got)
	}
	// INCDEC on `a++`.
	if got := countOp(ms, OpIncDec); got != 1 {
		t.Errorf("expected 1 INCDEC mutant, got %d", got)
	}
	// COND on each of the two `if` statements.
	if got := countOp(ms, OpCond); got != 2 {
		t.Errorf("expected 2 COND mutants, got %d", got)
	}

	// IDs must be unique and stable.
	seen := map[string]bool{}
	for _, m := range ms {
		if m.ID == "" {
			t.Errorf("mutant has empty ID: %s", m.Describe())
		}
		if seen[m.ID] {
			t.Errorf("duplicate mutant ID %s for %s", m.ID, m.Describe())
		}
		seen[m.ID] = true
	}
}

func TestEnumerateDeterministic(t *testing.T) {
	src := `package p

func g(x int) bool { return x == 1 || x == 2 }
`
	p := writeTempGo(t, src)
	a, err := EnumerateFile(p, "example.com/p", "p/sample.go", enabledAll())
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnumerateFile(p, "example.com/p", "p/sample.go", enabledAll())
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("non-deterministic count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].offset != b[i].offset {
			t.Fatalf("enumeration order changed at %d: %s vs %s", i, a[i].Describe(), b[i].Describe())
		}
	}
}

func TestApplyROR(t *testing.T) {
	src := []byte(`package p
func h(a, b int) bool { return a < b }
`)
	dir := t.TempDir()
	p := filepath.Join(dir, "h.go")
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	ms, err := EnumerateFile(p, "example.com/p", "h.go", map[string]bool{OpROR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("expected 2 ROR mutants for `<`, got %d", len(ms))
	}
	for _, m := range ms {
		out := string(Apply(src, m))
		if strings.Contains(out, "a < b") {
			t.Errorf("mutant %s did not replace the operator: %q", m.Describe(), out)
		}
		want := "a " + m.Mutated + " b"
		if !strings.Contains(out, want) {
			t.Errorf("mutant %s: expected %q in output, got %q", m.Describe(), want, out)
		}
	}
}

func TestApplyCondWrapsCondition(t *testing.T) {
	src := []byte(`package p
func k(a int) int {
	if a > 0 {
		return 1
	}
	return 0
}
`)
	dir := t.TempDir()
	p := filepath.Join(dir, "k.go")
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	ms, err := EnumerateFile(p, "example.com/p", "k.go", map[string]bool{OpCond: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 COND mutant, got %d", len(ms))
	}
	out := string(Apply(src, ms[0]))
	if !strings.Contains(out, "if !(a > 0)") {
		t.Errorf("COND mutant did not wrap condition; got:\n%s", out)
	}
}

func TestApplyNegRemovesBang(t *testing.T) {
	src := []byte(`package p
func n(ok bool) bool { return !ok }
`)
	dir := t.TempDir()
	p := filepath.Join(dir, "n.go")
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	ms, err := EnumerateFile(p, "example.com/p", "n.go", map[string]bool{OpNeg: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 NEG mutant, got %d", len(ms))
	}
	out := string(Apply(src, ms[0]))
	if !strings.Contains(out, "return ok") || strings.Contains(out, "!ok") {
		t.Errorf("NEG mutant did not drop the `!`; got:\n%s", out)
	}
}

// TestBoolSkipsSelectorField ensures a struct field named true/false (legal in
// Go, since true/false are predeclared, not keywords) is never mutated as a
// boolean constant.
func TestBoolSkipsSelectorField(t *testing.T) {
	src := `package p

type T struct{ true bool }

func m(x T) bool { return x.true }
`
	p := writeTempGo(t, src)
	ms, err := EnumerateFile(p, "example.com/p", "p/sample.go", map[string]bool{OpBool: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, mut := range ms {
		t.Errorf("unexpected BOOL mutant over a selector field: %s", mut.Describe())
	}
}
