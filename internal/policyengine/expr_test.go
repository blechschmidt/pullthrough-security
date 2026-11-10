package policyengine

import "testing"

func evalBool(t *testing.T, src string, doc map[string]any) bool {
	t.Helper()
	p, err := Compile(src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	b, err := p.EvalBool(doc)
	if err != nil {
		t.Fatalf("eval %q: %v", src, err)
	}
	return b
}

func TestExprLiteralsAndArithmetic(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"1 == 1", true},
		{"1 != 2", true},
		{"1 + 2 == 3", true},
		{"2 * 3 - 1 == 5", true},
		{"10 / 2 == 5", true},
		{"7 % 3 == 1", true},
		{"1.5 + 1.5 == 3.0", true},
		{"3 > 2 && 2 > 1", true},
		{"3 < 2 || 5 >= 5", true},
		{"!(1 == 2)", true},
		{"-3 < 0", true},
		{`"a" + "b" == "ab"`, true},
		{"(2 + 3) * 2 == 10", true},
		{"true ? 1 == 1 : 1 == 2", true},
		{"false ? 1 == 1 : 2 == 2", true},
	}
	for _, c := range cases {
		if got := evalBool(t, c.src, nil); got != c.want {
			t.Errorf("%q = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestExprMembershipAndFunctions(t *testing.T) {
	doc := map[string]any{
		"list":  []any{"a", "b", "c"},
		"name":  "left-pad",
		"count": int64(3),
	}
	cases := []struct {
		src  string
		want bool
	}{
		{`"b" in list`, true},
		{`"z" in list`, false},
		{"size(list) == 3", true},
		{`name.startsWith("left")`, true},
		{`name.endsWith("pad")`, true},
		{`name.contains("-")`, true},
		{`startsWith(name, "left")`, true},
		{`lower("ABC") == "abc"`, true},
		{`upper("abc") == "ABC"`, true},
		{`matches(name, "^left-")`, true},
		{`string(count) == "3"`, true},
		{`int("5") == 5`, true},
		{`count in [1, 2, 3]`, true},
	}
	for _, c := range cases {
		if got := evalBool(t, c.src, doc); got != c.want {
			t.Errorf("%q = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestExprFieldAccessAndPresence(t *testing.T) {
	doc := map[string]any{
		"vuln": map[string]any{
			"criticalCount": int64(2),
			"hasCritical":   true,
		},
	}
	if !evalBool(t, "input.vuln.criticalCount == 2", doc) {
		t.Error("nested field access failed")
	}
	if !evalBool(t, "has(input.vuln)", doc) {
		t.Error("has() on present field should be true")
	}
	if evalBool(t, "has(input.license)", doc) {
		t.Error("has() on absent field should be false")
	}
	// Accessing a field on an absent section degrades to false, not an error.
	if evalBool(t, "input.license.denied", doc) {
		t.Error("absent nested field should be false")
	}
	if !evalBool(t, "!has(input.signature) || input.signature.verified", doc) {
		t.Error("guarded access pattern failed")
	}
}

func TestExprShortCircuit(t *testing.T) {
	// The right operand references a missing field; && must short-circuit on the
	// false left operand without erroring, and the missing field coerces to false.
	doc := map[string]any{"a": false}
	if evalBool(t, "input.a && input.b.c.d", doc) {
		t.Error("expected short-circuit false")
	}
	if !evalBool(t, "input.a || true", doc) {
		t.Error("expected || true")
	}
}

func TestExprCompileErrors(t *testing.T) {
	bad := []string{
		"1 +",
		"(1 + 2",
		"1 == ",
		"foo(",
		"1 ? 2",
		"\"unterminated",
		"a..b",
	}
	for _, src := range bad {
		if _, err := Compile(src); err == nil {
			t.Errorf("expected compile error for %q", src)
		}
	}
}

func TestExprEvalErrors(t *testing.T) {
	// Type errors at eval time surface as errors (not panics).
	p, err := Compile(`"x" < 3`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := p.EvalBool(nil); err == nil {
		t.Error("expected eval error comparing string and int")
	}
}

func TestExprNonBoolResult(t *testing.T) {
	p, _ := Compile("1 + 1")
	if _, err := p.EvalBool(nil); err == nil {
		t.Error("expected error for non-boolean when clause")
	}
}
