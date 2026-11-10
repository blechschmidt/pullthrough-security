package license

import "testing"

// evalExpr is a test helper: compile a policy, parse an expression, and return
// the folded outcome.
func evalExpr(t *testing.T, cfg PolicyConfig, expr string) leafEval {
	t.Helper()
	cp, err := compilePolicy(cfg)
	if err != nil {
		t.Fatalf("compilePolicy: %v", err)
	}
	e, err := ParseExpression(expr)
	if err != nil {
		t.Fatalf("ParseExpression(%q): %v", expr, err)
	}
	return cp.evaluate(e.root)
}

func TestPolicy_CompoundExpressions(t *testing.T) {
	// Permissive allowlist, GPL family denied, default allow for recognized.
	cfg := PolicyConfig{
		Allow: []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"},
		Deny:  []string{"@strong-copyleft", "@network-copyleft"},
	}
	cases := []struct {
		expr string
		want Outcome
	}{
		// Dual licensing: a consumer may pick the permissive disjunct.
		{"GPL-3.0-only OR MIT", OutcomeAllowed},
		{"MIT OR GPL-3.0-only", OutcomeAllowed},
		// AND: the denied conjunct dominates (all obligations apply).
		{"MIT AND GPL-3.0-only", OutcomeDenied},
		{"GPL-3.0-only AND MIT", OutcomeDenied},
		// Pure permissive.
		{"MIT AND Apache-2.0", OutcomeAllowed},
		// Nested: (MIT OR Apache) AND ISC -> allowed.
		{"(MIT OR Apache-2.0) AND ISC", OutcomeAllowed},
		// Nested with a denied branch reachable only through AND.
		{"(MIT OR Apache-2.0) AND AGPL-3.0-only", OutcomeDenied},
		// OR of two denied -> still denied (no acceptable choice).
		{"GPL-3.0-only OR AGPL-3.0-only", OutcomeDenied},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := evalExpr(t, cfg, tc.expr)
			if got.outcome != tc.want {
				t.Errorf("evaluate(%q) = %v, want %v", tc.expr, got.outcome, tc.want)
			}
		})
	}
}

func TestPolicy_DualLicensingPicksBest(t *testing.T) {
	cfg := PolicyConfig{
		Allow:  []string{"MIT"},
		Review: []string{"MPL-2.0"},
		Deny:   []string{"GPL-3.0-only"},
	}
	// OR should pick the most acceptable: MIT (allowed) over MPL (review) over GPL (denied).
	if got := evalExpr(t, cfg, "GPL-3.0-only OR MPL-2.0 OR MIT"); got.outcome != OutcomeAllowed {
		t.Errorf("OR best-pick = %v, want allowed", got.outcome)
	}
	// Without the permissive option, review wins over denied.
	if got := evalExpr(t, cfg, "GPL-3.0-only OR MPL-2.0"); got.outcome != OutcomeReview {
		t.Errorf("OR review-pick = %v, want review", got.outcome)
	}
}

func TestPolicy_UnknownAndNOASSERTION(t *testing.T) {
	cfg := PolicyConfig{Allow: []string{"MIT"}} // defaults: unknown=review, default=allow
	// Unrecognized custom license -> unknown disposition (review by default).
	if got := evalExpr(t, cfg, "LicenseRef-Weird-Thing"); got.outcome != OutcomeUnknown {
		t.Errorf("custom license = %v, want unknown", got.outcome)
	}
	// A recognized-but-unlisted permissive license -> default (allow).
	if got := evalExpr(t, cfg, "Zlib"); got.outcome != OutcomeAllowed {
		t.Errorf("recognized unlisted = %v, want allowed (default)", got.outcome)
	}

	// Deny-unknown posture.
	denyUnknown := PolicyConfig{Allow: []string{"MIT"}, Unknown: "deny"}
	if got := evalExpr(t, denyUnknown, "LicenseRef-Weird-Thing"); got.outcome != OutcomeDenied {
		t.Errorf("unknown=deny = %v, want denied", got.outcome)
	}
}

func TestPolicy_WITHException(t *testing.T) {
	cfg := PolicyConfig{
		Deny:            []string{"@strong-copyleft"},
		AllowExceptions: []string{"Classpath-exception-2.0"},
	}
	// GPL is denied...
	if got := evalExpr(t, cfg, "GPL-2.0-or-later"); got.outcome != OutcomeDenied {
		t.Fatalf("GPL = %v, want denied", got.outcome)
	}
	// ...but the Classpath exception rescues it.
	if got := evalExpr(t, cfg, "GPL-2.0-or-later WITH Classpath-exception-2.0"); got.outcome != OutcomeAllowed {
		t.Errorf("GPL WITH Classpath = %v, want allowed", got.outcome)
	}
	// A different (non-allowed) exception does not rescue it.
	if got := evalExpr(t, cfg, "GPL-2.0-or-later WITH GCC-exception-3.1"); got.outcome != OutcomeDenied {
		t.Errorf("GPL WITH GCC = %v, want denied", got.outcome)
	}
}

func TestPolicy_GlobAndFamilyDeny(t *testing.T) {
	cfg := PolicyConfig{Deny: []string{"GPL-*", "AGPL-*", "LGPL-*"}}
	for _, id := range []string{"GPL-3.0-only", "AGPL-3.0-or-later", "LGPL-2.1-only"} {
		if got := evalExpr(t, cfg, id); got.outcome != OutcomeDenied {
			t.Errorf("glob deny %q = %v, want denied", id, got.outcome)
		}
	}
	// MIT is unaffected (recognized, unlisted -> default allow).
	if got := evalExpr(t, cfg, "MIT"); got.outcome != OutcomeAllowed {
		t.Errorf("MIT under glob deny = %v, want allowed", got.outcome)
	}
}

func TestPolicy_PrecedenceDenyOverReviewOverAllow(t *testing.T) {
	cfg := PolicyConfig{
		Allow:  []string{"MPL-2.0"},
		Review: []string{"MPL-2.0"},
		Deny:   []string{"MPL-2.0"},
	}
	if got := evalExpr(t, cfg, "MPL-2.0"); got.outcome != OutcomeDenied {
		t.Errorf("deny precedence = %v, want denied", got.outcome)
	}
}

func TestCompilePolicy_InvalidEntries(t *testing.T) {
	if _, err := compilePolicy(PolicyConfig{Deny: []string{"@bogus-family"}}); err == nil {
		t.Error("expected error for unknown family keyword")
	}
	if _, err := compilePolicy(PolicyConfig{Action: "explode"}); err == nil {
		t.Error("expected error for invalid action")
	}
	if _, err := compilePolicy(PolicyConfig{Unknown: "maybe"}); err == nil {
		t.Error("expected error for invalid unknown disposition")
	}
}
