package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// stubSource is an AssessmentSource returning a fixed assessment (or error).
type stubSource struct {
	asmt Assessment
	err  error
}

func (s stubSource) Assess(context.Context, Artifact) (Assessment, error) {
	return s.asmt, s.err
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func npm(name, version string) Artifact {
	return Artifact{Ecosystem: "npm", Backend: "npm", Name: name, Version: version}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"lodash", "lodash", true},
		{"lodash", "lodash-es", false},
		{"left-*", "left-pad", true},
		{"@scope/*", "@scope/pkg", true},
		{"@scope/*", "@other/pkg", false},
		{"evil/*", "evil/sub/pkg", true}, // '*' spans '/'
		{"*", "anything/at/all", true},
		{"*-test", "my-test", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"github.com/evil/*", "github.com/evil/repo", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestDenylistBlocks(t *testing.T) {
	e := New(Config{Default: Rule{Denylist: []string{"evil-*"}}}, stubSource{asmt: Assessment{Found: true}}, testLogger())
	d := e.Evaluate(context.Background(), npm("evil-pkg", "1.0.0"))
	if !d.Blocked() {
		t.Fatalf("expected block, got %s (%s)", d.Action, d.Reason)
	}
	if d.Code != "denylist" {
		t.Errorf("code=%q want denylist", d.Code)
	}
}

func TestDenylistCaseInsensitive(t *testing.T) {
	e := New(Config{Default: Rule{Denylist: []string{"evil"}}}, nil, testLogger())
	if d := e.Evaluate(context.Background(), npm("EVIL", "1.0.0")); !d.Blocked() {
		t.Fatalf("case-folded denylist should block EVIL, got %s", d.Action)
	}
}

func TestAllowlistRestricts(t *testing.T) {
	e := New(Config{Default: Rule{Allowlist: []string{"@acme/*", "lodash"}}},
		stubSource{asmt: Assessment{Found: true}}, testLogger())

	if d := e.Evaluate(context.Background(), npm("lodash", "1.0.0")); d.Blocked() {
		t.Errorf("allowlisted package should be admitted, got block: %s", d.Reason)
	}
	if d := e.Evaluate(context.Background(), npm("@acme/widget", "1.0.0")); d.Blocked() {
		t.Errorf("allowlisted scope should be admitted, got block: %s", d.Reason)
	}
	d := e.Evaluate(context.Background(), npm("random-pkg", "1.0.0"))
	if !d.Blocked() || d.Code != "allowlist" {
		t.Errorf("non-allowlisted package should block via allowlist, got %s/%s", d.Action, d.Code)
	}
}

func TestDenylistBeatsAllowlist(t *testing.T) {
	e := New(Config{Default: Rule{
		Allowlist: []string{"*"},
		Denylist:  []string{"banned"},
	}}, nil, testLogger())
	if d := e.Evaluate(context.Background(), npm("banned", "1.0.0")); d.Code != "denylist" {
		t.Errorf("denylist must be evaluated before allowlist, got %s", d.Code)
	}
}

func TestMissingProvenanceAction(t *testing.T) {
	for _, tc := range []struct {
		action Action
		want   Action
	}{
		{ActionAllow, ActionAllow},
		{ActionWarn, ActionWarn},
		{ActionBlock, ActionBlock},
		{"", ActionAllow}, // unset -> allow
	} {
		e := New(Config{Default: Rule{OnMissingProvenance: tc.action}},
			stubSource{asmt: Assessment{Found: false}}, testLogger())
		d := e.Evaluate(context.Background(), npm("x", "1.0.0"))
		if d.Action != tc.want {
			t.Errorf("OnMissingProvenance=%q -> %q, want %q", tc.action, d.Action, tc.want)
		}
		if d.Code != "missing-provenance" {
			t.Errorf("code=%q want missing-provenance", d.Code)
		}
	}
}

func TestRiskScoreThresholds(t *testing.T) {
	rule := Rule{WarnAtRiskScore: 40, BlockAtRiskScore: 70}
	base := Assessment{Found: true, HasVerdict: true, Confidence: "attested"}

	mk := func(score int) Decision {
		a := base
		a.RiskScore = score
		e := New(Config{Default: rule}, stubSource{asmt: a}, testLogger())
		return e.Evaluate(context.Background(), npm("p", "1"))
	}

	if d := mk(10); d.Action != ActionAllow {
		t.Errorf("score 10 -> %s, want allow", d.Action)
	}
	if d := mk(50); d.Action != ActionWarn {
		t.Errorf("score 50 -> %s, want warn", d.Action)
	}
	if d := mk(90); d.Action != ActionBlock {
		t.Errorf("score 90 -> %s, want block", d.Action)
	}
}

func TestBlockMalicious(t *testing.T) {
	e := New(Config{Default: Rule{BlockMalicious: true, BlockAtRiskScore: 0}},
		stubSource{asmt: Assessment{Found: true, HasVerdict: true, Malicious: true, RiskScore: 5}}, testLogger())
	d := e.Evaluate(context.Background(), npm("p", "1"))
	if !d.Blocked() || d.Code != "malicious" {
		t.Errorf("malicious commit should block, got %s/%s", d.Action, d.Code)
	}
}

func TestRequireSignature(t *testing.T) {
	e := New(Config{Default: Rule{RequireSignature: true}},
		stubSource{asmt: Assessment{Found: true, SignatureVerified: false, Confidence: "claimed"}}, testLogger())
	if d := e.Evaluate(context.Background(), npm("p", "1")); !d.Blocked() || d.Code != "signature-required" {
		t.Errorf("unsigned should block, got %s/%s", d.Action, d.Code)
	}

	e2 := New(Config{Default: Rule{RequireSignature: true}},
		stubSource{asmt: Assessment{Found: true, SignatureVerified: true, Confidence: "claimed"}}, testLogger())
	if d := e2.Evaluate(context.Background(), npm("p", "1")); d.Blocked() {
		t.Errorf("signed should pass signature gate, got block: %s", d.Reason)
	}
}

func TestRequireAttested(t *testing.T) {
	e := New(Config{Default: Rule{RequireAttested: true}},
		stubSource{asmt: Assessment{Found: true, SignatureVerified: true, ChainTrusted: false, Confidence: "claimed"}}, testLogger())
	if d := e.Evaluate(context.Background(), npm("p", "1")); !d.Blocked() || d.Code != "attestation-required" {
		t.Errorf("untrusted-chain should block, got %s/%s", d.Action, d.Code)
	}

	e2 := New(Config{Default: Rule{RequireAttested: true}},
		stubSource{asmt: Assessment{Found: true, SignatureVerified: true, ChainTrusted: true, Confidence: "attested"}}, testLogger())
	if d := e2.Evaluate(context.Background(), npm("p", "1")); d.Blocked() {
		t.Errorf("fully attested should pass, got block: %s", d.Reason)
	}
}

func TestMinConfidence(t *testing.T) {
	e := New(Config{Default: Rule{MinConfidence: "attested", OnLowConfidence: ActionBlock}},
		stubSource{asmt: Assessment{Found: true, Confidence: "claimed"}}, testLogger())
	if d := e.Evaluate(context.Background(), npm("p", "1")); !d.Blocked() || d.Code != "low-confidence" {
		t.Errorf("claimed < attested should block, got %s/%s", d.Action, d.Code)
	}
}

func TestMissingScanAction(t *testing.T) {
	e := New(Config{Default: Rule{OnMissingScan: ActionWarn}},
		stubSource{asmt: Assessment{Found: true, HasVerdict: false, Confidence: "attested"}}, testLogger())
	d := e.Evaluate(context.Background(), npm("p", "1"))
	if d.Action != ActionWarn || d.Code != "missing-scan" {
		t.Errorf("unscanned commit -> %s/%s, want warn/missing-scan", d.Action, d.Code)
	}
}

func TestPerEcosystemOverride(t *testing.T) {
	cfg := Config{
		Default:    Rule{OnMissingProvenance: ActionBlock},
		Ecosystems: map[string]Rule{"go": {OnMissingProvenance: ActionAllow}},
	}
	e := New(cfg, stubSource{asmt: Assessment{Found: false}}, testLogger())

	if d := e.Evaluate(context.Background(), npm("p", "1")); !d.Blocked() {
		t.Errorf("npm should use default (block), got %s", d.Action)
	}
	goArt := Artifact{Ecosystem: "go", Name: "golang.org/x/text", Version: "v0.1.0"}
	if d := e.Evaluate(context.Background(), goArt); d.Blocked() {
		t.Errorf("go override should allow, got block: %s", d.Reason)
	}
}

func TestFailClosedVsOpen(t *testing.T) {
	srcErr := stubSource{err: errors.New("boom")}

	open := New(Config{FailClosed: false, Default: Rule{}}, srcErr, testLogger())
	if d := open.Evaluate(context.Background(), npm("p", "1")); d.Action != ActionWarn {
		t.Errorf("fail-open -> %s, want warn", d.Action)
	}

	closed := New(Config{FailClosed: true, Default: Rule{}}, srcErr, testLogger())
	if d := closed.Evaluate(context.Background(), npm("p", "1")); !d.Blocked() {
		t.Errorf("fail-closed -> %s, want block", d.Action)
	}
}

func TestStrongestWarnSurvives(t *testing.T) {
	// Both low-confidence (warn) and missing-scan (warn) fire; result is a warn,
	// and a risk warn is also possible. The most restrictive non-block wins.
	e := New(Config{Default: Rule{
		MinConfidence:   "attested",
		OnLowConfidence: ActionWarn,
		OnMissingScan:   ActionWarn,
	}}, stubSource{asmt: Assessment{Found: true, Confidence: "claimed", HasVerdict: false}}, testLogger())
	if d := e.Evaluate(context.Background(), npm("p", "1")); d.Action != ActionWarn {
		t.Errorf("expected warn, got %s", d.Action)
	}
}

func TestAllowByDefault(t *testing.T) {
	// Empty policy with full provenance admits silently.
	e := New(Config{Default: Rule{}}, stubSource{asmt: Assessment{
		Found: true, HasVerdict: true, RiskScore: 3, Confidence: "attested", SignatureVerified: true, ChainTrusted: true,
	}}, testLogger())
	if d := e.Evaluate(context.Background(), npm("p", "1")); d.Action != ActionAllow {
		t.Errorf("clean artifact -> %s, want allow", d.Action)
	}
}

func TestValidAction(t *testing.T) {
	for _, s := range []string{"", "allow", "warn", "block", "BLOCK", " warn "} {
		if !ValidAction(s) {
			t.Errorf("ValidAction(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"deny", "permit", "xyz"} {
		if ValidAction(s) {
			t.Errorf("ValidAction(%q)=true, want false", s)
		}
	}
}
