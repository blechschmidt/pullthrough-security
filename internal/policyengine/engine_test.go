package policyengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// criticalUnsignedInput is the canonical "deny" scenario.
func criticalUnsignedInput() Input {
	return Input{
		Artifact: ArtifactInput{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		Vuln:     &VulnInput{Scanned: true, CriticalCount: 1, MaxSeverity: "critical"},
		Signature: &SignatureInput{
			Checked: true, HasSignature: false, Verified: false,
		},
	}
}

func TestDefaultBundleParsesAndCompiles(t *testing.T) {
	b, err := DefaultBundle()
	if err != nil {
		t.Fatalf("DefaultBundle: %v", err)
	}
	if len(b.Rules) == 0 {
		t.Fatal("default bundle has no rules")
	}
	if _, err := CompileRuleSet([]*Bundle{b}, CompileOptions{}); err != nil {
		t.Fatalf("compile default bundle: %v", err)
	}
}

func TestDefaultBundleDeniesCriticalUnsigned(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true})
	res := e.Evaluate(context.Background(), criticalUnsignedInput())
	if res.EffectiveAction != ActionDeny {
		t.Fatalf("want deny, got %s (reason %q)", res.EffectiveAction, res.Decision.Reason)
	}
	if !res.Blocked() {
		t.Error("expected blocked")
	}
	reasons := res.Decision.DenyReasons()
	if len(reasons) == 0 {
		t.Error("expected deny reasons")
	}
}

func TestDefaultBundleWarnsCriticalSigned(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true})
	in := criticalUnsignedInput()
	in.Signature.Verified = true
	in.Signature.HasSignature = true
	res := e.Evaluate(context.Background(), in)
	if res.EffectiveAction != ActionWarn {
		t.Fatalf("want warn, got %s (reason %q)", res.EffectiveAction, res.Decision.Reason)
	}
}

func TestDefaultBundleAllowsClean(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true})
	in := Input{
		Artifact:  ArtifactInput{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		Vuln:      &VulnInput{Scanned: true},
		Signature: &SignatureInput{Checked: true, Verified: true, HasSignature: true},
		License:   &LicenseInput{Evaluated: true, Allowed: true, Code: "ok"},
	}
	res := e.Evaluate(context.Background(), in)
	if res.EffectiveAction != ActionAllow {
		t.Fatalf("want allow, got %s (reason %q; matches %+v)", res.EffectiveAction, res.Decision.Reason, res.Decision.Matches)
	}
	if !res.Decision.DefaultApplied {
		t.Error("expected default to apply for clean artifact")
	}
}

func TestVEXNotAffectedSuppressesDeny(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true})
	in := criticalUnsignedInput()
	// The single critical is adjudicated not_affected via VEX, so it is no longer
	// "unresolved" and the headline deny must not fire.
	in.Vuln.CriticalNotAffected = 1
	res := e.Evaluate(context.Background(), in)
	if res.EffectiveAction == ActionDeny {
		t.Fatalf("VEX not_affected should suppress deny, got %s", res.Decision.Reason)
	}
}

func TestAuditModeDowngradesDeny(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true, Mode: ModeAudit})
	res := e.Evaluate(context.Background(), criticalUnsignedInput())
	if res.Decision.Action != ActionDeny {
		t.Fatalf("decision should still be deny, got %s", res.Decision.Action)
	}
	if res.EffectiveAction != ActionAllow {
		t.Fatalf("audit mode should admit, got %s", res.EffectiveAction)
	}
	if !res.Audited {
		t.Error("expected Audited=true")
	}
	if e.Snapshot().AuditedDenies != 1 {
		t.Errorf("expected one audited deny, got %d", e.Snapshot().AuditedDenies)
	}
}

func TestMostRestrictiveActionWins(t *testing.T) {
	b := &Bundle{
		Name: "test",
		Rules: []Rule{
			{ID: "warn-rule", When: "true", Action: ActionWarn},
			{ID: "deny-rule", When: "true", Action: ActionDeny},
			{ID: "allow-rule", When: "true", Action: ActionAllow},
		},
	}
	rs, err := CompileRuleSet([]*Bundle{b}, CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dec := rs.evaluate("", Input{}.Document())
	if dec.Action != ActionDeny {
		t.Fatalf("most restrictive (deny) should win, got %s", dec.Action)
	}
	if len(dec.Matches) != 3 {
		t.Errorf("expected 3 matches, got %d", len(dec.Matches))
	}
}

func TestFinalAllowOverridesLaterDeny(t *testing.T) {
	b := &Bundle{
		Name: "test",
		Rules: []Rule{
			{ID: "whitelist", When: `input.artifact.name == "trusted"`, Action: ActionAllow, Final: true},
			{ID: "deny-all", When: "true", Action: ActionDeny},
		},
	}
	rs, _ := CompileRuleSet([]*Bundle{b}, CompileOptions{})
	in := Input{Artifact: ArtifactInput{Name: "trusted"}}
	dec := rs.evaluate("", in.Document())
	if dec.Action != ActionAllow {
		t.Fatalf("final allow should win, got %s (%q)", dec.Action, dec.Reason)
	}
	// A non-whitelisted artifact still gets denied.
	in2 := Input{Artifact: ArtifactInput{Name: "other"}}
	dec2 := rs.evaluate("", in2.Document())
	if dec2.Action != ActionDeny {
		t.Fatalf("non-whitelisted should deny, got %s", dec2.Action)
	}
}

func TestTenantOverridePrecedence(t *testing.T) {
	global := &Bundle{
		Name:  "global",
		Rules: []Rule{{ID: "deny-gpl", When: `input.license.code == "denied"`, Action: ActionDeny}},
	}
	// A tenant bundle whitelists a specific artifact past the global deny.
	tenant := &Bundle{
		Name:   "acme",
		Tenant: "acme",
		Rules:  []Rule{{ID: "acme-exception", When: `input.artifact.name == "acme-internal"`, Action: ActionAllow, Final: true}},
	}
	rs, err := CompileRuleSet([]*Bundle{global, tenant}, CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	denied := &LicenseInput{Evaluated: true, Code: "denied"}

	// acme tenant + the whitelisted artifact: tenant final-allow wins.
	in := Input{Tenant: "acme", Artifact: ArtifactInput{Name: "acme-internal"}, License: denied}
	if dec := rs.evaluate("acme", in.Document()); dec.Action != ActionAllow {
		t.Fatalf("tenant override should allow, got %s", dec.Action)
	}
	// acme tenant + a different artifact: global deny applies.
	in2 := Input{Tenant: "acme", Artifact: ArtifactInput{Name: "other"}, License: denied}
	if dec := rs.evaluate("acme", in2.Document()); dec.Action != ActionDeny {
		t.Fatalf("global deny should apply to non-whitelisted, got %s", dec.Action)
	}
	// A different tenant never sees acme's bundle.
	in3 := Input{Tenant: "other", Artifact: ArtifactInput{Name: "acme-internal"}, License: denied}
	if dec := rs.evaluate("other", in3.Document()); dec.Action != ActionDeny {
		t.Fatalf("other tenant must not get acme exception, got %s", dec.Action)
	}
}

func TestAuditRuleNeverEnforced(t *testing.T) {
	b := &Bundle{
		Name:  "test",
		Rules: []Rule{{ID: "staged-deny", When: "true", Action: ActionDeny, Audit: true}},
	}
	rs, _ := CompileRuleSet([]*Bundle{b}, CompileOptions{})
	dec := rs.evaluate("", Input{}.Document())
	if dec.Action != ActionAllow {
		t.Fatalf("audit-only rule must not enforce; got %s", dec.Action)
	}
	if len(dec.Matches) != 1 || !dec.Matches[0].Audit {
		t.Fatalf("expected one audit match, got %+v", dec.Matches)
	}
	if !dec.DefaultApplied {
		t.Error("expected default applied since only an audit rule matched")
	}
}

func TestRuleEvalErrorIsNonFatal(t *testing.T) {
	b := &Bundle{
		Name: "test",
		Rules: []Rule{
			// This compiles but errors at eval (comparing string to int).
			{ID: "buggy", When: `input.artifact.name < 3`, Action: ActionDeny},
			{ID: "ok", When: "true", Action: ActionWarn},
		},
	}
	rs, err := CompileRuleSet([]*Bundle{b}, CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dec := rs.evaluate("", Input{Artifact: ArtifactInput{Name: "x"}}.Document())
	if dec.Action != ActionWarn {
		t.Fatalf("buggy rule should be skipped, decision = %s", dec.Action)
	}
	if len(dec.Errors) != 1 {
		t.Fatalf("expected one rule error, got %+v", dec.Errors)
	}
}

func TestDuplicateRuleIDRejected(t *testing.T) {
	b := &Bundle{
		Name:  "test",
		Rules: []Rule{{ID: "dup", When: "true", Action: ActionAllow}, {ID: "dup", When: "false", Action: ActionDeny}},
	}
	if _, err := CompileRuleSet([]*Bundle{b}, CompileOptions{}); err == nil {
		t.Error("expected duplicate-id error")
	}
}

func TestInvalidWhenRejectedAtCompile(t *testing.T) {
	b := &Bundle{Name: "test", Rules: []Rule{{ID: "bad", When: "1 +", Action: ActionDeny}}}
	if _, err := CompileRuleSet([]*Bundle{b}, CompileOptions{}); err == nil {
		t.Error("expected compile error for invalid predicate")
	}
}

func TestHotReloadFromDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	v1 := `
name: ops
rules:
  - id: warn-all
    when: "true"
    action: warn
`
	if err := os.WriteFile(path, []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}
	e := mustEngine(t, Config{Dir: dir})
	if got := e.Evaluate(context.Background(), Input{}).Decision.Action; got != ActionWarn {
		t.Fatalf("v1 should warn, got %s", got)
	}

	// Rewrite the bundle to deny and reload.
	v2 := `
name: ops
rules:
  - id: deny-all
    when: "true"
    action: deny
`
	if err := os.WriteFile(path, []byte(v2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := e.Evaluate(context.Background(), Input{}).Decision.Action; got != ActionDeny {
		t.Fatalf("v2 should deny after reload, got %s", got)
	}
}

func TestReloadKeepsPreviousOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	good := "name: ops\nrules:\n  - id: deny-all\n    when: \"true\"\n    action: deny\n"
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	e := mustEngine(t, Config{Dir: dir})
	if got := e.Evaluate(context.Background(), Input{}).Decision.Action; got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
	// Write a broken bundle (invalid predicate); reload must fail and retain v1.
	bad := "name: ops\nrules:\n  - id: broken\n    when: \"1 +\"\n    action: deny\n"
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Error("expected reload error for broken bundle")
	}
	if got := e.Evaluate(context.Background(), Input{}).Decision.Action; got != ActionDeny {
		t.Fatalf("previous policy should be retained, got %s", got)
	}
	if e.Snapshot().ReloadFailures == 0 {
		t.Error("expected a recorded reload failure")
	}
}

func TestWatchReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte("name: ops\nrules:\n  - id: warn\n    when: \"true\"\n    action: warn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := mustEngine(t, Config{Dir: dir, ReloadInterval: 20 * time.Millisecond})
	// Give the mtime room to differ, then flip to deny.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("name: ops\nrules:\n  - id: deny\n    when: \"true\"\n    action: deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.Evaluate(context.Background(), Input{}).Decision.Action == ActionDeny {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("watch did not pick up the policy change")
}

func TestTestEvaluateDoesNotMutateMetrics(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true})
	before := e.Snapshot().Evaluations
	_ = e.TestEvaluate(criticalUnsignedInput())
	if after := e.Snapshot().Evaluations; after != before {
		t.Errorf("TestEvaluate must not change metrics: before=%d after=%d", before, after)
	}
}

func TestSnapshotCounters(t *testing.T) {
	e := mustEngine(t, Config{IncludeDefaultBundle: true})
	e.Evaluate(context.Background(), criticalUnsignedInput()) // deny
	clean := Input{Vuln: &VulnInput{Scanned: true}, Signature: &SignatureInput{Verified: true}}
	e.Evaluate(context.Background(), clean) // allow
	s := e.Snapshot()
	if s.Evaluations != 2 {
		t.Errorf("evaluations = %d, want 2", s.Evaluations)
	}
	if s.Denied != 1 {
		t.Errorf("denied = %d, want 1", s.Denied)
	}
	if s.Allowed != 1 {
		t.Errorf("allowed = %d, want 1", s.Allowed)
	}
	if len(s.DenyByRule) == 0 {
		t.Error("expected denyByRule populated")
	}
}
