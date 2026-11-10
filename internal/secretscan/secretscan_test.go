package secretscan

import (
	"strings"
	"testing"
)

// newDetector builds a detector with built-in rules and the default entropy
// heuristic for corpus tests.
func newDetector(t *testing.T) *Detector {
	t.Helper()
	return New(Config{})
}

// patchAdding wraps lines as a single-hunk unified diff that adds them, so the
// detector's added-line scoping is exercised end to end.
func patchAdding(lines ...string) string {
	var b strings.Builder
	b.WriteString("@@ -0,0 +1,")
	b.WriteString(itoa(len(lines)))
	b.WriteString(" @@\n")
	for _, l := range lines {
		b.WriteString("+")
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func scanLine(d *Detector, line string) []Finding {
	return d.ScanFiles([]FileInput{{Path: "src/config.go", Patch: patchAdding(line)}})
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// --- True positives: each named rule must fire on a realistic credential. ----

func TestTruePositives(t *testing.T) {
	d := newDetector(t)
	cases := []struct {
		name   string
		line   string
		ruleID string
	}{
		{"aws access key id", `AWS_ACCESS_KEY_ID = AKIA1234567890ABCDEF`, "aws-access-key-id"},
		{"aws temporary key", `key := "ASIAZ4XYABCDEFGH3K9Q"`, "aws-access-key-id"},
		{"aws secret key", `aws_secret_access_key = "aB3dEfGh1JkLmNoPqRsTuVwXyZ0123456789+abc"`, "aws-secret-access-key"},
		{"gcp service account", `  "type": "service_account",`, "gcp-service-account"},
		{"google api key", `const k = "AIzaSyA1234567890abcdefghijklmnopqrstuv";`, "gcp-api-key"},
		{"github classic pat", `token: ghp_abcdefghijklmnopqrstuvwxyz0123456789`, "github-token"},
		{"github oauth", `gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`, "github-token"},
		{"github fine-grained", `GH=github_pat_` + strings.Repeat("A", 82), "github-fine-grained-pat"},
		{"gitlab pat", `GITLAB_TOKEN=glpat-ABCDEFGHIJ1234567890`, "gitlab-pat"},
		// Synthetic token; the literal is split so GitHub push-protection does
		// not see a contiguous Slack-token pattern (scanLine reassembles it).
		{"slack bot token", `SLACK=xoxb-123456789012-abcd` + `efghijklmnop`, "slack-token"},
		{"slack webhook", `url = https://hooks.slack.com/services/T00000000/B11111111/abcdefABCDEF0123456789`, "slack-webhook"},
		{"rsa private key", `-----BEGIN RSA PRIVATE KEY-----`, "private-key-block"},
		{"openssh private key", `-----BEGIN OPENSSH PRIVATE KEY-----`, "private-key-block"},
		{"plain private key", `-----BEGIN PRIVATE KEY-----`, "private-key-block"},
		{"jwt", `auth = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`, "jwt"},
		// Synthetic key; literal split to evade GitHub push-protection matching.
		{"stripe secret", `STRIPE=sk_live_abcdefghijkl` + `mnopqrstuvwx`, "stripe-secret-key"},
		{"npm token", `//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`, "npm-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanLine(d, tc.line)
			if !hasRule(got, tc.ruleID) {
				t.Fatalf("expected rule %q to fire on %q; got %+v", tc.ruleID, tc.line, got)
			}
		})
	}
}

// --- False positives: ordinary code must not produce findings. ---------------

func TestFalsePositives(t *testing.T) {
	d := newDetector(t)
	lines := []string{
		`func computeHash(input string) string { return sha256(input) }`,
		`import { useState } from "react";`,
		`const greeting = "hello world, this is a normal sentence";`,
		`version = "1.2.3"`,
		`// AKIA is the prefix AWS uses for access key ids`,
		`color = "#1a2b3c4d"`,
		`uuid := "550e8400-e29b-41d4-a716-446655440000"`,
		`gitCommit = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"`,
		`"integrity": "sha512-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=="`,
		`"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"`,
		`url = "https://example.com/path/to/resource?query=value&other=thing"`,
		`logger.Info("processing request", "id", requestID)`,
		`data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42m2`,
		`const description = "A reasonably long human readable description string.";`,
		`path := filepath.Join(dir, "subdir", "file.txt")`,
	}
	for _, line := range lines {
		got := scanLine(d, line)
		if len(got) != 0 {
			t.Errorf("false positive on %q: %+v", line, got)
		}
	}
}

// --- Entropy heuristic -------------------------------------------------------

func TestEntropyHeuristicFlagsAssignedHighEntropyValue(t *testing.T) {
	d := newDetector(t)
	// A non-secret-named key with a long, high-entropy base64 value should be
	// flagged by the entropy heuristic even though it matches no named format
	// and no secret keyword (so the generic-secret rule does not apply).
	got := scanLine(d, `payload = "Zx9Kq2Lm8Pv4Tn7Rw1Yc6Bd3Hf0Jg5SaWe2"`)
	if !hasRule(got, EntropyRuleID) {
		t.Fatalf("expected entropy rule to fire; got %+v", got)
	}
}

func TestEntropyHeuristicIgnoresLowEntropyAndContext(t *testing.T) {
	d := newDetector(t)
	benign := []string{
		`name = "the_quick_brown_fox_jumps"`,                     // low entropy words
		`gitCommit = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"`, // hex, non-secret key
		`enabled = "truetruetruetruetruetrue"`,                   // few distinct chars
	}
	for _, line := range benign {
		if got := scanLine(d, line); hasRule(got, EntropyRuleID) {
			t.Errorf("entropy heuristic false positive on %q: %+v", line, got)
		}
	}
}

func TestEntropyHexRequiresSecretKey(t *testing.T) {
	d := newDetector(t)
	// 64 hex chars (all 16 digits, ~4.0 bits/char) under a secret-named key: flag.
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := scanLine(d, `signing_key = "`+hex64+`"`); !hasRule(got, EntropyRuleID) {
		t.Fatalf("expected hex entropy to flag a secret-named key; got %+v", got)
	}
	// Same value under a non-secret key (a digest): must not flag.
	if got := scanLine(d, `checksum = "`+hex64+`"`); hasRule(got, EntropyRuleID) {
		t.Fatalf("hex entropy must not flag a non-secret key; got %+v", got)
	}
}

func TestEntropyCanBeDisabled(t *testing.T) {
	d := New(Config{Entropy: EntropyConfigDisabled()})
	got := scanLine(d, `api_secret = "Zx9Kq2Lm8Pv4Tn7Rw1Yc6Bd3Hf0Jg5Sa"`)
	if hasRule(got, EntropyRuleID) {
		t.Fatalf("entropy heuristic should be disabled; got %+v", got)
	}
	// Named rules still work with entropy disabled.
	if got := scanLine(d, `ghp_abcdefghijklmnopqrstuvwxyz0123456789`); !hasRule(got, "github-token") {
		t.Fatalf("named rules must still fire when entropy disabled; got %+v", got)
	}
}

// --- Scoping: only added lines are scanned. ----------------------------------

func TestOnlyAddedLinesScanned(t *testing.T) {
	d := newDetector(t)
	patch := "@@ -1,3 +1,3 @@\n" +
		" context line unchanged\n" +
		"-old_token = ghp_REMOVEDREMOVEDREMOVEDREMOVEDREMOVE0\n" +
		"+new_value = 42\n" +
		" trailing context\n"
	got := d.ScanFiles([]FileInput{{Path: "a.txt", Patch: patch}})
	if len(got) != 0 {
		t.Fatalf("removed/context lines must not produce findings; got %+v", got)
	}
}

func TestLineNumbersAssigned(t *testing.T) {
	d := newDetector(t)
	patch := "@@ -10,2 +10,3 @@\n" +
		" ctx\n" +
		"+harmless = 1\n" +
		"+token = ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	got := d.ScanFiles([]FileInput{{Path: "a.txt", Patch: patch}})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	// Lines: 10=ctx, 11=harmless, 12=token.
	if got[0].Line != 12 {
		t.Fatalf("expected line 12, got %d", got[0].Line)
	}
}

func TestBinaryFilesSkipped(t *testing.T) {
	d := newDetector(t)
	got := d.ScanFiles([]FileInput{{
		Path:   "blob.bin",
		Patch:  patchAdding(`ghp_abcdefghijklmnopqrstuvwxyz0123456789`),
		Binary: true,
	}})
	if len(got) != 0 {
		t.Fatalf("binary files must be skipped; got %+v", got)
	}
}

// --- Redaction ---------------------------------------------------------------

func TestFindingsAreRedacted(t *testing.T) {
	d := newDetector(t)
	const raw = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	got := scanLine(d, "token = "+raw)
	if len(got) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range got {
		if strings.Contains(f.Match, "abcdefghijklmnop") {
			t.Fatalf("redacted match leaks the secret: %q", f.Match)
		}
		if !strings.HasPrefix(f.Match, "ghp_") {
			t.Fatalf("expected a short identifying prefix, got %q", f.Match)
		}
	}
}

// --- Allowlist / baseline ----------------------------------------------------

func TestAllowlistSuppressesFixturePaths(t *testing.T) {
	spec := AllowlistSpec{}
	allow, err := spec.Compile()
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Allowlist: allow})
	got := d.ScanFiles([]FileInput{{
		Path:  "internal/foo/testdata/sample.env",
		Patch: patchAdding(`ghp_abcdefghijklmnopqrstuvwxyz0123456789`),
	}})
	if len(got) != 0 {
		t.Fatalf("testdata path should be allowlisted; got %+v", got)
	}
}

func TestAllowlistSuppressesPlaceholders(t *testing.T) {
	allow, err := AllowlistSpec{}.Compile()
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Allowlist: allow})
	// Canonical AWS docs keys must be treated as placeholders.
	lines := []string{
		`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
		`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
	}
	for _, l := range lines {
		if got := scanLine2(d, l); len(got) != 0 {
			t.Errorf("placeholder %q should be suppressed; got %+v", l, got)
		}
	}
}

func scanLine2(d *Detector, line string) []Finding {
	return d.ScanFiles([]FileInput{{Path: "deploy/config.tf", Patch: patchAdding(line)}})
}

func TestBaselineSuppressesByFingerprint(t *testing.T) {
	d := newDetector(t)
	const path = "src/config.go"
	line := `token = ghp_abcdefghijklmnopqrstuvwxyz0123456789`
	got := d.ScanFiles([]FileInput{{Path: path, Patch: patchAdding(line)}})
	if len(got) == 0 {
		t.Fatal("expected a finding to baseline")
	}
	fp := got[0].Fingerprint

	allow, err := AllowlistSpec{Fingerprints: []string{fp}}.Compile()
	if err != nil {
		t.Fatal(err)
	}
	d2 := New(Config{Allowlist: allow})
	got2 := d2.ScanFiles([]FileInput{{Path: path, Patch: patchAdding(line)}})
	if hasRule(got2, "github-token") {
		t.Fatalf("baselined fingerprint should be suppressed; got %+v", got2)
	}
}

func TestFingerprintStable(t *testing.T) {
	a := fingerprint("rule", "file.go", "secret")
	b := fingerprint("rule", "file.go", "secret")
	if a != b {
		t.Fatal("fingerprint must be deterministic")
	}
	if fingerprint("rule", "file.go", "secret2") == a {
		t.Fatal("different secret must change fingerprint")
	}
}

// --- Custom / pluggable rules ------------------------------------------------

func TestCustomRuleLoadedFromSpec(t *testing.T) {
	rules, err := CompileRules([]RuleSpec{{
		ID:          "acme-key",
		Description: "ACME internal key",
		Severity:    "critical",
		Pattern:     `\b(ACME-[0-9A-F]{20})\b`,
		Group:       1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Rules: rules})
	got := scanLine(d, `secret = ACME-0123456789ABCDEF0123`)
	if !hasRule(got, "acme-key") {
		t.Fatalf("custom rule should fire; got %+v", got)
	}
	for _, f := range got {
		if f.RuleID == "acme-key" && f.Severity != SeverityCritical {
			t.Fatalf("expected critical severity, got %q", f.Severity)
		}
	}
}

func TestCustomRuleOverridesBuiltin(t *testing.T) {
	rules, err := CompileRules([]RuleSpec{{
		ID:          "github-token",
		Description: "overridden",
		Severity:    "low",
		Pattern:     `\b(ghp_[A-Za-z0-9]{36})\b`,
		Group:       1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Rules: rules})
	got := scanLine(d, `ghp_abcdefghijklmnopqrstuvwxyz0123456789`)
	var found bool
	for _, f := range got {
		if f.RuleID == "github-token" {
			found = true
			if f.Severity != SeverityLow {
				t.Fatalf("override should set low severity, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected overridden github-token rule to fire")
	}
}

func TestDisableBuiltins(t *testing.T) {
	d := New(Config{DisableBuiltins: true})
	if got := scanLine(d, `ghp_abcdefghijklmnopqrstuvwxyz0123456789`); hasRule(got, "github-token") {
		t.Fatalf("built-ins should be disabled; got %+v", got)
	}
}

func TestInvalidRuleSpecRejected(t *testing.T) {
	if _, err := (RuleSpec{ID: "x", Pattern: "(unbalanced"}).Compile(); err == nil {
		t.Fatal("expected invalid pattern to error")
	}
	if _, err := (RuleSpec{Pattern: "x"}).Compile(); err == nil {
		t.Fatal("expected missing id to error")
	}
	if _, err := CompileRules([]RuleSpec{
		{ID: "dup", Pattern: "a"},
		{ID: "dup", Pattern: "b"},
	}); err == nil {
		t.Fatal("expected duplicate id to error")
	}
}

// --- Metrics -----------------------------------------------------------------

func TestMetricsCounters(t *testing.T) {
	d := newDetector(t)
	d.ScanFiles([]FileInput{{
		Path: "src/a.go",
		Patch: patchAdding(
			`token = ghp_abcdefghijklmnopqrstuvwxyz0123456789`,
			`harmless = 1`,
		),
	}})
	snap := d.Metrics()
	if snap.DiffsScanned != 1 {
		t.Errorf("DiffsScanned = %d, want 1", snap.DiffsScanned)
	}
	if snap.FindingsTotal < 1 {
		t.Errorf("FindingsTotal = %d, want >= 1", snap.FindingsTotal)
	}
	if snap.ByRule["github-token"] < 1 {
		t.Errorf("ByRule[github-token] = %d, want >= 1", snap.ByRule["github-token"])
	}
	// Every built-in rule key is present (pre-populated) so charts are stable.
	if _, ok := snap.ByRule["aws-access-key-id"]; !ok {
		t.Error("expected pre-populated key for aws-access-key-id")
	}
	if _, ok := snap.ByRule[EntropyRuleID]; !ok {
		t.Error("expected pre-populated entropy key")
	}
}

func TestMetricsSuppressedCounted(t *testing.T) {
	allow, _ := AllowlistSpec{}.Compile()
	d := New(Config{Allowlist: allow})
	d.ScanFiles([]FileInput{{
		Path:  "x.tf",
		Patch: patchAdding(`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`),
	}})
	if snap := d.Metrics(); snap.Suppressed < 1 {
		t.Errorf("Suppressed = %d, want >= 1", snap.Suppressed)
	}
}

// --- De-duplication ----------------------------------------------------------

func TestDuplicateFindingsDeduped(t *testing.T) {
	d := newDetector(t)
	const tok = `ghp_abcdefghijklmnopqrstuvwxyz0123456789`
	// Same secret on two files -> two findings (different fingerprints). Same
	// secret twice in one file's added lines -> deduped to one.
	got := d.ScanFiles([]FileInput{{
		Path:  "same.go",
		Patch: patchAdding("a = "+tok, "b = "+tok),
	}})
	count := 0
	for _, f := range got {
		if f.RuleID == "github-token" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected duplicate secret in one file to dedupe to 1, got %d", count)
	}
}

// --- Shannon entropy sanity --------------------------------------------------

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy("aaaaaaaa"); e != 0 {
		t.Errorf("uniform string entropy = %v, want 0", e)
	}
	if e := shannonEntropy("01"); e != 1 {
		t.Errorf("two equiprobable symbols entropy = %v, want 1", e)
	}
	high := shannonEntropy("Zx9Kq2Lm8Pv4Tn7Rw1Yc6Bd3Hf0Jg5Sa")
	low := shannonEntropy("aaaabbbbccccdddd")
	if high <= low {
		t.Errorf("expected random string entropy (%v) > repetitive (%v)", high, low)
	}
}
