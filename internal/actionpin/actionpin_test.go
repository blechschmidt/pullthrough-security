package actionpin

import (
	"testing"
)

const shaPin = "11bd71901bbe5b1630ceea73d27597364c9af683" // 40 hex chars

func mustService(t *testing.T, cfg Config) *Service {
	t.Helper()
	s, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

func fileFrom(path, content string) FileInput {
	return FileInput{Path: path, Lines: Lines(content)}
}

// --- parser ------------------------------------------------------------------

func TestParseUsesValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"      uses: actions/checkout@v4", "actions/checkout@v4", true},
		{"- uses: actions/checkout@v4", "actions/checkout@v4", true},
		{`  uses: "actions/checkout@v4"`, "actions/checkout@v4", true},
		{"  uses: 'actions/checkout@v4'", "actions/checkout@v4", true},
		{"  uses: actions/checkout@" + shaPin + " # v4.2.2", "actions/checkout@" + shaPin, true},
		{"\tuses:\tactions/checkout@v4", "actions/checkout@v4", true},
		{"  uses:", "", false},
		{"  uses: ", "", false},
		{"  name: build", "", false},
		{"  uses-custom: x", "", false},
		{"  # uses: actions/checkout@v4", "", false},
		{"run: echo uses: foo", "", false},
	}
	for _, c := range cases {
		got, ok := ParseUsesValue(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseUsesValue(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseContentLineNumbers(t *testing.T) {
	content := "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: make\n      - uses: actions/setup-go@v5\n"
	refs := ParseContent(content)
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2", len(refs))
	}
	if refs[0].Line != 4 || refs[0].Repo != "checkout" {
		t.Errorf("ref0 = %+v", refs[0])
	}
	if refs[1].Line != 6 || refs[1].Repo != "setup-go" {
		t.Errorf("ref1 = %+v", refs[1])
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		raw   string
		kind  Kind
		owner string
		repo  string
		ref   string
		pin   Pinning
	}{
		{"actions/checkout@" + shaPin, KindRemote, "actions", "checkout", shaPin, PinSHA},
		{"actions/checkout@v4", KindRemote, "actions", "checkout", "v4", PinMutable},
		{"actions/checkout@main", KindRemote, "actions", "checkout", "main", PinMutable},
		{"actions/checkout", KindRemote, "actions", "checkout", "", PinNone},
		{"org/repo/.github/workflows/ci.yml@" + shaPin, KindRemote, "org", "repo", shaPin, PinSHA},
		{"./.github/actions/local", KindLocal, "", "", "", PinLocal},
		{"../shared/action", KindLocal, "", "", "", PinLocal},
		{"docker://alpine:3.18", KindDocker, "alpine", "", "", PinMutable},
		{"docker://ghcr.io/org/img@sha256:" + sha256hex(), KindDocker, "ghcr.io", "", "sha256:" + sha256hex(), PinDigest},
	}
	for _, c := range cases {
		ref := Classify(c.raw)
		if ref.Kind != c.kind || ref.Owner != c.owner || ref.Repo != c.repo || ref.Ref != c.ref {
			t.Errorf("Classify(%q) = %+v, want kind=%s owner=%s repo=%s ref=%s", c.raw, ref, c.kind, c.owner, c.repo, c.ref)
		}
		if pin := ref.pinningOf(); pin != c.pin {
			t.Errorf("Classify(%q).pinningOf() = %s, want %s", c.raw, pin, c.pin)
		}
	}
}

func sha256hex() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func TestIsActionsFile(t *testing.T) {
	yes := []string{
		".github/workflows/ci.yml",
		".github/workflows/ci.yaml",
		"./.github/workflows/release.yml",
		"action.yml",
		"path/to/action.yaml",
		".github/actions/build/action.yml",
	}
	no := []string{
		".github/workflows/README.md",
		"src/main.go",
		".github/dependabot.yml",
		"deep/.github/workflows/nested/ci.yml", // not directly under workflows dir
		"",
	}
	for _, p := range yes {
		if !IsActionsFile(p) {
			t.Errorf("IsActionsFile(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if IsActionsFile(p) {
			t.Errorf("IsActionsFile(%q) = true, want false", p)
		}
	}
}

// --- the three required gate cases ------------------------------------------

// A full-SHA pin passes: no findings, allow.
func TestGate_SHAPinned_Pass(t *testing.T) {
	s := mustService(t, DefaultConfig())
	content := "steps:\n  - uses: actions/checkout@" + shaPin + " # v4.2.2\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if !report.Inspected {
		t.Fatal("expected Inspected=true")
	}
	if report.HasFindings() {
		t.Fatalf("SHA-pinned action should produce no findings, got %+v", report.Findings)
	}
	if dec := s.Gate(report, ""); dec.Action != ActionAllow {
		t.Fatalf("SHA-pinned action should allow, got %s", dec.Action)
	}
}

// A tag pin is flagged (medium -> warn under the default thresholds).
func TestGate_TagPinned_Flag(t *testing.T) {
	s := mustService(t, DefaultConfig())
	content := "steps:\n  - uses: actions/checkout@v4\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if len(report.Findings) != 1 {
		t.Fatalf("tag-pinned action should produce one finding, got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != RuleMutableRef || f.Severity != SeverityMedium {
		t.Fatalf("got finding %+v, want mutable-ref/medium", f)
	}
	if f.Line != 2 {
		t.Errorf("finding line = %d, want 2", f.Line)
	}
	if dec := s.Gate(report, ""); dec.Action != ActionWarn {
		t.Fatalf("tag-pinned action should warn under default thresholds, got %s", dec.Action)
	}
}

// A tag pin blocks when the fail threshold is lowered to medium.
func TestGate_TagPinned_BlockWhenConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FailSeverity = SeverityMedium
	s := mustService(t, cfg)
	content := "steps:\n  - uses: actions/checkout@v4\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if dec := s.Gate(report, ""); dec.Action != ActionBlock {
		t.Fatalf("tag-pin should block when failSeverity=medium, got %s", dec.Action)
	}
}

// A disallowed owner is blocked (high -> block under the default thresholds).
func TestGate_DisallowedOwner_Block(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowedOwners = []string{"actions", "github"}
	s := mustService(t, cfg)
	// SHA-pinned, but the owner is not in the allowlist.
	content := "steps:\n  - uses: evilcorp/pwn@" + shaPin + "\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if len(report.Findings) != 1 {
		t.Fatalf("disallowed owner should produce one finding, got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != RuleDisallowedOwner || f.Severity != SeverityHigh {
		t.Fatalf("got finding %+v, want disallowed-owner/high", f)
	}
	if dec := s.Gate(report, ""); dec.Action != ActionBlock {
		t.Fatalf("disallowed owner should block, got %s", dec.Action)
	}
}

// An allowed owner, SHA-pinned, passes even with an allowlist configured.
func TestGate_AllowedOwner_Pass(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowedOwners = []string{"Actions"} // case-insensitive
	s := mustService(t, cfg)
	content := "steps:\n  - uses: actions/checkout@" + shaPin + "\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if report.HasFindings() {
		t.Fatalf("allowed owner + SHA pin should be clean, got %+v", report.Findings)
	}
}

// Disallowed owner wins over the pinning finding for the same reference.
func TestGate_DisallowedOwner_Precedence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowedOwners = []string{"actions"}
	s := mustService(t, cfg)
	content := "steps:\n  - uses: evilcorp/pwn@v1\n" // both disallowed-owner and mutable
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if len(report.Findings) != 1 || report.Findings[0].RuleID != RuleDisallowedOwner {
		t.Fatalf("expected a single disallowed-owner finding, got %+v", report.Findings)
	}
}

// Local actions are never flagged.
func TestGate_LocalAction_Clean(t *testing.T) {
	s := mustService(t, DefaultConfig())
	content := "steps:\n  - uses: ./.github/actions/setup\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if report.HasFindings() {
		t.Fatalf("local action should be clean, got %+v", report.Findings)
	}
}

// Unpinned (no ref) is flagged.
func TestGate_Unpinned_Flag(t *testing.T) {
	s := mustService(t, DefaultConfig())
	content := "steps:\n  - uses: actions/checkout\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if len(report.Findings) != 1 || report.Findings[0].RuleID != RuleUnpinned {
		t.Fatalf("expected one unpinned finding, got %+v", report.Findings)
	}
}

// Non-Actions files are ignored entirely.
func TestAssess_IgnoresNonActionsFiles(t *testing.T) {
	s := mustService(t, DefaultConfig())
	content := "steps:\n  - uses: actions/checkout@v4\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom("docs/example.yml", content)})
	if report.Inspected {
		t.Fatal("a non-Actions file should not be inspected")
	}
	if report.HasFindings() {
		t.Fatalf("non-Actions file should produce no findings, got %+v", report.Findings)
	}
}

// RequirePinning=false suppresses pinning findings but keeps allowlist enforcement.
func TestAssess_RequirePinningDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequirePinning = false
	cfg.AllowedOwners = []string{"actions"}
	s := mustService(t, cfg)
	content := "steps:\n  - uses: actions/checkout@v4\n  - uses: evil/x@v1\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if len(report.Findings) != 1 || report.Findings[0].RuleID != RuleDisallowedOwner {
		t.Fatalf("with pinning disabled, only the disallowed owner should flag, got %+v", report.Findings)
	}
}

func TestTenantOverrideBlocksTags(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tenants = map[string]TenantConfig{
		"strict": {FailSeverity: SeverityMedium},
	}
	s := mustService(t, cfg)
	content := "steps:\n  - uses: actions/checkout@v4\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	if dec := s.Gate(report, "default"); dec.Action != ActionWarn {
		t.Fatalf("default tenant should warn, got %s", dec.Action)
	}
	if dec := s.Gate(report, "strict"); dec.Action != ActionBlock {
		t.Fatalf("strict tenant should block, got %s", dec.Action)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{Enabled: true, FailSeverity: "nope"},
		{Enabled: true, FailSeverity: SeverityMedium, WarnSeverity: SeverityHigh}, // warn > fail
		{Enabled: true, FailSeverity: SeverityHigh, Action: "nuke"},
		{Enabled: true, FailSeverity: SeverityHigh, MaxFindings: -1},
		{Enabled: true, FailSeverity: SeverityHigh, AllowedOwners: []string{" "}},
	}
	for i, c := range bad {
		if _, err := NewService(c); err == nil {
			t.Errorf("bad config %d: expected error", i)
		}
	}
	if _, err := NewService(DefaultConfig()); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestMetrics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowedOwners = []string{"actions"}
	s := mustService(t, cfg)
	content := "steps:\n  - uses: actions/checkout@v4\n  - uses: evil/x@v1\n"
	report := s.Assess(Artifact{Repository: "r"}, []FileInput{fileFrom(".github/workflows/ci.yml", content)})
	s.Gate(report, "")
	snap := s.Metrics()
	if snap.Scanned != 1 || snap.FilesScanned != 1 {
		t.Errorf("snapshot counts off: %+v", snap)
	}
	if snap.FindingsByRule[RuleMutableRef] != 1 || snap.FindingsByRule[RuleDisallowedOwner] != 1 {
		t.Errorf("per-rule counts off: %+v", snap.FindingsByRule)
	}
	if snap.Blocked != 1 {
		t.Errorf("expected one block, got %d", snap.Blocked)
	}
}
