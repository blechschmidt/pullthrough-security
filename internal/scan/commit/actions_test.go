package commit

import (
	"context"
	"testing"
)

// fakeActionScanner returns a fixed set of action-pin findings regardless of
// input.
type fakeActionScanner struct {
	findings []ActionFinding
	calls    int
}

func (f *fakeActionScanner) ScanCommit(c *Commit) []ActionFinding {
	f.calls++
	return f.findings
}

// Deterministic-only mode driven solely by the action-pinning scanner (no LLM
// provider, no secret scanner): the pipeline must still run and surface the
// findings with a risk floor high enough to block at the default policy.
func TestDeterministicOnly_ActionPinning(t *testing.T) {
	scanner := &fakeActionScanner{findings: []ActionFinding{{
		RuleID:    "disallowed-owner",
		Title:     "Action owner \"evilcorp\" is not in the allowlist",
		Severity:  "high",
		File:      ".github/workflows/ci.yml",
		Line:      4,
		Reference: "evilcorp/pwn@v1",
	}}}
	p, err := New(nil, NewMemoryStore(), Config{Actions: scanner}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, err := p.Scan(context.Background(), testCommit())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanner.calls != 1 {
		t.Fatalf("action scanner called %d times, want 1", scanner.calls)
	}
	if len(v.Findings) != 1 || v.Findings[0].Category != CategoryActionPinning {
		t.Fatalf("expected 1 action-pinning finding, got %+v", v.Findings)
	}
	// high severity => risk floor 80 (blocks at the default block-at-75 policy).
	if v.RiskScore < 75 {
		t.Fatalf("risk score %d should meet the default block threshold", v.RiskScore)
	}
}

// With an LLM provider that scores the commit benign, a deterministic action
// finding is still retained and raises the risk score (it is authoritative
// ground truth applied after the model answers).
func TestActionFindingsOverrideBenignVerdict(t *testing.T) {
	provider := &fakeProvider{name: "fake", resp: benignVerdictJSON}
	scanner := &fakeActionScanner{findings: []ActionFinding{{
		RuleID:    "mutable-ref",
		Title:     "Action \"actions/checkout\" is pinned to a floating version tag",
		Severity:  "medium",
		File:      ".github/workflows/ci.yml",
		Line:      4,
		Reference: "actions/checkout@v4",
	}}}
	p, err := New(provider, NewMemoryStore(), Config{Actions: scanner, EscalateAtScore: 1000}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, err := p.Scan(context.Background(), testCommit())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range v.Findings {
		if f.Category == CategoryActionPinning {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the action-pinning finding to survive a benign LLM verdict, got %+v", v.Findings)
	}
	// medium severity => risk floor 55, overriding the benign score of 5.
	if v.RiskScore < 55 {
		t.Fatalf("risk score %d should be raised to the medium floor", v.RiskScore)
	}
}
