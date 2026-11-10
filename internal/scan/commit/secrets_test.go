package commit

import (
	"context"
	"errors"
	"testing"
)

// fakeProvider is a minimal Provider for tests. It returns the configured
// response/error and records how many times it was called.
type fakeProvider struct {
	name  string
	resp  string
	err   error
	calls int
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Complete(ctx context.Context, req Request) (string, Usage, error) {
	f.calls++
	if f.err != nil {
		return "", Usage{}, f.err
	}
	return f.resp, Usage{InputTokens: 10, OutputTokens: 5}, nil
}

// fakeSecretScanner returns a fixed set of secret findings regardless of input.
type fakeSecretScanner struct {
	findings []SecretFinding
	calls    int
}

func (f *fakeSecretScanner) ScanCommit(c *Commit) []SecretFinding {
	f.calls++
	return f.findings
}

func testCommit() *Commit {
	return &Commit{
		SHA:     "abc123def456abc123def456abc123def456abcd",
		Message: "add config",
		Files: []FileDiff{{
			Path:   "config.go",
			Status: "M",
			Patch:  "@@ -0,0 +1,1 @@\n+token = ghp_xxxx\n",
		}},
	}
}

const benignVerdictJSON = `{"riskScore": 5, "malicious": false, "rationale": "benign", "findings": []}`

// Deterministic-only mode: no provider, secret scanner supplies findings.
func TestDeterministicOnlyMode(t *testing.T) {
	scanner := &fakeSecretScanner{findings: []SecretFinding{{
		RuleID: "github-token", Description: "GitHub token", Severity: "high",
		File: "config.go", Line: 1, Match: "ghp_****",
	}}}
	p, err := New(nil, NewMemoryStore(), Config{Secrets: scanner}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, err := p.Scan(context.Background(), testCommit())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(v.Findings) != 1 || v.Findings[0].Category != CategorySecret {
		t.Fatalf("expected 1 secret finding, got %+v", v.Findings)
	}
	if v.RiskScore < 75 {
		t.Fatalf("high-severity secret should floor risk >= 75, got %d", v.RiskScore)
	}
	if v.Provider != "none" {
		t.Fatalf("expected provider 'none' in deterministic-only mode, got %q", v.Provider)
	}
	if scanner.calls != 1 {
		t.Fatalf("expected secret scanner called once, got %d", scanner.calls)
	}
}

// New must still reject a nil provider when no secret scanner is configured.
func TestNewRequiresProviderOrSecrets(t *testing.T) {
	if _, err := New(nil, NewMemoryStore(), Config{}, nil); err == nil {
		t.Fatal("expected error for nil provider without a secret scanner")
	}
}

// Secret findings merge into the LLM verdict and raise the risk floor.
func TestSecretFindingsMergeIntoLLMVerdict(t *testing.T) {
	prov := &fakeProvider{name: "fake", resp: benignVerdictJSON}
	scanner := &fakeSecretScanner{findings: []SecretFinding{{
		RuleID: "aws-secret-access-key", Description: "AWS secret", Severity: "critical",
		File: "config.go", Line: 1, Match: "abcd****",
	}}}
	p, err := New(prov, NewMemoryStore(), Config{Secrets: scanner, EscalateAtScore: 200}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Scan(context.Background(), testCommit())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// LLM said riskScore 5; the critical secret floor must dominate.
	if v.RiskScore < 90 {
		t.Fatalf("critical secret should floor risk high, got %d", v.RiskScore)
	}
	var found bool
	for _, f := range v.Findings {
		if f.Category == CategorySecret && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected merged critical secret finding, got %+v", v.Findings)
	}
}

// When the LLM fails but secrets were found, return a deterministic verdict.
func TestLLMFailureFallsBackToSecrets(t *testing.T) {
	prov := &fakeProvider{name: "fake", err: errors.New("provider down")}
	scanner := &fakeSecretScanner{findings: []SecretFinding{{
		RuleID: "private-key-block", Description: "PEM private key", Severity: "critical",
		File: "id_rsa", Line: 1, Match: "----****",
	}}}
	p, err := New(prov, NewMemoryStore(), Config{Secrets: scanner, MaxRetries: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Scan(context.Background(), testCommit())
	if err != nil {
		t.Fatalf("expected graceful fallback, got error: %v", err)
	}
	if v.Error == "" {
		t.Fatal("expected Error to record the LLM degradation")
	}
	if len(v.Findings) != 1 || v.Findings[0].Category != CategorySecret {
		t.Fatalf("expected the secret finding to survive, got %+v", v.Findings)
	}
	if v.RiskScore < 90 {
		t.Fatalf("critical secret floor expected, got %d", v.RiskScore)
	}
}

// When the LLM fails and there are no secret findings, the error propagates so
// the commit stays unscanned (missing-scan policy then applies).
func TestLLMFailureWithoutSecretsPropagates(t *testing.T) {
	prov := &fakeProvider{name: "fake", err: errors.New("provider down")}
	scanner := &fakeSecretScanner{} // no findings
	p, err := New(prov, NewMemoryStore(), Config{Secrets: scanner, MaxRetries: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Scan(context.Background(), testCommit()); err == nil {
		t.Fatal("expected error to propagate when no secrets and LLM fails")
	}
}

// Without a configured scanner the pipeline behaves exactly as before.
func TestNoSecretScannerUnchanged(t *testing.T) {
	prov := &fakeProvider{name: "fake", resp: benignVerdictJSON}
	p, err := New(prov, NewMemoryStore(), Config{EscalateAtScore: 200}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Scan(context.Background(), testCommit())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.RiskScore != 5 || len(v.Findings) != 0 {
		t.Fatalf("expected unmodified benign verdict, got risk=%d findings=%+v", v.RiskScore, v.Findings)
	}
}

func TestSecretRiskFloor(t *testing.T) {
	cases := map[string]int{
		"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10,
	}
	for sev, want := range cases {
		got := secretRiskFloor([]Finding{{Severity: sev}})
		if got != want {
			t.Errorf("severity %q: floor = %d, want %d", sev, got, want)
		}
	}
	// Highest severity wins.
	mixed := []Finding{{Severity: "low"}, {Severity: "critical"}, {Severity: "medium"}}
	if got := secretRiskFloor(mixed); got != 95 {
		t.Errorf("mixed floor = %d, want 95", got)
	}
}
