package chaos

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/scan"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// FaultyScanner is a scan.Scanner whose Scan always fails with Err, modeling a
// scanner/LLM backend that is unavailable. Per the scan.Scanner contract a
// returned error means "the scan could not be performed" (a dependency outage),
// as distinct from a clean scan that found problems — which is exactly the
// condition a gate's fail-open/fail-closed policy governs.
type FaultyScanner struct {
	ScannerName string
	Err         error

	calls int
}

var _ scan.Scanner = (*FaultyScanner)(nil)

// Name implements scan.Scanner.
func (s *FaultyScanner) Name() string {
	if s.ScannerName == "" {
		return "chaos-faulty-scanner"
	}
	return s.ScannerName
}

// Scan implements scan.Scanner, always returning Err.
func (s *FaultyScanner) Scan(ctx context.Context, _ *scan.Target) (*scan.Result, error) {
	s.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, s.Err
}

// Calls reports how many times Scan was invoked.
func (s *FaultyScanner) Calls() int { return s.calls }

// FaultyAssessmentSource is a policy.AssessmentSource that always fails with
// Err, modeling an unavailable provenance/scan backend. It is the seam that
// drives the policy engine's fail-open (warn) vs. fail-closed (block)
// degradation path.
type FaultyAssessmentSource struct {
	Err error
}

var _ policy.AssessmentSource = (*FaultyAssessmentSource)(nil)

// Assess implements policy.AssessmentSource.
func (s FaultyAssessmentSource) Assess(_ context.Context, _ policy.Artifact) (policy.Assessment, error) {
	return policy.Assessment{}, s.Err
}

// FaultyProvider is a commit.Provider whose Complete always fails with Err,
// modeling an unavailable LLM API (Claude/Codex). It records its call count so
// a test can assert retry behavior. A plain (non-retryable) error yields a
// single attempt, keeping the LLM-outage scenarios fast and deterministic.
type FaultyProvider struct {
	ProviderName string
	Err          error

	calls int
}

var _ commit.Provider = (*FaultyProvider)(nil)

// Name implements commit.Provider.
func (p *FaultyProvider) Name() string {
	if p.ProviderName == "" {
		return "chaos-faulty-llm"
	}
	return p.ProviderName
}

// Complete implements commit.Provider, always returning Err.
func (p *FaultyProvider) Complete(ctx context.Context, _ commit.Request) (string, commit.Usage, error) {
	p.calls++
	if err := ctx.Err(); err != nil {
		return "", commit.Usage{}, err
	}
	return "", commit.Usage{}, p.Err
}

// Calls reports how many times Complete was invoked.
func (p *FaultyProvider) Calls() int { return p.calls }

// staticSecretScanner is a commit.SecretScanner returning a fixed finding set
// regardless of input — the deterministic signal that lets the commit pipeline
// degrade gracefully when the LLM provider is unavailable.
type staticSecretScanner struct {
	findings []commit.SecretFinding
}

func (s staticSecretScanner) ScanCommit(_ *commit.Commit) []commit.SecretFinding {
	return s.findings
}

// sampleCommit is a minimal commit with one added diff line, enough to drive the
// commit-scan pipeline in the gate-degradation scenarios.
func sampleCommit() *commit.Commit {
	return &commit.Commit{
		SHA:     "abc123def456abc123def456abc123def456abcd",
		Message: "add config",
		Files: []commit.FileDiff{{
			Path:   "config.go",
			Status: "M",
			Patch:  "@@ -0,0 +1,1 @@\n+token = ghp_example\n",
		}},
	}
}
