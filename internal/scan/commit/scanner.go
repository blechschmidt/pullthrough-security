package commit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/scan"
)

// Scanner adapts the commit Pipeline to the generic scan.Scanner interface so
// the proxy/policy layers can treat LLM commit scanning like any other scanner.
//
// It expects a Target of kind scan.TargetGitCommit. The commit's metadata and
// diff are taken from Target.Content (JSON-encoded Commit) when present;
// otherwise a minimal commit is reconstructed from Target.Ref and Metadata so a
// caller that only has a SHA still gets a (message/metadata-only) scan.
type Scanner struct {
	pipeline *Pipeline
	// failOn is the minimum severity that fails the scanner's own verdict.
	failOn scan.Severity
}

// NewScanner wraps a Pipeline as a scan.Scanner. failOn is the minimum severity
// (info|low|medium|high|critical) that marks a commit as not passing; an empty
// value defaults to "high".
func NewScanner(p *Pipeline, failOn scan.Severity) *Scanner {
	if failOn == "" {
		failOn = scan.SeverityHigh
	}
	return &Scanner{pipeline: p, failOn: failOn}
}

// Name implements scan.Scanner.
func (s *Scanner) Name() string { return "llm-commit" }

// Verdict returns the persisted verdict for sha, or ErrNotFound. It lets the
// admin layer inspect scan results without re-running a scan.
func (s *Scanner) Verdict(ctx context.Context, sha string) (*Verdict, error) {
	return s.pipeline.Get(ctx, sha)
}

// Verdicts returns every persisted verdict, for administrative inspection.
func (s *Scanner) Verdicts(ctx context.Context) ([]*Verdict, error) {
	return s.pipeline.Verdicts(ctx)
}

// QueueDepth reports the number of commits waiting in the async scan queue.
func (s *Scanner) QueueDepth() int { return s.pipeline.QueueDepth() }

// PendingCount reports the number of commits queued or in-flight for scanning.
func (s *Scanner) PendingCount() int { return s.pipeline.PendingCount() }

// Pipeline returns the underlying pipeline so the admin layer can read its
// hardening configuration (cache signature, budgets, consensus) and operate on
// budgets and retention.
func (s *Scanner) Pipeline() *Pipeline { return s.pipeline }

// HardeningStatus reports the Task 78 hardening configuration for the admin API.
func (s *Scanner) HardeningStatus() HardeningStatus { return s.pipeline.HardeningStatus() }

// BudgetSnapshot reports per-tenant cost-budget usage (nil when budgeting off).
func (s *Scanner) BudgetSnapshot() []TenantBudget { return s.pipeline.BudgetSnapshot() }

// SetBudget sets a runtime per-tenant cost ceiling (USD per window).
func (s *Scanner) SetBudget(tenant string, ceilingUSD float64) error {
	return s.pipeline.SetBudget(tenant, ceilingUSD)
}

// PruneVerdicts evicts cached verdicts older than the configured retention TTL.
func (s *Scanner) PruneVerdicts(ctx context.Context) (int, error) {
	return s.pipeline.Prune(ctx)
}

// Scan implements scan.Scanner. For non-commit targets it returns a passing
// result (commit scanning does not apply). For commit targets it runs the
// pipeline and maps the verdict to findings.
func (s *Scanner) Scan(ctx context.Context, target *scan.Target) (*scan.Result, error) {
	if target == nil {
		return nil, fmt.Errorf("commit: nil target")
	}
	if target.Kind != scan.TargetGitCommit {
		return &scan.Result{Target: *target, Scanner: s.Name(), Passed: true}, nil
	}

	commit, err := commitFromTarget(target)
	if err != nil {
		return nil, err
	}

	verdict, err := s.pipeline.Scan(ctx, commit)
	if err != nil {
		return nil, err
	}
	return s.resultFromVerdict(target, verdict), nil
}

// commitFromTarget reconstructs a Commit from a scan.Target.
func commitFromTarget(target *scan.Target) (*Commit, error) {
	commit := &Commit{SHA: target.Ref}
	if target.Content != nil {
		data, err := io.ReadAll(target.Content)
		if err != nil {
			return nil, fmt.Errorf("commit: reading target content: %w", err)
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, commit); err != nil {
				return nil, fmt.Errorf("commit: decoding commit from target: %w", err)
			}
		}
	}
	if commit.SHA == "" {
		commit.SHA = target.Ref
	}
	if commit.SHA == "" {
		return nil, fmt.Errorf("commit: target has no commit SHA")
	}
	// Promote a couple of well-known metadata keys when the body omitted them.
	if commit.RepositoryURL == "" {
		commit.RepositoryURL = target.Metadata["repository"]
	}
	if commit.Tenant == "" {
		commit.Tenant = target.Metadata["tenant"]
	}
	return commit, nil
}

// resultFromVerdict maps a Verdict onto a scan.Result.
func (s *Scanner) resultFromVerdict(target *scan.Target, v *Verdict) *scan.Result {
	res := &scan.Result{
		Target:  *target,
		Scanner: s.Name(),
	}
	for _, f := range v.Findings {
		res.Findings = append(res.Findings, scan.Finding{
			RuleID:   string(f.Category),
			Severity: scan.Severity(normalizeSeverity(f.Severity)),
			Title:    f.Title,
			Detail:   f.Detail,
			Location: location(f),
		})
	}
	res.Passed = res.MaxSeverity() == "" || severityRank(res.MaxSeverity()) < severityRank(s.failOn)
	// A verdict the model itself called malicious never passes, regardless of the
	// per-finding severities it assigned.
	if v.Malicious {
		res.Passed = false
	}
	return res
}

func location(f Finding) string {
	if f.File == "" {
		return ""
	}
	if f.Line > 0 {
		return f.File + ":" + strconv.Itoa(f.Line)
	}
	return f.File
}

func severityRank(s scan.Severity) int {
	switch s {
	case scan.SeverityLow:
		return 1
	case scan.SeverityMedium:
		return 2
	case scan.SeverityHigh:
		return 3
	case scan.SeverityCritical:
		return 4
	default:
		return 0
	}
}
