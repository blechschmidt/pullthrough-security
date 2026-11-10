// Package scan defines the security scanning contract. Scanners inspect
// artifacts and Git history (potentially via an LLM API such as Claude or
// Codex, see Task 7) and emit findings that the policy layer (Task 9) uses to
// admit or reject content flowing through the proxy.
package scan

import (
	"context"
	"io"
)

// Severity classifies the seriousness of a Finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// TargetKind identifies what is being scanned.
type TargetKind string

const (
	// TargetGitCommit is a single Git commit (diff + metadata).
	TargetGitCommit TargetKind = "git-commit"
	// TargetArtifact is a package artifact (tarball, wheel, image layer, ...).
	TargetArtifact TargetKind = "artifact"
)

// Target describes the unit of work handed to a Scanner. Content is optional:
// some scanners operate purely on metadata and references.
type Target struct {
	Kind TargetKind
	// Ref is a stable identifier for the target, e.g. a commit SHA or a
	// content digest.
	Ref string
	// Content, when non-nil, is the bytes to scan. The Scanner does not own it
	// and must not Close it; the caller is responsible for the stream's
	// lifetime.
	Content io.Reader
	// Metadata carries contextual key/value pairs (repository URL, package
	// coordinate, author, ...).
	Metadata map[string]string
}

// Finding is a single issue surfaced by a Scanner.
type Finding struct {
	RuleID   string
	Severity Severity
	Title    string
	Detail   string
	// Location points at where the issue was found (file path, line, layer).
	Location string
}

// Result aggregates the findings for a Target.
type Result struct {
	Target   Target
	Scanner  string
	Findings []Finding
	// Passed reports whether the target satisfies the scanner's policy. The
	// authoritative admission decision is made by the policy layer; this is the
	// scanner's own verdict.
	Passed bool
}

// MaxSeverity returns the highest severity among the findings, or SeverityInfo
// when there are none.
func (r *Result) MaxSeverity() Severity {
	order := map[Severity]int{
		SeverityInfo:     0,
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}
	max := SeverityInfo
	for _, f := range r.Findings {
		if order[f.Severity] > order[max] {
			max = f.Severity
		}
	}
	return max
}

// Scanner inspects a Target and returns a Result. Implementations must be safe
// for concurrent use and must honor context cancellation.
type Scanner interface {
	// Name identifies the scanner (e.g. "llm-commit", "secret-detector").
	Name() string
	// Scan inspects the target. A returned error indicates the scan could not
	// be performed; a successful scan that found problems is reported through
	// Result.Findings, not as an error.
	Scan(ctx context.Context, target *Target) (*Result, error)
}
