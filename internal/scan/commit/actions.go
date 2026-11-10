package commit

import "fmt"

// ActionFinding is a deterministic GitHub Actions pinning / allowlist violation
// contributed by an ActionScanner (Task 115). It is produced by statically
// parsing the `uses:` references in a commit's changed .github/workflows/*.yml
// and composite action.yml files — the earliest place a mutable/unpinned action
// reference enters a repository's supply chain.
type ActionFinding struct {
	// RuleID identifies the check that fired ("mutable-ref", "unpinned",
	// "disallowed-owner").
	RuleID string
	// Title is a short, human-readable summary.
	Title string
	// Description explains the finding and the remediation.
	Description string
	// Severity is one of info|low|medium|high|critical.
	Severity string
	// File and Line locate the reference in the commit's changed content.
	File string
	Line int
	// Reference is the offending `uses:` value.
	Reference string
}

// ActionScanner runs a fast, deterministic GitHub Actions pinning pass over a
// commit's changed workflow / composite-action files. Like the SecretScanner it
// is independent of the LLM provider, so it yields reliable, cheap coverage even
// when the provider is unavailable or disabled.
//
// Implementations must be safe for concurrent use.
type ActionScanner interface {
	ScanCommit(c *Commit) []ActionFinding
}

// detectActionPins runs the configured deterministic GitHub Actions pinning
// scanner over the commit and converts its findings to pipeline Findings
// (category "action_pinning"). It returns nil when no scanner is configured or
// nothing is found.
func (p *Pipeline) detectActionPins(commit *Commit) []Finding {
	if p.cfg.Actions == nil {
		return nil
	}
	raw := p.cfg.Actions.ScanCommit(commit)
	if len(raw) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(raw))
	for _, af := range raw {
		title := af.Title
		if title == "" {
			title = "Unpinned GitHub Action (" + af.RuleID + ")"
		}
		detail := af.Description
		if detail == "" {
			detail = fmt.Sprintf("GitHub Actions pinning rule %q matched reference %q", af.RuleID, af.Reference)
		}
		out = append(out, Finding{
			Category:   CategoryActionPinning,
			Severity:   normalizeSeverity(af.Severity),
			Title:      title,
			Detail:     detail,
			File:       af.File,
			Line:       af.Line,
			Confidence: 1, // deterministic match
		})
	}
	return out
}

// applyActionFindings merges deterministic GitHub Actions pinning findings into a
// verdict and raises the risk score to the floor implied by the most severe
// finding, so a disallowed or unpinned action drives the policy gate regardless
// of what the model scored. These findings are authoritative ground truth and
// are always retained; an LLM finding at the same location is dropped to avoid
// double-reporting.
func applyActionFindings(v *Verdict, actionFindings []Finding) {
	if len(actionFindings) == 0 {
		return
	}
	covered := make(map[string]bool, len(actionFindings))
	for _, f := range actionFindings {
		covered[locationKey(f)] = true
	}
	kept := v.Findings[:0:0]
	for _, f := range v.Findings {
		if f.Category == CategoryActionPinning && covered[locationKey(f)] {
			continue
		}
		kept = append(kept, f)
	}
	v.Findings = append(kept, actionFindings...)

	if floor := secretRiskFloor(actionFindings); floor > v.RiskScore {
		v.RiskScore = floor
	}
}
