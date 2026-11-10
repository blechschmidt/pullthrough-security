package contentscan

import (
	"fmt"
	"strings"
)

// Outcome is the effective admission decision for a scanned artifact.
type Outcome string

const (
	// OutcomeAllow serves the artifact (clean, annotate/downgrade, or below the
	// block threshold).
	OutcomeAllow Outcome = "allow"
	// OutcomeRefuse refuses to serve the artifact (block action, a finding at/above
	// the fail threshold).
	OutcomeRefuse Outcome = "refuse"
)

// Decision is the admission verdict for an assessed artifact.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	// Action is the configured action this decision reflects.
	Action Action `json:"action"`
	// Evict reports whether the cached artifact should be removed (block).
	Evict bool `json:"evict"`
	// Code is a short machine-readable reason code.
	Code string `json:"code"`
	// Reason is a human-readable explanation.
	Reason string `json:"reason"`
	// Highest is the most-severe finding, when any.
	Highest *Finding `json:"highest,omitempty"`
}

// Served reports whether the decision permits serving the artifact.
func (d Decision) Served() bool { return d.Outcome == OutcomeAllow }

// Gate applies the configured action and fail-severity threshold to a report and
// returns the admission decision, folding the result into the metrics. A report
// with no findings always allows.
func (s *Service) Gate(report *Report) Decision {
	if report == nil || len(report.Findings) == 0 {
		return Decision{Outcome: OutcomeAllow, Action: s.action(), Code: "clean"}
	}
	worst := report.MaxSeverity
	highest := highestFinding(report.Findings)
	reason := decisionReason(report, worst)

	switch s.cfg.Action {
	case ActionBlock:
		if severityRank(worst) >= severityRank(s.cfg.FailSeverity) {
			s.blocked.Add(1)
			return Decision{
				Outcome: OutcomeRefuse,
				Action:  ActionBlock,
				Evict:   true,
				Code:    "content-risk",
				Reason:  reason,
				Highest: highest,
			}
		}
		// Findings below the block threshold are recorded (signal/SARIF) but served.
		s.annotated.Add(1)
		return Decision{Outcome: OutcomeAllow, Action: ActionBlock, Code: "below-threshold", Highest: highest}
	case ActionDowngrade:
		s.downgraded.Add(1)
		return Decision{Outcome: OutcomeAllow, Action: ActionDowngrade, Code: "downgraded", Reason: reason, Highest: highest}
	default: // ActionAnnotate
		s.annotated.Add(1)
		return Decision{Outcome: OutcomeAllow, Action: ActionAnnotate, Code: "annotated", Reason: reason, Highest: highest}
	}
}

func (s *Service) action() Action {
	if s == nil {
		return ActionAnnotate
	}
	return s.cfg.Action
}

// highestFinding returns the most-severe finding (first in stable order at that
// severity), or nil for an empty set.
func highestFinding(findings []Finding) *Finding {
	var best *Finding
	for i := range findings {
		if best == nil || severityRank(findings[i].Severity) > severityRank(best.Severity) {
			best = &findings[i]
		}
	}
	return best
}

func decisionReason(report *Report, worst Severity) string {
	cats := make([]string, 0, 4)
	seen := make(map[string]bool)
	for i := range report.Findings {
		c := report.Findings[i].Category
		if seen[c] {
			continue
		}
		seen[c] = true
		cats = append(cats, c)
		if len(cats) == 4 {
			break
		}
	}
	return fmt.Sprintf("%d static content finding(s) in package payload (max severity %s): %s",
		len(report.Findings), worst, strings.Join(cats, ", "))
}
