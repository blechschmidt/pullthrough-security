package installhooks

import (
	"fmt"
	"strings"
)

// Decision is the admission verdict for an assessed artifact under a tenant's
// effective thresholds.
type Decision struct {
	Action  Action   `json:"action"`
	Code    string   `json:"code"`
	Reason  string   `json:"reason"`
	Highest *Finding `json:"highest,omitempty"`
}

// Gate applies the tenant's effective severity thresholds to a report and
// returns the admission decision, folding warn/block tallies into the metrics.
// A report with no findings (or one the gate did not inspect) always allows.
func (s *Service) Gate(report *Report, tenant string) Decision {
	if report == nil || len(report.Findings) == 0 {
		return Decision{Action: ActionAllow, Code: "clean"}
	}
	fail, warn, action := s.resolveThresholds(tenant)
	worst := report.MaxSeverity
	highest := highestFinding(report.Findings)

	switch {
	case severityRank(worst) >= severityRank(fail):
		dec := Decision{
			Action:  action,
			Code:    "risky-install-script",
			Reason:  decisionReason(report, worst),
			Highest: highest,
		}
		if action == ActionBlock {
			s.blocked.Add(1)
		} else {
			s.warned.Add(1)
		}
		return dec
	case warn != "" && severityRank(worst) >= severityRank(warn):
		s.warned.Add(1)
		return Decision{
			Action:  ActionWarn,
			Code:    "risky-install-script",
			Reason:  decisionReason(report, worst),
			Highest: highest,
		}
	default:
		// Findings below the warn threshold are recorded in the signal/SARIF for
		// transparency but do not affect serving.
		return Decision{Action: ActionAllow, Code: "below-threshold", Highest: highest}
	}
}

// highestFinding returns the most severe finding (first in stable order at that
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
	rules := make([]string, 0, 4)
	seen := make(map[string]bool)
	for i := range report.Findings {
		id := report.Findings[i].RuleID
		if seen[id] {
			continue
		}
		seen[id] = true
		rules = append(rules, id)
		if len(rules) == 4 {
			break
		}
	}
	return fmt.Sprintf("%d high-risk install-hook pattern(s) detected (max severity %s): %s",
		len(report.Findings), worst, strings.Join(rules, ", "))
}
