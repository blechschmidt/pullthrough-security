package mlguard

import (
	"fmt"
	"strings"
)

// Decision is the admission verdict for an assessed weight file under a tenant's
// effective thresholds.
type Decision struct {
	Action  Action   `json:"action"`
	Code    string   `json:"code"`
	Reason  string   `json:"reason"`
	Highest *Finding `json:"highest,omitempty"`
}

// Gate applies the tenant's effective severity thresholds to a report and returns
// the admission decision, folding warn/block tallies into the metrics. A report
// with no findings (or one the gate did not inspect) always allows; a safetensors
// file is always admitted as the safe format.
func (s *Service) Gate(report *Report, tenant string) Decision {
	if report == nil {
		return Decision{Action: ActionAllow, Code: "clean"}
	}
	if report.SafeFormat {
		return Decision{Action: ActionAllow, Code: "safetensors-safe"}
	}
	if len(report.Findings) == 0 {
		return Decision{Action: ActionAllow, Code: "clean"}
	}
	fail, warn, action := s.resolveThresholds(tenant)
	worst := report.MaxSeverity
	highest := highestFinding(report.Findings)

	switch {
	case severityRank(worst) >= severityRank(fail):
		dec := Decision{
			Action:  action,
			Code:    "unsafe-pickle",
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
			Code:    "unsafe-pickle",
			Reason:  decisionReason(report, worst),
			Highest: highest,
		}
	default:
		return Decision{Action: ActionAllow, Code: "below-threshold", Highest: highest}
	}
}

// highestFinding returns the most severe finding, or nil for an empty set.
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
	imports := report.Imports
	if len(imports) > 4 {
		imports = imports[:4]
	}
	return fmt.Sprintf("%d unsafe pickle opcode finding(s) (max severity %s): unsafe imports [%s]",
		len(report.Findings), worst, strings.Join(imports, ", "))
}
