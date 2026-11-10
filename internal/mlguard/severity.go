package mlguard

import "strings"

// Severity is the gate's risk vocabulary, ordered info < low < medium < high <
// critical. It maps onto the canonical findings/SARIF severity scale by name,
// matching the other admission gates (installhooks, vulnscan, license).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank returns a comparable ordinal (info=1 .. critical=5), or 0 for an
// empty/unknown severity so it never accidentally meets a threshold.
func severityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// ParseSeverity normalizes a string into a Severity, returning ok=false for an
// unrecognized value (empty maps to ok=false so callers can substitute a
// default).
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityInfo:
		return SeverityInfo, true
	case SeverityLow:
		return SeverityLow, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityCritical:
		return SeverityCritical, true
	default:
		return "", false
	}
}

// maxSeverity returns the highest severity across the findings (or "" for none).
func maxSeverity(findings []Finding) Severity {
	var worst Severity
	for i := range findings {
		if severityRank(findings[i].Severity) > severityRank(worst) {
			worst = findings[i].Severity
		}
	}
	return worst
}

// riskScore maps the worst severity (and finding volume) onto a 0..100 ordinal
// risk contribution for the unified risk-scoring / policy engines.
func riskScore(worst Severity, count int) int {
	base := 0
	switch worst {
	case SeverityCritical:
		base = 95
	case SeverityHigh:
		base = 80
	case SeverityMedium:
		base = 55
	case SeverityLow:
		base = 30
	case SeverityInfo:
		base = 12
	default:
		return 0
	}
	if count > 1 {
		extra := (count - 1) * 3
		headroom := 100 - base
		if extra > headroom {
			extra = headroom
		}
		base += extra
	}
	if base > 100 {
		base = 100
	}
	return base
}
