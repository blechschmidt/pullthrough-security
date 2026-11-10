package contentscan

import "strings"

// Severity is the ordinal risk level of a content finding. It mirrors the
// vocabulary used across the proxy's gates (vulnscan, installhooks, avscan) so
// findings normalize cleanly onto the unified SARIF / dossier / risk pipeline.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank returns a total order over severities (higher = worse) so the
// gate can compare a finding against a configured threshold.
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

// ParseSeverity coerces a string to a known Severity. ok is false for an
// unrecognized value so config validation can reject it.
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

// downgradeOne lowers a severity by a single rank (critical->high, ...,
// low->info; info stays info). It implements the "downgrade" action, turning a
// gate's findings advisory without discarding them.
func downgradeOne(s Severity) Severity {
	switch s {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	case SeverityLow:
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// maxSeverity returns the worst severity across a finding set.
func maxSeverity(findings []Finding) Severity {
	worst := Severity("")
	for i := range findings {
		if severityRank(findings[i].Severity) > severityRank(worst) {
			worst = findings[i].Severity
		}
	}
	return worst
}

// riskScore maps the worst severity and the finding count onto an ordinal 0..100
// risk contribution for the unified risk-scoring engine. Severity dominates; the
// count adds a small, bounded surcharge so many findings edge the score upward
// without ever exceeding the next severity band's floor by much.
func riskScore(worst Severity, count int) int {
	base := 0
	switch worst {
	case SeverityCritical:
		base = 95
	case SeverityHigh:
		base = 75
	case SeverityMedium:
		base = 45
	case SeverityLow:
		base = 20
	case SeverityInfo:
		base = 5
	default:
		return 0
	}
	if count > 1 {
		surcharge := (count - 1) * 2
		if surcharge > 100-base {
			surcharge = 100 - base
		}
		base += surcharge
	}
	if base > 100 {
		base = 100
	}
	return base
}
