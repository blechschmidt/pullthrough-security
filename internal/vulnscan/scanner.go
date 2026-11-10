// Package vulnscan implements the proxy's software-composition / vulnerability
// scanning subsystem. As artifacts are pulled through the proxy it parses their
// metadata and embedded manifests into a CycloneDX Software Bill of Materials
// (SBOM), resolves the SBOM's components against a vulnerability database (the
// OSV.dev batch API by default), and feeds the result into the admission-gating
// layer so operators can block, warn on, or quarantine artifacts whose known
// vulnerabilities exceed a configured CVSS/severity threshold.
//
// The data-source is pluggable behind the Scanner interface: the OSV.dev client
// is the default, but a Trivy or Grype adapter can be swapped in without
// touching SBOM generation, result caching, or policy gating. Scan results are
// cached by content digest with a configurable TTL and an offline fallback so a
// transient database outage degrades to the last-known result rather than
// halting pulls.
package vulnscan

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Severity classifies the seriousness of a vulnerability. The buckets mirror the
// CVSS v3 qualitative scale and the policy/scan packages' severity vocabulary so
// thresholds are expressed in one shared language across the proxy.
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	// SeverityUnknown marks a vulnerability whose severity could not be derived
	// (no CVSS vector and no database-specific rating). It is ordered above "none"
	// but below "low" so a default "warn on unknown" posture is expressible.
	SeverityUnknown Severity = "unknown"
)

// severityRank orders severities so the most severe finding can be selected and
// compared against a threshold. Unknown sits just above none.
func severityRank(s Severity) int {
	switch Severity(strings.ToLower(strings.TrimSpace(string(s)))) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityUnknown:
		return 1
	default:
		return 0
	}
}

// Rank returns the ordinal of a severity (higher is more severe).
func (s Severity) Rank() int { return severityRank(s) }

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool { return severityRank(s) >= severityRank(other) }

// NormalizeSeverity coerces an arbitrary severity string (e.g. GHSA's
// "MODERATE", a CVSS rating, or an empty value) to a known Severity. Unrecognized
// non-empty values normalize to SeverityUnknown so they are still visible.
func NormalizeSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "none", "negligible":
		return SeverityNone
	case "", "unknown", "unspecified":
		return SeverityUnknown
	default:
		return SeverityUnknown
	}
}

// NormalizeSeverityConfig normalizes a configured severity threshold. Unlike
// NormalizeSeverity it maps the empty string to the empty Severity (threshold
// disabled) rather than to "unknown", so an unset failSeverity/warnSeverity does
// not silently gate on unknown-severity findings.
func NormalizeSeverityConfig(s string) Severity {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return NormalizeSeverity(s)
}

// SeverityFromCVSS buckets a CVSS base score onto the qualitative scale per the
// CVSS v3.1 specification (§5).
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// Vulnerability is a single known issue affecting a component, normalized across
// scanner backends.
type Vulnerability struct {
	// ID is the primary advisory identifier (e.g. "GHSA-xxxx" or "CVE-2024-1234").
	ID string `json:"id"`
	// Aliases are equivalent identifiers (CVE/GHSA/OSV cross-references).
	Aliases []string `json:"aliases,omitempty"`
	// Summary is a short human-readable title.
	Summary string `json:"summary,omitempty"`
	// Details is the longer description, when available.
	Details string `json:"details,omitempty"`
	// Severity is the normalized qualitative severity.
	Severity Severity `json:"severity"`
	// CVSS is the highest CVSS base score derived from the advisory's vectors,
	// or 0 when no vector was published.
	CVSS float64 `json:"cvss,omitempty"`
	// CVSSVector is the source vector string the CVSS score was derived from.
	CVSSVector string `json:"cvssVector,omitempty"`
	// FixedVersions lists versions in which the issue is fixed, when published.
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// References are advisory/fix URLs.
	References []string `json:"references,omitempty"`
	// Component identifies the affected SBOM component (purl).
	Component string `json:"component"`
	// Package and Version restate the affected coordinate for convenience.
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	// AffectedModules are the language-level module/package import paths the
	// advisory declares vulnerable, when the OSV record carries them (the
	// ecosystem_specific.imports[].path field, used by Go's vuln database and,
	// increasingly, PyPI/Maven advisories). They let reachability analysis match a
	// finding against the exact imported module rather than inferring one from the
	// package coordinate. Empty when the advisory publishes no import paths, in
	// which case reachability falls back to coordinate-derived candidates.
	AffectedModules []string `json:"affectedModules,omitempty"`
	// Withdrawn marks an advisory the upstream database has withdrawn; such
	// findings are retained for transparency but excluded from gating.
	Withdrawn bool `json:"withdrawn,omitempty"`

	// VEX annotation (Task 27). When a VEX statement matched this finding, these
	// fields record the asserted exploitability status, its justification, and the
	// document it came from. Suppressed findings are excluded from gating (a
	// vendor/operator declared the artifact not_affected or the issue fixed);
	// OriginalSeverity captures the pre-escalation severity when an "affected"
	// statement raised it.
	VEXStatus        VEXStatus        `json:"vexStatus,omitempty"`
	VEXJustification VEXJustification `json:"vexJustification,omitempty"`
	VEXSource        string           `json:"vexSource,omitempty"`
	Suppressed       bool             `json:"suppressed,omitempty"`
	OriginalSeverity Severity         `json:"originalSeverity,omitempty"`

	// Reachability annotation (Task 118). Reachability classifies whether the
	// vulnerable module/package is reachable from the consuming artifact's own
	// code via static import analysis; ReachabilityReason explains the verdict.
	// When policy acts on unreachable findings, ReachSuppressed records that the
	// finding was excluded from gating (kept for transparency) and
	// ReachOriginalSeverity captures the pre-downgrade severity when its severity
	// was lowered. All three are empty/false when reachability analysis is off.
	Reachability          Reachability `json:"reachability,omitempty"`
	ReachabilityReason    string       `json:"reachabilityReason,omitempty"`
	ReachSuppressed       bool         `json:"reachSuppressed,omitempty"`
	ReachOriginalSeverity Severity     `json:"reachOriginalSeverity,omitempty"`
}

// Scanner resolves an SBOM's components against a vulnerability database. It is
// the pluggable seam of the subsystem: the OSV.dev client is the default
// implementation, but a Trivy or Grype adapter satisfies the same contract.
//
// Implementations must be safe for concurrent use and must honor context
// cancellation. A returned error means the scan could not be performed (the
// caller applies offline-fallback handling); a successful scan that found
// nothing returns an empty slice and a nil error.
type Scanner interface {
	// Name identifies the scanner backend (e.g. "osv", "trivy", "grype").
	Name() string
	// Scan resolves every component of sbom and returns the vulnerabilities found.
	Scan(ctx context.Context, sbom *SBOM) ([]Vulnerability, error)
}

// Report is the outcome of scanning one artifact: its SBOM joined with the
// vulnerabilities found and the derived headline severity/score. It is the unit
// cached by digest and surfaced through the admin SBOM/vuln endpoints.
type Report struct {
	// Digest is the artifact content digest the report is keyed by.
	Digest string `json:"digest"`
	// Artifact identifies what was scanned.
	Artifact Artifact `json:"artifact"`
	// Scanner is the backend that produced the result.
	Scanner string `json:"scanner"`
	// SBOM is the generated CycloneDX bill of materials.
	SBOM *SBOM `json:"sbom,omitempty"`
	// Vulnerabilities are the findings, most severe first.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	// Counts is the per-severity tally of (non-withdrawn) findings.
	Counts SeverityCounts `json:"counts"`
	// MaxSeverity and MaxCVSS are the headline figures used for gating.
	MaxSeverity Severity `json:"maxSeverity"`
	MaxCVSS     float64  `json:"maxCvss"`
	// ScannedAt is when the scan completed.
	ScannedAt time.Time `json:"scannedAt"`
	// Offline reports that the result was served from a stale cache entry because
	// the scanner backend was unreachable (offline fallback).
	Offline bool `json:"offline,omitempty"`
	// Error, when non-empty, records that scanning failed and no usable result was
	// produced (the gate then applies its fail-open/closed posture).
	Error string `json:"error,omitempty"`
	// VEXSuppressed and VEXEscalated tally how many findings VEX statements
	// suppressed (dropped) and escalated (severity raised) for this artifact, so the
	// admin surface can show suppressed-vs-active at a glance (Task 27).
	VEXSuppressed int `json:"vexSuppressed,omitempty"`
	VEXEscalated  int `json:"vexEscalated,omitempty"`
}

// SeverityCounts tallies findings by severity bucket.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	None     int `json:"none"`
}

// Total returns the sum of all severity buckets.
func (c SeverityCounts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Unknown + c.None
}

// summarize sorts findings by descending severity/score and computes the headline
// figures and per-severity counts. Withdrawn advisories are retained in the list
// (flagged) but excluded from the counts and headline figures so they cannot
// trip a gate.
func (r *Report) summarize() {
	sort.SliceStable(r.Vulnerabilities, func(i, j int) bool {
		a, b := r.Vulnerabilities[i], r.Vulnerabilities[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.ID < b.ID
	})

	r.Counts = SeverityCounts{}
	r.MaxSeverity = SeverityNone
	r.MaxCVSS = 0
	for _, v := range r.Vulnerabilities {
		// Withdrawn advisories, VEX-suppressed findings (a vendor/operator declared
		// the artifact not_affected or the issue fixed), and reachability-suppressed
		// findings (proven unreachable from the artifact's own code and suppressed by
		// policy) are retained in the list for transparency but excluded from the
		// counts and headline figures so they cannot trip a gate.
		if v.Withdrawn || v.Suppressed || v.ReachSuppressed {
			continue
		}
		switch NormalizeSeverity(string(v.Severity)) {
		case SeverityCritical:
			r.Counts.Critical++
		case SeverityHigh:
			r.Counts.High++
		case SeverityMedium:
			r.Counts.Medium++
		case SeverityLow:
			r.Counts.Low++
		case SeverityNone:
			r.Counts.None++
		default:
			r.Counts.Unknown++
		}
		if severityRank(v.Severity) > severityRank(r.MaxSeverity) {
			r.MaxSeverity = v.Severity
		}
		if v.CVSS > r.MaxCVSS {
			r.MaxCVSS = v.CVSS
		}
	}
}
