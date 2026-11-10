// Package riskscore implements a unified, cross-cutting supply-chain risk
// scoring engine (Task 37). It aggregates the signals the existing admission
// gates already produce — vulnerability/OSV severity, VEX adjudication,
// signature/attestation verification, license posture, typosquat detection,
// secret findings, provenance completeness, and CVE-drift quarantine state —
// into a single composite, normalized risk score (0..100) and a band
// (low/medium/high/critical) per artifact.
//
// Two properties drive the design:
//
//   - Explainability. A score is useless to an operator who must answer "why was
//     this blocked?" without a breakdown. Every Assessment therefore carries an
//     ordered set of Contributions: each contributing signal, its normalized
//     sub-score (0..1 risk), its configured weight, its share of the weight after
//     normalization, and the marginal points it added to the composite. The
//     points sum to the composite score (modulo rounding), so the math is fully
//     auditable.
//
//   - Decoupling. The engine consumes the same aggregated admission document the
//     policy-as-code engine evaluates (policyengine.Input), which is a plain,
//     self-describing struct with no dependency on the concrete gate packages.
//     The engine therefore never imports vulnscan/license/sigverify/etc., stays
//     trivially unit-testable, and composes with — rather than replaces — the
//     policy engine: a configurable admission threshold (warn/block above a band)
//     layers on top of the existing gates exactly as the policy engine does.
//
// All exported methods are safe for concurrent use. The pure scoring path
// (Score) never mutates engine state; Record folds an assessment into the
// retained history and band counters for trend visibility and metrics.
package riskscore

import (
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// Band is a coarse risk classification derived from the composite score. The
// ordering low < medium < high < critical is meaningful and used by the
// admission threshold comparison.
type Band string

const (
	BandLow      Band = "low"
	BandMedium   Band = "medium"
	BandHigh     Band = "high"
	BandCritical Band = "critical"
)

// bandRank returns a comparable ordinal for b (low=0 .. critical=3), or -1 for
// an unrecognized value so a malformed threshold can never silently match.
func bandRank(b Band) int {
	switch b {
	case BandLow:
		return 0
	case BandMedium:
		return 1
	case BandHigh:
		return 2
	case BandCritical:
		return 3
	default:
		return -1
	}
}

// ParseBand normalizes a string into a Band, returning ok=false for an
// unrecognized value.
func ParseBand(s string) (Band, bool) {
	switch Band(s) {
	case BandLow, BandMedium, BandHigh, BandCritical:
		return Band(s), true
	default:
		return "", false
	}
}

// ThresholdAction is what the admission threshold does when an artifact's band
// meets or exceeds the configured trigger band.
type ThresholdAction string

const (
	// ThresholdOff disables the admission threshold entirely: the engine scores
	// and records artifacts (for metrics, the admin UI, and trend history) but
	// never influences serving. This is the default, so enabling the engine is
	// non-disruptive.
	ThresholdOff ThresholdAction = "off"
	// ThresholdWarn admits the artifact but annotates the response and emits a
	// threshold-crossing notification.
	ThresholdWarn ThresholdAction = "warn"
	// ThresholdBlock refuses the artifact with a 403, like the other hard gates.
	ThresholdBlock ThresholdAction = "block"
)

// ParseThresholdAction normalizes a string into a ThresholdAction, returning
// ok=false for an unrecognized value.
func ParseThresholdAction(s string) (ThresholdAction, bool) {
	switch ThresholdAction(s) {
	case ThresholdOff, ThresholdWarn, ThresholdBlock:
		return ThresholdAction(s), true
	default:
		return "", false
	}
}

// SignalKind identifies a contributing signal. The values are stable, lowercase
// identifiers suitable for metric labels and UI keys.
type SignalKind string

const (
	SignalVulnerability SignalKind = "vulnerability"
	SignalSignature     SignalKind = "signature"
	SignalLicense       SignalKind = "license"
	SignalNameguard     SignalKind = "nameguard"
	SignalSecret        SignalKind = "secret"
	SignalProvenance    SignalKind = "provenance"
	SignalQuarantine    SignalKind = "quarantine"
	SignalInstallHooks  SignalKind = "installhooks"
	SignalAVScan        SignalKind = "avscan"
	SignalContentScan   SignalKind = "contentscan"
	SignalRepoHealth    SignalKind = "repohealth"
	SignalRebuildVerify SignalKind = "rebuildverify"
	SignalContinuity    SignalKind = "continuity"
)

// allSignals is the canonical evaluation order, used to build the contribution
// list deterministically (so identical inputs always produce byte-identical
// assessments).
var allSignals = []SignalKind{
	SignalVulnerability,
	SignalSignature,
	SignalLicense,
	SignalNameguard,
	SignalSecret,
	SignalProvenance,
	SignalQuarantine,
	SignalInstallHooks,
	SignalAVScan,
	SignalContentScan,
	SignalRepoHealth,
	SignalRebuildVerify,
	SignalContinuity,
}

// Subject is the unit scored by the engine: the aggregated admission document
// (the same one the policy-as-code engine evaluates) plus signals that are not
// part of that document.
type Subject struct {
	// Input is the aggregated admission signal document produced by the gates.
	Input policyengine.Input
	// Quarantine, when non-nil, carries the artifact's CVE-drift quarantine state
	// (Task 18). It is supplied by callers that know it (the re-scan / admin path);
	// the per-request admission accumulator leaves it nil, in which case the
	// quarantine signal is simply not applicable and excluded from the score.
	Quarantine *QuarantineSignal
}

// QuarantineSignal carries the CVE-drift quarantine state for an artifact.
type QuarantineSignal struct {
	Quarantined bool   `json:"quarantined"`
	Advisory    string `json:"advisory,omitempty"`
}

// Artifact identifies the scored artifact in an assessment.
type Artifact struct {
	Ecosystem  string `json:"ecosystem,omitempty"`
	Backend    string `json:"backend,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Coordinate string `json:"coordinate,omitempty"`
}

// Contribution is one signal's explainable share of the composite score. The
// invariant the UI and operators rely on is:
//
//	Points == NormalizedWeight * Subscore * 100
//
// and the Points of every contribution sum to the composite Score (before the
// final integer rounding).
type Contribution struct {
	// Signal identifies the contributing gate.
	Signal SignalKind `json:"signal"`
	// Subscore is the signal's normalized risk in [0,1] (0 = no risk).
	Subscore float64 `json:"subscore"`
	// Weight is the configured (raw) weight for this signal.
	Weight float64 `json:"weight"`
	// NormalizedWeight is Weight divided by the sum of the weights of all
	// applicable signals, so it sums to 1 across the contributions.
	NormalizedWeight float64 `json:"normalizedWeight"`
	// Points is the marginal contribution to the 0..100 composite score.
	Points float64 `json:"points"`
	// Raw is a short human-readable rendering of the underlying raw value(s).
	Raw string `json:"raw,omitempty"`
	// Detail carries the structured raw values that produced the sub-score.
	Detail map[string]any `json:"detail,omitempty"`
}

// Assessment is the explainable result of scoring a Subject.
type Assessment struct {
	Tenant   string   `json:"tenant,omitempty"`
	Artifact Artifact `json:"artifact"`
	// Score is the composite normalized risk in [0,100].
	Score int  `json:"score"`
	Band  Band `json:"band"`

	// Action is the effective admission action for this artifact given the
	// configured threshold (off/warn/block). Block and Warn restate it as
	// booleans for convenient call-site branching.
	Action ThresholdAction `json:"action"`
	Block  bool            `json:"block"`
	Warn   bool            `json:"warn"`
	// Exceeds reports whether the band met or exceeded the configured threshold
	// band (independent of whether the action is off).
	Exceeds bool `json:"exceeds"`

	// ThresholdBand / ThresholdAction echo the configuration in force for the
	// tenant when this assessment was produced, so a persisted assessment is
	// self-explaining even after the policy changes.
	ThresholdBand   Band            `json:"thresholdBand"`
	ThresholdAction ThresholdAction `json:"thresholdAction"`

	// Contributions is the explainable breakdown, in canonical signal order,
	// including only signals that were applicable (present) for this artifact.
	Contributions []Contribution `json:"contributions"`
	// Skipped lists the signals that were not available for this artifact and
	// therefore excluded from the weighted average.
	Skipped []SignalKind `json:"skipped,omitempty"`

	// Summary is a one-line, human-readable explanation naming the top drivers.
	Summary  string    `json:"summary"`
	ScoredAt time.Time `json:"scoredAt"`
}

// ThresholdInfo restates the admission threshold for the snapshot/admin surface.
type ThresholdInfo struct {
	Band   Band            `json:"band"`
	Action ThresholdAction `json:"action"`
}

// Snapshot is the cumulative engine state for the admin API and metrics.
type Snapshot struct {
	Enabled     bool             `json:"enabled"`
	TotalScored int64            `json:"totalScored"`
	ByBand      map[string]int64 `json:"byBand"`
	Blocked     int64            `json:"blocked"`
	Warned      int64            `json:"warned"`
	Crossings   int64            `json:"crossings"`
	Threshold   ThresholdInfo    `json:"threshold"`
	Weights     Weights          `json:"weights"`
	Bands       BandThresholds   `json:"bands"`
	HistorySize int              `json:"historySize"`
	// Recent holds the most recently scored artifacts, most-recent-first, for the
	// trend view and drill-down.
	Recent []Assessment `json:"recent"`
}
