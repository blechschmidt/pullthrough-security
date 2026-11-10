// Package anomaly implements behavioral anomaly detection over the pull stream
// (Task 43). Where the other admission gates each judge a single artifact, this
// subsystem watches the *traffic* a tenant or identity generates over time and
// flags patterns that signal a compromised credential or active exfiltration
// rather than one bad package:
//
//   - distinct-package fan-out: a sudden spike in the number of distinct packages
//     pulled by one identity in a short window (enumeration / dependency sweep);
//   - new-namespace discovery: first-ever pulls of many never-before-seen
//     namespaces, characteristic of a stolen token probing what it can reach;
//   - off-hours bursts: heavy request volume during configured off-hours, when a
//     legitimate CI identity is normally idle;
//   - rapid enumeration: many 404 / negative-cache misses in a window, the
//     signature of a brute-force name sweep;
//   - anomalous egress: byte volume far above the scope's own rolling baseline,
//     the signature of bulk data exfiltration.
//
// The detectors are deliberately lightweight: rolling time windows and EWMA
// baselines (see stats.go), no external ML dependency and no unbounded state.
// Each observation produces an explainable Assessment — a per-detector breakdown
// plus an overall graded Level and a recommended Action — that the proxy folds
// into the existing notify subsystem and (optionally) uses to soft-block further
// traffic from an identity that is currently behaving anomalously.
//
// The Engine's scoring path (Observe) is the only mutator; Status and Snapshot
// are read-only views for the soft-block gate, the admin surface, and metrics.
// All exported methods are safe for concurrent use.
package anomaly

import "time"

// DetectorKind identifies one behavioral detector. The values are stable,
// lowercase identifiers suitable for metric labels, notification fields, and
// admin/UI keys.
type DetectorKind string

const (
	// DetectorFanout flags a spike in distinct packages pulled by one scope.
	DetectorFanout DetectorKind = "fanout"
	// DetectorNewNamespace flags first-ever pulls of many new namespaces.
	DetectorNewNamespace DetectorKind = "new_namespace"
	// DetectorOffHours flags heavy request volume during configured off-hours.
	DetectorOffHours DetectorKind = "off_hours"
	// DetectorEnumeration flags many 404/negative-cache hits (name brute-forcing).
	DetectorEnumeration DetectorKind = "enumeration"
	// DetectorEgress flags byte volume far above the scope's rolling baseline.
	DetectorEgress DetectorKind = "egress"
)

// allDetectors is the canonical evaluation order, used to build the per-detector
// breakdown deterministically so identical input streams produce byte-identical
// assessments.
var allDetectors = []DetectorKind{
	DetectorFanout,
	DetectorNewNamespace,
	DetectorOffHours,
	DetectorEnumeration,
	DetectorEgress,
}

// AllDetectors returns the canonical detector ordering.
func AllDetectors() []DetectorKind {
	out := make([]DetectorKind, len(allDetectors))
	copy(out, allDetectors)
	return out
}

// Level is the coarse, ordered severity of an anomaly signal. The ordering
// none < low < medium < high is meaningful and drives the warn/block decision.
type Level string

const (
	LevelNone   Level = "none"
	LevelLow    Level = "low"
	LevelMedium Level = "medium"
	LevelHigh   Level = "high"
)

// levelRank returns a comparable ordinal for l (none=0 .. high=3), or -1 for an
// unrecognized value so a malformed threshold can never silently match.
func levelRank(l Level) int {
	switch l {
	case LevelNone:
		return 0
	case LevelLow:
		return 1
	case LevelMedium:
		return 2
	case LevelHigh:
		return 3
	default:
		return -1
	}
}

// ParseLevel normalizes a string into a Level, returning ok=false for an
// unrecognized value.
func ParseLevel(s string) (Level, bool) {
	switch Level(s) {
	case LevelNone, LevelLow, LevelMedium, LevelHigh:
		return Level(s), true
	default:
		return "", false
	}
}

// levelForScore maps a 0..100 overall score to a Level using the configured
// cutoffs. The cutoffs align with the ramp pinning (warn→50, high→100) so a
// single detector at its warn cutoff yields medium and one at its high cutoff
// yields high.
func levelForScore(score float64, medium, high float64) Level {
	switch {
	case score >= high:
		return LevelHigh
	case score >= medium:
		return LevelMedium
	case score > 0:
		return LevelLow
	default:
		return LevelNone
	}
}

// Action is the recommended response to an assessment, derived from its Level
// and the configured warn/block thresholds.
type Action string

const (
	// ActionObserve records the assessment but takes no action (the default and
	// the only behavior until the warn/block levels are crossed).
	ActionObserve Action = "observe"
	// ActionWarn emits a graded notification but still serves the request.
	ActionWarn Action = "warn"
	// ActionBlock soft-blocks further traffic from the scope (HTTP 429) until its
	// behavior returns to baseline.
	ActionBlock Action = "block"
)

// ParseAction normalizes a string into an Action, returning ok=false for an
// unrecognized value.
func ParseAction(s string) (Action, bool) {
	switch Action(s) {
	case ActionObserve, ActionWarn, ActionBlock:
		return Action(s), true
	default:
		return "", false
	}
}

// Observation is one unit of pull traffic fed to the engine. The proxy builds it
// from the authenticated principal and the resolved artifact; tests build it
// directly. Time is supplied by the caller so detection is deterministic and
// testable.
type Observation struct {
	// Tenant is the team/tenant the request was billed to (may be empty).
	Tenant string
	// Identity is the stable caller identity (token subject); the scope is keyed
	// by tenant+identity so one compromised token is isolated from its tenant's
	// healthy traffic.
	Identity string
	// Ecosystem and Backend describe the upstream the artifact came from.
	Ecosystem string
	Backend   string
	// Namespace is the artifact's namespace/group (e.g. the npm scope, the Go
	// module path prefix, the Maven groupId). Empty namespaces are ignored by the
	// new-namespace detector.
	Namespace string
	// Package is the artifact coordinate (name or name@version), used as the
	// distinct-fan-out key.
	Package string
	// Bytes is the response body size served, or 0 for a not-yet-served / errored
	// request.
	Bytes int64
	// NotFound marks a 404 / negative-cache outcome, feeding the enumeration
	// detector.
	NotFound bool
	// Time is when the request occurred.
	Time time.Time
}

// scope returns the key the observation is aggregated under. An empty identity
// falls back to the tenant alone; an empty tenant falls back to the identity.
func (o Observation) scope() string {
	switch {
	case o.Tenant != "" && o.Identity != "":
		return o.Tenant + "|" + o.Identity
	case o.Identity != "":
		return o.Identity
	default:
		return o.Tenant
	}
}

// DetectorResult is one detector's explainable contribution to an assessment.
type DetectorResult struct {
	// Detector identifies the contributing detector.
	Detector DetectorKind `json:"detector"`
	// Score is the normalized anomaly score in [0,1] (0 = nominal).
	Score float64 `json:"score"`
	// Level is the per-detector coarse severity.
	Level Level `json:"level"`
	// Value is the observed metric in the detector's natural unit (distinct
	// count, request count, 404 count, or egress z-score).
	Value float64 `json:"value"`
	// Baseline is the comparison point: the configured warn cutoff for the
	// threshold detectors, or the rolling mean for the egress detector.
	Baseline float64 `json:"baseline"`
	// Triggered reports whether the detector met or exceeded its warn cutoff.
	Triggered bool `json:"triggered"`
	// Detail is a short, human-readable rendering of the underlying numbers.
	Detail string `json:"detail,omitempty"`
}

// Assessment is the explainable result of observing one request. It is a pure
// function of the scope's accumulated state and the observation, recorded into
// the engine's history when it crosses the warn threshold.
type Assessment struct {
	Tenant   string `json:"tenant,omitempty"`
	Identity string `json:"identity,omitempty"`
	Scope    string `json:"scope"`

	// Score is the overall anomaly score in [0,100] (the strongest detector).
	Score float64 `json:"score"`
	Level Level   `json:"level"`
	// Action is the effective response given the configured warn/block levels.
	Action Action `json:"action"`
	Block  bool   `json:"block"`
	Warn   bool   `json:"warn"`

	// Detectors is the per-detector breakdown, in canonical order.
	Detectors []DetectorResult `json:"detectors"`
	// Triggered names the detectors at or above their warn cutoff, strongest
	// first, for a compact summary.
	Triggered []DetectorKind `json:"triggered,omitempty"`

	// Summary is a one-line, human-readable explanation.
	Summary string `json:"summary"`
	// Alert reports whether this assessment should raise a notification (it
	// crossed the warn level and cleared the per-scope alert cooldown / escalated
	// since the last alert).
	Alert      bool      `json:"alert"`
	ObservedAt time.Time `json:"observedAt"`
}

// Trigger is a recorded anomaly event for the admin trend view: the salient
// fields of an alerting assessment, retained in a bounded ring.
type Trigger struct {
	Tenant   string       `json:"tenant,omitempty"`
	Identity string       `json:"identity,omitempty"`
	Scope    string       `json:"scope"`
	Detector DetectorKind `json:"detector"`
	Level    Level        `json:"level"`
	Action   Action       `json:"action"`
	Score    float64      `json:"score"`
	Summary  string       `json:"summary"`
	At       time.Time    `json:"at"`
}

// ScopeStatus is the current standing of one scope: its latest score, level, and
// per-detector breakdown. It is the soft-block gate's read model and the admin
// surface's per-scope row.
type ScopeStatus struct {
	Scope     string           `json:"scope"`
	Tenant    string           `json:"tenant,omitempty"`
	Identity  string           `json:"identity,omitempty"`
	Score     float64          `json:"score"`
	Level     Level            `json:"level"`
	Action    Action           `json:"action"`
	Detectors []DetectorResult `json:"detectors,omitempty"`
	UpdatedAt time.Time        `json:"updatedAt"`
}

// ThresholdInfo restates the effective warn/block configuration for the snapshot.
type ThresholdInfo struct {
	WarnLevel  Level `json:"warnLevel"`
	BlockLevel Level `json:"blockLevel"`
}

// Snapshot is the cumulative engine state for the admin API and metrics.
type Snapshot struct {
	Enabled        bool             `json:"enabled"`
	Observed       int64            `json:"observed"`
	Alerts         int64            `json:"alerts"`
	SoftBlocks     int64            `json:"softBlocks"`
	ByLevel        map[string]int64 `json:"byLevel"`
	TriggersByType map[string]int64 `json:"triggersByType"`
	Threshold      ThresholdInfo    `json:"threshold"`
	Window         string           `json:"window"`
	TrackedScopes  int              `json:"trackedScopes"`
	// Scopes lists the currently-tracked scopes, strongest score first.
	Scopes []ScopeStatus `json:"scopes"`
	// Recent holds the most recent triggers, most-recent first.
	Recent []Trigger `json:"recent"`
}
