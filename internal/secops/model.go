package secops

import (
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// NotableEvent is one security-relevant admission decision in the SOC feed: a
// flattened, drill-down-ready projection of a notify.Event annotated with the
// derived Outcome and owning Gate. It is both a feed row and the server-sent
// event payload streamed to the dashboard.
type NotableEvent struct {
	Seq       uint64            `json:"seq"`
	Time      time.Time         `json:"time"`
	Type      string            `json:"type"`     // notify event type (routing/grouping key)
	Gate      string            `json:"gate"`     // owning subsystem key (drill-down target)
	Outcome   Outcome           `json:"outcome"`  // block|warn|admit
	Severity  string            `json:"severity"` // info|low|medium|high|critical
	Title     string            `json:"title"`
	Summary   string            `json:"summary,omitempty"`
	Ecosystem string            `json:"ecosystem,omitempty"`
	Backend   string            `json:"backend,omitempty"`
	Artifact  string            `json:"artifact,omitempty"`
	Subject   string            `json:"subject,omitempty"` // actor or tenant/identity scope
	Fields    map[string]string `json:"fields,omitempty"`
}

// Count is one (key, value) tally in a breakdown (by gate, subject, severity).
type Count struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

// WindowStats is the rolling-window decision tally: the top-line block/warn/admit
// split plus the breakdowns the SOC view charts.
type WindowStats struct {
	Total      int64   `json:"total"`
	Blocks     int64   `json:"blocks"`
	Warns      int64   `json:"warns"`
	Admits     int64   `json:"admits"`
	ByGate     []Count `json:"byGate"`
	BySubject  []Count `json:"bySubject"`
	BySeverity []Count `json:"bySeverity"`
}

// Summary is the complete SOC read-model returned by /api/secops/summary.
type Summary struct {
	GeneratedAt   time.Time       `json:"generatedAt"`
	WindowSeconds float64         `json:"windowSeconds"`
	Window        WindowStats     `json:"window"`
	Posture       Posture         `json:"posture"`
	Recent        []NotableEvent  `json:"recent"`
	Subsystems    map[string]bool `json:"subsystems"`
}

// classify projects a notify.Event into a NotableEvent: it derives the coarse
// Outcome and the owning gate (the drill-down target) from the event type and
// its action/decision fields, without re-deriving any verdict — it only labels
// what the emitting subsystem already decided.
func classify(ev notify.Event) NotableEvent {
	gate := gateFor(ev.Type)
	out := outcomeFor(ev)
	return NotableEvent{
		Time:      ev.Time,
		Type:      string(ev.Type),
		Gate:      gate,
		Outcome:   out,
		Severity:  string(ev.Severity),
		Title:     ev.Title,
		Summary:   ev.Summary,
		Ecosystem: ev.Ecosystem,
		Backend:   ev.Backend,
		Artifact:  ev.Artifact,
		Subject:   ev.Subject,
		Fields:    ev.Fields,
	}
}

// gateFor maps an event type to the owning subsystem key. The key doubles as the
// dashboard drill-down target (the front-end maps it to a tab).
func gateFor(t notify.EventType) string {
	switch t {
	case notify.EventPolicyBlock:
		return "policyengine"
	case notify.EventVulnerability, notify.EventQuarantine, notify.EventRescanRegression:
		return "vulnscan"
	case notify.EventCommitScan:
		return "secretscan"
	case notify.EventProvenanceFailure:
		return "provenance"
	case notify.EventLicense:
		return "license"
	case notify.EventRiskScore:
		return "riskscore"
	case notify.EventUpstreamCircuitOpen:
		return "upstreams"
	case notify.EventAnomaly:
		return "anomaly"
	case notify.EventMaliciousBlock:
		return "malfeed"
	case notify.EventApproval:
		return "approvals"
	case notify.EventCacheGC:
		return "cache"
	case notify.EventExtension:
		return "extensions"
	case notify.EventMeteringBudget:
		return "metering"
	case notify.EventEgressBlocked:
		return "egress"
	case notify.EventMaintainerDrift:
		return "continuity"
	case notify.EventKeyExpiry, notify.EventKeyRotated:
		return "keyrotation"
	default:
		return string(t)
	}
}

// outcomeFor derives the coarse admission disposition. It prefers an explicit
// action/decision field (the gate's own outcome), falling back to a per-type
// default. Most security events that warrant a notification are blocks or warns;
// only an explicit override (a granted break-glass exception) reads as an admit.
func outcomeFor(ev notify.Event) Outcome {
	action := strings.ToLower(strings.TrimSpace(firstField(ev.Fields, "action", "decision")))

	// Approvals encode the workflow transition in the action field.
	if ev.Type == notify.EventApproval {
		switch action {
		case "granted":
			return OutcomeAdmit // a time-boxed allow override
		case "denied", "expired":
			return OutcomeBlock // the block stands / is reinstated
		default: // requested
			return OutcomeWarn
		}
	}

	switch action {
	case "block", "quarantine":
		return OutcomeBlock
	case "warn":
		return OutcomeWarn
	case "observe", "allow", "admit":
		return OutcomeAdmit
	}

	// No usable action field: fall back to the type's intrinsic disposition.
	switch ev.Type {
	case notify.EventPolicyBlock, notify.EventMaliciousBlock,
		notify.EventProvenanceFailure, notify.EventQuarantine,
		notify.EventEgressBlocked:
		return OutcomeBlock
	default:
		return OutcomeWarn
	}
}

// firstField returns the first non-empty value among keys, or "".
func firstField(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
