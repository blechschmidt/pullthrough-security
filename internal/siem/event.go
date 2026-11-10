// Package siem implements an outbound log-forwarding subsystem (Task 119) that
// streams the proxy's tamper-evident audit-log records and admission-gate
// findings to external SIEMs. It supports Splunk HTTP Event Collector (HEC) and
// a generic syslog/CEF (Common Event Format) TCP/UDP sink, with batching, retry
// with exponential backoff, TLS, and a bounded in-memory queue with optional
// disk spill so forwarding failures never block the pull path.
//
// The forwarder is a strictly read-only consumer of the audit log: it taps the
// already-hashed, already-chained records after the durable sink has committed
// them (see WrapAuditSink), so the local log's hash-chain integrity is never
// affected by SIEM forwarding.
package siem

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// Source identifies which internal stream an event originated from. It becomes
// a label/field on the forwarded record so a SIEM can route audit traffic and
// gate findings to distinct indices or dashboards.
type Source string

const (
	// SourceAudit marks an event derived from a tamper-evident audit-log record.
	SourceAudit Source = "audit"
	// SourceFinding marks an event derived from a normalized admission-gate
	// finding.
	SourceFinding Source = "finding"
)

// Severity is the canonical, ordered severity vocabulary shared across the
// forwarder, its config, and both sink formats. It mirrors the scale used by
// the findings and notification subsystems so a finding's severity maps across
// unchanged.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// rank returns the ordinal of a severity for threshold comparisons; an unknown
// value ranks as info so a typo never silently escalates past a configured
// floor.
func (s Severity) rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// AtLeast reports whether s is at or above the floor min.
func (s Severity) AtLeast(min Severity) bool { return s.rank() >= min.rank() }

// NormalizeSeverity coerces an arbitrary string to a known Severity, defaulting
// to info for the empty or unrecognized case.
func NormalizeSeverity(v string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(v))) {
	case SeverityLow:
		return SeverityLow
	case SeverityMedium:
		return SeverityMedium
	case SeverityHigh:
		return SeverityHigh
	case SeverityCritical:
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// ValidSeverity reports whether v names a known severity (used by config
// validation). The empty string is accepted (it defaults to info downstream).
func ValidSeverity(v string) bool {
	if strings.TrimSpace(v) == "" {
		return true
	}
	switch Severity(strings.ToLower(strings.TrimSpace(v))) {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// cefSeverity maps the canonical severity onto the CEF 0..10 integer scale.
func (s Severity) cefSeverity() int {
	switch s {
	case SeverityLow:
		return 3
	case SeverityMedium:
		return 5
	case SeverityHigh:
		return 8
	case SeverityCritical:
		return 10
	default:
		return 1
	}
}

// Event is the normalized, transport-agnostic unit the forwarder queues and the
// sinks render. It carries both a flat field map (for CEF extensions and
// indexed SIEM fields) and enough identity to key and search the record. Values
// must never contain secrets: the audit log and findings model already exclude
// credential material, and this type preserves that contract.
type Event struct {
	// Source is the originating internal stream (audit|finding).
	Source Source `json:"source"`
	// Time is the event's occurrence time (UTC).
	Time time.Time `json:"time"`
	// Severity is the canonical severity used for the min-severity floor and the
	// CEF severity field.
	Severity Severity `json:"severity"`
	// Category is a stable, coarse classifier: the audit EventType or the
	// originating gate name.
	Category string `json:"category"`
	// Name is a short human-readable title (the CEF "name" field).
	Name string `json:"name"`
	// Outcome is the decision/outcome for audit events (allow|deny|error) or the
	// SARIF level for findings (error|warning|note|none); empty when N/A.
	Outcome string `json:"outcome,omitempty"`
	// Subject identifies the actor or tenant, when known.
	Subject string `json:"subject,omitempty"`
	// Message is the full human-readable description.
	Message string `json:"message,omitempty"`
	// Fields carries structured, low-cardinality key/value detail surfaced as
	// CEF extensions and as nested fields in the HEC event payload.
	Fields map[string]string `json:"fields,omitempty"`
}

// sortedFieldKeys returns the event's field keys in deterministic order so
// rendered CEF extensions and test assertions are stable.
func (e Event) sortedFieldKeys() []string {
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// setField sets a non-empty field, lazily allocating the map.
func (e *Event) setField(k, v string) {
	if v == "" {
		return
	}
	if e.Fields == nil {
		e.Fields = make(map[string]string)
	}
	e.Fields[k] = v
}

// EventFromAuditRecord projects a tamper-evident audit record onto a SIEM event.
// The record is treated as read-only; nothing here participates in the hash
// chain. The record's sequence number and hashes are preserved as fields so a
// SIEM analyst can correlate a forwarded event back to its position in the local
// log (and, with the chain key, verify it).
func EventFromAuditRecord(rec audit.Record) Event {
	ev := rec.Event
	e := Event{
		Source:   SourceAudit,
		Time:     ev.Time.UTC(),
		Severity: auditSeverity(ev),
		Category: string(ev.Type),
		Name:     auditName(ev),
		Outcome:  string(ev.Decision),
		Subject:  ev.Subject,
		Message:  ev.Reason,
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.setField("seq", strconv.FormatUint(rec.Seq, 10))
	e.setField("hash", rec.Hash)
	e.setField("prevHash", rec.PrevHash)
	e.setField("team", ev.Team)
	e.setField("method", ev.Method)
	e.setField("backend", ev.Backend)
	e.setField("ecosystem", ev.Ecosystem)
	e.setField("resource", ev.Resource)
	e.setField("remoteAddr", ev.RemoteAddr)
	if ev.Status != 0 {
		e.setField("status", strconv.Itoa(ev.Status))
	}
	e.setField("traceId", ev.TraceID)
	e.setField("spanId", ev.SpanID)
	for k, v := range ev.Detail {
		e.setField("detail."+k, scalarString(v))
	}
	return e
}

// auditName renders a concise one-line title for an audited event.
func auditName(ev audit.Event) string {
	switch {
	case ev.Decision != "":
		return string(ev.Type) + " " + string(ev.Decision)
	default:
		return string(ev.Type)
	}
}

// auditSeverity assigns a severity to an audit event. Audit records carry no
// native severity, so a conservative mapping is applied: denials and errors on
// security-relevant decisions are elevated so a SIEM can alert on them, while
// routine pulls/cache events remain informational.
func auditSeverity(ev audit.Event) Severity {
	switch ev.Decision {
	case audit.DecisionError:
		return SeverityHigh
	case audit.DecisionDeny:
		switch ev.Type {
		case audit.EventPolicy, audit.EventEgress, audit.EventScanVerdict:
			return SeverityHigh
		default:
			return SeverityMedium
		}
	}
	switch ev.Type {
	case audit.EventEgress:
		return SeverityHigh
	case audit.EventAdmin, audit.EventGitOps, audit.EventSnapshot:
		return SeverityMedium
	default:
		return SeverityInfo
	}
}

// EventFromFinding projects a normalized admission-gate finding (within the
// context of its document's artifact and tenant) onto a SIEM event.
func EventFromFinding(doc findings.Document, f findings.Finding) Event {
	coord := f.Location.Coordinate
	if coord == "" {
		coord = doc.Artifact.Coordinate
	}
	e := Event{
		Source:   SourceFinding,
		Time:     doc.GeneratedAt.UTC(),
		Severity: NormalizeSeverity(string(f.Severity)),
		Category: string(f.Gate),
		Name:     f.Title,
		Outcome:  string(f.Level),
		Subject:  doc.Tenant,
		Message:  f.Message,
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.setField("ruleId", f.RuleID)
	e.setField("gate", string(f.Gate))
	e.setField("identifier", f.Identifier)
	e.setField("coordinate", coord)
	e.setField("ecosystem", doc.Artifact.Ecosystem)
	e.setField("backend", doc.Artifact.Backend)
	e.setField("artifact", doc.Artifact.Name)
	e.setField("version", doc.Artifact.Version)
	e.setField("digest", doc.Artifact.Digest)
	e.setField("file", f.Location.File)
	e.setField("commitSha", firstNonEmpty(f.Location.CommitSHA, doc.Artifact.CommitSHA))
	e.setField("repositoryUrl", firstNonEmpty(f.Location.RepositoryURL, doc.Artifact.RepositoryURL))
	if f.Suppressed {
		e.setField("suppressed", "true")
		e.setField("justification", f.Justification)
	}
	return e
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// scalarString renders a primitive detail value as a compact string. Composite
// values are rendered with the default verb; the audit model documents that
// Detail values are primitive, so this is a best-effort fallback.
func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return ""
	}
}
