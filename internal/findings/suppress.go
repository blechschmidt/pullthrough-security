package findings

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// This file implements the immutable suppression audit trail (Task 165).
//
// A finding can be suppressed or downgraded away from a build-failing verdict by
// several mechanisms: a VEX statement adjudicating a vulnerability
// not_affected/fixed (Task 27), a reachability analysis proving a vulnerable
// component is never reached (Task 118), an operator-authored policy rule, or a
// human break-glass approval (Task 50). Each of those is a security-relevant
// decision an auditor must be able to reconstruct: who or what suppressed the
// finding, under which mechanism, and why.
//
// SuppressionLedger is an append-only, immutable record of every such decision,
// queryable per coordinate and mirrored into the tamper-evident audit log. It is
// deliberately decoupled from the audit package (it writes through a narrow
// AuditSink interface) so the findings package stays free of heavy dependencies
// and import cycles.

// Mechanism classifies how a finding was suppressed or downgraded.
type Mechanism string

const (
	// MechanismVEX is a VEX statement (not_affected / fixed) adjudicating a
	// vulnerability away.
	MechanismVEX Mechanism = "vex"
	// MechanismReachability is a reachability analysis proving a vulnerable
	// component unreachable from the artifact's own code.
	MechanismReachability Mechanism = "reachability"
	// MechanismPolicy is an operator-authored policy rule downgrading a finding.
	MechanismPolicy Mechanism = "policy"
	// MechanismBreakGlass is a human break-glass approval overriding a block.
	MechanismBreakGlass Mechanism = "break-glass"
)

// SuppressionRecord is one immutable suppression-audit entry. Once appended to
// the ledger it is never mutated (a later re-observation of the same suppression
// only updates the bookkeeping LastSeen/Count, never the recorded decision).
type SuppressionRecord struct {
	// Seq is the ledger's monotonic sequence number (1-based).
	Seq uint64 `json:"seq"`
	// Time is when the suppression was first recorded.
	Time time.Time `json:"time"`
	// Tenant scopes the record (empty for the untenanted/global tenant).
	Tenant string `json:"tenant,omitempty"`
	// Coordinate is the package coordinate the suppressed finding applies to.
	Coordinate string `json:"coordinate"`
	// Digest is the artifact content digest the suppression was recorded against.
	Digest string `json:"digest,omitempty"`
	// Category / RuleID / Identifier / Gate identify the suppressed finding.
	Category   Category `json:"category,omitempty"`
	RuleID     string   `json:"ruleId,omitempty"`
	Identifier string   `json:"identifier,omitempty"`
	Gate       Gate     `json:"gate,omitempty"`
	// Mechanism is how the finding was suppressed.
	Mechanism Mechanism `json:"mechanism"`
	// Actor is who or what performed the suppression — the VEX status/author, the
	// policy rule id, the break-glass approver, or "system" for an automatic
	// downgrade.
	Actor string `json:"actor,omitempty"`
	// Justification is the human-readable reason the finding was suppressed.
	Justification string `json:"justification,omitempty"`
	// Locator is the within-category locator (file:line or advisory@component),
	// retained so the entry can be correlated back to the exact finding.
	Locator string `json:"locator,omitempty"`
	// LastSeen is the most recent pull at which this suppression was re-observed,
	// and Count how many times in total. These are the only mutable fields.
	LastSeen time.Time `json:"lastSeen"`
	Count    uint64    `json:"count"`
}

// AuditSink is the narrow seam through which the ledger mirrors a newly-recorded
// suppression into the tamper-evident audit log. The cmd wiring supplies an
// adapter over *audit.Logger; a nil sink disables mirroring. Only the first
// observation of a given suppression is emitted, so the hash-chained log is not
// spammed by repeat pulls of the same artifact.
type AuditSink interface {
	RecordSuppression(ctx context.Context, rec SuppressionRecord) error
}

// SuppressionMetrics is the cumulative, scrape-time view of ledger activity for
// the Prometheus bridge. Counters are monotonic.
type SuppressionMetrics struct {
	Recorded      uint64            // distinct suppressions recorded
	Observed      uint64            // total observations (incl. repeats)
	ByMechanism   map[string]uint64 // distinct suppressions, by mechanism
	Current       int               // live ledger size
	AuditErrors   uint64            // audit-sink mirroring failures
	AuditMirrored uint64            // suppressions mirrored to the audit log
}

// SuppressionLedger is an append-only, bounded, thread-safe suppression audit
// trail. New entries are deduplicated by their decision identity (tenant +
// coordinate + digest + category + locator + mechanism) so repeated pulls of the
// same artifact do not create duplicate entries; a repeat only bumps the
// existing entry's Count/LastSeen and is not re-mirrored to the audit log.
type SuppressionLedger struct {
	mu      sync.Mutex
	max     int
	now     func() time.Time
	seq     uint64
	order   []string // identity keys in insertion order, for eviction + listing
	entries map[string]*SuppressionRecord
	sink    AuditSink

	recorded    uint64
	observed    uint64
	byMechanism map[Mechanism]uint64
	auditErr    uint64
	auditOK     uint64
}

// SuppressionLedgerOptions configures a SuppressionLedger.
type SuppressionLedgerOptions struct {
	// MaxEntries bounds retained records (oldest-evicted). <=0 uses a default.
	MaxEntries int
	// Sink, when non-nil, receives each newly-recorded suppression for mirroring
	// into the tamper-evident audit log.
	Sink AuditSink
	// Now overrides the clock (tests). Nil uses time.Now.
	Now func() time.Time
}

const defaultMaxSuppressions = 8192

// NewSuppressionLedger constructs a ledger.
func NewSuppressionLedger(opts SuppressionLedgerOptions) *SuppressionLedger {
	max := opts.MaxEntries
	if max <= 0 {
		max = defaultMaxSuppressions
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &SuppressionLedger{
		max:         max,
		now:         now,
		entries:     make(map[string]*SuppressionRecord, 64),
		sink:        opts.Sink,
		byMechanism: make(map[Mechanism]uint64),
	}
}

func suppressionKey(r SuppressionRecord) string {
	return strings.ToLower(r.Tenant) + "\x00" +
		strings.ToLower(r.Coordinate) + "\x00" +
		strings.ToLower(r.Digest) + "\x00" +
		string(r.Category) + "\x00" +
		r.Locator + "\x00" +
		string(r.Mechanism)
}

// Record appends a suppression to the ledger (or bumps the existing entry for a
// repeat observation) and, on first observation, mirrors it to the audit log.
// It returns true when a new, distinct suppression was recorded. A nil ledger is
// a no-op returning false, so callers need no nil checks.
func (l *SuppressionLedger) Record(ctx context.Context, rec SuppressionRecord) bool {
	if l == nil {
		return false
	}
	if rec.Coordinate == "" || rec.Mechanism == "" {
		return false
	}
	now := l.now()

	l.mu.Lock()
	l.observed++
	key := suppressionKey(rec)
	if existing, ok := l.entries[key]; ok {
		existing.Count++
		existing.LastSeen = now
		l.mu.Unlock()
		return false
	}
	l.seq++
	rec.Seq = l.seq
	if rec.Time.IsZero() {
		rec.Time = now
	}
	rec.LastSeen = now
	rec.Count = 1
	stored := rec
	l.entries[key] = &stored
	l.order = append(l.order, key)
	l.recorded++
	l.byMechanism[rec.Mechanism]++
	l.evictLocked()
	sink := l.sink
	l.mu.Unlock()

	// Mirror outside the lock so a slow/failing audit sink never stalls the
	// serving path. Mirroring is best-effort: a failure is counted, never fatal.
	if sink != nil {
		if err := sink.RecordSuppression(ctx, stored); err != nil {
			l.mu.Lock()
			l.auditErr++
			l.mu.Unlock()
		} else {
			l.mu.Lock()
			l.auditOK++
			l.mu.Unlock()
		}
	}
	return true
}

// evictLocked drops the oldest records until within capacity.
func (l *SuppressionLedger) evictLocked() {
	for len(l.order) > l.max {
		oldest := l.order[0]
		l.order = l.order[1:]
		delete(l.entries, oldest)
	}
}

// RecordFromDocument scans a (preferably de-duplicated) findings document for
// suppressed findings and records each one under its classified mechanism. It is
// the pull-path entry point: the gateway calls it after normalization so the VEX
// and reachability suppressions the gates already applied are captured without
// any gate needing to know about the ledger. Policy and break-glass suppressions
// are recorded by their own subsystems via Record. It returns the number of
// newly-recorded distinct suppressions.
func (l *SuppressionLedger) RecordFromDocument(ctx context.Context, d *Document) int {
	if l == nil || d == nil {
		return 0
	}
	n := 0
	for i := range d.Findings {
		f := &d.Findings[i]
		if !f.Suppressed {
			continue
		}
		mech, actor := classifySuppression(f)
		coord := f.Location.Coordinate
		if coord == "" {
			coord = d.Artifact.Coordinate
		}
		cat, _ := dedupKey(d, f)
		rec := SuppressionRecord{
			Tenant:        d.Tenant,
			Coordinate:    coord,
			Digest:        findingDigest(d, f),
			Category:      cat,
			RuleID:        f.RuleID,
			Identifier:    f.Identifier,
			Gate:          f.Gate,
			Mechanism:     mech,
			Actor:         actor,
			Justification: f.Justification,
			Locator:       locatorOf(cat, f),
		}
		if l.Record(ctx, rec) {
			n++
		}
	}
	return n
}

// Properties a finding carries to say how it was suppressed, when the
// mechanism cannot be read from its shape (a break-glass grant).
const (
	// PropSuppressionMechanism names the Mechanism ("break-glass").
	PropSuppressionMechanism = "suppressionMechanism"
	// PropSuppressedBy names who suppressed it (the approval request ID).
	PropSuppressedBy = "suppressedBy"
)

// findingDigest is the content digest a finding is about: its own "digest"
// property when it has one (a document that covers many artifacts, such as a
// repository's dependency scan), else the document artifact's.
func findingDigest(d *Document, f *Finding) string {
	if v, ok := f.Properties["digest"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return d.Artifact.Digest
}

// classifySuppression infers the suppression mechanism and actor from a
// suppressed finding's shape. A VEX-adjudicated vulnerability carries the VEX
// rule and a vexStatus property; a reachability downgrade stays under the
// vulnerable-dependency rule with an "unreachable" justification.
func classifySuppression(f *Finding) (Mechanism, string) {
	// A finding a human break-glass grant releases says so itself (the
	// repository dependency scan, Task 181, marks a dependency whose artifact
	// an approver released): the grant, not a policy, suppressed it.
	if m, _ := f.Properties[PropSuppressionMechanism].(string); Mechanism(m) == MechanismBreakGlass {
		actor := "break-glass"
		if by, ok := f.Properties[PropSuppressedBy].(string); ok && strings.TrimSpace(by) != "" {
			actor = "break-glass:" + strings.TrimSpace(by)
		}
		return MechanismBreakGlass, actor
	}
	if f.RuleID == RuleSuppressedVuln || f.Gate == GateVEX {
		actor := "vex"
		if st, ok := f.Properties["vexStatus"].(string); ok && strings.TrimSpace(st) != "" {
			actor = "vex:" + st
		}
		return MechanismVEX, actor
	}
	if strings.Contains(strings.ToLower(f.Justification), "unreachable") {
		return MechanismReachability, "reachability-analysis"
	}
	// A finding flagged suppressed by neither of the above was downgraded by
	// policy (the only remaining in-pipeline suppression path).
	return MechanismPolicy, "policy-engine"
}

// ByCoordinate returns every suppression recorded for a coordinate, newest
// first. The tenant is matched case-insensitively; an empty tenant matches any.
// The pkg argument may be an exact coordinate or a bare name.
func (l *SuppressionLedger) ByCoordinate(tenant, pkg string) []SuppressionRecord {
	if l == nil {
		return nil
	}
	pkg = strings.TrimSpace(pkg)
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []SuppressionRecord
	for _, key := range l.order {
		r := l.entries[key]
		if r == nil {
			continue
		}
		if tenant != "" && !strings.EqualFold(r.Tenant, tenant) {
			continue
		}
		if pkg != "" && !coordinateMatches(r.Coordinate, pkg) {
			continue
		}
		out = append(out, *r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	return out
}

// coordinateMatches reports whether a ledger coordinate is addressed by pkg,
// which may be the exact coordinate or a bare name component.
func coordinateMatches(coordinate, pkg string) bool {
	if strings.EqualFold(coordinate, pkg) {
		return true
	}
	// Bare-name query matches the name component of a "name@version" coordinate.
	if i := strings.LastIndex(coordinate, "@"); i > 0 {
		return strings.EqualFold(coordinate[:i], pkg)
	}
	return false
}

// Recent returns up to n of the most recently recorded suppressions across all
// coordinates, newest first. A non-positive n returns all.
func (l *SuppressionLedger) Recent(n int) []SuppressionRecord {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SuppressionRecord, 0, len(l.order))
	for _, key := range l.order {
		if r := l.entries[key]; r != nil {
			out = append(out, *r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Len reports the number of distinct suppressions retained.
func (l *SuppressionLedger) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Metrics returns a consistent snapshot of the ledger's cumulative counters.
func (l *SuppressionLedger) Metrics() SuppressionMetrics {
	if l == nil {
		return SuppressionMetrics{ByMechanism: map[string]uint64{}}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	by := make(map[string]uint64, len(l.byMechanism))
	for m, n := range l.byMechanism {
		by[string(m)] = n
	}
	return SuppressionMetrics{
		Recorded:      l.recorded,
		Observed:      l.observed,
		ByMechanism:   by,
		Current:       len(l.entries),
		AuditErrors:   l.auditErr,
		AuditMirrored: l.auditOK,
	}
}
