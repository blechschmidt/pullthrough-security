// Package timeline implements a read-only forensic correlation layer that
// reconstructs a single, chronologically-ordered, deduplicated "what happened"
// timeline for a given coordinate, tenant, identity, or incident ID.
//
// It owns no source of truth. Every entry is read live, through narrow provider
// interfaces, from the subsystem that already recorded the fact: the tamper-
// evident audit log (the Merkle-anchored spine — Task 31), the SOC verdict feed
// (secops — Task 60), behavioural anomaly triggers (anomaly — Task 43), the
// human-in-the-loop approval / break-glass workflow (approvals — Task 50), the
// emergency lockdown / kill-switch (lockdown — Task 74), and the unified
// admission findings store (findings — Task 42).
//
// The package's job is correlation, not capture: it folds these heterogeneous
// records into one normalized Event type, merges them onto a single time axis,
// de-duplicates the inevitable overlap (a policy block is recorded both in the
// audit log and in the SOC feed), and — where the underlying fact lives in the
// audit log — carries a link to the Merkle inclusion proof that makes it
// tamper-evident. The result is the artifact an incident responder reads to
// answer "what did the proxy do, to whom, and when, and can I prove it".
//
// Tenant scoping is enforced exactly like the self-service portal (Task 71):
// when a query is scoped to a tenant, an event attributed to a *different*
// tenant is never returned. Un-attributed, organisation-wide events (e.g. an
// emergency lockdown engaged for everyone) remain visible, which is the correct
// behaviour for incident response.
package timeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/secops"
)

// Source identifies the subsystem an event was reconstructed from.
type Source string

const (
	SourceAudit     Source = "audit"     // the tamper-evident hash-chained audit log
	SourceSecOps    Source = "secops"    // the SOC notable-verdict feed
	SourceAnomaly   Source = "anomaly"   // behavioural anomaly triggers
	SourceApprovals Source = "approvals" // quarantine review / break-glass workflow
	SourceLockdown  Source = "lockdown"  // emergency lockdown / kill-switch
	SourceFindings  Source = "findings"  // unified admission findings store
)

// sourcePriority ranks sources when two records de-duplicate onto the same
// timeline entry. The audit log wins because it is the only source that carries
// a Merkle inclusion proof, so the surviving entry stays provable.
var sourcePriority = map[Source]int{
	SourceAudit:     6,
	SourceApprovals: 5,
	SourceLockdown:  4,
	SourceSecOps:    3,
	SourceAnomaly:   2,
	SourceFindings:  1,
}

// Category is the coarse kind of thing that happened, used for grouping in the
// UI and for the de-duplication merge class.
type Category string

const (
	CategoryPull        Category = "pull"        // a client pull/fetch
	CategoryCache       Category = "cache"       // a cache hit/miss
	CategoryScan        Category = "scan"        // a commit/artifact scan verdict
	CategoryVerdict     Category = "verdict"     // an admission/policy gate decision
	CategoryFinding     Category = "finding"     // a recorded admission finding document
	CategoryAnomaly     Category = "anomaly"     // a behavioural anomaly trigger
	CategoryApproval    Category = "approval"    // a quarantine-review state change
	CategoryOverride    Category = "override"    // a break-glass grant (an allow override)
	CategoryLockdown    Category = "lockdown"    // an emergency lockdown action
	CategoryAuth        Category = "auth"        // an authentication / authorization outcome
	CategoryQuota       Category = "quota"       // a quota / rate-limit event
	CategoryAttestation Category = "attestation" // an outbound attestation issued
	CategorySnapshot    Category = "snapshot"    // a snapshot / freeze / rollback action
	CategoryAdmin       Category = "admin"       // a generic admin mutation
)

// ProofRef links a timeline entry back to the underlying tamper-evident record.
// It is populated only for entries reconstructed from the audit log while the
// Merkle transparency layer is active; the Path is a relative admin URL the UI
// and ptctl resolve against the admin prefix.
type ProofRef struct {
	AuditSeq uint64 `json:"auditSeq"`
	Path     string `json:"path"`
}

// Event is one normalized, source-agnostic entry on the reconstructed timeline.
type Event struct {
	Time       time.Time         `json:"time"`
	Source     Source            `json:"source"`
	Category   Category          `json:"category"`
	Kind       string            `json:"kind,omitempty"`   // source-specific event type/action
	Actor      string            `json:"actor,omitempty"`  // identity/subject responsible
	Tenant     string            `json:"tenant,omitempty"` // owning tenant/team, when attributed
	Ecosystem  string            `json:"ecosystem,omitempty"`
	Coordinate string            `json:"coordinate,omitempty"` // normalized name@version
	Decision   string            `json:"decision,omitempty"`   // canonicalized: block|warn|admit|error
	Summary    string            `json:"summary,omitempty"`
	IncidentID string            `json:"incidentId,omitempty"`
	Detail     map[string]string `json:"detail,omitempty"`
	// Proof links to the Merkle inclusion proof for this entry, when it was
	// reconstructed from the audit log and transparency is enabled.
	Proof *ProofRef `json:"proof,omitempty"`
	// Corroborated lists every source that recorded this same underlying fact,
	// in sorted order, after de-duplication merged them. A single-source event
	// still lists its one source, so the provenance is always explicit.
	Corroborated []string `json:"corroborated,omitempty"`
}

// Query selects and scopes the timeline. All set fields are AND-combined. At
// least one of Coordinate, Tenant, Identity, or IncidentID is required by the
// engine (an unbounded "everything that ever happened" dump is refused) unless
// All is set explicitly.
type Query struct {
	Coordinate string    `json:"coordinate,omitempty"`
	Tenant     string    `json:"tenant,omitempty"`
	Identity   string    `json:"identity,omitempty"`
	IncidentID string    `json:"incidentId,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	Until      time.Time `json:"until,omitempty"`
	Limit      int       `json:"limit,omitempty"`
	// All, when true, lifts the requirement for a scoping selector and returns
	// the whole correlated timeline (still bounded by Limit). It is intended for
	// the operator console's unfiltered view.
	All bool `json:"all,omitempty"`
}

// Result is the engine's answer: the chronologically-ordered, de-duplicated
// events plus enough metadata for the caller to render and reason about bounds.
type Result struct {
	Query       Query           `json:"query"`
	GeneratedAt time.Time       `json:"generatedAt"`
	Events      []Event         `json:"events"`
	Total       int             `json:"total"`     // matched before the Limit page
	Returned    int             `json:"returned"`  // len(Events)
	Truncated   bool            `json:"truncated"` // Total > Returned
	Sources     map[string]bool `json:"sources"`   // which subsystems contributed
}

// QueryError is a client-side validation error (bad/empty query) distinct from
// an internal failure, so the admin handler can map it to a 400.
type QueryError struct {
	Code string
	Msg  string
}

func (e *QueryError) Error() string { return e.Msg }

// --- providers --------------------------------------------------------------
//
// Each provider is the narrow read-only seam onto one subsystem's existing
// read-model. A nil provider means that subsystem is disabled or unwired and
// simply contributes nothing.

// AuditProvider exposes the tamper-evident audit log: the full record history
// and whether the Merkle transparency layer (and therefore inclusion proofs) is
// active. *audit.Logger satisfies it.
type AuditProvider interface {
	Records(ctx context.Context) ([]audit.Record, error)
	TransparencyEnabled() bool
}

// SecOpsProvider exposes the SOC notable-verdict feed. *secops.Hub satisfies it.
type SecOpsProvider interface {
	Summary() secops.Summary
}

// AnomalyProvider exposes recent behavioural anomaly triggers. *anomaly.Engine
// satisfies it.
type AnomalyProvider interface {
	Recent(limit int) []anomaly.Trigger
}

// ApprovalsProvider exposes the quarantine-review / break-glass workflow.
// *approvals.Service satisfies it.
type ApprovalsProvider interface {
	Enabled() bool
	List(status string, limit int) []approvals.Request
}

// LockdownProvider exposes the current emergency-lockdown status. *lockdown.Service
// satisfies it. (Historical lockdown actions are reconstructed from the audit
// log; this surfaces the live incident even before its audit record is read.)
type LockdownProvider interface {
	Status() lockdown.Status
}

// FindingsProvider exposes the unified admission findings store. *findings.Store
// satisfies it.
type FindingsProvider interface {
	Documents(tenant, q string) []findings.Document
}

// Providers bundles every optional source the timeline correlates.
type Providers struct {
	Audit     AuditProvider
	SecOps    SecOpsProvider
	Anomaly   AnomalyProvider
	Approvals ApprovalsProvider
	Lockdown  LockdownProvider
	Findings  FindingsProvider
}

func (p Providers) enabled() map[string]bool {
	return map[string]bool{
		string(SourceAudit):     p.Audit != nil,
		string(SourceSecOps):    p.SecOps != nil,
		string(SourceAnomaly):   p.Anomaly != nil,
		string(SourceApprovals): p.Approvals != nil && p.Approvals.Enabled(),
		string(SourceLockdown):  p.Lockdown != nil,
		string(SourceFindings):  p.Findings != nil,
	}
}

// Config tunes the engine.
type Config struct {
	// DefaultLimit is the page size when a query omits Limit. Clamped to MaxLimit.
	DefaultLimit int
	// MaxLimit bounds the number of events any single query may return.
	MaxLimit int
	// AuditScan bounds how many of the most-recent audit records are scanned per
	// query, so a very large on-disk log cannot make a query unbounded.
	AuditScan int
	// Now overrides the clock (for deterministic tests). Defaults to time.Now.
	Now func() time.Time
	// AdminPrefix is the admin mount prefix used to build relative proof links
	// (default "/admin"). Only affects the ProofRef.Path string.
	AdminPrefix string
}

// Default bounds.
const (
	DefaultLimit     = 200
	DefaultMaxLimit  = 2000
	DefaultAuditScan = 20000
)

// Engine reconstructs timelines from the wired providers. It holds no state
// beyond its configuration and providers; every query reads the sources live.
type Engine struct {
	providers    Providers
	defaultLimit int
	maxLimit     int
	auditScan    int
	now          func() time.Time
	adminPrefix  string
}

// New constructs an Engine. A zero Config is valid.
func New(cfg Config, providers Providers) *Engine {
	e := &Engine{
		providers:    providers,
		defaultLimit: cfg.DefaultLimit,
		maxLimit:     cfg.MaxLimit,
		auditScan:    cfg.AuditScan,
		now:          cfg.Now,
		adminPrefix:  strings.TrimRight(cfg.AdminPrefix, "/"),
	}
	if e.defaultLimit <= 0 {
		e.defaultLimit = DefaultLimit
	}
	if e.maxLimit <= 0 {
		e.maxLimit = DefaultMaxLimit
	}
	if e.defaultLimit > e.maxLimit {
		e.defaultLimit = e.maxLimit
	}
	if e.auditScan <= 0 {
		e.auditScan = DefaultAuditScan
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.adminPrefix == "" {
		e.adminPrefix = "/admin"
	}
	return e
}

// Sources reports which subsystems are wired and contributing.
func (e *Engine) Sources() map[string]bool { return e.providers.enabled() }

// Query reconstructs the correlated, ordered, de-duplicated timeline for the
// given selector. It is read-only.
func (e *Engine) Query(ctx context.Context, q Query) (Result, error) {
	q = normalizeQuery(q)
	if !q.All && q.Coordinate == "" && q.Tenant == "" && q.Identity == "" && q.IncidentID == "" {
		return Result{}, &QueryError{Code: "missing_selector", Msg: "a timeline query requires at least one of coordinate, tenant, identity, or incidentId (or all=true)"}
	}

	events := e.collect(ctx)
	matcher := newMatcher(q)

	// Filter first (cheap), then de-duplicate, then order. De-duplicating before
	// ordering keeps the merge independent of input order; ordering last gives a
	// stable, chronological result.
	filtered := events[:0:0]
	for _, ev := range events {
		if matcher.matches(ev) {
			filtered = append(filtered, ev)
		}
	}
	merged := dedupe(filtered)
	sortEvents(merged)

	total := len(merged)
	limit := q.Limit
	if limit <= 0 {
		limit = e.defaultLimit
	}
	if limit > e.maxLimit {
		limit = e.maxLimit
	}
	truncated := false
	if total > limit {
		// Keep the most recent `limit` events (the tail), but present them
		// oldest-first so the chain still reads chronologically.
		merged = merged[total-limit:]
		truncated = true
	}

	return Result{
		Query:       q,
		GeneratedAt: e.now().UTC(),
		Events:      merged,
		Total:       total,
		Returned:    len(merged),
		Truncated:   truncated,
		Sources:     e.providers.enabled(),
	}, nil
}

// collect reconstructs the full (unfiltered) set of normalized events from every
// wired provider.
func (e *Engine) collect(ctx context.Context) []Event {
	var out []Event
	out = append(out, e.fromAudit(ctx)...)
	out = append(out, e.fromSecOps()...)
	out = append(out, e.fromAnomaly()...)
	out = append(out, e.fromApprovals()...)
	out = append(out, e.fromLockdown()...)
	out = append(out, e.fromFindings()...)
	return out
}

// --- audit ------------------------------------------------------------------

func (e *Engine) fromAudit(ctx context.Context) []Event {
	if e.providers.Audit == nil {
		return nil
	}
	recs, err := e.providers.Audit.Records(ctx)
	if err != nil || len(recs) == 0 {
		return nil
	}
	// Bound the scan to the most-recent AuditScan records (records are ordered by
	// sequence, ascending).
	if len(recs) > e.auditScan {
		recs = recs[len(recs)-e.auditScan:]
	}
	proofs := e.providers.Audit.TransparencyEnabled()
	out := make([]Event, 0, len(recs))
	for _, rec := range recs {
		ev := auditToEvent(rec, e.adminPrefix, proofs)
		out = append(out, ev)
	}
	return out
}

func auditToEvent(rec audit.Record, adminPrefix string, proofs bool) Event {
	a := rec.Event
	cat, kind := classifyAudit(a)
	ev := Event{
		Time:         a.Time,
		Source:       SourceAudit,
		Category:     cat,
		Kind:         kind,
		Actor:        a.Subject,
		Tenant:       a.Team,
		Ecosystem:    a.Ecosystem,
		Coordinate:   normalizeCoordinate(a.Ecosystem, a.Resource),
		Decision:     canonicalDecision(string(a.Decision)),
		Summary:      auditSummary(a),
		Corroborated: []string{string(SourceAudit)},
	}
	if inc := incidentFromDetail(a.Detail); inc != "" {
		ev.IncidentID = inc
	}
	ev.Detail = stringifyDetail(a.Detail)
	if proofs {
		ev.Proof = &ProofRef{
			AuditSeq: rec.Seq,
			Path:     fmt.Sprintf("%s/api/audit/proof?seq=%d", adminPrefix, rec.Seq),
		}
	} else {
		// Even without the Merkle layer, surface the sequence so an operator can
		// locate the raw record.
		ev.Proof = &ProofRef{AuditSeq: rec.Seq}
	}
	return ev
}

// classifyAudit maps an audit event onto a timeline category and a specific
// kind. Admin mutations are refined by their Reason prefix (lockdown / approvals
// / snapshot all ride EventAdmin), so an incident reads as lockdown/override
// rather than an undifferentiated "admin".
func classifyAudit(a audit.Event) (Category, string) {
	reason := strings.ToLower(strings.TrimSpace(a.Reason))
	switch a.Type {
	case audit.EventPull:
		return CategoryPull, "pull"
	case audit.EventCache:
		return CategoryCache, "cache"
	case audit.EventScanVerdict:
		return CategoryScan, "scan_verdict"
	case audit.EventPolicy:
		return CategoryVerdict, firstNonEmpty(reasonHead(reason), "policy_decision")
	case audit.EventAuth:
		return CategoryAuth, "auth"
	case audit.EventAuthorization:
		return CategoryAuth, "authorization"
	case audit.EventQuota:
		return CategoryQuota, "quota"
	case audit.EventAttestation:
		return CategoryAttestation, "attestation"
	case audit.EventSnapshot:
		return CategorySnapshot, firstNonEmpty(reasonHead(reason), "snapshot")
	case audit.EventAdmin:
		switch {
		case strings.HasPrefix(reason, "lockdown"):
			return CategoryLockdown, reason
		case strings.HasPrefix(reason, "approvals:break-glass"):
			return CategoryOverride, reason
		case strings.HasPrefix(reason, "approvals"):
			return CategoryApproval, reason
		case strings.HasPrefix(reason, "snapshot"):
			return CategorySnapshot, reason
		default:
			return CategoryAdmin, firstNonEmpty(reasonHead(reason), "admin")
		}
	default:
		return CategoryAdmin, string(a.Type)
	}
}

func auditSummary(a audit.Event) string {
	if a.Reason != "" {
		return a.Reason
	}
	parts := make([]string, 0, 3)
	if a.Method != "" {
		parts = append(parts, a.Method)
	}
	if a.Resource != "" {
		parts = append(parts, a.Resource)
	}
	if a.Decision != "" {
		parts = append(parts, string(a.Decision))
	}
	return strings.Join(parts, " ")
}

// --- secops -----------------------------------------------------------------

func (e *Engine) fromSecOps() []Event {
	if e.providers.SecOps == nil {
		return nil
	}
	recent := e.providers.SecOps.Summary().Recent
	out := make([]Event, 0, len(recent))
	for _, ne := range recent {
		cat := CategoryVerdict
		if ne.Gate == "anomaly" {
			cat = CategoryAnomaly
		}
		out = append(out, Event{
			Time:         ne.Time,
			Source:       SourceSecOps,
			Category:     cat,
			Kind:         ne.Type,
			Actor:        ne.Subject,
			Tenant:       tenantFromSubject(ne.Subject),
			Ecosystem:    ne.Ecosystem,
			Coordinate:   normalizeCoordinate(ne.Ecosystem, ne.Artifact),
			Decision:     canonicalDecision(string(ne.Outcome)),
			Summary:      firstNonEmpty(ne.Summary, ne.Title),
			Detail:       copyStringMap(ne.Fields),
			Corroborated: []string{string(SourceSecOps)},
		})
	}
	return out
}

// --- anomaly ----------------------------------------------------------------

func (e *Engine) fromAnomaly() []Event {
	if e.providers.Anomaly == nil {
		return nil
	}
	triggers := e.providers.Anomaly.Recent(0)
	out := make([]Event, 0, len(triggers))
	for _, t := range triggers {
		out = append(out, Event{
			Time:     t.At,
			Source:   SourceAnomaly,
			Category: CategoryAnomaly,
			Kind:     string(t.Detector),
			Actor:    t.Identity,
			Tenant:   t.Tenant,
			Decision: canonicalDecision(string(t.Action)),
			Summary:  t.Summary,
			Detail: map[string]string{
				"scope":    t.Scope,
				"detector": string(t.Detector),
				"level":    string(t.Level),
				"score":    fmt.Sprintf("%.1f", t.Score),
			},
			Corroborated: []string{string(SourceAnomaly)},
		})
	}
	return out
}

// --- approvals --------------------------------------------------------------

// fromApprovals expands each approval Request into the discrete state-change
// events it represents (requested → approved/denied → expired), each at its own
// timestamp, so the workflow reads as a sequence on the timeline rather than a
// single opaque row.
func (e *Engine) fromApprovals() []Event {
	if e.providers.Approvals == nil || !e.providers.Approvals.Enabled() {
		return nil
	}
	reqs := e.providers.Approvals.List("", 0)
	var out []Event
	for _, r := range reqs {
		base := Event{
			Source:       SourceApprovals,
			Tenant:       r.Tenant,
			Ecosystem:    r.Ecosystem,
			Coordinate:   normalizeCoordinate(r.Ecosystem, r.Coordinate),
			Corroborated: []string{string(SourceApprovals)},
		}
		if !r.CreatedAt.IsZero() {
			ev := base
			ev.Time = r.CreatedAt
			ev.Category = CategoryApproval
			ev.Kind = "requested"
			ev.Actor = r.Requester
			ev.Summary = fmt.Sprintf("review opened for %s gate %q: %s", r.Coordinate, r.Gate, r.Reason)
			ev.Detail = map[string]string{"gate": r.Gate, "reason": r.Reason, "status": string(r.Status)}
			out = append(out, ev)
		}
		if !r.GrantedAt.IsZero() {
			ev := base
			ev.Time = r.GrantedAt
			ev.Category = CategoryOverride
			ev.Kind = "approved"
			ev.Actor = approverList(r.Approvers)
			ev.Decision = "admit"
			ev.Summary = fmt.Sprintf("break-glass grant issued for %s gate %q", r.Coordinate, r.Gate)
			ev.Detail = map[string]string{"gate": r.Gate, "justification": r.Justification, "expiresAt": timeStr(r.ExpiresAt)}
			out = append(out, ev)
		}
		if r.Status == approvals.StatusDenied && !r.DecidedAt.IsZero() {
			ev := base
			ev.Time = r.DecidedAt
			ev.Category = CategoryApproval
			ev.Kind = "denied"
			ev.Actor = r.DecidedBy
			ev.Decision = "block"
			ev.Summary = fmt.Sprintf("review denied for %s gate %q", r.Coordinate, r.Gate)
			ev.Detail = map[string]string{"gate": r.Gate}
			out = append(out, ev)
		}
		if r.Status == approvals.StatusExpired && !r.UpdatedAt.IsZero() {
			ev := base
			ev.Time = r.UpdatedAt
			ev.Category = CategoryApproval
			ev.Kind = "expired"
			ev.Decision = "block"
			ev.Summary = fmt.Sprintf("grant expired and re-quarantined %s gate %q", r.Coordinate, r.Gate)
			ev.Detail = map[string]string{"gate": r.Gate}
			out = append(out, ev)
		}
	}
	return out
}

// --- lockdown ---------------------------------------------------------------

// fromLockdown surfaces the currently-active incident as a timeline entry. The
// full lockdown history (engage/clear/expire) is reconstructed from the audit
// log; this guarantees the live incident appears even before, or independently
// of, the audit source.
func (e *Engine) fromLockdown() []Event {
	if e.providers.Lockdown == nil {
		return nil
	}
	st := e.providers.Lockdown.Status()
	if !st.Active {
		return nil
	}
	targets := make([]string, 0, len(st.Targets))
	for _, c := range st.Targets {
		targets = append(targets, c.String())
	}
	return []Event{{
		Time:         st.EngagedAt,
		Source:       SourceLockdown,
		Category:     CategoryLockdown,
		Kind:         "engaged:" + string(st.Mode),
		Actor:        st.Operator,
		Decision:     "block",
		IncidentID:   st.IncidentID,
		Summary:      fmt.Sprintf("emergency lockdown active (%s): %s", st.Mode, st.Reason),
		Detail:       map[string]string{"mode": string(st.Mode), "reason": st.Reason, "targets": strings.Join(targets, ",")},
		Corroborated: []string{string(SourceLockdown)},
	}}
}

// --- findings ---------------------------------------------------------------

func (e *Engine) fromFindings() []Event {
	if e.providers.Findings == nil {
		return nil
	}
	docs := e.providers.Findings.Documents("", "")
	out := make([]Event, 0, len(docs))
	for i := range docs {
		d := &docs[i]
		blocking := 0
		gates := make([]string, 0, len(d.Findings))
		seen := map[string]bool{}
		worst := ""
		for j := range d.Findings {
			f := &d.Findings[j]
			if f.Suppressed {
				continue
			}
			if f.Level == findings.LevelError {
				blocking++
			}
			if g := string(f.Gate); g != "" && !seen[g] {
				seen[g] = true
				gates = append(gates, g)
			}
			worst = worseSeverity(worst, string(f.Severity))
		}
		sort.Strings(gates)
		decision := "warn"
		if blocking > 0 {
			decision = "block"
		}
		out = append(out, Event{
			Time:         d.GeneratedAt,
			Source:       SourceFindings,
			Category:     CategoryFinding,
			Kind:         "findings",
			Tenant:       d.Tenant,
			Ecosystem:    d.Artifact.Ecosystem,
			Coordinate:   normalizeCoordinate(d.Artifact.Ecosystem, firstNonEmpty(d.Artifact.Coordinate, d.Artifact.Name+"@"+d.Artifact.Version)),
			Decision:     decision,
			Summary:      fmt.Sprintf("%d finding(s), %d blocking; worst=%s", len(d.Findings), blocking, firstNonEmpty(worst, "none")),
			Detail:       map[string]string{"gates": strings.Join(gates, ","), "blocking": fmt.Sprintf("%d", blocking)},
			Corroborated: []string{string(SourceFindings)},
		})
	}
	return out
}

// --- ordering & de-duplication ---------------------------------------------

// sortEvents orders events chronologically with a deterministic tiebreaker so
// the timeline is stable across runs and independent of provider iteration order.
func sortEvents(events []Event) {
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		// Same instant: order by source priority (descending) then by category,
		// kind, coordinate so identical inputs always sort identically.
		if pa, pb := sourcePriority[a.Source], sourcePriority[b.Source]; pa != pb {
			return pa > pb
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Coordinate != b.Coordinate {
			return a.Coordinate < b.Coordinate
		}
		return a.Kind < b.Kind
	})
}

// dedupe collapses entries that describe the same underlying fact reported by
// more than one source onto a single entry, keeping the highest-priority source
// (the audit log, which carries the proof) and recording every corroborating
// source. The merge is order-independent.
func dedupe(events []Event) []Event {
	type slot struct {
		idx int
	}
	index := make(map[string]*slot, len(events))
	out := make([]Event, 0, len(events))
	for _, ev := range events {
		key := ev.dedupeKey()
		if s, ok := index[key]; ok {
			out[s.idx] = mergeEvents(out[s.idx], ev)
			continue
		}
		index[key] = &slot{idx: len(out)}
		out = append(out, ev)
	}
	return out
}

// dedupeKey is the equivalence signature for de-duplication. Verdict-class
// events (a gate decision, equally reported by the audit log, the SOC feed, and
// the findings store) collapse on coordinate + canonical decision + the wall
// second, deliberately ignoring the actor (sources disagree on whether the
// subject is an identity or a tenant scope). Every other category keys on its
// full identity so distinct events are never wrongly merged.
func (ev Event) dedupeKey() string {
	sec := ev.Time.Unix()
	switch mergeClass(ev.Category) {
	case CategoryVerdict:
		return fmt.Sprintf("verdict\x00%s\x00%s\x00%d", strings.ToLower(ev.Coordinate), ev.Decision, sec)
	default:
		return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d",
			ev.Category, ev.Kind, strings.ToLower(ev.Coordinate),
			strings.ToLower(ev.Actor), ev.Decision, sec)
	}
}

// mergeClass groups categories that represent "a gate decided something" so
// their cross-source duplicates collapse together.
func mergeClass(c Category) Category {
	switch c {
	case CategoryVerdict, CategoryFinding:
		return CategoryVerdict
	default:
		return c
	}
}

// mergeEvents folds b into a, keeping the higher-priority source's identity but
// enriching it from the other: a missing proof is taken from whichever side has
// it, empty fields are backfilled, detail maps are unioned, and the
// corroborating-source set is extended.
func mergeEvents(a, b Event) Event {
	winner, loser := a, b
	if sourcePriority[b.Source] > sourcePriority[a.Source] {
		winner, loser = b, a
	}
	// Carry a proof from either side (the loser may be the audit record).
	if winner.Proof == nil || winner.Proof.AuditSeq == 0 {
		if loser.Proof != nil && loser.Proof.AuditSeq != 0 {
			winner.Proof = loser.Proof
		}
	}
	winner.Actor = firstNonEmpty(winner.Actor, loser.Actor)
	winner.Tenant = firstNonEmpty(winner.Tenant, loser.Tenant)
	winner.Ecosystem = firstNonEmpty(winner.Ecosystem, loser.Ecosystem)
	winner.Coordinate = firstNonEmpty(winner.Coordinate, loser.Coordinate)
	winner.Decision = firstNonEmpty(winner.Decision, loser.Decision)
	winner.Summary = firstNonEmpty(winner.Summary, loser.Summary)
	winner.IncidentID = firstNonEmpty(winner.IncidentID, loser.IncidentID)
	winner.Detail = unionStringMaps(winner.Detail, loser.Detail)
	winner.Corroborated = mergeSorted(winner.Corroborated, loser.Corroborated)
	return winner
}

// CoordinateStat is the per-coordinate roll-up the federated query layer (Task
// 67) projects as timeline fields.
type CoordinateStat struct {
	Events     int
	LastSource string
	LastAt     time.Time
	HasProof   bool
}

// CoordinateIndex reconstructs the whole de-duplicated timeline once and rolls
// it up per normalized (ecosystem, coordinate), so the queryapi model can stamp
// each coordinate with its timeline activity in a single pass. The key format
// matches queryapi's coordinate index ("<ecosystem>\x00<coordinate>", lowercased).
func (e *Engine) CoordinateIndex() map[string]CoordinateStat {
	events := dedupe(e.collect(context.Background()))
	out := make(map[string]CoordinateStat)
	for _, ev := range events {
		if ev.Coordinate == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(ev.Ecosystem)) + "\x00" + strings.ToLower(ev.Coordinate)
		st := out[key]
		st.Events++
		if ev.Time.After(st.LastAt) {
			st.LastAt = ev.Time
			st.LastSource = string(ev.Source)
		}
		if ev.Proof != nil && ev.Proof.AuditSeq != 0 {
			st.HasProof = true
		}
		out[key] = st
	}
	return out
}
