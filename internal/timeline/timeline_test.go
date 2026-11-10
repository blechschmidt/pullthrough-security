package timeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/secops"
)

var base = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// --- fakes ------------------------------------------------------------------

type fakeAudit struct {
	recs   []audit.Record
	proofs bool
}

func (f *fakeAudit) Records(ctx context.Context) ([]audit.Record, error) { return f.recs, nil }
func (f *fakeAudit) TransparencyEnabled() bool                           { return f.proofs }

type fakeSecOps struct{ recent []secops.NotableEvent }

func (f *fakeSecOps) Summary() secops.Summary { return secops.Summary{Recent: f.recent} }

type fakeAnomaly struct{ triggers []anomaly.Trigger }

func (f *fakeAnomaly) Recent(limit int) []anomaly.Trigger { return f.triggers }

type fakeApprovals struct {
	enabled bool
	reqs    []approvals.Request
}

func (f *fakeApprovals) Enabled() bool { return f.enabled }
func (f *fakeApprovals) List(status string, limit int) []approvals.Request {
	if status == "" {
		return f.reqs
	}
	var out []approvals.Request
	for _, r := range f.reqs {
		if string(r.Status) == status {
			out = append(out, r)
		}
	}
	return out
}

type fakeLockdown struct{ st lockdown.Status }

func (f *fakeLockdown) Status() lockdown.Status { return f.st }

type fakeFindings struct{ docs []findings.Document }

func (f *fakeFindings) Documents(tenant, q string) []findings.Document { return f.docs }

func auditRec(seq uint64, t time.Time, typ audit.EventType, tenant, subject, eco, resource string, dec audit.Decision, reason string, detail map[string]any) audit.Record {
	return audit.Record{
		Seq: seq,
		Event: audit.Event{
			Type: typ, Time: t, Team: tenant, Subject: subject,
			Ecosystem: eco, Resource: resource, Decision: dec, Reason: reason, Detail: detail,
		},
		Hash: "h" + string(rune('0'+seq)),
	}
}

func newEngine(t *testing.T, p Providers) *Engine {
	t.Helper()
	return New(Config{Now: func() time.Time { return base.Add(time.Hour) }, AdminPrefix: "/admin"}, p)
}

// --- tests ------------------------------------------------------------------

// TestOrdering proves events from heterogeneous sources merge onto a single,
// strictly chronological axis.
func TestOrdering(t *testing.T) {
	au := &fakeAudit{proofs: true, recs: []audit.Record{
		auditRec(1, base.Add(30*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionAllow, "", nil),
		auditRec(2, base.Add(90*time.Second), audit.EventPolicy, "acme", "alice", "npm", "evil@2.0.0", audit.DecisionDeny, "policy:block", nil),
	}}
	an := &fakeAnomaly{triggers: []anomaly.Trigger{
		{Tenant: "acme", Identity: "alice", Scope: "acme|alice", Detector: "fanout", Level: anomaly.LevelHigh, Action: anomaly.ActionBlock, Score: 90, Summary: "fanout spike", At: base.Add(60 * time.Second)},
	}}
	e := newEngine(t, Providers{Audit: au, Anomaly: an})

	res, err := e.Query(context.Background(), Query{Tenant: "acme"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Returned != 3 {
		t.Fatalf("expected 3 events, got %d", res.Returned)
	}
	wantOrder := []time.Time{base.Add(30 * time.Second), base.Add(60 * time.Second), base.Add(90 * time.Second)}
	for i, ev := range res.Events {
		if !ev.Time.Equal(wantOrder[i]) {
			t.Errorf("event %d time = %s, want %s", i, ev.Time, wantOrder[i])
		}
	}
	// Ascending order invariant.
	for i := 1; i < len(res.Events); i++ {
		if res.Events[i].Time.Before(res.Events[i-1].Time) {
			t.Fatalf("events not chronologically ordered at %d", i)
		}
	}
}

// TestDedup proves that the same underlying verdict reported by both the audit
// log and the SOC feed collapses to one entry, that the audit (provable) entry
// wins, and that both sources are recorded as corroborating.
func TestDedup(t *testing.T) {
	ts := base.Add(45 * time.Second)
	au := &fakeAudit{proofs: true, recs: []audit.Record{
		auditRec(7, ts, audit.EventPolicy, "acme", "alice", "npm", "evil@2.0.0", audit.DecisionDeny, "policy:block:risk", nil),
	}}
	so := &fakeSecOps{recent: []secops.NotableEvent{
		{Time: ts, Type: "policy.block", Gate: "policyengine", Outcome: secops.Outcome("block"), Ecosystem: "npm", Artifact: "evil@2.0.0", Subject: "acme"},
	}}
	e := newEngine(t, Providers{Audit: au, SecOps: so})

	res, err := e.Query(context.Background(), Query{Coordinate: "evil@2.0.0"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Returned != 1 {
		t.Fatalf("expected dedup to 1 event, got %d: %+v", res.Returned, res.Events)
	}
	ev := res.Events[0]
	if ev.Source != SourceAudit {
		t.Errorf("expected audit to win dedup, got source %s", ev.Source)
	}
	if ev.Proof == nil || ev.Proof.AuditSeq != 7 {
		t.Errorf("expected merged event to keep the audit proof (seq 7), got %+v", ev.Proof)
	}
	if ev.Proof.Path != "/admin/api/audit/proof?seq=7" {
		t.Errorf("unexpected proof path: %q", ev.Proof.Path)
	}
	if got := strings.Join(ev.Corroborated, ","); got != "audit,secops" {
		t.Errorf("expected corroborated audit,secops; got %q", got)
	}
}

// TestDedupOrderIndependent proves the merge result does not depend on the order
// the sources are collected in (audit-first vs secops-first yield the same
// surviving, provable entry).
func TestDedupOrderIndependent(t *testing.T) {
	ts := base.Add(45 * time.Second)
	auRec := auditRec(7, ts, audit.EventPolicy, "acme", "alice", "npm", "evil@2.0.0", audit.DecisionDeny, "policy:block", nil)
	soEv := secops.NotableEvent{Time: ts, Gate: "policyengine", Outcome: secops.Outcome("block"), Ecosystem: "npm", Artifact: "evil@2.0.0", Subject: "acme"}

	a := dedupe([]Event{
		auditToEvent(auRec, "/admin", true),
		secopsEvent(soEv),
	})
	b := dedupe([]Event{
		secopsEvent(soEv),
		auditToEvent(auRec, "/admin", true),
	})
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected both orders to dedup to 1, got %d and %d", len(a), len(b))
	}
	if a[0].Source != b[0].Source || a[0].Source != SourceAudit {
		t.Errorf("dedup winner differs by input order: %s vs %s", a[0].Source, b[0].Source)
	}
	if a[0].Proof == nil || b[0].Proof == nil || a[0].Proof.AuditSeq != b[0].Proof.AuditSeq {
		t.Error("proof not preserved consistently across input orders")
	}
}

func secopsEvent(ne secops.NotableEvent) Event {
	e := New(Config{}, Providers{SecOps: &fakeSecOps{recent: []secops.NotableEvent{ne}}})
	return e.fromSecOps()[0]
}

// TestTenantIsolation proves a tenant-scoped query never returns another
// tenant's attributed events, while organisation-wide (un-attributed) events
// remain visible.
func TestTenantIsolation(t *testing.T) {
	au := &fakeAudit{proofs: true, recs: []audit.Record{
		auditRec(1, base.Add(10*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionAllow, "", nil),
		auditRec(2, base.Add(20*time.Second), audit.EventPull, "globex", "bob", "npm", "left-pad@1.0.0", audit.DecisionAllow, "", nil),
		// Org-wide lockdown with no tenant attribution.
		auditRec(3, base.Add(30*time.Second), audit.EventAdmin, "", "operator", "", "", audit.DecisionDeny, "lockdown:engaged", map[string]any{"incidentId": "INC-1"}),
	}}
	e := newEngine(t, Providers{Audit: au})

	// Scope to acme: must see acme's pull + the org-wide lockdown, never globex's.
	res, err := e.Query(context.Background(), Query{Tenant: "acme"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, ev := range res.Events {
		if ev.Tenant == "globex" {
			t.Fatalf("tenant isolation breach: acme query returned a globex event: %+v", ev)
		}
	}
	if res.Returned != 2 {
		t.Fatalf("acme scope expected 2 events (own pull + org-wide lockdown), got %d", res.Returned)
	}
	// Scope to globex: must NOT see acme's event.
	res2, _ := e.Query(context.Background(), Query{Tenant: "globex"})
	for _, ev := range res2.Events {
		if ev.Tenant == "acme" {
			t.Fatalf("tenant isolation breach: globex query returned an acme event: %+v", ev)
		}
	}
}

// TestCoordinateBareNameMatch proves a bare-name coordinate query matches every
// version of that package.
func TestCoordinateBareNameMatch(t *testing.T) {
	au := &fakeAudit{recs: []audit.Record{
		auditRec(1, base.Add(10*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionAllow, "", nil),
		auditRec(2, base.Add(20*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@2.0.0", audit.DecisionAllow, "", nil),
		auditRec(3, base.Add(30*time.Second), audit.EventPull, "acme", "alice", "npm", "express@4.0.0", audit.DecisionAllow, "", nil),
	}}
	e := newEngine(t, Providers{Audit: au})

	res, _ := e.Query(context.Background(), Query{Coordinate: "lodash"})
	if res.Returned != 2 {
		t.Fatalf("bare-name lodash query expected 2 versions, got %d", res.Returned)
	}
	// Exact version query narrows to one.
	res2, _ := e.Query(context.Background(), Query{Coordinate: "lodash@2.0.0"})
	if res2.Returned != 1 {
		t.Fatalf("exact coordinate query expected 1, got %d", res2.Returned)
	}
}

// TestIncidentScope proves an incident-scoped query returns exactly the events
// tagged with that incident ID, drawn from both the lockdown live state and the
// audit log.
func TestIncidentScope(t *testing.T) {
	au := &fakeAudit{recs: []audit.Record{
		auditRec(1, base.Add(10*time.Second), audit.EventAdmin, "", "operator", "", "", audit.DecisionDeny, "lockdown:engaged", map[string]any{"incidentId": "INC-42"}),
		auditRec(2, base.Add(20*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionAllow, "", nil),
		auditRec(3, base.Add(99*time.Second), audit.EventAdmin, "", "operator", "", "", audit.DecisionAllow, "lockdown:cleared", map[string]any{"incidentId": "INC-42"}),
	}}
	e := newEngine(t, Providers{Audit: au})

	res, _ := e.Query(context.Background(), Query{IncidentID: "INC-42"})
	if res.Returned != 2 {
		t.Fatalf("incident scope expected 2 lockdown events, got %d: %+v", res.Returned, res.Events)
	}
	for _, ev := range res.Events {
		if ev.IncidentID != "INC-42" {
			t.Errorf("incident scope leaked a non-matching event: %+v", ev)
		}
	}
}

// TestApprovalExpansion proves an approval request expands into discrete
// timeline events for each of its state changes.
func TestApprovalExpansion(t *testing.T) {
	ap := &fakeApprovals{enabled: true, reqs: []approvals.Request{{
		ID: "a1", Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@2.0.0", Gate: "malfeed", Reason: "known-malicious",
		Status:    approvals.StatusApproved,
		CreatedAt: base.Add(10 * time.Second),
		GrantedAt: base.Add(20 * time.Second),
		ExpiresAt: base.Add(3600 * time.Second),
		Approvers: []approvals.Approver{{Subject: "carol", At: base.Add(20 * time.Second)}, {Subject: "dave", At: base.Add(20 * time.Second)}},
	}}}
	e := newEngine(t, Providers{Approvals: ap})

	res, _ := e.Query(context.Background(), Query{Coordinate: "evil@2.0.0"})
	if res.Returned != 2 {
		t.Fatalf("expected requested+approved = 2 events, got %d", res.Returned)
	}
	if res.Events[0].Kind != "requested" || res.Events[1].Kind != "approved" {
		t.Errorf("unexpected approval event kinds: %q, %q", res.Events[0].Kind, res.Events[1].Kind)
	}
	if res.Events[1].Category != CategoryOverride {
		t.Errorf("grant should be an override category, got %s", res.Events[1].Category)
	}
	if !strings.Contains(res.Events[1].Actor, "carol") || !strings.Contains(res.Events[1].Actor, "dave") {
		t.Errorf("approver identities missing from grant actor: %q", res.Events[1].Actor)
	}
}

// TestMissingSelector proves an unscoped query is refused unless All is set.
func TestMissingSelector(t *testing.T) {
	e := newEngine(t, Providers{Audit: &fakeAudit{}})
	_, err := e.Query(context.Background(), Query{})
	if err == nil {
		t.Fatal("expected an error for an unscoped query")
	}
	if qe, ok := err.(*QueryError); !ok || qe.Code != "missing_selector" {
		t.Fatalf("expected missing_selector QueryError, got %v", err)
	}
	// all=true lifts the requirement.
	if _, err := e.Query(context.Background(), Query{All: true}); err != nil {
		t.Fatalf("all=true should be accepted: %v", err)
	}
}

// TestLimitTruncation proves the limit keeps the most-recent events and flags
// truncation, still presenting them oldest-first.
func TestLimitTruncation(t *testing.T) {
	var recs []audit.Record
	for i := 0; i < 5; i++ {
		recs = append(recs, auditRec(uint64(i+1), base.Add(time.Duration(i)*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionAllow, "", nil))
	}
	e := newEngine(t, Providers{Audit: &fakeAudit{recs: recs}})
	res, _ := e.Query(context.Background(), Query{Tenant: "acme", Limit: 2})
	if res.Total != 5 || res.Returned != 2 || !res.Truncated {
		t.Fatalf("expected total=5 returned=2 truncated, got total=%d returned=%d trunc=%v", res.Total, res.Returned, res.Truncated)
	}
	// Most recent two, oldest-first.
	if !res.Events[0].Time.Equal(base.Add(3*time.Second)) || !res.Events[1].Time.Equal(base.Add(4*time.Second)) {
		t.Errorf("truncation kept the wrong window: %s, %s", res.Events[0].Time, res.Events[1].Time)
	}
}

// TestCoordinateIndex proves the per-coordinate roll-up used by the queryapi
// integration counts events and flags provability.
func TestCoordinateIndex(t *testing.T) {
	au := &fakeAudit{proofs: true, recs: []audit.Record{
		auditRec(1, base.Add(10*time.Second), audit.EventPull, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionAllow, "", nil),
		auditRec(2, base.Add(20*time.Second), audit.EventPolicy, "acme", "alice", "npm", "lodash@1.0.0", audit.DecisionDeny, "policy:block", nil),
	}}
	e := newEngine(t, Providers{Audit: au})
	idx := e.CoordinateIndex()
	st, ok := idx["npm\x00lodash@1.0.0"]
	if !ok {
		t.Fatalf("expected coordinate in index, got keys %v", keysOf(idx))
	}
	if st.Events != 2 {
		t.Errorf("expected 2 events for coordinate, got %d", st.Events)
	}
	if !st.HasProof {
		t.Error("expected coordinate roll-up to be provable")
	}
	if st.LastSource != string(SourceAudit) || !st.LastAt.Equal(base.Add(20*time.Second)) {
		t.Errorf("unexpected last event: %s @ %s", st.LastSource, st.LastAt)
	}
}

// TestMarkdownExport proves the Markdown report renders a row per event and
// inlines the proof link.
func TestMarkdownExport(t *testing.T) {
	au := &fakeAudit{proofs: true, recs: []audit.Record{
		auditRec(9, base.Add(10*time.Second), audit.EventPolicy, "acme", "alice", "npm", "evil@2.0.0", audit.DecisionDeny, "policy:block", nil),
	}}
	e := newEngine(t, Providers{Audit: au})
	res, _ := e.Query(context.Background(), Query{Coordinate: "evil@2.0.0"})
	md := res.Markdown()
	if !strings.Contains(md, "# Incident timeline") {
		t.Error("missing report header")
	}
	if !strings.Contains(md, "/admin/api/audit/proof?seq=9") {
		t.Errorf("missing proof link in markdown:\n%s", md)
	}
	if !strings.Contains(md, "evil@2.0.0") {
		t.Error("missing coordinate in markdown")
	}
}

func keysOf(m map[string]CoordinateStat) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
