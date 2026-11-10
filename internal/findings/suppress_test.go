package findings

import (
	"context"
	"testing"
	"time"
)

type captureSink struct {
	recs []SuppressionRecord
	err  error
}

func (c *captureSink) RecordSuppression(ctx context.Context, rec SuppressionRecord) error {
	if c.err != nil {
		return c.err
	}
	c.recs = append(c.recs, rec)
	return nil
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestSuppressionLedger_RecordFromDocument(t *testing.T) {
	sink := &captureSink{}
	l := NewSuppressionLedger(SuppressionLedgerOptions{Sink: sink, Now: fixedClock()})

	d := &Document{
		Tenant:   "acme",
		Artifact: Artifact{Name: "left-pad", Version: "1.0.0", Digest: "sha256:d", Coordinate: "left-pad@1.0.0"},
		Findings: []Finding{
			{
				RuleID: RuleSuppressedVuln, Gate: GateVEX, Severity: SeverityInfo, Suppressed: true,
				Identifier: "CVE-2020-1", Justification: "not affected: vulnerable code path not invoked",
				Location:   Location{Coordinate: "left-pad@1.0.0"},
				Properties: map[string]any{"vexStatus": "not_affected"},
			},
			{
				RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityInfo, Suppressed: true,
				Identifier: "CVE-2020-2", Justification: "unreachable: the vulnerable package is not imported",
				Location: Location{Coordinate: "left-pad@1.0.0"},
			},
			{
				RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityHigh,
				Identifier: "CVE-2020-3", Location: Location{Coordinate: "left-pad@1.0.0"},
			},
		},
	}

	n := l.RecordFromDocument(context.Background(), d)
	if n != 2 {
		t.Fatalf("recorded %d, want 2 (only the two suppressed findings)", n)
	}
	if len(sink.recs) != 2 {
		t.Fatalf("audit sink got %d, want 2", len(sink.recs))
	}

	recs := l.ByCoordinate("acme", "left-pad@1.0.0")
	if len(recs) != 2 {
		t.Fatalf("ByCoordinate = %d, want 2", len(recs))
	}
	// Mechanisms classified correctly.
	byMech := map[Mechanism]SuppressionRecord{}
	for _, r := range recs {
		byMech[r.Mechanism] = r
	}
	vex, ok := byMech[MechanismVEX]
	if !ok || vex.Actor != "vex:not_affected" {
		t.Errorf("vex record actor = %q (ok=%v), want vex:not_affected", vex.Actor, ok)
	}
	reach, ok := byMech[MechanismReachability]
	if !ok || reach.Identifier != "CVE-2020-2" {
		t.Errorf("reachability record = %+v (ok=%v)", reach, ok)
	}

	// Bare-name query also resolves.
	if got := l.ByCoordinate("acme", "left-pad"); len(got) != 2 {
		t.Errorf("bare-name ByCoordinate = %d, want 2", len(got))
	}
	// Wrong tenant isolates.
	if got := l.ByCoordinate("other", "left-pad@1.0.0"); len(got) != 0 {
		t.Errorf("cross-tenant leak: got %d", len(got))
	}
}

func TestSuppressionLedger_RepeatObservationDeduped(t *testing.T) {
	sink := &captureSink{}
	l := NewSuppressionLedger(SuppressionLedgerOptions{Sink: sink, Now: fixedClock()})
	rec := SuppressionRecord{
		Tenant: "t", Coordinate: "p@1", Digest: "sha256:x", Category: CategoryVulnerability,
		Identifier: "CVE-1", Mechanism: MechanismVEX, Locator: "CVE-1@p@1",
	}
	if !l.Record(context.Background(), rec) {
		t.Fatal("first Record should report a new suppression")
	}
	if l.Record(context.Background(), rec) {
		t.Fatal("repeat Record should not report a new suppression")
	}
	if l.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (repeat deduped)", l.Len())
	}
	if len(sink.recs) != 1 {
		t.Fatalf("audit mirrored %d, want 1 (repeat not re-mirrored)", len(sink.recs))
	}
	m := l.Metrics()
	if m.Recorded != 1 || m.Observed != 2 {
		t.Errorf("metrics recorded=%d observed=%d, want 1/2", m.Recorded, m.Observed)
	}
	if m.ByMechanism[string(MechanismVEX)] != 1 {
		t.Errorf("byMechanism[vex] = %d, want 1", m.ByMechanism[string(MechanismVEX)])
	}
	got := l.ByCoordinate("t", "p@1")
	if len(got) != 1 || got[0].Count != 2 {
		t.Errorf("record count = %v, want single record with Count 2", got)
	}
}

func TestSuppressionLedger_NilSafe(t *testing.T) {
	var l *SuppressionLedger
	if l.Record(context.Background(), SuppressionRecord{Coordinate: "x", Mechanism: MechanismVEX}) {
		t.Error("nil ledger Record should be a no-op returning false")
	}
	if l.Len() != 0 || l.ByCoordinate("", "") != nil || l.Recent(5) != nil {
		t.Error("nil ledger accessors should be safe")
	}
}

func TestSuppressionLedger_Eviction(t *testing.T) {
	l := NewSuppressionLedger(SuppressionLedgerOptions{MaxEntries: 2, Now: fixedClock()})
	for i, id := range []string{"CVE-A", "CVE-B", "CVE-C"} {
		l.Record(context.Background(), SuppressionRecord{
			Coordinate: "p@1", Mechanism: MechanismVEX, Identifier: id,
			Locator: id, Category: CategoryVulnerability,
		})
		_ = i
	}
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (oldest evicted)", l.Len())
	}
	// CVE-A is the oldest and should be gone.
	for _, r := range l.Recent(0) {
		if r.Identifier == "CVE-A" {
			t.Errorf("oldest record not evicted")
		}
	}
}

func TestSuppressionLedger_AuditErrorCounted(t *testing.T) {
	sink := &captureSink{err: context.DeadlineExceeded}
	l := NewSuppressionLedger(SuppressionLedgerOptions{Sink: sink, Now: fixedClock()})
	l.Record(context.Background(), SuppressionRecord{Coordinate: "p@1", Mechanism: MechanismVEX, Locator: "x"})
	if m := l.Metrics(); m.AuditErrors != 1 {
		t.Errorf("auditErrors = %d, want 1", m.AuditErrors)
	}
}
