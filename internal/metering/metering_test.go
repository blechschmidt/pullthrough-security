package metering

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// fakeEmitter captures emitted events for budget-alert assertions.
type fakeEmitter struct {
	mu     sync.Mutex
	events []notify.Event
}

func (f *fakeEmitter) Emit(_ context.Context, ev notify.Event) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
}

func (f *fakeEmitter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

// clock is a controllable time source for deterministic tests.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestMeter(t *testing.T, cfg Config) (*Meter, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)}
	cfg.Enabled = true
	cfg.Now = clk.now
	return New(cfg), clk
}

func TestRecordAccumulatesPerTenant(t *testing.T) {
	m, _ := newTestMeter(t, Config{})
	m.RecordRequest("acme", "npm-proxy", "npm")
	m.RecordRequest("acme", "npm-proxy", "npm")
	m.RecordTraffic("acme", 1000, true) // cache hit
	m.RecordTraffic("acme", 500, false) // upstream
	m.RecordStorage("acme", 500)
	m.RecordScan("acme", "vulnscan")
	m.RecordBlock("acme", "policyengine")

	snap := m.Snapshot()
	if len(snap.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(snap.Tenants))
	}
	c := snap.Tenants[0]
	if c.Tenant != "acme" {
		t.Fatalf("tenant = %q", c.Tenant)
	}
	if c.Requests != 2 {
		t.Errorf("requests = %d, want 2", c.Requests)
	}
	if c.BytesCacheHit != 1000 || c.BytesUpstream != 500 {
		t.Errorf("bytes hit=%d upstream=%d", c.BytesCacheHit, c.BytesUpstream)
	}
	if c.BytesServed() != 1500 {
		t.Errorf("served = %d, want 1500", c.BytesServed())
	}
	if c.StorageBytes != 500 {
		t.Errorf("storage = %d", c.StorageBytes)
	}
	if c.ScanInvocations != 1 || c.ScanCostMicros != defaultScanCostMicros {
		t.Errorf("scans=%d cost=%d", c.ScanInvocations, c.ScanCostMicros)
	}
	if c.Blocked != 1 {
		t.Errorf("blocked = %d", c.Blocked)
	}
	if c.ByBackend["npm-proxy"] != 2 || c.ByEcosystem["npm"] != 2 {
		t.Errorf("breakdowns: %v %v", c.ByBackend, c.ByEcosystem)
	}
	if c.ByScanGate["vulnscan"] != 1 || c.ByBlockGate["policyengine"] != 1 {
		t.Errorf("gate breakdowns: %v %v", c.ByScanGate, c.ByBlockGate)
	}
}

func TestUnscopedTenantBucket(t *testing.T) {
	m, _ := newTestMeter(t, Config{})
	m.RecordRequest("", "npm-proxy", "npm")
	if _, ok := m.TenantUsage(""); !ok {
		t.Fatal("expected unscoped tenant usage to exist")
	}
	snap := m.Snapshot()
	if snap.Tenants[0].Tenant != unscopedTenant {
		t.Fatalf("expected %q bucket, got %q", unscopedTenant, snap.Tenants[0].Tenant)
	}
}

func TestDisabledMeterNoops(t *testing.T) {
	m := New(Config{Enabled: false})
	m.RecordRequest("acme", "b", "npm")
	m.RecordScan("acme", "vulnscan")
	if got := len(m.Snapshot().Tenants); got != 0 {
		t.Fatalf("disabled meter recorded %d tenants", got)
	}
	if _, ok := m.TenantUsage("acme"); ok {
		t.Fatal("disabled meter returned usage")
	}
}

func TestScanCostModel(t *testing.T) {
	m, _ := newTestMeter(t, Config{
		DefaultScanCostMicros: 100,
		ScanCostMicros:        map[string]int64{"commitscan": 5000},
	})
	m.RecordScan("acme", "vulnscan")   // default 100
	m.RecordScan("acme", "commitscan") // override 5000
	u, _ := m.TenantUsage("acme")
	if u.ScanCostMicros != 5100 {
		t.Fatalf("scan cost = %d, want 5100", u.ScanCostMicros)
	}
	if u.ScanInvocations != 2 {
		t.Fatalf("scan invocations = %d", u.ScanInvocations)
	}
}

func TestRollupAndReport(t *testing.T) {
	m, clk := newTestMeter(t, Config{RollupInterval: time.Hour})

	// Hour 1 activity.
	m.RecordRequest("acme", "npm", "npm")
	m.RecordTraffic("acme", 1000, false)
	clk.t = clk.t.Add(time.Hour)
	m.Rollup(clk.t)

	// Hour 2 activity.
	m.RecordRequest("acme", "npm", "npm")
	m.RecordTraffic("acme", 2000, true)
	clk.t = clk.t.Add(time.Hour)
	m.Rollup(clk.t)

	// Hourly report over the whole span: two periods.
	rep := m.Report(ReportRequest{Granularity: "hour"})
	if len(rep.Rows) != 2 {
		t.Fatalf("hourly rows = %d, want 2", len(rep.Rows))
	}
	if rep.Grand.Requests != 2 || rep.Grand.BytesServed() != 3000 {
		t.Fatalf("grand requests=%d served=%d", rep.Grand.Requests, rep.Grand.BytesServed())
	}

	// Daily granularity collapses both hours (same UTC day) into one row.
	repDay := m.Report(ReportRequest{Granularity: "day"})
	if len(repDay.Rows) != 1 {
		t.Fatalf("daily rows = %d, want 1", len(repDay.Rows))
	}
	if repDay.Rows[0].Requests != 2 {
		t.Fatalf("daily row requests = %d", repDay.Rows[0].Requests)
	}

	// Per-tenant totals.
	if len(repDay.Totals) != 1 || repDay.Totals[0].Tenant != "acme" {
		t.Fatalf("totals = %+v", repDay.Totals)
	}
}

func TestReportIncludesPendingDelta(t *testing.T) {
	m, _ := newTestMeter(t, Config{RollupInterval: time.Hour})
	// Record but never roll up: the report must still reflect current usage via the
	// synthetic pending rollup.
	m.RecordRequest("acme", "npm", "npm")
	m.RecordTraffic("acme", 1234, true)

	rep := m.Report(ReportRequest{Granularity: "total"})
	if rep.Grand.Requests != 1 || rep.Grand.BytesServed() != 1234 {
		t.Fatalf("pending not reflected: requests=%d served=%d", rep.Grand.Requests, rep.Grand.BytesServed())
	}
}

func TestReportTenantFilter(t *testing.T) {
	m, _ := newTestMeter(t, Config{})
	m.RecordRequest("acme", "npm", "npm")
	m.RecordRequest("globex", "pypi", "pypi")
	rep := m.Report(ReportRequest{Tenant: "acme", Granularity: "total"})
	if len(rep.Totals) != 1 || rep.Totals[0].Tenant != "acme" {
		t.Fatalf("tenant filter failed: %+v", rep.Totals)
	}
}

func TestBudgetAlertFiresOnce(t *testing.T) {
	fe := &fakeEmitter{}
	m, _ := newTestMeter(t, Config{
		Notifier: fe,
		Budgets:  map[string]Budget{"acme": {MaxBytes: 1000}},
	})
	m.RecordTraffic("acme", 600, true)
	if fe.count() != 0 {
		t.Fatalf("alert fired early: %d", fe.count())
	}
	m.RecordTraffic("acme", 600, false) // total 1200 >= 1000
	if fe.count() != 1 {
		t.Fatalf("expected 1 alert, got %d", fe.count())
	}
	m.RecordTraffic("acme", 600, true) // still over, must not re-alert
	if fe.count() != 1 {
		t.Fatalf("budget alert not deduplicated: %d", fe.count())
	}
	ev := fe.events[0]
	if ev.Type != notify.EventMeteringBudget || ev.Fields["dimension"] != "bytes" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestBudgetDefaultWildcard(t *testing.T) {
	fe := &fakeEmitter{}
	m, _ := newTestMeter(t, Config{
		Notifier: fe,
		Budgets:  map[string]Budget{"*": {MaxScanCostMicros: 1000}},
	})
	m.RecordScan("anytenant", "vulnscan") // default cost applies
	for i := 0; i < 20; i++ {
		m.RecordScan("anytenant", "vulnscan")
	}
	if fe.count() != 1 {
		t.Fatalf("expected exactly 1 scan-cost alert via wildcard budget, got %d", fe.count())
	}
	if fe.events[0].Fields["dimension"] != "scanCost" {
		t.Fatalf("unexpected dimension: %v", fe.events[0].Fields)
	}
}

func TestObserveQuarantineTap(t *testing.T) {
	m, _ := newTestMeter(t, Config{})
	m.Observe(notify.Event{Type: notify.EventQuarantine, Subject: "acme"})
	m.Observe(notify.QuarantineEvent(notify.SeverityHigh, "npm", "b", "npm evil@1", "adv", "bad").WithField("tenant", "globex"))
	m.Observe(notify.Event{Type: notify.EventPolicyBlock, Subject: "acme"}) // ignored (not quarantine)

	acme, _ := m.TenantUsage("acme")
	globex, _ := m.TenantUsage("globex")
	if acme.Quarantined != 1 {
		t.Errorf("acme quarantined = %d, want 1", acme.Quarantined)
	}
	if globex.Quarantined != 1 {
		t.Errorf("globex quarantined = %d, want 1 (from tenant field)", globex.Quarantined)
	}
}

func TestRetentionPrunesOldRollups(t *testing.T) {
	m, clk := newTestMeter(t, Config{RetentionHours: 2, RollupInterval: time.Hour})
	for i := 0; i < 5; i++ {
		m.RecordRequest("acme", "npm", "npm")
		clk.t = clk.t.Add(time.Hour)
		m.Rollup(clk.t)
	}
	m.mu.Lock()
	retained := len(m.history)
	m.mu.Unlock()
	// With a 2h retention horizon only the most recent rollups survive.
	if retained == 0 || retained > 3 {
		t.Fatalf("retained %d rollups, expected a small bounded number", retained)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/usage.json"
	clk := &clock{t: time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)}

	m1 := New(Config{Enabled: true, StatePath: path, RollupInterval: time.Hour, Now: clk.now})
	m1.RecordRequest("acme", "npm", "npm")
	m1.RecordTraffic("acme", 4096, true)
	clk.t = clk.t.Add(time.Hour)
	m1.Rollup(clk.t)

	// A fresh meter loads the persisted history.
	m2 := New(Config{Enabled: true, StatePath: path, RollupInterval: time.Hour, Now: clk.now})
	rep := m2.Report(ReportRequest{Granularity: "total"})
	if rep.Grand.Requests != 1 || rep.Grand.BytesServed() != 4096 {
		t.Fatalf("persisted usage not restored: %+v", rep.Grand)
	}
}

func TestReportRenderers(t *testing.T) {
	m, _ := newTestMeter(t, Config{})
	m.RecordRequest("acme", "npm", "npm")
	m.RecordTraffic("acme", 2048, true)
	m.RecordScan("acme", "vulnscan")
	rep := m.Report(ReportRequest{Granularity: "total"})

	csv := rep.CSV()
	if !strings.Contains(csv, "tenant,period_start") || !strings.Contains(csv, "acme") {
		t.Fatalf("CSV missing header/data:\n%s", csv)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "Usage & chargeback") || !strings.Contains(md, "acme") {
		t.Fatalf("Markdown missing content:\n%s", md)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	m, clk := newTestMeter(t, Config{RollupInterval: time.Hour})
	m.RecordRequest("acme", "npm", "npm")
	m.RecordTraffic("acme", 100, false)
	clk.t = clk.t.Add(time.Hour)
	m.Rollup(clk.t)

	ms := m.MetricsSnapshot()
	if ms.RollupsTotal != 1 {
		t.Errorf("rollups = %d, want 1", ms.RollupsTotal)
	}
	if len(ms.Tenants) != 1 || ms.Tenants[0].Tenant != "acme" {
		t.Fatalf("metrics tenants = %+v", ms.Tenants)
	}
	if ms.Tenants[0].BytesUpstream != 100 {
		t.Errorf("metrics upstream bytes = %d", ms.Tenants[0].BytesUpstream)
	}
}
