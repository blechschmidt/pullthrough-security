package vulnscan

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// driftScanner is a fake OSV client whose advisory database changes over time: it
// returns no findings until a CVE is "published" for a package, after which a scan
// of any SBOM containing that package's component yields the advisory. This models
// CVE drift — a vulnerability disclosed after an artifact was first pulled.
type driftScanner struct {
	mu        sync.Mutex
	published map[string]Vulnerability // package name -> advisory
	calls     atomic.Int64
}

func newDriftScanner() *driftScanner {
	return &driftScanner{published: make(map[string]Vulnerability)}
}

func (d *driftScanner) Name() string { return "fake-osv" }

// publish makes the scanner start reporting adv for components named pkg.
func (d *driftScanner) publish(pkg string, adv Vulnerability) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.published[pkg] = adv
}

func (d *driftScanner) Scan(ctx context.Context, sbom *SBOM) ([]Vulnerability, error) {
	d.calls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if sbom == nil {
		return nil, nil
	}
	var out []Vulnerability
	for _, c := range sbom.scannableComponents() {
		if adv, ok := d.published[c.Name]; ok {
			v := adv
			v.Component = c.PURL
			v.Package = c.Name
			v.Version = c.Version
			out = append(out, v)
		}
	}
	return out, nil
}

// recordingEvicter records the keys passed to Delete so the test can assert the
// poisoned artifact's content was evicted on quarantine.
type recordingEvicter struct {
	mu      sync.Mutex
	deleted []string
}

func (e *recordingEvicter) Delete(ctx context.Context, key string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deleted = append(e.deleted, key)
	return nil
}

func (e *recordingEvicter) wasDeleted(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, k := range e.deleted {
		if k == key {
			return true
		}
	}
	return false
}

func newCVE() Vulnerability {
	return Vulnerability{
		ID:            "CVE-2026-9999",
		Summary:       "remote code execution",
		Severity:      SeverityCritical,
		CVSS:          9.8,
		FixedVersions: []string{"1.0.1"},
	}
}

// assessClean primes the result cache with a clean scan of art, returning the
// service, drift scanner, and evicter under test.
func setupRescan(t *testing.T, action policy.Action) (*Service, *driftScanner, *recordingEvicter, Artifact) {
	t.Helper()
	ds := newDriftScanner()
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: action}, ds, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	art := Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:evil1"}
	report, err := svc.Assess(context.Background(), art, openNil)
	if err != nil {
		t.Fatalf("initial Assess: %v", err)
	}
	if report.Counts.Total() != 0 {
		t.Fatalf("expected clean initial scan, got %+v", report.Counts)
	}
	if svc.EvaluateReport(report).Action.Blocked() {
		t.Fatalf("artifact should be servable before the CVE is published")
	}
	return svc, ds, &recordingEvicter{}, art
}

func TestRescanDetectsNewlyPublishedCVE(t *testing.T) {
	svc, ds, evicter, art := setupRescan(t, policy.ActionBlock)
	rs := NewRescanner(svc, RescanConfig{Workers: 2}, evicter, nil, nil)

	// A CVE is disclosed for the already-cached package after it was pulled.
	ds.publish("evil", newCVE())

	summary := rs.RunOnce(context.Background())

	if summary.Rescanned != 1 {
		t.Errorf("Rescanned = %d, want 1", summary.Rescanned)
	}
	if summary.NewlyVulnerable != 1 {
		t.Errorf("NewlyVulnerable = %d, want 1", summary.NewlyVulnerable)
	}
	if summary.Changed != 1 {
		t.Errorf("Changed = %d, want 1", summary.Changed)
	}
	if len(summary.Changes) != 1 {
		t.Fatalf("want 1 change, got %d", len(summary.Changes))
	}
	ch := summary.Changes[0]
	if !ch.NewlyVulnerable {
		t.Errorf("change should be flagged newly vulnerable")
	}
	if ch.NewMaxSeverity != SeverityCritical {
		t.Errorf("NewMaxSeverity = %s, want critical", ch.NewMaxSeverity)
	}
	if ch.PrevAction.Blocked() || !ch.NewAction.Blocked() {
		t.Errorf("expected transition servable->blocked, got %s->%s", ch.PrevAction, ch.NewAction)
	}
	if len(ch.NewAdvisories) != 1 || ch.NewAdvisories[0] != "CVE-2026-9999" {
		t.Errorf("NewAdvisories = %v, want [CVE-2026-9999]", ch.NewAdvisories)
	}

	// The artifact must now be quarantined so the serve gate refuses it.
	q, ok := svc.QuarantineInfo(art.Digest)
	if !ok {
		t.Fatalf("artifact was not quarantined")
	}
	if q.Advisory != "CVE-2026-9999" || q.MaxSeverity != SeverityCritical {
		t.Errorf("quarantine entry wrong: %+v", q)
	}
	if !svc.IsQuarantined(art.Digest) {
		t.Errorf("IsQuarantined should be true")
	}

	// Content should have been evicted from the content cache (best effort).
	if !evicter.wasDeleted(art.Digest) {
		t.Errorf("expected content eviction of %s", art.Digest)
	}

	// Metrics reflect the drift.
	m := svc.Metrics()
	if m.RescansTotal < 1 {
		t.Errorf("RescansTotal = %d, want >=1", m.RescansTotal)
	}
	if m.NewlyVulnerableTotal != 1 {
		t.Errorf("NewlyVulnerableTotal = %d, want 1", m.NewlyVulnerableTotal)
	}
	if m.LastRescanUnix == 0 {
		t.Errorf("LastRescanUnix should be set")
	}
	if m.QuarantinedEntries != 1 {
		t.Errorf("QuarantinedEntries = %d, want 1", m.QuarantinedEntries)
	}

	// The cached report was refreshed to the vulnerable result.
	refreshed, ok := svc.Report(art.Digest)
	if !ok || refreshed.Counts.Critical != 1 {
		t.Errorf("cached report not refreshed: %+v", refreshed)
	}
}

func TestRescanNoChangeWhenStillClean(t *testing.T) {
	svc, _, evicter, art := setupRescan(t, policy.ActionBlock)
	rs := NewRescanner(svc, RescanConfig{Workers: 1}, evicter, nil, nil)

	summary := rs.RunOnce(context.Background())

	if summary.Rescanned != 1 {
		t.Errorf("Rescanned = %d, want 1", summary.Rescanned)
	}
	if summary.Changed != 0 || summary.NewlyVulnerable != 0 {
		t.Errorf("expected no changes, got changed=%d newly=%d", summary.Changed, summary.NewlyVulnerable)
	}
	if svc.IsQuarantined(art.Digest) {
		t.Errorf("clean artifact must not be quarantined")
	}
	if svc.Metrics().NewlyVulnerableTotal != 0 {
		t.Errorf("NewlyVulnerableTotal should be 0")
	}
}

func TestRescanEmitsAuditEvent(t *testing.T) {
	svc, ds, evicter, _ := setupRescan(t, policy.ActionBlock)

	var (
		mu     sync.Mutex
		events []RescanAudit
	)
	auditFn := func(ctx context.Context, ev RescanAudit) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}
	rs := NewRescanner(svc, RescanConfig{Workers: 2}, evicter, auditFn, nil)

	ds.publish("evil", newCVE())
	rs.RunOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(events))
	}
	ev := events[0]
	if !ev.Quarantined || ev.Advisory != "CVE-2026-9999" || ev.MaxSeverity != SeverityCritical {
		t.Errorf("audit event wrong: %+v", ev)
	}
}

func TestRescanTriggerViaScheduler(t *testing.T) {
	svc, ds, evicter, art := setupRescan(t, policy.ActionQuarantine)
	rs := NewRescanner(svc, RescanConfig{Workers: 2}, evicter, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs.Start(ctx)
	defer rs.Close()

	ds.publish("evil", newCVE())

	summary, err := rs.Trigger(context.Background())
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if summary.NewlyVulnerable != 1 {
		t.Errorf("NewlyVulnerable = %d, want 1", summary.NewlyVulnerable)
	}
	if !svc.IsQuarantined(art.Digest) {
		t.Errorf("artifact should be quarantined after triggered sweep")
	}

	// LastSummary and RiskChanges expose the result to the admin surface.
	if got := rs.LastSummary(); got.NewlyVulnerable != 1 {
		t.Errorf("LastSummary.NewlyVulnerable = %d, want 1", got.NewlyVulnerable)
	}
	if changes := rs.RiskChanges(); len(changes) != 1 {
		t.Errorf("RiskChanges len = %d, want 1", len(changes))
	}
}

func TestReleaseQuarantine(t *testing.T) {
	svc, ds, evicter, art := setupRescan(t, policy.ActionBlock)
	rs := NewRescanner(svc, RescanConfig{Workers: 1}, evicter, nil, nil)
	ds.publish("evil", newCVE())
	rs.RunOnce(context.Background())

	if !svc.IsQuarantined(art.Digest) {
		t.Fatalf("precondition: artifact should be quarantined")
	}
	if !svc.ReleaseQuarantine(art.Digest) {
		t.Errorf("ReleaseQuarantine should report it released an entry")
	}
	if svc.IsQuarantined(art.Digest) {
		t.Errorf("artifact should no longer be quarantined")
	}
	// Releasing again is a no-op.
	if svc.ReleaseQuarantine(art.Digest) {
		t.Errorf("second release should report nothing released")
	}
	// The scan cache was dropped so the next pull re-scans.
	if _, ok := svc.Report(art.Digest); ok {
		t.Errorf("cached report should have been evicted on release")
	}
}

// TestRescanOfflineSkips verifies an offline service performs no re-scan work
// (there is no backend to re-query, and content must not be re-downloaded).
func TestRescanOfflineSkips(t *testing.T) {
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock, Offline: true}, nil, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	rs := NewRescanner(svc, RescanConfig{}, nil, nil, nil)
	summary := rs.RunOnce(context.Background())
	if summary.Rescanned != 0 {
		t.Errorf("offline rescan should do nothing, got Rescanned=%d", summary.Rescanned)
	}
}
