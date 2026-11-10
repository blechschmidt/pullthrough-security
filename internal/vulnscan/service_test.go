package vulnscan

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// fakeScanner returns a fixed set of vulnerabilities (or an error) and counts calls.
type fakeScanner struct {
	mu    sync.Mutex
	vulns []Vulnerability
	err   error
	calls int
}

func (f *fakeScanner) Name() string { return "fake" }

func (f *fakeScanner) Scan(ctx context.Context, sbom *SBOM) ([]Vulnerability, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.vulns, nil
}

func (f *fakeScanner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func openNil() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }

func critical() Vulnerability {
	return Vulnerability{ID: "CVE-2024-0001", Severity: SeverityCritical, CVSS: 9.8, Package: "evil", Version: "1.0.0",
		FixedVersions: []string{"1.0.1"}}
}

func TestServiceGateBlocksAboveThreshold(t *testing.T) {
	fs := &fakeScanner{vulns: []Vulnerability{critical()}}
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock}, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	art := Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:d1"}
	report, err := svc.Assess(context.Background(), art, openNil)
	if err != nil {
		t.Fatal(err)
	}
	if report.MaxSeverity != SeverityCritical || report.Counts.Critical != 1 {
		t.Errorf("report summary wrong: %+v", report.Counts)
	}
	dec := svc.Gate(report)
	if dec.Action != policy.ActionBlock {
		t.Errorf("action = %s want block", dec.Action)
	}
	if !strings.Contains(dec.Reason, "CVE-2024-0001") || !strings.Contains(dec.Reason, "1.0.1") {
		t.Errorf("reason missing detail: %s", dec.Reason)
	}
}

func TestServiceGateCVSSThreshold(t *testing.T) {
	v := Vulnerability{ID: "X", Severity: SeverityMedium, CVSS: 6.5}
	fs := &fakeScanner{vulns: []Vulnerability{v}}
	// Severity threshold is critical (won't trip), but CVSS >= 6.0 should.
	svc, _ := NewService(Config{FailSeverity: SeverityCritical, FailCVSS: 6.0, Action: policy.ActionQuarantine}, fs, nil)
	report, _ := svc.Assess(context.Background(), Artifact{Digest: "sha256:c1"}, openNil)
	dec := svc.Gate(report)
	if dec.Action != policy.ActionQuarantine {
		t.Errorf("action = %s want quarantine (cvss gate)", dec.Action)
	}
}

func TestServiceGateWarnBand(t *testing.T) {
	v := Vulnerability{ID: "X", Severity: SeverityMedium, CVSS: 5.0}
	fs := &fakeScanner{vulns: []Vulnerability{v}}
	svc, _ := NewService(Config{FailSeverity: SeverityHigh, WarnSeverity: SeverityMedium, Action: policy.ActionBlock}, fs, nil)
	report, _ := svc.Assess(context.Background(), Artifact{Digest: "sha256:w1"}, openNil)
	dec := svc.Gate(report)
	if dec.Action != policy.ActionWarn {
		t.Errorf("action = %s want warn", dec.Action)
	}
}

func TestServiceGateAllowsBelowThreshold(t *testing.T) {
	v := Vulnerability{ID: "X", Severity: SeverityLow, CVSS: 2.0}
	fs := &fakeScanner{vulns: []Vulnerability{v}}
	svc, _ := NewService(Config{FailSeverity: SeverityHigh, WarnSeverity: SeverityHigh, Action: policy.ActionBlock}, fs, nil)
	report, _ := svc.Assess(context.Background(), Artifact{Digest: "sha256:a1"}, openNil)
	if dec := svc.Gate(report); dec.Action != policy.ActionAllow {
		t.Errorf("action = %s want allow", dec.Action)
	}
}

func TestServiceIgnoreList(t *testing.T) {
	v := critical()
	v.Aliases = []string{"GHSA-aaaa"}
	fs := &fakeScanner{vulns: []Vulnerability{v}}
	svc, _ := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock, IgnoreIDs: []string{"GHSA-aaaa"}}, fs, nil)
	report, _ := svc.Assess(context.Background(), Artifact{Digest: "sha256:i1"}, openNil)
	if dec := svc.Gate(report); dec.Action != policy.ActionAllow {
		t.Errorf("ignored finding still gated: %s", dec.Action)
	}
}

func TestServiceWithdrawnExcluded(t *testing.T) {
	v := critical()
	v.Withdrawn = true
	fs := &fakeScanner{vulns: []Vulnerability{v}}
	svc, _ := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock}, fs, nil)
	report, _ := svc.Assess(context.Background(), Artifact{Digest: "sha256:wd"}, openNil)
	if report.Counts.Critical != 0 {
		t.Errorf("withdrawn finding counted: %+v", report.Counts)
	}
	if dec := svc.Gate(report); dec.Action != policy.ActionAllow {
		t.Errorf("withdrawn finding gated: %s", dec.Action)
	}
}

func TestServiceCachesByDigest(t *testing.T) {
	fs := &fakeScanner{vulns: []Vulnerability{critical()}}
	svc, _ := NewService(Config{FailSeverity: SeverityHigh, CacheTTL: time.Hour}, fs, nil)
	art := Artifact{Digest: "sha256:cache"}
	for i := 0; i < 3; i++ {
		if _, err := svc.Assess(context.Background(), art, openNil); err != nil {
			t.Fatal(err)
		}
	}
	if fs.callCount() != 1 {
		t.Errorf("scanner called %d times, want 1 (cached)", fs.callCount())
	}
	if r, ok := svc.Report("sha256:cache"); !ok || r == nil {
		t.Error("report not retrievable by digest")
	}
}

func TestServiceConcurrentSingleFlight(t *testing.T) {
	fs := &fakeScanner{vulns: []Vulnerability{critical()}}
	svc, _ := NewService(Config{CacheTTL: time.Hour}, fs, nil)
	art := Artifact{Digest: "sha256:herd"}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Assess(context.Background(), art, openNil)
		}()
	}
	wg.Wait()
	if fs.callCount() != 1 {
		t.Errorf("thundering herd scanned %d times, want 1", fs.callCount())
	}
}

func TestServiceOfflineFallbackToStale(t *testing.T) {
	fs := &fakeScanner{vulns: []Vulnerability{critical()}}
	// Zero TTL so the first result is immediately stale on the second pull.
	svc, _ := NewService(Config{CacheTTL: time.Nanosecond, FailSeverity: SeverityHigh}, fs, nil)
	art := Artifact{Digest: "sha256:off"}
	if _, err := svc.Assess(context.Background(), art, openNil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	// Now the backend fails; the stale cached result must be used.
	fs.mu.Lock()
	fs.err = errors.New("network down")
	fs.mu.Unlock()
	report, err := svc.Assess(context.Background(), art, openNil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Offline {
		t.Error("expected offline fallback flag")
	}
	if report.MaxSeverity != SeverityCritical {
		t.Errorf("stale result not preserved: %s", report.MaxSeverity)
	}
	if svc.Metrics().OfflineFallbacks != 1 {
		t.Errorf("offline fallback not metered: %+v", svc.Metrics())
	}
}

func TestServiceScanErrorFailOpenClosed(t *testing.T) {
	// Fail-open: scan error with no cache → warn.
	fs := &fakeScanner{err: errors.New("boom")}
	open := svc(t, Config{FailOnError: false})
	report, _ := open.svc.Assess(context.Background(), Artifact{Digest: "sha256:e1"}, openNil)
	if dec := open.svc.Gate(report); dec.Action != policy.ActionWarn {
		t.Errorf("fail-open action = %s want warn", dec.Action)
	}
	_ = fs

	// Fail-closed: scan error with no cache → block.
	closed := svc(t, Config{FailOnError: true})
	report2, _ := closed.svc.Assess(context.Background(), Artifact{Digest: "sha256:e2"}, openNil)
	if dec := closed.svc.Gate(report2); dec.Action != policy.ActionBlock {
		t.Errorf("fail-closed action = %s want block", dec.Action)
	}
}

func TestServiceOfflineModeNoScanner(t *testing.T) {
	svc, err := NewService(Config{Offline: true}, nil, nil)
	if err != nil {
		t.Fatalf("offline service should not require a scanner: %v", err)
	}
	report, _ := svc.Assess(context.Background(), Artifact{Digest: "sha256:o1"}, openNil)
	if report.Error == "" {
		t.Error("offline scan with no cache should report an error")
	}
}

func TestNewServiceRequiresScanner(t *testing.T) {
	if _, err := NewService(Config{}, nil, nil); err == nil {
		t.Error("expected error for nil scanner when not offline")
	}
}

// svcHarness bundles a service with a failing scanner for the fail-open/closed test.
type svcHarness struct{ svc *Service }

func svc(t *testing.T, cfg Config) svcHarness {
	t.Helper()
	s, err := NewService(cfg, &fakeScanner{err: errors.New("boom")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svcHarness{svc: s}
}
