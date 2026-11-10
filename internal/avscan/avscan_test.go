package avscan

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// fakeEngine is an injectable Engine for service-level tests.
type fakeEngine struct {
	verdict Verdict
	err     error
	scans   int
}

func (f *fakeEngine) Name() string { return "fake" }
func (f *fakeEngine) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	f.scans++
	n, _ := io.Copy(io.Discard, r)
	if f.err != nil {
		return Verdict{}, f.err
	}
	v := f.verdict
	v.Bytes = n
	return v, nil
}
func (f *fakeEngine) Ping(ctx context.Context) error { return f.err }

func newTestService(t *testing.T, action Action, failOpen bool, eng Engine) *Service {
	t.Helper()
	svc, err := NewService(Config{
		Enabled:    true,
		Action:     action,
		FailOpen:   failOpen,
		EngineImpl: eng,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func opener(data string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(data)), nil
	}
}

func TestServiceCleanAllows(t *testing.T) {
	svc := newTestService(t, ActionQuarantine, true, &fakeEngine{})
	art := Artifact{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Filename: "left-pad-1.0.0.tgz"}
	rep, err := svc.Assess(context.Background(), art, opener("benign bytes"))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !rep.Scanned || rep.Infected {
		t.Fatalf("expected clean scanned report, got %+v", rep)
	}
	d := svc.Gate(rep)
	if !d.Served() || d.Evict {
		t.Fatalf("clean artifact must be served and not evicted: %+v", d)
	}
	if svc.Metrics().Clean != 1 {
		t.Errorf("clean counter = %d, want 1", svc.Metrics().Clean)
	}
}

func TestServiceInfectedQuarantine(t *testing.T) {
	eng := &fakeEngine{verdict: Verdict{Infected: true, Signature: "Eicar-Test-Signature"}}
	svc := newTestService(t, ActionQuarantine, true, eng)
	art := Artifact{Ecosystem: "pypi", Name: "evil", Version: "6.6.6"}
	rep, err := svc.Assess(context.Background(), art, opener(eicar))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !rep.Infected || rep.Signature != "Eicar-Test-Signature" {
		t.Fatalf("expected infected report, got %+v", rep)
	}
	if !rep.HasFindings() || rep.Findings[0].RuleID != RuleMalwareDetected {
		t.Fatalf("expected malware finding, got %+v", rep.Findings)
	}
	if rep.Risk != detectionRisk {
		t.Errorf("risk = %d, want %d", rep.Risk, detectionRisk)
	}
	d := svc.Gate(rep)
	if d.Served() {
		t.Fatalf("infected artifact must be refused under quarantine")
	}
	if !d.Evict {
		t.Fatalf("quarantine must evict")
	}
	if svc.Metrics().Quarantined != 1 || svc.Metrics().Infected != 1 {
		t.Errorf("counters = %+v", svc.Metrics())
	}
	if svc.Metrics().InfectedBySignat["Eicar-Test-Signature"] != 1 {
		t.Errorf("signature breakdown missing: %+v", svc.Metrics().InfectedBySignat)
	}
}

func TestServiceInfectedBlockNoEvict(t *testing.T) {
	eng := &fakeEngine{verdict: Verdict{Infected: true, Signature: "Trojan"}}
	svc := newTestService(t, ActionBlock, true, eng)
	rep, _ := svc.Assess(context.Background(), Artifact{Name: "x"}, opener(eicar))
	d := svc.Gate(rep)
	if d.Served() {
		t.Fatalf("block must refuse serving")
	}
	if d.Evict {
		t.Fatalf("block must NOT evict (forensic retention)")
	}
	if svc.Metrics().Blocked != 1 {
		t.Errorf("blocked counter = %d, want 1", svc.Metrics().Blocked)
	}
}

func TestServiceInfectedAnnotateServes(t *testing.T) {
	eng := &fakeEngine{verdict: Verdict{Infected: true, Signature: "Trojan"}}
	svc := newTestService(t, ActionAnnotate, true, eng)
	rep, _ := svc.Assess(context.Background(), Artifact{Name: "x"}, opener(eicar))
	d := svc.Gate(rep)
	if !d.Served() {
		t.Fatalf("annotate must still serve")
	}
	if d.Evict {
		t.Fatalf("annotate must not evict")
	}
	if svc.Metrics().Annotated != 1 {
		t.Errorf("annotated counter = %d, want 1", svc.Metrics().Annotated)
	}
}

func TestServiceEngineUnavailableFailOpen(t *testing.T) {
	eng := &fakeEngine{err: errors.New("connection refused")}
	svc := newTestService(t, ActionQuarantine, true, eng)
	rep, err := svc.Assess(context.Background(), Artifact{Name: "x"}, opener("data"))
	if err != nil {
		t.Fatalf("Assess returned hard error, want graceful report: %v", err)
	}
	if !rep.Unavailable || rep.Scanned {
		t.Fatalf("expected unavailable report, got %+v", rep)
	}
	d := svc.Gate(rep)
	if !d.Served() {
		t.Fatalf("fail-open must serve on engine-unavailable")
	}
	if svc.Metrics().Unavailable != 1 || svc.Metrics().Degraded != 1 {
		t.Errorf("counters = %+v", svc.Metrics())
	}
}

func TestServiceEngineUnavailableFailClosed(t *testing.T) {
	eng := &fakeEngine{err: errors.New("connection refused")}
	svc := newTestService(t, ActionQuarantine, false, eng)
	rep, _ := svc.Assess(context.Background(), Artifact{Name: "x"}, opener("data"))
	d := svc.Gate(rep)
	if d.Served() {
		t.Fatalf("fail-closed must refuse on engine-unavailable")
	}
	if d.Evict {
		t.Fatalf("engine-unavailable must never evict")
	}
}

func TestServiceContextCanceled(t *testing.T) {
	eng := &fakeEngine{err: context.Canceled}
	svc := newTestService(t, ActionQuarantine, true, eng)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.Assess(ctx, Artifact{Name: "x"}, opener("data"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestServiceTruncation(t *testing.T) {
	eng := &fakeEngine{}
	svc, err := NewService(Config{
		Enabled: true, Action: ActionQuarantine, FailOpen: true,
		EngineImpl: eng, MaxScanBytes: 8, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	rep, err := svc.Assess(context.Background(), Artifact{Name: "x"}, opener("0123456789abcdef"))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !rep.Truncated {
		t.Fatalf("expected truncated report for oversize artifact, got %+v", rep)
	}
	if rep.Bytes != 8 {
		t.Errorf("scanned bytes = %d, want 8", rep.Bytes)
	}
}

func TestNilServiceSafe(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Error("nil service must not be enabled")
	}
	if svc.Metrics().Scanned != 0 {
		t.Error("nil service metrics must be zero")
	}
	if err := svc.Ping(context.Background()); err != nil {
		t.Errorf("nil ping: %v", err)
	}
	if svc.Action() != ActionQuarantine {
		t.Errorf("nil action = %v", svc.Action())
	}
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"bad action", Config{Action: "nuke", EngineImpl: &fakeEngine{}}, "invalid action"},
		{"unknown engine", Config{Engine: "sophos", Address: "x:1"}, "unknown engine"},
		{"missing address", Config{Engine: "clamav"}, "requires an address"},
		{"negative timeout", Config{Address: "x:1", Timeout: -1}, "timeout must not be negative"},
		{"ok clamav", Config{Address: "127.0.0.1:3310"}, ""},
		{"ok injected", Config{EngineImpl: &fakeEngine{}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewService(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestEndToEndWithRealClamdProtocol(t *testing.T) {
	// Service over the real ClamdEngine talking to the fake daemon: proves the
	// wire protocol and the service layer compose.
	f := newFakeClamd(t)
	f.matcher = eicarMatcher
	svc, err := NewService(Config{
		Enabled: true, Action: ActionQuarantine, FailOpen: true,
		Engine: "clamav", Address: f.addr(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	rep, err := svc.Assess(context.Background(), Artifact{Name: "evil", Version: "1"}, opener(eicar))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !rep.Infected {
		t.Fatalf("expected infected via real protocol, got %+v", rep)
	}
	if svc.Gate(rep).Served() {
		t.Fatalf("infected artifact must be refused")
	}
}
