package prewarm

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeFetcher records the targets it is asked to fetch and returns a
// configurable outcome, tracking peak concurrency.
type fakeFetcher struct {
	mu       sync.Mutex
	calls    []Target
	outcome  map[string]Outcome // keyed by target version; default admitted
	fetchErr map[string]error
	delay    time.Duration
	cur      int
	peak     int
}

func (f *fakeFetcher) Fetch(ctx context.Context, t Target) (FetchResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, t)
	f.cur++
	if f.cur > f.peak {
		f.peak = f.cur
	}
	f.mu.Unlock()

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	f.mu.Lock()
	f.cur--
	err := f.fetchErr[t.Version]
	out, ok := f.outcome[t.Version]
	f.mu.Unlock()

	if err != nil {
		return FetchResult{Outcome: OutcomeError}, err
	}
	if !ok {
		out = OutcomeAdmitted
	}
	return FetchResult{Outcome: out}, nil
}

func (f *fakeFetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newTestService(t *testing.T, cfg Config, f Fetcher) *Service {
	t.Helper()
	cfg.Enabled = true
	base := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	svc, err := New(cfg, Deps{Fetcher: f, Clock: func() time.Time { return base }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc == nil {
		t.Fatal("New returned nil for an enabled config")
	}
	return svc
}

func TestNewDisabledReturnsNil(t *testing.T) {
	svc, err := New(Config{Enabled: false}, Deps{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc != nil {
		t.Fatal("disabled config should yield a nil service")
	}
	// Nil service is a safe no-op.
	svc.Observe(PullEvent{Backend: "pip", Name: "foo"})
	if st := svc.Status(); st.Enabled {
		t.Error("nil service Status should report disabled")
	}
}

func TestRunOnceFetchesPredictedPatch(t *testing.T) {
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, f)

	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz", Tenant: "acme"})

	rep := svc.RunOnce(context.Background())
	if rep.Predicted != 1 || rep.Fetched != 1 {
		t.Fatalf("want predicted=1 fetched=1, got %+v", rep)
	}
	if f.count() != 1 {
		t.Fatalf("want 1 fetch call, got %d", f.count())
	}
	call := f.calls[0]
	if call.Path != "/v1/pip/foo-1.2.4.tar.gz" || call.Version != "1.2.4" || call.Tenant != "acme" {
		t.Fatalf("unexpected fetched target %+v", call)
	}

	m := svc.Metrics().Snapshot()
	if m.Predicted != 1 || m.Fetched != 1 || m.CyclesRun != 1 {
		t.Fatalf("unexpected metrics %+v", m)
	}
}

func TestHitAttribution(t *testing.T) {
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, f)
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})
	svc.RunOnce(context.Background())

	// A later client HIT for the pre-warmed artifact is attributed once.
	warmedPath := "/v1/pip/foo-1.2.4.tar.gz"
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.4", Path: warmedPath, CacheHit: true})
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.4", Path: warmedPath, CacheHit: true})

	if got := svc.Metrics().Snapshot().HitAttributed; got != 1 {
		t.Fatalf("want hitAttributed=1 (once per pre-warmed artifact), got %d", got)
	}
}

func TestGateBlockedRecorded(t *testing.T) {
	f := &fakeFetcher{outcome: map[string]Outcome{"1.2.4": OutcomeGateBlocked}}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, f)
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})

	rep := svc.RunOnce(context.Background())
	if rep.GateBlocked != 1 || rep.Fetched != 0 {
		t.Fatalf("want gateBlocked=1 fetched=0, got %+v", rep)
	}
	// A blocked artifact is never marked pre-warmed: a later hit is not attributed.
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.4", Path: "/v1/pip/foo-1.2.4.tar.gz", CacheHit: true})
	if got := svc.Metrics().Snapshot().HitAttributed; got != 0 {
		t.Fatalf("blocked artifact must not be attributable, got hitAttributed=%d", got)
	}
}

func TestFetchErrorRecorded(t *testing.T) {
	f := &fakeFetcher{fetchErr: map[string]error{"1.2.4": context.DeadlineExceeded}}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, f)
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})
	rep := svc.RunOnce(context.Background())
	if rep.Errors != 1 {
		t.Fatalf("want errors=1, got %+v", rep)
	}
}

func TestKillSwitchSkipsCycle(t *testing.T) {
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, f)
	svc.SetKillSwitch(func() bool { return true })
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})

	rep := svc.RunOnce(context.Background())
	if rep.Skipped != skipKillSwitch {
		t.Fatalf("want skip reason %q, got %+v", skipKillSwitch, rep)
	}
	if f.count() != 0 {
		t.Fatalf("kill-switch must prevent any fetch, got %d calls", f.count())
	}
}

func TestScheduledCycleLeaderGate(t *testing.T) {
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, f)
	svc.SetLeaderGate(func() bool { return false })
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})

	rep := svc.scheduledCycle(context.Background())
	if rep.Skipped != skipNotLeader {
		t.Fatalf("follower should skip with %q, got %+v", skipNotLeader, rep)
	}
	if f.count() != 0 {
		t.Fatalf("follower must not fetch, got %d calls", f.count())
	}
}

func TestNoFetcherSkips(t *testing.T) {
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1}, nil)
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})
	rep := svc.RunOnce(context.Background())
	if rep.Skipped != skipNoFetcher {
		t.Fatalf("want skip %q, got %+v", skipNoFetcher, rep)
	}
}

func TestMaxPerCycleAndConcurrency(t *testing.T) {
	f := &fakeFetcher{delay: 5 * time.Millisecond}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 5, MaxConcurrency: 2, MaxPerCycle: 3}, f)
	// One coordinate with 5 patch look-aheads → 5 candidates, capped to 3.
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})

	rep := svc.RunOnce(context.Background())
	// The predictor caps candidate generation at MaxPerCycle, so at most 3 of the
	// 5 possible patch look-aheads are produced and fetched.
	if rep.Predicted != 3 {
		t.Fatalf("want predicted=3 (capped at MaxPerCycle), got %+v", rep)
	}
	if f.count() != 3 {
		t.Fatalf("MaxPerCycle should cap fetches to 3, got %d", f.count())
	}
	f.mu.Lock()
	peak := f.peak
	f.mu.Unlock()
	if peak > 2 {
		t.Fatalf("MaxConcurrency=2 exceeded, peak=%d", peak)
	}
}

func TestWindowGating(t *testing.T) {
	// Off-peak 01:00-05:00 UTC; the test clock is 03:00 (inside).
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1, OffPeakStart: "01:00", OffPeakEnd: "05:00"}, f)
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})
	if rep := svc.scheduledCycle(context.Background()); rep.Skipped != "" {
		t.Fatalf("03:00 is inside 01:00-05:00; cycle should run, got %+v", rep)
	}

	// Move the clock to 08:00 (outside the window) and confirm a skip.
	outside := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return outside }
	if rep := svc.scheduledCycle(context.Background()); rep.Skipped != skipOffPeak {
		t.Fatalf("08:00 is outside the window; want %q, got %+v", skipOffPeak, rep)
	}
}

func TestWindowWrapsMidnight(t *testing.T) {
	startMin, endMin, loc, err := compileWindow("22:00", "05:00", "UTC")
	if err != nil {
		t.Fatalf("compileWindow: %v", err)
	}
	s := &Service{startMin: startMin, endMin: endMin, loc: loc}
	at := func(h, m int) time.Time { return time.Date(2026, 1, 1, h, m, 0, 0, time.UTC) }
	if !s.inWindow(at(23, 0)) {
		t.Error("23:00 should be inside a 22:00-05:00 window")
	}
	if !s.inWindow(at(2, 0)) {
		t.Error("02:00 should be inside a 22:00-05:00 window")
	}
	if s.inWindow(at(12, 0)) {
		t.Error("12:00 should be outside a 22:00-05:00 window")
	}
}

func TestInvalidWindowRejected(t *testing.T) {
	_, err := New(Config{Enabled: true, OffPeakStart: "25:00", OffPeakEnd: "05:00"}, Deps{})
	if err == nil {
		t.Fatal("expected an error for an invalid off-peak start")
	}
	_, err = New(Config{Enabled: true, OffPeakStart: "01:00"}, Deps{}) // only one bound
	if err == nil {
		t.Fatal("expected an error when only one off-peak bound is set")
	}
}

func TestTriggerThroughLoop(t *testing.T) {
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1, Interval: time.Hour}, f)
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	defer svc.Close()

	rep, err := svc.Trigger(context.Background())
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if rep.Fetched != 1 {
		t.Fatalf("want fetched=1 from triggered cycle, got %+v", rep)
	}
}

func TestStatusReflectsState(t *testing.T) {
	f := &fakeFetcher{}
	svc := newTestService(t, Config{MinPulls: 1, PatchLookahead: 1, MaxConcurrency: 3, RatePerMinute: 120}, f)
	svc.SetLeaderGate(func() bool { return true })
	svc.SetKillSwitch(func() bool { return false })
	svc.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz"})
	svc.RunOnce(context.Background())

	st := svc.Status()
	if !st.Enabled || !st.Leader || st.KillSwitchActive {
		t.Fatalf("unexpected status flags %+v", st)
	}
	if st.HistoryCoordinates != 1 {
		t.Errorf("want 1 history coordinate, got %d", st.HistoryCoordinates)
	}
	if st.PrewarmedTracked != 1 {
		t.Errorf("want 1 pre-warmed tracked, got %d", st.PrewarmedTracked)
	}
	if st.MaxConcurrency != 3 || st.RatePerMinute != 120 {
		t.Errorf("status did not surface config: %+v", st)
	}
	if st.LastRun.Fetched != 1 {
		t.Errorf("status LastRun not updated: %+v", st.LastRun)
	}
}
