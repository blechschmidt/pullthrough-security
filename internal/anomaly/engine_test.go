package anomaly

import (
	"fmt"
	"testing"
	"time"
)

// baseTime is a fixed, deterministic anchor at 12:00 UTC (within business hours
// for the default 20→6 off-hours window) so tests that do not exercise the
// off-hours detector are unaffected by it.
var baseTime = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

func newTestEngine(t *testing.T, mutate func(*Config)) *Engine {
	t.Helper()
	cfg := Config{
		Enabled: true,
		Window:  time.Minute,
		// A wide alert cooldown keeps alert bookkeeping predictable in tests that
		// drive a single burst; tests that exercise the cooldown override it.
		AlertCooldown: time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestFanoutDetectorTriggersOnDistinctSpike(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = Tunables{
			FanoutWarn: 10, FanoutHigh: 20,
			NewNamespaceWarn: 6, NewNamespaceHigh: 25,
			OffHoursWarn: 60, OffHoursHigh: 250,
			EnumerationWarn: 25, EnumerationHigh: 120,
			EgressZWarn: 3.5, EgressZHigh: 7,
		}
	})

	var last Assessment
	for i := 0; i < 25; i++ {
		last = e.Observe(Observation{
			Tenant:   "acme",
			Identity: "ci-token",
			Package:  fmt.Sprintf("pkg-%d", i),
			Time:     baseTime.Add(time.Duration(i) * time.Second),
		})
	}

	fan := detectorResult(t, last, DetectorFanout)
	if !fan.Triggered {
		t.Fatalf("expected fanout detector to trigger, got %+v", fan)
	}
	if fan.Value < 20 {
		t.Fatalf("expected distinct count >= 20, got %v", fan.Value)
	}
	if last.Level != LevelHigh {
		t.Fatalf("expected high level after 25 distinct packages, got %q (score=%v)", last.Level, last.Score)
	}
	if len(last.Triggered) == 0 || last.Triggered[0] != DetectorFanout {
		t.Fatalf("expected fanout as top trigger, got %v", last.Triggered)
	}
}

func TestFanoutWindowExpiryResetsScore(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.FanoutWarn = 5
		c.Tunables.FanoutHigh = 10
	})

	// 12 distinct packages inside the first window → triggered.
	var hot Assessment
	for i := 0; i < 12; i++ {
		hot = e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: fmt.Sprintf("p%d", i),
			Time: baseTime.Add(time.Duration(i) * time.Second),
		})
	}
	if !detectorResult(t, hot, DetectorFanout).Triggered {
		t.Fatalf("expected fanout to trigger inside window")
	}

	// One more pull, two minutes later: the earlier window has fully expired, so
	// only this single distinct package remains.
	cool := e.Observe(Observation{
		Tenant: "acme", Identity: "id", Package: "later",
		Time: baseTime.Add(2 * time.Minute),
	})
	fan := detectorResult(t, cool, DetectorFanout)
	if fan.Triggered {
		t.Fatalf("expected fanout to reset after window expiry, got value=%v", fan.Value)
	}
	if fan.Value != 1 {
		t.Fatalf("expected 1 distinct package after expiry, got %v", fan.Value)
	}
}

func TestNewNamespaceDetector(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.NewNamespaceWarn = 3
		c.Tunables.NewNamespaceHigh = 8
	})

	// Pull the same two namespaces repeatedly: only the first sighting of each
	// counts as "new", so the new-namespace count stays at 2 and never triggers.
	for i := 0; i < 10; i++ {
		ns := "@org-a"
		if i%2 == 1 {
			ns = "@org-b"
		}
		a := e.Observe(Observation{
			Tenant: "acme", Identity: "id", Namespace: ns, Package: fmt.Sprintf("p%d", i),
			Time: baseTime.Add(time.Duration(i) * time.Second),
		})
		if detectorResult(t, a, DetectorNewNamespace).Triggered {
			t.Fatalf("repeated namespaces should not trigger new-namespace (i=%d)", i)
		}
	}

	// Now discover several brand-new namespaces in quick succession.
	var last Assessment
	for i := 0; i < 5; i++ {
		last = e.Observe(Observation{
			Tenant: "acme", Identity: "id", Namespace: fmt.Sprintf("@new-%d", i), Package: fmt.Sprintf("np%d", i),
			Time: baseTime.Add(time.Duration(20+i) * time.Second),
		})
	}
	ns := detectorResult(t, last, DetectorNewNamespace)
	if !ns.Triggered {
		t.Fatalf("expected new-namespace to trigger, got value=%v", ns.Value)
	}
}

func TestEnumerationDetectorCounts404s(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.EnumerationWarn = 5
		c.Tunables.EnumerationHigh = 10
	})

	var last Assessment
	for i := 0; i < 12; i++ {
		// Distinct package names so the fan-out detector is what would otherwise
		// fire — but we keep the fan-out threshold at its high default so only
		// enumeration triggers here.
		last = e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: fmt.Sprintf("ghost-%d", i),
			NotFound: true, Time: baseTime.Add(time.Duration(i) * time.Second),
		})
	}
	enum := detectorResult(t, last, DetectorEnumeration)
	if !enum.Triggered {
		t.Fatalf("expected enumeration to trigger, got value=%v", enum.Value)
	}
	if enum.Value < 10 {
		t.Fatalf("expected >=10 negative lookups, got %v", enum.Value)
	}
	if last.Level != LevelHigh {
		t.Fatalf("expected high level, got %q", last.Level)
	}
}

func TestOffHoursDetector(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.OffHoursWarn = 5
		c.Tunables.OffHoursHigh = 10
		c.OffHoursStart = 20
		c.OffHoursEnd = 6
	})

	// Requests at 02:00 UTC fall inside the 20→6 off-hours window.
	night := time.Date(2026, 6, 20, 2, 0, 0, 0, time.UTC)
	var last Assessment
	for i := 0; i < 8; i++ {
		last = e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: "p", // same package: not fan-out
			Time: night.Add(time.Duration(i) * time.Second),
		})
	}
	off := detectorResult(t, last, DetectorOffHours)
	if !off.Triggered {
		t.Fatalf("expected off-hours to trigger at night, got value=%v", off.Value)
	}

	// The same volume during business hours must not trigger off-hours.
	e2 := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.OffHoursWarn = 5
		c.Tunables.OffHoursHigh = 10
		c.OffHoursStart = 20
		c.OffHoursEnd = 6
	})
	day := time.Date(2026, 6, 20, 13, 0, 0, 0, time.UTC)
	var dayLast Assessment
	for i := 0; i < 8; i++ {
		dayLast = e2.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: "p",
			Time: day.Add(time.Duration(i) * time.Second),
		})
	}
	if detectorResult(t, dayLast, DetectorOffHours).Triggered {
		t.Fatalf("off-hours must not trigger during business hours")
	}
}

func TestEgressDetectorSpikeVsBaseline(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.EgressZWarn = 3
		c.Tunables.EgressZHigh = 6
		c.EgressWarmup = 8
		c.EgressMinVolume = 1 << 20 // 1 MiB
		c.Window = 10 * time.Second
		c.EgressBaselineAlpha = 0.1
	})

	// Establish a steady ~2 MiB-per-request baseline, spaced so each request's
	// window holds roughly one transfer (window 10s, spacing 12s).
	const steady = 2 << 20
	tm := baseTime
	for i := 0; i < 20; i++ {
		a := e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: fmt.Sprintf("p%d", i),
			Bytes: steady, Time: tm,
		})
		if detectorResult(t, a, DetectorEgress).Triggered {
			t.Fatalf("steady baseline traffic must not trigger egress (i=%d)", i)
		}
		tm = tm.Add(12 * time.Second)
	}

	// A sudden 200 MiB transfer is far above the established baseline.
	spike := e.Observe(Observation{
		Tenant: "acme", Identity: "id", Package: "dump.tar",
		Bytes: 200 << 20, Time: tm,
	})
	eg := detectorResult(t, spike, DetectorEgress)
	if !eg.Triggered {
		t.Fatalf("expected egress spike to trigger, got value(z)=%v baseline=%v", eg.Value, eg.Baseline)
	}
}

func TestEgressWarmupSuppressesEarlyAlerts(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.EgressZWarn = 2
		c.Tunables.EgressZHigh = 4
		c.EgressWarmup = 10
		c.EgressMinVolume = 1
	})
	// A huge very first transfer must not trigger: the baseline is not warmed up.
	a := e.Observe(Observation{
		Tenant: "acme", Identity: "id", Package: "big", Bytes: 1 << 30, Time: baseTime,
	})
	if detectorResult(t, a, DetectorEgress).Triggered {
		t.Fatalf("egress must stay silent before warmup")
	}
}

func TestSoftBlockGateAndStatus(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.EnumerationWarn = 5
		c.Tunables.EnumerationHigh = 10
		c.BlockLevel = LevelHigh
	})

	// Cold scope is nominal.
	if st := e.Status("acme", "id"); st.Action != ActionObserve || st.Level != LevelNone {
		t.Fatalf("cold scope should be observe/none, got %+v", st)
	}

	var last Assessment
	for i := 0; i < 12; i++ {
		last = e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: fmt.Sprintf("g%d", i),
			NotFound: true, Time: baseTime.Add(time.Duration(i) * time.Second),
		})
	}
	if last.Action != ActionBlock {
		t.Fatalf("expected block action at high level, got %q (level=%q)", last.Action, last.Level)
	}
	// The gate reads Status: the scope is now in a block standing.
	st := e.Status("acme", "id")
	if st.Action != ActionBlock {
		t.Fatalf("expected Status to report block, got %q", st.Action)
	}
}

func TestBlockDisabledByDefault(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.EnumerationWarn = 5
		c.Tunables.EnumerationHigh = 10
		// BlockLevel left empty → soft-blocking disabled.
	})
	var last Assessment
	for i := 0; i < 15; i++ {
		last = e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: fmt.Sprintf("g%d", i),
			NotFound: true, Time: baseTime.Add(time.Duration(i) * time.Second),
		})
	}
	if last.Level != LevelHigh {
		t.Fatalf("expected high level, got %q", last.Level)
	}
	if last.Action == ActionBlock {
		t.Fatalf("block must be disabled when BlockLevel is empty, got %q", last.Action)
	}
	if last.Action != ActionWarn {
		t.Fatalf("expected warn action (warn default at medium), got %q", last.Action)
	}
}

func TestAlertCooldownAndEscalation(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.EnumerationWarn = 5
		c.Tunables.EnumerationHigh = 10
		c.AlertCooldown = 30 * time.Minute
		c.WarnLevel = LevelMedium
	})

	alerts := 0
	// Drive to medium first (5..9 negative lookups), then to high (>=10).
	for i := 0; i < 12; i++ {
		a := e.Observe(Observation{
			Tenant: "acme", Identity: "id", Package: fmt.Sprintf("g%d", i),
			NotFound: true, Time: baseTime.Add(time.Duration(i) * time.Second),
		})
		if a.Alert {
			alerts++
		}
	}
	// Expect exactly two alerts within the cooldown: the first warn (medium) and
	// the escalation to high. Subsequent same-level assessments are suppressed.
	if alerts != 2 {
		t.Fatalf("expected 2 alerts (medium then high escalation), got %d", alerts)
	}

	snap := e.Snapshot()
	if snap.Alerts != 2 {
		t.Fatalf("snapshot alerts = %d, want 2", snap.Alerts)
	}
	if len(snap.Recent) != 2 {
		t.Fatalf("expected 2 recorded triggers, got %d", len(snap.Recent))
	}
	// Most-recent first: the high escalation should head the list.
	if snap.Recent[0].Level != LevelHigh {
		t.Fatalf("expected most-recent trigger to be high, got %q", snap.Recent[0].Level)
	}
}

func TestScopeIsolation(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.FanoutWarn = 5
		c.Tunables.FanoutHigh = 10
	})
	// One identity sweeps many packages; a second identity in the same tenant
	// stays quiet and must remain nominal.
	for i := 0; i < 12; i++ {
		e.Observe(Observation{Tenant: "acme", Identity: "attacker", Package: fmt.Sprintf("p%d", i),
			Time: baseTime.Add(time.Duration(i) * time.Second)})
	}
	quiet := e.Observe(Observation{Tenant: "acme", Identity: "honest", Package: "left-pad",
		Time: baseTime.Add(20 * time.Second)})
	if quiet.Level != LevelNone {
		t.Fatalf("second identity must be unaffected, got level=%q", quiet.Level)
	}
	if st := e.Status("acme", "attacker"); st.Level != LevelHigh {
		t.Fatalf("attacker scope should be high, got %q", st.Level)
	}
}

func TestSnapshotCountersAndOrdering(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.Tunables.FanoutWarn = 5
		c.Tunables.FanoutHigh = 10
	})
	// Two scopes with different intensities so Snapshot ordering (strongest
	// first) is observable.
	for i := 0; i < 12; i++ {
		e.Observe(Observation{Tenant: "t", Identity: "hot", Package: fmt.Sprintf("p%d", i),
			Time: baseTime.Add(time.Duration(i) * time.Second)})
	}
	for i := 0; i < 6; i++ {
		e.Observe(Observation{Tenant: "t", Identity: "warm", Package: fmt.Sprintf("q%d", i),
			Time: baseTime.Add(time.Duration(i) * time.Second)})
	}
	snap := e.Snapshot()
	if snap.Observed != 18 {
		t.Fatalf("observed = %d, want 18", snap.Observed)
	}
	if snap.TrackedScopes != 2 {
		t.Fatalf("tracked scopes = %d, want 2", snap.TrackedScopes)
	}
	if len(snap.Scopes) != 2 || snap.Scopes[0].Score < snap.Scopes[1].Score {
		t.Fatalf("scopes should be strongest-first, got %+v", snap.Scopes)
	}
	if snap.TriggersByType[string(DetectorFanout)] == 0 {
		t.Fatalf("expected fanout triggers recorded")
	}
}

func TestScopeEvictionByTTL(t *testing.T) {
	e := newTestEngine(t, func(c *Config) {
		c.Tunables = DefaultTunables()
		c.ScopeTTL = 5 * time.Minute
	})
	e.Observe(Observation{Tenant: "t", Identity: "old", Package: "p", Time: baseTime})
	// A much later observation from a different scope evicts the idle one.
	e.Observe(Observation{Tenant: "t", Identity: "new", Package: "p", Time: baseTime.Add(time.Hour)})
	snap := e.Snapshot()
	if snap.TrackedScopes != 1 {
		t.Fatalf("expected stale scope evicted, tracked=%d", snap.TrackedScopes)
	}
	if snap.Scopes[0].Identity != "new" {
		t.Fatalf("expected surviving scope to be 'new', got %q", snap.Scopes[0].Identity)
	}
}

func TestDisabledEngineIsInert(t *testing.T) {
	e, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.Enabled() {
		t.Fatalf("engine should report disabled")
	}
	a := e.Observe(Observation{Tenant: "t", Identity: "id", Package: "p", Time: baseTime})
	if a.Action != ActionObserve || a.Level != LevelNone {
		t.Fatalf("disabled engine should produce an inert assessment, got %+v", a)
	}
	if snap := e.Snapshot(); snap.Observed != 0 {
		t.Fatalf("disabled engine should not record observations, got %d", snap.Observed)
	}
}

func TestDeterministicReplay(t *testing.T) {
	build := func() *Engine {
		return newTestEngine(t, func(c *Config) {
			c.Tunables = DefaultTunables()
			c.Tunables.FanoutWarn = 5
			c.Tunables.FanoutHigh = 10
			c.EgressWarmup = 4
			c.EgressMinVolume = 1
		})
	}
	run := func(e *Engine) []float64 {
		var scores []float64
		for i := 0; i < 30; i++ {
			a := e.Observe(Observation{
				Tenant: "t", Identity: "id", Package: fmt.Sprintf("p%d", i%9),
				Namespace: fmt.Sprintf("ns%d", i%4), Bytes: int64(1000 * (i%5 + 1)),
				NotFound: i%7 == 0, Time: baseTime.Add(time.Duration(i) * time.Second),
			})
			scores = append(scores, a.Score)
		}
		return scores
	}
	a, b := run(build()), run(build())
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic score at %d: %v vs %v", i, a[i], b[i])
		}
	}
}

func TestConcurrentObserveIsSafe(t *testing.T) {
	e := newTestEngine(t, func(c *Config) { c.Tunables = DefaultTunables() })
	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				e.Observe(Observation{
					Tenant:   "t",
					Identity: fmt.Sprintf("id-%d", w),
					Package:  fmt.Sprintf("p-%d", i),
					Bytes:    int64(i),
					NotFound: i%3 == 0,
					Time:     baseTime.Add(time.Duration(i) * time.Millisecond),
				})
				_ = e.Status("t", fmt.Sprintf("id-%d", w))
				_ = e.Snapshot()
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
	if snap := e.Snapshot(); snap.Observed != 8*200 {
		t.Fatalf("observed = %d, want %d", snap.Observed, 8*200)
	}
}

// detectorResult extracts a named detector's result from an assessment.
func detectorResult(t *testing.T, a Assessment, k DetectorKind) DetectorResult {
	t.Helper()
	for _, d := range a.Detectors {
		if d.Detector == k {
			return d
		}
	}
	t.Fatalf("detector %q absent from assessment", k)
	return DetectorResult{}
}
