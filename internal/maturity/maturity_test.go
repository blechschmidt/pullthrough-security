package maturity

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock returns a deterministic, mutable clock for tests.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time { return c.t }

// stubResolver returns canned timestamps keyed by version, counting calls so a
// test can assert the bounded cache prevented re-resolution.
type stubResolver struct {
	times map[string]time.Time
	calls atomic.Int64
}

func (s *stubResolver) PublishedAt(_ context.Context, c Coordinate) (time.Time, bool, error) {
	s.calls.Add(1)
	t, ok := s.times[c.Version]
	return t, ok, nil
}

func newTestService(t *testing.T, cfg Config, clk *fixedClock) *Service {
	t.Helper()
	cfg.Now = clk.now
	return NewService(cfg)
}

func TestCheck_BlocksNewAdmitsAged(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{
		"1.0.0": clk.t.Add(-2 * time.Hour),  // published 2h ago
		"2.0.0": clk.t.Add(-10 * time.Hour), // published 10h ago
	}}
	svc := newTestService(t, Config{
		DefaultCooldown: 7 * 24 * time.Hour, // 7 days
		Ecosystems:      map[string]time.Duration{"npm": 6 * time.Hour},
		Resolver:        res,
	}, clk)

	// 2h-old version under a 6h npm cooldown → cooling.
	d := svc.Check("", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"})
	if !d.Cooling {
		t.Fatalf("expected 1.0.0 to be cooling, got %+v", d)
	}
	if d.Remaining <= 0 || d.Remaining > 4*time.Hour {
		t.Fatalf("unexpected remaining %s", d.Remaining)
	}

	// 10h-old version under the 6h npm cooldown → admitted.
	d = svc.Check("", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"})
	if d.Cooling {
		t.Fatalf("expected 2.0.0 to be admitted, got %+v", d)
	}
}

func TestCheck_CacheResolvesOnce(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{"1.0.0": clk.t.Add(-1 * time.Hour)}}
	svc := newTestService(t, Config{DefaultCooldown: 24 * time.Hour, Resolver: res}, clk)

	for i := 0; i < 5; i++ {
		svc.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	}
	if got := res.calls.Load(); got != 1 {
		t.Fatalf("expected resolver to be called once (cached), got %d", got)
	}
}

func TestCheck_AdmitsAfterAgingPastCooldown(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	pub := clk.t.Add(-1 * time.Hour)
	res := &stubResolver{times: map[string]time.Time{"1.0.0": pub}}
	svc := newTestService(t, Config{DefaultCooldown: 2 * time.Hour, Resolver: res, CacheTTL: time.Minute}, clk)

	if d := svc.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); !d.Cooling {
		t.Fatalf("expected cooling at t0, got %+v", d)
	}
	// Advance the clock past the cooldown window and the cache TTL.
	clk.t = clk.t.Add(90 * time.Minute)
	if d := svc.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); d.Cooling {
		t.Fatalf("expected admitted after aging past cooldown, got %+v", d)
	}
	// The matured coordinate must be cleared from the cooling registry.
	if n := svc.Metrics().CoolingNow; n != 0 {
		t.Fatalf("expected 0 cooling after maturation, got %d", n)
	}
}

func TestCheck_UnknownTimestamp_FailOpenAndClosed(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{}} // never knows a timestamp

	open := newTestService(t, Config{DefaultCooldown: time.Hour, Resolver: res}, clk)
	if d := open.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "9.9.9"}); d.Cooling || !d.Unknown {
		t.Fatalf("fail-open: expected admitted+unknown, got %+v", d)
	}

	closed := newTestService(t, Config{DefaultCooldown: time.Hour, FailClosedOnUnknown: true, Resolver: res}, clk)
	if d := closed.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "9.9.9"}); !d.Cooling || !d.Unknown {
		t.Fatalf("fail-closed: expected blocked+unknown, got %+v", d)
	}
}

func TestCheck_AllowlistBypass(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{"1.0.0": clk.t.Add(-time.Minute)}}
	svc := newTestService(t, Config{
		DefaultCooldown: 24 * time.Hour,
		Allowlist:       []string{"@acme/", "npm:trusted-pkg", "internal-*", "exactname"},
		Resolver:        res,
	}, clk)

	cases := []struct {
		eco, name string
		bypass    bool
	}{
		{"npm", "@acme/widget", true},   // scope prefix
		{"npm", "trusted-pkg", true},    // eco:name exact
		{"pip", "trusted-pkg", false},   // wrong ecosystem for eco:name
		{"npm", "internal-tools", true}, // glob prefix
		{"npm", "exactname", true},      // bare exact
		{"npm", "untrusted", false},     // not listed
	}
	for _, c := range cases {
		d := svc.Check("", Coordinate{Ecosystem: c.eco, Name: c.name, Version: "1.0.0"})
		if d.Allowlisted != c.bypass {
			t.Fatalf("%s/%s: allowlisted=%v want %v (%+v)", c.eco, c.name, d.Allowlisted, c.bypass, d)
		}
		if c.bypass && d.Cooling {
			t.Fatalf("%s/%s: allowlisted coordinate must not be cooling", c.eco, c.name)
		}
	}
}

func TestCooldownFor_Precedence(t *testing.T) {
	day := 24 * time.Hour
	tenantDefault := 12 * time.Hour
	svc := NewService(Config{
		DefaultCooldown: 7 * day,
		Ecosystems:      map[string]time.Duration{"npm": 2 * day, "pip": 0}, // pip explicitly disabled globally
		Tenants: map[string]TenantConfig{
			"team-a": {
				DefaultCooldown: &tenantDefault,
				Ecosystems:      map[string]time.Duration{"npm": time.Hour},
			},
		},
	})

	tests := []struct {
		tenant, eco string
		want        time.Duration
	}{
		{"team-a", "npm", time.Hour},        // tenant eco override (most specific)
		{"team-a", "cargo", 12 * time.Hour}, // tenant default (no eco override)
		{"team-a", "pip", 0},                // global eco override beats tenant default
		{"", "npm", 2 * day},                // global eco override
		{"", "cargo", 7 * day},              // global default
		{"other", "npm", 2 * day},           // unknown tenant → global rules
	}
	for _, tc := range tests {
		if got := svc.cooldownFor(tc.tenant, tc.eco); got != tc.want {
			t.Fatalf("cooldownFor(%q,%q)=%s want %s", tc.tenant, tc.eco, got, tc.want)
		}
	}
}

func TestCheck_PerTenantOverride(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{"1.0.0": clk.t.Add(-3 * time.Hour)}}
	short := 1 * time.Hour
	svc := newTestService(t, Config{
		DefaultCooldown: 24 * time.Hour,
		Tenants:         map[string]TenantConfig{"fast": {DefaultCooldown: &short}},
		Resolver:        res,
	}, clk)

	// 3h-old version: blocked under the 24h default, admitted for tenant "fast" (1h).
	if d := svc.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); !d.Cooling {
		t.Fatalf("default tenant should block, got %+v", d)
	}
	if d := svc.Check("fast", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); d.Cooling {
		t.Fatalf("fast tenant should admit, got %+v", d)
	}
}

func TestCheck_DisabledScopesAndListings(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{"1.0.0": clk.t}}

	// Zero default cooldown → gate inert.
	off := newTestService(t, Config{DefaultCooldown: 0, Resolver: res}, clk)
	if d := off.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); d.Cooling {
		t.Fatalf("zero cooldown must admit, got %+v", d)
	}
	if res.calls.Load() != 0 {
		t.Fatalf("disabled scope must not resolve a timestamp")
	}

	// Version-less (index/listing) request → always admitted, never resolved.
	on := newTestService(t, Config{DefaultCooldown: time.Hour, Resolver: res}, clk)
	if d := on.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: ""}); d.Cooling {
		t.Fatalf("listing request must admit, got %+v", d)
	}
	if res.calls.Load() != 0 {
		t.Fatalf("listing request must not resolve a timestamp")
	}
}

func TestMetricsAndCoolingView(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{
		"1.0.0": clk.t.Add(-time.Hour),
		"2.0.0": clk.t.Add(-30 * time.Minute),
	}}
	svc := newTestService(t, Config{DefaultCooldown: 24 * time.Hour, Resolver: res}, clk)

	svc.Check("t1", Coordinate{Ecosystem: "npm", Name: "a", Version: "1.0.0"})
	svc.Check("t1", Coordinate{Ecosystem: "pip", Name: "b", Version: "2.0.0"})

	snap := svc.Metrics()
	if snap.Checks != 2 || snap.Blocks != 2 {
		t.Fatalf("unexpected counters: %+v", snap)
	}
	if snap.CoolingNow != 2 {
		t.Fatalf("expected 2 cooling, got %d", snap.CoolingNow)
	}
	if snap.BlocksByEco["npm"] != 1 || snap.BlocksByEco["pip"] != 1 {
		t.Fatalf("unexpected per-eco blocks: %+v", snap.BlocksByEco)
	}

	cooling := svc.Cooling(0)
	if len(cooling) != 2 {
		t.Fatalf("expected 2 cooling views, got %d", len(cooling))
	}
	// Ordered by ascending remaining: the 30m-old (longer remaining) comes after
	// the 1h-old one under the same 24h cooldown.
	if cooling[0].RemainingSeconds > cooling[1].RemainingSeconds {
		t.Fatalf("cooling not sorted by remaining: %+v", cooling)
	}
	st := svc.Status()
	if !st.Enabled || st.CoolingNow != 2 || st.Blocks != 2 {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestCheck_FutureTimestampTreatedAsFresh(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	res := &stubResolver{times: map[string]time.Time{"1.0.0": clk.t.Add(time.Hour)}} // future
	svc := newTestService(t, Config{DefaultCooldown: 2 * time.Hour, Resolver: res}, clk)
	d := svc.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if !d.Cooling || d.Age != 0 {
		t.Fatalf("future timestamp should be treated as freshly published, got %+v", d)
	}
}

func TestNilServiceIsNoOp(t *testing.T) {
	var svc *Service
	if d := svc.Check("t", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); d.Cooling {
		t.Fatalf("nil service must admit")
	}
	if svc.Metrics().Checks != 0 || svc.Cooling(0) != nil || svc.Status().Enabled {
		t.Fatalf("nil service surfaces must be empty")
	}
}
