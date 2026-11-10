package depfirewall

import (
	"testing"
)

func mustService(t *testing.T, cfg Config) *Service {
	t.Helper()
	s, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

func TestCheckPinned(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{{Ecosystem: "npm", Name: "left-pad", Pinned: []string{"1.3.0"}}},
	})

	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}); d.Blocked {
		t.Fatalf("pinned exact version should be allowed: %+v", d)
	}
	d := s.Check("", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.4.0"})
	if !d.Blocked || d.Code != codeNotPinned {
		t.Fatalf("off-pin version should be blocked not-pinned, got %+v", d)
	}
	// Leading-v normalization.
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "v1.3.0"}); d.Blocked {
		t.Fatalf("v-prefixed pinned version should match: %+v", d)
	}
}

func TestCheckRanges(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{{Ecosystem: "pip", Name: "requests", Ranges: []string{">=2.20.0 <3.0.0"}}},
	})
	cases := []struct {
		ver     string
		blocked bool
	}{
		{"2.20.0", false},
		{"2.31.0", false},
		{"2.19.9", true},
		{"3.0.0", true},
	}
	for _, c := range cases {
		d := s.Check("", Coordinate{Ecosystem: "pip", Name: "requests", Version: c.ver})
		if d.Blocked != c.blocked {
			t.Errorf("requests %s: blocked=%v want %v (%s)", c.ver, d.Blocked, c.blocked, d.Reason)
		}
	}
}

func TestCheckCaretAndTilde(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{
			{Ecosystem: "npm", Name: "a", Ranges: []string{"^1.2.3"}},
			{Ecosystem: "npm", Name: "b", Ranges: []string{"~1.2.3"}},
			{Ecosystem: "npm", Name: "c", Ranges: []string{"^0.2.3"}},
		},
	})
	check := func(name, ver string) bool {
		return s.Check("", Coordinate{Ecosystem: "npm", Name: name, Version: ver}).Blocked
	}
	// ^1.2.3 => >=1.2.3 <2.0.0
	if check("a", "1.9.9") {
		t.Error("^1.2.3 should allow 1.9.9")
	}
	if !check("a", "2.0.0") {
		t.Error("^1.2.3 should block 2.0.0")
	}
	if !check("a", "1.2.2") {
		t.Error("^1.2.3 should block 1.2.2")
	}
	// ~1.2.3 => >=1.2.3 <1.3.0
	if check("b", "1.2.9") {
		t.Error("~1.2.3 should allow 1.2.9")
	}
	if !check("b", "1.3.0") {
		t.Error("~1.2.3 should block 1.3.0")
	}
	// ^0.2.3 => >=0.2.3 <0.3.0
	if check("c", "0.2.9") {
		t.Error("^0.2.3 should allow 0.2.9")
	}
	if !check("c", "0.3.0") {
		t.Error("^0.2.3 should block 0.3.0")
	}
}

func TestCheckMinVersionFloor(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{{Ecosystem: "go", Name: "golang.org/x/crypto", MinVersion: "v0.17.0"}},
	})
	if d := s.Check("", Coordinate{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "v0.16.0"}); !d.Blocked || d.Code != codeBelowFloor {
		t.Fatalf("below-floor version should be blocked, got %+v", d)
	}
	if d := s.Check("", Coordinate{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "v0.17.0"}); d.Blocked {
		t.Fatalf("at-floor version should be allowed, got %+v", d)
	}
	if d := s.Check("", Coordinate{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "v0.20.0"}); d.Blocked {
		t.Fatalf("above-floor version should be allowed, got %+v", d)
	}
}

func TestCheckDenylist(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{{
			Ecosystem: "npm", Name: "event-stream",
			Ranges: []string{"*"},
			Denied: []string{"3.3.6"},
		}},
	})
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}); !d.Blocked || d.Code != codeDenied {
		t.Fatalf("denied version must block even with a satisfying range, got %+v", d)
	}
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "event-stream", Version: "3.3.5"}); d.Blocked {
		t.Fatalf("non-denied version should be allowed, got %+v", d)
	}
}

func TestDefaultActionBlock(t *testing.T) {
	s := mustService(t, Config{
		DefaultAction: ActionBlock,
		Rules:         []Rule{{Ecosystem: "npm", Name: "approved", Pinned: []string{"1.0.0"}}},
	})
	// Governed coordinate passes.
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "approved", Version: "1.0.0"}); d.Blocked {
		t.Fatalf("approved pinned coordinate should pass in deny-by-default, got %+v", d)
	}
	// Ungoverned coordinate is denied by default.
	d := s.Check("", Coordinate{Ecosystem: "npm", Name: "random", Version: "9.9.9"})
	if !d.Blocked || d.Code != codeDefaultBlock {
		t.Fatalf("ungoverned coordinate should be denied by default, got %+v", d)
	}
	// Listing requests (no version) always pass.
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "random"}); d.Blocked {
		t.Fatalf("version-less request must never block, got %+v", d)
	}
}

func TestTenantOverridesGlobal(t *testing.T) {
	s := mustService(t, Config{
		DefaultAction: ActionAllow,
		Rules:         []Rule{{Ecosystem: "npm", Name: "lodash", Pinned: []string{"4.17.21"}}},
		Tenants: map[string]TenantConfig{
			"team-a": {Rules: []Rule{{Ecosystem: "npm", Name: "lodash", Pinned: []string{"4.17.20"}}}},
		},
	})
	// Global rule pins 4.17.21.
	if d := s.Check("other", Coordinate{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}); d.Blocked {
		t.Fatalf("global pin should allow 4.17.21 for other tenant, got %+v", d)
	}
	// Tenant override pins 4.17.20, so 4.17.21 is blocked for team-a.
	if d := s.Check("team-a", Coordinate{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}); !d.Blocked {
		t.Fatalf("tenant override should block 4.17.21 for team-a, got %+v", d)
	}
	if d := s.Check("team-a", Coordinate{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}); d.Blocked {
		t.Fatalf("tenant override should allow 4.17.20 for team-a, got %+v", d)
	}
}

func TestTenantDefaultActionOverride(t *testing.T) {
	s := mustService(t, Config{
		DefaultAction: ActionAllow,
		Tenants: map[string]TenantConfig{
			"strict": {DefaultAction: ActionBlock},
		},
	})
	if d := s.Check("loose", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); d.Blocked {
		t.Fatalf("global allow should pass for non-strict tenant, got %+v", d)
	}
	if d := s.Check("strict", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); !d.Blocked {
		t.Fatalf("strict tenant default-block should refuse ungoverned coordinate, got %+v", d)
	}
}

func TestRuntimeMutation(t *testing.T) {
	s := mustService(t, Config{})
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "2.0.0"}); d.Blocked {
		t.Fatalf("default-allow with no rules should pass, got %+v", d)
	}
	if err := s.SetRule("", Rule{Ecosystem: "npm", Name: "x", Pinned: []string{"1.0.0"}}); err != nil {
		t.Fatalf("SetRule: %v", err)
	}
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "2.0.0"}); !d.Blocked {
		t.Fatalf("after SetRule, off-pin version should block, got %+v", d)
	}
	if !s.DeleteRule("", "npm", "x") {
		t.Fatalf("DeleteRule should report a removal")
	}
	if d := s.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "2.0.0"}); d.Blocked {
		t.Fatalf("after DeleteRule, version should pass again, got %+v", d)
	}
}

func TestInvalidRangeRejected(t *testing.T) {
	if _, err := NewService(Config{Rules: []Rule{{Ecosystem: "npm", Name: "x", Ranges: []string{">=not-a-version"}}}}); err == nil {
		t.Fatalf("expected an error for a malformed range")
	}
	s := mustService(t, Config{})
	if err := s.SetRule("", Rule{Ecosystem: "npm", Name: "x", Ranges: []string{"<<<"}}); err == nil {
		t.Fatalf("SetRule should reject a malformed range")
	}
}

func TestMetricsTally(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{{Ecosystem: "npm", Name: "x", Pinned: []string{"1.0.0"}}},
	})
	s.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}) // allow
	s.Check("", Coordinate{Ecosystem: "npm", Name: "x", Version: "2.0.0"}) // block
	snap := s.Metrics()
	if snap.Checks != 2 || snap.Blocks != 1 || snap.Allowed != 1 {
		t.Fatalf("unexpected tallies: %+v", snap)
	}
	if snap.BlocksByEco["npm"] != 1 {
		t.Fatalf("expected 1 npm block, got %+v", snap.BlocksByEco)
	}
	if snap.BlocksByCode[codeNotPinned] != 1 {
		t.Fatalf("expected not-pinned block code tally, got %+v", snap.BlocksByCode)
	}
}

func TestConcurrentCheckAndMutate(t *testing.T) {
	s := mustService(t, Config{
		Rules: []Rule{{Ecosystem: "npm", Name: "x", Pinned: []string{"1.0.0"}}},
	})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			s.Check("t", Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
			s.Check("t", Coordinate{Ecosystem: "npm", Name: "x", Version: "2.0.0"})
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		_ = s.SetRule("t", Rule{Ecosystem: "npm", Name: "x", Ranges: []string{"^1.0.0"}})
		_ = s.Status()
		_ = s.Rules("*")
	}
	<-done
}

func TestNilServiceIsNoOp(t *testing.T) {
	var s *Service
	if d := s.Check("t", Coordinate{Ecosystem: "npm", Name: "x", Version: "1"}); d.Blocked {
		t.Fatalf("nil service must admit everything")
	}
	if s.Enabled() {
		t.Fatalf("nil service must report disabled")
	}
}
