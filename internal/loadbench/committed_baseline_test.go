package loadbench

import "testing"

// TestCommittedBaselineDecodes guards the repo's perf/perf-baseline.json against
// drift that would make the perfguard CI gate fail to load it.
func TestCommittedBaselineDecodes(t *testing.T) {
	b, err := LoadBaseline("../../perf/perf-baseline.json")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	cr, ok := b.Scenarios["conn-reuse"]
	if !ok {
		t.Fatal("committed baseline missing the conn-reuse scenario")
	}
	if cr.ConnReuseRatio <= 0 || cr.ConnReuseRatio > 1 {
		t.Fatalf("conn-reuse connReuseRatio = %v, want in (0,1]", cr.ConnReuseRatio)
	}
}
