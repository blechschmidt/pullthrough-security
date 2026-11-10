package anomaly

import (
	"testing"
	"time"
)

func TestRollingWindowPrunes(t *testing.T) {
	var w rollingWindow
	now := baseTime
	window := 10 * time.Second
	for i := 0; i < 5; i++ {
		w.add(now.Add(time.Duration(i)*time.Second), now.Add(time.Duration(i)*time.Second), window)
	}
	if got := w.count(baseTime.Add(4*time.Second), window); got != 5 {
		t.Fatalf("count within window = %d, want 5", got)
	}
	// Far in the future: everything has expired.
	if got := w.count(baseTime.Add(time.Minute), window); got != 0 {
		t.Fatalf("count after expiry = %d, want 0", got)
	}
}

func TestDistinctWindowDedup(t *testing.T) {
	var d distinctWindow
	now := baseTime
	window := time.Minute
	d.add("a", now, now, window)
	d.add("a", now.Add(time.Second), now.Add(time.Second), window)
	d.add("b", now.Add(2*time.Second), now.Add(2*time.Second), window)
	if got := d.count(now.Add(2*time.Second), window); got != 2 {
		t.Fatalf("distinct count = %d, want 2", got)
	}
}

func TestByteWindowSum(t *testing.T) {
	var b byteWindow
	now := baseTime
	window := 10 * time.Second
	b.add(100, now, now, window)
	b.add(200, now.Add(time.Second), now.Add(time.Second), window)
	if b.sum != 300 {
		t.Fatalf("sum = %d, want 300", b.sum)
	}
	// Advance past the window: the sum drains back to zero.
	got := b.add(50, now.Add(time.Minute), now.Add(time.Minute), window)
	if got != 50 {
		t.Fatalf("sum after expiry = %d, want 50", got)
	}
}

func TestBaselineZScore(t *testing.T) {
	b := newBaseline(0.3)
	for i := 0; i < 20; i++ {
		b.update(100)
	}
	if !b.ready(10) {
		t.Fatalf("baseline should be ready")
	}
	// A value equal to the mean has z≈0; a large value has a large z.
	if z := b.zscore(100, 1); z > 1 || z < -1 {
		t.Fatalf("z for mean value = %v, want near 0", z)
	}
	if z := b.zscore(10000, 1); z <= 0 {
		t.Fatalf("z for large value = %v, want positive", z)
	}
}

func TestRampEval(t *testing.T) {
	r := ramp{warn: 10, high: 20}
	cases := []struct {
		v     float64
		level Level
	}{
		{0, LevelNone},
		{3, LevelNone}, // below warn/2
		{6, LevelLow},  // [warn/2, warn)
		{10, LevelMedium},
		{15, LevelMedium},
		{20, LevelHigh},
		{40, LevelHigh},
	}
	for _, tc := range cases {
		score, lvl := r.eval(tc.v)
		if lvl != tc.level {
			t.Fatalf("eval(%v) level = %q, want %q (score=%v)", tc.v, lvl, tc.level, score)
		}
		if score < 0 || score > 1 {
			t.Fatalf("eval(%v) score out of range: %v", tc.v, score)
		}
	}
	// Monotonicity: score must not decrease as the value rises.
	prev := -1.0
	for v := 0.0; v <= 25; v += 0.5 {
		s, _ := r.eval(v)
		if s < prev {
			t.Fatalf("score decreased at v=%v: %v < %v", v, s, prev)
		}
		prev = s
	}
}
