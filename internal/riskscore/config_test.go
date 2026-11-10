package riskscore

import "testing"

func TestConfigDefaultsApplied(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.Weights.isZero() {
		t.Error("expected default weights")
	}
	if cfg.Bands != DefaultBands() {
		t.Errorf("expected default bands, got %+v", cfg.Bands)
	}
	if cfg.Threshold.Action != ThresholdOff {
		t.Errorf("expected default threshold off, got %s", cfg.Threshold.Action)
	}
	if cfg.HistorySize != defaultHistorySize {
		t.Errorf("expected default history size, got %d", cfg.HistorySize)
	}
	if cfg.Now == nil {
		t.Error("expected default clock")
	}
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"defaults", Config{}, true},
		{"negative weight", Config{Weights: Weights{Vulnerability: -1}}, false},
		{"all-zero weights treated as default", Config{Weights: Weights{}}, true},
		{"non-monotonic bands", Config{Bands: BandThresholds{Medium: 60, High: 50, Critical: 70}}, false},
		{"band over 100", Config{Bands: BandThresholds{Medium: 25, High: 50, Critical: 120}}, false},
		{"bad action", Config{Threshold: Threshold{Band: BandHigh, Action: "nuke"}}, false},
		{"bad band", Config{Threshold: Threshold{Band: "severe", Action: ThresholdWarn}}, false},
		{"bad tenant weight", Config{TenantOverrides: map[string]TenantOverride{"t": {Weights: &Weights{Secret: -2}}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if tc.ok && err != nil {
				t.Fatalf("expected valid config, got error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestBandForBoundaries(t *testing.T) {
	b := DefaultBands() // 25/50/75
	cases := []struct {
		score int
		want  Band
	}{
		{0, BandLow}, {24, BandLow}, {25, BandMedium}, {49, BandMedium},
		{50, BandHigh}, {74, BandHigh}, {75, BandCritical}, {100, BandCritical},
	}
	for _, tc := range cases {
		if got := b.bandFor(tc.score); got != tc.want {
			t.Errorf("bandFor(%d) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestResolveTenantIndependentParts(t *testing.T) {
	cfg := Config{
		Weights:   Weights{Vulnerability: 1},
		Threshold: Threshold{Band: BandHigh, Action: ThresholdOff},
		TenantOverrides: map[string]TenantOverride{
			// Override only the threshold action; weights/bands inherit globals.
			"t": {Threshold: &Threshold{Action: ThresholdBlock}},
		},
	}.withDefaults()
	r := cfg.resolve("t")
	if r.threshold.Action != ThresholdBlock {
		t.Errorf("tenant threshold action not applied: %s", r.threshold.Action)
	}
	if r.threshold.Band != BandHigh {
		t.Errorf("tenant should inherit global band, got %s", r.threshold.Band)
	}
	if r.weights.Vulnerability != 1 {
		t.Errorf("tenant should inherit global weights, got %+v", r.weights)
	}
}
