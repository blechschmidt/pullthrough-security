package reposcore

import "testing"

func TestConfigDefaultsAndValidation(t *testing.T) {
	c := Config{Enabled: true}.withDefaults()
	if c.Weights.isZero() {
		t.Error("expected default weights to be applied")
	}
	if c.Window != defaultWindow || c.CacheTTL != defaultCacheTTL || c.HistorySize != defaultHistorySize {
		t.Errorf("expected defaults to be filled, got %+v", c)
	}
	if err := c.validate(); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestValidateWeightsRejectsNegativeAndEmpty(t *testing.T) {
	if err := validateWeights(Weights{CI: -1}); err == nil {
		t.Error("expected negative weight to be rejected")
	}
	if err := validateWeights(Weights{}); err == nil {
		t.Error("expected all-zero weights to be rejected")
	}
}

func TestResolveWeightsTenantOverride(t *testing.T) {
	custom := Weights{SignedCommits: 1}
	c := Config{
		Weights:         DefaultWeights(),
		TenantOverrides: map[string]TenantOverride{"t1": {Weights: &custom}},
	}
	if got := c.resolveWeights("t1"); got != custom {
		t.Errorf("expected tenant override, got %+v", got)
	}
	if got := c.resolveWeights("other"); got != c.Weights {
		t.Errorf("expected global weights for unknown tenant, got %+v", got)
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/Acme/Widget.git": "github.com/acme/widget",
		"https://github.com/acme/widget/":    "github.com/acme/widget",
		"git@github.com:acme/widget.git":     "github.com/acme/widget",
		"git+https://gitlab.com/g/p":         "gitlab.com/g/p",
		"":                                   "",
	}
	for in, want := range cases {
		if got := normalizeRepoURL(in); got != want {
			t.Errorf("normalizeRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBusFactor(t *testing.T) {
	// One author dominating → bus factor 1.
	if got := busFactor(map[string]int{"a": 9, "b": 1}, 10); got != 1 {
		t.Errorf("expected bus factor 1, got %d", got)
	}
	// Even spread across 4 → need 3 to exceed half.
	if got := busFactor(map[string]int{"a": 1, "b": 1, "c": 1, "d": 1}, 4); got != 3 {
		t.Errorf("expected bus factor 3, got %d", got)
	}
	if got := busFactor(nil, 0); got != 0 {
		t.Errorf("expected bus factor 0 for empty history, got %d", got)
	}
}
