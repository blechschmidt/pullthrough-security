package config

import "testing"

func TestSecretScanConfigValidate(t *testing.T) {
	enabled := true
	disabled := false

	t.Run("valid rule", func(t *testing.T) {
		c := SecretScanConfig{
			Rules: []SecretRuleConfig{{ID: "x", Pattern: `\bAKIA[A-Z0-9]{16}\b`, Severity: "high"}},
		}
		if err := c.validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid pattern rejected", func(t *testing.T) {
		c := SecretScanConfig{Rules: []SecretRuleConfig{{ID: "x", Pattern: "(unbalanced"}}}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for invalid pattern")
		}
	})

	t.Run("missing id rejected", func(t *testing.T) {
		c := SecretScanConfig{Rules: []SecretRuleConfig{{Pattern: "a"}}}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for missing id")
		}
	})

	t.Run("duplicate id rejected", func(t *testing.T) {
		c := SecretScanConfig{Rules: []SecretRuleConfig{
			{ID: "dup", Pattern: "a"}, {ID: "dup", Pattern: "b"},
		}}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for duplicate id")
		}
	})

	t.Run("invalid severity rejected", func(t *testing.T) {
		c := SecretScanConfig{Entropy: SecretEntropyConfig{Severity: "extreme"}}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for invalid entropy severity")
		}
	})

	t.Run("invalid allowlist regex rejected", func(t *testing.T) {
		c := SecretScanConfig{Allowlist: SecretAllowlistConfig{Paths: []string{"(bad"}}}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for invalid allowlist path regex")
		}
	})

	t.Run("disabled skips validation", func(t *testing.T) {
		c := SecretScanConfig{Enabled: &disabled, Rules: []SecretRuleConfig{{ID: "x", Pattern: "(bad"}}}
		if err := c.validate(); err != nil {
			t.Fatalf("disabled config must skip validation, got %v", err)
		}
	})

	t.Run("explicitly enabled validates", func(t *testing.T) {
		c := SecretScanConfig{Enabled: &enabled, Rules: []SecretRuleConfig{{ID: "x", Pattern: "(bad"}}}
		if err := c.validate(); err == nil {
			t.Fatal("expected validation when explicitly enabled")
		}
	})
}
