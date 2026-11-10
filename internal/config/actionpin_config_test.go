package config

import (
	"strings"
	"testing"
)

func TestActionPinValidation(t *testing.T) {
	// The defaults populate the gate thresholds, which must validate.
	def := Default()
	if err := def.Validate(); err != nil {
		t.Fatalf("default config (actionpin) rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"bad failSeverity", func(c *Config) {
			c.Scanning.Actions.FailSeverity = "nope"
		}, "scanning.actions.failSeverity"},
		{"bad warnSeverity", func(c *Config) {
			c.Scanning.Actions.WarnSeverity = "sometimes"
		}, "scanning.actions.warnSeverity"},
		{"warn exceeds fail", func(c *Config) {
			c.Scanning.Actions.FailSeverity = "medium"
			c.Scanning.Actions.WarnSeverity = "high"
		}, "must not exceed"},
		{"bad action", func(c *Config) {
			c.Scanning.Actions.Action = "nuke"
		}, "scanning.actions.action"},
		{"negative maxFindings", func(c *Config) {
			c.Scanning.Actions.MaxFindings = -1
		}, "scanning.actions.maxFindings"},
		{"empty owner", func(c *Config) {
			c.Scanning.Actions.AllowedOwners = []string{"actions", "  "}
		}, "allowedOwners[1]"},
		{"bad tenant action", func(c *Config) {
			c.Scanning.Actions.Tenants = map[string]ActionPinTenantConfig{
				"t": {Action: "explode"},
			}
		}, "tenants[\"t\"].action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	// A valid non-default policy (allowlist + lower threshold) validates.
	c := Default()
	c.Scanning.Actions.FailSeverity = "medium"
	c.Scanning.Actions.WarnSeverity = ""
	c.Scanning.Actions.AllowedOwners = []string{"actions", "github"}
	c.Scanning.Actions.Tenants = map[string]ActionPinTenantConfig{
		"strict": {FailSeverity: "medium", Action: "block"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid actionpin policy rejected: %v", err)
	}
}
