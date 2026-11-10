package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateScanningProvider(t *testing.T) {
	valid := func() *Config {
		c := Default()
		c.Scanning = ScanningConfig{
			Enabled:  true,
			Provider: "openai",
			FailOn:   "high",
		}
		return &c
	}

	if err := valid().Validate(); err != nil {
		t.Fatalf("valid openai scanning config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"claude accepted", func(c *Config) { c.Scanning.Provider = "claude" }, ""},
		{"codex accepted", func(c *Config) { c.Scanning.Provider = "codex" }, ""},
		{"unknown provider", func(c *Config) { c.Scanning.Provider = "gemini" }, "unknown scanning.provider"},
		{"enabled requires provider", func(c *Config) { c.Scanning.Provider = "none" }, "requires a provider"},
		{"negative timeout", func(c *Config) { c.Scanning.Timeout = -time.Second }, "timeout must not be negative"},
		{"non-http base url", func(c *Config) { c.Scanning.BaseURL = "ftp://x" }, "baseUrl must be an absolute"},
		{"http base url ok", func(c *Config) { c.Scanning.BaseURL = "https://gw.example/v1" }, ""},
		{"bad reasoning effort", func(c *Config) { c.Scanning.ReasoningEffort = "extreme" }, "reasoningEffort"},
		{"good reasoning effort", func(c *Config) { c.Scanning.ReasoningEffort = "high" }, ""},
		{"consensus unknown provider", func(c *Config) {
			c.Scanning.Commit.Consensus = []ConsensusProviderConfig{{Provider: "llama", Model: "m"}}
		}, "consensus"},
		{"consensus openai ok", func(c *Config) {
			c.Scanning.Commit.Consensus = []ConsensusProviderConfig{{Provider: "openai", Model: "gpt-4o"}}
		}, ""},
		{"consensus bad base url", func(c *Config) {
			c.Scanning.Commit.Consensus = []ConsensusProviderConfig{{Provider: "openai", Model: "m", BaseURL: "ftp://x"}}
		}, "consensus[0].baseUrl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	// Disabled scanning must skip provider validation.
	c := Default()
	c.Scanning = ScanningConfig{Enabled: false, Provider: "bogus"}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled scanning should not validate provider: %v", err)
	}
}
