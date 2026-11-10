package config

import (
	"strings"
	"testing"
	"time"
)

func TestTransparencyValidation(t *testing.T) {
	// The defaults leave the Rekor subsystem disabled, which must validate.
	def := Default()
	if err := def.Validate(); err != nil {
		t.Fatalf("default config (transparency disabled) rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"non-http url", func(c *Config) {
			c.Transparency.Rekor.Enabled = true
			c.Transparency.Rekor.URL = "ftp://rekor.example"
		}, "http(s) URL"},
		{"negative timeout", func(c *Config) {
			c.Transparency.Rekor.Enabled = true
			c.Transparency.Rekor.Timeout = -1 * time.Second
		}, "timeout"},
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

	// A disabled subsystem skips validation entirely.
	c := Default()
	c.Transparency.Rekor.Enabled = false
	c.Transparency.Rekor.URL = "not-a-url"
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled transparency must skip validation, got %v", err)
	}

	// A well-formed enabled config validates (submit on, default URL).
	c = Default()
	c.Transparency.Rekor.Enabled = true
	c.Transparency.Rekor.Submit = true
	c.Transparency.Rekor.RequireInclusionProof = true
	if err := c.Validate(); err != nil {
		t.Fatalf("valid transparency config rejected: %v", err)
	}
}
