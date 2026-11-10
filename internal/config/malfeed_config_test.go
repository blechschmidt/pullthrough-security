package config

import (
	"strings"
	"testing"
	"time"
)

func TestMalfeedValidation(t *testing.T) {
	// The defaults enable malfeed with no sources, which must validate (inert).
	def := Default()
	if err := def.Validate(); err != nil {
		t.Fatalf("default config (malfeed enabled, no sources) rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"empty source url", func(c *Config) {
			c.Malfeed.Sources = []MalfeedSourceConfig{{URL: ""}}
		}, "url is required"},
		{"non-http url", func(c *Config) {
			c.Malfeed.Sources = []MalfeedSourceConfig{{URL: "ftp://feeds.example/m.json"}}
		}, "valid http(s) URL"},
		{"negative refresh", func(c *Config) {
			c.Malfeed.RefreshInterval = -1 * time.Second
		}, "refreshInterval"},
		{"negative stale", func(c *Config) {
			c.Malfeed.StaleAfter = -1 * time.Second
		}, "staleAfter"},
		{"missing bundle", func(c *Config) {
			c.Malfeed.BundlePath = "/nonexistent/bundle.json"
		}, "bundlePath"},
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

	// A disabled gate skips validation entirely.
	c := Default()
	c.Malfeed.Enabled = false
	c.Malfeed.Sources = []MalfeedSourceConfig{{URL: "not-a-url"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled malfeed must skip validation, got %v", err)
	}

	// A well-formed source validates.
	c = Default()
	c.Malfeed.Sources = []MalfeedSourceConfig{{URL: "https://feeds.example/m.json", Name: "ossf"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid malfeed source rejected: %v", err)
	}
}
