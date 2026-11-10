package config

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestRequireModuleOrDefault(t *testing.T) {
	cases := []struct {
		name string
		in   *bool
		want bool
	}{
		{"unset defaults to true", nil, true},
		{"explicit true", boolPtr(true), true},
		{"explicit false", boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := FIPSConfig{RequireModule: tc.in}
			if got := f.RequireModuleOrDefault(); got != tc.want {
				t.Fatalf("RequireModuleOrDefault() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateFIPS_DisabledSkipsChecks(t *testing.T) {
	c := Default()
	// A sub-1.2 TLS floor is only rejected when FIPS is enabled.
	c.Outbound.TLS.MinVersion = "1.0"
	c.FIPS.Enabled = false
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled FIPS must not enforce approved TLS floors: %v", err)
	}
}

func TestValidateFIPS_OK(t *testing.T) {
	c := Default()
	c.FIPS.Enabled = true
	c.Outbound.TLS.MinVersion = "1.2"
	c.Upstreams = map[string]UpstreamConfig{
		"npm": {Type: "npm", URL: "https://registry.npmjs.org", TLS: &TLSConfig{MinVersion: "1.3"}},
		// An unset upstream floor is acceptable: the proxy applies an approved floor.
		"pypi": {Type: "pip", URL: "https://pypi.org"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid FIPS config, got %v", err)
	}
}

func TestValidateFIPS_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "outbound TLS below 1.2",
			mutate: func(c *Config) { c.Outbound.TLS.MinVersion = "1.1" },
			want:   "outbound.tls.minVersion",
		},
		{
			name: "upstream TLS below 1.2",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"npm": {Type: "npm", URL: "https://registry.npmjs.org", TLS: &TLSConfig{MinVersion: "1.0"}},
				}
			},
			want: "tls.minVersion",
		},
		{
			name: "upstream mirror TLS below 1.2",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"npm": {
						Type: "npm", URL: "https://registry.npmjs.org",
						Mirrors: []MirrorConfig{{URL: "https://mirror.example.com", TLS: &TLSConfig{MinVersion: "1.1"}}},
					},
				}
			},
			want: "mirror 0 tls.minVersion",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.FIPS.Enabled = true
			c.Outbound.TLS.MinVersion = "1.2"
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected a validation error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}
