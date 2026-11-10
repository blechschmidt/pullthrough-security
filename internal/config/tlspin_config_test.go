package config

import (
	"strings"
	"testing"
)

// validSPKIPin is a well-formed spki-sha256 pin (base64 of 32 zero bytes). Its
// value is irrelevant to parsing; only its shape is validated at config time.
const validSPKIPin = "spki-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestValidateTLSPins_Valid(t *testing.T) {
	c := Default()
	c.Upstreams = map[string]UpstreamConfig{
		"npm": {
			Type: "npm",
			URL:  "https://registry.npmjs.org",
			TLS: &TLSConfig{
				Pins:          []string{validSPKIPin, "cert-sha256:" + strings.Repeat("ab", 32)},
				PinReportOnly: true,
			},
			Mirrors: []MirrorConfig{
				{URL: "https://mirror.example.com", TLS: &TLSConfig{Pins: []string{validSPKIPin}}},
			},
		},
	}
	c.Outbound.TLS.Pins = []string{"ca-sha256:" + strings.Repeat("cd", 32)}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid pin config, got %v", err)
	}
}

func TestValidateTLSPins_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "malformed outbound pin",
			mutate: func(c *Config) { c.Outbound.TLS.Pins = []string{"not-a-pin"} },
			want:   "outbound.tls",
		},
		{
			name: "malformed upstream pin",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"npm": {Type: "npm", URL: "https://registry.npmjs.org", TLS: &TLSConfig{Pins: []string{"spki-sha256:tooshort"}}},
				}
			},
			want: `upstream "npm" tls`,
		},
		{
			name: "malformed mirror pin",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"npm": {
						Type: "npm", URL: "https://registry.npmjs.org",
						Mirrors: []MirrorConfig{{URL: "https://m.example.com", TLS: &TLSConfig{Pins: []string{"md5:abc"}}}},
					},
				}
			},
			want: "mirror 0 tls",
		},
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
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestValidateTLSPins_EmptyIsNoop confirms the common case (no pins) validates.
func TestValidateTLSPins_EmptyIsNoop(t *testing.T) {
	if err := validateTLSPins(nil); err != nil {
		t.Fatalf("nil pins should validate: %v", err)
	}
	if err := validateTLSPins([]string{}); err != nil {
		t.Fatalf("empty pins should validate: %v", err)
	}
}
