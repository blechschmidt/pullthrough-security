package config

import (
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func basePinsConfig(pins ...ProvenancePin) *Config {
	c := Default()
	c.Upstreams = map[string]UpstreamConfig{
		"npm": {Type: "npm", URL: "https://registry.npmjs.org"},
	}
	c.Provenance.Enabled = true
	c.Provenance.Pins = pins
	return &c
}

func TestValidateProvenancePins_OK(t *testing.T) {
	c := basePinsConfig(
		ProvenancePin{Ecosystem: "npm", Name: "@acme/widget", Version: "1.4.2", Repository: "https://git.example.com/acme/widget", Commit: testCommit},
		// Same package, different version: a distinct coordinate.
		ProvenancePin{Ecosystem: "npm", Name: "@acme/widget", Version: "1.4.3", Commit: testCommit},
		// Every version, every ecosystem.
		ProvenancePin{Name: "left-pad", Commit: strings.Repeat("A", 40)},
		// SHA-256 object format.
		ProvenancePin{Ecosystem: "docker", Name: "library/alpine", Version: "*", Commit: strings.Repeat("0", 64)},
	)
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid pins, got %v", err)
	}
}

func TestValidateProvenancePins_NoPinsNeedsNothing(t *testing.T) {
	c := basePinsConfig()
	c.Provenance.Enabled = false
	if err := c.Validate(); err != nil {
		t.Fatalf("no pins must validate with provenance disabled: %v", err)
	}
}

func TestValidateProvenancePins_Errors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"provenance disabled", func(c *Config) { c.Provenance.Enabled = false }, "provenance.enabled is false"},
		{"missing name", func(c *Config) { c.Provenance.Pins[0].Name = " " }, "pins[0].name is required"},
		{"name pattern", func(c *Config) { c.Provenance.Pins[0].Name = "@acme/*" }, "not a pattern"},
		{"missing commit", func(c *Config) { c.Provenance.Pins[0].Commit = "" }, "pins[0].commit"},
		{"abbreviated commit", func(c *Config) { c.Provenance.Pins[0].Commit = "0123456" }, "full 40- or 64-character"},
		{"non-hex commit", func(c *Config) { c.Provenance.Pins[0].Commit = strings.Repeat("g", 40) }, "full 40- or 64-character"},
		{"duplicate coordinate", func(c *Config) {
			c.Provenance.Pins = append(c.Provenance.Pins,
				ProvenancePin{Ecosystem: "NPM", Name: "Widget", Version: "1.0.0", Commit: testCommit})
		}, "pins[1] duplicates provenance.pins[0]"},
		{"duplicate wildcard spellings", func(c *Config) {
			c.Provenance.Pins = []ProvenancePin{
				{Ecosystem: "*", Name: "widget", Commit: testCommit},
				{Name: "widget", Version: "*", Commit: testCommit},
			}
		}, "pins[1] duplicates provenance.pins[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := basePinsConfig(ProvenancePin{Ecosystem: "npm", Name: "widget", Version: "1.0.0", Commit: testCommit})
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected a validation error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}
