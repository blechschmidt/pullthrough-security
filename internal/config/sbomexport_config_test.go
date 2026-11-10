package config

import (
	"strings"
	"testing"
	"time"
)

func TestSBOMExportValidation(t *testing.T) {
	// The defaults keep the subsystem disabled, so the default config validates.
	def := Default()
	if err := def.Validate(); err != nil {
		t.Fatalf("default config (sbomExport) rejected: %v", err)
	}

	// A fully-specified, enabled config with both sinks validates.
	valid := func() *Config {
		c := Default()
		c.SBOMExport.Enabled = true
		c.SBOMExport.MinSeverity = "high"
		c.SBOMExport.DependencyTrack = SBOMExportDependencyTrackConfig{
			Enabled: true,
			URL:     "https://dtrack.example.com",
			APIKey:  "abc123",
		}
		c.SBOMExport.GUAC = SBOMExportGUACConfig{
			Enabled:      true,
			URL:          "https://guac.example.com/ingest",
			DocumentType: "intoto",
		}
		return &c
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid sbomExport config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no sink", func(c *Config) {
			c.SBOMExport.DependencyTrack.Enabled = false
			c.SBOMExport.GUAC.Enabled = false
		}, "at least one sink"},
		{"dt missing url", func(c *Config) {
			c.SBOMExport.GUAC.Enabled = false
			c.SBOMExport.DependencyTrack.URL = ""
		}, "dependencyTrack.enabled requires a url"},
		{"dt relative url", func(c *Config) {
			c.SBOMExport.GUAC.Enabled = false
			c.SBOMExport.DependencyTrack.URL = "dtrack.example.com"
		}, "dependencyTrack.url must be an absolute"},
		{"dt missing apiKey", func(c *Config) {
			c.SBOMExport.GUAC.Enabled = false
			c.SBOMExport.DependencyTrack.APIKey = ""
		}, "requires an apiKey"},
		{"guac missing url", func(c *Config) {
			c.SBOMExport.DependencyTrack.Enabled = false
			c.SBOMExport.GUAC.URL = ""
		}, "guac.enabled requires a url"},
		{"guac bad docType", func(c *Config) {
			c.SBOMExport.DependencyTrack.Enabled = false
			c.SBOMExport.GUAC.DocumentType = "spdx"
		}, "guac.documentType"},
		{"bad minSeverity", func(c *Config) {
			c.SBOMExport.MinSeverity = "catastrophic"
		}, "sbomExport.minSeverity"},
		{"negative maxRetries", func(c *Config) {
			c.SBOMExport.MaxRetries = -1
		}, "sbomExport.maxRetries"},
		{"negative duration", func(c *Config) {
			c.SBOMExport.Timeout = -time.Second
		}, "sbomExport durations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestSBOMExportDisabledSkipsValidation confirms a disabled subsystem is never
// validated (so a half-specified, disabled block does not block startup).
func TestSBOMExportDisabledSkipsValidation(t *testing.T) {
	body := `
sbomExport:
  enabled: false
  dependencyTrack:
    enabled: true
`
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("disabled sbomExport should not be validated: %v", err)
	}
}

// TestSBOMExportDefaults confirms the OrDefault helpers default on.
func TestSBOMExportDefaults(t *testing.T) {
	var c SBOMExportConfig
	if !c.IncludeFindingsOrDefault() {
		t.Error("includeFindings should default to true")
	}
	if !c.DependencyTrack.AutoCreateOrDefault() {
		t.Error("dependencyTrack.autoCreate should default to true")
	}
	f := false
	c.IncludeFindings = &f
	c.DependencyTrack.AutoCreate = &f
	if c.IncludeFindingsOrDefault() || c.DependencyTrack.AutoCreateOrDefault() {
		t.Error("explicit false must be honored")
	}
}
