package config

import (
	"strings"
	"testing"
	"time"
)

func TestOTLPLogsActive(t *testing.T) {
	var o OTLPLogsConfig
	if o.Active() {
		t.Error("zero config should be inactive")
	}
	o.Enabled = true
	if o.Active() {
		t.Error("enabled without endpoint should be inactive")
	}
	o.Endpoint = "http://collector:4318"
	if !o.Active() {
		t.Error("enabled with endpoint should be active")
	}
}

func TestValidateOTLPLogs_DisabledSkipsChecks(t *testing.T) {
	c := Default()
	c.Telemetry.OTLPLogs.Enabled = false
	c.Telemetry.OTLPLogs.MaxQueueSize = -1
	c.Telemetry.OTLPLogs.MinLevel = "nonsense"
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled OTLP logs must not enforce bounds: %v", err)
	}
}

func TestValidateOTLPLogs_OK(t *testing.T) {
	c := Default()
	c.Telemetry.OTLPLogs.Enabled = true
	c.Telemetry.OTLPLogs.Endpoint = "http://collector:4318"
	c.Telemetry.OTLPLogs.MinLevel = "warn"
	c.Telemetry.OTLPLogs.MaxQueueSize = 1024
	c.Telemetry.OTLPLogs.MaxBatchSize = 256
	c.Telemetry.OTLPLogs.BatchTimeout = 3 * time.Second
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	// An enabled-but-endpointless block is the documented inert state, not fatal.
	c.Telemetry.OTLPLogs.Endpoint = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("endpointless OTLP logs block must be accepted, got %v", err)
	}
}

func TestValidateOTLPLogs_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"negative queue", func(c *Config) { c.Telemetry.OTLPLogs.MaxQueueSize = -1 }, "must not be negative"},
		{"negative duration", func(c *Config) { c.Telemetry.OTLPLogs.Timeout = -time.Second }, "durations must not be negative"},
		{"bad level", func(c *Config) { c.Telemetry.OTLPLogs.MinLevel = "verbose" }, "minLevel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.Telemetry.OTLPLogs.Enabled = true
			c.Telemetry.OTLPLogs.Endpoint = "http://collector:4318"
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}
