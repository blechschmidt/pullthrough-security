package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePrewarm_DisabledSkipsChecks(t *testing.T) {
	c := Default()
	c.Prewarm.Enabled = false
	// Invalid values are only rejected when pre-warming is enabled.
	c.Prewarm.Interval = -1
	c.Prewarm.MaxConcurrency = -5
	c.Prewarm.OffPeakStart = "nonsense"
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled prewarm must not enforce bounds: %v", err)
	}
}

func TestValidatePrewarm_OK(t *testing.T) {
	c := Default()
	c.Prewarm.Enabled = true
	c.Prewarm.Interval = time.Hour
	c.Prewarm.MaxConcurrency = 4
	c.Prewarm.MaxPerCycle = 100
	c.Prewarm.RatePerMinute = 60
	c.Prewarm.OffPeakStart = "22:00"
	c.Prewarm.OffPeakEnd = "05:00"
	c.Prewarm.OffPeakTimezone = "UTC"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid prewarm config, got %v", err)
	}
	// An empty off-peak window (any time) is valid.
	c.Prewarm.OffPeakStart = ""
	c.Prewarm.OffPeakEnd = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("empty off-peak window must be accepted, got %v", err)
	}
}

func TestValidatePrewarm_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"negative interval", func(c *Config) { c.Prewarm.Interval = -1 }, "prewarm.interval"},
		{"negative concurrency", func(c *Config) { c.Prewarm.MaxConcurrency = -1 }, "prewarm numeric bounds"},
		{"one off-peak bound", func(c *Config) { c.Prewarm.OffPeakStart = "01:00" }, "both be set or both empty"},
		{"bad off-peak time", func(c *Config) {
			c.Prewarm.OffPeakStart = "25:61"
			c.Prewarm.OffPeakEnd = "05:00"
		}, "prewarm.offPeakStart"},
		{"bad timezone", func(c *Config) {
			c.Prewarm.OffPeakStart = "01:00"
			c.Prewarm.OffPeakEnd = "05:00"
			c.Prewarm.OffPeakTimezone = "Mars/Phobos"
		}, "prewarm.offPeakTimezone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.Prewarm.Enabled = true
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
