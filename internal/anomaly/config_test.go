package anomaly

import (
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	c := Config{Enabled: true}.withDefaults()
	if c.Window != defaultWindow {
		t.Fatalf("window default = %v", c.Window)
	}
	if c.Tunables != DefaultTunables() {
		t.Fatalf("tunables default mismatch: %+v", c.Tunables)
	}
	if c.WarnLevel != LevelMedium {
		t.Fatalf("warn-level default = %q", c.WarnLevel)
	}
	if c.Location != time.UTC {
		t.Fatalf("location default should be UTC")
	}
	if c.LevelMedium != defaultLevelMedium || c.LevelHigh != defaultLevelHigh {
		t.Fatalf("level cutoff defaults = %v/%v", c.LevelMedium, c.LevelHigh)
	}
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"ok", nil, false},
		{"warn>=high", func(c *Config) { c.Tunables.FanoutWarn = 200; c.Tunables.FanoutHigh = 100 }, true},
		{"negative", func(c *Config) { c.Tunables.EnumerationWarn = -1 }, true},
		{"bad warn level", func(c *Config) { c.WarnLevel = "panic" }, true},
		{"bad block level", func(c *Config) { c.BlockLevel = "boom" }, true},
		{"levels inverted", func(c *Config) { c.LevelMedium = 90; c.LevelHigh = 80 }, true},
		{"bad off-hours", func(c *Config) { c.OffHoursStart = 30 }, true},
		{"empty block ok", func(c *Config) { c.BlockLevel = "" }, false},
		{"valid block", func(c *Config) { c.BlockLevel = LevelHigh }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Enabled: true}
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			c = c.withDefaults()
			err := c.validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("validate err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestTenantOverrideResolution(t *testing.T) {
	custom := DefaultTunables()
	custom.FanoutWarn = 3
	custom.FanoutHigh = 6
	c := Config{
		Enabled:    true,
		WarnLevel:  LevelMedium,
		BlockLevel: LevelHigh,
		TenantOverrides: map[string]TenantOverride{
			"sensitive": {Tunables: &custom, BlockLevel: LevelMedium},
		},
	}.withDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	def := c.resolve("other")
	if def.tunables.FanoutWarn != DefaultTunables().FanoutWarn {
		t.Fatalf("unknown tenant should inherit defaults")
	}
	if def.blockLevel != LevelHigh {
		t.Fatalf("default block level = %q", def.blockLevel)
	}

	ov := c.resolve("sensitive")
	if ov.tunables.FanoutWarn != 3 {
		t.Fatalf("override tunables not applied: %+v", ov.tunables)
	}
	if ov.blockLevel != LevelMedium {
		t.Fatalf("override block level = %q", ov.blockLevel)
	}
	// WarnLevel was not overridden for the tenant: it inherits the global value.
	if ov.warnLevel != LevelMedium {
		t.Fatalf("warn level should inherit global, got %q", ov.warnLevel)
	}
	if !ov.blockEnabled() {
		t.Fatalf("block should be enabled for overridden tenant")
	}
}

func TestBlockEnabledDisabledWhenEmpty(t *testing.T) {
	c := Config{Enabled: true}.withDefaults()
	if c.resolve("").blockEnabled() {
		t.Fatalf("block must be disabled when BlockLevel is empty")
	}
}
