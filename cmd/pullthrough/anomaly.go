package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// buildAnomaly constructs the behavioral anomaly-detection engine (Task 43) when
// enabled. It translates the YAML detector thresholds, off-hours window, and
// warn/block levels (with per-tenant overrides) into the engine config, applying
// built-in defaults for any unset part. It returns nil when disabled, in which
// case no detection runs and the admin/metrics surfaces report it absent.
func buildAnomaly(cfg *config.Config, logger *slog.Logger) (*anomaly.Engine, error) {
	ac := cfg.Anomaly
	if !ac.Enabled {
		logger.Info("behavioral anomaly detection disabled (set anomaly.enabled to watch the pull stream for compromise/exfiltration patterns)")
		return nil, nil
	}

	warnLevel, err := parseAnomalyLevel(ac.WarnLevel, "warnLevel")
	if err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}
	blockLevel, err := parseAnomalyBlockLevel(ac.BlockLevel)
	if err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}

	loc := time.UTC
	if tz := strings.TrimSpace(ac.Timezone); tz != "" {
		loc, err = time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("anomaly: invalid timezone %q: %w", ac.Timezone, err)
		}
	}

	tenants, err := anomalyTenantOverrides(ac.Tenants)
	if err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}

	engine, err := anomaly.New(anomaly.Config{
		Enabled:         true,
		Window:          ac.Window,
		Tunables:        anomalyTunables(ac.Thresholds),
		WarnLevel:       warnLevel,
		BlockLevel:      blockLevel,
		OffHoursStart:   ac.OffHoursStart,
		OffHoursEnd:     ac.OffHoursEnd,
		Location:        loc,
		AlertCooldown:   ac.AlertCooldown,
		HistorySize:     ac.HistorySize,
		MaxScopes:       ac.MaxScopes,
		TenantOverrides: tenants,
	})
	if err != nil {
		return nil, err
	}

	snap := engine.Snapshot()
	blockDesc := "disabled (observe + notify only)"
	if snap.Threshold.BlockLevel != anomaly.LevelNone {
		blockDesc = string(snap.Threshold.BlockLevel)
	}
	logger.Info("behavioral anomaly detection enabled",
		"window", snap.Window,
		"warnLevel", snap.Threshold.WarnLevel,
		"blockLevel", blockDesc,
		"offHours", fmt.Sprintf("%02d:00-%02d:00 %s", ac.OffHoursStart, ac.OffHoursEnd, loc),
		"tenantOverrides", len(tenants))
	return engine, nil
}

// parseAnomalyLevel resolves a required level string, applying a medium default
// for empty input.
func parseAnomalyLevel(s, field string) (anomaly.Level, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return anomaly.LevelMedium, nil
	}
	l, ok := anomaly.ParseLevel(v)
	if !ok {
		return "", fmt.Errorf("invalid %s %q (want low|medium|high)", field, s)
	}
	return l, nil
}

// parseAnomalyBlockLevel resolves the block level, where an empty value (or the
// explicit "none"/"off") disables soft-blocking.
func parseAnomalyBlockLevel(s string) (anomaly.Level, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "", "none", "off":
		return "", nil
	}
	l, ok := anomaly.ParseLevel(v)
	if !ok {
		return "", fmt.Errorf("invalid blockLevel %q (want none|low|medium|high)", s)
	}
	return l, nil
}

// anomalyTunables translates the config thresholds, leaving an all-zero block to
// be filled with the engine's built-in defaults.
func anomalyTunables(t config.AnomalyThresholds) anomaly.Tunables {
	return anomaly.Tunables{
		FanoutWarn:       t.FanoutWarn,
		FanoutHigh:       t.FanoutHigh,
		NewNamespaceWarn: t.NewNamespaceWarn,
		NewNamespaceHigh: t.NewNamespaceHigh,
		OffHoursWarn:     t.OffHoursWarn,
		OffHoursHigh:     t.OffHoursHigh,
		EnumerationWarn:  t.EnumerationWarn,
		EnumerationHigh:  t.EnumerationHigh,
		EgressZWarn:      t.EgressZWarn,
		EgressZHigh:      t.EgressZHigh,
	}
}

// anomalyTenantOverrides translates per-tenant overrides, validating each
// tenant's level enums up front so a misconfiguration fails startup rather than
// silently degrading at detection time.
func anomalyTenantOverrides(in map[string]config.AnomalyTenantConfig) (map[string]anomaly.TenantOverride, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]anomaly.TenantOverride, len(in))
	for tenant, tc := range in {
		ov := anomaly.TenantOverride{}
		if tc.Thresholds != nil {
			tn := anomalyTunables(*tc.Thresholds)
			ov.Tunables = &tn
		}
		if warn := strings.TrimSpace(tc.WarnLevel); warn != "" {
			l, ok := anomaly.ParseLevel(strings.ToLower(warn))
			if !ok {
				return nil, fmt.Errorf("tenant %q: invalid warnLevel %q", tenant, tc.WarnLevel)
			}
			ov.WarnLevel = l
		}
		if block := strings.TrimSpace(tc.BlockLevel); block != "" {
			l, err := parseAnomalyBlockLevel(block)
			if err != nil {
				return nil, fmt.Errorf("tenant %q: %w", tenant, err)
			}
			// An explicit "none" disables blocking for the tenant; represent it as
			// LevelNone so it overrides a non-empty global block level.
			if l == "" {
				l = anomaly.LevelNone
			}
			ov.BlockLevel = l
		}
		out[tenant] = ov
	}
	return out, nil
}
