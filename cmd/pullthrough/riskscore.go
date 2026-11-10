package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// buildRiskScore constructs the unified supply-chain risk-scoring engine (Task
// 37) when enabled. It translates the YAML weighting model, band cutoffs, and
// admission threshold (with per-tenant overrides) into the engine config,
// applying built-in defaults for any unset part. It returns nil when disabled,
// in which case no scoring runs and the admin/metrics surfaces report it absent.
func buildRiskScore(cfg *config.Config, logger *slog.Logger) (*riskscore.Engine, error) {
	rc := cfg.RiskScore
	if !rc.Enabled {
		logger.Info("unified risk scoring disabled (set riskScore.enabled to compute composite supply-chain risk scores)")
		return nil, nil
	}

	band, action, err := parseRiskThreshold(rc.ThresholdBand, rc.ThresholdAction)
	if err != nil {
		return nil, fmt.Errorf("risk scoring: %w", err)
	}

	tenants, err := riskTenantOverrides(rc.Tenants)
	if err != nil {
		return nil, fmt.Errorf("risk scoring: %w", err)
	}

	engine, err := riskscore.New(riskscore.Config{
		Enabled:         true,
		Weights:         riskWeights(rc.Weights),
		Bands:           riskBands(rc.Bands),
		Threshold:       riskscore.Threshold{Band: band, Action: action},
		TenantOverrides: tenants,
		HistorySize:     rc.HistorySize,
	})
	if err != nil {
		return nil, fmt.Errorf("risk scoring: %w", err)
	}

	snap := engine.Snapshot()
	logger.Info("unified risk scoring enabled",
		"thresholdBand", snap.Threshold.Band,
		"thresholdAction", snap.Threshold.Action,
		"historySize", snap.HistorySize,
		"tenantOverrides", len(tenants))
	return engine, nil
}

// parseRiskThreshold resolves the global threshold band/action strings, applying
// observe-only defaults (band=high, action=off) for empty values.
func parseRiskThreshold(bandStr, actionStr string) (riskscore.Band, riskscore.ThresholdAction, error) {
	band := riskscore.DefaultThreshold().Band
	if v := strings.ToLower(strings.TrimSpace(bandStr)); v != "" {
		b, ok := riskscore.ParseBand(v)
		if !ok {
			return "", "", fmt.Errorf("invalid thresholdBand %q (want low|medium|high|critical)", bandStr)
		}
		band = b
	}
	action := riskscore.ThresholdOff
	if v := strings.ToLower(strings.TrimSpace(actionStr)); v != "" {
		a, ok := riskscore.ParseThresholdAction(v)
		if !ok {
			return "", "", fmt.Errorf("invalid thresholdAction %q (want off|warn|block)", actionStr)
		}
		action = a
	}
	return band, action, nil
}

// riskWeights translates the config weights, leaving an all-zero block to be
// filled with the engine's built-in defaults.
func riskWeights(w config.RiskScoreWeights) riskscore.Weights {
	return riskscore.Weights{
		Vulnerability: w.Vulnerability,
		Signature:     w.Signature,
		License:       w.License,
		Nameguard:     w.Nameguard,
		Secret:        w.Secret,
		Provenance:    w.Provenance,
		Quarantine:    w.Quarantine,
		InstallHooks:  w.InstallHooks,
		RepoHealth:    w.RepoHealth,
	}
}

// riskBands translates the config band cutoffs, leaving an all-zero block to be
// filled with the engine's built-in defaults.
func riskBands(b config.RiskScoreBands) riskscore.BandThresholds {
	return riskscore.BandThresholds{Medium: b.Medium, High: b.High, Critical: b.Critical}
}

// riskTenantOverrides translates per-tenant overrides, validating each tenant's
// threshold enums up front so a misconfiguration fails startup rather than
// silently degrading at score time.
func riskTenantOverrides(in map[string]config.RiskScoreTenantConfig) (map[string]riskscore.TenantOverride, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]riskscore.TenantOverride, len(in))
	for tenant, tc := range in {
		ov := riskscore.TenantOverride{}
		if tc.Weights != nil {
			w := riskWeights(*tc.Weights)
			ov.Weights = &w
		}
		if tc.Bands != nil {
			b := riskBands(*tc.Bands)
			ov.Bands = &b
		}
		// Preserve partial overrides: an unset band/action inherits the global
		// default rather than being forced to a value, so a tenant can override
		// just the action (or just the band).
		if bandStr := strings.TrimSpace(tc.ThresholdBand); bandStr != "" || strings.TrimSpace(tc.ThresholdAction) != "" {
			thr := &riskscore.Threshold{}
			if bandStr != "" {
				b, ok := riskscore.ParseBand(strings.ToLower(bandStr))
				if !ok {
					return nil, fmt.Errorf("tenant %q: invalid thresholdBand %q", tenant, tc.ThresholdBand)
				}
				thr.Band = b
			}
			if actionStr := strings.TrimSpace(tc.ThresholdAction); actionStr != "" {
				a, ok := riskscore.ParseThresholdAction(strings.ToLower(actionStr))
				if !ok {
					return nil, fmt.Errorf("tenant %q: invalid thresholdAction %q", tenant, tc.ThresholdAction)
				}
				thr.Action = a
			}
			ov.Threshold = thr
		}
		out[tenant] = ov
	}
	return out, nil
}
