package main

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
)

// buildRepoScore constructs the source-repository health signal provider (Task
// 63) when enabled. It wires a MirrorLocator over a cache directory (offline by
// default; on-demand cloning is opt-in via repoScore.allowFetch) and translates
// the YAML weighting model and per-tenant overrides into the engine config. It
// returns nil when disabled, in which case no repository health is derived and
// the admin/metrics surfaces report it absent.
func buildRepoScore(cfg *config.Config, logger *slog.Logger) (*reposcore.Service, error) {
	rc := cfg.RepoScore
	if !rc.Enabled {
		logger.Info("source-repository health scoring disabled (set repoScore.enabled to derive OpenSSF Scorecard-style signals)")
		return nil, nil
	}

	cacheDir := strings.TrimSpace(rc.CacheDir)
	if cacheDir == "" {
		base := strings.TrimSpace(cfg.Cache.Dir)
		if base == "" {
			base = "."
		}
		cacheDir = filepath.Join(base, "reposcore")
	}

	locator, err := reposcore.NewMirrorLocator(reposcore.MirrorLocatorOptions{
		Root:         cacheDir,
		GitBinary:    rc.GitBinary,
		AllowFetch:   rc.AllowFetch,
		Depth:        rc.CloneDepth,
		FetchTimeout: rc.FetchTimeout,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("repo-health scoring: %w", err)
	}

	tenants := repoScoreTenantOverrides(rc.Tenants)

	svc, err := reposcore.New(reposcore.Config{
		Enabled:         true,
		Weights:         repoScoreWeights(rc.Weights),
		TenantOverrides: tenants,
		Window:          rc.Window,
		CacheTTL:        rc.CacheTTL,
		AnalyzeTimeout:  rc.AnalyzeTimeout,
		Locator:         locator,
		GitBinary:       rc.GitBinary,
	})
	if err != nil {
		return nil, fmt.Errorf("repo-health scoring: %w", err)
	}

	logger.Info("source-repository health scoring enabled",
		"cacheDir", cacheDir,
		"allowFetch", rc.AllowFetch,
		"window", svc.Status(0).Window,
		"tenantOverrides", len(tenants))
	return svc, nil
}

// repoScoreWeights translates the config weights, leaving an all-zero block to be
// filled with the engine's built-in defaults.
func repoScoreWeights(w config.RepoScoreWeights) reposcore.Weights {
	return reposcore.Weights{
		BranchProtection: w.BranchProtection,
		SignedCommits:    w.SignedCommits,
		CI:               w.CI,
		SecurityPolicy:   w.SecurityPolicy,
		Maintainers:      w.Maintainers,
		Activity:         w.Activity,
		DepAutomation:    w.DepAutomation,
	}
}

// repoScoreTenantOverrides translates per-tenant weighting overrides.
func repoScoreTenantOverrides(in map[string]config.RepoScoreTenantConfig) map[string]reposcore.TenantOverride {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]reposcore.TenantOverride, len(in))
	for tenant, tc := range in {
		ov := reposcore.TenantOverride{}
		if tc.Weights != nil {
			w := repoScoreWeights(*tc.Weights)
			ov.Weights = &w
		}
		out[tenant] = ov
	}
	return out
}
