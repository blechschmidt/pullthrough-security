package main

import (
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
)

// buildSbomDiff constructs the SBOM diff & dependency-drift subsystem (Task 64)
// when enabled. It wires the license-compliance service as the license-
// disposition cross-reference so a newly-introduced GPL/copyleft dependency is
// flagged (not just any new license), and translates the YAML thresholds and
// weighting model into the service config. It returns nil when disabled, in which
// case no drift history is kept and the admin/metrics surfaces report it absent.
func buildSbomDiff(cfg *config.Config, licenseSvc *license.Service, logger *slog.Logger) *sbomdiff.Service {
	sc := cfg.SbomDiff
	if !sc.Enabled {
		logger.Info("sbom-diff / dependency-drift subsystem disabled (set sbomDiff.enabled to track per-coordinate dependency drift)")
		return nil
	}

	// A nil *license.Service is fine — the typed-nil still satisfies the
	// dispositioner interface and returns "" (no cross-reference). Pass an explicit
	// nil interface when license compliance is off so the diff records new licenses
	// without a disposition rather than calling into a disabled service.
	var disp sbomdiff.LicenseDispositioner
	if licenseSvc != nil {
		disp = licenseSvc
	}

	svc := sbomdiff.NewService(sbomdiff.Config{
		Enabled:              true,
		HistorySize:          sc.HistorySize,
		MaxCoordinates:       sc.MaxCoordinates,
		Action:               sbomDiffAction(sc.Action),
		WarnThreshold:        sc.WarnThreshold,
		BlockThreshold:       sc.BlockThreshold,
		SignificantThreshold: sc.SignificantThreshold,
		Weights:              sbomDiffWeights(sc.Weights),
	}, disp)

	m := svc.Metrics(0)
	logger.Info("sbom-diff / dependency-drift subsystem enabled",
		"action", m.Action,
		"warnThreshold", m.WarnThreshold,
		"blockThreshold", m.BlockThreshold,
		"significantThreshold", m.SignificantThreshold,
		"historySize", m.HistorySize,
		"licenseCrossRef", disp != nil)
	return svc
}

// sbomDiffAction maps the config action token to a policy.Action, defaulting to
// warn (observe-and-alert).
func sbomDiffAction(s string) policy.Action {
	switch s {
	case "block":
		return policy.ActionBlock
	case "quarantine":
		return policy.ActionQuarantine
	default:
		return policy.ActionWarn
	}
}

// sbomDiffWeights translates the config weights; an all-zero block inherits the
// subsystem's built-in defaults.
func sbomDiffWeights(w config.SbomDriftWeights) sbomdiff.Weights {
	return sbomdiff.Weights{
		PerAddedDep:      w.PerAddedDep,
		PerNewNamespace:  w.PerNewNamespace,
		PerVersionBump:   w.PerVersionBump,
		PerRemovedDep:    w.PerRemovedDep,
		NewLicenseAllow:  w.NewLicenseAllow,
		NewLicenseReview: w.NewLicenseReview,
		NewLicenseDeny:   w.NewLicenseDeny,
		VulnCritical:     w.VulnCritical,
		VulnHigh:         w.VulnHigh,
		VulnMedium:       w.VulnMedium,
		VulnLow:          w.VulnLow,
	}
}
