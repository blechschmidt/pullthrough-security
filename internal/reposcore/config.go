package reposcore

import (
	"errors"
	"fmt"
	"time"
)

const (
	// defaultWindow bounds how many recent commits the history walk examines. It
	// keeps the signal "recent history" and the `git log` cheap on large repos.
	defaultWindow = 200
	// defaultCacheTTL is how long a computed report is reused before the repository
	// is re-derived.
	defaultCacheTTL = 6 * time.Hour
	// defaultNegativeTTL is the (shorter) reuse window for an unresolved report, so
	// a momentarily-unreachable repository is retried sooner than a healthy one.
	defaultNegativeTTL = 30 * time.Minute
	// defaultAnalyzeTimeout bounds a single repository analysis (including any
	// on-demand clone) so a slow or huge repo never stalls a pull.
	defaultAnalyzeTimeout = 20 * time.Second
	// defaultHistorySize bounds the retained recent-report ring for the admin view.
	defaultHistorySize = 200
	// weakThreshold is the health value at or below which a sub-signal is listed in
	// Report.Weak.
	weakThreshold = 0.34
)

// Weights is the per-sub-signal weighting model for the composite health score.
// Weights are relative: the score normalizes by the sum of the weights of the
// signals that were applicable, so a signal that could not be derived neither
// inflates nor deflates the result. Weights must be non-negative.
type Weights struct {
	BranchProtection float64 `json:"branchProtection"`
	SignedCommits    float64 `json:"signedCommits"`
	CI               float64 `json:"ci"`
	SecurityPolicy   float64 `json:"securityPolicy"`
	Maintainers      float64 `json:"maintainers"`
	Activity         float64 `json:"activity"`
	DepAutomation    float64 `json:"depAutomation"`
}

func (w Weights) forSignal(k SignalKind) float64 {
	switch k {
	case SignalBranchProtection:
		return w.BranchProtection
	case SignalSignedCommits:
		return w.SignedCommits
	case SignalCI:
		return w.CI
	case SignalSecurityPolicy:
		return w.SecurityPolicy
	case SignalMaintainers:
		return w.Maintainers
	case SignalActivity:
		return w.Activity
	case SignalDepAutomation:
		return w.DepAutomation
	default:
		return 0
	}
}

func (w Weights) sum() float64 {
	return w.BranchProtection + w.SignedCommits + w.CI + w.SecurityPolicy + w.Maintainers + w.Activity + w.DepAutomation
}

func (w Weights) isZero() bool { return w.sum() == 0 }

// DefaultWeights is the built-in weighting model. Branch protection and
// signed-commit hygiene weigh most (they are the strongest tamper-resistance
// signals), CI and an active maintainer base follow, and a security policy and
// dependency automation round it out.
func DefaultWeights() Weights {
	return Weights{
		BranchProtection: 0.18,
		SignedCommits:    0.18,
		CI:               0.15,
		Maintainers:      0.15,
		SecurityPolicy:   0.12,
		Activity:         0.12,
		DepAutomation:    0.10,
	}
}

func validateWeights(w Weights) error {
	for name, v := range map[string]float64{
		"branchProtection": w.BranchProtection, "signedCommits": w.SignedCommits, "ci": w.CI,
		"securityPolicy": w.SecurityPolicy, "maintainers": w.Maintainers, "activity": w.Activity,
		"depAutomation": w.DepAutomation,
	} {
		if v < 0 {
			return fmt.Errorf("%s weight must be non-negative, got %g", name, v)
		}
	}
	if w.sum() <= 0 {
		return errors.New("at least one weight must be positive")
	}
	return nil
}

// TenantOverride overrides the global weighting model for one tenant. A nil
// Weights inherits the global default.
type TenantOverride struct {
	Weights *Weights `json:"weights,omitempty"`
}

// Config configures the repository-health Service.
type Config struct {
	// Enabled gates whether the Service is built and wired as a signal provider.
	Enabled bool
	// Weights is the global default weighting model. Zero substitutes
	// DefaultWeights.
	Weights Weights
	// TenantOverrides keys per-tenant weighting overrides by tenant id (team).
	TenantOverrides map[string]TenantOverride

	// Window bounds how many recent commits the history walk examines. Zero
	// substitutes defaultWindow.
	Window int
	// CacheTTL is how long a computed report is reused. Zero substitutes
	// defaultCacheTTL.
	CacheTTL time.Duration
	// NegativeTTL is the reuse window for an unresolved report. Zero substitutes
	// defaultNegativeTTL.
	NegativeTTL time.Duration
	// AnalyzeTimeout bounds a single repository analysis. Zero substitutes
	// defaultAnalyzeTimeout.
	AnalyzeTimeout time.Duration
	// HistorySize bounds the retained recent-report ring. Zero substitutes
	// defaultHistorySize.
	HistorySize int

	// Locator resolves a repository URL to a local git directory. Required when
	// Enabled; nil yields an unresolved report for every repository (the offline
	// no-op).
	Locator Locator
	// GitBinary is the git executable (default "git", resolved on PATH).
	GitBinary string
	// Enricher, when set, is the optional online enrichment hook (e.g. real
	// branch-protection settings from a forge API). Nil keeps the path fully
	// offline.
	Enricher Enricher

	// Now is an injectable clock for tests; nil substitutes time.Now.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Weights.isZero() {
		c.Weights = DefaultWeights()
	}
	if c.Window <= 0 {
		c.Window = defaultWindow
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = defaultCacheTTL
	}
	if c.NegativeTTL <= 0 {
		c.NegativeTTL = defaultNegativeTTL
	}
	if c.AnalyzeTimeout <= 0 {
		c.AnalyzeTimeout = defaultAnalyzeTimeout
	}
	if c.HistorySize <= 0 {
		c.HistorySize = defaultHistorySize
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c Config) validate() error {
	if err := validateWeights(c.Weights); err != nil {
		return fmt.Errorf("weights: %w", err)
	}
	for tenant, ov := range c.TenantOverrides {
		if ov.Weights != nil {
			if err := validateWeights(*ov.Weights); err != nil {
				return fmt.Errorf("tenant %q weights: %w", tenant, err)
			}
		}
	}
	return nil
}

// resolveWeights returns the effective weighting model for a tenant, layering any
// per-tenant override over the global default.
func (c Config) resolveWeights(tenant string) Weights {
	if tenant != "" {
		if ov, ok := c.TenantOverrides[tenant]; ok && ov.Weights != nil && !ov.Weights.isZero() {
			return *ov.Weights
		}
	}
	return c.Weights
}
