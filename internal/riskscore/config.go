package riskscore

import (
	"errors"
	"fmt"
	"time"
)

// Weights is the per-signal weighting model. Weights are relative: the composite
// score normalizes by the sum of the weights of the signals that were actually
// applicable for an artifact, so a missing gate neither inflates nor deflates the
// result. Weights must be non-negative.
type Weights struct {
	Vulnerability float64 `json:"vulnerability"`
	Signature     float64 `json:"signature"`
	License       float64 `json:"license"`
	Nameguard     float64 `json:"nameguard"`
	Secret        float64 `json:"secret"`
	Provenance    float64 `json:"provenance"`
	Quarantine    float64 `json:"quarantine"`
	InstallHooks  float64 `json:"installHooks"`
	AVScan        float64 `json:"avScan"`
	ContentScan   float64 `json:"contentScan"`
	LLMPackage    float64 `json:"llmPackageScan"`
	RepoHealth    float64 `json:"repoHealth"`
	RebuildVerify float64 `json:"rebuildVerify"`
	Continuity    float64 `json:"continuity"`
}

// forSignal returns the configured weight for a signal kind.
func (w Weights) forSignal(k SignalKind) float64 {
	switch k {
	case SignalVulnerability:
		return w.Vulnerability
	case SignalSignature:
		return w.Signature
	case SignalLicense:
		return w.License
	case SignalNameguard:
		return w.Nameguard
	case SignalSecret:
		return w.Secret
	case SignalProvenance:
		return w.Provenance
	case SignalQuarantine:
		return w.Quarantine
	case SignalInstallHooks:
		return w.InstallHooks
	case SignalAVScan:
		return w.AVScan
	case SignalContentScan:
		return w.ContentScan
	case SignalLLMPackage:
		return w.LLMPackage
	case SignalRepoHealth:
		return w.RepoHealth
	case SignalRebuildVerify:
		return w.RebuildVerify
	case SignalContinuity:
		return w.Continuity
	default:
		return 0
	}
}

// sum returns the total of all weights.
func (w Weights) sum() float64 {
	return w.Vulnerability + w.Signature + w.License + w.Nameguard + w.Secret + w.Provenance + w.Quarantine + w.InstallHooks + w.AVScan + w.ContentScan + w.LLMPackage + w.RepoHealth + w.RebuildVerify + w.Continuity
}

// isZero reports whether no weight has been set, so the caller can substitute
// defaults.
func (w Weights) isZero() bool { return w.sum() == 0 }

// DefaultWeights is the built-in, sane-default weighting model. Vulnerability
// severity dominates; cryptographic provenance (signature + attestation) and
// source provenance follow; name/secret/license/quarantine round out the model.
func DefaultWeights() Weights {
	return Weights{
		Vulnerability: 0.30,
		Signature:     0.20,
		Provenance:    0.15,
		License:       0.12,
		Nameguard:     0.10,
		InstallHooks:  0.10,
		AVScan:        0.20,
		ContentScan:   0.12,
		LLMPackage:    0.20,
		RebuildVerify: 0.10,
		Continuity:    0.10,
		Secret:        0.08,
		RepoHealth:    0.08,
		Quarantine:    0.05,
	}
}

// BandThresholds defines the score cutoffs (inclusive lower bounds) for each
// band. A score below Medium is low; >= Medium and < High is medium; >= High and
// < Critical is high; >= Critical is critical.
type BandThresholds struct {
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

func (b BandThresholds) isZero() bool { return b.Medium == 0 && b.High == 0 && b.Critical == 0 }

// DefaultBands is the built-in band cutoff model.
func DefaultBands() BandThresholds {
	return BandThresholds{Medium: 25, High: 50, Critical: 75}
}

// bandFor maps a 0..100 score to its band.
func (b BandThresholds) bandFor(score int) Band {
	switch {
	case score >= b.Critical:
		return BandCritical
	case score >= b.High:
		return BandHigh
	case score >= b.Medium:
		return BandMedium
	default:
		return BandLow
	}
}

func (b BandThresholds) validate() error {
	if b.Medium <= 0 || b.High <= 0 || b.Critical <= 0 {
		return errors.New("band thresholds must be positive")
	}
	if !(b.Medium < b.High && b.High < b.Critical) {
		return fmt.Errorf("band thresholds must be strictly increasing (medium=%d high=%d critical=%d)", b.Medium, b.High, b.Critical)
	}
	if b.Critical > 100 {
		return fmt.Errorf("critical band threshold %d exceeds 100", b.Critical)
	}
	return nil
}

// Threshold is the admission threshold: the minimum band that triggers Action.
type Threshold struct {
	Band   Band            `json:"band"`
	Action ThresholdAction `json:"action"`
}

// DefaultThreshold is observe-only: the engine scores and records but never
// influences serving until an operator configures an action.
func DefaultThreshold() Threshold {
	return Threshold{Band: BandHigh, Action: ThresholdOff}
}

// TenantOverride overrides any subset of the global model for one tenant. A nil
// pointer field inherits the global default; a non-nil pointer fully replaces
// that part of the model.
type TenantOverride struct {
	Weights   *Weights        `json:"weights,omitempty"`
	Bands     *BandThresholds `json:"bands,omitempty"`
	Threshold *Threshold      `json:"threshold,omitempty"`
}

// Config configures the scoring engine.
type Config struct {
	// Enabled gates whether the engine is constructed and wired into the pull
	// path. Disabled engines are simply not built by the wiring layer.
	Enabled bool
	// Weights is the global default weighting model. Zero substitutes
	// DefaultWeights.
	Weights Weights
	// Bands is the global default band cutoff model. Zero substitutes DefaultBands.
	Bands BandThresholds
	// Threshold is the global default admission threshold. A zero Action
	// substitutes DefaultThreshold (observe-only).
	Threshold Threshold
	// TenantOverrides keys per-tenant model overrides by tenant id.
	TenantOverrides map[string]TenantOverride
	// HistorySize bounds the retained recent-assessment ring for trend visibility.
	// Zero substitutes defaultHistorySize.
	HistorySize int
	// Now is an injectable clock for tests; nil substitutes time.Now.
	Now func() time.Time
}

const defaultHistorySize = 200

// withDefaults returns a copy of the config with all zero-valued fields filled
// from the built-in defaults.
func (c Config) withDefaults() Config {
	if c.Weights.isZero() {
		c.Weights = DefaultWeights()
	}
	if c.Bands.isZero() {
		c.Bands = DefaultBands()
	}
	if c.Threshold.Action == "" {
		c.Threshold.Action = ThresholdOff
	}
	if c.Threshold.Band == "" {
		c.Threshold.Band = DefaultThreshold().Band
	}
	if c.HistorySize <= 0 {
		c.HistorySize = defaultHistorySize
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if err := validateWeights(c.Weights); err != nil {
		return fmt.Errorf("weights: %w", err)
	}
	if err := c.Bands.validate(); err != nil {
		return err
	}
	if _, ok := ParseThresholdAction(string(c.Threshold.Action)); !ok {
		return fmt.Errorf("invalid threshold action %q", c.Threshold.Action)
	}
	if _, ok := ParseBand(string(c.Threshold.Band)); !ok {
		return fmt.Errorf("invalid threshold band %q", c.Threshold.Band)
	}
	for tenant, ov := range c.TenantOverrides {
		if ov.Weights != nil {
			if err := validateWeights(*ov.Weights); err != nil {
				return fmt.Errorf("tenant %q weights: %w", tenant, err)
			}
		}
		if ov.Bands != nil {
			if err := ov.Bands.validate(); err != nil {
				return fmt.Errorf("tenant %q bands: %w", tenant, err)
			}
		}
		if ov.Threshold != nil {
			// A tenant may override only part of the threshold; an empty band or
			// action inherits the global default, so validate only what is set.
			if ov.Threshold.Action != "" {
				if _, ok := ParseThresholdAction(string(ov.Threshold.Action)); !ok {
					return fmt.Errorf("tenant %q invalid threshold action %q", tenant, ov.Threshold.Action)
				}
			}
			if ov.Threshold.Band != "" {
				if _, ok := ParseBand(string(ov.Threshold.Band)); !ok {
					return fmt.Errorf("tenant %q invalid threshold band %q", tenant, ov.Threshold.Band)
				}
			}
		}
	}
	return nil
}

func validateWeights(w Weights) error {
	for name, v := range map[string]float64{
		"vulnerability": w.Vulnerability, "signature": w.Signature, "license": w.License,
		"nameguard": w.Nameguard, "secret": w.Secret, "provenance": w.Provenance, "quarantine": w.Quarantine,
		"installHooks": w.InstallHooks, "avScan": w.AVScan, "contentScan": w.ContentScan,
		"llmPackageScan": w.LLMPackage, "repoHealth": w.RepoHealth,
		"rebuildVerify": w.RebuildVerify, "continuity": w.Continuity,
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

// resolved is the effective model for a given tenant.
type resolved struct {
	weights   Weights
	bands     BandThresholds
	threshold Threshold
}

// resolve computes the effective model for a tenant, layering any per-tenant
// override over the global defaults. Each part overrides independently.
func (c Config) resolve(tenant string) resolved {
	r := resolved{weights: c.Weights, bands: c.Bands, threshold: c.Threshold}
	ov, ok := c.TenantOverrides[tenant]
	if !ok || tenant == "" {
		return r
	}
	if ov.Weights != nil && !ov.Weights.isZero() {
		r.weights = *ov.Weights
	}
	if ov.Bands != nil && !ov.Bands.isZero() {
		r.bands = *ov.Bands
	}
	if ov.Threshold != nil {
		if ov.Threshold.Action != "" {
			r.threshold.Action = ov.Threshold.Action
		}
		if ov.Threshold.Band != "" {
			r.threshold.Band = ov.Threshold.Band
		}
	}
	return r
}
