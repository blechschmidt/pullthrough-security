package simreplay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// Evaluator computes an admission Verdict for a single admission document. It is
// the seam the simulator drives: the production path's policy + risk engines are
// one implementation (EngineEvaluator); a test can supply a trivial stub.
//
// Implementations MUST be pure — deterministic in their input and free of side
// effects — so replay is reproducible. EngineEvaluator satisfies this by using
// the engines' pure evaluation methods (TestEvaluate / Score), which never move
// operational metrics or read the clock.
type Evaluator interface {
	Evaluate(in policyengine.Input) Verdict
}

// EngineEvaluator fuses a policy-as-code engine and a risk-scoring engine into a
// single Evaluator mirroring the pull path's admission decision. Either engine
// may be nil, in which case that gate does not contribute to the verdict.
type EngineEvaluator struct {
	Policy *policyengine.Engine
	Risk   *riskscore.Engine
}

// Evaluate runs the input through both engines purely and fuses their outcomes
// into the canonical admit/block Verdict, retaining per-gate detail for diffing.
func (e EngineEvaluator) Evaluate(in policyengine.Input) Verdict {
	var v Verdict
	if e.Policy != nil {
		res := e.Policy.TestEvaluate(in)
		v.PolicyEnabled = true
		v.PolicyAction = res.EffectiveAction
		v.PolicyReason = res.Decision.Reason
		for _, m := range res.Decision.Matches {
			v.PolicyMatches = append(v.PolicyMatches, VerdictMatch{RuleID: m.RuleID, Action: m.Action})
		}
	}
	if e.Risk != nil && e.Risk.Enabled() {
		a := e.Risk.Score(riskscore.Subject{Input: in})
		v.RiskEnabled = true
		v.RiskScore = a.Score
		v.RiskBand = a.Band
		v.RiskAction = a.Action
		v.RiskExceeds = a.Exceeds
	}
	return v.finalize()
}

// CandidateConfig is the self-contained, file-and-API-friendly description of a
// candidate admission configuration: the policy-as-code engine and the risk-
// scoring engine an operator wants to test against captured traffic. It is the
// schema both the CLI's candidate-config file and the admin endpoint's POST body
// accept (as YAML or JSON). Each section is a pointer so an absent section means
// "that gate does not run in the candidate".
type CandidateConfig struct {
	PolicyEngine *PolicyCandidate `json:"policyEngine,omitempty" yaml:"policyEngine,omitempty"`
	RiskScore    *RiskCandidate   `json:"riskScore,omitempty" yaml:"riskScore,omitempty"`
}

// PolicyCandidate describes a candidate policy-as-code engine.
type PolicyCandidate struct {
	Enabled              bool   `json:"enabled" yaml:"enabled"`
	Dir                  string `json:"dir,omitempty" yaml:"dir,omitempty"`
	Mode                 string `json:"mode,omitempty" yaml:"mode,omitempty"`                                 // enforce|audit (default enforce)
	DefaultAction        string `json:"defaultAction,omitempty" yaml:"defaultAction,omitempty"`               // allow|warn|deny
	IncludeDefaultBundle *bool  `json:"includeDefaultBundle,omitempty" yaml:"includeDefaultBundle,omitempty"` // default true
	// InlineBundle is an optional policy bundle (YAML or JSON) provided directly in
	// the candidate config. It lets an operator test a brand-new bundle through the
	// admin endpoint without first writing it to a server-side directory. When set,
	// it is written to a private temp dir and loaded alongside any Dir/default bundle.
	InlineBundle string `json:"inlineBundle,omitempty" yaml:"inlineBundle,omitempty"`
}

// RiskCandidate describes a candidate risk-scoring engine.
type RiskCandidate struct {
	Enabled         bool                      `json:"enabled" yaml:"enabled"`
	HistorySize     int                       `json:"historySize,omitempty" yaml:"historySize,omitempty"`
	ThresholdBand   string                    `json:"thresholdBand,omitempty" yaml:"thresholdBand,omitempty"`     // low|medium|high|critical
	ThresholdAction string                    `json:"thresholdAction,omitempty" yaml:"thresholdAction,omitempty"` // off|warn|block
	Weights         *riskscore.Weights        `json:"weights,omitempty" yaml:"weights,omitempty"`
	Bands           *riskscore.BandThresholds `json:"bands,omitempty" yaml:"bands,omitempty"`
}

// BuildEvaluator constructs an EngineEvaluator from a candidate config. It
// returns the evaluator and a cleanup func that MUST be called when replay is
// done (it stops the policy engine and removes any temp bundle dir). The cleanup
// func is non-nil even on success and safe to call once.
//
// The policy engine is constructed with no background reload (the simulation is a
// point-in-time evaluation), so it spawns no goroutines beyond its own teardown.
func BuildEvaluator(cfg CandidateConfig) (EngineEvaluator, func() error, error) {
	var (
		ev      EngineEvaluator
		tempDir string
	)
	cleanup := func() error {
		var err error
		if ev.Policy != nil {
			err = ev.Policy.Close()
		}
		if tempDir != "" {
			if rmErr := os.RemoveAll(tempDir); rmErr != nil && err == nil {
				err = rmErr
			}
		}
		return err
	}

	if pc := cfg.PolicyEngine; pc != nil && pc.Enabled {
		peCfg := policyengine.Config{
			Dir:                  pc.Dir,
			Mode:                 parsePolicyMode(pc.Mode),
			DefaultAction:        policyengine.Action(strings.ToLower(strings.TrimSpace(pc.DefaultAction))),
			IncludeDefaultBundle: pc.IncludeDefaultBundle == nil || *pc.IncludeDefaultBundle,
			// ReloadInterval intentionally 0: a what-if is evaluated once.
		}
		if strings.TrimSpace(pc.InlineBundle) != "" {
			dir, derr := writeInlineBundle(pc.InlineBundle)
			if derr != nil {
				_ = cleanup()
				return EngineEvaluator{}, func() error { return nil }, derr
			}
			tempDir = dir
			peCfg.Dir = dir
		}
		engine, err := policyengine.New(peCfg)
		if err != nil {
			_ = cleanup()
			return EngineEvaluator{}, func() error { return nil }, fmt.Errorf("simreplay: candidate policy engine: %w", err)
		}
		ev.Policy = engine
	}

	if rc := cfg.RiskScore; rc != nil && rc.Enabled {
		band := riskscore.DefaultThreshold().Band
		if v := strings.ToLower(strings.TrimSpace(rc.ThresholdBand)); v != "" {
			b, ok := riskscore.ParseBand(v)
			if !ok {
				_ = cleanup()
				return EngineEvaluator{}, func() error { return nil }, fmt.Errorf("simreplay: candidate risk: invalid thresholdBand %q", rc.ThresholdBand)
			}
			band = b
		}
		action := riskscore.ThresholdOff
		if v := strings.ToLower(strings.TrimSpace(rc.ThresholdAction)); v != "" {
			a, ok := riskscore.ParseThresholdAction(v)
			if !ok {
				_ = cleanup()
				return EngineEvaluator{}, func() error { return nil }, fmt.Errorf("simreplay: candidate risk: invalid thresholdAction %q", rc.ThresholdAction)
			}
			action = a
		}
		riskCfg := riskscore.Config{
			Enabled:     true,
			Threshold:   riskscore.Threshold{Band: band, Action: action},
			HistorySize: rc.HistorySize,
		}
		if rc.Weights != nil {
			riskCfg.Weights = *rc.Weights
		}
		if rc.Bands != nil {
			riskCfg.Bands = *rc.Bands
		}
		engine, err := riskscore.New(riskCfg)
		if err != nil {
			_ = cleanup()
			return EngineEvaluator{}, func() error { return nil }, fmt.Errorf("simreplay: candidate risk engine: %w", err)
		}
		ev.Risk = engine
	}

	if ev.Policy == nil && ev.Risk == nil {
		return EngineEvaluator{}, func() error { return nil },
			fmt.Errorf("simreplay: candidate config enables no gate (set policyEngine.enabled and/or riskScore.enabled)")
	}

	return ev, cleanup, nil
}

func parsePolicyMode(s string) policyengine.Mode {
	if strings.EqualFold(strings.TrimSpace(s), string(policyengine.ModeAudit)) {
		return policyengine.ModeAudit
	}
	return policyengine.ModeEnforce
}

// writeInlineBundle writes an inline policy bundle to a fresh private temp dir
// and returns the dir for use as the engine's bundle directory.
func writeInlineBundle(bundle string) (string, error) {
	dir, err := os.MkdirTemp("", "simreplay-bundle-")
	if err != nil {
		return "", fmt.Errorf("simreplay: temp bundle dir: %w", err)
	}
	path := filepath.Join(dir, "candidate.yaml")
	if err := os.WriteFile(path, []byte(bundle), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("simreplay: writing inline bundle: %w", err)
	}
	return dir, nil
}
