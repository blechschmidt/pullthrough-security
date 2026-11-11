package riskscore

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func TestEvalLLMPackage(t *testing.T) {
	// No signal, and an artifact that went unscanned for a reason that says
	// nothing about it (a provider outage, a spent budget), contribute nothing:
	// absent, not a zero that would dilute the composite.
	for name, l := range map[string]*policyengine.LLMPackageInput{
		"nil":              nil,
		"empty":            {},
		"provider outage":  {Disposition: "unscanned", Unscanned: true, UnscannedCode: "provider-error"},
		"budget exhausted": {Disposition: "unscanned", Unscanned: true, UnscannedCode: "budget-exhausted"},
	} {
		if res := evalLLMPackage(l); res.present {
			t.Errorf("%s: expected the signal to be absent, got %+v", name, res)
		}
	}

	for name, tc := range map[string]struct {
		in       *policyengine.LLMPackageInput
		subscore float64
		raw      string
	}{
		"benign": {
			&policyengine.LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign", Confidence: 0.9},
			0, "benign"},
		"malicious": {
			&policyengine.LLMPackageInput{Scanned: true, Verdict: "malicious", Disposition: "malicious", Confidence: 0.95, Risk: 99},
			0.99, "malicious (verdict malicious, confidence 0.95)"},
		"suspicious by the proxy's own check": {
			&policyengine.LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "suspicious", Confidence: 0.9, Risk: 67, Injection: true},
			0.67, "suspicious (verdict benign"},
		"made itself unscannable": {
			&policyengine.LLMPackageInput{Disposition: "unscanned", Unscanned: true, UnscannedCode: "oversized", ContentAttributable: true, Risk: 25},
			0.25, "could not examine the package (oversized)"},
		"risk is clamped": {
			&policyengine.LLMPackageInput{Scanned: true, Verdict: "malicious", Disposition: "malicious", Risk: 250},
			1, "malicious"},
	} {
		res := evalLLMPackage(tc.in)
		if !res.present {
			t.Errorf("%s: expected the signal to be present", name)
			continue
		}
		if res.subscore < tc.subscore-1e-9 || res.subscore > tc.subscore+1e-9 {
			t.Errorf("%s: subscore = %v, want %v", name, res.subscore, tc.subscore)
		}
		if !strings.Contains(res.raw, tc.raw) {
			t.Errorf("%s: raw = %q, want it to contain %q", name, res.raw, tc.raw)
		}
		if res.detail["disposition"] == "" || res.detail["risk"] != tc.in.Risk {
			t.Errorf("%s: detail = %v", name, res.detail)
		}
	}

	// The breakdown never carries the model's free text: only categories.
	res := evalLLMPackage(&policyengine.LLMPackageInput{
		Scanned: true, Verdict: "malicious", Disposition: "malicious", Risk: 90, Reason: "PROXY SENTENCE",
		Findings: []policyengine.LLMPackageFinding{{Detail: "MODEL PROSE", Title: "t"}},
	})
	for k, v := range res.detail {
		if s, ok := v.(string); ok && (strings.Contains(s, "MODEL PROSE") || strings.Contains(s, "PROXY SENTENCE")) {
			t.Errorf("detail[%s] carries free text: %q", k, s)
		}
	}
	if strings.Contains(res.raw, "MODEL PROSE") {
		t.Errorf("raw carries the model's prose: %q", res.raw)
	}
}

func TestLLMPackageParticipatesInComposite(t *testing.T) {
	e := newEngine(t, Config{})
	score := func(l *policyengine.LLMPackageInput) Assessment {
		return e.Score(Subject{Input: policyengine.Input{
			Artifact:   policyengine.ArtifactInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"},
			Vuln:       &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"},
			LLMPackage: l,
		}})
	}
	benign := score(&policyengine.LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign", Confidence: 0.9})
	suspicious := score(&policyengine.LLMPackageInput{Scanned: true, Verdict: "suspicious", Disposition: "suspicious", Confidence: 0.8, Risk: 64})
	malicious := score(&policyengine.LLMPackageInput{Scanned: true, Verdict: "malicious", Disposition: "malicious", Confidence: 0.97, Risk: 99})
	absent := score(nil)

	if !(benign.Score < suspicious.Score && suspicious.Score < malicious.Score) {
		t.Errorf("composite must rise with the verdict: benign=%d suspicious=%d malicious=%d", benign.Score, suspicious.Score, malicious.Score)
	}
	if benign.Score != 0 {
		t.Errorf("a clean verdict on a clean artifact should score 0, got %d", benign.Score)
	}
	contribution := func(a Assessment) (Contribution, bool) {
		for _, c := range a.Contributions {
			if c.Signal == SignalLLMPackage {
				return c, true
			}
		}
		return Contribution{}, false
	}
	c, ok := contribution(malicious)
	if !ok || c.Weight != 0.20 {
		t.Fatalf("llmpkgscan contribution = %+v (present %v), want the default weight 0.20", c, ok)
	}
	if _, present := contribution(absent); present {
		t.Error("with no signal the gate must not appear in the breakdown")
	}

	// The weight is configurable, and a zero weight takes the signal out.
	heavy := newEngine(t, Config{Weights: Weights{Vulnerability: 1, LLMPackage: 5}})
	light := newEngine(t, Config{Weights: Weights{Vulnerability: 1, LLMPackage: 0.01}})
	in := Subject{Input: policyengine.Input{
		Vuln:       &policyengine.VulnInput{Scanned: true, MaxSeverity: "none"},
		LLMPackage: &policyengine.LLMPackageInput{Scanned: true, Verdict: "malicious", Disposition: "malicious", Risk: 99},
	}}
	if h, l := heavy.Score(in).Score, light.Score(in).Score; h <= l {
		t.Errorf("a heavier llmPackageScan weight should raise the score: heavy=%d light=%d", h, l)
	}
}

func TestLLMPackageWeightIsValidatedAndListed(t *testing.T) {
	if got := DefaultWeights().LLMPackage; got != 0.20 {
		t.Errorf("default llmPackageScan weight = %v, want 0.20", got)
	}
	if got := DefaultWeights().forSignal(SignalLLMPackage); got != 0.20 {
		t.Errorf("forSignal(llmpkgscan) = %v", got)
	}
	err := validateWeights(Weights{Vulnerability: 1, LLMPackage: -0.1})
	if err == nil || !strings.Contains(err.Error(), "llmPackageScan") {
		t.Errorf("a negative llmPackageScan weight: err = %v", err)
	}
	found := false
	for _, k := range allSignals {
		if k == SignalLLMPackage {
			found = true
		}
	}
	if !found {
		t.Error("llmpkgscan is not among the signals the engine evaluates")
	}
}
