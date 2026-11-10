package riskscore

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func TestEvalRepoHealth_AppliesInverseHealth(t *testing.T) {
	// An unresolved (or unevaluated) repo contributes nothing.
	for _, h := range []*policyengine.RepoHealthInput{
		nil,
		{Evaluated: false},
		{Evaluated: true, Resolved: false},
	} {
		if res := evalRepoHealth(h); res.present {
			t.Errorf("expected unresolved repo health to be absent, got %+v", res)
		}
	}

	// A resolved, unhealthy repo (risk 80) is a high sub-score.
	res := evalRepoHealth(&policyengine.RepoHealthInput{
		Evaluated: true, Resolved: true, Health: 20, Risk: 80, Grade: "F",
		Weak: []string{"signed-commits", "ci"},
	})
	if !res.present {
		t.Fatal("expected resolved repo health to be present")
	}
	if res.subscore < 0.79 || res.subscore > 0.81 {
		t.Errorf("expected sub-score ~0.8 for risk 80, got %v", res.subscore)
	}
}

func TestRepoHealthParticipatesInComposite(t *testing.T) {
	e, err := New(Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	unhealthy := e.Score(Subject{Input: policyengine.Input{
		RepoHealth: &policyengine.RepoHealthInput{Evaluated: true, Resolved: true, Health: 10, Risk: 90, Grade: "F"},
	}})
	healthy := e.Score(Subject{Input: policyengine.Input{
		RepoHealth: &policyengine.RepoHealthInput{Evaluated: true, Resolved: true, Health: 95, Risk: 5, Grade: "A"},
	}})
	if unhealthy.Score <= healthy.Score {
		t.Errorf("an unhealthy source repo should raise composite risk: unhealthy=%d healthy=%d",
			unhealthy.Score, healthy.Score)
	}
	// The repohealth signal must appear in the explainable breakdown.
	found := false
	for _, c := range unhealthy.Contributions {
		if c.Signal == SignalRepoHealth {
			found = true
		}
	}
	if !found {
		t.Error("expected repohealth contribution in the breakdown")
	}
}
