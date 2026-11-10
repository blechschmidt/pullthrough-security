package proxy

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// The policy & risk what-if replay harness (Task 47) captures, after the
// admission gates run for a request, the per-request admission document together
// with the verdict the live configuration produced. It reuses the same signal
// accumulator the policy-as-code, risk-scoring, and findings layers read, so it
// adds no scanning work — it only re-projects what the gates already computed and
// hands it to the bounded, sampled, redacted ring buffer.
//
// captureSimReplay runs deferred on every gated pull (admitted or blocked), so a
// later replay can show how a candidate config would have treated both. It is
// best-effort and never affects serving.
func (g *Gateway) captureSimReplay(r *http.Request) {
	if !g.deps.SimReplay.Enabled() {
		return
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return
	}
	s.mu.Lock()
	in := s.input
	pol := s.policy
	rsk := s.risk
	s.mu.Unlock()

	// Only capture an addressable artifact; a bare path with no resolved
	// coordinate would be meaningless to replay.
	if in.Artifact.Name == "" {
		return
	}

	v := simreplay.Verdict{}
	if pol != nil {
		v.PolicyEnabled = true
		// findings.PolicySignal carries the effective action and matched rules as
		// strings; project them back onto the typed verdict the harness diffs.
		v.PolicyAction = policyengine.Action(pol.Action)
		v.PolicyReason = pol.Reason
		for _, m := range pol.Matches {
			v.PolicyMatches = append(v.PolicyMatches, simreplay.VerdictMatch{
				RuleID: m.RuleID,
				Action: policyengine.Action(m.Action),
			})
		}
	}
	if rsk != nil {
		v.RiskEnabled = true
		v.RiskScore = rsk.Score
		v.RiskBand = riskscore.Band(rsk.Band)
		v.RiskAction = riskscore.ThresholdAction(rsk.Action)
		v.RiskExceeds = rsk.Exceeds
	}

	g.deps.SimReplay.Observe(in, v)
}
