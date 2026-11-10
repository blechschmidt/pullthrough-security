package proxy

import (
	"context"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// SIEMForwarder is the narrow gateway-facing surface of the SIEM / log-forwarding
// subsystem (Task 119). The gateway forwards a normalized findings document to
// it after the admission gates run; the implementation enqueues one event per
// finding for asynchronous, non-blocking delivery to external SIEM sinks. It is
// an interface (rather than the concrete *siem.Forwarder) so the proxy package
// does not depend on the siem package and so a true-nil value disables it.
type SIEMForwarder interface {
	ForwardFindings(ctx context.Context, doc findings.Document)
}

// The SARIF findings-aggregation layer (Task 42) records, after the admission
// gates have run for a request, a normalized findings document keyed by the
// artifact's (tenant, coordinate). It reuses the same per-request signal
// accumulator the policy-as-code and risk-scoring gates evaluate, so it adds no
// new scanning work — it only re-projects what the gates already computed into
// the canonical findings model and retains it for the SARIF export endpoint/CLI.
//
// recordFindings runs on every exit path of a gated pull (admitted or blocked),
// via a deferred call in handleBackend, so a CI pipeline can retrieve the
// findings that explain a block just as readily as those on an admitted artifact.
// It is best-effort and never affects serving.

// recordFindings normalizes the accumulated admission signals into a findings
// document and stores it. It is a no-op when the findings store is absent or the
// request never accumulated signals (e.g. a non-gated or unresolved request).
func (g *Gateway) recordFindings(r *http.Request) {
	if g.deps.Findings == nil {
		return
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return
	}
	s.mu.Lock()
	in := s.input
	opts := findings.Options{Risk: s.risk, Policy: s.policy}
	s.mu.Unlock()

	// Only retain a document that has an addressable artifact; a bare path with no
	// resolved coordinate would be unaddressable by the lookup endpoint anyway.
	if in.Artifact.Name == "" {
		return
	}
	doc := findings.FromInput(in, opts)

	// De-duplicate overlapping findings before recording (Task 165): multiple
	// gates can emit the same logical finding for one coordinate+digest (a secret
	// surfaced by both commit scanning and content analysis, a CVE surfaced by both
	// the scanner and the remediation advisor). Collapsing them here — ahead of the
	// store, the SIEM forward, the dossier, and SARIF export, all of which read the
	// recorded document — keeps the risk picture from double-counting while
	// preserving each contributing gate's provenance in the merged finding.
	stats := doc.Deduplicate()
	g.deps.FindingsMetrics.RecordDedup(stats)

	// Record the suppression audit trail (Task 165): capture who/what suppressed
	// each finding (VEX, reachability downgrade, policy) and why, queryable per
	// coordinate and mirrored into the tamper-evident audit log. Best-effort.
	g.deps.Suppressions.RecordFromDocument(r.Context(), &doc)

	g.deps.Findings.Record(doc)

	// Stream the findings to an external SIEM, when configured (Task 119). This is
	// best-effort and non-blocking: the forwarder enqueues each finding and never
	// blocks or fails the serving path.
	if g.deps.SIEM != nil {
		g.deps.SIEM.ForwardFindings(r.Context(), doc)
	}
}

// riskSignal projects a riskscore.Assessment onto the neutral findings.RiskSignal
// so the findings layer need not import the riskscore package.
func riskSignal(a riskscore.Assessment) *findings.RiskSignal {
	return &findings.RiskSignal{
		Score:   a.Score,
		Band:    string(a.Band),
		Exceeds: a.Exceeds,
		Action:  string(a.Action),
		Summary: a.Summary,
	}
}

// policySignal projects a policyengine.Result onto the neutral
// findings.PolicySignal, carrying only the matched rules and their effects.
func policySignal(res policyengine.Result) *findings.PolicySignal {
	sig := &findings.PolicySignal{
		Action: string(res.EffectiveAction),
		Reason: res.Decision.Reason,
	}
	for _, m := range res.Decision.Matches {
		sig.Matches = append(sig.Matches, findings.PolicyMatch{
			RuleID: m.RuleID,
			Action: string(m.Action),
			Reason: m.Message,
		})
	}
	return sig
}
