package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// The unified risk-scoring engine (Task 37) runs after the policy-as-code gate
// over the same per-request admission accumulator. It folds every gate signal
// into one composite, explainable score and band, and — when an admission
// threshold is configured — warns on or blocks artifacts at/above a band. It
// composes with the policy engine rather than replacing it: the policy engine
// makes declarative rule decisions; the risk engine makes a single weighted-
// score decision. Either can deny; neither re-admits a hard-blocked artifact.
//
// Every served/blocked artifact is scored and recorded for trend visibility, so
// the gate runs even when the threshold action is "off" (observe-only).

// gateRiskScore scores the accumulated admission signals and applies the
// configured admission threshold. It returns true when the request may proceed
// and false when the artifact has been blocked and a 403 response written.
func (g *Gateway) gateRiskScore(w http.ResponseWriter, r *http.Request, name, ecosystem string) bool {
	if g.deps.RiskScore == nil {
		return true
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return true
	}
	s.mu.Lock()
	in := s.input
	s.mu.Unlock()

	a := g.deps.RiskScore.ScoreAndRecord(riskscore.Subject{Input: in})

	// Stash the risk verdict on the accumulator so the findings-aggregation layer
	// (Task 42) can include a threshold-exceeded finding in the SARIF export.
	s.mu.Lock()
	s.risk = riskSignal(a)
	s.mu.Unlock()

	// Always surface the score so clients and proxies downstream can observe it,
	// even when the threshold admits the artifact.
	w.Header().Set("X-Risk-Score", strconv.Itoa(a.Score))
	w.Header().Set("X-Risk-Band", string(a.Band))

	// Fold the composite risk into the request-level span so traces are
	// filterable by risk band and the score is visible alongside latency.
	tracing.SpanFromContext(r.Context()).SetAttributes(
		tracing.String("pullthrough.risk.band", string(a.Band)),
		tracing.Int("pullthrough.risk.score", a.Score),
	)

	g.auditRiskScore(r, name, ecosystem, a)

	switch a.Action {
	case riskscore.ThresholdBlock:
		g.deps.Logger.Warn("risk-score gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", a.Artifact.Name,
			"score", a.Score, "band", a.Band)
		g.notifyRiskScore(r, name, ecosystem, a)
		writeRiskScoreBlock(w, a)
		return false
	case riskscore.ThresholdWarn:
		g.deps.Logger.Info("risk-score gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", a.Artifact.Name,
			"score", a.Score, "band", a.Band)
		w.Header().Set("X-Risk-Decision", "warn")
		w.Header().Set("X-Risk-Reason", headerSafe(a.Summary))
		g.notifyRiskScore(r, name, ecosystem, a)
		return true
	default:
		return true
	}
}

// riskScoreError is the JSON body returned when the risk-score threshold blocks.
type riskScoreError struct {
	Error         string                   `json:"error"`
	Code          string                   `json:"code"`
	Score         int                      `json:"score"`
	Band          string                   `json:"band"`
	Threshold     string                   `json:"threshold"`
	Summary       string                   `json:"summary"`
	Contributions []riskscore.Contribution `json:"contributions"`
}

func writeRiskScoreBlock(w http.ResponseWriter, a riskscore.Assessment) {
	body := riskScoreError{
		Error:         "artifact blocked: composite supply-chain risk score above the admission threshold",
		Code:          "risk-score",
		Score:         a.Score,
		Band:          string(a.Band),
		Threshold:     string(a.ThresholdBand),
		Summary:       a.Summary,
		Contributions: a.Contributions,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Risk-Decision", "block")
	h.Set("X-Risk-Reason", headerSafe(a.Summary))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

func (g *Gateway) auditRiskScore(r *http.Request, backend, ecosystem string, a riskscore.Assessment) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionAllow
	if a.Block {
		decision = audit.DecisionDeny
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "riskscore:" + string(a.Band),
		Detail: map[string]any{
			"score":     a.Score,
			"band":      string(a.Band),
			"action":    string(a.Action),
			"threshold": string(a.ThresholdBand),
			"package":   a.Artifact.Name,
			"version":   a.Artifact.Version,
			"summary":   a.Summary,
		},
	}
	if a.Block {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) notifyRiskScore(r *http.Request, backend, ecosystem string, a riskscore.Assessment) {
	if g.deps.Notify == nil {
		return
	}
	coord := a.Artifact.Coordinate
	if coord == "" {
		coord = a.Artifact.Name
	}
	ev := notify.RiskScoreEvent(riskScoreSeverity(a.Band), ecosystem, backend, coord,
		string(a.Band), a.Score, string(a.Action), a.Summary)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// riskScoreSeverity maps a risk band to a notification severity.
func riskScoreSeverity(b riskscore.Band) notify.Severity {
	switch b {
	case riskscore.BandCritical:
		return notify.SeverityCritical
	case riskscore.BandHigh:
		return notify.SeverityHigh
	case riskscore.BandMedium:
		return notify.SeverityMedium
	default:
		return notify.SeverityLow
	}
}
