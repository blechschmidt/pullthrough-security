package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// gatePolicy applies the admission policy to a resolved artifact. It is the
// security middleware that sits between resolution and serving (Task 9): a
// blocked artifact is refused here, before any cache lookup or upstream fetch, so
// risky content never enters the cache. It returns true when the request may
// proceed (allow or warn) and false when it has been blocked and a response has
// already been written.
//
// Policy applies only to concrete, versioned artifacts — identified by a resolved
// Coordinate carrying both a name and a version. Mutable index documents (package
// listings, service indexes) carry no such coordinate and are passed through
// untouched: they are revalidated metadata, not the supply-chain payload being
// gated.
func (g *Gateway) gatePolicy(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Policy == nil {
		return true
	}
	art, ok := artifactFor(ecosystem, name, resolved)
	if !ok {
		return true
	}

	decision := g.deps.Policy.Evaluate(r.Context(), art)
	recordProvenanceSignal(r.Context(), decision.Assessment)
	action := decision.Action
	if action == "" {
		action = policy.ActionAllow
	}
	g.metrics().IncPolicyDecision(ecosystem, string(action))
	switch decision.Action {
	case policy.ActionBlock:
		// Human-in-the-loop break-glass (Task 50): an operator may have granted a
		// time-boxed exception for this coordinate; serve it instead of refusing.
		if g.breakGlass(w, r, approvalGatePolicy, name, ecosystem, art.String(), decision.Reason) {
			return true
		}
		g.auditPolicy(r, name, ecosystem, decision)
		g.deps.Logger.Warn("policy blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.String(),
			"code", decision.Code, "reason", decision.Reason)
		g.notifyPolicyBlock(r, name, ecosystem, art, decision)
		writePolicyBlock(w, decision)
		return false
	case policy.ActionWarn:
		g.auditPolicy(r, name, ecosystem, decision)
		g.deps.Logger.Warn("policy warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.String(),
			"code", decision.Code, "reason", decision.Reason)
		// Surface the warning to the client without breaking the pull. The header is
		// advisory; the artifact is still served.
		w.Header().Set("X-Policy-Decision", "warn")
		w.Header().Set("X-Policy-Reason", headerSafe(decision.Reason))
		return true
	default:
		return true
	}
}

// artifactFor builds the policy artifact from a resolved resource, returning
// ok=false when the resource is not a concrete versioned artifact (so policy does
// not apply).
func artifactFor(ecosystem, backend string, resolved *backends.Resolved) (policy.Artifact, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return policy.Artifact{}, false
	}
	return policy.Artifact{
		Ecosystem: ecosystem,
		Backend:   backend,
		Name:      c.Name,
		Version:   c.Version,
		Digest:    resolved.Digest,
	}, true
}

// policyError is the JSON body returned to a client when an artifact is blocked.
// It is deliberately actionable: the client (a developer's package manager, or
// the developer reading the failed install) gets the coordinate, the machine
// reason code, and a human explanation of how to proceed.
type policyError struct {
	Error      string `json:"error"`
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Package    string `json:"package,omitempty"`
	Version    string `json:"version,omitempty"`
	CommitSHA  string `json:"commitSha,omitempty"`
	RiskScore  int    `json:"riskScore,omitempty"`
	Confidence string `json:"provenanceConfidence,omitempty"`
}

// writePolicyBlock writes an actionable 403 response describing why the artifact
// was refused. The status is 403 Forbidden: the request was understood and
// authenticated but admission policy forbids serving this content.
func writePolicyBlock(w http.ResponseWriter, d policy.Decision) {
	body := policyError{
		Error:      "artifact blocked by supply-chain admission policy",
		Code:       d.Code,
		Reason:     d.Reason,
		Ecosystem:  d.Artifact.Ecosystem,
		Package:    d.Artifact.Name,
		Version:    d.Artifact.Version,
		CommitSHA:  d.Assessment.CommitSHA,
		RiskScore:  d.Assessment.RiskScore,
		Confidence: d.Assessment.Confidence,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Policy-Decision", "block")
	h.Set("X-Policy-Code", d.Code)
	h.Set("X-Policy-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditPolicy records a policy decision in the tamper-evident audit log.
func (g *Gateway) auditPolicy(r *http.Request, backend, ecosystem string, d policy.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == policy.ActionWarn {
		decision = audit.DecisionAllow
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     d.Code,
		Detail: map[string]any{
			"action":     string(d.Action),
			"code":       d.Code,
			"package":    d.Artifact.Name,
			"version":    d.Artifact.Version,
			"commitSha":  d.Assessment.CommitSHA,
			"riskScore":  d.Assessment.RiskScore,
			"confidence": d.Assessment.Confidence,
		},
	}
	if d.Action == policy.ActionBlock {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyPolicyBlock dispatches a security alert for a policy block. A block
// caused by a provenance signature/attestation requirement is surfaced as the
// more specific provenance-failure event so operators can route it
// independently; every other block is a generic policy-block alert.
func (g *Gateway) notifyPolicyBlock(r *http.Request, backend, ecosystem string, art policy.Artifact, d policy.Decision) {
	if g.deps.Notify == nil {
		return
	}
	var ev notify.Event
	switch d.Code {
	case "signature-required", "attestation-required", "low-confidence":
		ev = notify.ProvenanceFailureEvent(ecosystem, backend, art.String(), d.Code, d.Reason)
	default:
		ev = notify.PolicyBlockEvent(ecosystem, backend, art.String(), d.Code, d.Reason)
	}
	if d.Assessment.CommitSHA != "" {
		ev = ev.WithField("commitSha", d.Assessment.CommitSHA)
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// headerSafe strips control characters (CR/LF in particular) from a string so it
// cannot inject additional response headers (HTTP response splitting).
func headerSafe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			out = append(out, ' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
	}
	const max = 400
	if len(out) > max {
		out = out[:max]
	}
	return string(out)
}
