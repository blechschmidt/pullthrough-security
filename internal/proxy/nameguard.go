package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// gateNameguard runs the typosquatting & dependency-confusion admission gate
// (Task 19) on a resolved coordinate. It is a name-based check that needs no
// artifact content, so — like the provenance policy gate — it runs between
// resolution and retrieval: a blocked look-alike or namespace-shadowing package
// is refused before any upstream fetch or cache fill. It returns true when the
// request may proceed (allow or warn) and false when it has been blocked and a
// response has already been written.
//
// Unlike the provenance/vulnerability gates, the guard applies as soon as a name
// is known — a version is not required — so a typosquat is caught at index lookup,
// before any specific artifact is downloaded.
func (g *Gateway) gateNameguard(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.NameGuard == nil {
		return true
	}
	art, ok := nameguardArtifactFor(ecosystem, resolved)
	if !ok {
		return true
	}

	report := g.deps.NameGuard.Inspect(art)
	recordNameguardSignal(r.Context(), report)
	decision := g.deps.NameGuard.Gate(report)
	switch decision.Action {
	case policy.ActionBlock, policy.ActionQuarantine:
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditNameguard(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("nameguard blocked artifact",
			"backend", name, "ecosystem", ecosystem, "package", art.Name,
			"code", decision.Code, "reason", decision.Reason)
		writeNameguardBlock(w, art, report, decision)
		return false
	case policy.ActionWarn:
		g.metrics().IncPolicyDecision(ecosystem, "warn")
		g.auditNameguard(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("nameguard warning on artifact",
			"backend", name, "ecosystem", ecosystem, "package", art.Name,
			"code", decision.Code, "reason", decision.Reason)
		w.Header().Set("X-Nameguard-Decision", "warn")
		w.Header().Set("X-Nameguard-Code", decision.Code)
		w.Header().Set("X-Nameguard-Reason", headerSafe(decision.Reason))
		return true
	default:
		return true
	}
}

// nameguardArtifactFor builds the guard's coordinate from a resolved resource,
// returning ok=false when no package name is available (so the guard does not
// apply to nameless infrastructure requests). A version is optional.
func nameguardArtifactFor(ecosystem string, resolved *backends.Resolved) (nameguard.Artifact, bool) {
	c := resolved.Coordinate
	if c.Name == "" {
		return nameguard.Artifact{}, false
	}
	return nameguard.Artifact{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
	}, true
}

// nameguardError is the JSON body returned when a pull is refused by the guard.
// It is actionable: the developer sees which heuristic fired, the legitimate
// package they likely meant, and why the name was flagged.
type nameguardError struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	// DidYouMean is the legitimate/internal name the flagged package resembles.
	DidYouMean string              `json:"didYouMean,omitempty"`
	Findings   []nameguard.Finding `json:"findings,omitempty"`
}

// writeNameguardBlock writes an actionable 403 describing why the pull was
// refused.
func writeNameguardBlock(w http.ResponseWriter, art nameguard.Artifact, report *nameguard.Report, d nameguard.Decision) {
	body := nameguardError{
		Error:     "package refused by typosquatting / dependency-confusion admission policy",
		Code:      d.Code,
		Action:    string(d.Action),
		Reason:    d.Reason,
		Ecosystem: art.Ecosystem,
		Package:   art.Name,
		Version:   art.Version,
	}
	if d.Highest != nil {
		body.DidYouMean = d.Highest.Similar
	}
	if report != nil {
		body.Findings = report.Findings
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Nameguard-Decision", string(d.Action))
	h.Set("X-Nameguard-Code", d.Code)
	h.Set("X-Nameguard-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditNameguard records a name-guard decision in the tamper-evident audit log.
func (g *Gateway) auditNameguard(r *http.Request, backend, ecosystem string, art nameguard.Artifact, report *nameguard.Report, d nameguard.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == policy.ActionWarn {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":  string(d.Action),
		"code":    d.Code,
		"package": art.Name,
		"version": art.Version,
	}
	if d.Highest != nil {
		detail["kind"] = string(d.Highest.Kind)
		detail["severity"] = string(d.Highest.Severity)
		detail["similar"] = d.Highest.Similar
		if d.Highest.Distance > 0 {
			detail["distance"] = d.Highest.Distance
		}
	}
	if report != nil {
		detail["findings"] = len(report.Findings)
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "nameguard:" + d.Code,
		Detail:     detail,
	}
	if d.Action.Blocked() {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}
