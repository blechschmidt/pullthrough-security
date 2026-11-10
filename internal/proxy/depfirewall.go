package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// gateDepFirewall runs the dependency-firewall version-policy admission gate
// (Task 65) on a resolved coordinate. Like the name guard and maturity gates it
// needs no artifact content — only the concrete (ecosystem, name, version) — so
// it runs early, between resolution and retrieval: a version outside the
// tenant's approved set (not pinned, out of every allowed range, below the
// minimum-version floor, denylisted, or — in deny-by-default mode — an ungoverned
// coordinate) is refused before any upstream fetch or cache fill. This turns the
// proxy into a guarantee that CI can only fetch operator-approved (e.g.
// lockfile-resolved) versions. It returns true when the request may proceed and
// false when it has been blocked and a response has already been written.
func (g *Gateway) gateDepFirewall(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.DepFirewall == nil {
		return true
	}
	coord, ok := depFirewallCoordinateFor(ecosystem, resolved)
	if !ok {
		return true
	}

	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}

	decision := g.deps.DepFirewall.Check(tenant, coord)
	if !decision.Blocked {
		return true
	}

	// Human-in-the-loop break-glass (Task 50): an operator may have granted a
	// time-boxed exception for this exact coordinate; serve it instead of refusing.
	if g.breakGlass(w, r, approvalGateDepFirewall, name, ecosystem, depFirewallCoordinate(coord), decision.Code) {
		return true
	}

	g.metrics().IncPolicyDecision(ecosystem, "block")
	g.auditDepFirewall(r, name, ecosystem, coord, decision)
	g.notifyDepFirewall(r, name, ecosystem, coord, decision)
	g.deps.Logger.Warn("dependency firewall blocked version outside the approved set",
		"backend", name, "ecosystem", ecosystem, "package", coord.Name, "version", coord.Version,
		"code", decision.Code, "reason", decision.Reason)
	writeDepFirewallBlock(w, coord, decision)
	return false
}

// depFirewallCoordinateFor builds the gate's coordinate from a resolved
// resource, returning ok=false when no concrete (name, version) is available: an
// index or listing request has no single artifact to gate, so it is admitted.
func depFirewallCoordinateFor(ecosystem string, resolved *backends.Resolved) (depfirewall.Coordinate, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return depfirewall.Coordinate{}, false
	}
	return depfirewall.Coordinate{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
	}, true
}

// depFirewallCoordinate renders a "name@version" coordinate for a block.
func depFirewallCoordinate(c depfirewall.Coordinate) string {
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// depFirewallError is the JSON body returned when a pull is refused by the
// firewall. It is actionable: the developer sees which constraint fired and the
// approved set (pinned versions, ranges, floor) the version failed.
type depFirewallError struct {
	Error      string   `json:"error"`
	Code       string   `json:"code"`
	Reason     string   `json:"reason"`
	Ecosystem  string   `json:"ecosystem,omitempty"`
	Package    string   `json:"package,omitempty"`
	Version    string   `json:"version,omitempty"`
	Pinned     []string `json:"pinned,omitempty"`
	Ranges     []string `json:"ranges,omitempty"`
	MinVersion string   `json:"minVersion,omitempty"`
}

// writeDepFirewallBlock writes an actionable 403 describing why the pull was
// refused.
func writeDepFirewallBlock(w http.ResponseWriter, coord depfirewall.Coordinate, d depfirewall.Decision) {
	body := depFirewallError{
		Error:      "package version refused by the dependency-firewall (version policy) admission gate",
		Code:       d.Code,
		Reason:     d.Reason,
		Ecosystem:  coord.Ecosystem,
		Package:    coord.Name,
		Version:    coord.Version,
		Pinned:     d.Pinned,
		Ranges:     d.Ranges,
		MinVersion: d.MinVersion,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Depfirewall-Decision", "block")
	h.Set("X-Depfirewall-Code", d.Code)
	h.Set("X-Depfirewall-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditDepFirewall records a dependency-firewall block in the tamper-evident
// audit log.
func (g *Gateway) auditDepFirewall(r *http.Request, backend, ecosystem string, coord depfirewall.Coordinate, d depfirewall.Decision) {
	if g.deps.Audit == nil {
		return
	}
	detail := map[string]any{
		"package": coord.Name,
		"version": coord.Version,
		"code":    d.Code,
	}
	if d.RuleSource != "" {
		detail["ruleSource"] = d.RuleSource
	}
	if len(d.Pinned) > 0 {
		detail["pinned"] = d.Pinned
	}
	if len(d.Ranges) > 0 {
		detail["ranges"] = d.Ranges
	}
	if d.MinVersion != "" {
		detail["minVersion"] = d.MinVersion
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   audit.DecisionDeny,
		Status:     http.StatusForbidden,
		Reason:     "depfirewall:" + d.Code,
		Detail:     detail,
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyDepFirewall emits a security alert for a dependency-firewall block.
func (g *Gateway) notifyDepFirewall(r *http.Request, backend, ecosystem string, coord depfirewall.Coordinate, d depfirewall.Decision) {
	if g.deps.Notify == nil {
		return
	}
	artifact := coord.Name
	if coord.Version != "" {
		artifact = coord.Name + "@" + coord.Version
	}
	ev := notify.DepFirewallEvent(ecosystem, backend, artifact, d.Code, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
