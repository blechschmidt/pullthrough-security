package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// gateMalfeed runs the known-malicious-package admission gate (Task 48) on a
// resolved coordinate. Like the name guard it needs no artifact content, so it
// runs between resolution and retrieval: a coordinate listed in a curated
// malware dataset (OpenSSF/OSV malicious-packages or a GitHub Advisory malware
// entry) — or, under a fail-closed policy, any pull while that feed is stale —
// is refused before any upstream fetch or cache fill. It returns true when the
// request may proceed and false when it has been blocked and a response has
// already been written.
func (g *Gateway) gateMalfeed(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Malfeed == nil {
		return true
	}
	coord, ok := malfeedCoordinateFor(ecosystem, resolved)
	if !ok {
		return true
	}

	decision := g.deps.Malfeed.Check(coord)
	if !decision.Blocked {
		return true
	}

	// Human-in-the-loop break-glass (Task 50): an operator may have granted a
	// time-boxed exception for this exact coordinate; serve it instead of refusing.
	if g.breakGlass(w, r, approvalGateMalfeed, name, ecosystem, malfeedCoordinate(coord), decision.Reason) {
		return true
	}

	g.metrics().IncPolicyDecision(ecosystem, "block")
	g.auditMalfeed(r, name, ecosystem, coord, decision)
	g.notifyMalfeed(r, name, ecosystem, coord, decision)
	g.deps.Logger.Warn("malfeed blocked known-malicious artifact",
		"backend", name, "ecosystem", ecosystem, "package", coord.Name, "version", coord.Version,
		"code", decision.Code, "advisory", decision.AdvisoryID(), "reason", decision.Reason)
	writeMalfeedBlock(w, coord, decision)
	return false
}

// malfeedCoordinateFor builds the gate's coordinate from a resolved resource,
// returning ok=false when no package name is available (the gate does not apply
// to nameless infrastructure requests). A version is optional; a version-less
// lookup is only ever blocked when the entire package is known malicious.
func malfeedCoordinateFor(ecosystem string, resolved *backends.Resolved) (malfeed.Coordinate, bool) {
	c := resolved.Coordinate
	if c.Name == "" {
		return malfeed.Coordinate{}, false
	}
	return malfeed.Coordinate{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
	}, true
}

// malfeedCoordinate renders a "name@version" coordinate for a malfeed match,
// falling back to the bare name when no version is present.
func malfeedCoordinate(c malfeed.Coordinate) string {
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// malfeedError is the JSON body returned when a pull is refused by the gate. It
// is actionable: the developer sees the advisory id, the malware class, and the
// reason the coordinate was refused.
type malfeedError struct {
	Error      string   `json:"error"`
	Code       string   `json:"code"`
	Reason     string   `json:"reason"`
	Ecosystem  string   `json:"ecosystem,omitempty"`
	Package    string   `json:"package,omitempty"`
	Version    string   `json:"version,omitempty"`
	Advisory   string   `json:"advisory,omitempty"`
	Aliases    []string `json:"aliases,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Source     string   `json:"source,omitempty"`
}

// writeMalfeedBlock writes an actionable 403 describing why the pull was refused.
func writeMalfeedBlock(w http.ResponseWriter, coord malfeed.Coordinate, d malfeed.Decision) {
	body := malfeedError{
		Error:     "package refused by known-malicious-package admission policy",
		Code:      d.Code,
		Reason:    d.Reason,
		Ecosystem: coord.Ecosystem,
		Package:   coord.Name,
		Version:   coord.Version,
		Advisory:  d.AdvisoryID(),
	}
	if d.Entry != nil {
		body.Aliases = d.Entry.Aliases
		body.Categories = d.Entry.Categories
		body.Source = d.Entry.Source
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Malfeed-Decision", "block")
	h.Set("X-Malfeed-Code", d.Code)
	if id := d.AdvisoryID(); id != "" {
		h.Set("X-Malfeed-Advisory", headerSafe(id))
	}
	h.Set("X-Malfeed-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditMalfeed records a known-malicious block in the tamper-evident audit log.
func (g *Gateway) auditMalfeed(r *http.Request, backend, ecosystem string, coord malfeed.Coordinate, d malfeed.Decision) {
	if g.deps.Audit == nil {
		return
	}
	detail := map[string]any{
		"code":     d.Code,
		"package":  coord.Name,
		"version":  coord.Version,
		"stale":    d.Stale,
		"advisory": d.AdvisoryID(),
	}
	if d.Entry != nil {
		detail["source"] = d.Entry.Source
		if len(d.Entry.Categories) > 0 {
			detail["categories"] = strings.Join(d.Entry.Categories, ",")
		}
		if len(d.Entry.Aliases) > 0 {
			detail["aliases"] = strings.Join(d.Entry.Aliases, ",")
		}
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
		Reason:     "malfeed:" + d.Code,
		Detail:     detail,
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyMalfeed emits a critical security alert for a known-malicious block.
func (g *Gateway) notifyMalfeed(r *http.Request, backend, ecosystem string, coord malfeed.Coordinate, d malfeed.Decision) {
	if g.deps.Notify == nil {
		return
	}
	artifact := coord.Name
	if coord.Version != "" {
		artifact = coord.Name + "@" + coord.Version
	}
	categories := ""
	if d.Entry != nil {
		categories = strings.Join(d.Entry.Categories, ",")
	}
	ev := notify.MaliciousBlockEvent(ecosystem, backend, artifact, d.AdvisoryID(), d.Code, categories, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
