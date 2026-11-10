package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// gateMaturity runs the release-maturity / version-cooldown admission gate (Task
// 61) on a resolved coordinate. Like the name guard and malfeed gate it needs no
// artifact content — only the publish timestamp derived from the upstream
// registry metadata — so it runs between resolution and retrieval: a version
// published less than the configured cooldown window ago is quarantined before
// any upstream fetch or cache fill. This blunts fast-moving supply-chain attacks
// where a malicious version is published and yanked within hours. It returns true
// when the request may proceed and false when it has been blocked and a response
// has already been written.
func (g *Gateway) gateMaturity(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Maturity == nil {
		return true
	}
	coord, ok := maturityCoordinateFor(ecosystem, resolved)
	if !ok {
		return true
	}

	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}

	decision := g.deps.Maturity.Check(tenant, coord)
	if !decision.Cooling {
		return true
	}

	// Human-in-the-loop break-glass (Task 50): an operator may have granted a
	// time-boxed exception to release this still-cooling version; serve it instead
	// of refusing.
	if g.breakGlass(w, r, approvalGateMaturity, name, ecosystem, maturityCoordinate(coord), decision.Reason) {
		return true
	}

	g.metrics().IncPolicyDecision(ecosystem, "block")
	g.auditMaturity(r, name, ecosystem, coord, decision)
	g.notifyMaturity(r, name, ecosystem, coord, decision)
	g.deps.Logger.Warn("maturity gate quarantined newly-published version",
		"backend", name, "ecosystem", ecosystem, "package", coord.Name, "version", coord.Version,
		"remaining", decision.Remaining.String(), "cooldown", decision.Cooldown.String(),
		"unknown", decision.Unknown, "reason", decision.Reason)
	writeMaturityBlock(w, coord, decision)
	return false
}

// maturityCoordinateFor builds the gate's coordinate from a resolved resource,
// returning ok=false when no concrete (name, version) is available: an index or
// listing request has nothing to age, so it is always admitted by this gate.
func maturityCoordinateFor(ecosystem string, resolved *backends.Resolved) (maturity.Coordinate, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return maturity.Coordinate{}, false
	}
	return maturity.Coordinate{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
	}, true
}

// maturityCoordinate renders a "name@version" coordinate for a cooldown block.
func maturityCoordinate(c maturity.Coordinate) string {
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// maturityError is the JSON body returned when a pull is held by the cooldown
// gate. It is actionable: the developer sees how long the version has been
// published, the cooldown window, and when it will be released.
type maturityError struct {
	Error            string  `json:"error"`
	Code             string  `json:"code"`
	Reason           string  `json:"reason"`
	Ecosystem        string  `json:"ecosystem,omitempty"`
	Package          string  `json:"package,omitempty"`
	Version          string  `json:"version,omitempty"`
	PublishedAt      string  `json:"publishedAt,omitempty"`
	CooldownSeconds  float64 `json:"cooldownSeconds,omitempty"`
	RemainingSeconds float64 `json:"remainingSeconds,omitempty"`
	AvailableAt      string  `json:"availableAt,omitempty"`
}

// writeMaturityBlock writes an actionable 403 describing why the pull is held.
func writeMaturityBlock(w http.ResponseWriter, coord maturity.Coordinate, d maturity.Decision) {
	code := "cooling"
	if d.Unknown {
		code = "publish-time-unknown"
	}
	body := maturityError{
		Error:           "package version held by release-maturity (version-cooldown) admission policy",
		Code:            code,
		Reason:          d.Reason,
		Ecosystem:       coord.Ecosystem,
		Package:         coord.Name,
		Version:         coord.Version,
		CooldownSeconds: d.Cooldown.Seconds(),
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Maturity-Decision", "block")
	h.Set("X-Maturity-Code", code)
	h.Set("X-Maturity-Reason", headerSafe(d.Reason))
	if !d.Unknown {
		body.RemainingSeconds = d.Remaining.Seconds()
		if !d.PublishedAt.IsZero() {
			body.PublishedAt = d.PublishedAt.UTC().Format(http.TimeFormat)
		}
		if avail := d.AvailableAt(); !avail.IsZero() {
			body.AvailableAt = avail.UTC().Format(http.TimeFormat)
			h.Set("Retry-After", headerSafe(avail.UTC().Format(http.TimeFormat)))
		}
	}
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditMaturity records a cooldown block in the tamper-evident audit log.
func (g *Gateway) auditMaturity(r *http.Request, backend, ecosystem string, coord maturity.Coordinate, d maturity.Decision) {
	if g.deps.Audit == nil {
		return
	}
	detail := map[string]any{
		"package":          coord.Name,
		"version":          coord.Version,
		"unknown":          d.Unknown,
		"cooldownSeconds":  d.Cooldown.Seconds(),
		"remainingSeconds": d.Remaining.Seconds(),
	}
	if !d.PublishedAt.IsZero() {
		detail["publishedAt"] = d.PublishedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	reason := "maturity:cooling"
	if d.Unknown {
		reason = "maturity:publish-time-unknown"
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
		Reason:     reason,
		Detail:     detail,
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyMaturity emits a security alert for a release-cooldown block.
func (g *Gateway) notifyMaturity(r *http.Request, backend, ecosystem string, coord maturity.Coordinate, d maturity.Decision) {
	if g.deps.Notify == nil {
		return
	}
	artifact := coord.Name
	if coord.Version != "" {
		artifact = coord.Name + "@" + coord.Version
	}
	ev := notify.MaturityEvent(ecosystem, backend, artifact, d.Remaining, d.Cooldown, d.Unknown, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
