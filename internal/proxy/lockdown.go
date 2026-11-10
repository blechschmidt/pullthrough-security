package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// The emergency-lockdown / global kill-switch incident-response control (Task 74)
// is the very FIRST check on the pull path, ahead of every other admission gate.
// It plays three roles:
//
//   - gateLockdown runs before the name guard. A targeted `block` lockdown denies
//     a specific (eco,name[,version]) coordinate everywhere — the fast path for a
//     freshly-disclosed malicious package, ahead of the malfeed feed refresh — and
//     composes with the break-glass workflow. A `strict` lockdown is recorded as an
//     admission signal the aggregating policy/risk engines consume (it never refuses
//     the coordinate outright). A `freeze` lockdown does not refuse here (cache hits
//     must still serve); it is enforced at the upstream-fetch boundary.
//
//   - lockdownBlocksFetch is consulted inside the cache loader: under a `freeze`
//     lockdown the proxy serves only already-cached artifacts and refuses any new
//     upstream fetch, pinning the org to last-known-good content during an incident.

// gateLockdown is the FIRST pull-path admission check. It returns true when the
// request may proceed and false when it has been blocked and a response written.
func (g *Gateway) gateLockdown(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Lockdown == nil || !g.deps.Lockdown.Enabled() {
		return true
	}
	c := resolved.Coordinate
	dec := g.deps.Lockdown.Check(lockdown.Coordinate{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
	})
	if !dec.Blocked {
		return true
	}

	coordinate := c.Name
	if c.Version != "" {
		coordinate = c.Name + "@" + c.Version
	}

	// Human-in-the-loop break-glass (Task 50): even during a lockdown an operator
	// may have granted a time-boxed, dual-control exception for this exact
	// coordinate; serve it instead of refusing.
	if g.breakGlass(w, r, approvalGateLockdown, name, ecosystem, coordinate, dec.Code) {
		return true
	}

	g.metrics().IncPolicyDecision(ecosystem, "block")
	g.auditLockdown(r, name, ecosystem, coordinate, dec)
	g.notifyLockdown(r, name, ecosystem, coordinate, dec)
	g.deps.Logger.Warn("emergency lockdown blocked pull",
		"backend", name, "ecosystem", ecosystem, "package", c.Name, "version", c.Version,
		"mode", dec.Mode, "incident", dec.IncidentID, "reason", dec.Reason)
	writeLockdownBlock(w, ecosystem, coordinate, dec)
	return false
}

// recordLockdownSignal folds the active lockdown posture into the per-request
// admission accumulator so the aggregating policy and risk engines can react to
// an incident (most usefully `has(input.incident) && input.incident.strict`). It
// is best-effort and runs alongside withAdmissionSignals.
func (g *Gateway) recordLockdownSignal(r *http.Request) {
	if g.deps.Lockdown == nil || !g.deps.Lockdown.Enabled() {
		return
	}
	mode := g.deps.Lockdown.Mode()
	if mode == lockdown.ModeOff {
		return
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return
	}
	s.mu.Lock()
	s.input.Incident = &policyengine.IncidentInput{
		Active:     true,
		Mode:       string(mode),
		Strict:     mode == lockdown.ModeStrict,
		IncidentID: g.deps.Lockdown.IncidentID(),
	}
	s.mu.Unlock()
}

// lockdownBlocksFetch reports whether a freeze lockdown is active. The cache
// loader consults it before performing an upstream fetch: under a freeze, a cache
// miss must not reach the upstream — only already-cached content is served.
func (g *Gateway) lockdownBlocksFetch() bool {
	return g.deps.Lockdown != nil && g.deps.Lockdown.FreezeActive()
}

// lockdownError is the actionable JSON body returned when a pull is refused by an
// emergency lockdown.
type lockdownError struct {
	Error      string `json:"error"`
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	Mode       string `json:"mode,omitempty"`
	IncidentID string `json:"incidentId,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Coordinate string `json:"coordinate,omitempty"`
}

func writeLockdownBlock(w http.ResponseWriter, ecosystem, coordinate string, dec lockdown.Decision) {
	body := lockdownError{
		Error:      "pull refused by an active emergency lockdown (incident-response mode)",
		Code:       dec.Code,
		Reason:     dec.Reason,
		Mode:       string(dec.Mode),
		IncidentID: dec.IncidentID,
		Ecosystem:  ecosystem,
		Coordinate: coordinate,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Lockdown-Decision", "block")
	h.Set("X-Lockdown-Mode", string(dec.Mode))
	if dec.IncidentID != "" {
		h.Set("X-Lockdown-Incident", headerSafe(dec.IncidentID))
	}
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// writeLockdownFreezeError refuses a cache miss under an active freeze lockdown:
// the artifact is not already cached, and a freeze forbids the upstream fetch
// that would be needed to serve it.
func writeLockdownFreezeError(w http.ResponseWriter, r *http.Request, g *Gateway, name, ecosystem string, resolved *backends.Resolved) {
	coordinate := resolved.Coordinate.Name
	if v := resolved.Coordinate.Version; v != "" {
		coordinate = coordinate + "@" + v
	}
	dec := lockdown.Decision{
		Code:       lockdown.CodeFreeze,
		Reason:     "this artifact is not already cached and a freeze lockdown forbids new upstream fetches; serving only last-known-good cached content",
		Mode:       lockdown.ModeFreeze,
		IncidentID: g.deps.Lockdown.IncidentID(),
	}
	g.deps.Lockdown.RecordFreezeFetchBlock()
	g.metrics().IncPolicyDecision(ecosystem, "block")
	g.auditLockdown(r, name, ecosystem, coordinate, dec)
	g.notifyLockdown(r, name, ecosystem, coordinate, dec)
	g.deps.Logger.Warn("emergency lockdown (freeze) blocked upstream fetch on cache miss",
		"backend", name, "ecosystem", ecosystem, "coordinate", coordinate, "incident", dec.IncidentID)
	body := lockdownError{
		Error:      "pull refused: a freeze lockdown serves only already-cached artifacts and forbids new upstream fetches",
		Code:       dec.Code,
		Reason:     dec.Reason,
		Mode:       string(dec.Mode),
		IncidentID: dec.IncidentID,
		Ecosystem:  ecosystem,
		Coordinate: coordinate,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Lockdown-Decision", "freeze-block")
	h.Set("X-Lockdown-Mode", string(dec.Mode))
	if dec.IncidentID != "" {
		h.Set("X-Lockdown-Incident", headerSafe(dec.IncidentID))
	}
	h.Set("X-Cache", "MISS-BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// errLockdownFreeze is the sentinel the cache loader returns to signal that an
// upstream fetch was refused by a freeze lockdown (distinguished from a real
// upstream error so the gateway can render the actionable freeze response).
type lockdownFreezeError struct{}

func (lockdownFreezeError) Error() string {
	return "lockdown: upstream fetch refused by an active freeze lockdown"
}

func (g *Gateway) auditLockdown(r *http.Request, backend, ecosystem, coordinate string, dec lockdown.Decision) {
	if g.deps.Audit == nil {
		return
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
		Reason:     "lockdown:" + dec.Code,
		Detail: map[string]any{
			"coordinate": coordinate,
			"mode":       string(dec.Mode),
			"incidentId": dec.IncidentID,
			"code":       dec.Code,
		},
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) notifyLockdown(r *http.Request, backend, ecosystem, coordinate string, dec lockdown.Decision) {
	if g.deps.Notify == nil {
		return
	}
	// A pull refused under a lockdown is a high-signal security block; raise it as a
	// malicious-block-class alert so it surfaces in the SecOps feed and routes.
	ev := notify.MaliciousBlockEvent(ecosystem, backend, coordinate, dec.IncidentID, dec.Code, string(dec.Mode), dec.Reason)
	ev.Title = "Pull blocked by emergency lockdown (" + string(dec.Mode) + ")"
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
