package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/continuity"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// gateContinuity runs the maintainer/publisher continuity monitoring gate (Task
// 91) on a resolved coordinate. Like the name guard and maturity gate it needs no
// artifact content — only the publisher metadata derived from the upstream
// registry — so it runs right after the name guard, between resolution and
// retrieval. It derives the current publisher principals (the registry maintainer
// roster, the publishing namespace owner, and any signing-key identity established
// by the signature path), compares them against the durable trust-on-first-use
// known-maintainer set, and raises a maintainer_drift signal when a previously-
// unseen maintainer/key/namespace appears for an already-known package — the
// classic account-takeover / hijack precursor. The signal feeds the policy/risk/
// findings layers; under a block disposition the still-untrusted version is refused
// (subject to break-glass). It returns true when the request may proceed and false
// when it has been blocked and a response has already been written.
func (g *Gateway) gateContinuity(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Continuity == nil || !g.deps.Continuity.Enabled() {
		return true
	}
	coord, ok := continuityCoordinateFor(ecosystem, resolved)
	if !ok {
		return true
	}

	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}

	// Fold any signature-verified signer identity already recorded by an earlier
	// gate into the observed publisher set, so a publishing-key rotation registers
	// as an ownership change alongside the registry maintainer roster. This reuses
	// the sigverify identity extraction surfaced via the admission accumulator.
	extra := continuityExtraIdentity(r.Context())

	decision := g.deps.Continuity.Check(r.Context(), tenant, coord, extra)
	recordContinuitySignal(r.Context(), decision)

	if !decision.Drift {
		if decision.FirstUse {
			w.Header().Set("X-Continuity-Decision", "first-use")
		}
		return true
	}

	if decision.Block() {
		// Human-in-the-loop break-glass (Task 50): an operator may have granted a
		// time-boxed exception to trust the new maintainer early; serve it instead of
		// refusing.
		if g.breakGlass(w, r, approvalGateContinuity, name, ecosystem, continuityCoordinate(coord), decision.Reason) {
			return true
		}
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditContinuity(r, name, ecosystem, coord, decision)
		g.notifyContinuity(r, name, ecosystem, coord, decision)
		g.deps.Logger.Warn("continuity gate blocked maintainer drift",
			"backend", name, "ecosystem", ecosystem, "package", coord.Name, "version", coord.Version,
			"added", strings.Join(decision.Added, ","), "reason", decision.Reason)
		writeContinuityBlock(w, coord, decision)
		return false
	}

	// Observe or warn: record/alert but admit.
	g.auditContinuity(r, name, ecosystem, coord, decision)
	if decision.Disposition == continuity.DispositionWarn {
		g.notifyContinuity(r, name, ecosystem, coord, decision)
		w.Header().Set("X-Continuity-Decision", "warn")
		w.Header().Set("X-Continuity-Reason", headerSafe(decision.Reason))
	}
	g.deps.Logger.Info("continuity gate observed maintainer drift",
		"backend", name, "ecosystem", ecosystem, "package", coord.Name, "version", coord.Version,
		"disposition", string(decision.Disposition), "added", strings.Join(decision.Added, ","))
	return true
}

// continuityExtraIdentity builds the supplemental publisher identity from any
// signature-verification result already recorded in the per-request admission
// accumulator. At the name-guard insertion point the signature gate has not run
// yet, so this is normally empty; it is read defensively so the key principal is
// folded in on any code path where signature verification precedes this gate.
func continuityExtraIdentity(ctx context.Context) continuity.Identity {
	s := signalsFrom(ctx)
	if s == nil {
		return continuity.Identity{}
	}
	s.mu.Lock()
	sig := s.input.Signature
	s.mu.Unlock()
	if sig == nil || !sig.Verified || sig.Identity == "" {
		return continuity.Identity{}
	}
	key := continuity.KeyPrincipalFromIdentity(sig.Identity, sig.Issuer)
	if key == "" {
		return continuity.Identity{}
	}
	return continuity.Identity{Keys: []string{key}}
}

// recordContinuitySignal captures the continuity verdict into the per-request
// admission signal accumulator for the policy-as-code and risk-scoring engines
// (and the SARIF findings layer). It is a no-op when no accumulator is attached or
// no publisher identity could be derived.
func recordContinuitySignal(ctx context.Context, d continuity.Decision) {
	s := signalsFrom(ctx)
	if s == nil || d.Unknown || d.Allowlisted {
		return
	}
	in := &policyengine.ContinuityInput{
		Evaluated:       true,
		Drift:           d.Drift,
		FirstUse:        d.FirstUse,
		Disposition:     string(d.Disposition),
		Added:           append([]string(nil), d.Added...),
		Removed:         append([]string(nil), d.Removed...),
		NewMaintainers:  len(d.Added),
		TrustedCount:    d.TrustedCount,
		PreviousVersion: d.PreviousVersion,
		Version:         d.Version,
		CooldownActive:  d.Remaining > 0,
		Reason:          d.Reason,
	}
	s.mu.Lock()
	s.input.Continuity = in
	s.mu.Unlock()
}

// continuityCoordinateFor builds the gate's coordinate from a resolved resource,
// returning ok=false when no concrete (name, version) is available: an index or
// listing request has no single artifact whose publisher to track.
func continuityCoordinateFor(ecosystem string, resolved *backends.Resolved) (continuity.Coordinate, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return continuity.Coordinate{}, false
	}
	return continuity.Coordinate{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
	}, true
}

// continuityCoordinate renders a "name@version" coordinate for a drift block.
func continuityCoordinate(c continuity.Coordinate) string {
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// continuityError is the JSON body returned when a pull is refused by the
// continuity gate. It names the new (untrusted) publisher principals so a developer
// can confirm whether the ownership change is legitimate.
type continuityError struct {
	Error           string   `json:"error"`
	Code            string   `json:"code"`
	Reason          string   `json:"reason"`
	Ecosystem       string   `json:"ecosystem,omitempty"`
	Package         string   `json:"package,omitempty"`
	Version         string   `json:"version,omitempty"`
	PreviousVersion string   `json:"previousVersion,omitempty"`
	NewMaintainers  []string `json:"newMaintainers,omitempty"`
	TrustedCount    int      `json:"trustedCount"`
}

// writeContinuityBlock writes an actionable 403 describing the ownership change.
func writeContinuityBlock(w http.ResponseWriter, coord continuity.Coordinate, d continuity.Decision) {
	body := continuityError{
		Error:           "package version held by maintainer/publisher continuity policy (ownership change)",
		Code:            "maintainer-drift",
		Reason:          d.Reason,
		Ecosystem:       coord.Ecosystem,
		Package:         coord.Name,
		Version:         coord.Version,
		PreviousVersion: d.PreviousVersion,
		NewMaintainers:  d.Added,
		TrustedCount:    d.TrustedCount,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Continuity-Decision", "block")
	h.Set("X-Continuity-Code", "maintainer-drift")
	h.Set("X-Continuity-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditContinuity records a continuity-gate decision in the tamper-evident audit
// log. A block is a deny; an observe/warn is recorded as an allow with the drift
// context.
func (g *Gateway) auditContinuity(r *http.Request, backend, ecosystem string, coord continuity.Coordinate, d continuity.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionAllow
	status := http.StatusOK
	if d.Block() {
		decision = audit.DecisionDeny
		status = http.StatusForbidden
	}
	detail := map[string]any{
		"package":         coord.Name,
		"version":         coord.Version,
		"previousVersion": d.PreviousVersion,
		"disposition":     string(d.Disposition),
		"added":           d.Added,
		"removed":         d.Removed,
		"trustedCount":    d.TrustedCount,
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Status:     status,
		Reason:     "continuity:maintainer-drift",
		Detail:     detail,
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyContinuity emits a security alert for a maintainer-drift decision.
func (g *Gateway) notifyContinuity(r *http.Request, backend, ecosystem string, coord continuity.Coordinate, d continuity.Decision) {
	if g.deps.Notify == nil {
		return
	}
	ev := notify.MaintainerDriftEvent(ecosystem, backend, continuityCoordinate(coord),
		string(d.Disposition), d.Added, d.PreviousVersion, d.Version, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
