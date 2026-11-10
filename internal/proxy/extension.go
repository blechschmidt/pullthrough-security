package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/extension"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// The WASM extensibility gate (Task 59) runs after the risk-scoring gate as the
// final, operator-extensible admission stage. It hands each configured extension
// module a serialized, read-only view of the request context — the same
// aggregated gate signals the policy and risk engines saw, plus the composite
// risk score — and applies the modules' combined verdict (allow / warn / block).
// Like the policy and risk gates, it composes with the hard-coded gates: a module
// can turn an otherwise-allowed artifact into a warn or block, but is never
// consulted to re-admit something an earlier gate already refused.

// gateExtension evaluates the per-tenant extension modules over the accumulated
// admission signals. It returns true when the request may proceed and false when
// a module blocked the artifact and a 403 has been written.
func (g *Gateway) gateExtension(w http.ResponseWriter, r *http.Request, name, ecosystem string) bool {
	if !g.deps.Extension.Enabled() {
		return true
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return true
	}
	s.mu.Lock()
	in := s.input
	risk := s.risk
	s.mu.Unlock()

	hi := extension.HostInput{Signals: in}
	if risk != nil {
		hi.Risk = &extension.RiskView{Score: risk.Score, Band: risk.Band, Action: risk.Action}
	}

	res := g.deps.Extension.Evaluate(r.Context(), hi)
	if len(res.Modules) == 0 {
		// No modules selected for this tenant: nothing to enforce or record.
		return true
	}

	// Surface the combined decision so downstream proxies/clients can observe it,
	// even when the gate admits.
	w.Header().Set("X-Extension-Decision", string(res.Decision))
	if res.Module != "" {
		w.Header().Set("X-Extension-Module", headerSafe(res.Module))
	}

	tracing.SpanFromContext(r.Context()).SetAttributes(
		tracing.String("pullthrough.extension.decision", string(res.Decision)),
		tracing.String("pullthrough.extension.module", res.Module),
	)

	g.auditExtension(r, name, ecosystem, res)

	switch res.Decision {
	case extension.DecisionBlock:
		g.deps.Logger.Warn("extension gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", in.Artifact.Name,
			"module", res.Module, "reason", res.Reason)
		g.notifyExtension(r, name, ecosystem, extensionCoordinate(in), res)
		writeExtensionBlock(w, res)
		return false
	case extension.DecisionWarn:
		g.deps.Logger.Info("extension gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", in.Artifact.Name,
			"module", res.Module, "reason", res.Reason)
		w.Header().Set("X-Extension-Reason", headerSafe(res.Reason))
		g.notifyExtension(r, name, ecosystem, extensionCoordinate(in), res)
		return true
	default:
		return true
	}
}

// extensionError is the JSON body returned when an extension module blocks.
type extensionError struct {
	Error       string                   `json:"error"`
	Code        string                   `json:"code"`
	Module      string                   `json:"module"`
	Reason      string                   `json:"reason,omitempty"`
	Annotations map[string]string        `json:"annotations,omitempty"`
	Modules     []extension.ModuleResult `json:"modules,omitempty"`
}

func writeExtensionBlock(w http.ResponseWriter, res extension.Result) {
	body := extensionError{
		Error:       "artifact blocked by a custom extension admission gate",
		Code:        "extension",
		Module:      res.Module,
		Reason:      res.Reason,
		Annotations: res.Annotations,
		Modules:     res.Modules,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Extension-Decision", "block")
	h.Set("X-Extension-Reason", headerSafe(res.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

func (g *Gateway) auditExtension(r *http.Request, backend, ecosystem string, res extension.Result) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionAllow
	if res.Block {
		decision = audit.DecisionDeny
	}
	// Render the per-module outcomes compactly for the audit detail.
	outcomes := make(map[string]string, len(res.Modules))
	for _, m := range res.Modules {
		outcomes[m.Module] = string(m.Outcome)
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "extension:" + res.Module,
		Detail: map[string]any{
			"decision":    string(res.Decision),
			"module":      res.Module,
			"reason":      res.Reason,
			"outcomes":    outcomes,
			"annotations": res.Annotations,
		},
	}
	if res.Block {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) notifyExtension(r *http.Request, backend, ecosystem, coord string, res extension.Result) {
	if g.deps.Notify == nil {
		return
	}
	sev := notify.SeverityMedium
	if res.Block {
		sev = notify.SeverityHigh
	}
	ev := notify.ExtensionEvent(sev, ecosystem, backend, coord, res.Module, string(res.Decision), res.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// artifactCoordinate renders an artifact's name@version (or just name) for
// notifications and logs.
func extensionCoordinate(in policyengine.Input) string {
	if in.Artifact.Name == "" {
		return ""
	}
	if in.Artifact.Version == "" {
		return in.Artifact.Name
	}
	return in.Artifact.Name + "@" + in.Artifact.Version
}
