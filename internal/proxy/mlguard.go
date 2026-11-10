package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/mlguard"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// gateMLGuard runs the ML weight-scanning gate (Task 110) on a cached Hugging
// Face model/dataset blob. It statically disassembles a pickle-based weight file
// (.bin/.pkl/.pt/.pth/.ckpt — unwrapping the PyTorch ZIP container) and flags
// imports of code-execution / network / filesystem primitives invoked via
// __reduce__ — the malicious-model attack vector — without ever unpickling
// anything. It records the result into the per-request admission signal
// accumulator (so the policy and risk engines see it) and, when the worst finding
// meets the tenant's threshold, blocks (and evicts/quarantines) or warns per
// policy. A served pickle may additionally carry an advisory header preferring the
// safer safetensors format.
//
// It runs after the content gates (it needs the artifact bytes, already in the
// cache) and before the aggregating policy/risk gates so its signal feeds them. It
// returns true when the request may proceed (allow or warn) and false when blocked
// and a response was written.
func (g *Gateway) gateMLGuard(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.MLGuard == nil || !g.deps.MLGuard.Enabled() {
		return true
	}
	art, ok := mlGuardArtifactFor(ecosystem, resolved)
	if !ok {
		return true
	}

	// Open a fresh content stream for static disassembly, independent of the one
	// being served to the client.
	open := func() (io.ReadCloser, error) {
		e, err := g.deps.Cache.Get(r.Context(), resolved.CacheKey)
		if err != nil {
			return nil, err
		}
		return e.Content, nil
	}

	report, err := g.deps.MLGuard.Assess(art, open)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false
		}
		g.deps.Logger.Warn("ML weight analysis errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(), "error", err)
		return true
	}

	recordMLGuardSignal(r.Context(), report)

	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}
	decision := g.deps.MLGuard.Gate(report, tenant)
	switch decision.Action {
	case mlguard.ActionBlock:
		// Human-in-the-loop break-glass (Task 50): an active grant for this
		// coordinate lets the flagged weight be served (and retained) pending review.
		if g.breakGlass(w, r, approvalGateMLGuard, name, ecosystem, art.Coordinate(), decision.Reason) {
			return true
		}
		g.evictMLGuard(r.Context(), resolved)
		g.auditMLGuard(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("ML weight gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"format", string(report.Format), "maxSeverity", string(report.MaxSeverity),
			"imports", strings.Join(report.Imports, ","))
		g.notifyMLGuard(r, name, ecosystem, art, report, decision)
		writeMLGuardBlock(w, art, report, decision)
		return false
	case mlguard.ActionWarn:
		g.auditMLGuard(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Info("ML weight gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"maxSeverity", string(report.MaxSeverity))
		g.notifyMLGuard(r, name, ecosystem, art, report, decision)
		w.Header().Set("X-MLGuard-Decision", "warn")
		w.Header().Set("X-MLGuard-Max-Severity", string(report.MaxSeverity))
		w.Header().Set("X-MLGuard-Reason", headerSafe(decision.Reason))
		mlGuardFormatHeaders(w, g, report)
		return true
	default:
		if report.SafeFormat {
			w.Header().Set("X-MLGuard-Decision", "allow")
			w.Header().Set("X-MLGuard-Format", string(report.Format))
		} else if report.Inspected {
			w.Header().Set("X-MLGuard-Decision", "allow")
			if report.MaxSeverity != "" {
				w.Header().Set("X-MLGuard-Max-Severity", string(report.MaxSeverity))
			}
		}
		mlGuardFormatHeaders(w, g, report)
		return true
	}
}

// mlGuardFormatHeaders adds the format advisory headers, preferring safetensors
// when a pickle weight is served and the gate is configured to recommend it.
func mlGuardFormatHeaders(w http.ResponseWriter, g *Gateway, report *mlguard.Report) {
	if report.Format != "" {
		w.Header().Set("X-MLGuard-Format", string(report.Format))
	}
	if report.Format == mlguard.FormatPickle && g.deps.MLGuard.PreferSafetensors() {
		w.Header().Set("X-MLGuard-Prefer-Safetensors", "true")
	}
}

// evictMLGuard removes a flagged weight file from the content cache so an unsafe
// pickle is neither served nor retained (quarantine).
func (g *Gateway) evictMLGuard(ctx context.Context, resolved *backends.Resolved) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("ML weight gate: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
}

// recordMLGuardSignal captures the weight-scan result into the admission signal
// accumulator for the policy-as-code and risk-scoring engines (and SARIF). No-op
// when no accumulator is attached or the gate did not inspect a weight file.
func recordMLGuardSignal(ctx context.Context, report *mlguard.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	if !report.Inspected && !report.SafeFormat {
		return
	}
	in := &policyengine.MLGuardInput{
		Scanned:      report.Inspected,
		Format:       string(report.Format),
		SafeFormat:   report.SafeFormat,
		Unsafe:       report.HasFindings(),
		FindingCount: len(report.Findings),
		MaxSeverity:  string(report.MaxSeverity),
		Risk:         report.Risk,
		Imports:      report.Imports,
	}
	for _, f := range report.Findings {
		in.Findings = append(in.Findings, policyengine.MLGuardFinding{
			RuleID:   f.RuleID,
			Severity: string(f.Severity),
			Import:   f.Import,
			Stream:   f.Stream,
		})
	}
	s.mu.Lock()
	s.input.MLGuard = in
	s.mu.Unlock()
}

// mlGuardArtifactFor builds the analysis artifact from a resolved resource,
// returning ok=false for a non-versioned resource (a metadata document) so the
// gate does not apply.
func mlGuardArtifactFor(ecosystem string, resolved *backends.Resolved) (mlguard.Artifact, bool) {
	c := resolved.Coordinate
	if c.Name == "" {
		return mlguard.Artifact{}, false
	}
	filename := resolved.Metadata[huggingface.MetaPath]
	if filename == "" {
		filename = path.Base(resolved.UpstreamURL)
	}
	// A git-lfs pointer body is a tiny text blob, not a real weight file; skip it.
	if resolved.Metadata[huggingface.MetaPointer] == "1" {
		return mlguard.Artifact{}, false
	}
	return mlguard.Artifact{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
		Filename:  filename,
		Digest:    resolved.Metadata[huggingface.MetaOID],
	}, true
}

// mlGuardError is the JSON body returned when a weight file is refused.
type mlGuardError struct {
	Error       string            `json:"error"`
	Code        string            `json:"code"`
	Action      string            `json:"action"`
	Reason      string            `json:"reason"`
	Ecosystem   string            `json:"ecosystem,omitempty"`
	Package     string            `json:"package,omitempty"`
	Version     string            `json:"version,omitempty"`
	Format      string            `json:"format,omitempty"`
	MaxSeverity string            `json:"maxSeverity,omitempty"`
	Imports     []string          `json:"unsafeImports,omitempty"`
	Findings    []mlguard.Finding `json:"findings,omitempty"`
}

// writeMLGuardBlock writes an actionable 403 describing why the weight was refused.
func writeMLGuardBlock(w http.ResponseWriter, art mlguard.Artifact, report *mlguard.Report, d mlguard.Decision) {
	body := mlGuardError{
		Error:       "model weight blocked by ML pickle-safety policy",
		Code:        d.Code,
		Action:      string(d.Action),
		Reason:      d.Reason,
		Ecosystem:   art.Ecosystem,
		Package:     art.Name,
		Version:     art.Version,
		Format:      string(report.Format),
		MaxSeverity: string(report.MaxSeverity),
		Imports:     report.Imports,
		Findings:    report.Findings,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-MLGuard-Decision", string(d.Action))
	h.Set("X-MLGuard-Code", d.Code)
	h.Set("X-MLGuard-Max-Severity", string(report.MaxSeverity))
	h.Set("X-MLGuard-Reason", headerSafe(d.Reason))
	h.Set("X-MLGuard-Format", string(report.Format))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditMLGuard records an ML-weight-gate decision in the audit log.
func (g *Gateway) auditMLGuard(r *http.Request, backend, ecosystem string, art mlguard.Artifact, report *mlguard.Report, d mlguard.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == mlguard.ActionWarn {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":        string(d.Action),
		"code":          d.Code,
		"package":       art.Name,
		"version":       art.Version,
		"format":        string(report.Format),
		"maxSeverity":   string(report.MaxSeverity),
		"findings":      len(report.Findings),
		"unsafeImports": report.Imports,
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "mlguard:" + d.Code,
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

// notifyMLGuard dispatches a security alert for an ML-weight-gate decision.
func (g *Gateway) notifyMLGuard(r *http.Request, backend, ecosystem string, art mlguard.Artifact, report *mlguard.Report, d mlguard.Decision) {
	if g.deps.Notify == nil {
		return
	}
	sev := notify.NormalizeSeverity(string(report.MaxSeverity))
	ev := notify.MLGuardEvent(sev, ecosystem, backend, art.Coordinate(),
		strings.ToLower(string(d.Action)), string(report.Format),
		strings.Join(report.Imports, ","), len(report.Findings), d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
