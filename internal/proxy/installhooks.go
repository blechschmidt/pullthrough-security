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
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// gateInstallHooks runs the install-script / lifecycle-hook risk-analysis gate
// (Task 62) on a cached artifact. It statically extracts the package's
// install-time hooks (npm pre/post-install scripts, Python setup.py / pyproject
// build hooks, RubyGems native extensions + post-install message, Cargo build.rs)
// and scores them against a fixed set of deterministic high-risk patterns — never
// executing anything. It records the result into the per-request admission signal
// accumulator (so the policy and risk engines see it) and, when the worst
// finding meets the tenant's configured threshold, blocks or warns per policy.
//
// It runs after the vulnerability/license gates because, like them, it needs the
// artifact bytes (already in the cache) — and before the policy/risk gates so its
// signal feeds them. A blocked artifact is evicted from the cache so a malicious
// install hook is neither served nor retained. It returns true when the request
// may proceed (allow or warn) and false when blocked and a response was written.
func (g *Gateway) gateInstallHooks(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.InstallHooks == nil || !g.deps.InstallHooks.Enabled() {
		return true
	}
	art, ok := installHooksArtifactFor(ecosystem, resolved, entry)
	if !ok {
		return true
	}

	// Open a fresh content stream for static extraction, independent of the one
	// being served to the client (closed by Assess via the returned ReadCloser).
	open := func() (io.ReadCloser, error) {
		e, err := g.deps.Cache.Get(r.Context(), resolved.CacheKey)
		if err != nil {
			return nil, err
		}
		return e.Content, nil
	}

	report, err := g.deps.InstallHooks.Assess(art, open)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false
		}
		g.deps.Logger.Warn("install-hook analysis errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "error", err)
		return true
	}

	recordInstallHooksSignal(r.Context(), report)

	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}
	decision := g.deps.InstallHooks.Gate(report, tenant)
	switch decision.Action {
	case installhooks.ActionBlock:
		// Human-in-the-loop break-glass (Task 50): an active grant for this
		// coordinate lets the flagged artifact be served (and retained) pending
		// review; consult before evicting.
		if g.breakGlass(w, r, approvalGateInstallHooks, name, ecosystem, art.Coordinate(), decision.Reason) {
			return true
		}
		g.evictInstallHooks(r.Context(), resolved)
		g.auditInstallHooks(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("install-hook gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"maxSeverity", string(report.MaxSeverity), "findings", len(report.Findings))
		g.notifyInstallHooks(r, name, ecosystem, art, report, decision)
		writeInstallHooksBlock(w, art, report, decision)
		return false
	case installhooks.ActionWarn:
		g.auditInstallHooks(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Info("install-hook gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"maxSeverity", string(report.MaxSeverity), "findings", len(report.Findings))
		g.notifyInstallHooks(r, name, ecosystem, art, report, decision)
		w.Header().Set("X-InstallHooks-Decision", "warn")
		w.Header().Set("X-InstallHooks-Max-Severity", string(report.MaxSeverity))
		w.Header().Set("X-InstallHooks-Reason", headerSafe(decision.Reason))
		return true
	default:
		if report.Inspected {
			w.Header().Set("X-InstallHooks-Decision", "allow")
			if report.MaxSeverity != "" {
				w.Header().Set("X-InstallHooks-Max-Severity", string(report.MaxSeverity))
			}
		}
		return true
	}
}

// evictInstallHooks removes a flagged artifact from the content cache so a
// malicious install hook is neither served nor retained.
func (g *Gateway) evictInstallHooks(ctx context.Context, resolved *backends.Resolved) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("install-hook gate: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
}

// recordInstallHooksSignal captures the install-hook analysis into the admission
// signal accumulator for the policy-as-code and risk-scoring engines (and the
// SARIF findings layer). It is a no-op when no accumulator is attached.
func recordInstallHooksSignal(ctx context.Context, report *installhooks.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil || !report.Inspected {
		return
	}
	in := &policyengine.InstallHooksInput{
		Scanned:      true,
		HookCount:    len(report.Hooks),
		FindingCount: len(report.Findings),
		MaxSeverity:  string(report.MaxSeverity),
		Risk:         report.Risk,
	}
	for _, f := range report.Findings {
		in.Findings = append(in.Findings, policyengine.InstallHookFinding{
			RuleID:   f.RuleID,
			Severity: string(f.Severity),
			Hook:     f.HookLabel,
			File:     f.File,
		})
	}
	s.mu.Lock()
	s.input.InstallHooks = in
	s.mu.Unlock()
}

// installHooksArtifactFor builds the analysis artifact from a resolved resource,
// returning ok=false for a non-versioned resource (an index/listing) so the gate
// does not apply.
func installHooksArtifactFor(ecosystem string, resolved *backends.Resolved, entry *cache.Entry) (installhooks.Artifact, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return installhooks.Artifact{}, false
	}
	digest := resolved.Digest
	if digest == "" && entry != nil {
		digest = entry.Stat.Key
	}
	return installhooks.Artifact{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
		Digest:    digest,
		Filename:  path.Base(resolved.UpstreamURL),
		MediaType: resolved.MediaType,
	}, true
}

// installHooksError is the JSON body returned when an artifact is refused by the
// install-hook gate. It is actionable: the developer sees which hook and which
// rule fired, with a redacted excerpt of the offending line.
type installHooksError struct {
	Error       string                 `json:"error"`
	Code        string                 `json:"code"`
	Action      string                 `json:"action"`
	Reason      string                 `json:"reason"`
	Ecosystem   string                 `json:"ecosystem,omitempty"`
	Package     string                 `json:"package,omitempty"`
	Version     string                 `json:"version,omitempty"`
	MaxSeverity string                 `json:"maxSeverity,omitempty"`
	Hooks       int                    `json:"hooks"`
	Findings    []installhooks.Finding `json:"findings,omitempty"`
}

// writeInstallHooksBlock writes an actionable 403 describing why the artifact was
// refused.
func writeInstallHooksBlock(w http.ResponseWriter, art installhooks.Artifact, report *installhooks.Report, d installhooks.Decision) {
	body := installHooksError{
		Error:       "artifact blocked by install-script / lifecycle-hook risk policy",
		Code:        d.Code,
		Action:      string(d.Action),
		Reason:      d.Reason,
		Ecosystem:   art.Ecosystem,
		Package:     art.Name,
		Version:     art.Version,
		MaxSeverity: string(report.MaxSeverity),
		Hooks:       len(report.Hooks),
		Findings:    report.Findings,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-InstallHooks-Decision", string(d.Action))
	h.Set("X-InstallHooks-Code", d.Code)
	h.Set("X-InstallHooks-Max-Severity", string(report.MaxSeverity))
	h.Set("X-InstallHooks-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditInstallHooks records an install-hook-gate decision in the audit log.
func (g *Gateway) auditInstallHooks(r *http.Request, backend, ecosystem string, art installhooks.Artifact, report *installhooks.Report, d installhooks.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == installhooks.ActionWarn {
		decision = audit.DecisionAllow
	}
	rules := make([]string, 0, len(report.Findings))
	seen := make(map[string]bool)
	for i := range report.Findings {
		id := report.Findings[i].RuleID
		if !seen[id] {
			seen[id] = true
			rules = append(rules, id)
		}
	}
	detail := map[string]any{
		"action":      string(d.Action),
		"code":        d.Code,
		"package":     art.Name,
		"version":     art.Version,
		"maxSeverity": string(report.MaxSeverity),
		"hooks":       len(report.Hooks),
		"findings":    len(report.Findings),
		"rules":       rules,
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "installhooks:" + d.Code,
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

// notifyInstallHooks dispatches a security alert for an install-hook-gate
// decision (warn or block). The alert severity is the worst matched-pattern
// severity so a severity-filtered route delivers only the alerts that matter.
func (g *Gateway) notifyInstallHooks(r *http.Request, backend, ecosystem string, art installhooks.Artifact, report *installhooks.Report, d installhooks.Decision) {
	if g.deps.Notify == nil {
		return
	}
	sev := notify.NormalizeSeverity(string(report.MaxSeverity))
	rule := ""
	if d.Highest != nil {
		rule = d.Highest.RuleID
	}
	ev := notify.InstallHooksEvent(sev, ecosystem, backend, art.Coordinate(),
		strings.ToLower(string(d.Action)), rule, len(report.Hooks), len(report.Findings), d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
