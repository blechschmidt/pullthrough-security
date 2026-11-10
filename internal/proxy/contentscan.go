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
	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// gateContentScan runs the package-payload static content-analysis gate (Task
// 138) on a cached source artifact. It unpacks the archive and scans every file
// against deterministic heuristics (embedded native binaries, high-entropy
// blobs, obfuscated JavaScript, dynamic code-execution sinks, and in-source
// secrets) — never executing anything. It records the result into the per-request
// admission signal accumulator (so the policy and risk engines, the SARIF layer,
// and the notification pipeline see it) and, under the block action, refuses and
// evicts an artifact whose worst finding meets the configured fail threshold.
//
// It runs alongside the other content gates (it needs the artifact bytes, already
// in the cache) and before the policy/risk gates so its signal feeds them. It
// returns true when the request may proceed and false when a response was written
// (refused).
func (g *Gateway) gateContentScan(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.ContentScan == nil || !g.deps.ContentScan.Applies(ecosystem) {
		return true
	}
	art, ok := contentScanArtifactFor(ecosystem, resolved, entry)
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

	report, err := g.deps.ContentScan.Assess(r.Context(), art, open)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		g.deps.Logger.Warn("content analysis errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(), "error", err)
		return true
	}

	recordContentScanSignal(r.Context(), report)

	decision := g.deps.ContentScan.Gate(report)
	h := w.Header()
	if report.Inspected {
		h.Set("X-ContentScan-Decision", decisionLabel(decision))
		if report.MaxSeverity != "" {
			h.Set("X-ContentScan-Max-Severity", string(report.MaxSeverity))
		}
	}

	if decision.Outcome == contentscan.OutcomeRefuse {
		// Human-in-the-loop break-glass (Task 50): an active grant for this
		// coordinate lets the flagged artifact be served pending review.
		if g.breakGlass(w, r, approvalGateContentScan, name, ecosystem, art.Coordinate(), decision.Reason) {
			return true
		}
		if decision.Evict {
			g.evictContentScan(r.Context(), resolved)
		}
		g.auditContentScan(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("content-analysis gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"maxSeverity", string(report.MaxSeverity), "findings", len(report.Findings))
		g.notifyContentScan(r, name, ecosystem, art, report, decision)
		writeContentScanBlock(w, art, report, decision)
		return false
	}

	// Allowed. Record/notify when findings were present (annotate/downgrade or a
	// below-threshold block), so observe-mode is still auditable.
	if report.HasFindings() {
		g.auditContentScan(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Info("content-analysis gate findings (serving)",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"action", string(decision.Action), "maxSeverity", string(report.MaxSeverity),
			"findings", len(report.Findings))
		g.notifyContentScan(r, name, ecosystem, art, report, decision)
		h.Set("X-ContentScan-Reason", headerSafe(decision.Reason))
	}
	if report.Truncated {
		h.Set("X-ContentScan-Truncated", "true")
	}
	return true
}

// decisionLabel renders a short header label for an allowed/refused decision.
func decisionLabel(d contentscan.Decision) string {
	if d.Outcome == contentscan.OutcomeRefuse {
		return "block"
	}
	switch d.Code {
	case "clean":
		return "clean"
	default:
		return string(d.Action)
	}
}

// contentScanArtifactFor builds the analysis artifact from a resolved resource,
// returning ok=false for a non-versioned resource (an index/listing) so the gate
// does not apply.
func contentScanArtifactFor(ecosystem string, resolved *backends.Resolved, entry *cache.Entry) (contentscan.Artifact, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return contentscan.Artifact{}, false
	}
	digest := resolved.Digest
	if digest == "" && entry != nil {
		digest = entry.Stat.Key
	}
	return contentscan.Artifact{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
		Digest:    digest,
		Filename:  path.Base(resolved.UpstreamURL),
		MediaType: resolved.MediaType,
	}, true
}

// evictContentScan removes a flagged artifact from the content cache so a
// malicious payload is neither served nor retained.
func (g *Gateway) evictContentScan(ctx context.Context, resolved *backends.Resolved) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("content-analysis gate: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
}

// recordContentScanSignal captures the content analysis into the admission signal
// accumulator for the policy-as-code and risk-scoring engines (and the SARIF
// findings layer). It is a no-op when no accumulator is attached or nothing was
// inspected.
func recordContentScanSignal(ctx context.Context, report *contentscan.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil || !report.Inspected {
		return
	}
	in := &policyengine.ContentScanInput{
		Scanned:      true,
		Action:       string(report.Action),
		FilesScanned: report.FilesScanned,
		Truncated:    report.Truncated,
		TimedOut:     report.TimedOut,
		FindingCount: len(report.Findings),
		MaxSeverity:  string(report.MaxSeverity),
		Risk:         report.Risk,
	}
	catSeen := make(map[string]bool)
	for _, f := range report.Findings {
		if !catSeen[f.Category] {
			catSeen[f.Category] = true
			in.Categories = append(in.Categories, f.Category)
		}
		in.Findings = append(in.Findings, policyengine.ContentScanFinding{
			RuleID:   f.RuleID,
			Category: f.Category,
			Severity: string(f.Severity),
			File:     f.File,
			Line:     f.Line,
		})
	}
	s.mu.Lock()
	s.input.ContentScan = in
	s.mu.Unlock()
}

// contentScanError is the JSON body returned when an artifact is refused. It is
// actionable: the developer sees which files and categories triggered the block.
type contentScanError struct {
	Error       string                `json:"error"`
	Code        string                `json:"code"`
	Action      string                `json:"action"`
	Reason      string                `json:"reason"`
	Ecosystem   string                `json:"ecosystem,omitempty"`
	Package     string                `json:"package,omitempty"`
	Version     string                `json:"version,omitempty"`
	MaxSeverity string                `json:"maxSeverity,omitempty"`
	Files       int                   `json:"filesScanned"`
	Findings    []contentscan.Finding `json:"findings,omitempty"`
}

// writeContentScanBlock writes an actionable 403 describing why the artifact was
// refused.
func writeContentScanBlock(w http.ResponseWriter, art contentscan.Artifact, report *contentscan.Report, d contentscan.Decision) {
	// Bound the findings echoed back so a pathological artifact cannot bloat the
	// error body.
	findings := report.Findings
	if len(findings) > 20 {
		findings = findings[:20]
	}
	body := contentScanError{
		Error:       "artifact blocked by package-content analysis policy",
		Code:        d.Code,
		Action:      string(d.Action),
		Reason:      d.Reason,
		Ecosystem:   art.Ecosystem,
		Package:     art.Name,
		Version:     art.Version,
		MaxSeverity: string(report.MaxSeverity),
		Files:       report.FilesScanned,
		Findings:    findings,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-ContentScan-Decision", "block")
	h.Set("X-ContentScan-Code", d.Code)
	h.Set("X-ContentScan-Max-Severity", string(report.MaxSeverity))
	h.Set("X-ContentScan-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditContentScan records a content-analysis-gate decision in the audit log.
func (g *Gateway) auditContentScan(r *http.Request, backend, ecosystem string, art contentscan.Artifact, report *contentscan.Report, d contentscan.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Outcome == contentscan.OutcomeAllow {
		decision = audit.DecisionAllow
	}
	cats := make([]string, 0, 4)
	seen := make(map[string]bool)
	for i := range report.Findings {
		c := report.Findings[i].Category
		if !seen[c] {
			seen[c] = true
			cats = append(cats, c)
		}
	}
	detail := map[string]any{
		"action":      string(d.Action),
		"code":        d.Code,
		"package":     art.Name,
		"version":     art.Version,
		"maxSeverity": string(report.MaxSeverity),
		"files":       report.FilesScanned,
		"findings":    len(report.Findings),
		"categories":  cats,
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "contentscan:" + d.Code,
		Detail:     detail,
	}
	if d.Outcome == contentscan.OutcomeRefuse {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyContentScan dispatches a security alert for a content-analysis-gate
// decision. The alert severity is the worst finding's severity so a
// severity-filtered route delivers only the findings that matter.
func (g *Gateway) notifyContentScan(r *http.Request, backend, ecosystem string, art contentscan.Artifact, report *contentscan.Report, d contentscan.Decision) {
	if g.deps.Notify == nil {
		return
	}
	sev := notify.NormalizeSeverity(string(report.MaxSeverity))
	category := ""
	if d.Highest != nil {
		category = d.Highest.Category
	}
	ev := notify.ContentScanEvent(sev, ecosystem, backend, art.Coordinate(),
		strings.ToLower(string(d.Action)), category, report.FilesScanned, len(report.Findings), d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
