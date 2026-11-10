package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/avscan"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// gateAVScan runs the antivirus content-scanning gate (Task 136) on a cached
// artifact blob. It streams the artifact's bytes through the configured AV
// engine (ClamAV via the clamd INSTREAM protocol) and, on a positive byte-level
// malware detection, annotates / quarantines (refuse + evict) / blocks the
// artifact per policy. It records the result into the per-request admission
// signal accumulator (so the policy, risk, SARIF and dossier layers see it).
//
// It runs after the content gates (it needs the artifact bytes, already in the
// cache) and before the aggregating policy/risk gates. When the engine is
// unreachable it degrades gracefully (fail-open admits, fail-closed refuses).
// It returns true when the request may proceed and false when a response was
// written (refused).
func (g *Gateway) gateAVScan(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.AVScan == nil || !g.deps.AVScan.Enabled() {
		return true
	}
	art := avScanArtifactFor(ecosystem, resolved)

	// Open a fresh content stream for scanning, independent of the one being
	// served to the client.
	open := func() (io.ReadCloser, error) {
		e, err := g.deps.Cache.Get(r.Context(), resolved.CacheKey)
		if err != nil {
			return nil, err
		}
		return e.Content, nil
	}

	report, err := g.deps.AVScan.Assess(r.Context(), art, open)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		// A hard failure to re-open the cached bytes is not an engine fault; log and
		// serve rather than failing the pull on an internal I/O error.
		g.deps.Logger.Warn("antivirus scan errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(), "error", err)
		return true
	}

	recordAVScanSignal(r.Context(), report)

	decision := g.deps.AVScan.Gate(report)
	h := w.Header()
	h.Set("X-AVScan-Engine", report.Engine)

	if decision.Outcome == avscan.OutcomeRefuse {
		// Human-in-the-loop break-glass (Task 50): an active grant for this
		// coordinate lets the flagged artifact be served pending review.
		if report.Infected && g.breakGlass(w, r, approvalGateAVScan, name, ecosystem, art.Coordinate(), decision.Reason) {
			return true
		}
		if decision.Evict {
			g.evictAVScan(r.Context(), resolved)
		}
		g.auditAVScan(r, name, ecosystem, art, report, decision)
		if report.Infected {
			g.deps.Logger.Warn("antivirus gate blocked artifact",
				"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
				"engine", report.Engine, "signature", report.Signature, "action", decision.Action)
			g.notifyAVScan(r, name, ecosystem, art, report, decision)
		} else {
			g.deps.Logger.Warn("antivirus gate refused artifact (engine unavailable, fail-closed)",
				"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
				"engine", report.Engine)
		}
		writeAVScanBlock(w, art, report, decision)
		return false
	}

	// Allowed: clean, annotate (served detection), or fail-open degradation.
	switch {
	case report.Infected:
		// annotate mode: the artifact is served but the detection is recorded.
		g.auditAVScan(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("antivirus gate detected malware (annotate mode; serving)",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"engine", report.Engine, "signature", report.Signature)
		g.notifyAVScan(r, name, ecosystem, art, report, decision)
		h.Set("X-AVScan-Decision", "annotate")
		h.Set("X-AVScan-Signature", headerSafe(report.Signature))
	case report.Unavailable:
		h.Set("X-AVScan-Decision", "degraded")
		g.deps.Logger.Debug("antivirus engine unavailable; served under fail-open policy",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Coordinate(),
			"engine", report.Engine, "error", report.Error)
	case report.Scanned:
		h.Set("X-AVScan-Decision", "clean")
		if report.Truncated {
			h.Set("X-AVScan-Truncated", "true")
		}
	}
	return true
}

// avScanArtifactFor builds the scan artifact from a resolved resource. The gate
// is ecosystem-agnostic, so it always produces an artifact (the coordinate may
// be empty for a bare blob).
func avScanArtifactFor(ecosystem string, resolved *backends.Resolved) avscan.Artifact {
	filename := path.Base(resolved.UpstreamURL)
	if filename == "." || filename == "/" {
		filename = ""
	}
	digest := resolved.Digest
	return avscan.Artifact{
		Ecosystem: ecosystem,
		Name:      resolved.Coordinate.Name,
		Version:   resolved.Coordinate.Version,
		Filename:  filename,
		Digest:    digest,
		MediaType: resolved.MediaType,
	}
}

// evictAVScan removes a flagged artifact from the content cache so an infected
// payload is neither served nor retained (quarantine).
func (g *Gateway) evictAVScan(ctx context.Context, resolved *backends.Resolved) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("antivirus gate: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
}

// recordAVScanSignal captures the AV scan result into the admission signal
// accumulator for the policy-as-code and risk-scoring engines (and SARIF /
// dossier). No-op when no accumulator is attached or nothing was scanned.
func recordAVScanSignal(ctx context.Context, report *avscan.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	if !report.Scanned && !report.Unavailable {
		return
	}
	in := &policyengine.AVScanInput{
		Scanned:      report.Scanned,
		Engine:       report.Engine,
		Infected:     report.Infected,
		Signature:    report.Signature,
		Unavailable:  report.Unavailable,
		Truncated:    report.Truncated,
		FindingCount: len(report.Findings),
		Risk:         report.Risk,
	}
	for _, f := range report.Findings {
		if in.MaxSeverity == "" {
			in.MaxSeverity = string(f.Severity)
		}
		in.Findings = append(in.Findings, policyengine.AVScanFinding{
			RuleID:    f.RuleID,
			Severity:  string(f.Severity),
			Signature: f.Signature,
		})
	}
	s.mu.Lock()
	s.input.AVScan = in
	s.mu.Unlock()
}

// avScanError is the JSON body returned when an artifact is refused.
type avScanError struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	Engine    string `json:"engine,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// writeAVScanBlock writes an actionable 403 describing why the artifact was
// refused.
func writeAVScanBlock(w http.ResponseWriter, art avscan.Artifact, report *avscan.Report, d avscan.Decision) {
	msg := "artifact blocked by antivirus content-scanning policy"
	if !report.Infected {
		msg = "artifact refused: antivirus engine unavailable (fail-closed policy)"
	}
	body := avScanError{
		Error:     msg,
		Code:      d.Code,
		Action:    d.Action,
		Reason:    d.Reason,
		Ecosystem: art.Ecosystem,
		Package:   art.Name,
		Version:   art.Version,
		Engine:    report.Engine,
		Signature: report.Signature,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-AVScan-Decision", "block")
	h.Set("X-AVScan-Code", d.Code)
	h.Set("X-AVScan-Reason", headerSafe(d.Reason))
	if report.Signature != "" {
		h.Set("X-AVScan-Signature", headerSafe(report.Signature))
	}
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditAVScan records an AV-gate decision in the audit log.
func (g *Gateway) auditAVScan(r *http.Request, backend, ecosystem string, art avscan.Artifact, report *avscan.Report, d avscan.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Outcome == avscan.OutcomeAllow {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":    d.Action,
		"code":      d.Code,
		"package":   art.Name,
		"version":   art.Version,
		"engine":    report.Engine,
		"signature": report.Signature,
		"infected":  report.Infected,
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "avscan:" + d.Code,
		Detail:     detail,
	}
	if d.Outcome == avscan.OutcomeRefuse {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyAVScan dispatches a security alert for an AV-gate detection.
func (g *Gateway) notifyAVScan(r *http.Request, backend, ecosystem string, art avscan.Artifact, report *avscan.Report, d avscan.Decision) {
	if g.deps.Notify == nil {
		return
	}
	ev := notify.AVScanEvent(notify.SeverityCritical, ecosystem, backend, art.Coordinate(),
		d.Action, report.Engine, report.Signature, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
