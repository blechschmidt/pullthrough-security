package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// gateVulnerabilities runs the vulnerability-scanning admission gate (Task 15) on
// a cached artifact. It generates the artifact's SBOM, resolves it against the
// vulnerability database (results cached by content digest), and applies the
// configured severity/CVSS policy. It returns true when the request may proceed
// (allow or warn) and false when the artifact has been blocked or quarantined and
// a response has already been written.
//
// Unlike the provenance policy gate, this runs after the artifact is in the cache
// because its content must be read to build the SBOM. A quarantine decision evicts
// the offending content from both the artifact cache and the scan-result cache so
// it is neither served nor retained.
func (g *Gateway) gateVulnerabilities(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.Vulnerabilities == nil {
		return true
	}
	art, ok := vulnArtifactFor(ecosystem, resolved, entry)
	if !ok {
		return true
	}

	// CVE-drift quarantine (Task 18): the background re-scan subsystem may have
	// marked this digest unservable after a vulnerability was disclosed since it
	// was cached. Refuse it here before any scan/serve, independent of the cached
	// scan result (which may be a stale, pre-disclosure clean verdict).
	if q, quarantined := g.deps.Vulnerabilities.QuarantineInfo(art.Digest); quarantined {
		// Human-in-the-loop break-glass (Task 50): an active grant for this
		// coordinate lets the CVE-drift-quarantined artifact be served (and retained)
		// pending remediation. Consult before evicting.
		if g.breakGlass(w, r, approvalGateCVEDrift, name, ecosystem, artifactCoordinate(art), q.Reason) {
			return true
		}
		g.quarantineArtifact(r.Context(), resolved, art)
		decision := vulnscan.Decision{
			Action: policy.ActionQuarantine,
			Code:   "cve-drift-quarantine",
			Reason: q.Reason,
		}
		report := &vulnscan.Report{
			Digest:      q.Digest,
			Artifact:    art,
			Counts:      q.Counts,
			MaxSeverity: q.MaxSeverity,
			MaxCVSS:     q.MaxCVSS,
		}
		g.auditVuln(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("vulnerability gate refused quarantined artifact (cve drift)",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"advisory", q.Advisory, "maxSeverity", string(q.MaxSeverity))
		g.emit(r.Context(), notify.QuarantineEvent(
			notify.NormalizeSeverity(string(q.MaxSeverity)), ecosystem, name,
			artifactCoordinate(art), q.Advisory, q.Reason))
		writeVulnBlock(w, art, report, decision)
		return false
	}

	// Lazily open a fresh content stream for SBOM extraction; only invoked on a
	// scan-cache miss (a cached result reuses the prior SBOM). The stream is
	// independent of the one being served to the client and is closed by the
	// scanning service.
	open := func() (io.ReadCloser, error) {
		e, err := g.deps.Cache.Get(r.Context(), resolved.CacheKey)
		if err != nil {
			return nil, err
		}
		return e.Content, nil
	}

	report, err := g.deps.Vulnerabilities.Assess(r.Context(), art, open)
	if err != nil {
		// An internal assessment failure (e.g. context cancellation) is not a
		// vulnerability finding; log and let the request proceed rather than denying
		// on an infrastructure error the gate's own fail-open handling did not cover.
		if errors.Is(err, context.Canceled) {
			return false
		}
		g.deps.Logger.Warn("vulnerability assessment errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "error", err)
		return true
	}

	// Account the SBOM/OSV scan invocation (and its estimated cost) to the tenant
	// for per-tenant usage/chargeback (Task 84).
	g.meterScan(r, "vulnscan")
	recordVulnSignal(r.Context(), report)
	decision := g.deps.Vulnerabilities.Gate(report)
	switch decision.Action {
	case policy.ActionQuarantine:
		// Human-in-the-loop break-glass (Task 50): consult before evicting so an
		// active grant lets the vulnerable artifact be served and retained.
		if g.breakGlass(w, r, approvalGateVulnscan, name, ecosystem, artifactCoordinate(art), decision.Reason) {
			return true
		}
		g.quarantineArtifact(r.Context(), resolved, art)
		g.auditVuln(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("vulnerability gate quarantined artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"code", decision.Code, "maxSeverity", string(report.MaxSeverity), "maxCvss", report.MaxCVSS)
		g.notifyVuln(r, name, ecosystem, art, report, decision)
		writeVulnBlock(w, art, report, decision)
		return false
	case policy.ActionBlock:
		if g.breakGlass(w, r, approvalGateVulnscan, name, ecosystem, artifactCoordinate(art), decision.Reason) {
			return true
		}
		g.auditVuln(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("vulnerability gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"code", decision.Code, "maxSeverity", string(report.MaxSeverity), "maxCvss", report.MaxCVSS)
		g.notifyVuln(r, name, ecosystem, art, report, decision)
		writeVulnBlock(w, art, report, decision)
		return false
	case policy.ActionWarn:
		g.auditVuln(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("vulnerability gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"code", decision.Code, "reason", decision.Reason)
		g.notifyVuln(r, name, ecosystem, art, report, decision)
		w.Header().Set("X-Vuln-Decision", "warn")
		w.Header().Set("X-Vuln-Max-Severity", string(report.MaxSeverity))
		w.Header().Set("X-Vuln-Reason", headerSafe(decision.Reason))
		return true
	default:
		// Surface the (clean) result for transparency even on allow.
		if report != nil && report.SBOM != nil {
			w.Header().Set("X-Vuln-Decision", "allow")
			w.Header().Set("X-Vuln-Max-Severity", string(report.MaxSeverity))
		}
		return true
	}
}

// quarantineArtifact removes a poisoned artifact from both the content cache and
// the scan-result cache so it is neither served nor retained.
func (g *Gateway) quarantineArtifact(ctx context.Context, resolved *backends.Resolved, art vulnscan.Artifact) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("quarantine: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
	g.deps.Vulnerabilities.Evict(art.Digest)
}

// vulnArtifactFor builds the scanning artifact from a resolved resource, returning
// ok=false when the resource is not a concrete versioned artifact (so the gate
// does not apply). The scan-cache key is the content digest when known, otherwise
// the stable cache key.
func vulnArtifactFor(ecosystem string, resolved *backends.Resolved, entry *cache.Entry) (vulnscan.Artifact, bool) {
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		return vulnscan.Artifact{}, false
	}
	digest := resolved.Digest
	if digest == "" && entry != nil {
		digest = entry.Stat.Key
	}
	return vulnscan.Artifact{
		Ecosystem: ecosystem,
		Name:      c.Name,
		Version:   c.Version,
		Digest:    digest,
		Filename:  path.Base(resolved.UpstreamURL),
		MediaType: resolved.MediaType,
	}, true
}

// vulnError is the JSON body returned when an artifact is refused by the
// vulnerability gate. It is actionable: the developer sees the offending advisory,
// its severity/score, and where a fix is available.
type vulnError struct {
	Error         string                  `json:"error"`
	Code          string                  `json:"code"`
	Action        string                  `json:"action"`
	Reason        string                  `json:"reason"`
	Ecosystem     string                  `json:"ecosystem,omitempty"`
	Package       string                  `json:"package,omitempty"`
	Version       string                  `json:"version,omitempty"`
	MaxSeverity   string                  `json:"maxSeverity,omitempty"`
	MaxCVSS       float64                 `json:"maxCvss,omitempty"`
	Advisory      string                  `json:"advisory,omitempty"`
	FixedVersions []string                `json:"fixedVersions,omitempty"`
	Counts        vulnscan.SeverityCounts `json:"counts"`
}

// writeVulnBlock writes an actionable 403 describing why the artifact was refused.
func writeVulnBlock(w http.ResponseWriter, art vulnscan.Artifact, report *vulnscan.Report, d vulnscan.Decision) {
	body := vulnError{
		Error:     "artifact blocked by vulnerability admission policy",
		Code:      d.Code,
		Action:    string(d.Action),
		Reason:    d.Reason,
		Ecosystem: art.Ecosystem,
		Package:   art.Name,
		Version:   art.Version,
	}
	if report != nil {
		body.MaxSeverity = string(report.MaxSeverity)
		body.MaxCVSS = report.MaxCVSS
		body.Counts = report.Counts
	}
	if d.Highest != nil {
		body.Advisory = d.Highest.ID
		body.FixedVersions = d.Highest.FixedVersions
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Vuln-Decision", string(d.Action))
	h.Set("X-Vuln-Code", d.Code)
	h.Set("X-Vuln-Reason", headerSafe(d.Reason))
	if report != nil {
		h.Set("X-Vuln-Max-Severity", string(report.MaxSeverity))
	}
	h.Set("X-Cache", strings.ToUpper(string(d.Action)))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditVuln records a vulnerability-gate decision in the tamper-evident audit log.
func (g *Gateway) auditVuln(r *http.Request, backend, ecosystem string, art vulnscan.Artifact, report *vulnscan.Report, d vulnscan.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == policy.ActionWarn {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":      string(d.Action),
		"code":        d.Code,
		"package":     art.Name,
		"version":     art.Version,
		"maxSeverity": string(report.MaxSeverity),
		"maxCvss":     report.MaxCVSS,
		"critical":    report.Counts.Critical,
		"high":        report.Counts.High,
		"medium":      report.Counts.Medium,
		"low":         report.Counts.Low,
	}
	if d.Highest != nil {
		detail["advisory"] = d.Highest.ID
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "vuln:" + d.Code,
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

// notifyVuln dispatches a security alert for a vulnerability-gate decision
// (warn, block, or quarantine). A quarantine is surfaced as the dedicated
// quarantine event; warn/block are vulnerability-finding events. The alert's
// severity is the artifact's highest finding severity so a severity-filtered
// route delivers only the alerts that matter.
func (g *Gateway) notifyVuln(r *http.Request, backend, ecosystem string, art vulnscan.Artifact, report *vulnscan.Report, d vulnscan.Decision) {
	if g.deps.Notify == nil {
		return
	}
	sev := notify.NormalizeSeverity(string(report.MaxSeverity))
	advisory := ""
	if d.Highest != nil {
		advisory = d.Highest.ID
	}
	coord := artifactCoordinate(art)

	var ev notify.Event
	if d.Action == policy.ActionQuarantine {
		ev = notify.QuarantineEvent(sev, ecosystem, backend, coord, advisory, d.Reason)
	} else {
		ev = notify.VulnerabilityEvent(sev, ecosystem, backend, coord, advisory, string(d.Action), d.Reason)
	}
	ev = ev.WithField("maxCvss", strconv.FormatFloat(report.MaxCVSS, 'f', -1, 64))
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// artifactCoordinate renders a "name@version" coordinate for a scanning artifact,
// falling back to the digest when the version is unknown.
func artifactCoordinate(art vulnscan.Artifact) string {
	switch {
	case art.Name != "" && art.Version != "":
		return art.Name + "@" + art.Version
	case art.Name != "":
		return art.Name
	default:
		return art.Digest
	}
}
