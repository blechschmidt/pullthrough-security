package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// gateLicense runs the license-compliance admission gate (Task 28) on a cached
// artifact. It reads the artifact's SPDX license(s) from the SBOM the
// vulnerability subsystem already generated (or extracts the SBOM on demand when
// vulnerability scanning is disabled), evaluates them against the configured
// allow/deny/review policy for the request's tenant, and applies the resulting
// action. It returns true when the request may proceed (allow or warn) and false
// when the artifact was blocked or quarantined and a response has been written.
func (g *Gateway) gateLicense(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.License == nil {
		return true
	}
	art, ok := vulnArtifactFor(ecosystem, resolved, entry)
	if !ok {
		return true
	}

	sbom := g.licenseSBOM(r.Context(), art, resolved)
	comps := licenseComponents(art, sbom)
	if len(comps) == 0 {
		return true
	}

	tenant := licenseTenant(r)
	decision := g.deps.License.Evaluate(tenant, comps)
	recordLicenseSignal(r.Context(), decision)

	switch decision.Action {
	case policy.ActionQuarantine:
		g.quarantineLicense(r.Context(), resolved, art)
		g.auditLicense(r, name, ecosystem, art, decision)
		g.deps.Logger.Warn("license gate quarantined artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"code", decision.Code, "tenant", tenant)
		g.notifyLicense(r, name, ecosystem, art, decision)
		writeLicenseBlock(w, art, decision)
		return false
	case policy.ActionBlock:
		g.auditLicense(r, name, ecosystem, art, decision)
		g.deps.Logger.Warn("license gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"code", decision.Code, "reason", decision.Reason, "tenant", tenant)
		g.notifyLicense(r, name, ecosystem, art, decision)
		writeLicenseBlock(w, art, decision)
		return false
	case policy.ActionWarn:
		// A routine undeclared license ("unknown") is common for artifacts whose
		// license cannot be extracted (Go modules, Docker images); recording an
		// audit entry and firing an alert on every such pull would be noise. So a
		// non-blocking "unknown" is surfaced via the response headers and the
		// cumulative metrics only, while an explicit review-list match or a license
		// drift (the actionable warns) is audited and alerted.
		if decision.Code != "unknown" {
			g.auditLicense(r, name, ecosystem, art, decision)
			g.notifyLicense(r, name, ecosystem, art, decision)
		}
		g.deps.Logger.Warn("license gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"code", decision.Code, "reason", decision.Reason, "tenant", tenant)
		w.Header().Set("X-License-Decision", "warn")
		w.Header().Set("X-License-Code", decision.Code)
		w.Header().Set("X-License-Reason", headerSafe(decision.Reason))
		return true
	default:
		w.Header().Set("X-License-Decision", "allow")
		return true
	}
}

// licenseSBOM obtains the artifact's SBOM, preferring the one the vulnerability
// subsystem already cached (no re-read of content) and falling back to extracting
// it from the cached content when vulnerability scanning is disabled.
func (g *Gateway) licenseSBOM(ctx context.Context, art vulnscan.Artifact, resolved *backends.Resolved) *vulnscan.SBOM {
	if g.deps.Vulnerabilities != nil {
		if rep, ok := g.deps.Vulnerabilities.Report(art.Digest); ok && rep != nil && rep.SBOM != nil {
			return rep.SBOM
		}
	}
	e, err := g.deps.Cache.Get(ctx, resolved.CacheKey)
	if err != nil {
		// Without content we can still evaluate the primary coordinate (it will be
		// NOASSERTION and flagged for review if no license is otherwise known).
		sbom, _ := vulnscan.Extract(art, nil)
		return sbom
	}
	defer e.Content.Close()
	sbom, _ := vulnscan.Extract(art, e.Content)
	return sbom
}

// licenseComponents builds the license-evaluation inputs from an SBOM: the
// primary artifact (always present, even when it declares no license, so an
// undeclared license is surfaced for review) plus any dependency component that
// carries a declared license.
func licenseComponents(art vulnscan.Artifact, sbom *vulnscan.SBOM) []license.Component {
	var comps []license.Component

	primary := license.Component{
		Ecosystem: art.Ecosystem,
		Name:      art.Name,
		Version:   art.Version,
		Primary:   true,
	}
	if sbom != nil && sbom.Metadata != nil && sbom.Metadata.Component != nil {
		primary.Expression = sbom.Metadata.Component.LicenseExpression()
	}
	comps = append(comps, primary)

	if sbom != nil {
		for i := range sbom.Components {
			c := &sbom.Components[i]
			expr := c.LicenseExpression()
			if expr == "" {
				continue
			}
			comps = append(comps, license.Component{
				Ecosystem:  art.Ecosystem,
				Name:       componentName(c),
				Version:    c.Version,
				Expression: expr,
			})
		}
	}
	return comps
}

// componentName renders a dependency component's display name, including its
// group/namespace when present.
func componentName(c *vulnscan.Component) string {
	if c.Group != "" {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

// licenseTenant resolves the tenant key for per-tenant license policy from the
// authenticated principal's team, or "" for an anonymous/unmapped request.
func licenseTenant(r *http.Request) string {
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		return p.Team
	}
	return ""
}

// quarantineLicense evicts a license-noncompliant artifact from the content cache
// (and the scan-result cache when present) so it is neither served nor retained.
func (g *Gateway) quarantineLicense(ctx context.Context, resolved *backends.Resolved, art vulnscan.Artifact) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("license quarantine: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
	if g.deps.Vulnerabilities != nil {
		g.deps.Vulnerabilities.Evict(art.Digest)
	}
}

// licenseError is the JSON body returned when an artifact is refused by the
// license gate. It is actionable: the developer sees the offending license and
// the per-component findings.
type licenseError struct {
	Error     string            `json:"error"`
	Code      string            `json:"code"`
	Action    string            `json:"action"`
	Reason    string            `json:"reason"`
	Ecosystem string            `json:"ecosystem,omitempty"`
	Package   string            `json:"package,omitempty"`
	Version   string            `json:"version,omitempty"`
	Tenant    string            `json:"tenant,omitempty"`
	Findings  []license.Finding `json:"findings,omitempty"`
}

// writeLicenseBlock writes an actionable 403 describing why the artifact was
// refused by the license gate.
func writeLicenseBlock(w http.ResponseWriter, art vulnscan.Artifact, d license.Decision) {
	body := licenseError{
		Error:     "artifact blocked by license-compliance policy",
		Code:      d.Code,
		Action:    string(d.Action),
		Reason:    d.Reason,
		Ecosystem: art.Ecosystem,
		Package:   art.Name,
		Version:   art.Version,
		Tenant:    d.Tenant,
		Findings:  d.Findings,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-License-Decision", string(d.Action))
	h.Set("X-License-Code", d.Code)
	h.Set("X-License-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", strings.ToUpper(string(d.Action)))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditLicense records a license-gate decision in the tamper-evident audit log.
func (g *Gateway) auditLicense(r *http.Request, backend, ecosystem string, art vulnscan.Artifact, d license.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == policy.ActionWarn {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":  string(d.Action),
		"code":    d.Code,
		"package": art.Name,
		"version": art.Version,
	}
	if len(d.Findings) > 0 {
		detail["license"] = d.Findings[0].License
		detail["findings"] = len(d.Findings)
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "license:" + d.Code,
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

// notifyLicense dispatches a security alert for a license-gate decision. The
// alert's severity escalates with the gate action so a severity-filtered route
// delivers only the alerts that matter.
func (g *Gateway) notifyLicense(r *http.Request, backend, ecosystem string, art vulnscan.Artifact, d license.Decision) {
	if g.deps.Notify == nil {
		return
	}
	licenseID := ""
	if len(d.Findings) > 0 {
		licenseID = d.Findings[0].License
	}
	sev := licenseEventSeverity(d)
	ev := notify.LicenseViolationEvent(sev, ecosystem, backend, artifactCoordinate(art),
		licenseID, string(d.Action), d.Code, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// licenseEventSeverity maps a license decision to an alert severity: a block /
// quarantine is high, a warn is medium, drift at least medium.
func licenseEventSeverity(d license.Decision) notify.Severity {
	switch {
	case d.Action.Blocked():
		return notify.SeverityHigh
	case d.Code == "drift":
		return notify.SeverityMedium
	default:
		return notify.SeverityMedium
	}
}
