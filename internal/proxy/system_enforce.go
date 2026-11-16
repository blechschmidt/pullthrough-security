package proxy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// The LLM package-content scan gate's action ladder, applied to an object the
// proxy judged for itself (Task 192).
//
// A client's pull is judged by the gate on its way out: a refusal is written,
// the object evicted, the decision audited, the alert sent and the findings
// recorded, all by the gate. The full scan judges objects nobody asked for —
// cached artifacts it puts before the gate with SystemScan, and the files the
// full mirror fetched with DeferLLMRefusal — so that a bad upload is blocked
// before any client asks for it. EnforceLLMScan does for such a reading what
// the gate does for a pull: under block or quarantine a refused object is
// evicted (unless a release pins it), and the refusal is audited and alerted
// like a client's; a flagged object that is served (annotate, a suspicious one
// under block) is audited and alerted once per verdict; and the findings
// document goes through the findings layer — de-duplication, the suppression
// trail, the findings store and the SIEM — as a pull's does.

// SystemEnforceRequest asks for the gate's action ladder to be applied to a
// reading of one cached object.
type SystemEnforceRequest struct {
	// Backend is the upstream name, Path the backend-relative path the object
	// is served under (for the audit record).
	Backend string
	Path    string
	// Tenant and Subject name who the reading was made for and by: the tenant
	// whose cache namespace holds the object, and the system principal.
	Tenant  string
	Subject string
	// CacheKey is the object's cache key (default: the reading's).
	CacheKey string
	// Scan is the reading: SystemScan's result, or a system fetch's LLMScan.
	Scan *SystemLLMScan
	// RecordFindings sends the reading's findings through the findings layer.
	// A system scan sets it; a system fetch's request recorded its own
	// findings document already.
	RecordFindings bool
	// Source names the caller in the audit record ("full-scan").
	Source string
}

// SystemEnforceResult is what the ladder did.
type SystemEnforceResult struct {
	// Refused reports that the configured action refuses the object: a pull of
	// it is refused while the reading stands. Action is the decision's action
	// ("block", "quarantine", "annotate", "fail-open", "fail-closed", or
	// "break-glass" when an active grant releases the object).
	Refused bool
	Action  string
	// Evicted reports that the object was removed from the cache; KeptPinned
	// that it was kept because a release pins it.
	Evicted    bool
	KeptPinned bool
	// Findings is how many findings were recorded.
	Findings int
}

// EnforceLLMScan applies the LLM package-content scan gate's action ladder to
// a reading of a cached object the proxy judged for itself. It never fetches
// or scans anything. Safe with a nil reading (nothing happens).
func (g *Gateway) EnforceLLMScan(ctx context.Context, req SystemEnforceRequest) (SystemEnforceResult, error) {
	sl := req.Scan
	svc := g.deps.LLMPkgScan
	if sl == nil || !sl.Applicable || sl.Report == nil {
		return SystemEnforceResult{}, nil
	}
	if !svc.Enabled() {
		return SystemEnforceResult{}, ErrLLMScanDisabled
	}
	ctx = context.WithoutCancel(ctx)
	report, d := sl.Report, sl.Decision
	key := req.CacheKey
	if key == "" {
		key = sl.CacheKey
	}
	ecosystem := g.ecosystemFor(req.Backend)
	fresh := report.Scanned() && !report.Cached
	res := SystemEnforceResult{Action: d.Action}
	if req.RecordFindings {
		res.Findings = g.recordSystemFindings(ctx, req, ecosystem, svc, report)
	}
	flagged := report.Disposition == llmpkgscan.DispositionMalicious || report.Disposition == llmpkgscan.DispositionSuspicious

	if !d.Served() && sl.BreakGlass != "" {
		// An operator's grant releases exactly these bytes: they stay, served.
		res.Action = "break-glass"
		if flagged {
			g.auditSystemLLMScan(ctx, req, ecosystem, report, d, false, false, sl.BreakGlass)
		}
		return res, nil
	}
	if !d.Served() {
		res.Refused = true
		if d.Evict && key != "" {
			pinned := sl.Pinned || (g.deps.Pins != nil && g.deps.Pins.IsPinned(key))
			switch {
			case pinned:
				// A release pins the bytes (Task 180): kept, for forensics, and
				// refused to every client while the verdict stands.
				res.KeptPinned = true
			case g.replacedSince(ctx, key, report.Artifact.Digest):
				// The cache holds other bytes under the key now (refilled
				// while the scan ran): the verdict is not about them, and they
				// are judged on their own.
			default:
				if err := g.deps.Cache.Delete(ctx, key); err == nil || errors.Is(err, cache.ErrNotFound) {
					res.Evicted = true
				} else {
					g.deps.Logger.Warn("LLM package scan: evicting a refused object failed", "key", key, "error", err)
				}
			}
		}
		g.auditSystemLLMScan(ctx, req, ecosystem, report, d, res.Evicted, res.KeptPinned, "")
		g.deps.Logger.Warn("LLM package-scan gate refused a cached artifact the proxy judged for itself",
			"source", req.Source, "backend", req.Backend, "ecosystem", ecosystem, "artifact", report.Artifact.Coordinate(),
			"digest", report.Artifact.Digest, "disposition", string(report.Disposition), "code", d.Code,
			"action", d.Action, "evicted", res.Evicted, "keptPinned", res.KeptPinned)
		// One alert per verdict: a fresh one, or a stored one that has just
		// cost the object its place in the cache.
		if report.Scanned() && (fresh || res.Evicted) {
			g.notifySystemLLMScan(ctx, req, ecosystem, report, d)
		}
		return res, nil
	}
	switch {
	case flagged:
		g.auditSystemLLMScan(ctx, req, ecosystem, report, d, false, false, "")
		if fresh {
			g.notifySystemLLMScan(ctx, req, ecosystem, report, d)
		}
	case report.Unscanned != nil && report.Unscanned.Content:
		// The artifact itself defeated the scan: a record, as on a pull.
		g.auditSystemLLMScan(ctx, req, ecosystem, report, d, false, false, "")
	}
	return res, nil
}

// replacedSince reports whether the cache holds bytes other than the ones with
// the digest given under key.
func (g *Gateway) replacedSince(ctx context.Context, key, digest string) bool {
	if digest == "" {
		return false
	}
	st, err := g.deps.Cache.Stat(ctx, key)
	if err != nil {
		return false
	}
	got := st.Metadata[cache.MetaDigest]
	return got != "" && !strings.EqualFold(got, digest)
}

// recordSystemFindings sends a reading's findings through the findings layer:
// de-duplication, the suppression trail, the findings store and the SIEM. A
// reading with nothing to report — a clean verdict — records nothing: the full
// scan reads every cached artifact, and an empty document per artifact would
// bury the ones that matter.
//
// The findings store keeps one document per tenant and coordinate, the one the
// last pull of the artifact recorded with every gate's findings. A system
// reading has only this gate's: it replaces this gate's findings in a document
// about the same bytes and keeps the others (vulnerabilities, install hooks,
// licences); the SIEM is sent the reading's own.
func (g *Gateway) recordSystemFindings(ctx context.Context, req SystemEnforceRequest, ecosystem string, svc *llmpkgscan.Service, report *llmpkgscan.Report) int {
	if len(report.Findings) == 0 || (g.deps.Findings == nil && g.deps.SIEM == nil) {
		return 0
	}
	art := report.Artifact
	name := art.Name
	if name == "" {
		name = art.Filename
	}
	if name == "" {
		return 0
	}
	in := policyengine.Input{
		Tenant: req.Tenant,
		Artifact: policyengine.ArtifactInput{
			Ecosystem: ecosystem, Backend: req.Backend, Name: name, Version: art.Version, Digest: art.Digest,
		},
		LLMPackage: llmPkgScanInput(svc, report),
	}
	doc := findings.FromInput(in, findings.Options{GeneratedAt: time.Now().UTC()})
	if len(doc.Findings) == 0 {
		return 0
	}
	g.deps.FindingsMetrics.RecordDedup(doc.Deduplicate())
	g.deps.Suppressions.RecordFromDocument(ctx, &doc)
	if g.deps.Findings != nil {
		stored := doc
		// A pull's document names the digest the upstream declared, if any
		// (the cache fill verified the bytes against it): no digest, or the
		// reading's, is a document about the same bytes.
		if prev, ok := g.deps.Findings.Get(doc.Tenant, doc.Artifact.Coordinate); ok &&
			prev.Artifact.Coordinate == doc.Artifact.Coordinate &&
			(prev.Artifact.Digest == "" || strings.EqualFold(prev.Artifact.Digest, doc.Artifact.Digest)) {
			merged := prev
			merged.Findings = nil
			for _, f := range prev.Findings {
				if f.Gate != findings.GateLLMPkgScan {
					merged.Findings = append(merged.Findings, f)
				}
			}
			merged.Findings = append(merged.Findings, doc.Findings...)
			merged.GeneratedAt = doc.GeneratedAt
			stored = merged
		}
		g.deps.Findings.Record(stored)
	}
	if g.deps.SIEM != nil {
		g.deps.SIEM.ForwardFindings(ctx, doc)
	}
	return len(doc.Findings)
}

// auditSystemLLMScan records the ladder's decision on a reading in the audit
// log, in the shape of the gate's own record (reason "llmpkgscan:<code>"),
// with the caller named.
func (g *Gateway) auditSystemLLMScan(ctx context.Context, req SystemEnforceRequest, ecosystem string, report *llmpkgscan.Report, d llmpkgscan.Decision, evicted, keptPinned bool, breakGlass string) {
	if g.deps.Audit == nil {
		return
	}
	art := report.Artifact
	decision := audit.DecisionDeny
	if d.Served() || breakGlass != "" {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":      d.Action,
		"code":        d.Code,
		"package":     art.Name,
		"version":     art.Version,
		"digest":      art.Digest,
		"disposition": string(report.Disposition),
		"evicted":     evicted,
		"source":      firstNonEmptyString(req.Source, "system"),
	}
	if keptPinned {
		detail["keptPinned"] = true
	}
	if breakGlass != "" {
		detail["breakGlass"] = breakGlass
	}
	if v := report.Verdict; v != nil {
		detail["verdict"] = v.Verdict
		detail["confidence"] = v.Confidence
		detail["provider"] = v.Provider
		detail["model"] = v.Model
		detail["promptVersion"] = v.PromptVersion
		detail["verdictKey"] = v.Key
		detail["cached"] = report.Cached
		detail["truncated"] = v.Truncated
		detail["findings"] = len(report.Findings)
	}
	if u := report.Unscanned; u != nil {
		detail["unscannedCode"] = u.Code
		detail["contentAttributable"] = u.Content
	}
	ev := audit.Event{
		Type:      audit.EventPolicy,
		Method:    http.MethodGet,
		Subject:   req.Subject,
		Team:      req.Tenant,
		Backend:   req.Backend,
		Ecosystem: ecosystem,
		Decision:  decision,
		Reason:    "llmpkgscan:" + d.Code,
		Detail:    detail,
	}
	if strings.HasPrefix(req.Path, "/") {
		ev.Resource = "/v1/" + req.Backend + req.Path
	}
	if decision == audit.DecisionDeny {
		ev.Status = http.StatusForbidden
	}
	g.logAudit(ctx, ev)
}

// notifySystemLLMScan sends the security alert for a flagged reading, as the
// gate does for a pull.
func (g *Gateway) notifySystemLLMScan(ctx context.Context, req SystemEnforceRequest, ecosystem string, report *llmpkgscan.Report, d llmpkgscan.Decision) {
	if g.deps.Notify == nil || report.Verdict == nil {
		return
	}
	sev := notify.SeverityMedium
	switch report.Disposition {
	case llmpkgscan.DispositionMalicious:
		sev = notify.SeverityCritical
	case llmpkgscan.DispositionSuspicious:
		for _, f := range report.Findings {
			if severityRank(f.Severity) >= severityRank("high") {
				sev = notify.SeverityHigh
			}
		}
	}
	v := report.Verdict
	ev := notify.LLMPackageScanEvent(sev, ecosystem, req.Backend, report.Artifact.Coordinate(),
		string(report.Disposition), d.Action, v.Model, v.Confidence, d.Reason)
	ev.Subject = req.Subject
	g.emit(ctx, ev)
}

// LLMScanObserver hears of the gate's reading of each cached artifact a client
// pulls (Dependencies.LLMScanObserver).
type LLMScanObserver interface {
	ObserveLLMScan(ctx context.Context, obs LLMScanObservation)
}

// LLMScanObservation is the gate's reading of one cached artifact a client
// pulled.
type LLMScanObservation struct {
	// Backend is the upstream, Path the backend-relative request path, Accept
	// the request's Accept header, Tenant the client principal's tenant.
	Backend string
	Path    string
	Accept  string
	Tenant  string
	// CacheKey, Digest and Size describe the cached object.
	CacheKey string
	Digest   string
	Size     int64
	// Scan is the reading (NotApplicable when the gate did not examine the
	// object); Evicted reports that the refusal removed it from the cache.
	Scan    *SystemLLMScan
	Evicted bool
}
