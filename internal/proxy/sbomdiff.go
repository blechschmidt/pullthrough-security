package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// gateSbomDiff runs the SBOM diff & dependency-drift subsystem (Task 64) on a
// cached artifact. It reduces the SBOM the vulnerability subsystem already
// generated (or extracts it on demand) plus the scan's vulnerabilities to a
// per-version snapshot, records it in the bounded per-coordinate history, and
// diffs the new version against the prior one. It folds the resulting drift score
// into the admission accumulator (a policy/risk signal) and, when the score meets
// the block threshold and the subsystem is configured to enforce, warns on or
// blocks/quarantines the artifact. It runs after the vulnerability and license
// gates (so the SBOM and post-VEX vulnerabilities are available) and before the
// aggregating policy/risk gates (so its signal feeds them).
//
// It returns true when the request may proceed (allow, warn, or no prior version
// to compare) and false when the artifact was blocked/quarantined and a response
// has been written.
func (g *Gateway) gateSbomDiff(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if !g.deps.SbomDiff.Enabled() {
		return true
	}
	art, ok := vulnArtifactFor(ecosystem, resolved, entry)
	if !ok {
		return true
	}

	sbom := g.licenseSBOM(r.Context(), art, resolved)
	vulns := g.sbomDiffVulns(art.Digest)

	tenant := licenseTenant(r)
	snap := sbomdiff.BuildSnapshot(sbomdiff.SnapshotInput{
		Tenant:     tenant,
		Ecosystem:  ecosystem,
		Coordinate: art.Name,
		Version:    art.Version,
		Digest:     art.Digest,
		ObservedAt: time.Now().UTC(),
	}, sbom, vulns)

	res := g.deps.SbomDiff.Observe(snap)
	if !res.Compared || res.Diff == nil {
		// First sighting of this coordinate: baseline recorded, nothing to compare.
		return true
	}

	recordSbomDriftSignal(r.Context(), res.Diff)

	switch res.Action {
	case policy.ActionQuarantine:
		if g.breakGlass(w, r, approvalGateSbomDrift, name, ecosystem, artifactCoordinate(art), res.Reason) {
			return true
		}
		g.quarantineArtifact(r.Context(), resolved, art)
		g.auditSbomDrift(r, name, ecosystem, art, res)
		g.deps.Logger.Warn("sbom-diff gate quarantined artifact on dependency drift",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"driftScore", res.Diff.DriftScore, "from", res.Diff.From.Version, "to", res.Diff.To.Version)
		g.notifySbomDrift(r, name, ecosystem, art, res)
		writeSbomDriftBlock(w, art, res)
		return false
	case policy.ActionBlock:
		if g.breakGlass(w, r, approvalGateSbomDrift, name, ecosystem, artifactCoordinate(art), res.Reason) {
			return true
		}
		g.auditSbomDrift(r, name, ecosystem, art, res)
		g.deps.Logger.Warn("sbom-diff gate blocked artifact on dependency drift",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"driftScore", res.Diff.DriftScore, "from", res.Diff.From.Version, "to", res.Diff.To.Version)
		g.notifySbomDrift(r, name, ecosystem, art, res)
		writeSbomDriftBlock(w, art, res)
		return false
	case policy.ActionWarn:
		if res.Significant {
			g.auditSbomDrift(r, name, ecosystem, art, res)
			g.notifySbomDrift(r, name, ecosystem, art, res)
		}
		g.deps.Logger.Info("sbom-diff gate detected dependency drift",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"driftScore", res.Diff.DriftScore, "from", res.Diff.From.Version, "to", res.Diff.To.Version)
		setSbomDriftHeaders(w, res)
		return true
	default:
		if res.Diff.DriftScore > 0 {
			setSbomDriftHeaders(w, res)
		}
		return true
	}
}

// sbomDiffVulns returns the post-VEX vulnerabilities the scan subsystem cached
// for a digest, or nil when scanning is disabled / no report exists. Reusing the
// cached report means the diff never re-scans.
func (g *Gateway) sbomDiffVulns(digest string) []vulnscan.Vulnerability {
	if g.deps.Vulnerabilities == nil || digest == "" {
		return nil
	}
	rep, ok := g.deps.Vulnerabilities.Report(digest)
	if !ok || rep == nil {
		return nil
	}
	return rep.Vulnerabilities
}

// recordSbomDriftSignal folds the diff into the per-request policy/risk signal
// accumulator so the policy-as-code engine can key on the drift.
func recordSbomDriftSignal(ctx context.Context, diff *sbomdiff.Diff) {
	s := signalsFrom(ctx)
	if s == nil || diff == nil {
		return
	}
	denied := 0
	for _, l := range diff.NewLicenses {
		switch l.Disposition {
		case "denied", "deny", "review":
			denied++
		}
	}
	in := &policyengine.SbomDriftInput{
		Evaluated:          true,
		FromVersion:        diff.From.Version,
		ToVersion:          diff.To.Version,
		DriftScore:         diff.DriftScore,
		Significant:        diff.Significant,
		AddedDeps:          len(diff.AddedDeps),
		RemovedDeps:        len(diff.RemovedDeps),
		VersionBumps:       len(diff.VersionBumps),
		NewNamespaces:      len(diff.NewNamespaces),
		NewLicenses:        len(diff.NewLicenses),
		NewDeniedLicenses:  denied,
		NewVulnerabilities: len(diff.NewVulnerabilities),
	}
	s.mu.Lock()
	s.input.SbomDrift = in
	s.mu.Unlock()
}

// setSbomDriftHeaders annotates the response with the drift verdict so a client
// or downstream proxy can observe it without parsing a body.
func setSbomDriftHeaders(w http.ResponseWriter, res sbomdiff.DriftResult) {
	h := w.Header()
	h.Set("X-Sbom-Drift-Score", strconv.FormatFloat(res.Diff.DriftScore, 'f', -1, 64))
	h.Set("X-Sbom-Drift-From", headerSafe(res.Diff.From.Version))
	h.Set("X-Sbom-Drift-To", headerSafe(res.Diff.To.Version))
	if res.Significant {
		h.Set("X-Sbom-Drift", "significant")
	}
}

// sbomDriftError is the JSON body returned when an artifact is refused for
// excessive dependency drift. It is actionable: the operator sees the score, the
// versions compared, and a summary of what changed.
type sbomDriftError struct {
	Error         string  `json:"error"`
	Code          string  `json:"code"`
	Action        string  `json:"action"`
	Reason        string  `json:"reason"`
	Ecosystem     string  `json:"ecosystem,omitempty"`
	Package       string  `json:"package,omitempty"`
	FromVersion   string  `json:"fromVersion,omitempty"`
	ToVersion     string  `json:"toVersion,omitempty"`
	DriftScore    float64 `json:"driftScore"`
	AddedDeps     int     `json:"addedDeps"`
	NewNamespaces int     `json:"newNamespaces"`
	NewLicenses   int     `json:"newLicenses"`
	NewVulns      int     `json:"newVulnerabilities"`
}

// writeSbomDriftBlock writes an actionable 403 describing the refused drift.
func writeSbomDriftBlock(w http.ResponseWriter, art vulnscan.Artifact, res sbomdiff.DriftResult) {
	d := res.Diff
	body := sbomDriftError{
		Error:         "artifact blocked by dependency-drift policy",
		Code:          res.Code,
		Action:        string(res.Action),
		Reason:        res.Reason,
		Ecosystem:     art.Ecosystem,
		Package:       art.Name,
		FromVersion:   d.From.Version,
		ToVersion:     d.To.Version,
		DriftScore:    d.DriftScore,
		AddedDeps:     len(d.AddedDeps),
		NewNamespaces: len(d.NewNamespaces),
		NewLicenses:   len(d.NewLicenses),
		NewVulns:      len(d.NewVulnerabilities),
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Sbom-Drift-Decision", string(res.Action))
	h.Set("X-Sbom-Drift-Score", strconv.FormatFloat(d.DriftScore, 'f', -1, 64))
	h.Set("X-Sbom-Drift-Reason", headerSafe(res.Reason))
	h.Set("X-Cache", strings.ToUpper(string(res.Action)))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditSbomDrift records a drift decision in the tamper-evident audit log.
func (g *Gateway) auditSbomDrift(r *http.Request, backend, ecosystem string, art vulnscan.Artifact, res sbomdiff.DriftResult) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if res.Action == policy.ActionWarn {
		decision = audit.DecisionAllow
	}
	d := res.Diff
	detail := map[string]any{
		"action":             string(res.Action),
		"code":               res.Code,
		"package":            art.Name,
		"fromVersion":        d.From.Version,
		"toVersion":          d.To.Version,
		"driftScore":         d.DriftScore,
		"addedDeps":          len(d.AddedDeps),
		"newNamespaces":      len(d.NewNamespaces),
		"newLicenses":        len(d.NewLicenses),
		"newVulnerabilities": len(d.NewVulnerabilities),
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "sbom-drift:" + res.Code,
		Detail:     detail,
	}
	if res.Action.Blocked() {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifySbomDrift dispatches a security alert for a significant drift decision.
func (g *Gateway) notifySbomDrift(r *http.Request, backend, ecosystem string, art vulnscan.Artifact, res sbomdiff.DriftResult) {
	if g.deps.Notify == nil {
		return
	}
	d := res.Diff
	ev := notify.SbomDriftEvent(ecosystem, backend, artifactCoordinate(art),
		d.From.Version, d.To.Version, string(res.Action), d.DriftScore,
		len(d.AddedDeps), len(d.NewVulnerabilities), len(d.NewLicenses), len(d.NewNamespaces),
		res.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
