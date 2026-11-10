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
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
)

// gateBuildProv runs the inbound build-provenance verification gate (Task 72) on
// a cached, signature-checked artifact. It fetches the upstream-published build
// provenance (npm provenance / GitHub artifact attestation), cryptographically
// verifies it, and cross-checks the source commit/repository it PROVES against
// the package-to-commit association the provenance subsystem (Task 8) reported —
// the source CLAIMED by package metadata. A disagreement is the decisive finding.
//
// It runs right after the signature gate (both establish authenticity/source
// integrity) and folds its signals into the admission accumulator for the policy/
// risk gates below. Non-blocking in observe mode; in enforce mode a failing
// finding (notably a confirmed source mismatch) is refused here and the artifact
// evicted, composing with the break-glass workflow.
//
// It returns true when the request may proceed (observe path, or any non-blocking
// verdict) and false when an enforced finding was refused and a response written.
func (g *Gateway) gateBuildProv(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.BuildProv == nil || !g.deps.BuildProv.Enabled() {
		return true
	}
	art, ok := buildProvArtifactFor(name, ecosystem, resolved)
	if !ok {
		return true
	}
	// Resolve the metadata-claimed source association to cross-check against.
	art.Claim = g.buildProvClaim(r.Context(), ecosystem, resolved)
	if art.RepositoryURL == "" {
		art.RepositoryURL = art.Claim.RepositoryURL
	}

	report, err := g.deps.BuildProv.Verify(r.Context(), art)
	if err != nil {
		if errors.Is(err, buildprov.ErrNotApplicable) {
			return true
		}
		if errors.Is(err, context.Canceled) {
			return false
		}
		g.deps.Logger.Warn("build-provenance verification errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "error", err)
		return true
	}

	recordBuildProvSignal(r.Context(), report)

	tenant := licenseTenant(r)
	decision := g.deps.BuildProv.Gate(report, tenant)
	switch decision.Action {
	case policy.ActionQuarantine, policy.ActionBlock:
		if g.breakGlass(w, r, approvalGateBuildProv, name, ecosystem, art.Coordinate(), decision.Reason) {
			return true
		}
		g.evictArtifact(r.Context(), resolved)
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditBuildProv(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("build-provenance gate refused artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code,
			"provenCommit", report.CommitSHA, "claimedCommit", art.Claim.CommitSHA)
		g.notifyBuildProv(r, name, ecosystem, art, report, decision)
		writeBuildProvBlock(w, art, report, decision)
		return false
	case policy.ActionWarn:
		g.metrics().IncPolicyDecision(ecosystem, "warn")
		g.auditBuildProv(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("build-provenance gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code, "reason", decision.Reason)
		g.notifyBuildProv(r, name, ecosystem, art, report, decision)
		w.Header().Set("X-BuildProv-Decision", "warn")
		w.Header().Set("X-BuildProv-Code", decision.Code)
		w.Header().Set("X-BuildProv-Reason", headerSafe(decision.Reason))
		return true
	default:
		if report != nil && report.SourceVerified {
			w.Header().Set("X-BuildProv-Decision", "allow")
			w.Header().Set("X-BuildProv-Source-Verified", "true")
		} else if report != nil && report.Verified {
			w.Header().Set("X-BuildProv-Decision", "allow")
		}
		return true
	}
}

// buildProvArtifactFor builds the verification subject from a resolved resource,
// returning ok=false when the gate does not apply. It mirrors the signature gate:
// for package ecosystems a concrete name@version is required.
func buildProvArtifactFor(backend, ecosystem string, resolved *backends.Resolved) (buildprov.Artifact, bool) {
	switch strings.ToLower(ecosystem) {
	case "npm", "pip", "pypi":
		c := resolved.Coordinate
		if c.Name == "" || c.Version == "" {
			return buildprov.Artifact{}, false
		}
		return buildprov.Artifact{
			Ecosystem: ecosystem,
			Backend:   backend,
			Name:      c.Name,
			Version:   c.Version,
			Digest:    resolved.Digest,
		}, true
	default:
		return buildprov.Artifact{}, false
	}
}

// buildProvClaim resolves the metadata-claimed package-to-commit association for
// the artifact. It prefers the provenance signal the earlier gates already
// recorded on the per-request accumulator; absent that it resolves directly via
// the provenance resolver (which caches).
func (g *Gateway) buildProvClaim(ctx context.Context, ecosystem string, resolved *backends.Resolved) buildprov.Claim {
	if s := signalsFrom(ctx); s != nil {
		s.mu.Lock()
		prov := s.input.Provenance
		s.mu.Unlock()
		if prov != nil && prov.Found && (prov.CommitSHA != "" || prov.RepositoryURL != "") {
			return buildprov.Claim{
				CommitSHA:     prov.CommitSHA,
				RepositoryURL: prov.RepositoryURL,
				Confidence:    prov.Confidence,
				Source:        "provenance",
			}
		}
	}
	if g.deps.Provenance != nil {
		art := provenance.Artifact{
			Ecosystem: ecosystem,
			Name:      resolved.Coordinate.Name,
			Version:   resolved.Coordinate.Version,
			Digest:    resolved.Digest,
		}
		if link, err := g.deps.Provenance.Resolve(ctx, art); err == nil && link != nil {
			return buildprov.Claim{
				CommitSHA:     link.CommitSHA,
				RepositoryURL: link.RepositoryURL,
				Confidence:    string(link.Confidence),
				Source:        link.ResolverName,
			}
		}
	}
	return buildprov.Claim{}
}

// recordBuildProvSignal folds a build-provenance report into the per-request
// admission-signal accumulator. It is a no-op when no accumulator is attached.
func recordBuildProvSignal(ctx context.Context, report *buildprov.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	in := &policyengine.BuildProvInput{
		Checked:              true,
		Source:               report.Source,
		Present:              report.Present,
		Verified:             report.Verified,
		SourceVerified:       report.SourceVerified,
		Mismatch:             report.Mismatch,
		CommitSHA:            report.CommitSHA,
		RepositoryURL:        report.RepositoryURL,
		Builder:              report.BuilderID,
		WorkflowRef:          report.WorkflowRef,
		ClaimedCommitSHA:     report.Artifact.Claim.CommitSHA,
		ClaimedRepositoryURL: report.Artifact.Claim.RepositoryURL,
		MaxSeverity:          report.MaxSeverity(),
		Error:                report.Error,
	}
	s.mu.Lock()
	s.input.BuildProv = in
	s.mu.Unlock()
}

// buildProvError is the JSON body returned when an artifact is refused by the
// build-provenance gate.
type buildProvError struct {
	Error          string `json:"error"`
	Code           string `json:"code"`
	Action         string `json:"action"`
	Reason         string `json:"reason"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	Package        string `json:"package,omitempty"`
	Version        string `json:"version,omitempty"`
	ProvenCommit   string `json:"provenCommit,omitempty"`
	ProvenRepo     string `json:"provenRepository,omitempty"`
	ClaimedCommit  string `json:"claimedCommit,omitempty"`
	ClaimedRepo    string `json:"claimedRepository,omitempty"`
	WorkflowRef    string `json:"workflowRef,omitempty"`
	Present        bool   `json:"present"`
	Verified       bool   `json:"verified"`
	SourceVerified bool   `json:"sourceVerified"`
	Mismatch       bool   `json:"mismatch"`
}

// writeBuildProvBlock writes an actionable 403 describing why the artifact was
// refused.
func writeBuildProvBlock(w http.ResponseWriter, art buildprov.Artifact, report *buildprov.Report, d buildprov.Decision) {
	body := buildProvError{
		Error:         "artifact refused by inbound build-provenance admission policy",
		Code:          d.Code,
		Action:        string(d.Action),
		Reason:        d.Reason,
		Ecosystem:     art.Ecosystem,
		Package:       art.Name,
		Version:       art.Version,
		ClaimedCommit: art.Claim.CommitSHA,
		ClaimedRepo:   art.Claim.RepositoryURL,
	}
	if report != nil {
		body.ProvenCommit = report.CommitSHA
		body.ProvenRepo = report.RepositoryURL
		body.WorkflowRef = report.WorkflowRef
		body.Present = report.Present
		body.Verified = report.Verified
		body.SourceVerified = report.SourceVerified
		body.Mismatch = report.Mismatch
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-BuildProv-Decision", string(d.Action))
	h.Set("X-BuildProv-Code", d.Code)
	h.Set("X-BuildProv-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", strings.ToUpper(string(d.Action)))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditBuildProv records a build-provenance gate decision in the tamper-evident
// audit log.
func (g *Gateway) auditBuildProv(r *http.Request, backend, ecosystem string, art buildprov.Artifact, report *buildprov.Report, d buildprov.Decision) {
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
		"mode":    string(d.Mode),
		"package": art.Name,
		"version": art.Version,
	}
	if report != nil {
		detail["present"] = report.Present
		detail["verified"] = report.Verified
		detail["sourceVerified"] = report.SourceVerified
		detail["mismatch"] = report.Mismatch
		detail["provenCommit"] = report.CommitSHA
		detail["claimedCommit"] = art.Claim.CommitSHA
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "buildprov:" + d.Code,
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

// notifyBuildProv dispatches a security alert for a build-provenance gate
// decision (warn, block, or quarantine).
func (g *Gateway) notifyBuildProv(r *http.Request, backend, ecosystem string, art buildprov.Artifact, report *buildprov.Report, d buildprov.Decision) {
	if g.deps.Notify == nil {
		return
	}
	action := "warn"
	if d.Action.Blocked() {
		action = "block"
		if d.Action == policy.ActionQuarantine {
			action = "quarantine"
		}
	}
	provenCommit := ""
	if report != nil {
		provenCommit = report.CommitSHA
	}
	ev := notify.BuildProvenanceEvent(ecosystem, backend, art.Coordinate(), d.Code, action,
		provenCommit, art.Claim.CommitSHA, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
