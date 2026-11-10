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
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// gateSigverify runs the Sigstore/cosign signature & attestation admission gate
// (Task 23) on a resolved artifact. For OCI images it verifies cosign signatures
// and SLSA provenance attestations; for npm/pip packages it verifies Sigstore
// publish attestations. It returns true when the request may proceed (allow or
// warn) and false when the artifact has been blocked/quarantined and a response
// has already been written.
//
// The gate is content-independent (signatures are fetched from the registry, not
// derived from the bytes), but runs after the cache fill so the artifact's
// content digest is reliably known and a blocked/quarantined artifact can be
// evicted from the cache.
func (g *Gateway) gateSigverify(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Sigverify == nil || !g.deps.Sigverify.Enabled() {
		return true
	}
	art, ok := sigverifyArtifactFor(name, ecosystem, resolved)
	if !ok {
		return true
	}

	report, err := g.deps.Sigverify.Verify(r.Context(), art)
	if err != nil {
		if errors.Is(err, sigverify.ErrNotApplicable) {
			return true
		}
		if errors.Is(err, context.Canceled) {
			return false
		}
		// An unexpected internal error is not a verification verdict; log and serve
		// rather than denying on infrastructure trouble the gate did not classify.
		g.deps.Logger.Warn("signature verification errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "error", err)
		return true
	}

	// Account the signature/attestation verification scan to the tenant (Task 84).
	g.meterScan(r, "sigverify")
	recordSigverifySignal(r.Context(), report)
	decision := g.deps.Sigverify.Gate(report)
	switch decision.Action {
	case policy.ActionQuarantine:
		// Human-in-the-loop break-glass (Task 50): an active grant for this
		// coordinate lets the artifact be served (and retained) despite the
		// verification failure. Consult before evicting.
		if g.breakGlass(w, r, approvalGateSigverify, name, ecosystem, sigverifyCoordinate(art), decision.Reason) {
			return true
		}
		g.evictArtifact(r.Context(), resolved)
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditSigverify(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("signature gate quarantined artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code)
		g.notifySigverify(r, name, ecosystem, art, decision)
		writeSigverifyBlock(w, art, report, decision)
		return false
	case policy.ActionBlock:
		if g.breakGlass(w, r, approvalGateSigverify, name, ecosystem, sigverifyCoordinate(art), decision.Reason) {
			return true
		}
		g.evictArtifact(r.Context(), resolved)
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditSigverify(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("signature gate blocked artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code)
		g.notifySigverify(r, name, ecosystem, art, decision)
		writeSigverifyBlock(w, art, report, decision)
		return false
	case policy.ActionWarn:
		g.metrics().IncPolicyDecision(ecosystem, "warn")
		g.auditSigverify(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("signature gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code, "reason", decision.Reason)
		g.notifySigverify(r, name, ecosystem, art, decision)
		w.Header().Set("X-Sigverify-Decision", "warn")
		w.Header().Set("X-Sigverify-Code", decision.Code)
		w.Header().Set("X-Sigverify-Reason", headerSafe(decision.Reason))
		return true
	default:
		if report != nil && report.VerifiedSignature {
			w.Header().Set("X-Sigverify-Decision", "allow")
			if report.VerifiedAttestation {
				w.Header().Set("X-Sigverify-Attested", "true")
			}
			if report.PostQuantum {
				w.Header().Set("X-Sigverify-PQC", "true")
				// Record the algorithm of a post-quantum/hybrid verification even on
				// allow, so the audit log captures PQC adoption per verification (Task 151).
				g.auditSigverify(r, name, ecosystem, art, report, decision)
			}
		}
		return true
	}
}

// sigverifyCoordinate renders a "name@version" coordinate for the break-glass
// scope, falling back to the digest when name/version are unknown.
func sigverifyCoordinate(art sigverify.Artifact) string {
	switch {
	case art.Name != "" && art.Version != "":
		return art.Name + "@" + art.Version
	case art.Name != "":
		return art.Name
	default:
		return art.Digest
	}
}

// evictArtifact removes a refused artifact from the content cache so unverified
// content is neither served nor retained.
func (g *Gateway) evictArtifact(ctx context.Context, resolved *backends.Resolved) {
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("sigverify: evicting refused artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
}

// sigverifyArtifactFor builds the verification subject from a resolved resource,
// returning ok=false when the gate does not apply: for OCI only image manifests
// (not blobs, listings, or probes) are verified; for npm/pip a concrete
// name@version is required.
func sigverifyArtifactFor(backend, ecosystem string, resolved *backends.Resolved) (sigverify.Artifact, bool) {
	switch strings.ToLower(ecosystem) {
	case "docker", "oci":
		if resolved.Metadata["_kind"] != "manifest" || resolved.Digest == "" {
			return sigverify.Artifact{}, false
		}
		return sigverify.Artifact{
			Ecosystem: ecosystem,
			Backend:   backend,
			Name:      resolved.Coordinate.Name,
			Digest:    resolved.Digest,
		}, true
	case "npm", "pip", "pypi":
		c := resolved.Coordinate
		if c.Name == "" || c.Version == "" {
			return sigverify.Artifact{}, false
		}
		return sigverify.Artifact{
			Ecosystem: ecosystem,
			Backend:   backend,
			Name:      c.Name,
			Version:   c.Version,
			Digest:    resolved.Digest,
		}, true
	default:
		return sigverify.Artifact{}, false
	}
}

// sigverifyError is the JSON body returned when an artifact is refused by the
// signature gate. It is actionable: the developer sees which authenticity check
// failed and the signer identity involved.
type sigverifyError struct {
	Error               string `json:"error"`
	Code                string `json:"code"`
	Action              string `json:"action"`
	Reason              string `json:"reason"`
	Ecosystem           string `json:"ecosystem,omitempty"`
	Package             string `json:"package,omitempty"`
	Version             string `json:"version,omitempty"`
	Digest              string `json:"digest,omitempty"`
	Identity            string `json:"identity,omitempty"`
	VerifiedSignature   bool   `json:"verifiedSignature"`
	VerifiedAttestation bool   `json:"verifiedAttestation"`
}

// writeSigverifyBlock writes an actionable 403 describing why the artifact was
// refused.
func writeSigverifyBlock(w http.ResponseWriter, art sigverify.Artifact, report *sigverify.Report, d sigverify.Decision) {
	body := sigverifyError{
		Error:     "artifact refused by signature/attestation admission policy",
		Code:      d.Code,
		Action:    string(d.Action),
		Reason:    d.Reason,
		Ecosystem: art.Ecosystem,
		Package:   art.Name,
		Version:   art.Version,
		Digest:    art.Digest,
	}
	if d.Highest != nil {
		body.Identity = d.Highest.Identity
	}
	if report != nil {
		body.VerifiedSignature = report.VerifiedSignature
		body.VerifiedAttestation = report.VerifiedAttestation
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Sigverify-Decision", string(d.Action))
	h.Set("X-Sigverify-Code", d.Code)
	h.Set("X-Sigverify-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", strings.ToUpper(string(d.Action)))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditSigverify records a signature-gate decision in the tamper-evident audit
// log.
func (g *Gateway) auditSigverify(r *http.Request, backend, ecosystem string, art sigverify.Artifact, report *sigverify.Report, d sigverify.Decision) {
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
		"digest":  art.Digest,
	}
	if report != nil {
		detail["verifiedSignature"] = report.VerifiedSignature
		detail["verifiedAttestation"] = report.VerifiedAttestation
		// Record the signature algorithm(s) used per verification (Task 151) so the
		// tamper-evident audit log captures the post-quantum posture of each gate
		// decision.
		if len(report.Algorithms) > 0 {
			detail["algorithms"] = report.Algorithms
		}
		detail["postQuantum"] = report.PostQuantum
	}
	if d.Highest != nil && d.Highest.Identity != "" {
		detail["identity"] = d.Highest.Identity
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "sigverify:" + d.Code,
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

// notifySigverify dispatches a security alert for a signature-gate decision
// (warn, block, or quarantine), reusing the provenance-failure event type since
// a signature/attestation failure is a provenance-authenticity failure.
func (g *Gateway) notifySigverify(r *http.Request, backend, ecosystem string, art sigverify.Artifact, d sigverify.Decision) {
	if g.deps.Notify == nil {
		return
	}
	coord := art.Name
	if art.Version != "" {
		coord = art.Name + "@" + art.Version
	} else if art.Digest != "" {
		coord = art.Digest
	}
	ev := notify.ProvenanceFailureEvent(ecosystem, backend, coord, "sigverify:"+d.Code, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
