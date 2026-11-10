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
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/pypiattest"
)

// gatePyPIAttest runs the inbound PyPI PEP 740 digital-attestation verification
// gate (Task 146) on a cached, signature-checked wheel/sdist. It fetches the
// distribution's PEP 740 provenance (PyPI Integrity API / JSON-index "provenance"
// field), cryptographically verifies the enclosed Sigstore attestations against
// the Fulcio/Rekor trust root, and binds the attested sha256 digest to the served
// artifact. A cryptographically-valid attestation that attests a DIFFERENT digest
// than the one served is the decisive finding (the served file is not the attested
// one).
//
// It folds its signals into the admission accumulator for the policy/risk gates
// below. Per the configured action it annotates (serve + headers), downgrades
// (serve + warning), or blocks (403 + evict, composing with the break-glass
// workflow) the pull.
//
// It returns true when the request may proceed and false when the pull was
// blocked and a response written.
func (g *Gateway) gatePyPIAttest(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.PyPIAttest == nil || !g.deps.PyPIAttest.Enabled() {
		return true
	}
	art, ok := pypiAttestArtifactFor(name, ecosystem, resolved)
	if !ok {
		return true
	}

	report, err := g.deps.PyPIAttest.Verify(r.Context(), art)
	if err != nil {
		if errors.Is(err, pypiattest.ErrNotApplicable) {
			return true
		}
		if errors.Is(err, context.Canceled) {
			return false
		}
		g.deps.Logger.Warn("pypi attestation verification errored; serving without gate",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "error", err)
		return true
	}

	recordPyPIAttestSignal(r.Context(), report)

	tenant := licenseTenant(r)
	decision := g.deps.PyPIAttest.Gate(report, tenant)
	switch decision.Action {
	case pypiattest.ActionBlock:
		if g.breakGlass(w, r, approvalGatePyPIAttest, name, ecosystem, art.Coordinate(), decision.Reason) {
			return true
		}
		g.evictArtifact(r.Context(), resolved)
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditPyPIAttest(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("pypi attestation gate refused artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code,
			"present", report.Present, "verified", report.Verified, "digestMismatch", report.DigestMismatch)
		g.notifyPyPIAttest(r, name, ecosystem, art, decision)
		writePyPIAttestBlock(w, art, report, decision)
		return false
	case pypiattest.ActionDowngrade:
		g.metrics().IncPolicyDecision(ecosystem, "warn")
		g.auditPyPIAttest(r, name, ecosystem, art, report, decision)
		g.deps.Logger.Warn("pypi attestation gate downgrade on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name, "code", decision.Code, "reason", decision.Reason)
		g.notifyPyPIAttest(r, name, ecosystem, art, decision)
		w.Header().Set("X-PyPI-Attestation-Decision", "downgrade")
		w.Header().Set("X-PyPI-Attestation-Code", decision.Code)
		w.Header().Set("X-PyPI-Attestation-Reason", headerSafe(decision.Reason))
		return true
	default:
		if report != nil && report.PublisherTrusted {
			w.Header().Set("X-PyPI-Attestation-Decision", "annotate")
			w.Header().Set("X-PyPI-Attestation-Publisher-Verified", "true")
		} else if report != nil && report.Verified {
			w.Header().Set("X-PyPI-Attestation-Decision", "annotate")
		}
		return true
	}
}

// pypiAttestArtifactFor builds the verification subject from a resolved resource,
// returning ok=false when the gate does not apply. It applies only to concrete
// pip/PyPI distributions identified by name@version.
func pypiAttestArtifactFor(backend, ecosystem string, resolved *backends.Resolved) (pypiattest.Artifact, bool) {
	switch strings.ToLower(ecosystem) {
	case "pip", "pypi":
		c := resolved.Coordinate
		if c.Name == "" || c.Version == "" {
			return pypiattest.Artifact{}, false
		}
		return pypiattest.Artifact{
			Ecosystem: ecosystem,
			Backend:   backend,
			Name:      c.Name,
			Version:   c.Version,
			Digest:    resolved.Digest,
		}, true
	default:
		return pypiattest.Artifact{}, false
	}
}

// recordPyPIAttestSignal folds a PyPI-attestation report into the per-request
// admission-signal accumulator. It is a no-op when no accumulator is attached.
func recordPyPIAttestSignal(ctx context.Context, report *pypiattest.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	in := &policyengine.PyPIAttestInput{
		Checked:              true,
		Source:               report.Source,
		Present:              report.Present,
		Verified:             report.Verified,
		PublisherTrusted:     report.PublisherTrusted,
		DigestMismatch:       report.DigestMismatch,
		TransparencyVerified: report.TransparencyVerified,
		PublisherKind:        report.Publisher.Kind,
		Repository:           report.Publisher.Repository,
		Workflow:             report.Publisher.Workflow,
		Identity:             report.Publisher.Identity,
		Issuer:               report.Publisher.Issuer,
		MaxSeverity:          report.MaxSeverity(),
		Error:                report.Error,
	}
	s.mu.Lock()
	s.input.PyPIAttest = in
	s.mu.Unlock()
}

// pypiAttestError is the JSON body returned when a distribution is refused by the
// PyPI attestation gate.
type pypiAttestError struct {
	Error            string `json:"error"`
	Code             string `json:"code"`
	Action           string `json:"action"`
	Reason           string `json:"reason"`
	Ecosystem        string `json:"ecosystem,omitempty"`
	Package          string `json:"package,omitempty"`
	Version          string `json:"version,omitempty"`
	Publisher        string `json:"publisher,omitempty"`
	Present          bool   `json:"present"`
	Verified         bool   `json:"verified"`
	PublisherTrusted bool   `json:"publisherTrusted"`
	DigestMismatch   bool   `json:"digestMismatch"`
}

// writePyPIAttestBlock writes an actionable 403 describing why the distribution
// was refused.
func writePyPIAttestBlock(w http.ResponseWriter, art pypiattest.Artifact, report *pypiattest.Report, d pypiattest.Decision) {
	body := pypiAttestError{
		Error:     "artifact refused by inbound PyPI attestation admission policy",
		Code:      d.Code,
		Action:    string(d.Action),
		Reason:    d.Reason,
		Ecosystem: art.Ecosystem,
		Package:   art.Name,
		Version:   art.Version,
	}
	if report != nil {
		body.Publisher = report.Publisher.Identity
		body.Present = report.Present
		body.Verified = report.Verified
		body.PublisherTrusted = report.PublisherTrusted
		body.DigestMismatch = report.DigestMismatch
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-PyPI-Attestation-Decision", string(d.Action))
	h.Set("X-PyPI-Attestation-Code", d.Code)
	h.Set("X-PyPI-Attestation-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCK")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditPyPIAttest records a PyPI-attestation gate decision in the tamper-evident
// audit log.
func (g *Gateway) auditPyPIAttest(r *http.Request, backend, ecosystem string, art pypiattest.Artifact, report *pypiattest.Report, d pypiattest.Decision) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionDeny
	if d.Action == pypiattest.ActionDowngrade {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":  string(d.Action),
		"code":    d.Code,
		"package": art.Name,
		"version": art.Version,
	}
	if report != nil {
		detail["present"] = report.Present
		detail["verified"] = report.Verified
		detail["publisherTrusted"] = report.PublisherTrusted
		detail["digestMismatch"] = report.DigestMismatch
		detail["publisher"] = report.Publisher.Identity
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "pypiattest:" + d.Code,
		Detail:     detail,
	}
	if d.Action.Blocks() {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyPyPIAttest dispatches a security alert for a PyPI-attestation gate
// decision (downgrade or block).
func (g *Gateway) notifyPyPIAttest(r *http.Request, backend, ecosystem string, art pypiattest.Artifact, d pypiattest.Decision) {
	if g.deps.Notify == nil {
		return
	}
	ev := notify.ProvenanceFailureEvent(ecosystem, backend, art.Coordinate(), "pypiattest:"+d.Code, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
