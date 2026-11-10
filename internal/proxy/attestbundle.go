package proxy

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// Outbound attestation (Task 46): once an artifact has cleared every admission
// gate and is about to be served, the proxy assembles a signed in-toto/SLSA
// statement that binds the served artifact digest to its source commit, the
// verdicts it passed, and the proxy's identity, then signs it with the audit-log
// signing key (or a dedicated cosign key). This turns the proxy from a verifier
// into an ATTESTER: downstream CI can require "admitted and signed by our proxy".
//
// recordAttestation runs only on the admitted/served path (after the risk gate),
// reusing the same per-request signal accumulator the policy/risk/findings layers
// read, so it adds no scanning work — it re-projects what the gates computed into
// the attestation predicate. It is best-effort and never blocks or fails a pull;
// the produced bundle's digest is folded into the tamper-evident audit log so the
// attestation itself is anchored in the chain.

// recordAttestation builds, signs, and stores the outbound attestation for a
// served artifact and embeds its bundle digest in the audit log. It is a no-op
// when the attestor is absent or the request never resolved an addressable
// artifact.
func (g *Gateway) recordAttestation(r *http.Request, backend, ecosystem string) {
	if g.deps.Attestor == nil {
		return
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return
	}
	s.mu.Lock()
	in := s.input
	risk := s.risk
	policy := s.policy
	s.mu.Unlock()

	// An attestation must bind a concrete subject: both an addressable coordinate
	// and a content digest. A bare path with no resolved digest has nothing to
	// vouch for, so skip it rather than emit an unbindable claim.
	if in.Artifact.Name == "" || in.Artifact.Digest == "" {
		return
	}

	bundle, err := g.deps.Attestor.AttestFromSignals(in, risk, policy)
	if err != nil {
		g.deps.Logger.Warn("outbound attestation failed",
			"backend", backend, "ecosystem", ecosystem, "artifact", in.Artifact.Name, "error", err)
		return
	}
	if bundle == nil {
		return
	}

	g.deps.Logger.Debug("attested served artifact",
		"backend", backend, "artifact", in.Artifact.Name,
		"subjectDigest", bundle.SubjectDigest, "bundleDigest", bundle.Digest)
	g.auditAttestation(r, backend, ecosystem, in.Artifact.Name, in.Artifact.Version, bundle)
}

// auditAttestation records the produced attestation — most importantly its
// verifiable bundle digest — into the tamper-evident audit log, so the chain
// commits to the exact bytes of every attestation the proxy issued.
func (g *Gateway) auditAttestation(r *http.Request, backend, ecosystem, pkg, version string, bundle *attestbundle.Bundle) {
	if g.deps.Audit == nil {
		return
	}
	ev := audit.Event{
		Type:       audit.EventAttestation,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   audit.DecisionAllow,
		Reason:     "attestbundle:issued",
		Detail: map[string]any{
			"package":       pkg,
			"version":       version,
			"subjectDigest": bundle.SubjectDigest,
			"bundleDigest":  bundle.Digest,
			"predicateType": bundle.PredicateType,
			"keyId":         bundle.KeyID,
		},
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}
