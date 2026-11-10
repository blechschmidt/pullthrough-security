package admin

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
)

// AttestInspector is the outbound-attestation surface (Task 46): the proxy-signed
// supply-chain attestation bundles produced for served artifacts. The
// attestbundle.Service satisfies it. A nil inspector means the subsystem is
// disabled (no signing key configured).
type AttestInspector interface {
	// Snapshot reports the engine's counters and signing identity.
	Snapshot() attestbundle.Snapshot
	// Get returns the retained bundle for an artifact. pkg may be an exact
	// coordinate, a bare name (latest), or empty.
	Get(tenant, pkg string) (*attestbundle.Bundle, bool)
	// Documents returns retained bundles filtered by tenant and a coordinate
	// substring, most-recently-recorded first.
	Documents(tenant, q string) []*attestbundle.Bundle
	// Referrers returns the OCI referrers index for a subject content digest.
	Referrers(subjectDigest string) (attestbundle.ReferrersIndex, bool)
}

// attestListResponse is the JSON envelope for GET {prefix}/api/attest: the engine
// status plus the retained bundles (or a single bundle when ?package= is set).
type attestListResponse struct {
	Enabled  bool                   `json:"enabled"`
	Status   attestbundle.Snapshot  `json:"status"`
	Total    int                    `json:"total"`
	Returned int                    `json:"returned"`
	Items    []*attestbundle.Bundle `json:"items"`
}

// handleAttestList reports the attestation engine status and lists retained
// bundles, optionally filtered by tenant and a coordinate substring
// (?tenant=&q=&limit=), or a single artifact's bundle (?package=).
func (s *Server) handleAttestList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Attest == nil {
		s.writeJSON(w, http.StatusOK, attestListResponse{
			Enabled: false, Status: attestbundle.Snapshot{}, Items: []*attestbundle.Bundle{},
		})
		return
	}
	q := r.URL.Query()
	status := s.opts.Attest.Snapshot()

	if pkg := strings.TrimSpace(q.Get("package")); pkg != "" {
		b, ok := s.opts.Attest.Get(q.Get("tenant"), pkg)
		if !ok {
			s.writeError(w, http.StatusNotFound, "no attestation for the requested package (it may not have been served through the proxy yet)")
			return
		}
		s.writeJSON(w, http.StatusOK, attestListResponse{
			Enabled: true, Status: status, Total: 1, Returned: 1,
			Items: []*attestbundle.Bundle{b},
		})
		return
	}

	docs := s.opts.Attest.Documents(q.Get("tenant"), q.Get("q"))
	total := len(docs)
	if limit := parseLimit(r, 200); limit > 0 && len(docs) > limit {
		docs = docs[:limit]
	}
	if docs == nil {
		docs = []*attestbundle.Bundle{}
	}
	s.writeJSON(w, http.StatusOK, attestListResponse{
		Enabled:  true,
		Status:   status,
		Total:    total,
		Returned: len(docs),
		Items:    docs,
	})
}

// handleAttestBundle returns the raw, verifiable DSSE envelope for one artifact
// (GET {prefix}/api/attest/bundle?tenant=&package=) with the in-toto media type,
// so a downstream consumer can verify it directly against the proxy's public key
// (e.g. with cosign). 404 when the artifact has not been served/attested yet.
func (s *Server) handleAttestBundle(w http.ResponseWriter, r *http.Request) {
	if s.opts.Attest == nil {
		s.writeError(w, http.StatusNotFound, "outbound attestation is not enabled")
		return
	}
	pkg := strings.TrimSpace(r.URL.Query().Get("package"))
	if pkg == "" {
		s.writeError(w, http.StatusBadRequest, "the package query parameter is required")
		return
	}
	b, ok := s.opts.Attest.Get(r.URL.Query().Get("tenant"), pkg)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no attestation for the requested package")
		return
	}
	raw, err := b.EnvelopeJSON()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "encoding attestation envelope")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/vnd.dsse.envelope.v1+json")
	h.Set("X-Attestation-Digest", b.Digest)
	h.Set("X-Attestation-Predicate", b.PredicateType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte("\n"))
}

// handleAttestReferrers returns the OCI referrers index for a subject content
// digest (GET {prefix}/api/attest/referrers?digest=sha256:...): an OCI image
// index whose manifests are the attestations the proxy produced for that digest,
// the conventional discovery shape (`oras discover`, cosign) adapted to the
// proxy's store.
func (s *Server) handleAttestReferrers(w http.ResponseWriter, r *http.Request) {
	if s.opts.Attest == nil {
		s.writeError(w, http.StatusNotFound, "outbound attestation is not enabled")
		return
	}
	digest := strings.TrimSpace(r.URL.Query().Get("digest"))
	if digest == "" {
		s.writeError(w, http.StatusBadRequest, "the digest query parameter is required (e.g. sha256:...)")
		return
	}
	idx, ok := s.opts.Attest.Referrers(digest)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "invalid subject digest")
		return
	}
	w.Header().Set("OCI-Subject", digest)
	s.writeOCIIndex(w, attestbundle.MediaTypeImageIndex, idx)
}
