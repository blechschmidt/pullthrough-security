package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// DossierInspector is the unified per-coordinate security "360 view" surface
// (Task 87): a fixed, opinionated, human-first projection that folds every wired
// subsystem's view of one artifact coordinate (provenance, risk, findings,
// vulnerabilities, license, signatures, approvals, reproducible-build, SBOM
// drift, and the correlated timeline) into a single triage card. The
// *dossier.Builder satisfies it.
type DossierInspector interface {
	Build(ctx context.Context, q dossier.Query) *dossier.Dossier
	Sources() map[string]bool
}

// handleDossier assembles and returns the security dossier for a coordinate. It
// is strictly read-only (a GET) and guarded by the read capability (see
// authz.go). The request is hard-scoped to the caller's tenant exactly like the
// federated query and MCP surfaces: a tenant-bound identity cannot widen its
// scope via the query string. Scope is taken from query parameters:
//
//	ecosystem= npm|pypi|...        the artifact ecosystem (recommended)
//	coordinate= name[@version]     the package coordinate (a bare name aggregates versions)
//	version= X                     an explicit version (overrides one in the coordinate)
//	tenant= team                   only honored for a global (non-tenant-bound) identity
//	format=md | Accept: text/markdown   render the Markdown triage report
//
// A coordinate is required; an empty one is a 400 so a caller cannot request an
// unscoped dossier.
func (s *Server) handleDossier(w http.ResponseWriter, r *http.Request) {
	if s.opts.Dossier == nil {
		s.writeError(w, http.StatusNotFound, "the security dossier API is not enabled")
		return
	}
	qp := r.URL.Query()
	coord := strings.TrimSpace(firstQuery(qp.Get("coordinate"), qp.Get("coord"), qp.Get("name")))
	if coord == "" {
		s.writeError(w, http.StatusBadRequest, "a coordinate is required (?coordinate=name[@version])")
		return
	}
	q := dossier.Query{
		Tenant:     mcpTenant(r), // reuse the federated/MCP tenant hard-scoping rule
		Ecosystem:  strings.TrimSpace(firstQuery(qp.Get("ecosystem"), qp.Get("eco"))),
		Coordinate: coord,
		Version:    strings.TrimSpace(qp.Get("version")),
	}

	d := s.opts.Dossier.Build(r.Context(), q)

	if wantsMarkdown(r) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(d.Markdown()))
		return
	}
	s.writeJSON(w, http.StatusOK, d)
}
