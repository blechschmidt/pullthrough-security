package admin

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// FindingsInspector is the unified findings/SARIF surface (Task 42): the retained
// per-artifact findings documents and the tool version stamped into exported
// SARIF. The findings.Store (adapted with the build version) satisfies it.
type FindingsInspector interface {
	// Get returns the retained findings document for an artifact. pkg may be an
	// exact coordinate ("name@version"), a bare name (latest version), or empty.
	Get(tenant, pkg string) (findings.Document, bool)
	// Documents returns retained documents filtered by tenant and a package-name
	// substring (both optional), most-recently-recorded first.
	Documents(tenant, q string) []findings.Document
	// ToolVersion is the producing-tool version stamped into exported SARIF.
	ToolVersion() string
}

// findingsListResponse is the JSON envelope for GET {prefix}/api/findings: the
// retained canonical findings documents (not SARIF), for the dashboard and for
// programmatic clients that prefer the native model.
type findingsListResponse struct {
	Enabled  bool                `json:"enabled"`
	Total    int                 `json:"total"`
	Returned int                 `json:"returned"`
	Items    []findings.Document `json:"items"`
}

// handleFindingsList lists retained findings documents (canonical model),
// optionally filtered by tenant and a package substring (?tenant=&q=).
func (s *Server) handleFindingsList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Findings == nil {
		s.writeJSON(w, http.StatusOK, findingsListResponse{Enabled: false, Items: []findings.Document{}})
		return
	}
	q := r.URL.Query()
	docs := s.opts.Findings.Documents(q.Get("tenant"), q.Get("q"))
	total := len(docs)
	if limit := parseLimit(r, 200); limit > 0 && len(docs) > limit {
		docs = docs[:limit]
	}
	if docs == nil {
		docs = []findings.Document{}
	}
	s.writeJSON(w, http.StatusOK, findingsListResponse{
		Enabled:  true,
		Total:    total,
		Returned: len(docs),
		Items:    docs,
	})
}

// handleFindingsSARIF is the core CI-facing endpoint
// (GET {prefix}/api/findings/sarif?tenant=&package=). It exports SARIF 2.1.0 so a
// customer's pipeline can call the proxy, retrieve an artifact's findings, and
// decorate pull requests / fail builds via native GitHub/GitLab SARIF ingestion.
//
//   - With ?package= set, it exports the single artifact's findings (404 if the
//     artifact has not been pulled/scanned through the proxy yet).
//   - Without ?package=, it exports a batch SARIF over every retained artifact
//     for the tenant — the air-gapped import-preflight shape — so CI can ingest
//     the whole consumed set in one document.
func (s *Server) handleFindingsSARIF(w http.ResponseWriter, r *http.Request) {
	if s.opts.Findings == nil {
		s.writeError(w, http.StatusNotFound, "findings aggregation is not enabled")
		return
	}
	q := r.URL.Query()
	tenant := q.Get("tenant")
	pkg := strings.TrimSpace(q.Get("package"))
	opts := findings.SARIFOptions{ToolVersion: s.opts.Findings.ToolVersion()}

	var log findings.Log
	if pkg != "" {
		doc, ok := s.opts.Findings.Get(tenant, pkg)
		if !ok {
			s.writeError(w, http.StatusNotFound, "no findings for the requested package (it may not have been pulled through the proxy yet)")
			return
		}
		log = doc.SARIF(opts)
	} else {
		docs := s.opts.Findings.Documents(tenant, q.Get("q"))
		log = findings.SARIFFromDocuments(docs, opts)
	}
	s.writeSARIF(w, log)
}
