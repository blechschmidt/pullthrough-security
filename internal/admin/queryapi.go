package admin

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

// QueryAPIInspector is the unified federated query surface (Task 67): a
// read-only JSON query/projection DSL that joins the per-coordinate security
// facts spread across provgraph, findings, riskscore, vulnscan, approvals, and
// secops into a single answerable model. The queryapi.Engine satisfies it.
type QueryAPIInspector interface {
	Query(q queryapi.Query) (queryapi.Result, error)
	Schema() queryapi.Schema
	Snapshot() queryapi.MetricsSnapshot
}

// maxQueryBody bounds the accepted query document so a hostile client cannot
// stream an unbounded body into the decoder.
const maxQueryBody = 256 << 10 // 256 KiB

// handleQueryRun executes a federated query. It is a POST because the query is a
// structured document, but it is strictly read-only: it mutates no state and is
// guarded by the read capability (see authz.go). Validation failures return 400
// with the stable machine-readable error code so CI can branch on them.
func (s *Server) handleQueryRun(w http.ResponseWriter, r *http.Request) {
	if s.opts.QueryAPI == nil {
		s.writeError(w, http.StatusNotFound, "the federated query API is not enabled")
		return
	}
	var q queryapi.Query
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxQueryBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid query document: "+err.Error())
		return
	}
	res, err := s.opts.QueryAPI.Query(q)
	if err != nil {
		// A *queryapi.QueryError is a client-side validation/shape error.
		if qe, ok := err.(*queryapi.QueryError); ok {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": qe.Msg,
				"code":  qe.Code,
			})
			return
		}
		s.writeError(w, http.StatusInternalServerError, "query failed: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleQuerySchema serves the stable, self-describing query schema: every
// queryable field, the operators each accepts, the wired data sources, and the
// engine's result bounds. Clients (the UI console, ptctl, CI) read it to build
// and validate queries.
func (s *Server) handleQuerySchema(w http.ResponseWriter, r *http.Request) {
	if s.opts.QueryAPI == nil {
		s.writeError(w, http.StatusNotFound, "the federated query API is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.QueryAPI.Schema())
}

// handleQueryMetrics serves the engine's cumulative cost telemetry (also
// exported to Prometheus via the metrics bridge) for the console's cost readout.
func (s *Server) handleQueryMetrics(w http.ResponseWriter, r *http.Request) {
	if s.opts.QueryAPI == nil {
		s.writeError(w, http.StatusNotFound, "the federated query API is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.QueryAPI.Snapshot())
}
