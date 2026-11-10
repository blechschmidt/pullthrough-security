package admin

import "net/http"

// handleTracing serves the distributed-tracing status (Task 41): the effective
// tracing configuration (endpoint, service name, sampler ratio) plus the live
// OTLP exporter counters, so operators can confirm tracing is active and watch
// for dropped spans or export failures.
func (s *Server) handleTracing(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tracing == nil {
		// Tracing disabled: report the inert state rather than 404, so the
		// dashboard can render an "off" tile.
		s.writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Tracing.Status())
}
