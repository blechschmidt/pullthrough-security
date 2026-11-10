package admin

import "net/http"

// handleRebuildVerify serves the reproducible-build verification overview (Task
// 68): the effective configuration (mode, async, registered builders), the
// cumulative per-verdict and per-ecosystem tallies, and the recent verification
// results (reproducible / mismatch / unsupported / unattested). The optional
// ?limit query bounds the recent-results list.
func (s *Server) handleRebuildVerify(w http.ResponseWriter, r *http.Request) {
	if s.opts.RebuildVerify == nil || !s.opts.RebuildVerify.Enabled() {
		s.writeError(w, http.StatusNotFound, "reproducible-build verification subsystem is not enabled")
		return
	}
	limit := queryLimit(r, 50)
	s.writeJSON(w, http.StatusOK, s.opts.RebuildVerify.Status(limit))
}
