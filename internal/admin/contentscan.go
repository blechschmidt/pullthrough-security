package admin

import "net/http"

// handleContentScan serves the package-payload static content-analysis gate's
// effective configuration (action, fail-severity, ecosystems) and cumulative
// scan/finding tallies (Task 138).
func (s *Server) handleContentScan(w http.ResponseWriter, r *http.Request) {
	if s.opts.ContentScan == nil || !s.opts.ContentScan.Enabled() {
		s.writeError(w, http.StatusNotFound, "package-content analysis gate is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.ContentScan.Status())
}
