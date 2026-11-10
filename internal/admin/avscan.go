package admin

import "net/http"

// handleAVScan serves the antivirus content-scanning gate's effective
// configuration (engine, action, fail-open policy, scan bounds) and cumulative
// scan/detection tallies (Task 136).
func (s *Server) handleAVScan(w http.ResponseWriter, r *http.Request) {
	if s.opts.AVScan == nil || !s.opts.AVScan.Enabled() {
		s.writeError(w, http.StatusNotFound, "antivirus content-scanning gate is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.AVScan.Status())
}
