package admin

import "net/http"

// handleBuildProv serves the inbound build-provenance verification overview (Task
// 72): the effective configuration (mode, action, requirements, trust posture),
// the cumulative per-outcome and per-ecosystem tallies (present / verified /
// source-verified / mismatch), and the recent verification reports — each binding
// a package version to the source repo + commit + CI workflow proven by its
// upstream-published build-provenance attestation, and the claimed source it was
// cross-checked against. The optional ?limit query bounds the recent list.
func (s *Server) handleBuildProv(w http.ResponseWriter, r *http.Request) {
	if s.opts.BuildProv == nil || !s.opts.BuildProv.Enabled() {
		s.writeError(w, http.StatusNotFound, "inbound build-provenance verification subsystem is not enabled")
		return
	}
	limit := queryLimit(r, 50)
	s.writeJSON(w, http.StatusOK, s.opts.BuildProv.Status(limit))
}
