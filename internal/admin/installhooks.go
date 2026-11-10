package admin

import "net/http"

// handleInstallHooks serves the install-script / lifecycle-hook risk gate's
// effective configuration, active rule catalog (with per-rule finding counts),
// and cumulative scan/block tallies (Task 62).
func (s *Server) handleInstallHooks(w http.ResponseWriter, r *http.Request) {
	if s.opts.InstallHooks == nil || !s.opts.InstallHooks.Enabled() {
		s.writeError(w, http.StatusNotFound, "install-hook analysis gate is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.InstallHooks.Status())
}
