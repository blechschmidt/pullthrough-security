package admin

import (
	"net/http"
	"strconv"
)

// handleRepoScore serves the source-repository health snapshot (Task 63): the
// cumulative provider status (per-grade resolved-repo counts, average health,
// resolve/cache tallies, the weighting model) plus the recent explainable
// per-repo reports for the drill-down. The optional ?limit query bounds the
// number of recent reports (default: all retained).
func (s *Server) handleRepoScore(w http.ResponseWriter, r *http.Request) {
	if s.opts.RepoScore == nil || !s.opts.RepoScore.Enabled() {
		s.writeError(w, http.StatusNotFound, "source-repository health scoring is not enabled")
		return
	}
	limit := 0
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if lim, err := strconv.Atoi(limStr); err == nil && lim >= 0 {
			limit = lim
		}
	}
	s.writeJSON(w, http.StatusOK, s.opts.RepoScore.Status(limit))
}
