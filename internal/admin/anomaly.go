package admin

import (
	"net/http"
	"strconv"
)

// handleAnomaly serves the behavioral-anomaly-detection snapshot (Task 43): the
// cumulative engine state (observations, alerts, soft-blocks, per-level and
// per-detector counters, the configured warn/block thresholds), the current
// per-scope standings, and the recent triggers for the trend view. The optional
// ?limit query bounds the number of recent triggers (default: all retained).
func (s *Server) handleAnomaly(w http.ResponseWriter, r *http.Request) {
	if s.opts.Anomaly == nil {
		s.writeError(w, http.StatusNotFound, "behavioral anomaly detection is not enabled")
		return
	}
	snap := s.opts.Anomaly.Snapshot()
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if lim, err := strconv.Atoi(limStr); err == nil && lim >= 0 {
			snap.Recent = s.opts.Anomaly.Recent(lim)
		}
	}
	s.writeJSON(w, http.StatusOK, snap)
}
