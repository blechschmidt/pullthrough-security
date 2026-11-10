package admin

import (
	"net/http"
	"strconv"
)

// handleRiskScore serves the unified risk-scoring snapshot: the cumulative
// engine state (per-band counts, threshold, weighting model) plus the recent
// explainable assessments for the trend view and drill-down. The optional
// ?limit query bounds the number of recent assessments (default: all retained).
func (s *Server) handleRiskScore(w http.ResponseWriter, r *http.Request) {
	if s.opts.RiskScore == nil {
		s.writeError(w, http.StatusNotFound, "unified risk scoring is not enabled")
		return
	}
	snap := s.opts.RiskScore.Snapshot()
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if lim, err := strconv.Atoi(limStr); err == nil && lim >= 0 {
			snap.Recent = s.opts.RiskScore.Recent(lim)
		}
	}
	s.writeJSON(w, http.StatusOK, snap)
}
