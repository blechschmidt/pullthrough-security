package admin

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// handleCacheTiering reports the hot/cold tiered storage layer's status and
// cumulative statistics (Task 154): promotions, demotions, tier-hit ratios, and
// the live per-tier object/byte gauges, so an operator (or `ptctl cache-tiering
// status`) can see how artifacts are distributed across the fast and cheap
// tiers. When the layer is disabled it returns an Enabled=false snapshot.
func (s *Server) handleCacheTiering(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tiering == nil {
		s.writeJSON(w, http.StatusOK, cache.TieredStats{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Tiering.TieredStats())
}

// handleCacheTieringSweep triggers an on-demand demotion sweep: idle (and, under
// capacity pressure, least-recently-used) hot artifacts are demoted to the cold
// tier. It returns the sweep report (candidates / demoted / skipped / error
// counts). Unlike the background sweep this is not leader-gated — an operator
// asking for a sweep gets one (demotions are idempotent and tier-safe).
func (s *Server) handleCacheTieringSweep(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tiering == nil {
		s.writeError(w, http.StatusNotFound, "tiered cache storage is not enabled")
		return
	}
	rep, err := s.opts.Tiering.SweepTiers(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "tier sweep failed: "+err.Error())
		return
	}
	s.logger.Info("admin: cache tier demotion sweep triggered",
		"candidates", rep.Candidates, "demoted", rep.Demoted, "skipped", rep.Skipped, "errors", rep.Errors)
	s.writeJSON(w, http.StatusOK, rep)
}
