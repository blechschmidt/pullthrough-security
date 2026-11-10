package admin

import (
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/maturity"
)

// maturityResponse is the release-maturity / version-cooldown gate status plus
// the list of coordinates currently held in their cooldown window (ordered by
// ascending time-remaining) for the admin tab.
type maturityResponse struct {
	maturity.Status
	Cooling []maturity.CoolingView `json:"cooling"`
}

// handleMaturity serves the release-maturity / version-cooldown gate status and
// the currently-cooling coordinates with their time remaining (Task 61). The
// optional ?limit bounds the cooling list (default 200; 0 = all).
func (s *Server) handleMaturity(w http.ResponseWriter, r *http.Request) {
	if s.opts.Maturity == nil || !s.opts.Maturity.Enabled() {
		s.writeError(w, http.StatusNotFound, "release-maturity gate is not enabled")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	cooling := s.opts.Maturity.Cooling(limit)
	if cooling == nil {
		cooling = []maturity.CoolingView{}
	}
	s.writeJSON(w, http.StatusOK, maturityResponse{
		Status:  s.opts.Maturity.Status(),
		Cooling: cooling,
	})
}
