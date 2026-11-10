package admin

import (
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/continuity"
)

// continuityResponse is the maintainer/publisher continuity gate status plus the
// list of coordinates with a currently-untrusted (within-cooldown) new maintainer,
// ordered by ascending time-remaining, for the admin "Continuity" tab.
type continuityResponse struct {
	continuity.Status
	Pending []continuity.PendingView `json:"pending"`
}

// handleContinuity serves the maintainer/publisher continuity gate status and the
// coordinates currently in maintainer-drift cooldown (Task 91). The optional
// ?limit bounds the pending list (default 200; 0 = all).
func (s *Server) handleContinuity(w http.ResponseWriter, r *http.Request) {
	if s.opts.Continuity == nil || !s.opts.Continuity.Enabled() {
		s.writeError(w, http.StatusNotFound, "maintainer/publisher continuity gate is not enabled")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	pending := s.opts.Continuity.Pending(limit)
	if pending == nil {
		pending = []continuity.PendingView{}
	}
	s.writeJSON(w, http.StatusOK, continuityResponse{
		Status:  s.opts.Continuity.Status(),
		Pending: pending,
	})
}
