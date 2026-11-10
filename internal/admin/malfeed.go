package admin

import (
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
)

// malfeedResponse is the known-malicious-package gate status plus the (optionally
// filtered) loaded entries for the admin list/search view.
type malfeedResponse struct {
	malfeed.Status
	Results []malfeed.Entry `json:"results"`
}

// handleMalfeed serves the known-malicious-package gate status and a search over
// the loaded entries (Task 48). The optional ?q filters by id/name/alias/
// summary/category, ?ecosystem restricts to a canonical ecosystem, and ?limit
// bounds the number of returned entries (default 200; 0 = all).
func (s *Server) handleMalfeed(w http.ResponseWriter, r *http.Request) {
	if s.opts.Malfeed == nil || !s.opts.Malfeed.Enabled() {
		s.writeError(w, http.StatusNotFound, "known-malicious-package gate is not enabled")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	results := s.opts.Malfeed.Search(r.URL.Query().Get("q"), r.URL.Query().Get("ecosystem"), limit)
	if results == nil {
		results = []malfeed.Entry{}
	}
	s.writeJSON(w, http.StatusOK, malfeedResponse{
		Status:  s.opts.Malfeed.Status(),
		Results: results,
	})
}

// handleMalfeedRefresh forces an immediate feed refresh (ETag/conditional) and
// returns the resulting status.
func (s *Server) handleMalfeedRefresh(w http.ResponseWriter, r *http.Request) {
	if s.opts.Malfeed == nil || !s.opts.Malfeed.Enabled() {
		s.writeError(w, http.StatusNotFound, "known-malicious-package gate is not enabled")
		return
	}
	if err := s.opts.Malfeed.Refresh(r.Context()); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "malfeed refresh failed: "+err.Error())
		return
	}
	status := s.opts.Malfeed.Status()
	s.logger.Info("admin: malfeed refresh triggered", "entries", status.Entries, "stale", status.Stale)
	s.writeJSON(w, http.StatusOK, status)
}
