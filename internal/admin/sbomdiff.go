package admin

import (
	"net/http"
	"strconv"
	"strings"
)

// handleSbomDiff serves the SBOM diff & dependency-drift overview (Task 64): the
// cumulative drift metrics (snapshots observed, versions compared, significant
// drifts, warn/block/quarantine tallies, per-ecosystem breakdown, recent
// significant drifts) plus the tracked coordinates and their retained versions.
// The optional ?limit query bounds the recent-drift list and coordinate listing.
func (s *Server) handleSbomDiff(w http.ResponseWriter, r *http.Request) {
	if s.opts.SbomDiff == nil || !s.opts.SbomDiff.Enabled() {
		s.writeError(w, http.StatusNotFound, "sbom-diff / dependency-drift subsystem is not enabled")
		return
	}
	limit := queryLimit(r, 0)
	resp := struct {
		Metrics     any `json:"metrics"`
		Coordinates any `json:"coordinates"`
	}{
		Metrics:     s.opts.SbomDiff.Metrics(limit),
		Coordinates: s.opts.SbomDiff.Coordinates(limit),
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleSbomDiffDiff serves an on-demand version-to-version diff for a coordinate
// — the "what changed since the version I last approved?" query. Parameters:
//
//	ecosystem  (required) the package ecosystem (npm/pip/cargo/...)
//	package    (required) the coordinate name
//	tenant     (optional) the tenant whose history to read (default: shared)
//	from, to   (optional) the two versions; when omitted the two most recent
//	           distinct versions are diffed
//	format     (optional) "json" (default) or "md"/"markdown" for a rendered report
func (s *Server) handleSbomDiffDiff(w http.ResponseWriter, r *http.Request) {
	if s.opts.SbomDiff == nil || !s.opts.SbomDiff.Enabled() {
		s.writeError(w, http.StatusNotFound, "sbom-diff / dependency-drift subsystem is not enabled")
		return
	}
	q := r.URL.Query()
	ecosystem := strings.TrimSpace(q.Get("ecosystem"))
	coordinate := strings.TrimSpace(q.Get("package"))
	if coordinate == "" {
		coordinate = strings.TrimSpace(q.Get("coordinate"))
	}
	if ecosystem == "" || coordinate == "" {
		s.writeError(w, http.StatusBadRequest, "ecosystem and package are required")
		return
	}
	tenant := strings.TrimSpace(q.Get("tenant"))
	from := strings.TrimSpace(q.Get("from"))
	to := strings.TrimSpace(q.Get("to"))

	var (
		diff any
		ok   bool
	)
	if from == "" || to == "" {
		d, found := s.opts.SbomDiff.DiffLatest(tenant, ecosystem, coordinate)
		diff, ok = d, found
	} else {
		d, found := s.opts.SbomDiff.Diff(tenant, ecosystem, coordinate, from, to)
		diff, ok = d, found
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "no diff available for the requested coordinate/versions (need at least two recorded versions)")
		return
	}

	switch strings.ToLower(strings.TrimSpace(q.Get("format"))) {
	case "md", "markdown":
		if md, mok := diff.(interface{ Markdown() string }); mok {
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(md.Markdown()))
			return
		}
		fallthrough
	default:
		s.writeJSON(w, http.StatusOK, diff)
	}
}

// queryLimit parses a non-negative ?limit query parameter, returning def when
// absent or malformed.
func queryLimit(r *http.Request, def int) int {
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}
