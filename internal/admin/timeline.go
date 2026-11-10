package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/timeline"
)

// TimelineInspector is the forensic incident-timeline surface (Task 77): a
// read-only reconstruction of a single, chronologically-ordered, deduplicated
// event history for a coordinate, tenant, identity, or incident ID, correlated
// across the audit log (Merkle), the SOC verdict feed, anomaly triggers, the
// approval/break-glass workflow, lockdown actions, and admission findings. The
// timeline.Engine satisfies it.
type TimelineInspector interface {
	Query(ctx context.Context, q timeline.Query) (timeline.Result, error)
	Sources() map[string]bool
}

// handleTimeline reconstructs and returns the incident timeline for the supplied
// scope. It is strictly read-only (a GET) and guarded by the read capability
// (see authz.go). The scope is taken from query parameters:
//
//	coordinate= name[@version]   pivot on a package (bare name matches all versions)
//	tenant=     team             scope to a tenant (portal-consistent isolation)
//	identity=   subject          scope to an actor
//	incident=   incidentID       scope to a lockdown/approval incident
//	since=,until= RFC3339        bound the window
//	limit=      N                cap the number of returned events
//	all=true                     return the whole timeline (no selector required)
//	format=md | Accept: text/markdown   render the Markdown forensic report
//
// At least one selector (or all=true) is required; an unscoped request is a 400
// so an operator cannot accidentally dump the entire history.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	if s.opts.Timeline == nil {
		s.writeError(w, http.StatusNotFound, "incident timeline reconstruction is not enabled")
		return
	}
	q, err := parseTimelineQuery(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, qerr := s.opts.Timeline.Query(r.Context(), q)
	if qerr != nil {
		if te, ok := qerr.(*timeline.QueryError); ok {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": te.Msg,
				"code":  te.Code,
			})
			return
		}
		s.writeError(w, http.StatusInternalServerError, "timeline reconstruction failed: "+qerr.Error())
		return
	}

	if wantsMarkdown(r) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(res.Markdown()))
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// parseTimelineQuery builds a timeline.Query from the request's query parameters.
func parseTimelineQuery(r *http.Request) (timeline.Query, error) {
	qp := r.URL.Query()
	q := timeline.Query{
		Coordinate: strings.TrimSpace(qp.Get("coordinate")),
		Tenant:     strings.TrimSpace(qp.Get("tenant")),
		Identity:   strings.TrimSpace(qp.Get("identity")),
		IncidentID: strings.TrimSpace(firstQuery(qp.Get("incident"), qp.Get("incidentId"))),
		All:        boolParam(qp.Get("all")),
	}
	if v := strings.TrimSpace(qp.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return timeline.Query{}, &parseError{"limit must be a non-negative integer"}
		}
		q.Limit = n
	}
	if v := strings.TrimSpace(qp.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return timeline.Query{}, &parseError{"since must be an RFC3339 timestamp"}
		}
		q.Since = t
	}
	if v := strings.TrimSpace(qp.Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return timeline.Query{}, &parseError{"until must be an RFC3339 timestamp"}
		}
		q.Until = t
	}
	return q, nil
}

type parseError struct{ msg string }

func (e *parseError) Error() string { return e.msg }

func wantsMarkdown(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "md", "markdown":
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/markdown")
}

func boolParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func firstQuery(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
