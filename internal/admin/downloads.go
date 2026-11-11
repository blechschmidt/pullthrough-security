package admin

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// DownloadLogInspector is the read-only surface of the download log (Task 176):
// which package was downloaded from which client address. *downloadlog.Log
// satisfies it.
type DownloadLogInspector interface {
	Enabled() bool
	Query(q downloadlog.Query) (downloadlog.Result, error)
	Select(q downloadlog.Query) (*downloadlog.Selection, error)
	Summarize(q downloadlog.Query, top int) (downloadlog.Summary, error)
	Stats() downloadlog.Stats
}

// downloadsResponse is the body of GET /api/downloads.
type downloadsResponse struct {
	// Enabled is false when the download log is switched off
	// (downloadLog.enabled); the rest is then empty.
	Enabled bool `json:"enabled"`
	// Total is the number of retained entries matching the filter; Returned how
	// many of them this page holds.
	Total    int `json:"total"`
	Returned int `json:"returned"`
	// NextBefore, when present, is the cursor of the next (older) page: repeat
	// the request with before=<NextBefore>.
	NextBefore uint64 `json:"nextBefore,omitempty"`
	// Entries is the page, newest first.
	Entries []downloadlog.Entry `json:"entries"`
	// Log describes the log itself: its bounds and how much it currently holds.
	Log downloadlog.Stats `json:"log"`
}

// downloadsSummaryResponse is the body of GET /api/downloads/summary.
type downloadsSummaryResponse struct {
	Enabled bool `json:"enabled"`
	downloadlog.Summary
	Log downloadlog.Stats `json:"log"`
}

// downloadLog returns the inspector when the log is wired and enabled.
func (s *Server) downloadLog() (DownloadLogInspector, bool) {
	if s.opts.DownloadLog == nil || !s.opts.DownloadLog.Enabled() {
		return nil, false
	}
	return s.opts.DownloadLog, true
}

// handleDownloads serves the download log: one entry per package download (or
// refused attempt), newest first. Guarded by the read capability via the RBAC
// middleware. Query parameters, all optional and ANDed:
//
//	ip         client address ("10.0.0.7") or CIDR prefix ("10.0.0.0/8")
//	package    package name; "*" is a wildcard ("@acme/*")
//	version    package version
//	ecosystem  cargo | go | npm | pip | docker | git | …
//	upstream   configured upstream name
//	outcome    served | not_modified | blocked | not_found | error
//	kind       package | metadata | unclassified
//	subject    authenticated subject
//	tenant     tenant / team
//	q          free-text search across the textual fields
//	since      lower time bound: an age ("15m", "24h", "7d"), RFC 3339, or unix seconds
//	until      upper time bound, same forms
//	limit      page size (default 100, at most 1000)
//	before     pagination cursor, from a previous response's nextBefore
//	format     json (default) | csv
//
// A filter value that cannot be parsed is a 400, never an ignored filter: an
// answer to a different question than the one asked is worse than an error.
//
// format=csv returns every matching entry (or the first `limit`, when given) as
// a CSV download for use outside the console.
func (s *Server) handleDownloads(w http.ResponseWriter, r *http.Request) {
	log, ok := s.downloadLog()
	if !ok {
		s.writeJSON(w, http.StatusOK, downloadsResponse{
			Entries: []downloadlog.Entry{},
			Log:     (*downloadlog.Log)(nil).Stats(),
		})
		return
	}
	values := r.URL.Query()
	q, err := downloadlog.QueryFromValues(values, time.Now())
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch format := strings.ToLower(strings.TrimSpace(values.Get("format"))); format {
	case "", "json":
	case "csv":
		// An export is the whole selection unless the caller bounded it — and
		// then it is exactly that many rows. The page-size cap of the JSON form
		// does not apply: a CSV carries no cursor to fetch the rest with, so a
		// silently capped export would pass for a complete one.
		//
		// The rows are streamed from a snapshot of the log rather than collected
		// first: the export of a log of millions of entries must not cost a
		// second copy of it in memory.
		sel, err := log.Select(q)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="downloads.csv"`)
		w.Header().Set("X-Total-Count", strconv.Itoa(sel.Total()))
		w.WriteHeader(http.StatusOK)
		cw, err := downloadlog.NewCSVWriter(w)
		if err == nil {
			rows := 0
			sel.Each(func(e *downloadlog.Entry) bool {
				if q.Limit > 0 && rows >= q.Limit {
					return false
				}
				rows++
				err = cw.Write(e)
				return err == nil
			})
			if err == nil {
				err = cw.Flush()
			}
		}
		if err != nil {
			// The status line is long gone; the client went away mid-export.
			s.logger.Debug("admin: writing the download log export failed", "error", err)
		}
		return
	default:
		s.writeError(w, http.StatusBadRequest, "unknown format "+strconv.Quote(format)+" (want json or csv)")
		return
	}

	res, err := log.Query(q)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, downloadsResponse{
		Enabled:    true,
		Total:      res.Total,
		Returned:   len(res.Entries),
		NextBefore: res.NextBefore,
		Entries:    res.Entries,
		Log:        log.Stats(),
	})
}

// handleDownloadsSummary aggregates the download log: totals by outcome, and the
// client addresses and packages with the most entries. It accepts the same
// filters as handleDownloads (paging parameters are ignored), so the two views
// answer the log's two questions directly:
//
//	?package=left-pad   → byClient lists who pulled left-pad
//	?ip=10.0.0.7        → byPackage lists what 10.0.0.7 pulled
//
// plus `top`, the number of clients and packages to list (default 10, at most
// 500).
func (s *Server) handleDownloadsSummary(w http.ResponseWriter, r *http.Request) {
	log, ok := s.downloadLog()
	if !ok {
		disabled := (*downloadlog.Log)(nil)
		empty, _ := disabled.Summarize(downloadlog.Query{}, 0)
		s.writeJSON(w, http.StatusOK, downloadsSummaryResponse{Summary: empty, Log: disabled.Stats()})
		return
	}
	values := r.URL.Query()
	q, err := downloadlog.QueryFromValues(values, time.Now())
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	top := 0
	if raw := strings.TrimSpace(values.Get("top")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			s.writeError(w, http.StatusBadRequest, "invalid top: "+strconv.Quote(raw)+" is not a positive integer")
			return
		}
		top = n
	}
	sum, err := log.Summarize(q, top)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, downloadsSummaryResponse{Enabled: true, Summary: sum, Log: log.Stats()})
}
