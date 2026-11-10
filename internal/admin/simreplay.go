package admin

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// SimReplayInspector is the policy & risk what-if replay surface (Task 47): the
// live capture recorder's operational status, its captured-traffic buffer (for
// export and replay), and a reset hook. The simreplay.Recorder satisfies it.
type SimReplayInspector interface {
	Enabled() bool
	Status() simreplay.Status
	Records() []simreplay.Record
	Capture() simreplay.Capture
	Reset()
}

// maxCandidateConfigBytes bounds the candidate-config POST body so a malformed or
// hostile request cannot exhaust memory. A real policy bundle is far smaller.
const maxCandidateConfigBytes = 1 << 20 // 1 MiB

// handleSimReplayStatus serves the capture recorder's operational status: whether
// capture is on, the ring-buffer capacity/fill, the sample rate, and the running
// observed/captured counters. It is the lightweight surface a dashboard polls.
func (s *Server) handleSimReplayStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.SimReplay == nil {
		s.writeError(w, http.StatusNotFound, "policy & risk what-if replay is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.SimReplay.Status())
}

// handleSimReplayCapture exports the captured-traffic buffer as a self-describing
// Capture envelope, so an operator can download the live buffer and replay it
// offline with the `simulate` CLI.
func (s *Server) handleSimReplayCapture(w http.ResponseWriter, r *http.Request) {
	if s.opts.SimReplay == nil {
		s.writeError(w, http.StatusNotFound, "policy & risk what-if replay is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.SimReplay.Capture())
}

// handleSimReplayReset clears the capture buffer so an operator can start a fresh
// capture window (e.g. after deploying a config change).
func (s *Server) handleSimReplayReset(w http.ResponseWriter, r *http.Request) {
	if s.opts.SimReplay == nil {
		s.writeError(w, http.StatusNotFound, "policy & risk what-if replay is not enabled")
		return
	}
	s.opts.SimReplay.Reset()
	s.logger.Info("admin: simreplay capture buffer reset")
	s.writeJSON(w, http.StatusOK, map[string]any{"reset": true})
}

// handleSimReplaySimulate replays the live capture buffer through a candidate
// configuration supplied in the request body (YAML or JSON in the simreplay
// CandidateConfig schema) and returns the diff report. The report is JSON by
// default, or Markdown with ?format=markdown.
//
// Query parameters:
//
//	format=markdown|json   output format (default json)
//	records=1              include per-record diffs (default summary + tenants only)
//	all=1                  with records=1, include unchanged records too
//	limit=N                cap the number of per-record diffs included
func (s *Server) handleSimReplaySimulate(w http.ResponseWriter, r *http.Request) {
	if s.opts.SimReplay == nil {
		s.writeError(w, http.StatusNotFound, "policy & risk what-if replay is not enabled")
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCandidateConfigBytes+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "reading candidate config: "+err.Error())
		return
	}
	if len(raw) > maxCandidateConfigBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "candidate config exceeds 1 MiB")
		return
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		s.writeError(w, http.StatusBadRequest, "candidate config body is required")
		return
	}

	cfg, err := simreplay.ParseCandidate(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	evaluator, cleanup, err := simreplay.BuildEvaluator(cfg)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() { _ = cleanup() }()

	q := r.URL.Query()
	opts := simreplay.Options{
		IncludeRecords: isTruthy(q.Get("records")),
		OnlyChanged:    !isTruthy(q.Get("all")),
	}
	if v := q.Get("limit"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n >= 0 {
			opts.MaxRecords = n
		}
	}

	records := s.opts.SimReplay.Records()
	report := simreplay.Run(records, evaluator, opts)

	s.logger.Info("admin: simreplay what-if evaluated",
		"replayed", report.Summary.Total,
		"changed", report.Summary.Changed,
		"nowBlocked", report.Summary.NowBlocked,
		"nowAdmitted", report.Summary.NowAdmitted)

	switch strings.ToLower(strings.TrimSpace(q.Get("format"))) {
	case "markdown", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.Markdown()))
	default:
		s.writeJSON(w, http.StatusOK, report)
	}
}
