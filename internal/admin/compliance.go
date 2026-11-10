package admin

import (
	"net/http"
	"strings"
)

// handleCompliance returns the latest continuous-compliance scorecard (Task 35).
// By default it serves the structured JSON report; ?format=markdown serves the
// Markdown rendering. ?refresh=1 recomputes the scorecard from the live posture
// before responding.
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if s.opts.Compliance == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	card := s.opts.Compliance.Latest()
	if isTruthy(r.URL.Query().Get("refresh")) {
		card = s.opts.Compliance.Recompute()
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "markdown", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(card.Markdown()))
	default:
		s.writeJSON(w, http.StatusOK, card)
	}
}

// handleComplianceRefresh recomputes the scorecard from the live signals on
// demand and returns the fresh JSON report.
func (s *Server) handleComplianceRefresh(w http.ResponseWriter, r *http.Request) {
	if s.opts.Compliance == nil {
		s.writeError(w, http.StatusNotFound, "compliance scorecard is not enabled")
		return
	}
	card := s.opts.Compliance.Recompute()
	s.logger.Info("admin: compliance scorecard recomputed",
		"score", card.Score, "grade", card.Grade, "status", card.Status,
		"slsaLevel", card.SLSA.BuildLevel)
	s.writeJSON(w, http.StatusOK, card)
}

// handleComplianceHTML serves the scorecard as a self-contained HTML document —
// the operator-facing "compliance view" suitable for opening in a browser tab or
// printing to PDF for an audit packet.
func (s *Server) handleComplianceHTML(w http.ResponseWriter, r *http.Request) {
	if s.opts.Compliance == nil {
		s.writeError(w, http.StatusNotFound, "compliance scorecard is not enabled")
		return
	}
	card := s.opts.Compliance.Latest()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(card.HTML()))
}

// handleComplianceExport serves the signed, exportable compliance-report artifact
// for auditors: the scorecard plus a content digest and (when a signing key is
// configured) a cryptographic signature an auditor can verify independently. The
// response is delivered as a download.
func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request) {
	if s.opts.Compliance == nil {
		s.writeError(w, http.StatusNotFound, "compliance scorecard is not enabled")
		return
	}
	report, err := s.opts.Compliance.Export()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "building report: "+err.Error())
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="compliance-report.json"`)
	s.writeJSON(w, http.StatusOK, report)
}

// isTruthy interprets a query-parameter flag.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
