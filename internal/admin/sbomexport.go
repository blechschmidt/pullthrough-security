package admin

import (
	"context"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/sbomexport"
)

// SBOMExportController is the outbound SBOM/findings federation surface the admin
// API exposes (Task 153): the operational status and an on-demand export
// trigger. The sbomexport.Service satisfies it.
type SBOMExportController interface {
	Status() sbomexport.Status
	Trigger(ctx context.Context) (sbomexport.RunReport, error)
}

// handleSBOMExport reports the outbound SBOM/findings federation status (Task
// 153), so an operator (or `ptctl sbom-export status`) can see the configured
// sinks, the sweep interval, leader state, the last sweep's outcome, and the
// cumulative upload/failure/retry counters. When the subsystem is disabled it
// returns an Enabled=false status.
func (s *Server) handleSBOMExport(w http.ResponseWriter, r *http.Request) {
	if s.opts.SBOMExport == nil {
		s.writeJSON(w, http.StatusOK, sbomexport.Status{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.SBOMExport.Status())
}

// handleSBOMExportRun triggers an immediate export sweep on this node, bypassing
// the HA leader gate (an operator explicitly asked this node to export). It
// returns the sweep's report.
func (s *Server) handleSBOMExportRun(w http.ResponseWriter, r *http.Request) {
	if s.opts.SBOMExport == nil {
		s.writeError(w, http.StatusNotFound, "outbound SBOM/findings federation is not enabled")
		return
	}
	report, err := s.opts.SBOMExport.Trigger(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "SBOM export sweep could not be run: "+err.Error())
		return
	}
	s.logger.Info("admin: SBOM/findings export sweep triggered",
		"reports", report.Reports, "uploaded", report.Uploaded,
		"failed", report.Failed, "skipped", report.Skipped)
	s.writeJSON(w, http.StatusOK, report)
}
