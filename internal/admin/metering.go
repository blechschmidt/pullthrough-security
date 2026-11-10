package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/metering"
)

// MeteringInspector is the read-only surface of the per-tenant usage-metering &
// chargeback subsystem (Task 84): the live cumulative per-tenant snapshot and a
// time-ranged, per-tenant chargeback report. The *metering.Meter satisfies it.
type MeteringInspector interface {
	Enabled() bool
	Snapshot() metering.Snapshot
	Report(req metering.ReportRequest) metering.UsageReport
}

// handleMeteringStatus serves the live cumulative per-tenant usage snapshot plus
// the subsystem's rollup metadata. Guarded by the read capability via the RBAC
// middleware. This is the cross-tenant operator view; tenant self-service is the
// hard-scoped portal Usage surface.
func (s *Server) handleMeteringStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Metering == nil {
		s.writeError(w, http.StatusNotFound, "per-tenant usage metering is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Metering.Snapshot())
}

// handleMeteringUsage serves a time-ranged chargeback report. Query parameters:
//
//	tenant       restrict to one tenant (empty = all tenants)
//	start, end   RFC3339 or unix-seconds bounds (empty start = earliest retained,
//	             empty end = now)
//	granularity  hour|day|total (default day)
//	format       json|csv|markdown (default json)
//
// The CSV and Markdown forms are the operator-facing chargeback exports.
func (s *Server) handleMeteringUsage(w http.ResponseWriter, r *http.Request) {
	if s.opts.Metering == nil {
		s.writeError(w, http.StatusNotFound, "per-tenant usage metering is not enabled")
		return
	}
	q := r.URL.Query()
	start, err := parseReportTime(q.Get("start"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid start time: "+err.Error())
		return
	}
	end, err := parseReportTime(q.Get("end"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid end time: "+err.Error())
		return
	}
	report := s.opts.Metering.Report(metering.ReportRequest{
		Tenant:      strings.TrimSpace(q.Get("tenant")),
		Start:       start,
		End:         end,
		Granularity: q.Get("granularity"),
	})

	switch strings.ToLower(strings.TrimSpace(q.Get("format"))) {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="usage.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.CSV()))
	case "markdown", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.Markdown()))
	default:
		s.writeJSON(w, http.StatusOK, report)
	}
}

// parseReportTime accepts an RFC3339 timestamp or a unix-seconds integer, or an
// empty string (the zero time, meaning "unbounded" to the report builder).
func parseReportTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	// Fall back to a unix-seconds integer.
	secs, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("not an RFC3339 timestamp or unix-seconds integer")
	}
	return time.Unix(secs, 0).UTC(), nil
}
