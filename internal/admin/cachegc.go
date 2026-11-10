package admin

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
)

// cacheGCStatusResponse is the GET /api/cachegc payload: the cumulative GC
// snapshot (utilization vs watermark, bytes reclaimed, eviction counts) plus the
// most recent run report.
type cacheGCStatusResponse struct {
	Enabled    bool             `json:"enabled"`
	Snapshot   cachegc.Snapshot `json:"snapshot"`
	LastReport *cachegc.Report  `json:"lastReport,omitempty"`
}

// handleCacheGCStatus reports cache utilization, watermark headroom, and the most
// recent garbage-collection run so an operator can see how full the cache is and
// what the last sweep reclaimed (Task 39).
func (s *Server) handleCacheGCStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.CacheGC == nil {
		s.writeJSON(w, http.StatusOK, cacheGCStatusResponse{Enabled: false})
		return
	}
	resp := cacheGCStatusResponse{
		Enabled:  true,
		Snapshot: s.opts.CacheGC.Snapshot(),
	}
	if rep, ok := s.opts.CacheGC.LastReport(); ok {
		resp.LastReport = &rep
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// cacheGCRunResponse wraps the report produced by an on-demand sweep.
type cacheGCRunResponse struct {
	Report cachegc.Report `json:"report"`
}

// handleCacheGCRun triggers an on-demand garbage-collection sweep and returns its
// report. By default the run is a dry-run (report-only, deletes nothing) so an
// operator can preview exactly what eviction would remove; pass ?dryRun=false (or
// dryRun=0) to perform real eviction. The dry-run report is an accurate preview:
// the same planning produces the real run's deletions.
func (s *Server) handleCacheGCRun(w http.ResponseWriter, r *http.Request) {
	if s.opts.CacheGC == nil {
		s.writeError(w, http.StatusNotFound, "cache garbage collection is not enabled")
		return
	}
	// Default to a safe dry-run; only a deliberate dryRun=false performs deletion.
	dryRun := true
	if v := r.URL.Query().Get("dryRun"); v != "" {
		switch v {
		case "false", "0", "no":
			dryRun = false
		case "true", "1", "yes":
			dryRun = true
		default:
			s.writeError(w, http.StatusBadRequest, "invalid dryRun parameter (want true|false)")
			return
		}
	}
	rep, err := s.opts.CacheGC.Run(r.Context(), dryRun)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "gc run failed: "+err.Error())
		return
	}
	s.logger.Info("admin: cache gc run triggered",
		"dryRun", dryRun, "evicted", rep.EvictedCount, "bytesReclaimed", rep.BytesReclaimed,
		"retained", rep.RetainedCount, "aboveHigh", rep.AboveHighWatermark)
	s.writeJSON(w, http.StatusOK, cacheGCRunResponse{Report: rep})
}
