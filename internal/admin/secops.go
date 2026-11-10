package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/secops"
)

// SecOpsInspector is the unified Security Operations surface (Task 60): the
// aggregated cross-subsystem posture summary (rolling-window block/warn/admit
// tallies, breakdowns, backlog, active anomalies, risk-band distribution) and a
// live subscription to the notable-verdict event feed for the dashboard's
// real-time SOC view. The secops.Hub satisfies it.
type SecOpsInspector interface {
	Summary() secops.Summary
	Subscribe() (<-chan secops.NotableEvent, func())
}

// handleSecOpsSummary serves the unified SOC read-model: a near-real-time,
// cross-subsystem aggregation of recent admission decisions and the current
// security posture. It taps existing metrics, the findings store, and the
// subsystem read-models rather than duplicating any source of truth, and it
// degrades gracefully when individual subsystems are disabled (absent sections
// are simply omitted). Guarded by the read capability via the RBAC middleware.
func (s *Server) handleSecOpsSummary(w http.ResponseWriter, r *http.Request) {
	if s.opts.SecOps == nil {
		s.writeError(w, http.StatusNotFound, "the security operations dashboard is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.SecOps.Summary())
}

// handleSecOpsStream is a server-sent-events endpoint streaming notable verdicts
// (blocks, warns, anomalies, approvals, vulnerabilities) as they happen, so the
// dashboard's live feed updates without polling. Each event is a NotableEvent
// JSON object carrying enough context to drill into the owning subsystem tab.
//
// The stream is bounded and non-blocking end to end: a slow client never applies
// backpressure to the proxy's request path (the Hub drops rather than blocks),
// and the connection is closed cleanly when the client disconnects. A periodic
// comment heartbeat keeps intermediaries from idling the connection out.
func (s *Server) handleSecOpsStream(w http.ResponseWriter, r *http.Request) {
	if s.opts.SecOps == nil {
		s.writeError(w, http.StatusNotFound, "the security operations dashboard is not enabled")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "streaming is not supported by this server")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)
	w.WriteHeader(http.StatusOK)

	ch, cancel := s.opts.SecOps.Subscribe()
	defer cancel()

	// Advise the browser EventSource on the reconnect backoff and open the stream
	// with a comment so the connection is established immediately.
	fmt.Fprintf(w, "retry: 5000\n: connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// A comment line is ignored by EventSource but keeps the socket warm.
			if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			// Name the SSE event "verdict" and tag it with the monotonic seq as the
			// SSE id so a reconnecting client can reason about gaps.
			if _, err := fmt.Fprintf(w, "event: verdict\nid: %d\ndata: %s\n\n", ev.Seq, data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
