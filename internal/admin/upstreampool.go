package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
)

// upstreamPoolStatusResponse is the GET /api/upstreams payload (Task 38): the
// health and circuit state of every mirror pool the proxy fronts.
type upstreamPoolStatusResponse struct {
	Enabled bool                    `json:"enabled"`
	Pools   []upstreampool.Snapshot `json:"pools"`
}

// handleUpstreamPoolStatus reports the per-backend mirror-pool snapshots:
// endpoint circuit state, success/failure counts, latency, drain flags, and
// failover totals, so an operator can see which mirror is serving traffic and
// which have been taken out of rotation.
func (s *Server) handleUpstreamPoolStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.UpstreamPool == nil {
		s.writeJSON(w, http.StatusOK, upstreamPoolStatusResponse{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, upstreamPoolStatusResponse{
		Enabled: true,
		Pools:   s.opts.UpstreamPool.Snapshots(),
	})
}

// upstreamPoolDrainRequest force-drains (or undrains) a single mirror endpoint.
type upstreamPoolDrainRequest struct {
	Backend  string `json:"backend"`
	Endpoint string `json:"endpoint"`
	Drained  bool   `json:"drained"`
}

// handleUpstreamPoolDrain pulls a mirror out of rotation (or returns it) without
// altering its circuit state, for planned maintenance. The change is immediate.
func (s *Server) handleUpstreamPoolDrain(w http.ResponseWriter, r *http.Request) {
	if s.opts.UpstreamPool == nil {
		s.writeError(w, http.StatusNotFound, "upstream mirror pools are not enabled")
		return
	}
	var req upstreamPoolDrainRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Backend) == "" || strings.TrimSpace(req.Endpoint) == "" {
		s.writeError(w, http.StatusBadRequest, "both backend and endpoint are required")
		return
	}
	if err := s.opts.UpstreamPool.SetDrained(req.Backend, req.Endpoint, req.Drained); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("admin: upstream mirror drain state changed",
		"backend", req.Backend, "endpoint", req.Endpoint, "drained", req.Drained)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"backend": req.Backend, "endpoint": req.Endpoint, "drained": req.Drained,
	})
}

// upstreamPoolCircuitRequest overrides a mirror endpoint's circuit breaker.
// Action is "reset" (force closed) or "open" (force tripped).
type upstreamPoolCircuitRequest struct {
	Backend  string `json:"backend"`
	Endpoint string `json:"endpoint"`
	Action   string `json:"action"`
}

// handleUpstreamPoolCircuit lets an operator force a mirror's circuit closed
// (reset, to re-admit it immediately after a known fix) or open (to take it out
// of rotation for the cooldown window).
func (s *Server) handleUpstreamPoolCircuit(w http.ResponseWriter, r *http.Request) {
	if s.opts.UpstreamPool == nil {
		s.writeError(w, http.StatusNotFound, "upstream mirror pools are not enabled")
		return
	}
	var req upstreamPoolCircuitRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Backend) == "" || strings.TrimSpace(req.Endpoint) == "" {
		s.writeError(w, http.StatusBadRequest, "both backend and endpoint are required")
		return
	}
	var err error
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "reset", "close", "closed":
		err = s.opts.UpstreamPool.ResetCircuit(req.Backend, req.Endpoint)
	case "open", "trip":
		err = s.opts.UpstreamPool.OpenCircuit(req.Backend, req.Endpoint)
	default:
		s.writeError(w, http.StatusBadRequest, `action must be "reset" or "open"`)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("admin: upstream mirror circuit overridden",
		"backend", req.Backend, "endpoint", req.Endpoint, "action", req.Action)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"backend": req.Backend, "endpoint": req.Endpoint, "action": req.Action,
	})
}
