package admin

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/coord"
)

// coordinationResponse is the GET /api/coordination payload: this replica's local
// leadership state for every coordinated job plus the observed cross-replica
// leaseholders read live from the coordination backend.
type coordinationResponse struct {
	coord.Snapshot
	// Leaseholders is the backend's view of who currently holds each lease across
	// the cluster — a follower can answer this for the whole deployment.
	Leaseholders []coord.Leaseholder `json:"leaseholders"`
}

// handleCoordination reports the HA distributed-coordination status (Task 56): the
// per-job leader/lease state for this replica and the current leaseholders across
// the cluster, so an operator can verify exactly one replica leads each scheduled
// job and spot leadership flapping or a stuck lease.
func (s *Server) handleCoordination(w http.ResponseWriter, r *http.Request) {
	if s.opts.Coordination == nil || !s.opts.Coordination.Enabled() {
		// Distributed coordination is not enabled (single-node deployment); report it
		// as disabled rather than 404 so the dashboard can render a clear state.
		s.writeJSON(w, http.StatusOK, coordinationResponse{
			Snapshot:     coord.Snapshot{Enabled: false},
			Leaseholders: []coord.Leaseholder{},
		})
		return
	}
	resp := coordinationResponse{
		Snapshot:     s.opts.Coordination.Snapshot(),
		Leaseholders: s.opts.Coordination.Leaseholders(r.Context()),
	}
	if resp.Leaseholders == nil {
		resp.Leaseholders = []coord.Leaseholder{}
	}
	s.writeJSON(w, http.StatusOK, resp)
}
