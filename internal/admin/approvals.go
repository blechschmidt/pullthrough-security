package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
)

// ApprovalsInspector is the quarantine-review / break-glass workflow surface the
// admin API exposes (Task 50): the cumulative snapshot, a status-filtered listing
// of requests, and the approve/deny decision endpoints (each requiring an
// approver identity and a justification). The approvals.Service satisfies it.
type ApprovalsInspector interface {
	Enabled() bool
	Snapshot() approvals.Snapshot
	List(status string, limit int) []approvals.Request
	Approve(ctx context.Context, id string, in approvals.ApproveInput) (approvals.Request, error)
	Deny(ctx context.Context, id, approver, justification string) (approvals.Request, error)
	// Sweep revokes due grants and stale pending reviews so the listing reflects
	// live status; called before serving the list so the UI never shows an expired
	// grant as active.
	Sweep(ctx context.Context) int
}

// approvalsStatusResponse is the payload for GET {prefix}/api/approvals: the
// workflow snapshot plus the (optionally status-filtered) requests.
type approvalsStatusResponse struct {
	Enabled  bool                `json:"enabled"`
	Snapshot *approvals.Snapshot `json:"snapshot,omitempty"`
	Total    int                 `json:"total"`
	Returned int                 `json:"returned"`
	Items    []approvals.Request `json:"items"`
}

// handleApprovalsList serves the workflow snapshot and the requests, filtered by
// the optional ?status= (pending|approved|denied|expired) and capped by ?limit=.
func (s *Server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Approvals == nil || !s.opts.Approvals.Enabled() {
		s.writeJSON(w, http.StatusOK, approvalsStatusResponse{Enabled: false, Items: []approvals.Request{}})
		return
	}
	// Reconcile expirations so the listing reports live status.
	s.opts.Approvals.Sweep(r.Context())
	status := r.URL.Query().Get("status")
	items := s.opts.Approvals.List(status, parseLimit(r, 200))
	if items == nil {
		items = []approvals.Request{}
	}
	snap := s.opts.Approvals.Snapshot()
	s.writeJSON(w, http.StatusOK, approvalsStatusResponse{
		Enabled:  true,
		Snapshot: &snap,
		Total:    len(items),
		Returned: len(items),
		Items:    items,
	})
}

// approvalDecisionRequest is the POST body for approve/deny.
type approvalDecisionRequest struct {
	ID              string `json:"id"`
	Approver        string `json:"approver"`
	Justification   string `json:"justification"`
	DurationSeconds int    `json:"durationSeconds,omitempty"`
}

func (s *Server) decodeApprovalDecision(w http.ResponseWriter, r *http.Request) (approvalDecisionRequest, bool) {
	var req approvalDecisionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return req, false
	}
	if req.ID == "" {
		s.writeError(w, http.StatusBadRequest, "missing id")
		return req, false
	}
	return req, true
}

// handleApprovalApprove records one approver's vote toward a break-glass grant.
// When the configured number of distinct approvers is reached the request becomes
// an active, time-boxed exception.
func (s *Server) handleApprovalApprove(w http.ResponseWriter, r *http.Request) {
	if s.opts.Approvals == nil || !s.opts.Approvals.Enabled() {
		s.writeError(w, http.StatusNotFound, "approval workflow is not enabled")
		return
	}
	req, ok := s.decodeApprovalDecision(w, r)
	if !ok {
		return
	}
	in := approvals.ApproveInput{
		Approver:      req.Approver,
		Justification: req.Justification,
	}
	if req.DurationSeconds > 0 {
		in.Duration = time.Duration(req.DurationSeconds) * time.Second
	}
	out, err := s.opts.Approvals.Approve(r.Context(), req.ID, in)
	if err != nil {
		s.writeApprovalError(w, err)
		return
	}
	s.logger.Info("admin: approval vote recorded",
		"requestId", req.ID, "approver", req.Approver, "status", string(out.Status))
	s.writeJSON(w, http.StatusOK, out)
}

// handleApprovalDeny confirms the block on a pending request (no exception is
// granted and no fresh review is auto-opened).
func (s *Server) handleApprovalDeny(w http.ResponseWriter, r *http.Request) {
	if s.opts.Approvals == nil || !s.opts.Approvals.Enabled() {
		s.writeError(w, http.StatusNotFound, "approval workflow is not enabled")
		return
	}
	req, ok := s.decodeApprovalDecision(w, r)
	if !ok {
		return
	}
	out, err := s.opts.Approvals.Deny(r.Context(), req.ID, req.Approver, req.Justification)
	if err != nil {
		s.writeApprovalError(w, err)
		return
	}
	s.logger.Info("admin: approval denied", "requestId", req.ID, "approver", req.Approver)
	s.writeJSON(w, http.StatusOK, out)
}

// writeApprovalError maps the workflow's typed errors to HTTP status codes.
func (s *Server) writeApprovalError(w http.ResponseWriter, err error) {
	switch err {
	case approvals.ErrNotFound:
		s.writeError(w, http.StatusNotFound, err.Error())
	case approvals.ErrNotPending, approvals.ErrDuplicateApprover,
		approvals.ErrNoApprover, approvals.ErrNoJustification:
		s.writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.writeError(w, http.StatusInternalServerError, err.Error())
	}
}
