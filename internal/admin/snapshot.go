package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
)

// The admin "Snapshots" surface (Task 70) exposes the organization-wide
// dependency snapshot / freeze / instant-rollback subsystem: list and inspect
// signed point-in-time captures, diff two of them, capture a new one, mark a
// snapshot known-good, freeze the org to a snapshot, and execute a one-action
// rollback to the last-known-good snapshot.

// snapshotListResponse is the snapshots list plus the active freeze state and
// the cumulative metrics for the tab header.
type snapshotListResponse struct {
	Snapshots []snapshot.Summary   `json:"snapshots"`
	Freeze    snapshot.FreezeState `json:"freeze"`
	Metrics   snapshot.Metrics     `json:"metrics"`
}

func (s *Server) snapshotEnabled(w http.ResponseWriter) bool {
	if s.opts.Snapshot == nil || !s.opts.Snapshot.Enabled() {
		s.writeError(w, http.StatusNotFound, "snapshot subsystem is not enabled")
		return false
	}
	return true
}

// actorSubject derives the calling identity for attributing a snapshot action,
// falling back to "admin" when SSO/RBAC is not configured.
func actorSubject(r *http.Request) string {
	if id, ok := adminauth.IdentityFromContext(r.Context()); ok && id != nil && id.Subject != "" {
		return id.Subject
	}
	return "admin"
}

// handleSnapshotList serves the snapshot inventory, freeze state, and metrics.
func (s *Server) handleSnapshotList(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	list := s.opts.Snapshot.List()
	if list == nil {
		list = []snapshot.Summary{}
	}
	s.writeJSON(w, http.StatusOK, snapshotListResponse{
		Snapshots: list,
		Freeze:    s.opts.Snapshot.FreezeState(),
		Metrics:   s.opts.Snapshot.Metrics(),
	})
}

// handleSnapshotGet serves one full manifest (with entries) by ?id=.
func (s *Server) handleSnapshotGet(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	m, ok := s.opts.Snapshot.Get(id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such snapshot")
		return
	}
	s.writeJSON(w, http.StatusOK, m)
}

// handleSnapshotDiff serves the diff between ?from= and ?to= (Markdown when
// ?format=md, JSON otherwise).
func (s *Server) handleSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	q := r.URL.Query()
	from := strings.TrimSpace(q.Get("from"))
	to := strings.TrimSpace(q.Get("to"))
	if from == "" || to == "" {
		s.writeError(w, http.StatusBadRequest, "from and to are required")
		return
	}
	d, ok := s.opts.Snapshot.Diff(from, to)
	if !ok {
		s.writeError(w, http.StatusNotFound, "one or both snapshots are unknown")
		return
	}
	if strings.EqualFold(strings.TrimSpace(q.Get("format")), "md") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(d.Markdown()))
		return
	}
	s.writeJSON(w, http.StatusOK, d)
}

// snapshotCreateRequest is the POST body for capturing a snapshot.
type snapshotCreateRequest struct {
	Name string `json:"name"`
	Note string `json:"note"`
}

// handleSnapshotCreate captures a new point-in-time snapshot of the live state.
func (s *Server) handleSnapshotCreate(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	var req snapshotCreateRequest
	if !s.decodeJSON(w, r, 16*1024, &req) {
		return
	}
	m, err := s.opts.Snapshot.Take(snapshot.TakeOptions{
		Name:      req.Name,
		Note:      req.Note,
		CreatedBy: actorSubject(r),
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, m.Summary(s.opts.Snapshot.FreezeState().SnapshotID))
}

// snapshotMarkGoodRequest is the POST body for (un)marking a known-good snapshot.
type snapshotMarkGoodRequest struct {
	ID   string `json:"id"`
	Good *bool  `json:"good"`
}

// handleSnapshotMarkGood sets/clears a snapshot's known-good rollback flag.
func (s *Server) handleSnapshotMarkGood(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	var req snapshotMarkGoodRequest
	if !s.decodeJSON(w, r, 4096, &req) {
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		s.writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	good := true
	if req.Good != nil {
		good = *req.Good
	}
	if err := s.opts.Snapshot.MarkGood(req.ID, good); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": req.ID, "good": good})
}

// snapshotFreezeRequest is the POST body for activating a freeze.
type snapshotFreezeRequest struct {
	ID            string `json:"id"`
	Mode          string `json:"mode"`
	Reason        string `json:"reason"`
	EnforceDigest bool   `json:"enforceDigest"`
}

// handleSnapshotFreeze pins the organization to a snapshot.
func (s *Server) handleSnapshotFreeze(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	var req snapshotFreezeRequest
	if !s.decodeJSON(w, r, 8192, &req) {
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		s.writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	fs, err := s.opts.Snapshot.Freeze(snapshot.FreezeOptions{
		SnapshotID:    req.ID,
		Mode:          snapshot.FreezeMode(req.Mode),
		Reason:        req.Reason,
		ActivatedBy:   actorSubject(r),
		EnforceDigest: req.EnforceDigest,
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, fs)
}

// handleSnapshotUnfreeze lifts the active freeze.
func (s *Server) handleSnapshotUnfreeze(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	fs, err := s.opts.Snapshot.Unfreeze(actorSubject(r))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, fs)
}

// snapshotRollbackRequest is the optional POST body for an instant rollback.
type snapshotRollbackRequest struct {
	Reason string `json:"reason"`
}

// handleSnapshotRollback pins the org back to the last-known-good snapshot.
func (s *Server) handleSnapshotRollback(w http.ResponseWriter, r *http.Request) {
	if !s.snapshotEnabled(w) {
		return
	}
	var req snapshotRollbackRequest
	// The body is optional for rollback; ignore a decode error on an empty body.
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	fs, m, err := s.opts.Snapshot.Rollback(actorSubject(r), req.Reason)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"ok": true, "freeze": fs}
	if m != nil {
		resp["snapshot"] = m.Summary(fs.SnapshotID)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// decodeJSON decodes a JSON request body with a size cap and unknown-field
// rejection, writing a 400 on failure. It returns false when the caller should
// stop.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}
