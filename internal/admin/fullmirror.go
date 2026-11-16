package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

// FullMirrorController is the full-mirror engine (Task 189) as the admin API
// drives it. *fullmirror.Engine satisfies it.
type FullMirrorController interface {
	Status() fullmirror.Status
	UpstreamStatus(upstream string) (fullmirror.UpstreamStatus, error)
	Pause(ctx context.Context, upstream, by, reason string) error
	Resume(ctx context.Context, upstream, by string) error
	Resync(ctx context.Context, upstream, by string) error
}

// maxFullMirrorBody bounds a pause/resume/resync request.
const maxFullMirrorBody = 8 << 10

// fullMirrorRequest is the body of POST /api/fullmirror/{pause,resume,resync}.
// An empty upstream pauses or resumes every upstream; a resync names one.
type fullMirrorRequest struct {
	Upstream string `json:"upstream"`
	Reason   string `json:"reason"`
}

// handleFullMirrorStatus reports the full mirror: overall and per upstream
// (?upstream=<name> for one). With nothing mirrored it reports enabled false.
func (s *Server) handleFullMirrorStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.FullMirror == nil {
		s.writeJSON(w, http.StatusOK, fullmirror.Status{Upstreams: []fullmirror.UpstreamStatus{}})
		return
	}
	if name := strings.TrimSpace(r.URL.Query().Get("upstream")); name != "" {
		us, err := s.opts.FullMirror.UpstreamStatus(name)
		if err != nil {
			s.writeFullMirrorError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, us)
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.FullMirror.Status())
}

func (s *Server) handleFullMirrorPause(w http.ResponseWriter, r *http.Request) {
	s.fullMirrorAction(w, r, "paused", func(ctl FullMirrorController, req fullMirrorRequest, by string) error {
		return ctl.Pause(r.Context(), req.Upstream, by, req.Reason)
	})
}

func (s *Server) handleFullMirrorResume(w http.ResponseWriter, r *http.Request) {
	s.fullMirrorAction(w, r, "resumed", func(ctl FullMirrorController, req fullMirrorRequest, by string) error {
		return ctl.Resume(r.Context(), req.Upstream, by)
	})
}

func (s *Server) handleFullMirrorResync(w http.ResponseWriter, r *http.Request) {
	s.fullMirrorAction(w, r, "resync requested", func(ctl FullMirrorController, req fullMirrorRequest, by string) error {
		if strings.TrimSpace(req.Upstream) == "" || strings.TrimSpace(req.Upstream) == "*" {
			return errResyncNeedsUpstream
		}
		return ctl.Resync(r.Context(), req.Upstream, by)
	})
}

var errResyncNeedsUpstream = errors.New("name the upstream to resync: it enumerates the whole registry again")

// fullMirrorAction runs an operator's control action. The full mirror is
// instance-wide, so a tenant-bound identity may read its status but not
// steer it.
func (s *Server) fullMirrorAction(w http.ResponseWriter, r *http.Request, done string, act func(FullMirrorController, fullMirrorRequest, string) error) {
	if s.opts.FullMirror == nil {
		s.writeError(w, http.StatusNotFound, "full mirroring is not enabled (upstreams.<name>.fullMirror)")
		return
	}
	if id, ok := adminauth.IdentityFromContext(r.Context()); ok && id != nil && id.Tenant != "" {
		s.writeError(w, http.StatusForbidden, "the full mirror is instance-wide: a tenant-bound identity cannot pause, resume or resync it")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFullMirrorBody))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}
	var req fullMirrorRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
	}
	if q := strings.TrimSpace(r.URL.Query().Get("upstream")); q != "" && req.Upstream == "" {
		req.Upstream = q
	}
	by := actor(r)
	if err := act(s.opts.FullMirror, req, by); err != nil {
		s.writeFullMirrorError(w, err)
		return
	}
	s.logger.Info("admin: full mirror "+done, "upstream", firstNonEmptyStr(req.Upstream, "*"), "by", by)
	if req.Upstream != "" && req.Upstream != "*" {
		us, err := s.opts.FullMirror.UpstreamStatus(req.Upstream)
		if err == nil {
			s.writeJSON(w, http.StatusOK, us)
			return
		}
	}
	s.writeJSON(w, http.StatusOK, s.opts.FullMirror.Status())
}

func (s *Server) writeFullMirrorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fullmirror.ErrUnknownUpstream):
		s.writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errResyncNeedsUpstream):
		s.writeError(w, http.StatusBadRequest, err.Error())
	case strings.Contains(err.Error(), "reason is longer"), strings.Contains(err.Error(), "name the upstream"):
		s.writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.logger.Error("admin: full mirror", "error", err)
		s.writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
