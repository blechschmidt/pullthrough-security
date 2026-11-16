package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// FullScanController is the full scan (Task 192) as the admin API drives it.
// *fullscan.Service satisfies it.
type FullScanController interface {
	Status() fullscan.Status
	UpstreamStatus(upstream string) (fullscan.UpstreamStatus, error)
	Pause(ctx context.Context, upstream, by, reason string) error
	Resume(ctx context.Context, upstream, by string) error
	Rescan(ctx context.Context, req fullscan.RescanRequest) (fullscan.RescanRequest, error)
}

// fullScanRequest is the body of POST /api/fullscan/{pause,resume,rescan}.
type fullScanRequest struct {
	Upstream string `json:"upstream"`
	Reason   string `json:"reason"`
	// Filter and Path select what a re-scan covers.
	Filter string `json:"filter"`
	Path   string `json:"path"`
}

// fullScanRescanResponse answers a re-scan request.
type fullScanRescanResponse struct {
	Request fullscan.RescanRequest `json:"request"`
	Status  fullscan.Status        `json:"status"`
}

// tenantBound reports an identity bound to one tenant.
func tenantBound(r *http.Request) bool {
	id, ok := adminauth.IdentityFromContext(r.Context())
	return ok && id != nil && id.Tenant != ""
}

// handleFullScanStatus reports the full scan: overall and per upstream
// (?upstream=<name> for one). A tenant-bound identity sees the figures, not
// the artifacts other tenants' caches hold (the oldest unscanned one's path).
func (s *Server) handleFullScanStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.FullScan == nil {
		s.writeJSON(w, http.StatusOK, fullscan.Status{Subject: fullscan.Subject, Upstreams: []fullscan.UpstreamStatus{}})
		return
	}
	st := s.opts.FullScan.Status()
	if tenantBound(r) {
		st = st.Redacted()
	}
	if name := strings.TrimSpace(r.URL.Query().Get("upstream")); name != "" {
		for _, u := range st.Upstreams {
			if u.Upstream == name {
				s.writeJSON(w, http.StatusOK, u)
				return
			}
		}
		s.writeError(w, http.StatusNotFound, "the full scan does not cover upstream "+quoteName(name))
		return
	}
	s.writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleFullScanPause(w http.ResponseWriter, r *http.Request) {
	s.fullScanAction(w, r, "paused", func(ctl FullScanController, req fullScanRequest, by string) (any, error) {
		return nil, ctl.Pause(r.Context(), req.Upstream, by, req.Reason)
	})
}

func (s *Server) handleFullScanResume(w http.ResponseWriter, r *http.Request) {
	s.fullScanAction(w, r, "resumed", func(ctl FullScanController, req fullScanRequest, by string) (any, error) {
		return nil, ctl.Resume(r.Context(), req.Upstream, by)
	})
}

func (s *Server) handleFullScanRescan(w http.ResponseWriter, r *http.Request) {
	s.fullScanAction(w, r, "re-scan requested", func(ctl FullScanController, req fullScanRequest, by string) (any, error) {
		rr, err := ctl.Rescan(r.Context(), fullscan.RescanRequest{Upstream: req.Upstream, Filter: req.Filter, Path: req.Path, By: by})
		if err != nil {
			return nil, err
		}
		return fullScanRescanResponse{Request: rr, Status: ctl.Status()}, nil
	})
}

// fullScanAction runs an operator's control action. The full scan is
// instance-wide, so a tenant-bound identity may read its status but not steer
// it.
func (s *Server) fullScanAction(w http.ResponseWriter, r *http.Request, done string, act func(FullScanController, fullScanRequest, string) (any, error)) {
	if s.opts.FullScan == nil {
		s.writeError(w, http.StatusNotFound, "the full scan is not enabled (fullScan.enabled or upstreams.<name>.fullMirror.fullScan)")
		return
	}
	if tenantBound(r) {
		s.writeError(w, http.StatusForbidden, "the full scan is instance-wide: a tenant-bound identity cannot pause, resume or re-scan it")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFullMirrorBody))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}
	var req fullScanRequest
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
	out, err := act(s.opts.FullScan, req, by)
	if err != nil {
		switch {
		case errors.Is(err, fullscan.ErrUnknownUpstream):
			s.writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, fullscan.ErrDisabled):
			s.writeError(w, http.StatusNotFound, err.Error())
		case strings.Contains(err.Error(), "reason is longer"), strings.Contains(err.Error(), "re-scan"), strings.Contains(err.Error(), "path"):
			s.writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.logger.Error("admin: full scan", "error", err)
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.logger.Info("admin: full scan "+done, "upstream", firstNonEmptyStr(req.Upstream, "*"), "by", by)
	if out != nil {
		s.writeJSON(w, http.StatusOK, out)
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.FullScan.Status())
}

// quoteName renders a user-supplied name for an error message.
func quoteName(name string) string {
	if len(name) > 128 {
		name = name[:128] + "…"
	}
	b, _ := json.Marshal(name)
	return string(b)
}
