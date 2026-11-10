package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/keyrotation"
)

// KeyRotationInspector is the credential & signing-key rotation surface the
// admin API exposes (Task 148): the current expiry read-model for every
// monitored piece of trust material, and a trigger to drive a supported in-place
// rotation (dual-key overlap aware). The keyrotation.Service satisfies it.
type KeyRotationInspector interface {
	Enabled() bool
	Status(ctx context.Context) keyrotation.ScanResult
	Rotate(ctx context.Context, materialID string, force bool) (keyrotation.RotationOutcome, error)
}

// handleKeysStatus reports the current expiry standings for every monitored
// signing key / credential / certificate: which are OK, warning, critical, or
// already expired, with the effective expiry and remaining lifetime of each. It
// is the read-model behind `ptctl keys status`, the SOC "upcoming expiries"
// panel, and the pullthrough_key_expiry_seconds gauge.
func (s *Server) handleKeysStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.KeyRotation == nil || !s.opts.KeyRotation.Enabled() {
		s.writeJSON(w, http.StatusOK, keyrotation.ScanResult{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.KeyRotation.Status(r.Context()))
}

// keysRotateRequest is the POST /api/keys/rotate body: which material to rotate,
// and whether to override the single-in-flight overlap guard.
type keysRotateRequest struct {
	Material string `json:"material"`
	Force    bool   `json:"force"`
}

// handleKeysRotate drives a supported in-place rotation of a named material
// (today the cache KEK). Material with no automated rotation path returns a 200
// with an informative, Supported=false outcome describing the out-of-band
// procedure; a rotation refused because a prior one is still within its overlap
// window returns 409; a genuine rotation failure returns 503 (Task 148).
func (s *Server) handleKeysRotate(w http.ResponseWriter, r *http.Request) {
	if s.opts.KeyRotation == nil || !s.opts.KeyRotation.Enabled() {
		s.writeError(w, http.StatusNotFound, "key-rotation subsystem is not enabled")
		return
	}
	var req keysRotateRequest
	if r.Body != nil {
		// Tolerate an empty body; only a malformed non-empty body is an error.
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}
	req.Material = strings.TrimSpace(req.Material)
	if req.Material == "" {
		s.writeError(w, http.StatusBadRequest, "material is required (the id of the key/credential to rotate)")
		return
	}

	out, err := s.opts.KeyRotation.Rotate(r.Context(), req.Material, req.Force)
	switch {
	case errors.Is(err, keyrotation.ErrUnknownMaterial):
		s.writeError(w, http.StatusNotFound, "unknown material: "+req.Material)
		return
	case errors.Is(err, keyrotation.ErrRotationUnsupported):
		// Not a failure: the material is known but rotated out-of-band. Return the
		// informative outcome so the operator sees the procedure.
		s.writeJSON(w, http.StatusOK, out)
		return
	case errors.Is(err, keyrotation.ErrRotationInFlight):
		s.writeError(w, http.StatusConflict, "rotation refused: a prior rotation of "+req.Material+" is still within its overlap window (retry with force to override)")
		return
	case err != nil:
		s.writeError(w, http.StatusServiceUnavailable, "key rotation failed: "+err.Error())
		return
	}
	s.logger.Info("admin: key rotation triggered",
		"material", out.MaterialID, "newPrimaryKeyId", out.NewPrimaryKeyID,
		"rewrapped", out.Rewrapped, "scanned", out.Scanned)
	s.writeJSON(w, http.StatusOK, out)
}
