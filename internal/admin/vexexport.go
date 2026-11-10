package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/vexexport"
)

// VEXExporter is the outbound VEX-authoring surface (Task 137): it renders the
// proxy's current VEX posture — the suppression corpus, VEX-adjudicated
// findings, and active break-glass grants — as a signed OpenVEX document or a
// CycloneDX VEX/VDR BOM, scoped to one coordinate or a whole snapshot. The
// vexexport.Service satisfies it.
type VEXExporter interface {
	Enabled() bool
	CanSign() bool
	Export(ctx context.Context, req vexexport.Request) (*vexexport.Result, error)
}

// handleVEXExport renders and returns a VEX document for the requested scope.
//
// Query parameters:
//
//	format     openvex (default) | cyclonedx
//	tenant     scope findings/grants and snapshot/live enumeration (optional)
//	ecosystem  artifact ecosystem (npm|pip|…), with name/version for one coordinate
//	name       artifact name — selects a single-coordinate export
//	version    artifact version
//	coordinate alternative single-artifact selector ("name@version" or a digest)
//	snapshot   a captured snapshot id — export the posture for its coordinate set
//	sign       "true" to attach a detached cosign-compatible signature (headers)
//
// With no coordinate and no snapshot, the whole live posture for the tenant is
// exported. The response body is the raw VEX document (directly re-ingestable);
// when signed, the detached signature travels in X-Vex-Signature* headers so the
// document itself stays byte-for-byte verifiable and re-ingestable.
func (s *Server) handleVEXExport(w http.ResponseWriter, r *http.Request) {
	if s.opts.VEXExport == nil || !s.opts.VEXExport.Enabled() {
		s.writeError(w, http.StatusNotFound, "outbound VEX export is not enabled")
		return
	}
	q := r.URL.Query()

	format, ok := vexexport.NormalizeFormat(strings.TrimSpace(q.Get("format")))
	if !ok {
		s.writeError(w, http.StatusBadRequest, "unknown format (want openvex|cyclonedx)")
		return
	}

	sign := isTrue(q.Get("sign"))
	if sign && !s.opts.VEXExport.CanSign() {
		s.writeError(w, http.StatusBadRequest, "signing requested but no signing key is configured for VEX export")
		return
	}

	req := vexexport.Request{
		Tenant:     strings.TrimSpace(q.Get("tenant")),
		Ecosystem:  strings.TrimSpace(q.Get("ecosystem")),
		Name:       strings.TrimSpace(q.Get("name")),
		Version:    strings.TrimSpace(q.Get("version")),
		Coordinate: strings.TrimSpace(q.Get("coordinate")),
		SnapshotID: strings.TrimSpace(q.Get("snapshot")),
		Format:     format,
		Sign:       sign,
	}

	res, err := s.opts.VEXExport.Export(r.Context(), req)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "generating VEX document: "+err.Error())
		return
	}

	h := w.Header()
	h.Set("Content-Type", res.MediaType)
	h.Set("Content-Disposition", "attachment; filename="+res.Filename)
	h.Set("X-Vex-Statements", strconv.Itoa(res.Statements))
	h.Set("X-Vex-Coordinates", strconv.Itoa(res.Coordinates))
	h.Set("X-Vex-Scope", res.Scope)
	if res.Signature != nil {
		h.Set("X-Vex-Signature", res.Signature.Value)
		h.Set("X-Vex-Signature-Algorithm", res.Signature.Algorithm)
		h.Set("X-Vex-Signature-Key-Id", res.Signature.KeyID)
		h.Set("X-Vex-Digest", res.Signature.Digest)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Document)
}

// isTrue parses a permissive boolean query value.
func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
