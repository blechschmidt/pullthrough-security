package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/remediation"
)

// handleRemediationAdvise serves the automated dependency-remediation advisor
// (Task 121): given a flagged/blocked artifact it computes the nearest safe
// upgrade version, the findings that version resolves relative to the flagged
// one, the residual findings it does not clear, and any new findings it would
// introduce. Parameters:
//
//	ecosystem  (required) the package ecosystem (npm/pip/cargo/go/nuget/...)
//	name       (required) the package name/coordinate
//	version    (required) the flagged version to remediate
//	tenant     (optional) tenant scope for the tenant-aware gates
//	gates      (optional) comma-separated gate restriction
//	           (vulnscan,license,maturity,depfirewall); empty = all gates
//	max        (optional) bound on versions evaluated
//	prerelease (optional) "true" to consider prerelease upgrade targets
//	format     (optional) "json" (default) or "table"/"md" for the text report
//
// The computation makes live upstream and scan calls, so it can take longer
// than an in-memory read; callers should allow a generous timeout.
func (s *Server) handleRemediationAdvise(w http.ResponseWriter, r *http.Request) {
	if s.opts.Remediation == nil || !s.opts.Remediation.Enabled() {
		s.writeError(w, http.StatusNotFound, "remediation advisor is not enabled")
		return
	}
	q := r.URL.Query()
	ecosystem := strings.TrimSpace(q.Get("ecosystem"))
	name := strings.TrimSpace(q.Get("name"))
	if name == "" {
		name = strings.TrimSpace(q.Get("coordinate"))
	}
	version := strings.TrimSpace(q.Get("version"))
	// Accept a "name@version" coordinate too.
	if version == "" {
		if i := strings.LastIndexByte(name, '@'); i > 0 {
			version = name[i+1:]
			name = name[:i]
		}
	}
	if ecosystem == "" || name == "" || version == "" {
		s.writeError(w, http.StatusBadRequest, "ecosystem, name, and version are required")
		return
	}

	req := remediation.Request{
		Tenant:            strings.TrimSpace(q.Get("tenant")),
		Ecosystem:         ecosystem,
		Name:              name,
		Version:           version,
		Gates:             parseGates(q.Get("gates")),
		IncludePrerelease: strings.EqualFold(strings.TrimSpace(q.Get("prerelease")), "true"),
	}
	if m := strings.TrimSpace(q.Get("max")); m != "" {
		if n, err := strconv.Atoi(m); err == nil && n > 0 {
			req.MaxCandidates = n
		}
	}

	advice, err := s.opts.Remediation.Advise(r.Context(), req)
	if err != nil {
		if remediation.Disabled(err) {
			s.writeError(w, http.StatusNotFound, "remediation advisor is not enabled")
			return
		}
		s.writeError(w, http.StatusBadGateway, "remediation advisor failed: "+err.Error())
		return
	}

	switch strings.ToLower(strings.TrimSpace(q.Get("format"))) {
	case "table", "md", "markdown", "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(advice.Table()))
	default:
		s.writeJSON(w, http.StatusOK, advice)
	}
}

// parseGates parses a comma-separated gate restriction into GateKinds, dropping
// blanks. An empty input yields nil (all gates considered).
func parseGates(raw string) []remediation.GateKind {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []remediation.GateKind
	for _, part := range strings.Split(raw, ",") {
		if g := strings.TrimSpace(part); g != "" {
			out = append(out, remediation.GateKind(strings.ToLower(g)))
		}
	}
	return out
}
