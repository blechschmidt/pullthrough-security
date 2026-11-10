package portal

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/metering"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// recentScanLimit bounds how deep into the (global) risk-assessment history the
// portal scans before tenant-filtering. It is generous so a busy tenant still
// sees its recent verdicts even when interleaved with other tenants' pulls.
const recentScanLimit = 2000

// --- userinfo ---------------------------------------------------------------

// userinfoResponse tells the front-end who the caller is, whether they may use
// the portal, and where to log in. It is intentionally minimal and reveals
// nothing about other tenants.
type userinfoResponse struct {
	Authenticated bool   `json:"authenticated"`
	Subject       string `json:"subject,omitempty"`
	Tenant        string `json:"tenant,omitempty"`
	CanView       bool   `json:"canView"`
	Method        string `json:"method,omitempty"`
	LoginURL      string `json:"loginUrl,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// handleUserinfo reports the caller's portal eligibility. No guard: it always
// returns 200 so the page can render the right affordance (login / no-tenant /
// ready).
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	resp := userinfoResponse{LoginURL: s.opts.Auth.LoginPath()}
	id, err := s.opts.Auth.Authenticate(r.Context(), r)
	if err != nil || id == nil {
		resp.Reason = "Sign in to view your tenant's security posture."
		s.writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.Authenticated = true
	resp.Subject = id.Subject
	resp.Method = id.Method
	resp.Tenant = id.Tenant
	switch {
	case !id.Can(adminauth.CapTenantViewer):
		resp.Reason = "Your account lacks the tenant-viewer role required for the self-service portal."
	case strings.TrimSpace(id.Tenant) == "":
		resp.Reason = "Your account is not bound to a tenant, so there is nothing to scope to."
	default:
		resp.CanView = true
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// --- summary ----------------------------------------------------------------

type summaryResponse struct {
	Tenant     string          `json:"tenant"`
	Subject    string          `json:"subject,omitempty"`
	Verdicts   verdictTallies  `json:"verdicts"`
	Quarantine quarantineTally `json:"quarantine"`
	Findings   findingsTally   `json:"findings"`
	Sources    map[string]bool `json:"sources"`
}

type verdictTallies struct {
	Total int `json:"total"`
	Admit int `json:"admit"`
	Warn  int `json:"warn"`
	Block int `json:"block"`
}

type quarantineTally struct {
	Enabled bool `json:"enabled"`
	Open    int  `json:"open"`    // pending review
	Granted int  `json:"granted"` // active break-glass grant
}

type findingsTally struct {
	Coordinates int `json:"coordinates"`
	Findings    int `json:"findings"`
}

// handleSummary returns a tenant-scoped at-a-glance posture.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	resp := summaryResponse{
		Tenant:  tenant,
		Sources: map[string]bool{},
	}
	if id := identityOf(r); id != nil {
		resp.Subject = id.Subject
	}

	resp.Sources["verdicts"] = s.opts.Verdicts != nil
	for _, a := range s.tenantAssessments(tenant) {
		resp.Verdicts.Total++
		switch decisionOf(a) {
		case "block":
			resp.Verdicts.Block++
		case "warn":
			resp.Verdicts.Warn++
		default:
			resp.Verdicts.Admit++
		}
	}

	resp.Sources["quarantine"] = s.opts.Approvals != nil
	if s.opts.Approvals != nil {
		resp.Quarantine.Enabled = s.opts.Approvals.Enabled()
		for _, req := range s.tenantRequests(tenant) {
			switch req.Status {
			case approvals.StatusPending:
				resp.Quarantine.Open++
			case approvals.StatusApproved:
				resp.Quarantine.Granted++
			}
		}
	}

	resp.Sources["findings"] = s.opts.Findings != nil
	if s.opts.Findings != nil {
		docs := s.opts.Findings.Documents(tenant, "")
		resp.Findings.Coordinates = len(docs)
		for _, d := range docs {
			resp.Findings.Findings += len(d.Findings)
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// --- verdicts ---------------------------------------------------------------

type verdictDTO struct {
	Coordinate string   `json:"coordinate,omitempty"`
	Name       string   `json:"name,omitempty"`
	Version    string   `json:"version,omitempty"`
	Ecosystem  string   `json:"ecosystem,omitempty"`
	Decision   string   `json:"decision"` // admit|warn|block
	Score      int      `json:"score"`
	Band       string   `json:"band"`
	Summary    string   `json:"summary,omitempty"`
	Drivers    []string `json:"drivers,omitempty"`
	ScoredAt   string   `json:"scoredAt,omitempty"`
}

type verdictsResponse struct {
	Tenant   string       `json:"tenant"`
	Enabled  bool         `json:"enabled"`
	Total    int          `json:"total"`
	Verdicts []verdictDTO `json:"verdicts"`
}

// handleVerdicts lists the tenant's recent pull verdicts with explainable reasons.
func (s *Server) handleVerdicts(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	resp := verdictsResponse{Tenant: tenant, Enabled: s.opts.Verdicts != nil, Verdicts: []verdictDTO{}}
	for _, a := range s.tenantAssessments(tenant) {
		resp.Verdicts = append(resp.Verdicts, assessmentToDTO(a))
	}
	resp.Total = len(resp.Verdicts)
	s.writeJSON(w, http.StatusOK, resp)
}

// --- coordinate detail ------------------------------------------------------

type findingDTO struct {
	RuleID        string `json:"ruleId,omitempty"`
	Gate          string `json:"gate,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Level         string `json:"level,omitempty"`
	Identifier    string `json:"identifier,omitempty"`
	Title         string `json:"title"`
	Message       string `json:"message,omitempty"`
	Suppressed    bool   `json:"suppressed,omitempty"`
	Justification string `json:"justification,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	HelpURI       string `json:"helpUri,omitempty"`
}

type breakGlassDTO struct {
	Available bool   `json:"available"`
	RequestID string `json:"requestId,omitempty"`
	Status    string `json:"status,omitempty"`
	Gate      string `json:"gate,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Guidance  string `json:"guidance"`
}

type coordinateResponse struct {
	Tenant      string         `json:"tenant"`
	Coordinate  string         `json:"coordinate"`
	Found       bool           `json:"found"`
	Verdict     *verdictDTO    `json:"verdict,omitempty"`
	Findings    []findingDTO   `json:"findings"`
	Blocked     bool           `json:"blocked"`
	BreakGlass  breakGlassDTO  `json:"breakGlass"`
	Attestation attestationRef `json:"attestation"`
}

type attestationRef struct {
	Available bool   `json:"available"`
	URL       string `json:"url,omitempty"`
}

// handleCoordinate explains why a specific coordinate was flagged for the
// caller's tenant and what to do about it. The coordinate comes from the query;
// the TENANT does not — it is always the caller's own scope.
func (s *Server) handleCoordinate(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	coord := strings.TrimSpace(r.URL.Query().Get("coordinate"))
	if coord == "" {
		s.writeError(w, http.StatusBadRequest, "coordinate query parameter is required")
		return
	}
	resp := coordinateResponse{Tenant: tenant, Coordinate: coord, Findings: []findingDTO{}}

	if s.opts.Findings != nil {
		if doc, ok := s.opts.Findings.Get(tenant, coord); ok && sameTenant(tenant, doc.Tenant) {
			resp.Found = true
			for _, f := range doc.Findings {
				resp.Findings = append(resp.Findings, findingToDTO(f))
				if f.Level == findings.LevelError && !f.Suppressed {
					resp.Blocked = true
				}
			}
		}
	}

	// Matching risk verdict (scan the tenant's recent assessments).
	for _, a := range s.tenantAssessments(tenant) {
		if strings.EqualFold(a.Artifact.Coordinate, coord) || strings.EqualFold(a.Artifact.Name, coord) {
			resp.Found = true
			dto := assessmentToDTO(a)
			resp.Verdict = &dto
			if decisionOf(a) == "block" {
				resp.Blocked = true
			}
			break
		}
	}

	resp.BreakGlass = s.breakGlassFor(tenant, coord)
	if resp.BreakGlass.Available {
		resp.Found = true
	}

	if s.opts.Attest != nil {
		if b, ok := s.opts.Attest.Get(tenant, coord); ok && b != nil && sameTenant(tenant, b.Tenant) {
			resp.Attestation.Available = true
			resp.Attestation.URL = s.apiPrefix + "/attestation?package=" + urlQueryEscape(coord)
			resp.Found = true
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// --- quarantine -------------------------------------------------------------

type quarantineItem struct {
	ID         string `json:"id"`
	Coordinate string `json:"coordinate,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Gate       string `json:"gate,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Status     string `json:"status"`
	Hits       int    `json:"hits,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
	Guidance   string `json:"guidance"`
}

type quarantineResponse struct {
	Tenant  string           `json:"tenant"`
	Enabled bool             `json:"enabled"`
	Total   int              `json:"total"`
	Items   []quarantineItem `json:"items"`
}

// handleQuarantine lists the tenant's quarantined items / break-glass requests.
func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	resp := quarantineResponse{Tenant: tenant, Enabled: s.opts.Approvals != nil && s.opts.Approvals.Enabled(), Items: []quarantineItem{}}
	for _, req := range s.tenantRequests(tenant) {
		resp.Items = append(resp.Items, quarantineItem{
			ID:         req.ID,
			Coordinate: req.Coordinate,
			Ecosystem:  req.Ecosystem,
			Gate:       req.Gate,
			Reason:     req.Reason,
			Status:     string(req.Status),
			Hits:       req.Hits,
			CreatedAt:  fmtTime(req.CreatedAt),
			ExpiresAt:  fmtTime(req.ExpiresAt),
			Guidance:   guidanceFor(req),
		})
	}
	resp.Total = len(resp.Items)
	s.writeJSON(w, http.StatusOK, resp)
}

// --- onboarding -------------------------------------------------------------

type onboardingResponse struct {
	Tenant   string            `json:"tenant"`
	ProxyURL string            `json:"proxyUrl,omitempty"`
	Snippets []onboard.Snippet `json:"snippets"`
}

// handleOnboarding returns the per-package-manager config snippets for the
// caller, reusing the shared generators. The tenant is shown for context; the
// token is left as a placeholder (the portal never mints credentials).
func (s *Server) handleOnboarding(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	ctx := onboard.Context{
		ProxyBase: strings.TrimRight(s.opts.ProxyBaseURL, "/"),
		Host:      hostOf(s.opts.ProxyBaseURL),
		Tenant:    tenant,
	}
	resp := onboardingResponse{
		Tenant:   tenant,
		ProxyURL: ctx.ProxyBase,
		Snippets: onboard.ForAll(ctx, s.opts.Backends),
	}
	if resp.Snippets == nil {
		resp.Snippets = []onboard.Snippet{}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// --- SARIF download ---------------------------------------------------------

// handleSARIF exports the tenant's findings as SARIF 2.1.0 — a single artifact
// when ?package= is given, or the tenant's whole set otherwise. The tenant is
// always the caller's own scope, so a package belonging to another tenant is
// never returned.
func (s *Server) handleSARIF(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	if s.opts.Findings == nil {
		s.writeError(w, http.StatusNotFound, "findings are not available")
		return
	}
	opts := findings.SARIFOptions{ToolVersion: s.opts.Version}
	if pkg := strings.TrimSpace(r.URL.Query().Get("package")); pkg != "" {
		doc, ok := s.opts.Findings.Get(tenant, pkg)
		if !ok || !sameTenant(tenant, doc.Tenant) {
			s.writeError(w, http.StatusNotFound, "no findings recorded for that artifact under your tenant")
			return
		}
		s.writeSARIF(w, doc.SARIF(opts))
		return
	}
	docs := s.opts.Findings.Documents(tenant, "")
	// Defense in depth: Documents already filters by tenant, but re-assert it so a
	// future store change can never silently widen the scope.
	scoped := docs[:0]
	for _, d := range docs {
		if sameTenant(tenant, d.Tenant) {
			scoped = append(scoped, d)
		}
	}
	s.writeSARIF(w, findings.SARIFFromDocuments(scoped, opts))
}

// --- usage / chargeback (Task 84) -------------------------------------------

// handleUsage serves the caller's own per-tenant usage/chargeback report. The
// tenant is taken from the authenticated identity (never from a parameter) and
// forced onto the report request, so a tenant-viewer sees only their own usage.
// Supports format=json (default), csv, or markdown, plus start/end/granularity.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	if s.opts.Metering == nil || !s.opts.Metering.Enabled() {
		s.writeError(w, http.StatusNotFound, "usage metering is not available")
		return
	}
	q := r.URL.Query()
	report := s.opts.Metering.Report(metering.ReportRequest{
		Tenant:      tenant, // hard-scoped: forced from identity, ignoring any client value
		Start:       parsePortalTime(q.Get("start")),
		End:         parsePortalTime(q.Get("end")),
		Granularity: q.Get("granularity"),
	})
	switch strings.ToLower(strings.TrimSpace(q.Get("format"))) {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="usage.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.CSV()))
	case "markdown", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.Markdown()))
	default:
		s.writeJSON(w, http.StatusOK, report)
	}
}

// parsePortalTime accepts an RFC3339 timestamp or unix-seconds integer; an
// invalid or empty value yields the zero time (unbounded).
func parsePortalTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC()
	}
	return time.Time{}
}

// --- attestation download ---------------------------------------------------

// handleAttestation streams the raw DSSE attestation envelope for one of the
// tenant's own artifacts.
func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r)
	if s.opts.Attest == nil {
		s.writeError(w, http.StatusNotFound, "attestations are not available")
		return
	}
	pkg := strings.TrimSpace(r.URL.Query().Get("package"))
	if pkg == "" {
		s.writeError(w, http.StatusBadRequest, "package query parameter is required")
		return
	}
	b, ok := s.opts.Attest.Get(tenant, pkg)
	if !ok || b == nil || !sameTenant(tenant, b.Tenant) {
		s.writeError(w, http.StatusNotFound, "no attestation recorded for that artifact under your tenant")
		return
	}
	w.Header().Set("Content-Type", "application/vnd.dsse.envelope.v1+json")
	w.Header().Set("X-Attestation-Digest", b.Digest)
	w.Header().Set("X-Attestation-Predicate", b.PredicateType)
	s.writeJSON(w, http.StatusOK, b.Envelope)
}

// --- helpers ----------------------------------------------------------------

// tenantAssessments returns the caller-tenant's recent risk assessments, most
// recent first. It hard-filters the global history by tenant.
func (s *Server) tenantAssessments(tenant string) []riskscore.Assessment {
	if s.opts.Verdicts == nil {
		return nil
	}
	var out []riskscore.Assessment
	for _, a := range s.opts.Verdicts.Recent(recentScanLimit) {
		if sameTenant(tenant, a.Tenant) {
			out = append(out, a)
		}
	}
	return out
}

// tenantRequests returns the caller-tenant's approval/quarantine requests, most
// recent first. It hard-filters the global list by tenant.
func (s *Server) tenantRequests(tenant string) []approvals.Request {
	if s.opts.Approvals == nil {
		return nil
	}
	var out []approvals.Request
	for _, req := range s.opts.Approvals.List("", recentScanLimit) {
		if sameTenant(tenant, req.Tenant) {
			out = append(out, req)
		}
	}
	return out
}

// breakGlassFor finds the open/active break-glass request matching a coordinate
// for the tenant and renders developer guidance.
func (s *Server) breakGlassFor(tenant, coord string) breakGlassDTO {
	dto := breakGlassDTO{
		Guidance: "If this package is blocked and you need it, ask an approver on your team to review the request in the admin approvals queue. Approvals are dual-control and time-boxed.",
	}
	if s.opts.Approvals == nil {
		return dto
	}
	var match *approvals.Request
	for _, req := range s.tenantRequests(tenant) {
		if !strings.EqualFold(req.Coordinate, coord) {
			continue
		}
		r := req
		// Prefer a pending request; otherwise keep the most recent match.
		if match == nil || req.Status == approvals.StatusPending {
			match = &r
			if req.Status == approvals.StatusPending {
				break
			}
		}
	}
	if match != nil {
		dto.Available = true
		dto.RequestID = match.ID
		dto.Status = string(match.Status)
		dto.Gate = match.Gate
		dto.Reason = match.Reason
	}
	return dto
}

// decisionOf maps a risk assessment to the verdict vocabulary.
func decisionOf(a riskscore.Assessment) string {
	switch {
	case a.Block:
		return "block"
	case a.Warn:
		return "warn"
	default:
		return "admit"
	}
}

func assessmentToDTO(a riskscore.Assessment) verdictDTO {
	return verdictDTO{
		Coordinate: a.Artifact.Coordinate,
		Name:       a.Artifact.Name,
		Version:    a.Artifact.Version,
		Ecosystem:  a.Artifact.Ecosystem,
		Decision:   decisionOf(a),
		Score:      a.Score,
		Band:       string(a.Band),
		Summary:    a.Summary,
		Drivers:    topDrivers(a),
		ScoredAt:   fmtTime(a.ScoredAt),
	}
}

// topDrivers names the highest-contributing risk signals, for an at-a-glance
// "why" without dumping the full breakdown.
func topDrivers(a riskscore.Assessment) []string {
	contribs := make([]riskscore.Contribution, len(a.Contributions))
	copy(contribs, a.Contributions)
	sort.SliceStable(contribs, func(i, j int) bool { return contribs[i].Points > contribs[j].Points })
	var out []string
	for _, c := range contribs {
		if c.Points <= 0 {
			continue
		}
		label := string(c.Signal)
		if c.Raw != "" {
			label += " (" + c.Raw + ")"
		}
		out = append(out, label)
		if len(out) == 3 {
			break
		}
	}
	return out
}

func findingToDTO(f findings.Finding) findingDTO {
	dto := findingDTO{
		RuleID:        f.RuleID,
		Gate:          string(f.Gate),
		Severity:      string(f.Severity),
		Level:         string(f.Level),
		Identifier:    f.Identifier,
		Title:         f.Title,
		Message:       f.Message,
		Suppressed:    f.Suppressed,
		Justification: f.Justification,
	}
	if text, uri, ok := findings.RuleHelp(f.RuleID); ok {
		dto.Remediation = text
		dto.HelpURI = uri
	}
	return dto
}

// guidanceFor renders status-specific developer guidance for a quarantine item.
func guidanceFor(req approvals.Request) string {
	switch req.Status {
	case approvals.StatusPending:
		return "Pending review. Ask an approver on your team to approve or deny this break-glass request in the admin approvals queue."
	case approvals.StatusApproved:
		return "Approved (break-glass grant active). Pulls are temporarily allowed until the grant expires, after which the item is re-quarantined."
	case approvals.StatusDenied:
		return "Denied. The block stands; resolve the underlying issue (upgrade, replace, or remediate) rather than retrying."
	case approvals.StatusExpired:
		return "Expired. Open a fresh request if you still need this package."
	default:
		return "Ask an approver on your team to review this item in the admin approvals queue."
	}
}

// fmtTime renders a timestamp as RFC3339, or "" when zero.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// hostOf extracts the host[:port] from a proxy base URL, for snippet rendering.
func hostOf(base string) string {
	if u, err := url.Parse(strings.TrimSpace(base)); err == nil && u.Host != "" {
		return u.Host
	}
	// Fall back to a best-effort strip of the scheme.
	b := strings.TrimSpace(base)
	b = strings.TrimPrefix(strings.TrimPrefix(b, "https://"), "http://")
	if i := strings.IndexAny(b, "/"); i >= 0 {
		b = b[:i]
	}
	return b
}

// urlQueryEscape percent-encodes a value for safe inclusion in a query string.
func urlQueryEscape(v string) string { return url.QueryEscape(v) }
