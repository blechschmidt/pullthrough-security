package main

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// runDoctorOnline runs the full live diagnostic against a running proxy. Every
// check degrades gracefully: a subsystem that is disabled, or an endpoint that a
// given proxy version does not expose (404), is reported as skipped/ok rather
// than aborting the run, so one missing surface never masks the rest of the
// report.
func runDoctorOnline(g globalFlags, opts doctorOptions) (*doctorReport, error) {
	c, err := newClient(g)
	if err != nil {
		return nil, err
	}
	d := &onlineDoctor{
		c: c,
		report: &doctorReport{
			Mode:        "online",
			Target:      c.baseURL,
			GeneratedAt: time.Now().UTC(),
		},
		backendArgs: opts.backendArgs,
	}

	// Reachability first: its result tells the operator whether a cascade of
	// subsequent failures is really just "the proxy is down".
	d.checkReachability()
	d.checkConfigValidate()
	d.checkConfigDrift()
	d.checkUpstreams()
	d.checkKeysAndCerts()
	d.checkSecrets()
	d.checkCacheIntegrity()
	d.checkLeaderElection()
	d.checkLockdown()
	d.checkGateCoverage()

	return d.report, nil
}

// onlineDoctor threads the HTTP client and accumulating report through the live
// checks, carrying the reachability verdict so dependent checks can explain a
// failure as a downstream effect of an unreachable proxy.
type onlineDoctor struct {
	c           *client
	report      *doctorReport
	backendArgs []string
	healthOK    bool
}

// fetchHint classifies an admin-API error for a check: a 404 means the endpoint
// is absent on this proxy (treated as "subsystem not present"), an auth failure
// is actionable, and anything else is surfaced verbatim. ok reports whether the
// error is a benign 404.
func fetchHint(err error) (severity, msg string, notFound bool) {
	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusNotFound:
			return sevSkip, "endpoint not available on this proxy version", true
		case http.StatusUnauthorized, http.StatusForbidden:
			return sevError, "admin API rejected the request — pass a read-capable --token or set PULLTHROUGH_TOKEN", false
		default:
			return sevError, ae.Error(), false
		}
	}
	return sevError, err.Error(), false
}

// --- individual online checks ----------------------------------------------

func (d *onlineDoctor) checkReachability() {
	health := d.c.probe("GET /healthz", d.c.gatewayURL("healthz"))
	ready := d.c.probe("GET /readyz", d.c.gatewayURL("readyz"))

	res := checkResult{Name: "proxy reachability", Category: "connectivity"}
	switch {
	case health.Verdict == "UNREACHABLE":
		res.Severity = sevError
		res.Summary = "proxy is not reachable"
		res.Details = []string{"/healthz: " + health.Detail}
		res.Remediation = "confirm the proxy is running and --url is correct (try --insecure for a self-signed dev proxy)"
	case health.Verdict == "AUTH":
		// Health endpoints are normally unauthenticated; an auth verdict still
		// proves the network path works.
		d.healthOK = true
		res.Severity = sevWarn
		res.Summary = "health endpoint requires authentication"
		res.Details = []string{fmt.Sprintf("/healthz: HTTP %d", health.Status)}
	case !health.ok():
		res.Severity = sevError
		res.Summary = fmt.Sprintf("health check failed (HTTP %d)", health.Status)
		res.Details = []string{"/healthz: " + health.Detail}
		res.Remediation = "inspect the proxy logs; the process is up but reporting unhealthy"
	case !ready.ok():
		d.healthOK = true
		res.Severity = sevWarn
		res.Summary = "proxy is live but not ready"
		res.Details = []string{fmt.Sprintf("/readyz: HTTP %d %s", ready.Status, ready.Detail)}
		res.Remediation = "the proxy is still warming up or a dependency is unavailable; re-check shortly"
	default:
		d.healthOK = true
		res.Severity = sevOK
		res.Summary = "live and ready"
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkConfigValidate() {
	res := checkResult{Name: "configuration validity", Category: "config"}
	var rep configReport
	if err := d.c.getJSON(d.c.adminURL("api/config/validate", nil), &rep); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not validate the running config"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}
	for _, is := range cappedIssues(rep.Issues, 8) {
		loc := is.Path
		if loc == "" {
			loc = "(document)"
		}
		res.Details = append(res.Details, fmt.Sprintf("[%s] %s: %s", is.Severity, loc, is.Message))
	}
	switch {
	case rep.Errors > 0:
		res.Severity = sevError
		res.Summary = fmt.Sprintf("%d error(s), %d warning(s)", rep.Errors, rep.Warnings)
		res.Remediation = "fix the fields above; run `ptctl config validate` for the full report"
	case rep.Warnings > 0:
		res.Severity = sevWarn
		res.Summary = fmt.Sprintf("%d warning(s)", rep.Warnings)
		res.Remediation = "review the flagged settings; they are loadable but likely misconfigured"
	default:
		res.Severity = sevOK
		res.Summary = "valid, no issues"
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkConfigDrift() {
	res := checkResult{Name: "configuration drift", Category: "config"}
	var st configDrift
	if err := d.c.getJSON(d.c.adminURL("api/config/drift", nil), &st); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not check config drift"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}
	path := st.Path
	if path == "" {
		res.Severity = sevOK
		res.Summary = "no config file (defaults + environment)"
		d.report.add(res)
		return
	}
	switch {
	case st.Error != "":
		res.Severity = sevError
		res.Summary = "on-disk config no longer loads"
		res.Details = []string{st.Error}
		res.Remediation = "repair " + path + " before the next reload/restart, or the proxy will fail to start"
	case st.Drifted:
		res.Severity = sevWarn
		res.Summary = "on-disk config differs from the running process"
		res.Details = []string{
			"running: " + short(st.RunningConfigHash),
			"on-disk: " + short(st.CurrentConfigHash),
		}
		res.Remediation = "reload/restart to apply " + path + ", or revert the on-disk change"
	default:
		res.Severity = sevOK
		res.Summary = "in sync (" + short(st.RunningConfigHash) + ")"
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkUpstreams() {
	res := checkResult{Name: "upstream reachability", Category: "connectivity"}
	backends, derr := resolveBackends(d.c, d.backendArgs)
	if derr != nil {
		res.Severity = sevSkip
		res.Summary = "could not enumerate backends"
		res.Details = []string{firstLine(derr.Error())}
		d.report.add(res)
		return
	}
	var unreachable, authFail, okCount int
	for _, b := range backends {
		path, _ := probePath(b)
		r := d.c.probe(fmt.Sprintf("%s (%s)", b.Name, orUnknown(b.Type)), d.c.gatewayURL(path))
		switch r.Verdict {
		case "OK":
			okCount++
		case "AUTH":
			authFail++
			res.Details = append(res.Details, fmt.Sprintf("%s: auth required (HTTP %d)", b.Name, r.Status))
		default: // UNREACHABLE | ERROR
			unreachable++
			res.Details = append(res.Details, fmt.Sprintf("%s: %s %s", b.Name, r.Verdict, r.Detail))
		}
	}
	switch {
	case unreachable > 0:
		res.Severity = sevError
		res.Summary = fmt.Sprintf("%d/%d backend(s) unreachable", unreachable, len(backends))
		res.Remediation = "check the proxy's egress/network path and upstream URLs for the failing backends"
	case authFail > 0:
		res.Severity = sevWarn
		res.Summary = fmt.Sprintf("%d/%d backend(s) require auth with this token", authFail, len(backends))
		res.Remediation = "this may be expected; supply a gateway-capable token to probe them fully"
	default:
		res.Severity = sevOK
		res.Summary = fmt.Sprintf("all %d backend(s) reachable", okCount)
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkKeysAndCerts() {
	res := checkResult{Name: "keys & certificate expiry", Category: "crypto"}
	var st keysStatusBody
	if err := d.c.getJSON(d.c.adminURL("api/keys/status", nil), &st); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not read key/cert expiry status"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}
	if !st.Enabled {
		res.Severity = sevSkip
		res.Summary = "expiry monitoring disabled"
		res.Remediation = "enable keyRotation to monitor signing keys, the cache KEK, upstream credentials, and pinned certificates for expiry"
		d.report.add(res)
		return
	}
	for _, m := range st.Materials {
		if m.Status == "warning" || m.Status == "critical" || m.Status == "expired" {
			exp := "no expiry"
			if m.HasExpiry {
				exp = humanizeRemaining(m.SecondsRemaining)
			}
			res.Details = append(res.Details, fmt.Sprintf("%s (%s): %s — %s", m.ID, m.Kind, strings.ToUpper(m.Status), exp))
		}
	}
	cnt := st.Counts
	switch {
	case cnt.Expired > 0:
		res.Severity = sevError
		res.Summary = fmt.Sprintf("%d material(s) expired", cnt.Expired)
		res.Remediation = "rotate the expired material(s): `ptctl keys rotate -material <id>` (or renew manually)"
	case cnt.Critical > 0:
		res.Severity = sevError
		res.Summary = fmt.Sprintf("%d material(s) expiring imminently", cnt.Critical)
		res.Remediation = "rotate/renew before expiry: `ptctl keys status` for detail"
	case cnt.Warning > 0:
		res.Severity = sevWarn
		res.Summary = fmt.Sprintf("%d material(s) approaching expiry", cnt.Warning)
		res.Remediation = "schedule rotation/renewal: `ptctl keys status` for detail"
	default:
		res.Severity = sevOK
		res.Summary = fmt.Sprintf("all %d material(s) healthy", cnt.Total)
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkSecrets() {
	// There is no admin endpoint for the secrets provider; the dependable online
	// signal is that the proxy is running, which proves every secretRef resolved
	// at startup (resolution failure aborts boot). Offline mode (--config) performs
	// an active resolution against the configured providers.
	res := checkResult{Name: "secrets-provider resolution", Category: "config"}
	if !d.healthOK {
		res.Severity = sevSkip
		res.Summary = "proxy not reachable; cannot infer secret resolution"
		d.report.add(res)
		return
	}
	res.Severity = sevOK
	res.Summary = "upstream credentials & API keys resolved at startup"
	res.Details = []string{"run `ptctl doctor --config <file>` to actively re-resolve every secretRef"}
	d.report.add(res)
}

func (d *onlineDoctor) checkCacheIntegrity() {
	res := checkResult{Name: "cache integrity", Category: "cache"}
	var st integrityStatus
	if err := d.c.getJSON(d.c.adminURL("api/integrity", nil), &st); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not read cache integrity status"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}
	if !st.Enabled {
		res.Severity = sevSkip
		res.Summary = "read-time integrity verification disabled"
		res.Remediation = "enable cache integrity verification to detect at-rest corruption/tampering"
		d.report.add(res)
		return
	}
	corrupt := st.Metrics.Failures
	if st.LastScan != nil {
		res.Details = append(res.Details, fmt.Sprintf("last scan: %d scanned, %d verified, %d corrupted",
			st.LastScan.Scanned, st.LastScan.Verified, st.LastScan.Corrupted))
		if st.LastScan.Corrupted > int(corrupt) {
			corrupt = int64(st.LastScan.Corrupted)
		}
	}
	res.Details = append(res.Details, fmt.Sprintf("%d verifications, %d failures", st.Metrics.Verifications, st.Metrics.Failures))
	if corrupt > 0 {
		res.Severity = sevError
		res.Summary = fmt.Sprintf("%d integrity failure(s) detected", corrupt)
		res.Remediation = "corrupted blobs were quarantined; investigate the backing store and run `POST api/integrity/scan`"
	} else {
		res.Severity = sevOK
		res.Summary = fmt.Sprintf("no corruption across %d verification(s)", st.Metrics.Verifications)
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkLeaderElection() {
	res := checkResult{Name: "leader election", Category: "coordination"}
	var st coordinationStatus
	if err := d.c.getJSON(d.c.adminURL("api/coordination", nil), &st); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not read coordination status"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}
	if !st.Enabled {
		res.Severity = sevOK
		res.Summary = "single-node (distributed coordination disabled)"
		d.report.add(res)
		return
	}
	var stuck int
	for _, lh := range st.Leaseholders {
		if lh.Expired {
			stuck++
			res.Details = append(res.Details, fmt.Sprintf("%s: lease expired (holder %s)", lh.Job, orNone(lh.Holder)))
		} else if !lh.Held {
			res.Details = append(res.Details, fmt.Sprintf("%s: no leaseholder", lh.Job))
		}
	}
	if stuck > 0 {
		res.Severity = sevWarn
		res.Summary = fmt.Sprintf("%s: %d expired lease(s)", st.Mode, stuck)
		res.Remediation = "a stuck/expired lease can leave a scheduled job without a leader; check replica health & clock skew"
	} else {
		res.Severity = sevOK
		res.Summary = fmt.Sprintf("%s, %d job(s) coordinated", st.Mode, len(st.Jobs))
	}
	d.report.add(res)
}

func (d *onlineDoctor) checkLockdown() {
	res := checkResult{Name: "kill-switch / lockdown", Category: "incident"}
	var resp lockdownStatusResponse
	if err := d.c.getJSON(d.c.adminURL("api/lockdown", nil), &resp); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not read lockdown state"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}
	st := resp.Status
	if !st.Active {
		res.Severity = sevOK
		res.Summary = "no active lockdown"
		d.report.add(res)
		return
	}
	// An active lockdown is an intentional incident-response posture, not a fault,
	// but the operator must know the proxy is degraded by design.
	res.Severity = sevWarn
	res.Summary = "LOCKDOWN ACTIVE: " + strings.ToUpper(st.Mode)
	res.Details = []string{"incident: " + st.IncidentID, "reason: " + st.Reason}
	if !st.ExpiresAt.IsZero() {
		res.Details = append(res.Details, "expires: "+st.ExpiresAt.Format(time.RFC3339))
	}
	if len(st.Targets) > 0 {
		res.Details = append(res.Details, fmt.Sprintf("%d coordinate(s) denied everywhere", len(st.Targets)))
	}
	res.Remediation = "clear it once the incident is resolved: `ptctl lockdown clear -reason <...>`"
	d.report.add(res)
}

func (d *onlineDoctor) checkGateCoverage() {
	res := checkResult{Name: "gate-enablement coverage", Category: "policy"}
	var ov doctorOverview
	if err := d.c.getJSON(d.c.adminURL("api/overview", nil), &ov); err != nil {
		sev, msg, _ := fetchHint(err)
		res.Severity, res.Summary = sev, "could not read gate coverage"
		res.Details = []string{msg}
		d.report.add(res)
		return
	}

	// Collect the ecosystems the proxy actually fronts.
	ecos := map[string]struct{}{}
	for _, u := range ov.Info.Upstreams {
		if t := strings.ToLower(u.Type); t != "" {
			ecos[ecosystemLabel(t)] = struct{}{}
		}
	}

	// Enabled admission gates reported by the overview snapshot. The overview is
	// the single always-available surface; it exposes the core gate flags without
	// requiring a fan-out across every per-gate endpoint.
	var enabled []string
	if ov.Info.ScanningEnabled {
		enabled = append(enabled, "commit-scan")
	}
	if ov.Info.VulnEnabled {
		enabled = append(enabled, "vuln")
	}
	if ov.Info.LicenseEnabled {
		enabled = append(enabled, "license")
	}
	if ov.Info.ProvenanceEnabled {
		enabled = append(enabled, "provenance")
	}

	res.Details = append(res.Details, "ecosystems: "+joinSorted(ecos))
	res.Details = append(res.Details, "gates enabled: "+orNone(strings.Join(enabled, ", ")))

	switch {
	case len(ecos) > 0 && len(enabled) == 0:
		res.Severity = sevWarn
		res.Summary = "no admission gates enabled"
		res.Remediation = "artifacts are proxied without security gating; enable at least vulnerability scanning"
	case !ov.Info.VulnEnabled:
		res.Severity = sevWarn
		res.Summary = fmt.Sprintf("%d gate(s) enabled; vulnerability scanning off", len(enabled))
		res.Remediation = "enable vulnerability scanning for baseline supply-chain coverage"
	default:
		res.Severity = sevOK
		res.Summary = fmt.Sprintf("%d gate(s) enabled across %d ecosystem(s)", len(enabled), len(ecos))
	}
	d.report.add(res)
}

// --- local admin-response shapes (fields the doctor renders) ----------------

// integrityStatus mirrors admin.integrityStatusResponse (Task 107).
type integrityStatus struct {
	Enabled       bool `json:"enabled"`
	VerifyOnServe bool `json:"verifyOnServe"`
	Metrics       struct {
		// cache.IntegrityMetricsSnapshot has no json tags; decode the Go field names.
		Verifications int64 `json:"Verifications"`
		Failures      int64 `json:"Failures"`
	} `json:"metrics"`
	LastScan *struct {
		Scanned   int `json:"scanned"`
		Verified  int `json:"verified"`
		Corrupted int `json:"corrupted"`
	} `json:"lastScan"`
}

// coordinationStatus mirrors admin.coordinationResponse (Task 56).
type coordinationStatus struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	NodeID  string `json:"nodeId"`
	Jobs    []struct {
		Job      string `json:"job"`
		IsLeader bool   `json:"isLeader"`
	} `json:"jobs"`
	Leaseholders []struct {
		Job     string `json:"job"`
		Held    bool   `json:"held"`
		Holder  string `json:"holder"`
		Expired bool   `json:"expired"`
	} `json:"leaseholders"`
}

// doctorOverview mirrors the subset of admin.overviewResponse the gate-coverage
// check reads: the core gate-enablement flags and the fronted upstreams.
type doctorOverview struct {
	Info struct {
		ScanningEnabled   bool `json:"scanningEnabled"`
		VulnEnabled       bool `json:"vulnEnabled"`
		LicenseEnabled    bool `json:"licenseEnabled"`
		ProvenanceEnabled bool `json:"provenanceEnabled"`
		Upstreams         []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"upstreams"`
	} `json:"info"`
}

// --- small helpers ----------------------------------------------------------

func cappedIssues(in []configIssue, n int) []configIssue {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

func joinSorted(set map[string]struct{}) string {
	if len(set) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
