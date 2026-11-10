package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- pure helpers -----------------------------------------------------------

func TestSevRankOrdering(t *testing.T) {
	if !(sevRank(sevError) > sevRank(sevWarn) &&
		sevRank(sevWarn) > sevRank(sevOK) &&
		sevRank(sevOK) > sevRank(sevSkip)) {
		t.Fatalf("severity ranking is not error>warn>ok>skip")
	}
}

func TestEcosystemLabelFolding(t *testing.T) {
	cases := map[string]string{
		"deb": "apt", "apt": "apt", "rpm": "yum", "yum": "yum",
		"pypi": "pip", "pip": "pip", "oci": "docker", "docker": "docker",
		"pub": "dart", "huggingface": "huggingface", "cargo": "cargo",
	}
	for in, want := range cases {
		if got := ecosystemLabel(in); got != want {
			t.Errorf("ecosystemLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReportFinalizeSortsAndTallies(t *testing.T) {
	r := &doctorReport{Checks: []checkResult{
		{Name: "a", Severity: sevOK},
		{Name: "b", Severity: sevError},
		{Name: "c", Severity: sevWarn},
		{Name: "d", Severity: sevSkip},
		{Name: "e", Severity: sevError},
	}}
	r.finalize(false)
	// Errors must sort to the front, stable within a severity.
	if r.Checks[0].Name != "b" || r.Checks[1].Name != "e" {
		t.Errorf("errors did not sort first (stable): %+v", r.Checks)
	}
	if r.Summary.Error != 2 || r.Summary.Warning != 1 || r.Summary.Skipped != 1 || r.Summary.OK != 1 {
		t.Errorf("tally wrong: %+v", r.Summary)
	}
	if r.Summary.Healthy {
		t.Error("report with errors must not be healthy")
	}
}

func TestReportFinalizeWarnAsError(t *testing.T) {
	r := &doctorReport{Checks: []checkResult{{Severity: sevWarn}, {Severity: sevOK}}}
	r.finalize(false)
	if !r.Summary.Healthy {
		t.Error("warnings alone should be healthy without --warn-as-error")
	}
	r.finalize(true)
	if r.Summary.Healthy {
		t.Error("warnings must fail under --warn-as-error")
	}
}

// --- fake proxy for the online diagnostic -----------------------------------

// doctorScenario toggles the fake proxy's responses so a single builder can
// stand up healthy, degraded, and failing deployments.
type doctorScenario struct {
	configErrors   int
	configWarnings int
	drifted        bool
	brokenBackend  bool // advertise a backend whose gateway path 5xxs
	keysExpired    int
	keysWarning    int
	cacheFailures  int64
	lockdownActive bool
	vulnEnabled    bool
}

func fakeDoctorProxy(t *testing.T, sc doctorScenario) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	// Overview: backends + gate flags.
	upstreams := []map[string]string{
		{"name": "npm", "type": "npm", "url": "https://registry.npmjs.org"},
		{"name": "central", "type": "maven", "url": "https://repo1.maven.org/maven2"},
	}
	if sc.brokenBackend {
		upstreams = append(upstreams, map[string]string{"name": "broken", "type": "go", "url": "https://example.invalid"})
	}
	mux.HandleFunc("/admin/api/overview", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{
			"info": map[string]any{
				"version":           "test",
				"scanningEnabled":   true,
				"vulnEnabled":       sc.vulnEnabled,
				"licenseEnabled":    true,
				"provenanceEnabled": true,
				"upstreams":         upstreams,
			},
			"backends": []string{"npm", "central"},
		})
	})

	// Gateway probes.
	mux.HandleFunc("/v1/npm/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/v1/central/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	mux.HandleFunc("/v1/broken/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) })

	mux.HandleFunc("/admin/api/config/validate", func(w http.ResponseWriter, r *http.Request) {
		issues := []map[string]string{}
		for i := 0; i < sc.configErrors; i++ {
			issues = append(issues, map[string]string{"path": "vulnerabilities.enabled", "message": "bad", "severity": "error"})
		}
		for i := 0; i < sc.configWarnings; i++ {
			issues = append(issues, map[string]string{"path": "license.action", "message": "noop", "severity": "warning"})
		}
		j(w, map[string]any{
			"ok": sc.configErrors == 0, "errors": sc.configErrors, "warnings": sc.configWarnings,
			"issues": issues, "fingerprint": "abc123def456",
		})
	})

	mux.HandleFunc("/admin/api/config/drift", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{
			"path": "/etc/pullthrough/config.yaml", "drifted": sc.drifted,
			"runningConfigHash": "aaaaaaaaaaaa1111", "currentConfigHash": "bbbbbbbbbbbb2222",
		})
	})

	mux.HandleFunc("/admin/api/keys/status", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{
			"enabled": true, "warnThreshold": "720h", "criticalThreshold": "168h",
			"counts": map[string]int{
				"total": 3, "ok": 3 - sc.keysExpired - sc.keysWarning,
				"warning": sc.keysWarning, "critical": 0, "expired": sc.keysExpired, "unknown": 0,
			},
			"materials": []map[string]any{
				{"id": "tls.upstream.github", "kind": "tls-cert", "status": keyStatusWord(sc), "hasExpiry": true, "secondsRemaining": 3600.0},
			},
		})
	})

	mux.HandleFunc("/admin/api/integrity", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{
			"enabled": true, "verifyOnServe": true,
			"metrics": map[string]int64{"Verifications": 1000, "Failures": sc.cacheFailures},
		})
	})

	mux.HandleFunc("/admin/api/coordination", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"enabled": false, "leaseholders": []any{}})
	})

	mux.HandleFunc("/admin/api/lockdown", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"status": map[string]any{
			"active": sc.lockdownActive, "mode": "freeze", "incidentId": "INC-1", "reason": "test",
		}})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func keyStatusWord(sc doctorScenario) string {
	switch {
	case sc.keysExpired > 0:
		return "expired"
	case sc.keysWarning > 0:
		return "warning"
	default:
		return "ok"
	}
}

// findCheck returns the result for a named check, or fails the test.
func findCheck(t *testing.T, r *doctorReport, name string) checkResult {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in report; have %d checks", name, len(r.Checks))
	return checkResult{}
}

func TestDoctorOnlineHealthy(t *testing.T) {
	srv := fakeDoctorProxy(t, doctorScenario{vulnEnabled: true})
	rep, err := runDoctorOnline(globalFlags{url: srv.URL}, doctorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rep.finalize(false)
	if !rep.Summary.Healthy {
		t.Fatalf("expected healthy, got %+v\n%v", rep.Summary, rep.Checks)
	}
	if rep.Summary.Error != 0 || rep.Summary.Warning != 0 {
		t.Errorf("healthy run should have no errors/warnings: %+v", rep.Summary)
	}
	if findCheck(t, rep, "proxy reachability").Severity != sevOK {
		t.Error("reachability should be ok")
	}
	if findCheck(t, rep, "upstream reachability").Severity != sevOK {
		t.Error("upstreams should be ok (404 counts as reachable)")
	}
	if findCheck(t, rep, "leader election").Severity != sevOK {
		t.Error("single-node coordination should be ok")
	}
}

func TestDoctorOnlineDegraded(t *testing.T) {
	srv := fakeDoctorProxy(t, doctorScenario{
		vulnEnabled: true, configWarnings: 1, drifted: true, keysWarning: 1, lockdownActive: true,
	})
	rep, err := runDoctorOnline(globalFlags{url: srv.URL}, doctorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rep.finalize(false)
	if rep.Summary.Error != 0 {
		t.Errorf("degraded run should have no errors: %+v", rep.Summary)
	}
	if rep.Summary.Warning < 4 {
		t.Errorf("expected at least 4 warnings (config, drift, keys, lockdown), got %d", rep.Summary.Warning)
	}
	if !rep.Summary.Healthy {
		t.Error("warnings alone should be healthy without --warn-as-error")
	}
	// --warn-as-error flips the verdict.
	rep.finalize(true)
	if rep.Summary.Healthy {
		t.Error("degraded run must be unhealthy under --warn-as-error")
	}
	if findCheck(t, rep, "configuration drift").Severity != sevWarn {
		t.Error("drift should warn")
	}
	if findCheck(t, rep, "kill-switch / lockdown").Severity != sevWarn {
		t.Error("active lockdown should warn")
	}
}

func TestDoctorOnlineFailing(t *testing.T) {
	srv := fakeDoctorProxy(t, doctorScenario{
		vulnEnabled: false, configErrors: 2, brokenBackend: true, keysExpired: 1, cacheFailures: 3,
	})
	rep, err := runDoctorOnline(globalFlags{url: srv.URL}, doctorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rep.finalize(false)
	if rep.Summary.Healthy {
		t.Fatalf("expected unhealthy, got %+v", rep.Summary)
	}
	if findCheck(t, rep, "configuration validity").Severity != sevError {
		t.Error("config errors should be error severity")
	}
	if findCheck(t, rep, "upstream reachability").Severity != sevError {
		t.Error("a 5xx backend should be error severity")
	}
	if findCheck(t, rep, "keys & certificate expiry").Severity != sevError {
		t.Error("an expired key should be error severity")
	}
	if findCheck(t, rep, "cache integrity").Severity != sevError {
		t.Error("cache corruption should be error severity")
	}
	if findCheck(t, rep, "gate-enablement coverage").Severity != sevWarn {
		t.Error("vuln scanning off should warn on gate coverage")
	}
	// Prioritized output: the first check must be an error.
	if rep.Checks[0].Severity != sevError {
		t.Errorf("most-severe finding should sort first, got %q", rep.Checks[0].Severity)
	}
}

func TestDoctorOnlineUnreachable(t *testing.T) {
	// A URL with no listener: reachability must be an error and the report unhealthy.
	rep, err := runDoctorOnline(globalFlags{url: "http://127.0.0.1:1"}, doctorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rep.finalize(false)
	if findCheck(t, rep, "proxy reachability").Severity != sevError {
		t.Error("an unreachable proxy should be error severity")
	}
	if findCheck(t, rep, "secrets-provider resolution").Severity != sevSkip {
		t.Error("secrets check should skip when the proxy is unreachable")
	}
	if rep.Summary.Healthy {
		t.Error("unreachable proxy must be unhealthy")
	}
}

// --- offline mode -----------------------------------------------------------

func TestDoctorOfflineValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := "" +
		"upstreams:\n" +
		"  npm:\n" +
		"    type: npm\n" +
		"    url: https://registry.npmjs.org\n" +
		"vulnerabilities:\n" +
		"  enabled: true\n" +
		"  failSeverity: high\n"
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := runDoctorOffline(path, 0)
	rep.finalize(false)
	if rep.Mode != "offline" {
		t.Errorf("mode = %q", rep.Mode)
	}
	if findCheck(t, rep, "configuration validity").Severity == sevError {
		t.Errorf("valid config should not be an error: %+v", findCheck(t, rep, "configuration validity"))
	}
	if findCheck(t, rep, "secrets-provider resolution").Severity != sevOK {
		t.Error("literal/absent secrets should resolve ok")
	}
	// Live-only checks are skipped in offline mode.
	for _, name := range []string{"proxy reachability", "cache integrity", "leader election", "kill-switch / lockdown"} {
		if findCheck(t, rep, name).Severity != sevSkip {
			t.Errorf("%q should be skipped offline", name)
		}
	}
}

func TestDoctorOfflineInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("this: : : not valid yaml\n  - broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := runDoctorOffline(path, 0)
	rep.finalize(false)
	if findCheck(t, rep, "configuration validity").Severity != sevError {
		t.Error("unparseable config should be an error")
	}
	if rep.Summary.Healthy {
		t.Error("invalid config must be unhealthy")
	}
}
