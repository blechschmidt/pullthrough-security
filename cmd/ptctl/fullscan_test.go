package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// fakeVerdicts judges the artifact under /evil malicious and the rest benign.
type fakeVerdicts struct{}

func (fakeVerdicts) Signature() string         { return "fake-model|p3|s1" }
func (fakeVerdicts) Load() (int64, int64, int) { return 0, 0, 4 }
func (fakeVerdicts) Scan(_ context.Context, a fullscan.Artifact, _ fullscan.ScanOptions) (fullscan.Reading, error) {
	r := fullscan.Reading{Kind: fullscan.ReadingVerdict, Disposition: "benign", Fresh: true, Cost: 0.25, Signature: "fake-model|p3|s1"}
	if strings.HasPrefix(a.Path, "/evil") {
		r.Disposition, r.Refused, r.Action, r.Evicted = "malicious", true, "quarantine", true
	}
	return r, nil
}

// twoObjects is a cache listing of two objects with fill metadata.
type twoObjects struct{}

func (twoObjects) Entries(context.Context) ([]cache.Stat, error) {
	meta := func(path string) map[string]string {
		return map[string]string{cache.MetaFillUpstream: "npm", cache.MetaFillPath: path}
	}
	return []cache.Stat{
		{Key: "npm:evil", Size: 10, ModTime: time.Now().Add(-time.Hour), Metadata: meta("/evil/-/evil-1.0.0.tgz")},
		{Key: "npm:good", Size: 10, ModTime: time.Now(), Metadata: meta("/good/-/good-1.0.0.tgz")},
	}, nil
}

func fullScanFixture(t *testing.T) []string {
	t.Helper()
	fs, err := fullscan.New(fullscan.Options{Dir: t.TempDir(), Upstreams: []string{"npm"}, DailyUSD: 10, MonthlyUSD: 100})
	if err != nil {
		t.Fatal(err)
	}
	fs.Attach(fakeVerdicts{}, twoObjects{})
	fs.Start(context.Background())
	t.Cleanup(func() { _ = fs.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if u, err := fs.UpstreamStatus("npm"); err == nil && u.Scanned == 1 && u.Malicious == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	const token = "ptctl-fullscan-test-token-0123456789"
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, FullScan: fs, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Setenv("PULLTHROUGH_STEPUP_TOKEN", "")
	return []string{"--url", ts.URL, "--token", token}
}

func TestPtctlFullScan(t *testing.T) {
	g := fullScanFixture(t)
	out, err := runReposCmd(t, fullScanStatus, g...)
	if err != nil || !strings.Contains(out, "Full scan: 1 upstream(s)") || !strings.Contains(out, "$0.50 of $10.00") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Total: 1 cached, 1 scanned (1 benign, 0 suspicious, 1 malicious)") || !strings.Contains(out, "1 quarantined") {
		t.Errorf("totals: %s", out)
	}
	out, err = runReposCmd(t, fullScanStatus, append([]string{"--upstream", "npm"}, g...)...)
	if err != nil || !strings.Contains(out, "1 evicted by the action ladder") || !strings.Contains(out, "2 with a model call") {
		t.Fatalf("status --upstream: %v\n%s", err, out)
	}
	out, err = runReposCmd(t, fullScanStatus, append([]string{"--json"}, g...)...)
	var st fullscan.Status
	if err != nil || json.Unmarshal([]byte(out), &st) != nil || st.Totals.Malicious != 1 || st.Budget.Daily.SpentUSD != 0.5 {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
	if _, err := runReposCmd(t, fullScanStatus, append([]string{"--upstream", "pypi"}, g...)...); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("an upstream outside the scope: %v", err)
	}

	out, err = runReposCmd(t, fullScanPause, append([]string{"--upstream", "npm", "--reason", "budget review"}, g...)...)
	if err != nil || !strings.Contains(out, "paused: npm") {
		t.Fatalf("pause: %v %s", err, out)
	}
	out, _ = runReposCmd(t, fullScanStatus, g...)
	if !strings.Contains(out, "npm (paused)") {
		t.Errorf("the pause is not shown: %s", out)
	}
	if out, err := runReposCmd(t, fullScanResume, g...); err != nil || !strings.Contains(out, "every upstream") {
		t.Fatalf("resume: %v %s", err, out)
	}
	if _, err := runReposCmd(t, fullScanRescan, append([]string{"--path", "/good/-/good-1.0.0.tgz"}, g...)...); err == nil {
		t.Error("a re-scan by path without an upstream was sent")
	}
	if _, err := runReposCmd(t, fullScanRescan, append([]string{"--filter", "bogus"}, g...)...); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("an unknown filter: %v", err)
	}
	out, err = runReposCmd(t, fullScanRescan, append([]string{"--upstream", "npm", "--filter", "benign"}, g...)...)
	if err != nil || !strings.Contains(out, "re-scan requested (#1)") || !strings.Contains(out, "benign artifacts") {
		t.Fatalf("rescan: %v %s", err, out)
	}
}

func TestPtctlFullScanDisabled(t *testing.T) {
	const token = "ptctl-fullscan-test-token-0123456789"
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	out, err := runReposCmd(t, fullScanStatus, "--url", ts.URL, "--token", token)
	if err != nil || !strings.Contains(out, "not enabled") {
		t.Fatalf("disabled: %v %s", err, out)
	}
	if _, err := runReposCmd(t, fullScanPause, "--url", ts.URL, "--token", token); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("pause without a full scan: %v", err)
	}
}
