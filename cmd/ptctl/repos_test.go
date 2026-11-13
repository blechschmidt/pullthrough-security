package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
)

func reposFixture(t *testing.T) []string {
	t.Helper()
	t.Setenv("PULLTHROUGH_TENANT", "")
	svc, err := repos.New(context.Background(), repos.Config{
		Repos: []repos.Repo{{Name: "widgets", URL: "https://git.example/acme/widgets.git", Tenant: "team-a"}},
	}, repos.Options{Store: repos.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	const token = "ptctl-repos-test-token-0123456789"
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, Repos: svc, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return []string{"--url", ts.URL, "--token", token}
}

func runReposCmd(t *testing.T, fn func([]string, io.Writer) error, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := fn(args, &out)
	return out.String(), err
}

func TestPtctlRepos(t *testing.T) {
	g := reposFixture(t)
	out, err := runReposCmd(t, reposAdd, append([]string{"tools", "https://git.example/acme/tools.git", "--owner", "team-a",
		"--credentials-ref", "env://TOOLS_TOKEN", "--lockfile", "go.*", "--upstream", "go=gomod"}, g...)...)
	if err != nil || !strings.Contains(out, "registered tools") {
		t.Fatalf("add: %v %s", err, out)
	}
	if _, err := runReposCmd(t, reposAdd, append([]string{"bad", "https://git.example/x.git", "--upstream", "go"}, g...)...); err == nil {
		t.Fatal("a malformed --upstream was accepted")
	}
	out, err = runReposCmd(t, reposList, g...)
	if err != nil || !strings.Contains(out, "widgets") || !strings.Contains(out, "tools") {
		t.Fatalf("list: %v %s", err, out)
	}
	out, err = runReposCmd(t, reposList, append([]string{"--tenant", "team-b"}, g...)...)
	if err != nil || strings.Contains(out, "widgets") {
		t.Fatalf("list --tenant team-b: %v %s", err, out)
	}
	out, err = runReposCmd(t, reposShow, append([]string{"tools"}, g...)...)
	if err != nil || !strings.Contains(out, "env://TOOLS_TOKEN") || !strings.Contains(out, "go.*") {
		t.Fatalf("show: %v %s", err, out)
	}
	out, err = runReposCmd(t, reposTags, append([]string{"widgets"}, g...)...)
	if err != nil || !strings.Contains(out, "TAG") {
		t.Fatalf("tags: %v %s", err, out)
	}
	out, err = runReposCmd(t, reposVerify, append([]string{"widgets"}, g...)...)
	if err != nil || !strings.Contains(out, "verifies") {
		t.Fatalf("verify: %v %s", err, out)
	}
	out, err = runReposCmd(t, reposLookup, append([]string{"npm/left-pad@1.0.0"}, g...)...)
	if err != nil || !strings.Contains(out, "no release contains it") {
		t.Fatalf("lookup: %v %s", err, out)
	}
	if _, err := runReposCmd(t, reposLookup, g...); err == nil {
		t.Fatal("lookup without a coordinate")
	}
	out, err = runReposCmd(t, reposCommit, append([]string{"abcdef1"}, g...)...)
	if err != nil || !strings.Contains(out, "no releases") {
		t.Fatalf("commit: %v %s", err, out)
	}
	out, err = runReposCmd(t, reposRemove, append([]string{"tools"}, g...)...)
	if err != nil || !strings.Contains(out, "kept") {
		t.Fatalf("remove: %v %s", err, out)
	}
	if _, err := runReposCmd(t, reposRemove, append([]string{"widgets"}, g...)...); err == nil {
		t.Fatal("a configured repository was removed")
	}
	if err := runRepos([]string{"bogus"}); err == nil {
		t.Fatal("an unknown action")
	}
}

// ptctl repos report reads a stored dependency scan (Task 181): the table,
// the verdict filter and the SARIF; ptctl repos scan says when scans are off.
func TestPtctlReposScanReport(t *testing.T) {
	t.Setenv("PULLTHROUGH_TENANT", "")
	const commit = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	store := repos.NewMemoryStore()
	rep := repos.ScanReport{
		Repo: "widgets", Tenant: "team-a", Commit: commit, Kind: repos.ScanRelease, Tags: []string{"v1.0"},
		Trigger: repos.TriggerRelease, Status: repos.ScanComplete, Result: repos.ResultMalicious, ContainsMaliciousDependency: true,
		Gate:    repos.ScannerStatus{Enabled: true, Provider: "mock-llm", Model: "model-1", PromptVersion: 2, Action: "block"},
		Summary: repos.ScanSummary{Dependencies: 2, Malicious: 1, Benign: 1},
		Dependencies: []repos.DependencyScan{
			{Type: "npm", Name: "evil-pad", Version: "1.0.0", Files: []string{"package-lock.json:21"}, Verdict: repos.VerdictMalicious, Pinned: true, Refused: true,
				Detail: &repos.VerdictDetail{Digest: "sha256:evil", ModelVerdict: "malicious", Confidence: 0.97, Model: "model-1",
					Reasons: []string{"MODEL-REASON-TEXT"}}},
			{Type: "npm", Name: "left-pad", Version: "1.0.0", Files: []string{"package-lock.json:9"}, Verdict: repos.VerdictBenign},
		},
	}
	data, _ := json.Marshal(rep)
	if err := store.Put(context.Background(), "scans/widgets/"+commit, data); err != nil {
		t.Fatal(err)
	}
	svc, err := repos.New(context.Background(), repos.Config{
		Repos: []repos.Repo{{Name: "widgets", URL: "https://git.example/acme/widgets.git", Tenant: "team-a"}},
	}, repos.Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	const token = "ptctl-repos-scan-token-0123456789"
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, Repos: svc, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	g := []string{"--url", ts.URL, "--token", token}

	out, err := runReposCmd(t, reposReport, append([]string{"widgets", "--rev", commit}, g...)...)
	if err != nil || !strings.Contains(out, "CONTAINS MALICIOUS DEPENDENCY") || !strings.Contains(out, "npm/evil-pad@1.0.0") ||
		!strings.Contains(out, "package-lock.json:21") || !strings.Contains(out, "model-1 (0.97)") || !strings.Contains(out, "kept for forensics") {
		t.Fatalf("report: %v\n%s", err, out)
	}
	if strings.Contains(out, "MODEL-REASON-TEXT") {
		t.Fatalf("the table printed the model's words:\n%s", out)
	}
	out, err = runReposCmd(t, reposReport, append([]string{"widgets", "--rev", commit, "--verdict", "flagged"}, g...)...)
	if err != nil || strings.Contains(out, "left-pad") {
		t.Fatalf("report --verdict flagged: %v\n%s", err, out)
	}
	if _, err := runReposCmd(t, reposReport, append([]string{"widgets", "--verdict", "odd"}, g...)...); err == nil {
		t.Fatal("an unknown --verdict was accepted")
	}
	out, err = runReposCmd(t, reposReport, append([]string{"widgets", "--rev", commit, "--sarif", "-"}, g...)...)
	if err != nil || !strings.Contains(out, `"ruleId": "llmpkgscan/malicious-dependency"`) || !strings.Contains(out, `"startLine": 21`) {
		t.Fatalf("report --sarif -: %v\n%s", err, out)
	}
	if _, err := runReposCmd(t, reposScan, append([]string{"widgets"}, g...)...); err == nil || !strings.Contains(err.Error(), "llmPackageScan.enabled") {
		t.Fatalf("scan with the scans off: %v", err)
	}
}

// TestPtctlReposUpdate covers the maintenance updater's commands (Task 182)
// against a registry whose updater is off, and the run report's rendering.
func TestPtctlReposUpdate(t *testing.T) {
	g := reposFixture(t)
	if _, err := runReposCmd(t, reposUpdate, append([]string{"widgets", "--dry-run"}, g...)...); err == nil ||
		!strings.Contains(err.Error(), "maintenance updater is off") {
		t.Fatalf("update with the updater off: %v", err)
	}
	if _, err := runReposCmd(t, reposUpdate, append([]string{"nope"}, g...)...); err == nil {
		t.Fatal("an unknown repository was accepted")
	}
	out, err := runReposCmd(t, reposUpdates, append([]string{"widgets"}, g...)...)
	if err != nil || !strings.Contains(out, "maintenance disabled") || !strings.Contains(out, "pullthrough/maintenance") {
		t.Fatalf("updates: %v %s", err, out)
	}

	var buf bytes.Buffer
	run := &repos.UpdateRun{ID: "20261113t000000.000z-0a0b0c0d", Repo: "widgets", Status: repos.UpdatePushed, Branch: "pullthrough/maintenance",
		BaseBranch: "main", Base: strings.Repeat("a", 40), Commit: strings.Repeat("b", 40), Reason: "created pullthrough/maintenance",
		Dependencies: 2,
		Updates: []repos.AppliedUpdate{{Type: "npm", Name: "left-pad", From: "1.0.0", To: "1.0.1", Bump: "patch", Method: "native",
			Verdict: "benign", ScanIDs: []string{"abc-1"}, Files: []string{"package-lock.json"}}},
		Skipped: []repos.SkippedCandidate{{Type: "npm", Name: "left-pad", From: "1.0.0", To: "1.1.0", Code: repos.SkipMalicious, Reason: "judged malicious"}},
	}
	if err := renderUpdateRun(&buf, run); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"widgets · pushed · pullthrough/maintenance on main@aaaaaaaaaaaa", "npm/left-pad  1.0.0  1.0.1  patch  native  benign   abc-1  package-lock.json",
		"npm/left-pad  1.0.0  1.1.0      malicious: judged malicious", "1 updates · 1 skipped"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the report lacks %q:\n%s", want, buf.String())
		}
	}
}
