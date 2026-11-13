package main

import (
	"bytes"
	"context"
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
