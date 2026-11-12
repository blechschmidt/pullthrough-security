package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// userLinksFixture starts a real admin API over a real personal-links service
// and returns the flags that reach it, the service, and the identifiers of the
// links it holds.
func userLinksFixture(t *testing.T, token string) (string, *userlinks.Service, map[string]string) {
	t.Helper()
	svc, err := userlinks.New(userlinks.Config{PublicURL: "https://proxy.example.com", Store: userlinks.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, l := range []struct {
		key, subject, team, label string
	}{
		{"alice-laptop", "alice@example.com", "platform", "laptop"},
		{"alice-ci", "alice@example.com", "platform", "ci"},
		{"bob-laptop", "bob@example.com", "payments", "laptop"},
	} {
		_, _, info, err := svc.Issue(context.Background(), userlinks.Identity{Subject: l.subject, Team: l.team}, userlinks.IssueOptions{Label: l.label})
		if err != nil {
			t.Fatal(err)
		}
		ids[l.key] = info.ID
	}
	svc.Registry().Touch(ids["alice-laptop"], "10.0.0.5", "npm/10.9.2")

	log, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	record := func(ip, subject, tenant, link, pkg string) {
		e := downloadlog.Entry{
			ClientIP: ip, Ecosystem: "npm", Upstream: "npm", Package: pkg, Version: "1.0.0", Kind: downloadlog.KindPackage,
			Method: http.MethodGet, Status: http.StatusOK, Outcome: downloadlog.OutcomeServed, Bytes: 100,
			Subject: subject, Tenant: tenant, Link: link,
		}
		if subject != "" {
			e.AuthMethod = userlinks.MethodPersonalLink
		}
		log.Record(e)
	}
	record("10.0.0.5", "alice@example.com", "platform", ids["alice-laptop"], "left-pad")
	record("10.0.9.9", "alice@example.com", "platform", ids["alice-ci"], "left-pad")
	record("10.0.0.6", "bob@example.com", "payments", ids["bob-laptop"], "lodash")
	record("10.0.0.7", "", "", "", "left-pad")

	srv, err := admin.New(admin.Options{Cache: emptyCache{}, UserLinks: svc, DownloadLog: log, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, svc, ids
}

// runCaptured invokes a ptctl command the way the shell does and returns what
// it printed on standard output. Usage text and flag errors, which go to
// standard error, are discarded.
func runCaptured(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// The global flags default from the environment; a developer's shell must
	// not decide what these tests talk to.
	for _, name := range []string{"PULLTHROUGH_URL", "PULLTHROUGH_TOKEN", "PULLTHROUGH_TENANT", "PULLTHROUGH_ADMIN_PREFIX"} {
		t.Setenv(name, "")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, devnull
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	runErr := run(args)
	os.Stdout, os.Stderr = stdout, stderr
	_ = w.Close()
	_ = devnull.Close()
	out := <-done
	_ = r.Close()
	return out, runErr
}

func TestUserLinksList(t *testing.T) {
	url, _, ids := userLinksFixture(t, "admin-token-0123456789")
	base := []string{"--url", url, "--token", "admin-token-0123456789"}

	out, err := runCaptured(t, append([]string{"userlinks", "list"}, base...)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ID", "USER", "STATE", ids["alice-laptop"], "alice@example.com", "platform", "laptop", "active", "10.0.0.5", "npm/10.9.2",
		"bob@example.com", "never", "3 working, 0 expired, 0 revoked; 2 users with a working link."} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, userlinks.TokenPrefix) {
		t.Fatalf("the listing contains a token:\n%s", out)
	}

	out, err = runCaptured(t, append([]string{"userlinks", "list", "--users"}, base...)...)
	if err != nil || !strings.Contains(out, "WORKING") || strings.Count(out, "alice@example.com") != 1 {
		t.Fatalf("per-user listing: %v\n%s", err, out)
	}
	out, err = runCaptured(t, append([]string{"userlinks", "list", "--user", "bob@example.com", "--format", "json"}, base...)...)
	if err != nil || !strings.Contains(out, `"total": 1`) || !strings.Contains(out, ids["bob-laptop"]) || strings.Contains(out, ids["alice-ci"]) {
		t.Fatalf("filtered JSON listing: %v\n%s", err, out)
	}
	out, err = runCaptured(t, append([]string{"userlinks", "list", "--state", "revoked"}, base...)...)
	if err != nil || !strings.Contains(out, "No links match.") {
		t.Fatalf("an empty selection: %v\n%s", err, out)
	}

	for name, args := range map[string][]string{
		"a bad state":      {"userlinks", "list", "--state", "bogus"},
		"a bad format":     {"userlinks", "list", "--format", "csv"},
		"a bad limit":      {"userlinks", "list", "--limit", "0"},
		"an unknown verb":  {"userlinks", "purge"},
		"no verb":          {"userlinks"},
		"without a token":  {"userlinks", "list", "--url", url},
		"without the URL":  {"userlinks", "list", "--url", ""},
		"an unknown flag":  {"userlinks", "list", "--nope"},
		"revoke: neither":  {"userlinks", "revoke"},
		"revoke: both":     {"userlinks", "revoke", "--id", ids["bob-laptop"], "--user", "bob@example.com"},
		"issue: no user":   {"userlinks", "issue"},
		"issue: a bad ttl": {"userlinks", "issue", "--user", "x", "--ttl-days", "-1"},
	} {
		full := args
		if name != "without a token" && name != "without the URL" && len(args) > 1 {
			full = append(append([]string{}, args...), base...)
		}
		if _, err := runCaptured(t, full...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestUserLinksRevokeAndIssue(t *testing.T) {
	url, svc, ids := userLinksFixture(t, "admin-token-0123456789")
	base := []string{"--url", url, "--token", "admin-token-0123456789"}

	out, err := runCaptured(t, append([]string{"userlinks", "revoke", "--id", ids["bob-laptop"], "--reason", "device lost"}, base...)...)
	if err != nil || !strings.Contains(out, "Revoked link "+ids["bob-laptop"]+" (laptop) of bob@example.com.") {
		t.Fatalf("revoking a link: %v\n%s", err, out)
	}
	if info, _ := svc.Registry().Get(ids["bob-laptop"]); info.State != userlinks.StateRevoked || info.RevokeReason != "device lost" {
		t.Fatalf("the link after the command = %+v", info)
	}

	out, err = runCaptured(t, append([]string{"userlinks", "revoke", "--user", "alice@example.com"}, base...)...)
	if err != nil || !strings.Contains(out, "Revoked everything issued to alice@example.com: 2 working link(s) ended") {
		t.Fatalf("revoking a user: %v\n%s", err, out)
	}
	if got := svc.Links(userlinks.Filter{State: userlinks.StateActive}); len(got) != 0 {
		t.Fatalf("%d links still work", len(got))
	}
	if _, err := runCaptured(t, append([]string{"userlinks", "revoke", "--id", "ffffffffffffffff"}, base...)...); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("revoking a link that does not exist: %v", err)
	}

	// Issuing prints the link — once — and how to use it.
	out, err = runCaptured(t, append([]string{"userlinks", "issue", "--user", "ci-bot", "--team", "platform", "--roles", "reader, builder", "--label", "pipeline", "--ttl-days", "7"}, base...)...)
	if err != nil {
		t.Fatalf("issuing: %v\n%s", err, out)
	}
	issued := svc.Links(userlinks.Filter{Subject: "ci-bot"})
	if len(issued) != 1 || issued[0].Label != "pipeline" || issued[0].Team != "platform" || len(issued[0].Roles) != 2 || issued[0].ExpiresAt == nil ||
		time.Until(*issued[0].ExpiresAt) > 7*24*time.Hour+time.Minute {
		t.Fatalf("the issued link = %+v", issued)
	}
	var token string
	for _, field := range strings.Fields(out) {
		if userlinks.WellFormed(field) {
			token = field
		}
	}
	if token == "" || !strings.Contains(out, "https://proxy.example.com/u/"+token) || !strings.Contains(out, "only time the link is shown") ||
		!strings.Contains(out, "ptctl config --personal-link https://proxy.example.com/u/"+token) {
		t.Fatalf("the output of issue:\n%s", out)
	}
	if link, err := svc.Registry().Resolve(context.Background(), token); err != nil || link.Subject != "ci-bot" {
		t.Fatalf("the printed link does not resolve: %+v, %v", link, err)
	}

	// On an admin surface that authenticates nobody, issuing is refused.
	open, _, _ := userLinksFixture(t, "")
	if _, err := runCaptured(t, "userlinks", "issue", "--user", "ceo@example.com", "--url", open); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("issuing on an unauthenticated admin surface: %v", err)
	}
}

func TestRenderUserLinksStates(t *testing.T) {
	var buf bytes.Buffer
	renderUserLinks(&buf, userLinksListing{}, false, time.Now())
	if !strings.Contains(buf.String(), "disabled on this proxy") {
		t.Fatalf("a disabled feature: %s", buf.String())
	}

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	revokedAt := now.Add(-time.Hour)
	expires := now.Add(30 * 24 * time.Hour)
	used := now.Add(-3 * time.Hour)
	buf.Reset()
	renderUserLinks(&buf, userLinksListing{
		Enabled: true, Total: 5,
		Registry: userlinks.Stats{Active: 1, Revoked: 1, Users: 1, Synced: false, LastSyncError: "the bucket is unreachable"},
		Links: []userlinks.Info{
			{ID: "0123456789abcdef", Identity: userlinks.Identity{Subject: "alice@example.com"}, State: userlinks.StateRevoked,
				CreatedAt: now.Add(-48 * time.Hour), RevokedAt: &revokedAt, RevokedBy: "ops@example.com"},
			{ID: "fedcba9876543210", Identity: userlinks.Identity{Subject: "alice@example.com"}, Label: "laptop", State: userlinks.StateActive,
				CreatedAt: now.Add(-24 * time.Hour), ExpiresAt: &expires, LastUsedAt: &used, LastAddr: "10.0.0.5"},
		},
	}, false, now)
	out := buf.String()
	for _, want := range []string{"WARNING: the link registry cannot reach its store (the bucket is unreachable)", "revoked by ops@example.com",
		"never", "2026-03-31", "3h ago", "2 of 5 matching links shown"} {
		if !strings.Contains(out, want) {
			t.Errorf("the rendering lacks %q:\n%s", want, out)
		}
	}

	for d, want := range map[time.Duration]string{
		30 * time.Second: "just now", 5 * time.Minute: "5m ago", 3 * time.Hour: "3h ago", 5 * 24 * time.Hour: "5d ago",
	} {
		at := now.Add(-d)
		if got := ago(&at, now); got != want {
			t.Errorf("ago(%v) = %q, want %q", d, got, want)
		}
	}
	if ago(nil, now) != "never" {
		t.Error("a link that was never used")
	}
}

// The download log by user: the same command, asked by name.
func TestDownloadsByUser(t *testing.T) {
	url, _, ids := userLinksFixture(t, "admin-token-0123456789")
	base := []string{"--url", url, "--token", "admin-token-0123456789"}

	out, err := runCaptured(t, append([]string{"downloads", "--user", "alice@example.com"}, base...)...)
	if err != nil || !strings.Contains(out, "2 matching entries.") || strings.Contains(out, "bob@example.com") {
		t.Fatalf("--user: %v\n%s", err, out)
	}
	out, err = runCaptured(t, append([]string{"downloads", "--subject", "*@example.com"}, base...)...)
	if err != nil || !strings.Contains(out, "3 matching entries.") {
		t.Fatalf("a pattern: %v\n%s", err, out)
	}
	out, err = runCaptured(t, append([]string{"downloads", "--user", "-"}, base...)...)
	if err != nil || !strings.Contains(out, "1 matching entries.") || !strings.Contains(out, "10.0.0.7") {
		t.Fatalf("downloads nobody was identified for: %v\n%s", err, out)
	}
	out, err = runCaptured(t, append([]string{"downloads", "--link", ids["alice-ci"]}, base...)...)
	if err != nil || !strings.Contains(out, "1 matching entries.") || !strings.Contains(out, "10.0.9.9") {
		t.Fatalf("--link: %v\n%s", err, out)
	}
	if _, err := runCaptured(t, append([]string{"downloads", "--user", "a", "--subject", "b"}, base...)...); err == nil {
		t.Fatal("--user and --subject with different values were accepted")
	}

	out, err = runCaptured(t, append([]string{"downloads", "--summary"}, base...)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Users: 2   Downloads without an identity: 1", "Users (most pulls first):", "USER", "ADDRESSES",
		"alice@example.com", "10.0.0.5, 10.0.9.9", "USERS"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	// "Who pulled left-pad?" — by name.
	out, err = runCaptured(t, append([]string{"downloads", "--summary", "--package", "left-pad"}, base...)...)
	if err != nil || !strings.Contains(out, "alice@example.com") || strings.Contains(out, "bob@example.com") ||
		!strings.Contains(out, "Users: 1   Downloads without an identity: 1") {
		t.Fatalf("who pulled left-pad: %v\n%s", err, out)
	}
	// The export carries the link.
	out, err = runCaptured(t, append([]string{"downloads", "--format", "csv", "--user", "bob@example.com"}, base...)...)
	if err != nil || !strings.Contains(out, ",link\n") || !strings.Contains(out, ","+ids["bob-laptop"]+"\n") {
		t.Fatalf("the CSV export: %v\n%s", err, out)
	}
}

// `ptctl config --personal-link`: the same snippets, pointed at the user's own
// address, without a separate credential, saying where the link must not go.
func TestConfigWithPersonalLink(t *testing.T) {
	token, err := userlinks.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	link := "https://proxy.example.com/u/" + token

	out, err := runCaptured(t, "config", "--personal-link", link, "npm=npm", "pypi=pip", "crates=cargo")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# proxy: https://proxy.example.com",
		"personal cache link",
		"registry=" + link + "/v1/npm/",
		"omit-lockfile-registry-resolved=true",
		"index-url = " + link + "/v1/pypi/simple/",
		`registry = "sparse+` + link + `/v1/crates/"`,
		"package-lock.json",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"_authToken", "PULLTHROUGH_TOKEN", "No token was supplied"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the output for a personal link mentions %q:\n%s", unwanted, out)
		}
	}

	// The address of one package source works as well: the link is found in it.
	out, err = runCaptured(t, "config", "--personal-link", link+"/v1/npm/", "npm=npm")
	if err != nil || !strings.Contains(out, "registry="+link+"/v1/npm/") {
		t.Fatalf("a link with a path after it: %v\n%s", err, out)
	}
	// A proxy published under a path.
	out, err = runCaptured(t, "config", "--personal-link", "https://example.com/proxy/me/"+token, "npm=npm")
	if err != nil || !strings.Contains(out, "registry=https://example.com/proxy/me/"+token+"/v1/npm/") || !strings.Contains(out, "# proxy: https://example.com/proxy\n") {
		t.Fatalf("a proxy under a path: %v\n%s", err, out)
	}
	// A token given for the admin API does not leak into the snippets.
	out, err = runCaptured(t, "config", "--personal-link", link, "--token", "admin-secret-0123456789", "npm=npm")
	if err != nil || strings.Contains(out, "admin-secret") {
		t.Fatalf("an admin token ended up in the snippets: %v\n%s", err, out)
	}
	// Another address for the admin API does not become the link's: the
	// snippets name the proxy the link belongs to.
	out, err = runCaptured(t, "config", "--url", "http://10.0.0.5:8080", "--personal-link", link, "npm=npm")
	if err != nil || !strings.Contains(out, "registry="+link+"/v1/npm/") || strings.Contains(out, "10.0.0.5") {
		t.Fatalf("with --url naming another address: %v\n%s", err, out)
	}

	for name, bad := range map[string]string{
		"not a URL":         "ptl1nope",
		"no link in it":     "https://proxy.example.com/v1/npm/",
		"a truncated link":  link[:len(link)-3],
		"the link is first": "https://proxy.example.com/" + token,
	} {
		_, err := runCaptured(t, "config", "--personal-link", bad, "npm=npm")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// An error about a mistyped link does not repeat most of it.
		if strings.Contains(err.Error(), token[:20]) {
			t.Errorf("%s: the error repeats the link: %v", name, err)
		}
	}
}
