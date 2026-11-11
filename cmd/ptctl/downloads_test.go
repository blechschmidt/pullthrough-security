package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// emptyCache is the minimal cache inspector an admin server needs.
type emptyCache struct{}

func (emptyCache) Entries(context.Context) ([]cache.Stat, error) { return nil, nil }
func (emptyCache) Stat(context.Context, string) (*cache.Stat, error) {
	return nil, cache.ErrNotFound
}
func (emptyCache) Delete(context.Context, string) error { return cache.ErrNotFound }

// downloadsFixture starts a real admin API over a real download log holding n
// served downloads (p0001 … from 10.0.<i/250>.<i%250+1>) plus one blocked
// attempt from 10.9.9.9 behind the proxy 10.255.0.1, and returns a client for it.
func downloadsFixture(t *testing.T, n int, token string) (*client, *downloadlog.Log) {
	t.Helper()
	log, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		log.Record(downloadlog.Entry{
			ClientIP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Ecosystem: "cargo", Upstream: "cargo",
			Package: fmt.Sprintf("p%04d", i), Version: "1.0.0", Kind: downloadlog.KindPackage,
			Method: http.MethodGet, Status: http.StatusOK, Outcome: downloadlog.OutcomeServed, Cache: "MISS", Bytes: 100,
			Subject: "alice", Tenant: "team-a",
		})
	}
	log.Record(downloadlog.Entry{
		ClientIP: "10.9.9.9", ForwardedBy: "10.255.0.1", Ecosystem: "go", Upstream: "go",
		Package: "github.com/pkg/errors", Version: "v0.9.1", Kind: downloadlog.KindMetadata,
		Method: http.MethodGet, Status: http.StatusForbidden, Outcome: downloadlog.OutcomeBlocked,
		Gate: "policy", Code: "malicious", Cache: "BLOCKED",
	})

	srv, err := admin.New(admin.Options{Cache: emptyCache{}, DownloadLog: log, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	c, err := newClient(globalFlags{url: ts.URL, adminPrefix: "/admin", token: token})
	if err != nil {
		t.Fatal(err)
	}
	return c, log
}

func TestFetchDownloadsLimitAndPaging(t *testing.T) {
	// More entries than one API page holds, so --all has to follow the cursor.
	const served = downloadsPageSize + 37
	c, _ := downloadsFixture(t, served, "")

	page, err := fetchDownloads(c, nil, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Enabled || page.Total != served+1 || page.Returned != 5 || len(page.Entries) != 5 {
		t.Fatalf("limit 5: enabled %v total %d returned %d", page.Enabled, page.Total, page.Returned)
	}
	// Newest first: the blocked attempt was recorded last.
	if page.Entries[0].Package != "github.com/pkg/errors" || page.Entries[1].Package != fmt.Sprintf("p%04d", served) {
		t.Fatalf("order = %s, %s", page.Entries[0].Package, page.Entries[1].Package)
	}

	everything, err := fetchDownloads(c, nil, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if everything.Returned != served+1 || everything.Total != served+1 {
		t.Fatalf("--all returned %d of %d", everything.Returned, everything.Total)
	}
	seen := map[uint64]bool{}
	for i, e := range everything.Entries {
		if seen[e.ID] {
			t.Fatalf("entry %d returned twice", e.ID)
		}
		seen[e.ID] = true
		if i > 0 && e.ID >= everything.Entries[i-1].ID {
			t.Fatalf("entries out of order at %d", i)
		}
	}

	// A limit that spans pages is exact.
	spanning, err := fetchDownloads(c, nil, downloadsPageSize+10, false)
	if err != nil || spanning.Returned != downloadsPageSize+10 {
		t.Fatalf("limit across pages: %d entries, %v", spanning.Returned, err)
	}
}

func TestFetchDownloadsCSV(t *testing.T) {
	// More entries than one API page holds: an export is not a page.
	const served = downloadsPageSize + 37
	c, _ := downloadsFixture(t, served, "")
	rows := func(text string) [][]string {
		t.Helper()
		records, err := csv.NewReader(strings.NewReader(text)).ReadAll()
		if err != nil {
			t.Fatalf("not valid CSV: %v", err)
		}
		if len(records) == 0 || records[0][0] != "time" {
			t.Fatalf("the export has no header row: %v", records)
		}
		return records[1:]
	}

	// --limit is exact, also above the page size of the JSON API.
	text, err := fetchDownloadsCSV(c, nil, downloadsPageSize+10, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rows(text)); got != downloadsPageSize+10 {
		t.Errorf("--limit %d exported %d rows", downloadsPageSize+10, got)
	}
	text, err = fetchDownloadsCSV(c, nil, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rows(text)); got != 3 {
		t.Errorf("--limit 3 exported %d rows", got)
	}

	// --all is every matching entry, whatever --limit says.
	text, err = fetchDownloadsCSV(c, nil, 3, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rows(text)); got != served+1 {
		t.Errorf("--all exported %d rows, want %d", got, served+1)
	}

	// Filters apply to an export as they do to the table.
	text, err = fetchDownloadsCSV(c, map[string]string{"outcome": "blocked"}, 50, false)
	if err != nil {
		t.Fatal(err)
	}
	blocked := rows(text)
	if len(blocked) != 1 || !strings.Contains(strings.Join(blocked[0], ","), "github.com/pkg/errors") {
		t.Errorf("the blocked-only export = %v", blocked)
	}
	if _, err := fetchDownloadsCSV(c, map[string]string{"ip": "not-an-address"}, 50, false); err == nil {
		t.Error("an invalid filter was not reported")
	}
}

func TestFetchDownloadsFilters(t *testing.T) {
	c, _ := downloadsFixture(t, 20, "")
	tests := []struct {
		query map[string]string
		want  int
	}{
		{map[string]string{"ip": "10.0.0.5"}, 1},
		{map[string]string{"ip": "10.0.0.0/24"}, 20},
		{map[string]string{"package": "p0007", "version": "1.0.0"}, 1},
		{map[string]string{"package": "p000*"}, 9},
		{map[string]string{"outcome": "blocked"}, 1},
		{map[string]string{"ecosystem": "go"}, 1},
		{map[string]string{"subject": "alice"}, 20},
		{map[string]string{"tenant": "team-b"}, 0},
		{map[string]string{"q": "malicious"}, 1},
	}
	for _, tc := range tests {
		page, err := fetchDownloads(c, tc.query, 100, false)
		if err != nil {
			t.Fatalf("%v: %v", tc.query, err)
		}
		if page.Total != tc.want || page.Returned != tc.want {
			t.Errorf("%v: %d entries (total %d), want %d", tc.query, page.Returned, page.Total, tc.want)
		}
	}

	// The server's refusal of a filter it cannot apply reaches the user.
	if _, err := fetchDownloads(c, map[string]string{"ip": "not-an-address"}, 10, false); err == nil || !strings.Contains(err.Error(), "ip filter") {
		t.Errorf("an invalid address filter: err = %v", err)
	}
}

// --package is passed on as typed: the API matches it against the package name
// and against the name@version coordinate, so a name that contains an "@"
// (Homebrew's openssl@3) is found, and so is name@version.
func TestFetchDownloadsByNameOrCoordinate(t *testing.T) {
	c, log := downloadsFixture(t, 3, "")
	log.Record(downloadlog.Entry{
		ClientIP: "10.4.4.4", Ecosystem: "homebrew", Upstream: "homebrew", Package: "openssl@3", Version: "3.4.0",
		Kind: downloadlog.KindPackage, Method: http.MethodGet, Status: http.StatusOK, Outcome: downloadlog.OutcomeServed,
	})
	for pkg, want := range map[string]string{
		"openssl@3":       "openssl@3", // a package name with an "@"
		"openssl@3@3.4.0": "openssl@3", // … and its coordinate
		"p0002@1.0.0":     "p0002",     // name@version
		"p0002":           "p0002",
		"P0002@1.*":       "p0002",
	} {
		page, err := fetchDownloads(c, map[string]string{"package": pkg}, 10, false)
		if err != nil {
			t.Fatalf("--package %s: %v", pkg, err)
		}
		if page.Total != 1 || page.Entries[0].Package != want {
			t.Errorf("--package %s matched %d entries (%+v), want the one for %s", pkg, page.Total, page.Entries, want)
		}
	}
	if page, err := fetchDownloads(c, map[string]string{"package": "p0002@9.9.9"}, 10, false); err != nil || page.Total != 0 {
		t.Errorf("--package p0002@9.9.9 matched %d entries, %v; want none", page.Total, err)
	}
}

func TestDownloadsRequiresTheAdminToken(t *testing.T) {
	c, _ := downloadsFixture(t, 3, "s3cret")
	if page, err := fetchDownloads(c, nil, 10, false); err != nil || page.Total != 4 {
		t.Fatalf("with the token: %d entries, %v", page.Total, err)
	}
	c.token = ""
	if _, err := fetchDownloads(c, nil, 10, false); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("without the token: err = %v, want an HTTP 401", err)
	}
}

func TestRenderDownloads(t *testing.T) {
	c, _ := downloadsFixture(t, 2, "")
	page, err := fetchDownloads(c, nil, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderDownloads(&buf, page)
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if got := strings.Fields(lines[0]); !reflect.DeepEqual(got, []string{"TIME", "CLIENT", "IP", "ECOSYSTEM", "PACKAGE", "VERSION", "OUTCOME", "CACHE", "BYTES", "IDENTITY"}) {
		t.Fatalf("header = %v", got)
	}
	for _, want := range []string{
		"10.9.9.9 (via 10.255.0.1)", "github.com/pkg/errors", "v0.9.1", "blocked:policy",
		"10.0.0.3", "p0002", "served", "MISS", "alice (team-a)",
		"2 of 3 matching entries shown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the table lacks %q:\n%s", want, out)
		}
	}
	// The cache column of a refused request would only repeat "blocked".
	if strings.Contains(lines[1], "BLOCKED") {
		t.Errorf("the blocked row shows a cache status: %q", lines[1])
	}

	buf.Reset()
	renderDownloads(&buf, downloadsPage{Enabled: true})
	if !strings.Contains(buf.String(), "No downloads match") {
		t.Errorf("empty result: %q", buf.String())
	}
	buf.Reset()
	renderDownloads(&buf, downloadsPage{})
	if !strings.Contains(buf.String(), "disabled") || !strings.Contains(buf.String(), "downloadLog.enabled") {
		t.Errorf("disabled log: %q", buf.String())
	}
}

func TestRenderDownloadsSummary(t *testing.T) {
	c, _ := downloadsFixture(t, 3, "")
	var sum downloadsSummary
	if err := c.getJSON(c.adminURL("api/downloads/summary", map[string]string{"top": "2"}), &sum); err != nil {
		t.Fatal(err)
	}
	if !sum.Enabled || sum.Total != 4 || sum.Blocked != 1 || sum.Clients != 4 || len(sum.ByClient) != 2 {
		t.Fatalf("summary = %+v", sum.Summary)
	}
	var buf bytes.Buffer
	renderDownloadsSummary(&buf, sum)
	out := buf.String()
	for _, want := range []string{
		"Downloads: 4  (served 3, blocked 1,", "Client addresses: 4   Packages: 4",
		"Client addresses (most pulls first):", "Packages (most pulls first):",
		"10.9.9.9", "github.com/pkg/errors", "v0.9.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}

	buf.Reset()
	renderDownloadsSummary(&buf, downloadsSummary{})
	if !strings.Contains(buf.String(), "disabled") {
		t.Errorf("disabled log: %q", buf.String())
	}
}

func TestRunDownloadsRejectsBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--url", "http://127.0.0.1:1", "--format", "xml"},
		{"--url", "http://127.0.0.1:1", "--limit", "0"},
		{"--url", "http://127.0.0.1:1", "--summary", "--format", "csv"},
	} {
		if err := runDownloads(args); err == nil {
			t.Errorf("ptctl downloads %v succeeded", args)
		}
	}
	// It is a registered subcommand, so shell completion offers it.
	found := false
	for _, name := range commandNames() {
		if name == "downloads" {
			found = true
		}
	}
	if !found {
		t.Error("downloads is not a registered subcommand")
	}
}
