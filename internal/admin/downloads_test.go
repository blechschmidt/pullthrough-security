package admin

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// newTestDownloadLog returns a log holding a small, known set of downloads:
//
//	1  10.0.0.5   cargo  cfg-if@1.0.0                  served   (alice / team-a)
//	2  10.0.0.5   cargo  itoa@1.0.11                   blocked  gate=policy code=malicious
//	3  10.0.0.6   cargo  cfg-if@1.0.0                  served   cache HIT
//	4  10.0.1.7   go     rsc.io/quote@v1.5.2           served
//	5  10.0.1.7   go     github.com/pkg/errors@v0.9.1  blocked  gate=policy code=malicious
func newTestDownloadLog(t *testing.T) *downloadlog.Log {
	t.Helper()
	log, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatalf("downloadlog.New: %v", err)
	}
	rec := func(ip, eco, pkg, version string, mutate func(*downloadlog.Entry)) {
		e := downloadlog.Entry{
			ClientIP: ip, Ecosystem: eco, Upstream: eco, Package: pkg, Version: version,
			Kind: downloadlog.KindPackage, Method: http.MethodGet, Path: "/v1/" + eco + "/" + pkg,
			Status: http.StatusOK, Outcome: downloadlog.OutcomeServed, Cache: "MISS", Bytes: 1000, Size: 1000,
		}
		if mutate != nil {
			mutate(&e)
		}
		log.Record(e)
	}
	blocked := func(e *downloadlog.Entry) {
		e.Outcome, e.Status, e.Gate, e.Code, e.Bytes, e.Cache = downloadlog.OutcomeBlocked, 403, "policy", "malicious", 0, "BLOCKED"
		e.Reason = "source commit flagged malicious by the commit scanner"
	}
	rec("10.0.0.5", "cargo", "cfg-if", "1.0.0", func(e *downloadlog.Entry) {
		e.Subject, e.Tenant, e.UserAgent, e.Artifact = "alice", "team-a", "cargo/1.84.0", "cfg-if-1.0.0.crate"
	})
	rec("10.0.0.5", "cargo", "itoa", "1.0.11", blocked)
	rec("10.0.0.6", "cargo", "cfg-if", "1.0.0", func(e *downloadlog.Entry) { e.Cache = "HIT" })
	rec("10.0.1.7", "go", "rsc.io/quote", "v1.5.2", nil)
	rec("10.0.1.7", "go", "github.com/pkg/errors", "v0.9.1", blocked)
	return log
}

func entryIDs(entries []downloadlog.Entry) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.ID
	}
	return out
}

func TestDownloadsEndpointListsNewestFirst(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	var resp downloadsResponse
	if code := getJSON(t, srv, "/admin/api/downloads", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !resp.Enabled || resp.Total != 5 || resp.Returned != 5 || resp.NextBefore != 0 {
		t.Fatalf("response = enabled %v total %d returned %d next %d", resp.Enabled, resp.Total, resp.Returned, resp.NextBefore)
	}
	if got := entryIDs(resp.Entries); !reflect.DeepEqual(got, []uint64{5, 4, 3, 2, 1}) {
		t.Fatalf("entry order = %v, want newest first", got)
	}
	first := resp.Entries[4]
	if first.ClientIP != "10.0.0.5" || first.Package != "cfg-if" || first.Version != "1.0.0" || first.Ecosystem != "cargo" ||
		first.Subject != "alice" || first.Tenant != "team-a" || first.Outcome != downloadlog.OutcomeServed {
		t.Fatalf("first entry = %+v", first)
	}
	// The response describes the log's bounds, so the console can say how far
	// back "everything" reaches.
	if !resp.Log.Enabled || resp.Log.Capacity != downloadlog.DefaultMaxEntries || resp.Log.Retained != 5 || resp.Log.RetentionSeconds == 0 {
		t.Fatalf("log stats = %+v", resp.Log)
	}
}

// The wire format is what the console and scripts are written against.
func TestDownloadsEndpointWireFormat(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads?outcome=blocked&ecosystem=cargo", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	var doc struct {
		Enabled bool             `json:"enabled"`
		Total   int              `json:"total"`
		Entries []map[string]any `json:"entries"`
		Log     map[string]any   `json:"log"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Enabled || doc.Total != 1 || len(doc.Entries) != 1 {
		t.Fatalf("document = %s", rec.Body.String())
	}
	e := doc.Entries[0]
	for key, want := range map[string]any{
		"clientIp": "10.0.0.5", "ecosystem": "cargo", "upstream": "cargo", "package": "itoa", "version": "1.0.11",
		"kind": "package", "method": "GET", "outcome": "blocked", "gate": "policy", "code": "malicious",
		"status": float64(403), "bytes": float64(0),
	} {
		if e[key] != want {
			t.Errorf("entry[%q] = %v, want %v", key, e[key], want)
		}
	}
	for _, key := range []string{"id", "time", "path", "reason"} {
		if _, ok := e[key]; !ok {
			t.Errorf("entry has no %q", key)
		}
	}
	for _, key := range []string{"capacity", "retained", "retentionSeconds", "persistent", "recorded"} {
		if _, ok := doc.Log[key]; !ok {
			t.Errorf("log has no %q", key)
		}
	}
}

func TestDownloadsEndpointFilters(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	tests := []struct {
		query string
		want  []uint64
	}{
		{"ip=10.0.0.5", []uint64{2, 1}},
		{"ip=10.0.0.0/24", []uint64{3, 2, 1}},
		{"ip=10.0.0.0%2F16", []uint64{5, 4, 3, 2, 1}},
		{"package=cfg-if", []uint64{3, 1}},
		{"package=rsc.io/quote&version=v1.5.2", []uint64{4}},
		{"package=github.com/*", []uint64{5}},
		{"ecosystem=go", []uint64{5, 4}},
		{"upstream=cargo&outcome=served", []uint64{3, 1}},
		{"outcome=blocked", []uint64{5, 2}},
		{"ip=10.0.1.7&outcome=blocked", []uint64{5}},
		{"subject=alice", []uint64{1}},
		{"tenant=team-a", []uint64{1}},
		{"q=quote", []uint64{4}},
		{"q=MALICIOUS", []uint64{5, 2}},
		{"kind=package", []uint64{5, 4, 3, 2, 1}},
		{"kind=metadata", []uint64{}},
		{"since=1h", []uint64{5, 4, 3, 2, 1}},
		{"until=1h", []uint64{}},
		{"limit=2", []uint64{5, 4}},
		{"limit=2&before=4", []uint64{3, 2}},
		{"ip=192.0.2.1", []uint64{}},
	}
	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			var resp downloadsResponse
			if code := getJSON(t, srv, "/admin/api/downloads?"+tc.query, "", &resp); code != http.StatusOK {
				t.Fatalf("status = %d", code)
			}
			if got := entryIDs(resp.Entries); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("entries = %v, want %v", got, tc.want)
			}
			if resp.Returned != len(tc.want) {
				t.Fatalf("returned = %d, want %d", resp.Returned, len(tc.want))
			}
			if resp.Entries == nil {
				t.Fatal("entries must be an empty list, never null: the console iterates it")
			}
		})
	}
}

func TestDownloadsEndpointPaging(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	var walked []uint64
	url := "/admin/api/downloads?limit=2"
	for page := 0; page < 10; page++ {
		var resp downloadsResponse
		if code := getJSON(t, srv, url, "", &resp); code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		if resp.Total != 5 {
			t.Fatalf("page %d: total = %d, want 5", page, resp.Total)
		}
		walked = append(walked, entryIDs(resp.Entries)...)
		if resp.NextBefore == 0 {
			break
		}
		url = fmt.Sprintf("/admin/api/downloads?limit=2&before=%d", resp.NextBefore)
	}
	if !reflect.DeepEqual(walked, []uint64{5, 4, 3, 2, 1}) {
		t.Fatalf("walked %v", walked)
	}
}

// A filter that cannot be applied is refused. Answering the unfiltered question
// instead would show an investigator every download as "from this address".
func TestDownloadsEndpointRejectsInvalidFilters(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	for _, query := range []string{
		"ip=not-an-address", "ip=10.0.0.0/64", "outcome=stolen", "kind=virus",
		"since=tomorrow", "until=never", "before=x", "limit=-3", "limit=many", "format=xml",
	} {
		for _, endpoint := range []string{"/admin/api/downloads", "/admin/api/downloads/summary"} {
			if endpoint == "/admin/api/downloads/summary" && strings.HasPrefix(query, "format=") {
				continue // format applies to the list only
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, endpoint+"?"+query, nil))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("GET %s?%s: status %d, want 400", endpoint, query, rec.Code)
				continue
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
				t.Errorf("GET %s?%s: error body %q", endpoint, query, rec.Body.String())
			}
		}
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads/summary?top=0", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("top=0: status %d, want 400", rec.Code)
	}
}

func TestDownloadsEndpointCSV(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads?format=csv&ecosystem=cargo", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="downloads.csv"`) {
		t.Errorf("content-disposition = %q", cd)
	}
	if got := rec.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("X-Total-Count = %q, want 3", got)
	}
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows, want a header and three cargo entries", len(rows))
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	for _, name := range []string{"time", "client_ip", "ecosystem", "package", "version", "outcome", "gate", "bytes"} {
		if _, ok := col[name]; !ok {
			t.Fatalf("CSV has no %q column: %v", name, rows[0])
		}
	}
	if got := rows[1][col["client_ip"]] + " " + rows[1][col["package"]] + " " + rows[1][col["outcome"]]; got != "10.0.0.6 cfg-if served" {
		t.Errorf("first row = %q", got)
	}
	if got := rows[2][col["package"]] + " " + rows[2][col["outcome"]] + " " + rows[2][col["gate"]]; got != "itoa blocked policy" {
		t.Errorf("second row = %q", got)
	}

	// An export is the whole selection, not one page of it.
	log, err := downloadlog.New(downloadlog.Config{Enabled: true, MaxEntries: 5000})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < downloadlog.MaxLimit+50; i++ {
		log.Record(downloadlog.Entry{ClientIP: "10.0.0.1", Ecosystem: "npm", Package: fmt.Sprintf("p%d", i), Kind: downloadlog.KindPackage, Outcome: downloadlog.OutcomeServed, Status: 200})
	}
	big := newTestServer(t, Options{DownloadLog: log})
	rec = httptest.NewRecorder()
	big.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads?format=csv", nil))
	rows, err = csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rows) - 1; got != downloadlog.MaxLimit+50 {
		t.Errorf("unbounded export has %d rows, want all %d", got, downloadlog.MaxLimit+50)
	}
	// … unless the caller bounds it.
	rec = httptest.NewRecorder()
	big.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads?format=csv&limit=7", nil))
	rows, _ = csv.NewReader(rec.Body).ReadAll()
	if got := len(rows) - 1; got != 7 {
		t.Errorf("bounded export has %d rows, want 7", got)
	}
	// A bound above the JSON page size is honoured exactly: a CSV has no cursor,
	// so an export capped at one page would pass for the whole selection.
	rec = httptest.NewRecorder()
	big.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/api/downloads?format=csv&limit=%d", downloadlog.MaxLimit+20), nil))
	rows, _ = csv.NewReader(rec.Body).ReadAll()
	if got := len(rows) - 1; got != downloadlog.MaxLimit+20 {
		t.Errorf("an export bounded above the page size has %d rows, want %d", got, downloadlog.MaxLimit+20)
	}
	if got := rec.Header().Get("X-Total-Count"); got != strconv.Itoa(downloadlog.MaxLimit+50) {
		t.Errorf("X-Total-Count = %q, want every match (%d)", got, downloadlog.MaxLimit+50)
	}
	// limit=0 is "no bound", as it is when the parameter is absent.
	rec = httptest.NewRecorder()
	big.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads?format=csv&limit=0", nil))
	rows, _ = csv.NewReader(rec.Body).ReadAll()
	if got := len(rows) - 1; got != downloadlog.MaxLimit+50 {
		t.Errorf("limit=0 export has %d rows, want all %d", got, downloadlog.MaxLimit+50)
	}
	// The JSON page stays capped regardless.
	var resp downloadsResponse
	if code := getJSON(t, big, "/admin/api/downloads?limit=100000", "", &resp); code != http.StatusOK || resp.Returned != downloadlog.MaxLimit {
		t.Errorf("oversized JSON page: status %d, %d entries; want %d", code, resp.Returned, downloadlog.MaxLimit)
	}
}

func TestDownloadsSummaryEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t)})
	var sum downloadsSummaryResponse
	if code := getJSON(t, srv, "/admin/api/downloads/summary", "", &sum); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !sum.Enabled || sum.Total != 5 || sum.Served != 3 || sum.Blocked != 2 || sum.Clients != 3 || sum.Packages != 4 || sum.Bytes != 3000 {
		t.Fatalf("totals = %+v", sum.Summary)
	}
	if len(sum.ByClient) != 3 || sum.ByClient[0].ClientIP != "10.0.1.7" || sum.ByClient[0].Downloads != 2 || sum.ByClient[0].Blocked != 1 {
		t.Fatalf("byClient = %+v", sum.ByClient)
	}
	if len(sum.ByPackage) != 4 || sum.ByPackage[0].Package != "cfg-if" || sum.ByPackage[0].Clients != 2 {
		t.Fatalf("byPackage = %+v", sum.ByPackage)
	}
	if len(sum.ByEcosystem) != 2 {
		t.Fatalf("byEcosystem = %+v", sum.ByEcosystem)
	}

	// "Who pulled cfg-if?"
	var who downloadsSummaryResponse
	if code := getJSON(t, srv, "/admin/api/downloads/summary?package=cfg-if", "", &who); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	var clients []string
	for _, c := range who.ByClient {
		clients = append(clients, c.ClientIP)
	}
	if !reflect.DeepEqual(clients, []string{"10.0.0.6", "10.0.0.5"}) {
		t.Fatalf("clients of cfg-if = %v", clients)
	}

	// "What did 10.0.0.5 pull?"
	var what downloadsSummaryResponse
	if code := getJSON(t, srv, "/admin/api/downloads/summary?ip=10.0.0.5", "", &what); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	var packages []string
	for _, p := range what.ByPackage {
		packages = append(packages, p.Package)
	}
	if !reflect.DeepEqual(packages, []string{"itoa", "cfg-if"}) || what.Blocked != 1 {
		t.Fatalf("packages of 10.0.0.5 = %v (blocked %d)", packages, what.Blocked)
	}

	var top downloadsSummaryResponse
	if code := getJSON(t, srv, "/admin/api/downloads/summary?top=1", "", &top); code != http.StatusOK || len(top.ByClient) != 1 || len(top.ByPackage) != 1 {
		t.Fatalf("top=1: status %d, %d clients, %d packages", code, len(top.ByClient), len(top.ByPackage))
	}
	if top.Clients != 3 || top.Packages != 4 {
		t.Fatalf("top=1 must not change the totals: %d clients, %d packages", top.Clients, top.Packages)
	}
}

// With the log switched off the endpoints still answer — with "disabled" — so
// the console can explain an empty tab instead of showing an error.
func TestDownloadsEndpointsWhenDisabled(t *testing.T) {
	disabled, err := downloadlog.New(downloadlog.Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string]Options{
		"not wired": {},
		"disabled":  {DownloadLog: disabled},
		"typed nil": {DownloadLog: (*downloadlog.Log)(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newTestServer(t, opts)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads?ip=10.0.0.5", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("list status = %d", rec.Code)
			}
			var list map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if list["enabled"] != false || list["total"] != float64(0) {
				t.Fatalf("list = %s", rec.Body.String())
			}
			if entries, ok := list["entries"].([]any); !ok || len(entries) != 0 {
				t.Fatalf("entries = %v, want an empty list", list["entries"])
			}

			rec = httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/downloads/summary", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("summary status = %d", rec.Code)
			}
			var sum map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
				t.Fatal(err)
			}
			if sum["enabled"] != false {
				t.Fatalf("summary = %s", rec.Body.String())
			}
			for _, key := range []string{"byClient", "byPackage", "byEcosystem"} {
				if list, ok := sum[key].([]any); !ok || len(list) != 0 {
					t.Fatalf("summary[%q] = %v, want an empty list", key, sum[key])
				}
			}
		})
	}
}

// The log names client addresses and identities: it is behind the admin
// credential like every other admin endpoint, and read-only.
func TestDownloadsEndpointsRequireTheAdminToken(t *testing.T) {
	srv := newTestServer(t, Options{DownloadLog: newTestDownloadLog(t), Token: "s3cret-admin-token"})
	for _, path := range []string{"/admin/api/downloads", "/admin/api/downloads/summary", "/admin/api/downloads?format=csv"} {
		if code := getJSON(t, srv, path, "", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: status %d, want 401", path, code)
		}
		if code := getJSON(t, srv, path, "wrong-token", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s with a wrong token: status %d, want 401", path, code)
		}
		if code := getJSON(t, srv, path, "s3cret-admin-token", nil); code != http.StatusOK {
			t.Errorf("GET %s with the token: status %d, want 200", path, code)
		}
	}
	// The log is read-only: only GET is routed to it. Any other method falls
	// through to the dashboard shell, as for every unknown admin path, and never
	// returns (let alone changes) log data.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/admin/api/downloads", nil)
		req.Header.Set("Authorization", "Bearer s3cret-admin-token")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || strings.Contains(rec.Body.String(), "clientIp") {
			t.Errorf("%s /admin/api/downloads returned log data: %s", method, rec.Body.String())
		}
	}
	var after downloadsResponse
	if code := getJSON(t, srv, "/admin/api/downloads", "s3cret-admin-token", &after); code != http.StatusOK || after.Total != 5 {
		t.Errorf("after non-GET requests: status %d, %d entries; want 200 and the 5 entries untouched", code, after.Total)
	}
}

// Under SSO/RBAC the log is readable with the read capability (a viewer), like
// the other read-only views.
func TestDownloadsEndpointsCapability(t *testing.T) {
	for _, path := range []string{"/api/downloads", "/api/downloads/summary"} {
		if got := requiredCapability(http.MethodGet, path); got != adminauth.CapRead {
			t.Errorf("requiredCapability(GET %s) = %v, want read", path, got)
		}
	}
}
