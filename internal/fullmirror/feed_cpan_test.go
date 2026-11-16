package fullmirror

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/cpan"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The recorded RECENT files of cpan.metacpan.org (2026-11-16): the hour file
// reaches back to cpanHourMin, the six-hour file to cpanSixHourMin.
const (
	cpanDirtymark   = "1760942917.81368"
	cpanHourMin     = "1794791745.16391"
	cpanHourMax     = "1794795306.63291"
	cpanSixHourMin  = "1794773108.6859"
	cpanTestUpWhere = "https://cpan.metacpan.org"
)

// cpanTestFeed builds the adapter against a fixture server standing in for
// cpan.metacpan.org's root (where the RECENT files are).
func cpanTestFeed(t *testing.T) (*cpanFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "cpan", srv.URL(), reads, nil)).(*cpanFeed)
	return f, srv, reads
}

func (f *cpanFeed) testCursor(epoch string) string {
	return encodeCursor(&cpanCursor{Format: f.format(), Epoch: epoch, Dirtymark: cpanDirtymark})
}

func TestCPANFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://cpan.metacpan.org", nil, "https://cpan.metacpan.org"},
		{"https://www.cpan.org/", nil, "https://www.cpan.org"},
		{"https://mirror.internal.example/CPAN", nil, "https://mirror.internal.example/CPAN"},
		// A minicpan has no RECENT files: the feed is a full mirror's.
		{"https://minicpan.internal.example", map[string]string{"url": "https://cpan.metacpan.org/"}, "https://cpan.metacpan.org"},
	} {
		f, err := cpanNewFeed(Env{Upstream: "c", Type: "cpan", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*cpanFeed).feed.String(); got != tc.want {
			t.Errorf("%s: feed %s, want %s", tc.url, got, tc.want)
		}
	}
	for _, opts := range []map[string]string{{"interval": "6h"}, {"url": "rsync://cpan-rsync.perl.org/CPAN"}, {"url": "https://u:p@x"}} {
		if err := Check(Env{Upstream: "c", Type: "cpan", URL: cpanTestUpWhere, Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestCPANBootstrapListsTheIndexedDistributions(t *testing.T) {
	f, srv, reads := cpanTestFeed(t)
	f.page = 3
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusOK, fixture(t, "cpan", "recent-1h.json"))
	reads.set("/modules/02packages.details.txt.gz", fixture(t, "cpan", "02packages.details.txt.gz"))
	ctx := context.Background()
	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cpan", "bootstrap-page-1", viewBatch(t, first))
	all := names(first.Items)
	b := first
	for i := 0; b.More && i < 5; i++ {
		if b, err = f.Bootstrap(ctx, b.Next); err != nil {
			t.Fatal(err)
		}
		all = append(all, names(b.Items)...)
	}
	checkGolden(t, "cpan", "bootstrap-last-page", viewBatch(t, b))
	want := "CHANG-LIU/XML-Node CJCOLLIER/Google-Cloud/DBD-BigQuery CPANIC/DBIx-Squirrel CPANIC/Ekorn-Pipeline CPANIC/Text-Redact-Secrets ETHER/Acme-CPANAuthors-Canadian ETHER/Moose KIMOTO/SPVM-UV"
	if got := strings.Join(all, " "); got != want {
		t.Errorf("listed %s\nwant   %s", got, want)
	}
	// The listing continues from cpanHold before the hour file's newest
	// event (an upload of that time may not be indexed yet).
	var c cpanCursor
	if err := f.decode(b.Next, &c); err != nil || c.Listing || c.Epoch != "1794788106.63291" || c.Dirtymark != cpanDirtymark {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	if _, err := f.Changes(ctx, first.Next); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, b.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
	// 02packages as a gate or the mirror refuses it.
	reads.setDoc("/modules/02packages.details.txt.gz", fakeDoc{status: http.StatusServiceUnavailable, retry: time.Minute})
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != time.Minute {
		t.Errorf("a 503 with Retry-After: %v", err)
	}
	for body, want := range map[string]string{"not gzip, not a header": "not \"Name: value\"", "\n\nA::B 1 A/AA/AAA/X-1.tar.gz\n": "no header",
		"\x1f\x8b\x08garbage": "not a gzip file", "File: x\n": "ends in its header", "File: x\nbad header\n\n": "not \"Name: value\""} {
		reads.set("/modules/02packages.details.txt.gz", []byte(body))
		_, err = f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, want)
	}
}

func TestCPANChangesFollowTheHourFile(t *testing.T) {
	f, srv, _ := cpanTestFeed(t)
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusOK, fixture(t, "cpan", "recent-1h.json"))
	ctx := context.Background()
	// The cursor at the hour file's oldest event: the file holds everything
	// after it. KIMOTO's upload is followed by its directory's CHECKSUMS.
	b, err := f.Changes(ctx, f.testCursor(cpanHourMin))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cpan", "changes", viewBatch(t, b))
	if len(b.Items) != 1 || b.Items[0] != (Coordinate{Name: "KIMOTO/SPVM-UV", Version: "0.008"}) || b.More {
		t.Fatalf("batch %+v", b)
	}
	// From the newest event, nothing is new.
	again, err := f.Changes(ctx, b.Next)
	if err != nil || len(again.Items) != 0 || again.Next != b.Next {
		t.Errorf("caught up: %+v, %v", again, err)
	}
}

func TestCPANChangesReadALongerIntervalForAnOlderCursor(t *testing.T) {
	f, srv, _ := cpanTestFeed(t)
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusOK, fixture(t, "cpan", "recent-1h.json"))
	srv.on("GET", "/RECENT-6h.json").reply(http.StatusOK, fixture(t, "cpan", "recent-6h.json"))
	b, err := f.Changes(context.Background(), f.testCursor(cpanSixHourMin))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cpan", "changes-6h", viewBatch(t, b))
	if len(b.Items) != 11 {
		t.Errorf("%d changes: %v", len(b.Items), names(b.Items))
	}
}

func TestCPANCursorOlderThanEveryFileOrRebuiltIsInvalid(t *testing.T) {
	f, srv, _ := cpanTestFeed(t)
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusOK, fixture(t, "cpan", "recent-1h.json"))
	srv.on("GET", "/RECENT-6h.json").reply(http.StatusOK, fixture(t, "cpan", "recent-6h.json"))
	for _, iv := range []string{"1d", "1W", "1M", "1Q"} {
		srv.on("GET", "/RECENT-"+iv+".json").reply(http.StatusNotFound, nil)
	}
	// The year file is past the read bound (72.6 MB on cpan.metacpan.org):
	// enumerate again rather than read it. (The Z file is never read.)
	srv.on("GET", "/RECENT-1Y.json").reply(http.StatusOK, []byte(`{"meta":{},"recent":[`+strings.Repeat(" ", maxFeedPage)+`]}`))
	ctx := context.Background()
	_, err := f.Changes(ctx, f.testCursor("1700000000.5"))
	mustErr(t, err, false, true, "reaches back")
	// A rebuilt history.
	_, err = f.Changes(ctx, encodeCursor(&cpanCursor{Format: f.format(), Epoch: cpanHourMin, Dirtymark: "1600000000.1"}))
	mustErr(t, err, false, true, "dirtymark")
	// Cursors that do not read.
	for _, bad := range []string{"", "1", `{"format":"cpan/1","epoch":"x","dirtymark":""}`, `{"format":"cpan/1","epoch":"1e9","dirtymark":""}`,
		`{"format":"cpan/1","epoch":"-1","dirtymark":""}`, `{"format":"cpan/1","epoch":"1.5","dirtymark":"x"}`, `{"format":"cpan/1","epoch":"1.5","dirtymark":"","after":"ETHER/Moose"}`,
		`{"format":"cpan/1","epoch":"1.5","dirtymark":"","listing":true,"after":"lower/x"}`, `{"format":"pip/1","epoch":"1"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestCPANUploadsWaitForTheirChecksums(t *testing.T) {
	f, srv, _ := cpanTestFeed(t)
	// An upload at 1000 whose directory's CHECKSUMS is not rewritten yet,
	// then another author's upload whose CHECKSUMS is.
	hour := func(newest string, events ...string) string {
		return fmt.Sprintf(`{"meta":{"aggregator":["1h","6h","Z"],"dirtymark":%s,"minmax":{"min":900,"max":%s}},"recent":[%s]}`,
			cpanDirtymark, newest, strings.Join(events, ","))
	}
	ev := func(epoch, path, typ string) string {
		return fmt.Sprintf(`{"epoch":%s,"path":%q,"type":%q}`, epoch, path, typ)
	}
	srv.on("GET", "/RECENT-1h.json").json(hour("1300.5",
		ev("1300.5", "authors/id/B/BB/BBB/CHECKSUMS", "new"),
		ev("1200", "authors/id/B/BB/BBB/Later-2.0.tar.gz", "new"),
		ev("1100", "authors/id/A/AA/AAA/Gone-0.1.tar.gz", "delete"),
		ev("1000", "authors/id/A/AA/AAA/Fresh-1.0.tar.gz", "new"),
		ev("950", "authors/id/A/AA/AAA/Fresh-1.0.meta", "new"),
		ev("940", "authors/id/A/AA/AAA/CHECKSUMS", "new")))
	ctx := context.Background()
	b, err := f.Changes(ctx, f.testCursor("900"))
	if err != nil {
		t.Fatal(err)
	}
	// AAA's CHECKSUMS was rewritten before the upload, not after: the batch
	// stops before it, and so do the events after it.
	if len(b.Items) != 0 || !b.LagKnown || b.Lag != 3 {
		t.Fatalf("held batch %+v", b)
	}
	var c cpanCursor
	if err := f.decode(b.Next, &c); err != nil || c.Epoch != "950" {
		t.Errorf("held cursor %+v (%v), want just before the upload", c, err)
	}
	// Once the upload is cpanHold old it is reported anyway.
	late := "8300"
	srv.on("GET", "/RECENT-1h.json").json(hour(late,
		ev(late, "authors/02STAMP", "new"),
		ev("1300.5", "authors/id/B/BB/BBB/CHECKSUMS", "new"),
		ev("1200", "authors/id/B/BB/BBB/Later-2.0.tar.gz", "new"),
		ev("1100", "authors/id/A/AA/AAA/Gone-0.1.tar.gz", "delete"),
		ev("1000", "authors/id/A/AA/AAA/Fresh-1.0.tar.gz", "new")))
	b, err = f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	want := []Coordinate{{Name: "AAA/Fresh", Version: "1.0"}, {Name: "AAA/Gone", Version: "0.1", Deleted: true}, {Name: "BBB/Later", Version: "2.0"}}
	if fmt.Sprintf("%#v", b.Items) != fmt.Sprintf("%#v", want) || b.Lag != 0 {
		t.Errorf("released batch %#v lag %d", b.Items, b.Lag)
	}
	// A batch is cut at maxItems and continues.
	f.maxItems = 1
	b, err = f.Changes(ctx, f.testCursor("950"))
	if err != nil || len(b.Items) != 1 || !b.More {
		t.Fatalf("cut batch %+v, %v", b, err)
	}
	if err := f.decode(b.Next, &c); err != nil || c.Epoch != "1000" {
		t.Errorf("cut cursor %+v (%v)", c, err)
	}
}

func TestCPANMalformedRecentFiles(t *testing.T) {
	f, srv, _ := cpanTestFeed(t)
	ctx := context.Background()
	for body, want := range map[string]string{
		`not json`:                               "not the JSON document",
		`{"recent":[]}`:                          "no meta",
		`{"meta":{}}`:                            "no meta or no recent",
		`{"meta":{"dirtymark":"x"},"recent":[]}`: "not the JSON document",
		`{"meta":{"dirtymark":1e5},"recent":[]}`: "not an epoch",
		`{"meta":{"aggregator":["1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h","1h"]},"recent":[]}`: "intervals",
	} {
		srv.on("GET", "/RECENT-1h.json").json(body)
		_, err := f.Changes(ctx, f.testCursor(cpanHourMin))
		mustErr(t, err, true, false, want)
	}
	// Events that are not valid are dropped; the others are kept.
	srv.on("GET", "/RECENT-1h.json").json(`{"meta":{"dirtymark":` + cpanDirtymark + `,"minmax":{"min":1,"max":5}},"recent":[
		{"epoch":5,"path":"authors/id/A/AA/AAA/X-1.0.tar.gz","type":"new"},
		{"epoch":4.5,"path":"authors/id/A/AA/AAA/CHECKSUMS","type":"new"},
		{"epoch":"4","path":"authors/id/A/AA/AAA/Y-2.0.tar.gz","type":"new"},
		{"epoch":3,"path":"authors/id/A/AA/AAA/Z-3.0.tar.gz","type":"moved"},
		{"epoch":2.5,"path":"authors/id/a/aa/aaa/Lower-1.tar.gz","type":"new"},
		{"epoch":2.4,"path":"authors/id/A/AB/AAA/Shard-1.tar.gz","type":"new"},
		{"epoch":2.3,"path":"authors/id/A/AA/AAA/../../x-1.tar.gz","type":"new"},
		{"epoch":2.2,"path":"authors/id/A/AA/AAA/a/b/c/d/e/Deep-1.tar.gz","type":"new"},
		{"epoch":2.1,"path":"modules/02packages.details.txt.gz","type":"new"},
		{"epoch":2,"path":"authors/id/A/AA/AAA/bad\nname-1.tar.gz","type":"new"}
	]}`)
	b, err := f.Changes(ctx, f.testCursor("1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[AAA/Y@2.0]" {
		t.Errorf("items %s", got)
	}
	// The registry's errors.
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusBadGateway, nil)
	_, err = f.Changes(ctx, f.testCursor(cpanHourMin))
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusNotFound, nil)
	_, err = f.Changes(ctx, f.testCursor(cpanHourMin))
	mustErr(t, err, true, false, "not found")
}

func TestCPANReleasesComeFromTheAuthorsChecksums(t *testing.T) {
	f, _, reads := cpanTestFeed(t)
	reads.set("/authors/id/C/CP/CPANIC/CHECKSUMS", fixture(t, "cpan", "checksums-cpanic.txt"))
	reads.set("/authors/id/E/ET/ETHER/CHECKSUMS", fixture(t, "cpan", "checksums-ether.txt"))
	ctx := context.Background()
	backend, err := cpan.New(cpan.Options{Name: f.k.env.Upstream, UpstreamURL: cpanTestUpWhere, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, dist, golden string }{
		{"CPANIC/Ekorn-Pipeline", "Ekorn-Pipeline", "releases-ekorn-pipeline"},
		{"ETHER/Acme-CPANAuthors-Canadian", "Acme-CPANAuthors-Canadian", "releases-acme-cpanauthors-canadian"},
	} {
		rels, err := f.Releases(ctx, c.name)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		checkGolden(t, "cpan", c.golden, viewReleases(rels))
		// The backend names the distribution without its author.
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return c.dist, r.Version })
	}
	// One CHECKSUMS read per Releases; the version the feed reported is listed.
	if n := reads.count("/authors/id/C/CP/CPANIC/CHECKSUMS"); n != 1 {
		t.Errorf("CHECKSUMS read %d times", n)
	}
	rels, _ := f.Releases(ctx, "CPANIC/Ekorn-Pipeline")
	if !hasVersion(rels, "v0.3.3") || rels[len(rels)-1].Artifacts[0].Size != 204005 {
		t.Errorf("v0.3.3 missing or without its size: %+v", rels[len(rels)-1])
	}

	// A distribution the author's directory does not hold, an author the
	// mirror does not have, names that are not ones.
	_, err = f.Releases(ctx, "CPANIC/No-Such-Dist")
	mustErr(t, err, true, false, "list no release")
	_, err = f.Releases(ctx, "NOBODY/Thing")
	mustErr(t, err, true, false, "not found")
	for _, bad := range []string{"Moose", "ether/Moose", "ETHER/../Moose", "ETHER/a/b/c/d/e/Moose", "E/Moose", "ETHER/Mo ose", "ETHER/"} {
		_, err = f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a CPAN distribution name")
	}
	// A subdirectory release reads that directory's CHECKSUMS.
	reads.set("/authors/id/C/CJ/CJCOLLIER/Google-Cloud/CHECKSUMS", []byte("$cksum = {\n  'DBD-BigQuery-0.01.tar.gz' => {\n    'mtime' => '2025-01-02',\n    'size' => 10\n  }\n};\n"))
	rels, err = f.Releases(ctx, "CJCOLLIER/Google-Cloud/DBD-BigQuery")
	if err != nil || len(rels) != 1 || rels[0].Artifacts[0].Path != "/authors/id/C/CJ/CJCOLLIER/Google-Cloud/DBD-BigQuery-0.01.tar.gz" {
		t.Errorf("subdirectory release %+v, %v", rels, err)
	}
	expectServed(t, backend, rels, func(Release, Artifact) (string, string) { return "DBD-BigQuery", "0.01" })
	// A gate's verdict on CHECKSUMS is final; access control is not a
	// verdict on the distribution.
	reads.setDoc("/authors/id/E/EV/EVIL/CHECKSUMS", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "EVIL/Thing")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/authors/id/H/HE/HELD/CHECKSUMS", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "HELD/Thing")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
}

func TestCPANEpochArithmetic(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1794795306.6329", "1794795306.63291", -1}, {"1794795306.63290", "1794795306.6329", 0}, {"10", "9.99999", 1},
		{"0009", "9", 0}, {"1.5", "1.45", 1}, {"", "0", -1}, {"5", "", 1},
	} {
		if got := cpanCompareEpochs(c.a, c.b); got != c.want {
			t.Errorf("compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for s, want := range map[string]bool{"1": true, "1.5": true, "1794795306.63291": true, "1.": false, ".5": false, "-1": false, "1e5": false, "1.2.3": false, "": false} {
		if cpanDecimal(s) != want {
			t.Errorf("cpanDecimal(%q) = %v", s, !want)
		}
	}
	if got := cpanEpochMinus("1794795306.63291", 2*time.Hour); got != "1794788106.63291" {
		t.Errorf("minus %s", got)
	}
	if got := cpanEpochMinus("100", time.Hour); got != "0" {
		t.Errorf("minus below zero %s", got)
	}
	if got := cpanEpochTime("1794795306.5"); !got.Equal(time.Unix(1794795306, 5e8)) {
		t.Errorf("time %v", got)
	}
}

func TestCPANDistributionPaths(t *testing.T) {
	for p, want := range map[string]string{
		"authors/id/C/CP/CPANIC/Ekorn-Pipeline-v0.3.3.tar.gz":         "CPANIC/Ekorn-Pipeline@v0.3.3",
		"id/K/KI/KIMOTO/SPVM-UV-0.008.tar.gz":                         "KIMOTO/SPVM-UV@0.008",
		"authors/id/C/CJ/CJCOLLIER/Google-Cloud/Protobuf-0.09.tar.gz": "CJCOLLIER/Google-Cloud/Protobuf@0.09",
		"authors/id/N/NI/NI-S/Tk-800.024.tar.gz":                      "NI-S/Tk@800.024",
		"authors/id/C/CP/CPANIC/Ekorn-Pipeline-v0.3.3.meta":           "",
		"authors/id/C/CP/CPANIC/CHECKSUMS":                            "",
		"authors/id/S/ST/STRYTOAST/bid.tar.gz":                        "",
		"authors/02STAMP":                                             "",
		"modules/RECENT-1h.yaml":                                      "",
	} {
		co, _, ok := cpanEventCoordinate(cpanEvent{epoch: "1", path: p, typ: "new"})
		if got := co.String(); (ok && got != want) || (!ok && want != "") {
			t.Errorf("%s: %q %v, want %q", p, got, ok, want)
		}
	}
	if dir, ok := cpanChecksumsDir("authors/id/C/CP/CPANIC/CHECKSUMS"); !ok || dir != "C/CP/CPANIC" {
		t.Errorf("CHECKSUMS dir %q %v", dir, ok)
	}
	if dir, dist, ok := cpanParseName("CJCOLLIER/Google-Cloud/DBD-BigQuery"); !ok || dir != "C/CJ/CJCOLLIER/Google-Cloud" || dist != "DBD-BigQuery" {
		t.Errorf("subdirectory name: %q %q %v", dir, dist, ok)
	}
}

func TestCPANIntervalFilesMustOverlap(t *testing.T) {
	// The hour file reaches back to …90000.5; a six-hour file that is behind
	// ends at …85000.5: the events between them are in neither file, so the
	// cursor must not move past them — the poll fails and is retried.
	f, srv, _ := cpanTestFeed(t)
	meta := func(iv, min, max string) string {
		return `{"aggregator":["1h","6h","1d","1W","1M","1Q","1Y","Z"],"dirtymark":` + cpanDirtymark +
			`,"interval":"` + iv + `","minmax":{"min":` + min + `,"max":` + max + `}}`
	}
	srv.on("GET", "/RECENT-1h.json").reply(http.StatusOK, []byte(`{"meta":`+meta("1h", "1794790000.5", "1794790100.5")+`,"recent":[`+
		`{"epoch":1794790100.5,"path":"authors/02STAMP","type":"new"},`+
		`{"epoch":1794790000.5,"path":"authors/id/X/XY/XYZ/Other-1.0.tar.gz.meta","type":"new"}]}`))
	srv.on("GET", "/RECENT-6h.json").reply(http.StatusOK, []byte(`{"meta":`+meta("6h", "1794780000.5", "1794785000.5")+`,"recent":[`+
		`{"epoch":1794785000.5,"path":"authors/02STAMP","type":"new"},`+
		`{"epoch":1794780000.5,"path":"authors/02STAMP","type":"new"}]}`))
	_, err := f.Changes(context.Background(), f.testCursor("1794782000.5"))
	mustErr(t, err, false, false, "behind")
	// Once the longer file has caught up, the events are read.
	srv.on("GET", "/RECENT-6h.json").reply(http.StatusOK, []byte(`{"meta":`+meta("6h", "1794780000.5", "1794790050.5")+`,"recent":[`+
		`{"epoch":1794790050.5,"path":"authors/02STAMP","type":"new"},`+
		`{"epoch":1794787000.5,"path":"authors/02STAMP","type":"new"},`+
		`{"epoch":1794780000.5,"path":"authors/02STAMP","type":"new"}]}`))
	if _, err := f.Changes(context.Background(), f.testCursor("1794782000.5")); err != nil {
		t.Errorf("overlapping files: %v", err)
	}
}
