package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/cran"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The recorded index (testdata/feeds/cran/PACKAGES): cloud.r-project.org's
// src/contrib/PACKAGES (served gzipped as PACKAGES.gz, 1.98 MB; 7.5 MB
// plain), trimmed to a few stanzas in the file's order — among them the
// recommended packages boot and Matrix, listed a second time at the end with
// "Path: 4.7.0/Recommended", and fields continued onto a second line.
const (
	cranETag     = `"1e37d8-6605cb1d0e036"`
	cranModified = "Mon, 16 Nov 2026 03:51:36 GMT"
)

// cranTestFeed builds the cran adapter against a fixture server standing in
// for the repository.
func cranTestFeed(t *testing.T, opts map[string]string) (*cranFeed, *fixtureServer) {
	t.Helper()
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "cran", srv.URL(), nil, opts)).(*cranFeed)
	return f, srv
}

// cranGzip compresses an index as the repository serves PACKAGES.gz.
func cranGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// cranView is a batch as the golden files show it, the fixture server's
// address replaced.
func cranView(t *testing.T, b Batch, srv *fixtureServer) batchView {
	t.Helper()
	v := viewBatch(t, b)
	v.Next = bytes.ReplaceAll(v.Next, []byte(srv.URL()), []byte("http://cran.example"))
	return v
}

func TestCRANFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://cloud.r-project.org", nil, "https://cloud.r-project.org"},
		{"https://packagemanager.posit.co/cran/2026-11-01/", nil, "https://packagemanager.posit.co/cran/2026-11-01"},
		{"https://nexus.internal.example/repository/r-proxy", map[string]string{"url": "https://cran.internal.example/"}, "https://cran.internal.example"},
	} {
		f, err := newCRANFeed(Env{Upstream: "cran", Type: "cran", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*cranFeed).src.root.String(); got != tc.want {
			t.Errorf("%s: root %s, want %s", tc.url, got, tc.want)
		}
		if got := f.(*cranFeed).src.settle; got != 45*time.Minute {
			t.Errorf("%s: settle %v", tc.url, got)
		}
	}
	for v, want := range map[string]time.Duration{"0": 0, "1h30m": 90 * time.Minute} {
		f, err := newCRANFeed(Env{Upstream: "cran", Type: "cran", URL: "https://cloud.r-project.org", Options: map[string]string{"settle": v}})
		if err != nil || f.(*cranFeed).src.settle != want {
			t.Errorf("settle %q: %v", v, err)
		}
	}
	for _, opts := range []map[string]string{{"binaries": "windows"}, {"url": "ftp://cran.example"}, {"url": "https://u:p@cran.example"}, {"url": "https://cran.example/?x=1"},
		{"settle": "-5m"}, {"settle": "1w"}, {"settle": "200h"}} {
		if err := Check(Env{Upstream: "cran", Type: "cran", URL: "https://cloud.r-project.org", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestCRANBootstrapThenChanges(t *testing.T) {
	f, srv := cranTestFeed(t, map[string]string{"settle": "0"})
	f.page = 4
	index := fixture(t, "cran", "PACKAGES")
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(200, cranGzip(t, index)).withHeader("ETag", cranETag).withHeader("Last-Modified", cranModified)
	ctx := context.Background()
	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.Bootstrap(ctx, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cran", "bootstrap", []batchView{cranView(t, first, srv), cranView(t, second, srv)})
	backend, err := cran.New(cran.Options{Name: f.src.k.env.Upstream, UpstreamURL: f.src.k.env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a11yShiny", "boot", "data.table", "jsonlite", "Matrix"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "cran", "releases-"+name, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	_, err = f.Releases(ctx, "ggplot2")
	mustErr(t, err, true, false, "not in the cran index")

	// Unchanged: one conditional request, answered 304.
	f.page = indexPage
	srv.on("GET", "/src/contrib/PACKAGES.gz").requireHeader("If-None-Match", cranETag).requireHeader("If-Modified-Since", cranModified).reply(http.StatusNotModified, nil)
	same, err := f.Changes(ctx, second.Next)
	if err != nil || len(same.Items) != 0 || same.Next != second.Next {
		t.Fatalf("an unchanged index: %+v %v", same, err)
	}
	// jsonlite 2.0.1 supersedes 2.0.0 (which moves to the archive), abind is
	// removed, zzz is new.
	doc := string(index)
	doc = strings.Replace(doc, "Package: jsonlite\nVersion: 2.0.0\n", "Package: jsonlite\nVersion: 2.0.1\n", 1)
	cut := strings.Index(doc, "Package: abind\n")
	end := strings.Index(doc, "Package: boot\n")
	doc = doc[:cut] + doc[end:] + "\nPackage: zzz\nVersion: 0.1.0\nLicense: MIT\nMD5sum: 0123456789abcdef0123456789abcdef\nNeedsCompilation: no\nPublished: 2026-11-16 05:00:00 UTC\n"
	srv.on("GET", "/src/contrib/PACKAGES.gz").requireHeader("If-None-Match", cranETag).reply(200, cranGzip(t, []byte(doc))).withHeader("ETag", `"2"`).withHeader("Last-Modified", "Mon, 16 Nov 2026 05:51:36 GMT")
	ch, err := f.Changes(ctx, second.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cran", "changes", cranView(t, ch, srv))
	rels, err := f.Releases(ctx, "jsonlite")
	if err != nil || len(rels) != 1 || rels[0].Version != "2.0.1" || rels[0].Artifacts[0].Path != "/src/contrib/jsonlite_2.0.1.tar.gz" {
		t.Errorf("the new current version: %+v %v", viewReleases(rels), err)
	}
}

func TestCRANPlainPACKAGESAndPathStanzas(t *testing.T) {
	f, srv := cranTestFeed(t, nil)
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(http.StatusNotFound, nil)
	// A repository written by tools::write_PACKAGES(subdirs = TRUE): a
	// package found only beneath a subdirectory.
	srv.on("GET", "/src/contrib/PACKAGES").reply(200, []byte("Package: inhouse\nVersion: 1.2-3\nMD5sum: 0123456789ABCDEF0123456789abcdef\nPath: team/stats\n")).withHeader("ETag", `"p1"`)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[inhouse]" {
		t.Fatalf("%v %v", names(b.Items), err)
	}
	rels, err := f.Releases(ctx, "inhouse")
	if err != nil || len(rels) != 1 || rels[0].Artifacts[0].Path != "/src/contrib/team/stats/inhouse_1.2-3.tar.gz" {
		t.Fatalf("%+v %v", viewReleases(rels), err)
	}
	backend, err := cran.New(cran.Options{Name: f.src.k.env.Upstream, UpstreamURL: f.src.k.env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	expectServed(t, backend, rels, func(Release, Artifact) (string, string) { return "inhouse", "1.2-3" })
	// The next poll asks for the plain index again, conditionally.
	srv.on("GET", "/src/contrib/PACKAGES").requireHeader("If-None-Match", `"p1"`).reply(http.StatusNotModified, nil)
	if same, err := f.Changes(ctx, b.Next); err != nil || len(same.Items) != 0 {
		t.Errorf("%+v %v", same, err)
	}
}

func TestCRANMalformedAndRefused(t *testing.T) {
	ctx := context.Background()
	f, srv := cranTestFeed(t, nil)
	stanzas := []string{
		"Package: good\nVersion: 1.0-1\nMD5sum: 0123456789abcdef0123456789abcdef\nPublished: 2026-01-02 03:04:05\n",
		"Package: nomd5\nVersion: 2.0\n",
		"Package: a_b\nVersion: 1.0\n",               // not an R package name
		"Package: badver\nVersion: 1.0a\n",           // not an R package version
		"Package: cont\nVersion: 1.0\n  .1\n",        // a version continued
		"Package: dup\nVersion: 1.0\nVersion: 2.0\n", // a field repeated
		"Version: 1.0\n",                             // no package
		"Package: file\nVersion: 1.0\nFile: other.tar.gz\n",
		"Package: path\nVersion: 1.0\nPath: ../up\n",
		"Package: junk\nnot a field\nVersion: 1.0\n",
		"Package: long\nVersion: 1.0\nDescription: " + strings.Repeat("x", 70<<10) + "\n",
		"Package: tabbed\nVersion:\t1.5\nImports: a,\n\tb\n",
	}
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(200, cranGzip(t, []byte(strings.Join(stanzas, "\n"))))
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[good nomd5 tabbed]" {
		t.Errorf("packages kept: %s", got)
	}
	rels, err := f.Releases(ctx, "good")
	if err != nil || len(rels) != 1 || rels[0].Published.IsZero() {
		t.Errorf("good: %+v %v", rels, err)
	}
	// An answer that is not an index at all is refused, not taken for an
	// empty repository.
	for _, body := range []string{"<html>\n<body>maintenance</body>\n</html>\n", "  indented\n  only\n", "\x00\x01\x02"} {
		srv.on("GET", "/src/contrib/PACKAGES.gz").reply(200, []byte(body))
		_, err = f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, "not a PACKAGES index")
	}
	// An empty index is an empty repository.
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(200, nil)
	if b, err := f.Bootstrap(ctx, ""); err != nil || len(b.Items) != 0 {
		t.Errorf("an empty index: %+v %v", b, err)
	}
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(200, []byte("\x1f\x8b\x08\x00broken"))
	if _, err := f.Bootstrap(ctx, ""); err == nil {
		t.Errorf("a broken gzip stream was read")
	}
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(http.StatusNotFound, nil)
	srv.on("GET", "/src/contrib/PACKAGES").reply(http.StatusNotFound, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "serves no src/contrib/PACKAGES")
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "30")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 30*time.Second {
		t.Errorf("a 429: %v", err)
	}
	for _, c := range []string{"[]", `{"format":"helm/1","snap":"` + strings.Repeat("c", 64) + `"}`} {
		_, err := f.Changes(ctx, c)
		mustErr(t, err, false, true, "")
	}
}

func TestCRANVersionOrder(t *testing.T) {
	ordered := []string{"1.0a", "0.2-3", "0.2-20", "0.10", "1", "1.0", "1.0-1", "1.0.1", "1.9", "1.10-0", "2.0.0", "10.0"}
	for i := range ordered {
		for j := range ordered {
			c := cranCompareVersions(ordered[i], ordered[j])
			if (i < j && c >= 0) || (i > j && c <= 0) || (i == j && c != 0) {
				t.Errorf("compare(%s, %s) = %d", ordered[i], ordered[j], c)
			}
		}
	}
	for v, want := range map[string]bool{"1.0": true, "0.2-20": true, "1": true, "1.0a": false, "1..0": false, "-1": false, "1.": false, "1.-0": false, "": false} {
		if cranValidVersion(v) != want {
			t.Errorf("valid(%q) = %v", v, !want)
		}
	}
	for n, want := range map[string]bool{"jsonlite": true, "data.table": true, "R6": true, "a": false, "1a": false, "a_b": false, "ab.": false, "a-b": false} {
		if cranValidName(n) != want {
			t.Errorf("name %q: %v", n, !want)
		}
	}
}

// cranBackendFetch fetches a tarball through the real backend, reading it
// whole, and returns how the backend verified it and what reading it gave.
func cranBackendFetch(t *testing.T, backend *cran.Backend, path string) (string, error) {
	t.Helper()
	ctx := context.Background()
	res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	fr, err := backend.Fetch(ctx, res)
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Content.Close()
	_, err = io.Copy(io.Discard, fr.Content)
	return res.Metadata[cran.MetaChecksumVerified], err
}

// cranStanzaOf is a PACKAGES stanza of a tarball published at published.
func cranStanzaOf(name, version string, tarball []byte, published time.Time) string {
	return fmt.Sprintf("\nPackage: %s\nVersion: %s\nLicense: MIT\nMD5sum: %x\nNeedsCompilation: no\nPublished: %s\n", name, version, md5.Sum(tarball), published.UTC().Format("2006-01-02 15:04:05 UTC"))
}

// A version is reported once it has been listed for the settle period (45
// minutes by default), on the repository's clock: until then CloudFront may
// hand the backend a plain PACKAGES that predates it, and the backend would
// serve the tarball unverified. A package whose new version is held keeps its
// previous one meanwhile, rather than vanish from the copy.
func TestCRANSettleHoldsNewVersions(t *testing.T) {
	f, srv := cranTestFeed(t, nil)
	t0 := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	clock := t0
	f.src.now = func() time.Time { return clock }
	date := func() string { return clock.Format(http.TimeFormat) }
	index := string(fixture(t, "cran", "PACKAGES"))
	zzz := []byte("zzz_0.1.0.tar.gz bytes")
	jsonlite := []byte("jsonlite_2.0.1.tar.gz bytes")
	srv.on("GET", "/src/contrib/zzz_0.1.0.tar.gz").reply(200, zzz)
	srv.on("GET", "/src/contrib/jsonlite_2.0.1.tar.gz").reply(200, jsonlite)
	// zzz was published ten minutes ago; CloudFront's PACKAGES predates it.
	first := index + cranStanzaOf("zzz", "0.1.0", zzz, t0.Add(-10*time.Minute))
	srv.on("GET", "/src/contrib/PACKAGES").reply(200, []byte(index))
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(200, cranGzip(t, []byte(first))).once().
		withHeader("ETag", `"p0"`).withHeader("Last-Modified", t0.Add(-time.Minute).Format(http.TimeFormat)).withHeader("Date", date())
	backend, err := cran.New(cran.Options{Name: f.src.k.env.Upstream, UpstreamURL: f.src.k.env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[Matrix a11yShiny abind boot data.table jsonlite]" {
		t.Fatalf("the first read: %v %v", names(b.Items), err)
	}
	if got, err := cranBackendFetch(t, backend, "/src/contrib/zzz_0.1.0.tar.gz"); got != "none" || err != nil {
		t.Fatalf("the premise: the backend verified zzz (%q, %v) against a PACKAGES that does not list it", got, err)
	}
	// Twenty minutes on, jsonlite 2.0.1 supersedes 2.0.0: held, and 2.0.0
	// stays in the copy meanwhile — nothing is reported.
	clock = t0.Add(20 * time.Minute)
	second := strings.Replace(first, "Package: jsonlite\nVersion: 2.0.0\n", "Package: jsonlite\nVersion: 2.0.1\n", 1)
	second = strings.Replace(second, "MD5sum: 3e54e6fbc0c9063936e3d01e91419c14\n", fmt.Sprintf("MD5sum: %x\n", md5.Sum(jsonlite)), 1)
	second = strings.Replace(second, "Published: 2025-03-27 06:40:02 UTC", "Published: "+clock.Add(-time.Minute).Format("2006-01-02 15:04:05 UTC"), 1)
	srv.on("GET", "/src/contrib/PACKAGES.gz").requireHeader("If-None-Match", `"p0"`).reply(200, cranGzip(t, []byte(second))).once().
		withHeader("ETag", `"p1"`).withHeader("Date", date())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 {
		t.Fatalf("twenty minutes on: %+v %v", ch, err)
	}
	if rels, err := f.Releases(ctx, "jsonlite"); err != nil || len(rels) != 1 || rels[0].Version != "2.0.0" {
		t.Errorf("jsonlite while 2.0.1 settles: %+v %v", viewReleases(rels), err)
	}
	// 45 minutes after it was listed, zzz has settled: the index is read
	// again although it did not change, and zzz reported. PACKAGES has caught
	// up meanwhile: the backend verifies it.
	clock = t0.Add(44*time.Minute + time.Second)
	srv.on("GET", "/src/contrib/PACKAGES.gz").requireHeader("If-None-Match", "").reply(200, cranGzip(t, []byte(second))).once().
		withHeader("ETag", `"p1"`).withHeader("Date", date())
	srv.on("GET", "/src/contrib/PACKAGES").reply(200, []byte(second))
	ch, err = f.Changes(ctx, ch.Next)
	if err != nil || fmt.Sprint(ch.Items) != "[zzz]" {
		t.Fatalf("zzz settled: %+v %v", ch, err)
	}
	rels, err := f.Releases(ctx, "zzz")
	if err != nil {
		t.Fatal(err)
	}
	expectServed(t, backend, rels, func(Release, Artifact) (string, string) { return "zzz", "0.1.0" })
	if got, err := cranBackendFetch(t, backend, rels[0].Artifacts[0].Path); got != "md5" || err != nil {
		t.Errorf("zzz, once reported: verified %q, %v", got, err)
	}
	// jsonlite 2.0.1 settles 45 minutes after it was first seen.
	clock = t0.Add(65*time.Minute + time.Second)
	srv.on("GET", "/src/contrib/PACKAGES.gz").requireHeader("If-None-Match", "").reply(200, cranGzip(t, []byte(second))).once().
		withHeader("ETag", `"p1"`).withHeader("Date", date())
	ch, err = f.Changes(ctx, ch.Next)
	if err != nil || fmt.Sprint(ch.Items) != "[jsonlite@2.0.1 jsonlite@2.0.0]" || !ch.Items[1].Deleted {
		t.Fatalf("jsonlite settled: %+v %v", ch, err)
	}
	if rels, err := f.Releases(ctx, "jsonlite"); err != nil || len(rels) != 1 || rels[0].Version != "2.0.1" {
		t.Errorf("jsonlite settled: %+v %v", viewReleases(rels), err)
	}
	// Nothing held any more: conditional again.
	srv.on("GET", "/src/contrib/PACKAGES.gz").requireHeader("If-None-Match", `"p1"`).reply(http.StatusNotModified, nil).once()
	if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
		t.Fatalf("nothing held: %+v %v", ch, err)
	}
}

// S3 (and CloudFront in front of it) answers 403 for a key that does not
// exist: a refused PACKAGES.gz is passed over for PACKAGES. When neither
// answers and one was refused, the upstream is held.
func TestCRANRefusedDocuments(t *testing.T) {
	ctx := context.Background()
	f, srv := cranTestFeed(t, map[string]string{"settle": "0"})
	srv.on("GET", "/src/contrib/PACKAGES.gz").reply(http.StatusForbidden, []byte("<Error><Code>AccessDenied</Code></Error>"))
	srv.on("GET", "/src/contrib/PACKAGES").reply(200, fixture(t, "cran", "PACKAGES")).withHeader("ETag", cranETag)
	b, err := f.Bootstrap(ctx, "")
	if err != nil || len(b.Items) != 6 {
		t.Fatalf("a repository on S3: %v %v", names(b.Items), err)
	}
	// The next poll asks for PACKAGES.gz again, then for PACKAGES
	// conditionally; nothing is asked for twice.
	srv.on("GET", "/src/contrib/PACKAGES").requireHeader("If-None-Match", cranETag).reply(http.StatusNotModified, nil)
	before := len(srv.requests())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 || ch.Next != b.Next {
		t.Fatalf("an unchanged repository on S3: %+v %v", ch, err)
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET /src/contrib/PACKAGES.gz GET /src/contrib/PACKAGES" {
		t.Errorf("requests: %s", got)
	}
	for name, statuses := range map[string][2]int{
		"both refused":             {http.StatusUnauthorized, http.StatusUnauthorized},
		"refused, then not found":  {http.StatusForbidden, http.StatusNotFound},
		"not found, then refused":  {http.StatusNotFound, http.StatusForbidden},
		"refused by a proxy first": {http.StatusProxyAuthRequired, http.StatusNotFound},
	} {
		srv.on("GET", "/src/contrib/PACKAGES.gz").reply(statuses[0], nil)
		srv.on("GET", "/src/contrib/PACKAGES").reply(statuses[1], nil)
		for _, poll := range []func() error{
			func() error { _, err := f.Bootstrap(ctx, ""); return err },
			func() error { _, err := f.Changes(ctx, ch.Next); return err },
		} {
			err := poll()
			if d, ok := RetryAfterOf(err); !ok || d != holdAfterRefusal || IsPermanent(err) {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// After a 404 of PACKAGES.gz (a CDN's hiccup) the feed reads PACKAGES — four
// times the bytes — only until PACKAGES.gz answers again: it is asked for at
// every poll. One that does not answer otherwise (a 5xx) does not fail the
// poll.
func TestCRANAsksForTheCompressedIndexAgain(t *testing.T) {
	ctx := context.Background()
	f, srv := cranTestFeed(t, map[string]string{"settle": "0"})
	index := fixture(t, "cran", "PACKAGES")
	const gz, plain = "/src/contrib/PACKAGES.gz", "/src/contrib/PACKAGES"
	srv.on("GET", gz).reply(http.StatusNotFound, nil)
	srv.on("GET", plain).reply(200, index).withHeader("ETag", `"plain-1"`)
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.on("GET", plain).requireHeader("If-None-Match", `"plain-1"`).reply(http.StatusNotModified, nil)
	before := len(srv.requests())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 {
		t.Fatalf("still no PACKAGES.gz: %+v %v", ch, err)
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET "+gz+" GET "+plain {
		t.Errorf("requests: %s", got)
	}
	srv.on("GET", gz).reply(http.StatusBadGateway, nil)
	if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
		t.Fatalf("a PACKAGES.gz answering 502: %+v %v", ch, err)
	}
	srv.on("GET", gz).reply(200, cranGzip(t, index)).withHeader("ETag", `"gz-1"`)
	srv.on("GET", gz).requireHeader("If-None-Match", `"gz-1"`).reply(http.StatusNotModified, nil)
	before = len(srv.requests())
	for i := 0; i < 3; i++ {
		if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
			t.Fatalf("poll %d with PACKAGES.gz back: %+v %v", i, ch, err)
		}
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET "+gz+" GET "+gz+" GET "+gz {
		t.Errorf("requests: %s", got)
	}
}
