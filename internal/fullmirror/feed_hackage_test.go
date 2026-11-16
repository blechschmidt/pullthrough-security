package fullmirror

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/hackage"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The recorded end of hackage.haskell.org's 01-index.tar (2026-11-16): its
// last 16 KiB, from offset hackageTailBase of an index of hackageTailTotal
// bytes. Four entries — seihou-okf-extension's and password's .cabal
// revisions, then time-manager 0.4.2's upload (package.json, then its .cabal)
// — and the two zero blocks that end the archive.
const (
	hackageTailBase  = 1054601728
	hackageTailTotal = 1054618112
	// Offsets of the entries' headers in the index.
	hackageSeihouHeader      = 1054601728
	hackageSeihouEnd         = 1054605824
	hackageTimeManagerHeader = 1054614528
	hackageTailEnd           = 1054617088
)

// hackageTestFeed builds the adapter against a fixture server standing in
// for hackage.haskell.org.
func hackageTestFeed(t *testing.T) (*hackageFeed, *fixtureServer) {
	t.Helper()
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "hackage", srv.URL(), newFakeReads(), nil)).(*hackageFeed)
	return f, srv
}

// hackageHeaderSum is the SHA-256 of the header block at an offset of the
// recorded tail.
func hackageHeaderSum(t *testing.T, tail []byte, off int64) string {
	t.Helper()
	rel := off - hackageTailBase
	sum := sha256.Sum256(tail[rel : rel+512])
	return hex.EncodeToString(sum[:])
}

// hackageServeRange answers one Range request for the recorded tail.
func hackageServeRange(srv *fixtureServer, tail []byte, first, last int64) {
	end := last
	if end > hackageTailTotal-1 {
		end = hackageTailTotal - 1
	}
	srv.on("GET", "/01-index.tar").
		requireHeader("Range", fmt.Sprintf("bytes=%d-%d", first, last)).
		reply(http.StatusPartialContent, tail[first-hackageTailBase:end-hackageTailBase+1]).
		withHeader("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, end, hackageTailTotal)).
		withHeader("Last-Modified", "Sun, 15 Nov 2026 23:39:56 GMT")
}

func TestHackageFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://hackage.haskell.org", nil, "https://hackage.haskell.org"},
		{"https://hackage.internal.example/hackage/", nil, "https://hackage.internal.example/hackage"},
		{"https://hackage-mirror.internal.example", map[string]string{"url": "https://hackage.haskell.org/"}, "https://hackage.haskell.org"},
	} {
		f, err := hackageNewFeed(Env{Upstream: "h", Type: "hackage", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*hackageFeed).feed.String(); got != tc.want {
			t.Errorf("%s: feed %s, want %s", tc.url, got, tc.want)
		}
		// The index is always the upstream's: what the feed reports is what
		// the sdists come from.
		if got, want := f.(*hackageFeed).indexURL(), strings.TrimRight(tc.url, "/")+"/01-index.tar"; got != want {
			t.Errorf("%s: index %s, want %s", tc.url, got, want)
		}
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "ftp://x"}, {"url": "https://u:p@x"}, {"url": "https://x/?q=1"}} {
		if err := Check(Env{Upstream: "h", Type: "hackage", URL: "https://hackage.haskell.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
	if err := Check(Env{Upstream: "h", Type: "hackage", URL: "not a url"}); err == nil {
		t.Errorf("Check accepted a bad upstream URL")
	}
}

func TestHackageBootstrapListsEveryNameThenFollowsFromTheIndexEnd(t *testing.T) {
	f, srv := hackageTestFeed(t)
	tail := fixture(t, "hackage", "index-tail.bin")
	f.page = 4
	// The last KiB holds only the end-of-archive blocks: the next, longer
	// read finds the last entry's header.
	f.tails = []int64{1024, 16384}
	srv.on("HEAD", "/01-index.tar").reply(http.StatusOK, nil).withHeader("Content-Length", strconv.Itoa(hackageTailTotal))
	hackageServeRange(srv, tail, hackageTailTotal-1024, hackageTailTotal-1)
	hackageServeRange(srv, tail, hackageTailBase, hackageTailTotal-1)
	srv.on("GET", "/packages/").requireHeader("Accept", "application/json").reply(http.StatusOK, fixture(t, "hackage", "packages.json"))
	ctx := context.Background()

	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "hackage", "bootstrap-page-1", viewBatch(t, first))
	if !first.More {
		t.Fatalf("a full page must ask for more")
	}
	var b Batch
	cur := first.Next
	var all []string
	all = append(all, names(first.Items)...)
	for i := 0; i < 5; i++ {
		if b, err = f.Bootstrap(ctx, cur); err != nil {
			t.Fatal(err)
		}
		all = append(all, names(b.Items)...)
		cur = b.Next
		if !b.More {
			break
		}
	}
	checkGolden(t, "hackage", "bootstrap-last-page", viewBatch(t, b))
	if got := strings.Join(all, " "); got != "2captcha 3d-graphics-examples 4Blocks A-gent AC-Angle base64 password seihou-okf-extension time-manager zyre2" {
		t.Errorf("listed %s", got)
	}
	// The listing ends with the cursor of the index's end as it was when the
	// listing began: after time-manager 0.4.2's .cabal.
	var c hackageCursor
	if err := f.decode(b.Next, &c); err != nil || c.Listing || c.End != hackageTailEnd || c.Header != hackageTimeManagerHeader || c.SHA256 != hackageHeaderSum(t, tail, hackageTimeManagerHeader) {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	if _, err := f.Changes(ctx, first.Next); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, b.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

func TestHackageChangesReadTheUploadsAfterTheCursor(t *testing.T) {
	f, srv := hackageTestFeed(t)
	tail := fixture(t, "hackage", "index-tail.bin")
	ctx := context.Background()
	// A cursor taken after seihou-okf-extension's revision: what follows in
	// the recorded index is password's revision (no upload) and
	// time-manager 0.4.2's upload.
	cur := encodeCursor(&hackageCursor{Format: f.format(), End: hackageSeihouEnd, Header: hackageSeihouHeader, SHA256: hackageHeaderSum(t, tail, hackageSeihouHeader)})
	hackageServeRange(srv, tail, hackageSeihouHeader, hackageSeihouHeader+f.window-1)
	b, err := f.Changes(ctx, cur)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "hackage", "changes", viewBatch(t, b))
	if b.More || !b.LagKnown || len(b.Items) != 1 || b.Items[0] != (Coordinate{Name: "time-manager", Version: "0.4.2"}) {
		t.Fatalf("batch %+v", b)
	}
	// From the end, nothing is new: the cursor stays.
	hackageServeRange(srv, tail, hackageTimeManagerHeader, hackageTimeManagerHeader+f.window-1)
	again, err := f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Items) != 0 || again.More || again.Next != b.Next || again.Head != strconv.Itoa(hackageTailTotal) {
		t.Errorf("caught up: %+v", again)
	}
}

// hackageIndexServer serves an index whose bytes from offset base on are
// data, with Range requests as hackage.haskell.org answers them.
func hackageIndexServer(t *testing.T, data []byte, base int64) *httptest.Server {
	t.Helper()
	total := base + int64(len(data))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/01-index.tar" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		var first, last int64
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &first, &last); err != nil || first < base {
			t.Errorf("unexpected range %q", r.Header.Get("Range"))
			http.Error(w, "bad range", http.StatusBadRequest)
			return
		}
		if first >= total {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if last >= total {
			last = total - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, total))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(data[first-base : last-base+1])
	}))
	t.Cleanup(srv.Close)
	return srv
}

// hackageAppend appends tar entries (ustar, as hackage-server writes them)
// to the recorded tail in place of its end-of-archive blocks.
func hackageAppend(t *testing.T, tail []byte, entries ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(tail[:hackageTailEnd-hackageTailBase])
	tw := tar.NewWriter(&buf)
	mtime := time.Date(2026, 11, 16, 4, 0, 0, 0, time.UTC)
	for i, name := range entries {
		body := []byte(`{"signed":{"_type":"Targets"}}`)
		if strings.HasSuffix(name, ".cabal") {
			body = []byte("cabal-version: 3.0\nname: x\n")
		}
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)), ModTime: mtime.Add(time.Duration(i) * time.Second),
			Uname: "Hackage", Gname: "Hackage", Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil { // writes the two zero blocks
		t.Fatal(err)
	}
	out := buf.Bytes()
	return out[:len(out)-len(out)%512]
}

func TestHackageChangesFollowAppendedEntriesWindowByWindow(t *testing.T) {
	tail := fixture(t, "hackage", "index-tail.bin")
	grown := hackageAppend(t, tail,
		"time-manager/0.4.3/package.json", "time-manager/0.4.3/time-manager.cabal",
		"base64/2.1/base64.cabal", // a revision: no upload
		"Bad Name/1.0/package.json", "aeson/1.0-beta/package.json", "aeson/2.3.2.0/extra/package.json",
		"aeson/2.3.2.0/package.json", "aeson/2.3.2.0/aeson.cabal",
		"seihou-okf-extension/0.16.0.2/package.json")
	srv := hackageIndexServer(t, grown, hackageTailBase)
	f := mustFeed(t, testEnv(t, "hackage", srv.URL, nil, nil)).(*hackageFeed)
	// Three blocks a window: the cursor's entry (5 blocks) does not fit with
	// another, so the window is the cursor's entry and the next two entries.
	f.window = 9 * 512
	ctx := context.Background()
	cur := encodeCursor(&hackageCursor{Format: f.format(), End: hackageTailEnd, Header: hackageTimeManagerHeader, SHA256: hackageHeaderSum(t, tail, hackageTimeManagerHeader)})
	var got []string
	polls := 0
	for ; polls < 20; polls++ {
		b, err := f.Changes(ctx, cur)
		if err != nil {
			t.Fatalf("poll %d: %v", polls, err)
		}
		got = append(got, names(b.Items)...)
		cur = b.Next
		if !b.More {
			if !b.LagKnown {
				t.Errorf("the last poll does not say it caught up")
			}
			break
		}
	}
	if want := "time-manager@0.4.3 aeson@2.3.2.0 seihou-okf-extension@0.16.0.2"; strings.Join(got, " ") != want {
		t.Errorf("uploads %v, want %s", got, want)
	}
	if polls < 3 {
		t.Errorf("read in %d polls; the window should have cut it", polls)
	}
	var c hackageCursor
	if err := f.decode(cur, &c); err != nil || c.End != int64(hackageTailBase+len(grown)-1024) {
		t.Errorf("final cursor %+v (%v), want the end at %d", c, err, hackageTailBase+len(grown)-1024)
	}
}

func TestHackageCursorThatDoesNotMatchTheIndexIsInvalid(t *testing.T) {
	tail := fixture(t, "hackage", "index-tail.bin")
	srv := hackageIndexServer(t, tail, hackageTailBase)
	f := mustFeed(t, testEnv(t, "hackage", srv.URL, nil, nil)).(*hackageFeed)
	ctx := context.Background()
	good := hackageHeaderSum(t, tail, hackageTimeManagerHeader)
	for name, c := range map[string]hackageCursor{
		// Another index (a mirror's, a rebuilt one) has other bytes there.
		"header hash": {End: hackageTailEnd, Header: hackageTimeManagerHeader, SHA256: strings.Repeat("0", 64)},
		// The index is shorter than the cursor.
		"beyond the end": {End: hackageTailTotal + 4096, Header: hackageTailTotal + 512, SHA256: good},
		// The entry's size does not lead to End.
		"end": {End: hackageTailEnd + 512, Header: hackageTimeManagerHeader, SHA256: good},
	} {
		c.Format = f.format()
		_, err := f.Changes(ctx, encodeCursor(&c))
		if name == "beyond the end" {
			// A shorter index may be a cache behind: retried twice, then
			// taken for a replaced index.
			mustErr(t, err, false, false, "1 of 3")
			_, err = f.Changes(ctx, encodeCursor(&c))
			mustErr(t, err, false, false, "2 of 3")
			_, err = f.Changes(ctx, encodeCursor(&c))
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, false, true, "")
	}
	for _, bad := range []string{"x", `{"format":"npm/1","since":"1"}`, `{"format":"hackage/1","end":1024,"header":0,"sha256":"` + good + `","x":1}`,
		`{"format":"hackage/1","end":1000,"header":0,"sha256":"` + good + `"}`, `{"format":"hackage/1","end":-512,"header":-1}`,
		`{"format":"hackage/1","end":512,"header":-1}`, `{"format":"hackage/1","end":1024,"header":768,"sha256":"` + good + `"}`,
		`{"format":"hackage/1","end":1024,"header":0,"sha256":"ABC"}`, `{"format":"hackage/1","end":0,"header":-1,"listing":true,"after":"../x"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestHackageMalformedIndexAnswers(t *testing.T) {
	tail := fixture(t, "hackage", "index-tail.bin")
	ctx := context.Background()
	cur := hackageCursor{End: hackageTailEnd, Header: hackageTimeManagerHeader, SHA256: hackageHeaderSum(t, tail, hackageTimeManagerHeader)}

	// Garbage where the next header should be.
	garbled := append(append([]byte(nil), tail[:hackageTailEnd-hackageTailBase]...), bytes.Repeat([]byte("x"), 1024)...)
	f := mustFeed(t, testEnv(t, "hackage", hackageIndexServer(t, garbled, hackageTailBase).URL, nil, nil)).(*hackageFeed)
	cur.Format = f.format()
	_, err := f.Changes(ctx, encodeCursor(&cur))
	mustErr(t, err, true, false, "not a tar header")

	// An index read to its end without the end-of-archive blocks is being
	// replaced: try again.
	cut := tail[:hackageTailEnd-hackageTailBase]
	f = mustFeed(t, testEnv(t, "hackage", hackageIndexServer(t, cut, hackageTailBase).URL, nil, nil)).(*hackageFeed)
	_, err = f.Changes(ctx, encodeCursor(&cur))
	mustErr(t, err, false, false, "without its end-of-archive")

	// A server that ignores Range cannot be followed.
	f2, srv := hackageTestFeed(t)
	srv.on("GET", "/01-index.tar").reply(http.StatusOK, tail)
	cur.Format = f2.format()
	_, err = f2.Changes(ctx, encodeCursor(&cur))
	mustErr(t, err, true, false, "ignores Range")
	// A Content-Range that is not the one asked for.
	srv.on("GET", "/01-index.tar").reply(http.StatusPartialContent, tail).withHeader("Content-Range", "bytes 0-16383/16384")
	_, err = f2.Changes(ctx, encodeCursor(&cur))
	mustErr(t, err, true, false, "Content-Range")
	// The registry's errors.
	srv.on("GET", "/01-index.tar").reply(http.StatusBadGateway, nil)
	_, err = f2.Changes(ctx, encodeCursor(&cur))
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/01-index.tar").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "30")
	_, err = f2.Changes(ctx, encodeCursor(&cur))
	if d, ok := RetryAfterOf(err); !ok || d != 30*time.Second {
		t.Errorf("Retry-After not carried: %v", err)
	}

	// Bootstrap: an index that is not a tar archive, and one whose end has
	// no chain of headers.
	f3, srv3 := hackageTestFeed(t)
	f3.tails = []int64{16384}
	srv3.on("HEAD", "/01-index.tar").reply(http.StatusOK, nil).withHeader("Content-Length", "1000")
	_, err = f3.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "not a tar archive")
	srv3.on("HEAD", "/01-index.tar").reply(http.StatusOK, nil).withHeader("Content-Length", "16384")
	srv3.on("GET", "/01-index.tar").requireHeader("Range", "bytes=0-16383").reply(http.StatusPartialContent, bytes.Repeat([]byte("y"), 16384)).withHeader("Content-Range", "bytes 0-16383/16384")
	_, err = f3.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "no chain of tar headers")
	// The index grew between the HEAD and the read: try again.
	srv3.on("GET", "/01-index.tar").requireHeader("Range", "bytes=0-16383").reply(http.StatusPartialContent, tail).withHeader("Content-Range", "bytes 0-16383/20480")
	_, err = f3.Bootstrap(ctx, "")
	mustErr(t, err, false, false, "changed")
	// The package list.
	srv3.on("HEAD", "/01-index.tar").reply(http.StatusOK, nil).withHeader("Content-Length", "0")
	for body, want := range map[string]string{`<html>`: "not the JSON document", `{"packageName":"x"}`: "not the JSON document", `null`: "not a list"} {
		srv3.on("GET", "/packages/").json(body)
		_, err = f3.Bootstrap(ctx, "")
		mustErr(t, err, true, false, want)
	}
}

func TestHackageEmptyIndex(t *testing.T) {
	// A hackage-server nothing has been uploaded to yet.
	f, srv := hackageTestFeed(t)
	srv.on("HEAD", "/01-index.tar").reply(http.StatusOK, nil).withHeader("Content-Length", "1024")
	srv.on("GET", "/01-index.tar").requireHeader("Range", "bytes=0-1023").reply(http.StatusPartialContent, make([]byte, 1024)).withHeader("Content-Range", "bytes 0-1023/1024")
	srv.on("GET", "/packages/").json(`[]`)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var c hackageCursor
	if err := f.decode(b.Next, &c); err != nil || b.More || len(b.Items) != 0 || c.Header != -1 || c.End != 0 {
		t.Fatalf("bootstrap %+v cursor %+v (%v)", b, c, err)
	}
	srv.on("GET", "/01-index.tar").requireHeader("Range", fmt.Sprintf("bytes=0-%d", f.window-1)).reply(http.StatusPartialContent, make([]byte, 1024)).withHeader("Content-Range", "bytes 0-1023/1024")
	if again, err := f.Changes(ctx, b.Next); err != nil || len(again.Items) != 0 || again.Next != b.Next {
		t.Errorf("changes of an empty index: %+v, %v", again, err)
	}
	// The first upload.
	tail := fixture(t, "hackage", "index-tail.bin")
	first := tail[hackageTimeManagerHeader-1024-hackageTailBase:] // its package.json, then its .cabal
	srv.on("GET", "/01-index.tar").requireHeader("Range", fmt.Sprintf("bytes=0-%d", f.window-1)).reply(http.StatusPartialContent, first).withHeader("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(first)-1, len(first)))
	got, err := f.Changes(ctx, b.Next)
	if err != nil || len(got.Items) != 1 || got.Items[0] != (Coordinate{Name: "time-manager", Version: "0.4.2"}) {
		t.Errorf("changes after the first upload: %+v, %v", got, err)
	}
}

func TestHackageReleasesComeFromThePreferredVersions(t *testing.T) {
	f, srv := hackageTestFeed(t)
	ctx := context.Background()
	srv.on("GET", "/package/time-manager/preferred").requireHeader("Accept", "application/json").reply(http.StatusOK, fixture(t, "hackage", "preferred-time-manager.json"))
	srv.on("GET", "/package/base64/preferred").requireHeader("Accept", "application/json").reply(http.StatusOK, fixture(t, "hackage", "preferred-base64.json"))
	backend, err := hackage.New(hackage.Options{Name: f.k.env.Upstream, UpstreamURL: "https://hackage.haskell.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"time-manager", "base64"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "hackage", "releases-"+name, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	// Deprecated versions are yanked; the order is Hackage's version order.
	rels, _ := f.Releases(ctx, "time-manager")
	var yanked []string
	for _, r := range rels {
		if r.Yanked {
			yanked = append(yanked, r.Version)
		}
	}
	if got := strings.Join(yanked, " "); got != "0.3.0 0.4.0 0.5.0" {
		t.Errorf("yanked %s", got)
	}
	if rels[0].Version != "0.0.0" || rels[len(rels)-1].Version != "0.5.2" {
		t.Errorf("order %s .. %s", rels[0].Version, rels[len(rels)-1].Version)
	}

	// An unknown package (Hackage answers 404 with a text body), a name that
	// is not one, malformed documents, the registry's errors.
	srv.on("GET", "/package/no-such-package/preferred").reply(http.StatusNotFound, []byte("Package not found: No such package in package index"))
	_, err = f.Releases(ctx, "no-such-package")
	mustErr(t, err, true, false, "not found")
	for _, bad := range []string{"../etc", "a/b", "", "1-2", "x y"} {
		_, err = f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a Hackage package name")
	}
	for body, want := range map[string]string{
		`<!DOCTYPE html>`:                     "not the JSON document",
		`{"normal-version":"1.0"}`:            "not a list of versions",
		`{"name":"x"}`:                        "lists no versions",
		`{"normal-version":["1.0-beta","x"]}`: "name no version",
		`["1.0"]`:                             "not the JSON document",
		`{"normal-version":[1.0]}`:            "not a list of versions",
		`{"deprecated-version":null}`:         "name no version",
		`{"normal-version":["` + strings.Repeat("1.", 70) + `1"]}`: "name no version",
	} {
		srv.on("GET", "/package/broken/preferred").json(body)
		_, err = f.Releases(ctx, "broken")
		mustErr(t, err, true, false, want)
	}
	srv.on("GET", "/package/flaky/preferred").reply(http.StatusServiceUnavailable, nil)
	_, err = f.Releases(ctx, "flaky")
	mustErr(t, err, false, false, "503")
	// The documents come from the repository itself: the hackage backend
	// serves neither /packages/ nor /package/<name>/preferred, so no gate
	// judges them (the sdists are gated when the engine fetches them).
}

func TestHackageHeaderParsing(t *testing.T) {
	// A header Go's archive/tar writes in the ustar format, with a name
	// long enough to use the prefix field.
	long := strings.Repeat("a", 60) + "/" + strings.Repeat("1.", 30) + "0/" + "package.json"
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: long, Typeflag: tar.TypeReg, Size: 700, Mode: 0o644, ModTime: time.Unix(1794785996, 0), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	name, size, mtime, typ, ok := hackageHeader(buf.Bytes()[:512])
	if !ok || name != long || size != 700 || mtime != 1794785996 || typ != '0' {
		t.Errorf("parsed %q %d %d %q %v", name, size, mtime, typ, ok)
	}
	blk := append([]byte(nil), buf.Bytes()[:512]...)
	blk[0] ^= 1 // the checksum no longer matches
	if _, _, _, _, ok := hackageHeader(blk); ok {
		t.Errorf("a header with a bad checksum was read")
	}
	if _, _, _, _, ok := hackageHeader(make([]byte, 512)); ok {
		t.Errorf("a zero block was read as a header")
	}
	if _, _, _, _, ok := hackageHeader(blk[:100]); ok {
		t.Errorf("a short block was read as a header")
	}
	for s, want := range map[string]bool{"time-manager": true, "2captcha": true, "HUnit": true, "a": true, "1-2": false, "a--b": false, "-a": false, "a-": false, "a_b": false, "": false} {
		if hackageIsName(s) != want {
			t.Errorf("hackageIsName(%q) = %v", s, !want)
		}
	}
	for s, want := range map[string]bool{"0": true, "0.4.2.4": true, "1.0-beta": false, "1..2": false, ".1": false, "v1": false, "1234567890": false} {
		if hackageIsVersion(s) != want {
			t.Errorf("hackageIsVersion(%q) = %v", s, !want)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.9", "1.10", -1}, {"1.0", "1", 1}, {"0.4.2.4", "0.4.2.4", 0}, {"2.0", "10.0", -1}, {"01", "1", -1}} {
		if got := hackageCompareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestHackageTailSearchIsLinear(t *testing.T) {
	// The longest end Bootstrap reads, every block of it a valid header of
	// an empty entry and no end-of-archive blocks: each block starts a chain
	// that runs to the end. Trying the chains one by one would walk
	// hackageMaxTailCandidates of them; a block a failed chain went through
	// is not walked again.
	var hdr bytes.Buffer
	tw := tar.NewWriter(&hdr)
	if err := tw.WriteHeader(&tar.Header{Name: "a/1/package.json", Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	n := hackageTails[len(hackageTails)-1]
	buf := bytes.Repeat(hdr.Bytes()[:512], int(n/512))
	start := time.Now()
	if c, ok := hackageTailCursor(buf, 1<<30, 1<<30+n); ok {
		t.Fatalf("a chain without end blocks was taken: %+v", c)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the search took %s", d)
	}
	// The same with the end blocks: the first header's chain is taken.
	buf = append(buf[:n-1024], make([]byte, 1024)...)
	c, ok := hackageTailCursor(buf, 1<<30, 1<<30+n)
	if !ok || c.End != 1<<30+n-1024 || c.Header != 1<<30+n-1536 {
		t.Errorf("cursor %+v %v", c, ok)
	}
}
