package fullmirror

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/rubygems"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// rubygemsTestServer stands in for rubygems.org's /versions as it answered on
// 2026-11-16: the ETag is the file's MD5, Repr-Digest and Digest its SHA-256
// (`sha-256="<base64>"`), a Range from an offset inside the file is answered
// 206 with Content-Range, a Range past its end with the whole file (200, not
// 416), and a matching If-None-Match with 304.
type rubygemsTestServer struct {
	t    *testing.T
	srv  *httptest.Server
	mu   sync.Mutex
	file []byte
	// digestOf, when set, is what the digest headers describe instead of the
	// file (a stale header); noDigest leaves them out; ignoreRange answers
	// every request with the whole file; short cuts a 206 body that many
	// bytes short of its Content-Range.
	digestOf    []byte
	noDigest    bool
	ignoreRange bool
	short       int
	log         []string
}

func rubygemsNewTestServer(t *testing.T, file []byte) *rubygemsTestServer {
	t.Helper()
	s := &rubygemsTestServer{t: t, file: file}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *rubygemsTestServer) set(file []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.file = file
}

func (s *rubygemsTestServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
}

func (s *rubygemsTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path != "/versions" || r.Method != http.MethodGet {
		s.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
		return
	}
	s.log = append(s.log, "GET "+r.Header.Get("Range"))
	sum := md5.Sum(s.file)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Last-Modified", "Mon, 16 Nov 2026 02:11:03 GMT")
	h.Set("Accept-Ranges", "bytes")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	if !s.noDigest {
		of := s.file
		if s.digestOf != nil {
			of = s.digestOf
		}
		d := sha256.Sum256(of)
		v := `sha-256="` + base64.StdEncoding.EncodeToString(d[:]) + `"`
		h.Set("Digest", v)
		h.Set("Repr-Digest", v)
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if rg := r.Header.Get("Range"); rg != "" && !s.ignoreRange {
		a, b, _ := strings.Cut(strings.TrimPrefix(rg, "bytes="), "-")
		from, _ := strconv.ParseInt(a, 10, 64)
		to := int64(-1)
		if b != "" {
			to, _ = strconv.ParseInt(b, 10, 64)
		}
		if n := int64(len(s.file)); from < n {
			if to < 0 || to >= n {
				to = n - 1
			}
			body := s.file[from : to+1]
			h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, n))
			if s.short > 0 && len(body) > s.short {
				body = body[:len(body)-s.short]
			}
			h.Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body)
			return
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(s.file)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.file)
}

// rubygemsTestFeed builds the adapter against a rubygemsTestServer serving
// file as /versions.
func rubygemsTestFeed(t *testing.T, file []byte) (*rubygemsFeed, *rubygemsTestServer, *fakeReads) {
	t.Helper()
	srv := rubygemsNewTestServer(t, file)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "rubygems", srv.srv.URL, reads, nil)).(*rubygemsFeed)
	return f, srv, reads
}

// rubygemsBootstrapAll runs Bootstrap to its end and returns the follow
// cursor.
func rubygemsBootstrapAll(t *testing.T, f *rubygemsFeed) string {
	t.Helper()
	cursor := ""
	for i := 0; i < 100; i++ {
		b, err := f.Bootstrap(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		if !b.More {
			return b.Next
		}
		cursor = b.Next
	}
	t.Fatal("the listing does not end")
	return ""
}

// rubygemsTestRewrite is what rubygems.org makes of /versions at the start of
// a month ("recalculated at the start of each month, removing yanked
// rubygems"): one line per gem, sorted by name, its live versions in the
// order they were added, the MD5 of its last line; a gem left without a
// version is dropped. The monthly rewrite cannot be recorded ahead of time,
// so the tests build it from the recorded lines.
func rubygemsTestRewrite(file []byte, created string) []byte {
	type gem struct {
		versions []string
		md5      string
	}
	gems := map[string]*gem{}
	var order []string
	body := false
	for _, line := range strings.Split(string(file), "\n") {
		if !body {
			body = line == "---"
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		g := gems[fields[0]]
		if g == nil {
			g = &gem{}
			gems[fields[0]] = g
			order = append(order, fields[0])
		}
		for _, v := range strings.Split(fields[1], ",") {
			if tok, yank := strings.CutPrefix(v, "-"); yank {
				kept := g.versions[:0]
				for _, x := range g.versions {
					if x != tok {
						kept = append(kept, x)
					}
				}
				g.versions = kept
			} else if !rubygemsContains(g.versions, v) {
				g.versions = append(g.versions, v)
			}
		}
		g.md5 = fields[2]
	}
	sort.Strings(order)
	var b strings.Builder
	b.WriteString("created_at: " + created + "\n---\n")
	for _, n := range order {
		if g := gems[n]; len(g.versions) > 0 {
			fmt.Fprintf(&b, "%s %s %s\n", n, strings.Join(g.versions, ","), g.md5)
		}
	}
	return []byte(b.String())
}

// rubygemsNovember is the copy at the bootstrap and what was appended after.
func rubygemsNovember(t *testing.T) (copyAt, tail []byte) {
	t.Helper()
	return fixture(t, "rubygems", "versions.txt"), fixture(t, "rubygems", "versions-tail.txt")
}

func rubygemsCat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestRubyGemsFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://rubygems.org", nil, "https://rubygems.org/versions"},
		{"https://gems.internal.example/private/", nil, "https://gems.internal.example/private/versions"},
		{"https://rubygems.org", map[string]string{"url": "https://index.rubygems.org/"}, "https://index.rubygems.org/versions"},
	} {
		f, err := rubygemsNewFeed(Env{Upstream: "g", Type: "rubygems", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*rubygemsFeed).versionsURL(); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.url, got, tc.want)
		}
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "ftp://x"}, {"url": "https://u:p@x"}} {
		if err := Check(Env{Upstream: "g", Type: "rubygems", URL: "https://rubygems.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestRubyGemsBootstrapListsEveryGemOfTheCopy(t *testing.T) {
	base, _ := rubygemsNovember(t)
	f, srv, _ := rubygemsTestFeed(t, base)
	f.page = 4
	ctx := context.Background()
	var batches []Batch
	cursor := ""
	for i := 1; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		checkGolden(t, "rubygems", fmt.Sprintf("bootstrap-page-%d", i), viewBatch(t, b))
		batches = append(batches, b)
		if !b.More {
			break
		}
		cursor = b.Next
	}
	if len(batches) != 3 {
		t.Fatalf("%d batches", len(batches))
	}
	// One download; the copy is the file as served.
	if got := fmt.Sprint(srv.requests()); got != "[GET ]" {
		t.Errorf("requests %s", got)
	}
	last := batches[len(batches)-1]
	var c rubygemsCursor
	if err := decodeCursor(last.Next, f.format(), &c); err != nil || c.Listing || c.Size != int64(len(base)) || c.Created != "2026-11-01T00:00:04Z" {
		t.Fatalf("final cursor %+v (%v)", c, err)
	}
	if data, err := os.ReadFile(f.files.path(rubygemsCopyName(c.Gen))); err != nil || !bytes.Equal(data, base) {
		t.Errorf("the copy: %v", err)
	}
	if _, err := f.Changes(ctx, batches[0].Next); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, last.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

func TestRubyGemsChangesReadTheTail(t *testing.T) {
	base, tail := rubygemsNovember(t)
	f, srv, _ := rubygemsTestFeed(t, base)
	ctx := context.Background()
	boot := rubygemsBootstrapAll(t, f)
	srv.set(rubygemsCat(base, tail))
	// The bytes after the copy: yanks are skipped, a platform release is one
	// version.
	b, err := f.Changes(ctx, boot)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "rubygems", "changes", viewBatch(t, b))
	reqs := srv.requests()
	if got, want := reqs[len(reqs)-1], fmt.Sprintf("GET bytes=%d-", len(base)-1); got != want {
		t.Errorf("request %q, want %q", got, want)
	}
	var c rubygemsCursor
	if err := decodeCursor(b.Next, f.format(), &c); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(f.files.path(rubygemsCopyName(c.Gen))); err != nil || !bytes.Equal(data, rubygemsCat(base, tail)) {
		t.Errorf("the copy was not extended: %v", err)
	}
	// Nothing new since: a 304, the same cursor.
	again, err := f.Changes(ctx, b.Next)
	if err != nil || again.Next != b.Next || len(again.Items) != 0 || again.More {
		t.Errorf("nothing new: %+v (%v)", again, err)
	}
	// The engine asks again from the cursor it had (it never committed the
	// batch): the copy is longer, but its first bytes still match.
	retry, err := f.Changes(ctx, boot)
	if err != nil || retry.Next != b.Next || fmt.Sprint(retry.Items) != fmt.Sprint(b.Items) {
		t.Errorf("asked again: %v (%v)", names(retry.Items), err)
	}
}

func TestRubyGemsMonthlyRewrite(t *testing.T) {
	ctx := context.Background()
	base, tail := rubygemsNovember(t)
	november := rubygemsCat(base, tail)
	december := rubygemsTestRewrite(november, "2026-12-01T00:00:04Z")
	if len(december) <= len(base) {
		t.Fatalf("the rewrite (%d bytes) is not longer than the copy (%d)", len(december), len(base))
	}

	// The rewritten file is longer than the copy: its bytes from the copy's
	// end come back (206), but the copy and they do not hash to the file's
	// digest. The whole file is fetched and diffed against the copy.
	f, srv, _ := rubygemsTestFeed(t, base)
	boot := rubygemsBootstrapAll(t, f)
	srv.set(december)
	b, err := f.Changes(ctx, boot)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "rubygems", "rewrite", viewBatch(t, b))
	reqs := srv.requests()
	if got := fmt.Sprint(reqs[len(reqs)-2:]); got != fmt.Sprintf("[GET bytes=%d- GET ]", len(base)-1) {
		t.Errorf("requests %s", got)
	}
	copies, _ := filepath.Glob(filepath.Join(f.files.dir, rubygemsCopyPrefix+"*"))
	if len(copies) != 2 {
		t.Errorf("copies after the rewrite %v, want the old and the new", copies)
	}
	next, err := f.Changes(ctx, b.Next)
	if err != nil || len(next.Items) != 0 || next.Next != b.Next {
		t.Errorf("after the rewrite: %+v (%v)", next, err)
	}
	if copies, _ = filepath.Glob(filepath.Join(f.files.dir, rubygemsCopyPrefix+"*")); len(copies) > 2 {
		t.Errorf("copies %v, want the new and at most the newest older one", copies)
	}

	// A server that ignores Range answers with the whole file: the same.
	g, srv2, _ := rubygemsTestFeed(t, base)
	boot2 := rubygemsBootstrapAll(t, g)
	srv2.ignoreRange = true
	srv2.set(december)
	b2, err := g.Changes(ctx, boot2)
	if err != nil || fmt.Sprint(b2.Items) != fmt.Sprint(b.Items) {
		t.Errorf("a whole-file answer: %v (%v)", names(b2.Items), err)
	}

	// After November's tail the rewrite is shorter than the copy: the range
	// starts past its end and rubygems.org answers with the whole file. A
	// version appended after the follower's last poll is in it.
	h, srv3, _ := rubygemsTestFeed(t, base)
	boot3 := rubygemsBootstrapAll(t, h)
	srv3.set(november)
	c1, err := h.Changes(ctx, boot3)
	if err != nil {
		t.Fatal(err)
	}
	missed := []byte("etunnel 1.7.6 21c8890455eef71c33f751c246150d0c\n")
	later := bytes.Replace(tail, []byte("etunnel 1.7.8"), append(missed, "etunnel 1.7.8"...), 1)
	december2 := rubygemsTestRewrite(rubygemsCat(base, later), "2026-12-01T00:00:04Z")
	if len(december2) >= len(november)-1 {
		t.Fatalf("the rewrite (%d bytes) is not shorter than the copy (%d)", len(december2), len(november))
	}
	srv3.set(december2)
	c2, err := h.Changes(ctx, c1.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(c2.Items)); got != "[etunnel@1.7.6]" {
		t.Errorf("the shorter rewrite reported %s", got)
	}
	var c rubygemsCursor
	if err := decodeCursor(c2.Next, h.format(), &c); err != nil || c.Created != "2026-12-01T00:00:04Z" || c.Size != int64(len(december2)) {
		t.Errorf("cursor after the rewrite %+v (%v)", c, err)
	}
}

func TestRubyGemsTornAndMismatchingTails(t *testing.T) {
	ctx := context.Background()
	base, tail := rubygemsNovember(t)
	november := rubygemsCat(base, tail)
	f, srv, _ := rubygemsTestFeed(t, base)
	boot := rubygemsBootstrapAll(t, f)
	srv.set(november)

	// A transfer cut short of its Content-Range: asked for again, nothing
	// trusted.
	srv.short = 10
	_, err := f.Changes(ctx, boot)
	mustErr(t, err, false, false, "Content-Range")
	srv.short = 0
	// A stale digest: neither the copy with the tail nor the whole file
	// hashes to it.
	srv.digestOf = base
	_, err = f.Changes(ctx, boot)
	mustErr(t, err, false, false, "digest")
	srv.digestOf = nil
	b, err := f.Changes(ctx, boot)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprint(names(b.Items))
	// A file being written, ending inside a line: the tail is torn and so is
	// the whole file.
	srv.set(november[:len(november)-5])
	_, err = f.Changes(ctx, boot)
	mustErr(t, err, false, false, "inside a line")

	// A server that states no digest: an append is taken once the file
	// still starts with the copy's first line …
	g, srv2, _ := rubygemsTestFeed(t, base)
	boot2 := rubygemsBootstrapAll(t, g)
	srv2.noDigest = true
	srv2.set(november)
	b2, err := g.Changes(ctx, boot2)
	if err != nil || fmt.Sprint(names(b2.Items)) != want {
		t.Errorf("without a digest: %v (%v)", names(b2.Items), err)
	}
	if reqs := srv2.requests(); reqs[len(reqs)-1] != "GET bytes=0-32" {
		t.Errorf("requests %v", reqs)
	}
	// … and a rewrite that keeps the copy's length and last byte is caught by
	// its first line.
	h, srv3, _ := rubygemsTestFeed(t, base)
	boot3 := rubygemsBootstrapAll(t, h)
	srv3.noDigest = true
	srv3.set(bytes.Replace(november, []byte("created_at: 2026-11-01T00:00:04Z"), []byte("created_at: 2026-12-01T00:00:04Z"), 1))
	b3, err := h.Changes(ctx, boot3)
	if err != nil || fmt.Sprint(names(b3.Items)) != want {
		t.Errorf("a rewrite without a digest: %v (%v)", names(b3.Items), err)
	}
	var c rubygemsCursor
	if err := decodeCursor(b3.Next, h.format(), &c); err != nil || c.Created != "2026-12-01T00:00:04Z" {
		t.Errorf("cursor %+v (%v)", c, err)
	}
}

func TestRubyGemsCursorMustMatchTheCopy(t *testing.T) {
	ctx := context.Background()
	base, _ := rubygemsNovember(t)
	f, _, _ := rubygemsTestFeed(t, base)
	boot := rubygemsBootstrapAll(t, f)
	var c rubygemsCursor
	if err := decodeCursor(boot, f.format(), &c); err != nil {
		t.Fatal(err)
	}
	long := c
	long.Size++
	_, err := f.Changes(ctx, f.cursor(long))
	mustErr(t, err, false, true, "shorter than the cursor")
	p := f.files.path(rubygemsCopyName(c.Gen))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	data[40] ^= 1
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = f.Changes(ctx, boot)
	mustErr(t, err, false, true, "does not match")
	os.Remove(p)
	_, err = f.Changes(ctx, boot)
	mustErr(t, err, false, true, "not stored")
	for _, bad := range []string{"", "x", `{"format":"rubygems/1"}`, `{"format":"npm/1","since":"1"}`,
		`{"format":"rubygems/1","gen":"zz","size":1,"sha256":"00"}`,
		strings.Replace(boot, `"format"`, `"extra":1,"format"`, 1)} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestRubyGemsReleasesComeFromInfo(t *testing.T) {
	ctx := context.Background()
	base, _ := rubygemsNovember(t)
	f, _, reads := rubygemsTestFeed(t, base)
	for _, name := range []string{"rack-test", "oximg", "3scale-3scale_ws_api"} {
		reads.set("/info/"+name, fixture(t, "rubygems", "info-"+name+".txt"))
	}
	backend, err := rubygems.New(rubygems.Options{Name: f.k.env.Upstream, UpstreamURL: "https://rubygems.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rack-test", "oximg"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "rubygems", "releases-"+name, viewReleases(rels))
		// The backend reads each file as the gem and the version token
		// (platform included) of its release.
		expectServed(t, backend, rels, func(r Release, a Artifact) (string, string) {
			file, _ := url.PathUnescape(path.Base(a.Path))
			token := strings.TrimSuffix(strings.TrimPrefix(file, name+"-"), ".gem")
			if v, _, ok := rubygemsSplit(token); !ok || v != r.Version {
				t.Errorf("%s: file %s is not of version %s", name, file, r.Version)
			}
			return name, token
		})
	}
	// The backend would read 3scale-3scale_ws_api-0.4.8.gem as gem "3scale":
	// not mirrored, and said so.
	_, err = f.Releases(ctx, "3scale-3scale_ws_api")
	mustErr(t, err, true, false, "another gem's")
	// An unknown gem, a name that is not one, a gate's verdict, an
	// access-control refusal and a document that is not an /info one.
	_, err = f.Releases(ctx, "no-such-gem")
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(ctx, "../etc")
	mustErr(t, err, true, false, "not a gem name")
	reads.setDoc("/info/typo-squat", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typo-squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/info/held", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	reads.set("/info/html", []byte("<html>\n<body>maintenance</body>\n"))
	_, err = f.Releases(ctx, "html")
	mustErr(t, err, true, false, "names a version")
	// A gem whose every version was yanked has an empty document.
	reads.set("/info/agent-evals", []byte("---\n"))
	if rels, err := f.Releases(ctx, "agent-evals"); err != nil || len(rels) != 0 {
		t.Errorf("a gem without versions: %v %v", rels, err)
	}
}

func TestRubyGemsLinesTokensAndHeaders(t *testing.T) {
	tail := "etunnel 1.7.9 7e16f5deea032efa1e88ab5565b7d5f2\n" +
		"etunnel -1.7.9 0db46331c510406bd8e07d56585ae3da\n" +
		"oximg 0.20.0,0.20.0-arm64-darwin a96f2a6391f0b4326a17a87a54cc3975\n" +
		"oximg -0.20.0-arm64-darwin de0513a81afef62e12af7ecdf86820c0\n" +
		"bad line\n../x 1.0 e1e67d2f570fd6bc45a9959e1f559064\n" +
		"new-gem 1.0.0.pre.rc1 51d909f4b0c4d8f73cf652575f67e2fb\n"
	// A version pushed and yanked in the tail is gone; one with a file left
	// is not.
	if got := fmt.Sprint(names(rubygemsAppended([]byte(tail)))); got != "[oximg@0.20.0 new-gem@1.0.0.pre.rc1]" {
		t.Errorf("appended: %s", got)
	}
	for tok, want := range map[string]string{"1.16.0-x86_64-linux": "1.16.0 x86_64-linux", "2.3.0": "2.3.0 ", "1.0.0.pre.rc1": "1.0.0.pre.rc1 ",
		"0.19.0-aarch64-linux-gnu": "0.19.0 aarch64-linux-gnu", "v1.0": "", "1.0-": "", "-1.0": "", "1.0/x": "", "": ""} {
		v, p, ok := rubygemsSplit(tok)
		if got := v + " " + p; ok != (want != "") || (ok && got != want) {
			t.Errorf("%q: %q %v, want %q", tok, got, ok, want)
		}
	}
	sum := sha256.Sum256([]byte("x"))
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	for _, h := range []http.Header{
		{"Repr-Digest": {`sha-256="` + b64 + `"`}},
		{"Repr-Digest": {`sha-512=:AAAA:, sha-256=:` + b64 + `:`}},
		{"Digest": {"SHA-256=" + b64}},
	} {
		if got, ok := rubygemsDigest(h); !ok || !bytes.Equal(got, sum[:]) {
			t.Errorf("%v: %x %v", h, got, ok)
		}
	}
	if _, ok := rubygemsDigest(http.Header{"Repr-Digest": {"sha-256=:short:"}}); ok {
		t.Errorf("a digest of the wrong length was read")
	}
	for v, want := range map[string]string{"bytes 10-19/20": "10 19 20", "bytes 0-0/1": "0 0 1", "bytes 10-9/20": "", "bytes 5-25/20": "", "bytes */20": "", "items 0-1/2": ""} {
		a, b, n, ok := rubygemsParseContentRange(v)
		if got := fmt.Sprintf("%d %d %d", a, b, n); ok != (want != "") || (ok && got != want) {
			t.Errorf("%q: %s %v", v, got, ok)
		}
	}
	for _, tc := range []struct {
		head, created string
		ok            bool
	}{
		{"created_at: 2026-11-01T00:00:04Z\n---\n- 1 x\n", "2026-11-01T00:00:04Z", true},
		{"---\nrack 1.0 x\n", "", true},
		{"created_at: 2026-11-01T00:00:04Z\nrack 1.0 x\n", "", false},
		{"<html>\n", "", false},
		{"created_at: \n---\n", "", false},
		{"created_at: 2026-11-01T00:00:04Z", "", false},
	} {
		created, _, ok := rubygemsHeader([]byte(tc.head))
		if ok != tc.ok || created != tc.created {
			t.Errorf("%q: %q %v, want %q %v", tc.head, created, ok, tc.created, tc.ok)
		}
	}
}

func TestRubyGemsMalformedVersionsFiles(t *testing.T) {
	ctx := context.Background()
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "rubygems", srv.URL(), nil, nil)).(*rubygemsFeed)
	srv.on("GET", "/versions").reply(200, []byte("<html>not the index</html>\n"))
	_, err := f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "not a compact index")
	srv.on("GET", "/versions").reply(404, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "not found")
	srv.on("GET", "/versions").reply(503, nil).withHeader("Retry-After", "60")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d.Seconds() != 60 {
		t.Errorf("Retry-After not carried: %v", err)
	}
	base, _ := rubygemsNovember(t)
	srv.on("GET", "/versions").reply(200, base).withHeader("Repr-Digest", `sha-256="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, false, false, "digest")
	if _, err := os.Stat(f.files.path(rubygemsDownload)); !os.IsNotExist(err) {
		t.Errorf("a download that does not match its digest was kept: %v", err)
	}
}
