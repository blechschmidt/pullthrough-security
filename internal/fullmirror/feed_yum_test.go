package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/yum"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The yum fixtures were recorded on 2026-11-16 (see testdata/feeds/yum): the
// repomd.xml of Fedora 44's updates (x86_64), Rocky Linux 9's AppStream and
// EPEL 9, as served, and their primaries trimmed to a few packages, kept
// uncompressed. A test serves a primary compressed as the recorded repomd.xml
// names it (zstd, gzip, xz) and rewrites the primary's entry of repomd.xml —
// checksum, open-checksum, location, size, open-size — to match.

func yumSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func yumCompress(t testing.TB, suffix string, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch suffix {
	case ".zst":
		zw, err := zstd.NewWriter(&buf, zstd.WithWindowSize(4<<20))
		if err != nil {
			t.Fatal(err)
		}
		zw.Write(b)
		zw.Close()
	case ".gz":
		gw := gzip.NewWriter(&buf)
		gw.Write(b)
		gw.Close()
	case ".xz":
		xw, err := xz.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		xw.Write(b)
		xw.Close()
	default:
		buf.Write(b)
	}
	return buf.Bytes()
}

// yumTestRepo is a repository as the fixture server serves it.
type yumTestRepo struct {
	repomd      []byte
	primaryPath string
	primary     []byte
	// sum is the primary's checksum as the cursor keeps it.
	sum string
}

var yumPrimaryBlock = regexp.MustCompile(`(?s)<data type="primary">.*?</data>`)

// yumRenderRepo rewrites a recorded repomd.xml's primary entry for primaryXML,
// compressed as the recorded location says.
func yumRenderRepo(t testing.TB, recorded, primaryXML []byte) yumTestRepo {
	t.Helper()
	block := yumPrimaryBlock.Find(recorded)
	if block == nil {
		t.Fatal("the recorded repomd.xml has no primary")
	}
	loc := regexp.MustCompile(`href="([^"]+)"`).FindSubmatch(block)[1]
	suffix := string(loc[bytes.LastIndexByte(loc, '.'):])
	body := yumCompress(t, suffix, primaryXML)
	path := "repodata/" + yumSHA256(body) + "-primary.xml" + suffix
	nb := string(block)
	for _, r := range []struct{ re, repl string }{
		{`<checksum type="sha256">[0-9a-f]+</checksum>`, `<checksum type="sha256">` + yumSHA256(body) + `</checksum>`},
		{`<open-checksum type="sha256">[0-9a-f]+</open-checksum>`, `<open-checksum type="sha256">` + yumSHA256(primaryXML) + `</open-checksum>`},
		{`href="[^"]+"`, `href="` + path + `"`},
		{`<size>\d+</size>`, fmt.Sprintf("<size>%d</size>", len(body))},
		{`<open-size>\d+</open-size>`, fmt.Sprintf("<open-size>%d</open-size>", len(primaryXML))},
	} {
		nb = regexp.MustCompile(r.re).ReplaceAllString(nb, r.repl)
	}
	return yumTestRepo{
		repomd:      bytes.Replace(recorded, block, []byte(nb), 1),
		primaryPath: "/" + path,
		primary:     body,
		sum:         "sha256:" + yumSHA256(body),
	}
}

// serve adds the repository's routes: repomd.xml with validators (a 304 for
// a request that presents them) and the primary.
func (r yumTestRepo) serve(srv *fixtureServer, etag string) {
	srv.on("GET", "/repodata/repomd.xml").reply(200, r.repomd).withHeader("ETag", etag).withHeader("Last-Modified", "Mon, 16 Nov 2026 01:16:36 GMT")
	srv.on("GET", "/repodata/repomd.xml").requireHeader("If-None-Match", etag).reply(http.StatusNotModified, nil)
	srv.on("GET", r.primaryPath).requireHeader("Accept-Encoding", "identity").reply(200, r.primary)
}

// yumGolden masks what depends on a compressor's output (the primary's
// checksum) with a label, so that the golden files hold across library
// versions.
func yumGolden(t *testing.T, name string, v any, labels map[string]string) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for sum, label := range labels {
		s = strings.ReplaceAll(s, sum, label)
	}
	checkGolden(t, "yum", name, json.RawMessage(s))
}

// yumTestBackend is the backend the adapter's paths are checked against.
func yumTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := yum.New(yum.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// yumServedAs is what the backend derives from a file's name: the package and
// its version without epoch or release.
func yumServedAs(name string) func(Release, Artifact) (string, string) {
	return func(r Release, _ Artifact) (string, string) {
		_, ver, _ := yumSplitEVR(r.Version)
		return name, ver
	}
}

func TestYumFeedLocation(t *testing.T) {
	for _, u := range []string{
		"https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64",
		"https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os",
		"https://pulp.internal.example/pulp/content/rhel9-baseos/",
	} {
		f, err := newYumFeed(Env{Upstream: "rpms", Type: "yum", URL: u})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if got := f.(*yumFeed).src.(*yumSource).root.String(); got != strings.TrimRight(u, "/") {
			t.Errorf("%s: the feed is read from %s", u, got)
		}
	}
	f, err := newYumFeed(Env{Upstream: "rpms", Type: "yum", URL: "https://cache.internal.example/fedora",
		Options: map[string]string{"url": "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*yumFeed).src.(*yumSource).root.String(); got != "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64" {
		t.Errorf("option url: %s", got)
	}
	if err := Check(Env{Upstream: "rpms", Type: "rpm", URL: "https://mirror.example/epel/9/Everything/x86_64"}); err != nil {
		t.Errorf("the rpm alias: %v", err)
	}
	for _, opts := range []map[string]string{{"suites": "x"}, {"url": "ftp://mirror.example/repo"}, {"url": "https://user:pw@mirror.example/repo"},
		{"url": "https://mirror.example/repo?x=1"}, {"url": "relative/path"}} {
		if err := Check(Env{Upstream: "rpms", Type: "yum", URL: "https://mirror.example/repo", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
	if err := Check(Env{Upstream: "rpms", Type: "yum", URL: "file:///srv/repo"}); err == nil {
		t.Errorf("a file: upstream accepted")
	}
}

func TestYumBootstrapChangesReleases(t *testing.T) {
	srv := newFixtureServer(t)
	repo := yumRenderRepo(t, fixture(t, "yum", "repomd-fedora.xml"), fixture(t, "yum", "primary-fedora.xml"))
	repo.serve(srv, `"1b8f-6605a87730d89"`)
	env := testEnv(t, "yum", srv.URL(), nil, nil)
	f := mustFeed(t, env).(*yumFeed)
	f.page = 2
	labels := map[string]string{repo.sum: "sha256:<primary-fedora.xml.zst>"}
	ctx := context.Background()
	var batches []batchView
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, viewBatch(t, b))
		cursor = b.Next
		if !b.More {
			break
		}
		if i > 10 {
			t.Fatal("Bootstrap does not end")
		}
	}
	yumGolden(t, "bootstrap", batches, labels)
	f.page = indexPage

	backend := yumTestBackend(t, env)
	for _, name := range []string{"emacs-devel", "kicad-doc", "octave-doc", "stb-doc"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "yum", "releases-fedora-"+name, viewReleases(rels))
		expectServed(t, backend, rels, yumServedAs(name))
	}
	// The records keep each file's checksum in full, as the primary declares
	// it, for a fetch that will check it.
	if recs, err := f.lookup("kicad-doc"); err != nil || len(recs) != 1 || recs[0].Digest != "sha256:4c7bd88324b81988389064d54e0aca5e3bb24c1159ab0f4201790cfc701b2f63" {
		t.Errorf("kicad-doc's record: %+v %v", recs, err)
	}
	_, err := f.Releases(ctx, "not-in-the-repository")
	mustErr(t, err, true, false, "not in the yum index")
	_, err = f.Releases(ctx, "../etc")
	mustErr(t, err, true, false, "not an RPM package name")

	// Nothing changed: repomd.xml answers 304, the primary is not read.
	before := len(srv.requests())
	b, err := f.Changes(ctx, cursor)
	if err != nil || len(b.Items) != 0 || b.Next != cursor {
		t.Fatalf("an unchanged repository: %+v %v", b, err)
	}
	if reqs := srv.requests()[before:]; len(reqs) != 1 || !strings.HasSuffix(reqs[0], "/repodata/repomd.xml") {
		t.Errorf("requests of an unchanged poll: %v", reqs)
	}

	// repomd.xml rewritten (another ETag, an updateinfo) around the same
	// primary: nothing to diff, the validators move on.
	edited := yumTestRepo{repomd: bytes.Replace(repo.repomd, []byte("<revision>1794788928</revision>"), []byte("<revision>1794792528</revision>"), 1)}
	srv.on("GET", "/repodata/repomd.xml").reply(200, edited.repomd).withHeader("ETag", `"r2"`)
	b, err = f.Changes(ctx, cursor)
	if err != nil || len(b.Items) != 0 || b.Head != "1794792528" {
		t.Fatalf("a repomd.xml around the same primary: %+v %v", b, err)
	}
	var c indexCursor
	if err := decodeCursor(b.Next, f.format(), &c); err != nil || !strings.Contains(string(c.State), `"etag":"\"r2\""`) {
		t.Errorf("the validators did not move on: %s (%v)", c.State, err)
	}
	cursor = b.Next

	// An update: emacs-devel rebuilt (a new release, both architectures),
	// octave-doc gone, kicad-doc's file republished (another checksum), a new
	// package.
	primary := string(fixture(t, "yum", "primary-fedora.xml"))
	primary = strings.ReplaceAll(primary, `ver="30.2" rel="29.fc44"`, `ver="30.2" rel="30.fc44"`)
	primary = strings.ReplaceAll(primary, `emacs-devel-30.2-29.fc44`, `emacs-devel-30.2-30.fc44`)
	primary = regexp.MustCompile(`(?s)<package type="rpm">\s*<name>octave-doc</name>.*?</package>\n`).ReplaceAllString(primary, "")
	primary = strings.Replace(primary, "4c7bd88324b81988389064d54e0aca5e3bb24c1159ab0f4201790cfc701b2f63", strings.Repeat("e", 64), 1)
	stb := regexp.MustCompile(`(?s)<package type="rpm">\s*<name>stb-doc</name>.*?</package>\n`).FindString(primary)
	primary = strings.Replace(primary, "</metadata>", strings.ReplaceAll(stb, "stb-doc", "stb-devel")+"</metadata>", 1)
	next := yumRenderRepo(t, edited.repomd, []byte(primary))
	next.serve(srv, `"r3"`)
	labels[next.sum] = "sha256:<primary-fedora-2.xml.zst>"
	b, err = f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	yumGolden(t, "changes", viewBatch(t, b), labels)
	rels, err := f.Releases(ctx, "emacs-devel")
	if err != nil || len(rels) != 1 || rels[0].Version != "1:30.2-30.fc44" || len(rels[0].Artifacts) != 2 {
		t.Errorf("emacs-devel after the update: %+v %v", rels, err)
	}
	if _, err := f.Releases(ctx, "octave-doc"); !IsPermanent(err) {
		t.Errorf("octave-doc after it was removed: %v", err)
	}
	// The engine may ask again from the cursor it stored: the same difference.
	again, err := f.Changes(ctx, cursor)
	if err != nil || fmt.Sprint(again.Items) != fmt.Sprint(b.Items) {
		t.Errorf("asked again: %+v %v", again.Items, err)
	}
}

// Rocky Linux keeps every version of a minor release (gzip primary); EPEL
// publishes xz. Versions are ordered by RPM's comparison, the release part of
// the version.
func TestYumRockyAndEPEL(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		names   []string
	}{
		{"rocky", []string{"libX11-common", "seavgabios-bin", "tigervnc-icons"}},
		{"epel", []string{"3cpio"}},
	} {
		srv := newFixtureServer(t)
		repo := yumRenderRepo(t, fixture(t, "yum", "repomd-"+tc.fixture+".xml"), fixture(t, "yum", "primary-"+tc.fixture+".xml"))
		repo.serve(srv, `"a"`)
		env := testEnv(t, "yum", srv.URL(), nil, nil)
		f := mustFeed(t, env).(*yumFeed)
		b, err := f.Bootstrap(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		if b.More || fmt.Sprint(names(b.Items)) != fmt.Sprint(tc.names) {
			t.Errorf("%s: bootstrap %v (more %v)", tc.fixture, names(b.Items), b.More)
		}
		backend := yumTestBackend(t, env)
		for _, name := range tc.names {
			rels, err := f.Releases(context.Background(), name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			checkGolden(t, "yum", "releases-"+tc.fixture+"-"+name, viewReleases(rels))
			expectServed(t, backend, rels, yumServedAs(name))
		}
	}
}

func TestYumMalformedAndRefused(t *testing.T) {
	ctx := context.Background()
	recorded := fixture(t, "yum", "repomd-fedora.xml")
	good := fixture(t, "yum", "primary-fedora.xml")
	bootstrap := func(srv *fixtureServer) error {
		f := mustFeed(t, testEnv(t, "yum", srv.URL(), nil, nil)).(*yumFeed)
		_, err := f.Bootstrap(ctx, "")
		return err
	}
	for name, tc := range map[string]struct {
		repomd    string
		permanent bool
		want      string
	}{
		"garbage":    {"<html>Service Unavailable</html>", true, "not a repomd.xml"},
		"not xml":    {"\x00\x01binary", true, "not XML"},
		"no primary": {`<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary_zck"><location href="repodata/a-primary.xml.zck"/></data></repomd>`, true, "lists no primary"},
		"md5": {`<repomd><data type="primary"><checksum type="md5">` + strings.Repeat("a", 32) + `</checksum><location href="repodata/p.xml.gz"/></data></repomd>`,
			true, "states no checksum"},
		"elsewhere": {`<repomd><data type="primary"><checksum type="sha256">` + strings.Repeat("a", 64) + `</checksum><location xml:base="https://other.example/" href="repodata/p.xml.gz"/></data></repomd>`,
			true, "another base URL"},
		"escape": {`<repomd><data type="primary"><checksum type="sha256">` + strings.Repeat("a", 64) + `</checksum><location href="../p.xml.gz"/></data></repomd>`,
			true, "not a path below"},
		"too large": {`<repomd><data type="primary"><checksum type="sha256">` + strings.Repeat("a", 64) + `</checksum><location href="repodata/p.xml.gz"/><open-size>99999999999</open-size></data></repomd>`,
			true, "the feed reads at most"},
		"deep": {`<repomd>` + strings.Repeat("<x>", 40) + strings.Repeat("</x>", 40) + `</repomd>`, true, "nest more than"},
	} {
		srv := newFixtureServer(t)
		srv.on("GET", "/repodata/repomd.xml").json(tc.repomd)
		mustErr(t, bootstrap(srv), tc.permanent, false, tc.want)
		_ = name
	}

	// A repomd.xml that is not there: the URL is not a repository root.
	srv := newFixtureServer(t)
	srv.on("GET", "/repodata/repomd.xml").reply(404, nil)
	mustErr(t, bootstrap(srv), true, false, "must be a repository root")

	// The primary changed while it was read (its checksum does not match),
	// or came short: worth retrying, not a verdict.
	repo := yumRenderRepo(t, recorded, good)
	srv = newFixtureServer(t)
	repo.serve(srv, `"a"`)
	other := yumCompress(t, ".zst", bytes.Replace(good, []byte("kicad-doc"), []byte("kicad-dog"), -1))
	srv.on("GET", repo.primaryPath).reply(200, other)
	mustErr(t, bootstrap(srv), false, false, "the repository changed while it was read")
	srv.on("GET", repo.primaryPath).reply(200, repo.primary[:len(repo.primary)/2])
	mustErr(t, bootstrap(srv), false, false, "")

	// A primary that is the one declared but no primary.xml, or that does
	// not decompress: the repository's fault.
	for name, body := range map[string][]byte{
		"html":    []byte("<html><body>maintenance</body></html>"),
		"garbage": []byte("\x28\xb5\x2f\xfdnot really zstd at all"),
	} {
		bad := yumRenderRepo(t, recorded, body)
		bad.primary = body
		bad.repomd = regexp.MustCompile(`<checksum type="sha256">[0-9a-f]+</checksum>`).ReplaceAll(bad.repomd, []byte(`<checksum type="sha256">`+yumSHA256(body)+`</checksum>`))
		bad.repomd = regexp.MustCompile(`<size>\d+</size>`).ReplaceAll(bad.repomd, []byte(fmt.Sprintf("<size>%d</size>", len(body))))
		bad.repomd = regexp.MustCompile(`<open-checksum type="sha256">[0-9a-f]+</open-checksum>`).ReplaceAll(bad.repomd, nil)
		bad.repomd = regexp.MustCompile(`<open-size>\d+</open-size>`).ReplaceAll(bad.repomd, nil)
		srv := newFixtureServer(t)
		bad.serve(srv, `"a"`)
		err := bootstrap(srv)
		if err == nil || !IsPermanent(err) {
			t.Errorf("%s: %v, want a permanent error", name, err)
		}
	}

	// Entries the proxy cannot fetch or name are left out; the rest stay.
	odd := strings.Replace(string(good), "</metadata>", `<package type="rpm"><name>elsewhere</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/>
<checksum type="sha256">`+strings.Repeat("a", 64)+`</checksum><location xml:base="https://cdn.example/" href="Packages/e/elsewhere-1-1.x86_64.rpm"/></package>
<package type="rpm"><name>Bad Name</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><location href="Packages/b/bad-1-1.x86_64.rpm"/></package>
<package type="rpm"><name>escape</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><location href="../../escape-1-1.x86_64.rpm"/></package>
<package type="rpm"><name>notrpm</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><location href="Packages/n/notrpm-1-1.x86_64.tar.gz"/></package>
<package type="rpm"><name>badver</name><arch>x86_64</arch><version epoch="x" ver="1" rel="1"/><location href="Packages/b/badver-1-1.x86_64.rpm"/></package>
<package type="rpm"><name>norel</name><arch>x86_64</arch><version epoch="0" ver="1"/><location href="Packages/n/norel-1.x86_64.rpm"/></package>
<package type="rpm"><name>url</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><location href="https://cdn.example/url-1-1.x86_64.rpm"/></package>
<package type="rpm"><name>kept</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><location href="/Packages/k/kept-1-1.x86_64.rpm"/></package>
</metadata>`, 1)
	repo = yumRenderRepo(t, recorded, []byte(odd))
	srv = newFixtureServer(t)
	repo.serve(srv, `"a"`)
	f := mustFeed(t, testEnv(t, "yum", srv.URL(), nil, nil)).(*yumFeed)
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[emacs-devel kept kicad-doc octave-doc stb-doc]" {
		t.Errorf("entries kept: %s", got)
	}
	rels, err := f.Releases(ctx, "kept")
	if err != nil || len(rels) != 1 || rels[0].Artifacts[0].Path != "/Packages/k/kept-1-1.x86_64.rpm" {
		t.Errorf("kept: %+v %v", rels, err)
	}
}

// The cursor's copy must read back; a state this source did not write reads
// the repository afresh.
func TestYumCursorResets(t *testing.T) {
	srv := newFixtureServer(t)
	repo := yumRenderRepo(t, fixture(t, "yum", "repomd-fedora.xml"), fixture(t, "yum", "primary-fedora.xml"))
	repo.serve(srv, `"a"`)
	f := mustFeed(t, testEnv(t, "yum", srv.URL(), nil, nil)).(*yumFeed)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var c indexCursor
	if err := decodeCursor(b.Next, f.format(), &c); err != nil {
		t.Fatal(err)
	}
	for _, cur := range []string{"{", `{"format":"apt/1","snap":"` + c.Snap + `"}`, `{"format":"yum/1","snap":"` + strings.Repeat("0", 64) + `"}`} {
		_, err := f.Changes(ctx, cur)
		mustErr(t, err, false, true, "")
	}
	// Validators the source cannot read: repomd.xml is read unconditionally,
	// and the same primary changes nothing.
	c.State = json.RawMessage(`["not","a","state"]`)
	b2, err := f.Changes(ctx, encodeCursor(&c))
	if err != nil || len(b2.Items) != 0 {
		t.Errorf("an unreadable state: %+v %v", b2, err)
	}
}

func TestYumVersionOrder(t *testing.T) {
	// rpmvercmp's own cases (rpm's tests/rpmvercmp.at), as [a, b, want].
	for _, tc := range [][3]string{
		{"1.0", "1.0", "0"}, {"1.0", "2.0", "-1"}, {"2.0", "1.0", "1"},
		{"2.0.1", "2.0.1", "0"}, {"2.0", "2.0.1", "-1"}, {"2.0.1a", "2.0.1", "1"},
		{"5.5p1", "5.5p2", "-1"}, {"5.5p10", "5.5p1", "1"}, {"10xyz", "10.1xyz", "-1"},
		{"xyz10", "xyz10.1", "-1"}, {"xyz.4", "8", "-1"}, {"xyz.4", "2", "-1"},
		{"5.5p2", "5.6p1", "-1"}, {"5.6p1", "6.5p1", "-1"}, {"6.0.rc1", "6.0", "1"},
		{"10b2", "10a1", "1"}, {"1.0aa", "1.0a", "1"}, {"10.0001", "10.1", "0"},
		{"10.0001", "10.0039", "-1"}, {"4.999.9", "5.0", "-1"}, {"20101121", "20101122", "-1"},
		{"2_0", "2_0", "0"}, {"2.0", "2_0", "0"}, {"a", "a", "0"}, {"a+", "a_", "0"}, {"+", "_", "0"},
		{"1.0~rc1", "1.0~rc1", "0"}, {"1.0~rc1", "1.0", "-1"}, {"1.0~rc1", "1.0~rc2", "-1"},
		{"1.0~rc1~git123", "1.0~rc1", "-1"}, {"1.0^", "1.0", "1"}, {"1.0^git1", "1.0", "1"},
		{"1.0^git1", "1.0^git2", "-1"}, {"1.0^git1", "1.01", "-1"}, {"1.0^20160101", "1.0.1", "-1"},
		{"1.0^20160101^git1", "1.0^20160101", "1"}, {"1.0~rc1^git1", "1.0~rc1", "1"}, {"1.0^git1~pre", "1.0^git1", "-1"},
	} {
		got := fmt.Sprint(yumVercmp(tc[0], tc[1]))
		if got != tc[2] {
			t.Errorf("rpmvercmp(%q, %q) = %s, want %s", tc[0], tc[1], got, tc[2])
		}
	}
	rels := []Release{{Version: "1:1.0-1"}, {Version: "1.8.12-1.el9_8.1"}, {Version: "1.10-1"}, {Version: "1.8.12-1.el9"}, {Version: "1.9-2"}, {Version: "2:0.1-1"}}
	yumSortReleases(rels)
	var got []string
	for _, r := range rels {
		got = append(got, r.Version)
	}
	if fmt.Sprint(got) != "[1.8.12-1.el9 1.8.12-1.el9_8.1 1.9-2 1.10-1 1:1.0-1 2:0.1-1]" {
		t.Errorf("EVR order: %v", got)
	}
	for _, tc := range []struct{ epoch, ver, rel, want string }{
		{"0", "1.0", "1.fc44", "1.0-1.fc44"}, {"", "1.0", "1", "1.0-1"}, {"6", "10.3.0", "8.fc44", "6:10.3.0-8.fc44"},
		{"007", "1", "1", "7:1-1"}, {"x", "1", "1", ""}, {"0", "1-2", "1", ""}, {"0", "1", "", ""}, {"0", "", "1", ""},
		{"99999999999", "1", "1", ""}, {"0", "1 2", "1", ""},
	} {
		got, ok := yumEVR(tc.epoch, tc.ver, tc.rel)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("yumEVR(%q, %q, %q) = %q, %v; want %q", tc.epoch, tc.ver, tc.rel, got, ok, tc.want)
		}
	}
}

// yumSyntheticPrimary is a primary.xml of n packages shaped like Fedora's
// (about 3.3 KB a package, most of it the <format> subtree).
func yumSyntheticPrimary(n int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("synthetic-package-%06d", i)
		fmt.Fprintf(&b, `<package type="rpm">
  <name>%[1]s</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="%[2]d.%[3]d.%[4]d" rel="%[3]d.fc44"/>
  <checksum type="sha256" pkgid="YES">%064[5]x</checksum>
  <summary>Synthetic package %[2]d for the memory bound</summary>
  <description>A package whose entry is shaped like a real one: a description of a few lines,
the format subtree with what it provides and requires, and the files it installs.
It exists so that the feed's memory can be measured against a document of a realistic size.</description>
  <packager>Fedora Project</packager>
  <url>https://example.org/%[1]s</url>
  <time file="%[6]d" build="%[6]d"/>
  <size package="%[7]d" installed="%[8]d" archive="%[8]d"/>
  <location href="Packages/s/%[1]s-%[2]d.%[3]d.%[4]d-%[3]d.fc44.x86_64.rpm"/>
  <format>
    <rpm:license>MIT AND Apache-2.0 AND BSD-3-Clause</rpm:license>
    <rpm:vendor>Fedora Project</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:buildhost>buildvm-x86-24.rdu3.fedoraproject.org</rpm:buildhost>
    <rpm:sourcerpm>%[1]s-%[2]d.%[3]d.%[4]d-%[3]d.fc44.src.rpm</rpm:sourcerpm>
    <rpm:header-range start="4504" end="%[7]d"/>
    <rpm:provides>
`, name, i%97, i%13, i%7, i+1, 1700000000+i, 10000+i, 40000+i)
		for j := 0; j < 8; j++ {
			fmt.Fprintf(&b, "      <rpm:entry name=\"lib%s-%d.so()(64bit)\"/>\n", name, j)
		}
		b.WriteString("    </rpm:provides>\n    <rpm:requires>\n")
		for j := 0; j < 12; j++ {
			fmt.Fprintf(&b, "      <rpm:entry name=\"libdep%d.so.%d()(64bit)\" flags=\"GE\" epoch=\"0\" ver=\"%d.0\" pre=\"1\"/>\n", j, i%5, j)
		}
		b.WriteString("    </rpm:requires>\n")
		for j := 0; j < 6; j++ {
			fmt.Fprintf(&b, "    <file>/usr/lib64/%s/plugin-%d.so</file>\n", name, j)
		}
		b.WriteString("  </format>\n</package>\n")
	}
	b.WriteString("</metadata>\n")
	return b.Bytes()
}

// Reading a large primary holds a bounded amount of memory: it is decompressed
// and parsed as it streams in, and its records spill to the copy's runs. The
// bound, 64 MiB, is the 4 MiB zstd window, the builder's records (here 10,000
// lines of about 200 bytes, under its 16 MiB spill threshold), the first
// listing page, and what a collection cycle lets accumulate on top (the
// collector lets the heap double), with headroom; reading the same document
// whole and handing it to the backend's old parser (ParsePrimary) holds the
// 33 MB document and more.
func TestYumPrimaryMemoryIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 33 MB primary.xml")
	}
	n := 10_000
	if raceEnabled {
		n = 500
	}
	doc := yumSyntheticPrimary(n)
	size := len(doc)
	if !raceEnabled && size < 30<<20 {
		t.Fatalf("the synthetic primary is %d bytes; the test wants at least 30 MB", size)
	}
	repo := yumRenderRepo(t, fixture(t, "yum", "repomd-fedora.xml"), doc)
	doc = nil
	srv := newFixtureServer(t)
	repo.serve(srv, `"a"`)
	f := mustFeed(t, testEnv(t, "yum", srv.URL(), nil, nil)).(*yumFeed)
	var b Batch
	var err error
	peak := sampleHeap(t, func() { b, err = f.Bootstrap(context.Background(), "") })
	if err != nil {
		t.Fatal(err)
	}
	if want := min(n, indexPage); len(b.Items) != want {
		t.Fatalf("listed %d packages, want %d", len(b.Items), want)
	}
	oldPeak := sampleHeap(t, func() {
		zr, err := zstd.NewReader(bytes.NewReader(repo.primary))
		if err != nil {
			t.Error(err)
			return
		}
		defer zr.Close()
		plain, err := io.ReadAll(zr)
		if err != nil {
			t.Error(err)
			return
		}
		if entries, err := yum.ParsePrimary(plain); err != nil || len(entries) != n {
			t.Errorf("ParsePrimary: %d entries, %v", len(entries), err)
		}
	})
	t.Logf("a %d-byte primary.xml (%d packages, %d bytes as zstd): the feed's peak heap %d MiB; reading it whole for ParsePrimary %d MiB",
		size, n, len(repo.primary), peak>>20, oldPeak>>20)
	const ceiling = 64 << 20
	if !raceEnabled && peak > ceiling {
		t.Errorf("reading the primary held %d MiB of heap; the bound is %d MiB", peak>>20, ceiling>>20)
	}
}

// The cursor keeps only validators it can carry compactly; the others make
// the next read unconditional.
func TestYumKeepsCompactValidators(t *testing.T) {
	for in, want := range map[string]string{
		`"1b8f-6605a87730d89"`:          `"1b8f-6605a87730d89"`,
		`W/"abc"`:                       `W/"abc"`,
		"Mon, 16 Nov 2026 01:16:36 GMT": "Mon, 16 Nov 2026 01:16:36 GMT",
		`"<script>"`:                    "",
		`"a&b"`:                         "",
		`"back\slash"`:                  "",
		"\"caf\xc3\xa9\"":               "",
		strings.Repeat("e", 129):        "",
	} {
		got := yumKeepValidators(httpValidators{ETag: in, LastModified: in}, 128)
		if got.ETag != want || got.LastModified != want {
			t.Errorf("%q kept as %+v, want %q", in, got, want)
		}
	}
}

// yumBombReader yields prefix, n bytes of fill repeated, then suffix, without
// holding the document in memory.
type yumBombReader struct {
	prefix, suffix string
	fill           []byte
	n              int64
	stage, off     int
}

func (g *yumBombReader) Read(p []byte) (int, error) {
	switch g.stage {
	case 0:
		k := copy(p, g.prefix[g.off:])
		if g.off += k; g.off == len(g.prefix) {
			g.stage, g.off = 1, 0
		}
		return k, nil
	case 1:
		k := 0
		for k < len(p) && g.n > 0 {
			c := copy(p[k:], g.fill[g.off:])
			if int64(c) > g.n {
				c = int(g.n)
			}
			k += c
			g.n -= int64(c)
			g.off = (g.off + c) % len(g.fill)
		}
		if g.n == 0 {
			g.stage, g.off = 2, 0
		}
		return k, nil
	case 2:
		k := copy(p, g.suffix[g.off:])
		if g.off += k; g.off == len(g.suffix) {
			g.stage = 3
		}
		return k, nil
	}
	return 0, io.EOF
}

// A primary of a few KB of zstd whose one <description> decompresses to
// hundreds of MiB of text with a '>' every KB passes every check the feed
// makes before parsing (its sizes and checksums are the ones repomd.xml
// states); the parser refuses the token at its bound, holding no more than
// that, and the document is the repository's fault.
func TestYumPrimaryTokenBomb(t *testing.T) {
	text := int64(192 << 20)
	if raceEnabled {
		text = 16 << 20
	}
	gen := &yumBombReader{
		prefix: `<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
<package type="rpm"><name>bomb</name><arch>noarch</arch><version epoch="0" ver="1" rel="1"/>
<checksum type="sha256">` + strings.Repeat("a", 64) + `</checksum><location href="Packages/b/bomb-1-1.noarch.rpm"/><description>`,
		fill:   []byte(strings.Repeat("x", 1023) + ">"),
		n:      text,
		suffix: "</description></package>\n</metadata>\n",
	}
	plain := sha256.New()
	var comp bytes.Buffer
	zw, err := zstd.NewWriter(&comp, zstd.WithWindowSize(4<<20))
	if err != nil {
		t.Fatal(err)
	}
	openSize, err := io.Copy(io.MultiWriter(zw, plain), gen)
	if err != nil {
		t.Fatal(err)
	}
	zw.Close()
	body := comp.Bytes()
	loc := "repodata/" + yumSHA256(body) + "-primary.xml.zst"
	srv := newFixtureServer(t)
	srv.on("GET", "/repodata/repomd.xml").json(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>
<data type="primary"><checksum type="sha256">%s</checksum><open-checksum type="sha256">%x</open-checksum>
<location href="%s"/><timestamp>1794788920</timestamp><size>%d</size><open-size>%d</open-size></data></repomd>`,
		yumSHA256(body), plain.Sum(nil), loc, len(body), openSize))
	srv.on("GET", "/"+loc).reply(200, body)
	f := mustFeed(t, testEnv(t, "yum", srv.URL(), nil, nil)).(*yumFeed)
	peak := sampleHeap(t, func() { _, err = f.Bootstrap(context.Background(), "") })
	mustErr(t, err, true, false, "a token longer than")
	t.Logf("a %d KB primary.xml.zst (%d MiB of XML): refused at a peak heap of %d MiB", len(body)>>10, openSize>>20, peak>>20)
	if !raceEnabled && peak > 64<<20 {
		t.Errorf("reading the primary held %d MiB of heap: the token bound does not hold", peak>>20)
	}
}
