package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/apt"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/ulikunitz/xz"
)

// The apt fixtures were recorded on 2026-11-16 (see testdata/feeds/apt):
// Debian trixie's InRelease (deb.debian.org) and Ubuntu noble-updates'
// (archive.ubuntu.com), their hash lists trimmed to main's indexes, and the
// Packages indexes those name, trimmed to a few stanzas. A test serves the
// Packages indexes compressed as the archives publish them (xz and gzip, the
// uncompressed form listed but not served, as Debian and Ubuntu do; by hash
// and by name) and an InRelease whose every hash list is rebuilt for them,
// its other lines — the signature among them — as recorded.

// aptTestSuite is one suite as the fixture server serves it.
type aptTestSuite struct {
	suite   string
	release []byte
	// files are the paths served, below the archive root; missing those it
	// lists but answers 404 for.
	files   map[string][]byte
	missing []string
}

// aptRender rebuilds a recorded Release's hash lists for parts (an index's
// directory below the suite, "main/binary-amd64", to its uncompressed
// content); edit, if set, changes the result's other lines.
func aptRender(t testing.TB, recorded []byte, suite string, parts map[string][]byte) aptTestSuite {
	t.Helper()
	ts := aptTestSuite{suite: suite, files: map[string][]byte{}}
	// The uncompressed index is listed but not served, as by Debian and
	// Ubuntu.
	type file struct {
		path string
		body []byte
	}
	var listed []file
	names := make([]string, 0, len(parts))
	for p := range parts {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		plain := parts[p]
		var gz, x bytes.Buffer
		gw := gzip.NewWriter(&gz)
		gw.Write(plain)
		gw.Close()
		xw, err := xz.NewWriter(&x)
		if err != nil {
			t.Fatal(err)
		}
		xw.Write(plain)
		xw.Close()
		listed = append(listed, file{p + "/Packages", plain}, file{p + "/Packages.gz", gz.Bytes()}, file{p + "/Packages.xz", x.Bytes()})
		sum := sha256.Sum256(plain)
		ts.missing = append(ts.missing, "/dists/"+suite+"/"+p+"/Packages", "/dists/"+suite+"/"+p+"/by-hash/SHA256/"+hex.EncodeToString(sum[:]))
		for _, f := range listed[len(listed)-2:] {
			sum := sha256.Sum256(f.body)
			ts.files["/dists/"+suite+"/"+f.path] = f.body
			ts.files["/dists/"+suite+"/"+p+"/by-hash/SHA256/"+hex.EncodeToString(sum[:])] = f.body
		}
	}
	hashes := map[string]func() hash.Hash{"MD5Sum:": md5.New, "SHA1:": sha1.New, "SHA256:": sha256.New, "SHA512:": sha512.New}
	var out bytes.Buffer
	inList := false
	for _, line := range strings.SplitAfter(string(recorded), "\n") {
		if inList && strings.HasPrefix(line, " ") {
			continue
		}
		inList = false
		out.WriteString(line)
		if newHash, ok := hashes[strings.TrimSpace(line)]; ok {
			inList = true
			for _, f := range listed {
				h := newHash()
				h.Write(f.body)
				fmt.Fprintf(&out, " %s %8d %s\n", hex.EncodeToString(h.Sum(nil)), len(f.body), f.path)
			}
		}
	}
	ts.release = out.Bytes()
	return ts
}

// serve adds the suite's routes: its InRelease with validators (a 304 for a
// request that presents them) and its index files, which must be asked for as
// they are.
func (ts aptTestSuite) serve(srv *fixtureServer, etag string) {
	in := "/dists/" + ts.suite + "/InRelease"
	srv.on("GET", in).reply(200, ts.release).withHeader("ETag", etag).withHeader("Last-Modified", "Sat, 12 Sep 2026 07:59:10 GMT")
	srv.on("GET", in).requireHeader("If-None-Match", etag).reply(http.StatusNotModified, nil)
	for p, body := range ts.files {
		srv.on("GET", p).requireHeader("Accept-Encoding", "identity").reply(200, body)
	}
	for _, p := range ts.missing {
		srv.on("GET", p).reply(http.StatusNotFound, nil)
	}
}

func aptTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := apt.New(apt.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// aptServedAs is what the backend derives from a .deb's name: the package and
// its version without epoch (pool file names leave it out).
func aptServedAs(name string) func(Release, Artifact) (string, string) {
	return func(r Release, _ Artifact) (string, string) {
		v := r.Version
		if i := strings.IndexByte(v, ':'); i >= 0 {
			v = v[i+1:]
		}
		return name, v
	}
}

func aptDrainBootstrap(t *testing.T, f Feed) ([]batchView, string) {
	t.Helper()
	var out []batchView
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, viewBatch(t, b))
		cursor = b.Next
		if !b.More {
			return out, cursor
		}
		if i > 10 {
			t.Fatal("Bootstrap does not end")
		}
	}
}

// aptReplaceStanza edits a Packages index: the stanza of package name is
// replaced by repl ("" removes it).
func aptReplaceStanza(t *testing.T, doc []byte, name, repl string) []byte {
	t.Helper()
	stanzas := strings.Split(strings.TrimRight(string(doc), "\n"), "\n\n")
	var out []string
	found := false
	for _, s := range stanzas {
		if strings.HasPrefix(s, "Package: "+name+"\n") {
			found = true
			if repl != "" {
				out = append(out, repl)
			}
			continue
		}
		out = append(out, s)
	}
	if !found {
		t.Fatalf("no stanza of %s", name)
	}
	return []byte(strings.Join(out, "\n\n") + "\n")
}

func TestAptFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://deb.debian.org/debian", map[string]string{"suites": "trixie, trixie-updates"}, "https://deb.debian.org/debian [trixie trixie-updates] [main] [amd64]"},
		{"http://archive.ubuntu.com/ubuntu/", map[string]string{"suites": "noble,noble-updates,noble-security", "components": "main,universe", "architectures": "amd64,arm64"},
			"http://archive.ubuntu.com/ubuntu [noble noble-updates noble-security] [main universe] [amd64 arm64]"},
		{"https://aptly.internal.example/repo", map[string]string{"suites": "stable", "architectures": "all"}, "https://aptly.internal.example/repo [stable] [main] [all]"},
		{"https://cache.internal.example/debian", map[string]string{"suites": "trixie,trixie", "url": "https://deb.debian.org/debian/"}, "https://deb.debian.org/debian [trixie] [main] [amd64]"},
	} {
		f, err := newAptFeed(Env{Upstream: "debs", Type: "apt", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		src := f.(*aptFeed).src.(*aptSource)
		if got := fmt.Sprint(src.root, " ", src.suites, " ", src.components, " ", src.archs); got != tc.want {
			t.Errorf("%s: %s", tc.url, got)
		}
	}
	if err := Check(Env{Upstream: "debs", Type: "deb", URL: "https://deb.debian.org/debian", Options: map[string]string{"suites": "trixie"}}); err != nil {
		t.Errorf("the deb alias: %v", err)
	}
	// Config validation refuses a feed without suites, saying what to set.
	err := Check(Env{Upstream: "debs", Type: "apt", URL: "https://deb.debian.org/debian"})
	if err == nil || !strings.Contains(err.Error(), "option suites") {
		t.Errorf("no suites: %v", err)
	}
	many := make([]string, aptMaxSuites+1)
	for i := range many {
		many[i] = fmt.Sprintf("s%d", i)
	}
	// 128 indexes of long names: within the index bound, past the state's.
	longSuites := make([]string, aptMaxSuites)
	for i := range longSuites {
		longSuites[i] = fmt.Sprintf("%02d", i) + strings.Repeat("s", 62)
	}
	for _, opts := range []map[string]string{
		{"suites": ""}, {"suites": "trixie,"}, {"suites": "../etc"}, {"suites": "tri xie"}, {"suites": "/trixie"}, {"suites": "trixie//x"},
		{"suites": "trixie", "components": "main,../x"}, {"suites": "trixie", "architectures": "AMD64"}, {"suites": "trixie", "architectures": "amd64;arm64"},
		{"suites": "trixie", "dist": "x"}, {"suites": "trixie", "url": "ftp://deb.debian.org/debian"}, {"suites": "trixie", "url": "https://u:p@deb.example/"},
		{"suites": strings.Join(many, ",")},
		{"suites": "a,b,c,d", "components": "c1,c2,c3,c4,c5,c6,c7,c8", "architectures": "amd64,arm64,armhf,i386"},
		{"suites": strings.Join(longSuites, ","), "components": strings.Repeat("c", 64) + "," + strings.Repeat("d", 64),
			"architectures": strings.Repeat("x", 32) + "," + strings.Repeat("y", 32) + "," + strings.Repeat("z", 32)},
	} {
		if err := Check(Env{Upstream: "debs", Type: "apt", URL: "https://deb.debian.org/debian", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestAptBootstrapChangesReleases(t *testing.T) {
	recorded := fixture(t, "apt", "InRelease-trixie")
	amd64 := fixture(t, "apt", "Packages-trixie-main-amd64")
	all := fixture(t, "apt", "Packages-trixie-main-all")
	srv := newFixtureServer(t)
	suite := aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": amd64, "main/binary-all": all})
	suite.serve(srv, `"22485-65b4493787114"`)
	env := testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie"})
	f := mustFeed(t, env).(*aptFeed)
	f.page = 5
	batches, cursor := aptDrainBootstrap(t, f)
	checkGolden(t, "apt", "bootstrap", batches)
	// Debian says No-Support-for-Architecture-all: binary-amd64 lists the
	// packages of architecture all, and binary-all is not read. The smallest
	// form (xz) is read by its hash.
	var reqs []string
	for _, r := range srv.requests() {
		reqs = append(reqs, regexp.MustCompile(`[0-9a-f]{64}`).ReplaceAllString(r, "<sha256>"))
	}
	if got := strings.Join(reqs, " "); got != "GET /dists/trixie/InRelease GET /dists/trixie/main/binary-amd64/by-hash/SHA256/<sha256>" {
		t.Errorf("requests: %s", got)
	}

	backend := aptTestBackend(t, env)
	for _, name := range []string{"0ad-data", "bind9-libs", "curl", "libstdc++6", "tzdata", "vim"} {
		rels, err := f.Releases(context.Background(), name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "apt", "releases-trixie-"+name, viewReleases(rels))
		expectServed(t, backend, rels, aptServedAs(name))
	}
	// The records keep each file's SHA-256 in full, for a fetch that will
	// check it (the backend does not, for the .debs the mirror fetches).
	sum := regexp.MustCompile(`(?s)Package: curl\n.*?SHA256: ([0-9a-f]{64})`).FindSubmatch(amd64)[1]
	if recs, err := f.lookup("curl"); err != nil || len(recs) != 1 || recs[0].Digest != "sha256:"+string(sum) {
		t.Errorf("curl's record: %+v %v", recs, err)
	}
	_, err := f.Releases(context.Background(), "not-in-the-archive")
	mustErr(t, err, true, false, "not in the apt index")
	_, err = f.Releases(context.Background(), "Bad_Name")
	mustErr(t, err, true, false, "not a Debian package name")

	// Nothing changed: InRelease answers 304, nothing else is read.
	before := len(srv.requests())
	b, err := f.Changes(context.Background(), cursor)
	if err != nil || len(b.Items) != 0 || b.Next != cursor {
		t.Fatalf("an unchanged suite: %+v %v", b, err)
	}
	if got := srv.requests()[before:]; len(got) != 1 {
		t.Errorf("requests of an unchanged poll: %v", got)
	}

	// The Release rewritten (a new date, another ETag) around the same
	// indexes: nothing to diff, the head and the validators move on.
	redated := bytes.Replace(suite.release, []byte("Date: Sat, 12 Sep 2026 07:55:41 UTC"), []byte("Date: Mon, 16 Nov 2026 08:00:00 UTC"), 1)
	srv.on("GET", "/dists/trixie/InRelease").reply(200, redated).withHeader("ETag", `"r2"`)
	before = len(srv.requests())
	b, err = f.Changes(context.Background(), cursor)
	if err != nil || len(b.Items) != 0 || b.Head != "2026-11-16T08:00:00Z" {
		t.Fatalf("a redated Release: %+v %v", b, err)
	}
	if got := srv.requests()[before:]; len(got) != 1 {
		t.Errorf("requests of a redated Release: %v", got)
	}
	cursor = b.Next

	// A point release: curl updated, vim removed, a package added.
	curl := regexp.MustCompile(`(?s)Package: curl\n.*?SHA256: [0-9a-f]+`).Find(amd64)
	newCurl := strings.NewReplacer("8.14.1-2+deb13u5", "8.14.1-2+deb13u6", "Size: ", "Size: 1", "SHA256: ", "SHA256: e").Replace(string(curl))
	newCurl = newCurl[:len(newCurl)-1]
	changed := aptReplaceStanza(t, aptReplaceStanza(t, amd64, "curl", newCurl), "vim", "")
	changed = append(changed, []byte("\n"+strings.ReplaceAll(newCurl, "Package: curl", "Package: curl-doc"))...)
	next := aptRender(t, redated, "trixie", map[string][]byte{"main/binary-amd64": changed, "main/binary-all": all})
	next.serve(srv, `"r3"`)
	b, err = f.Changes(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "apt", "changes", viewBatch(t, b))
	if rels, err := f.Releases(context.Background(), "curl"); err != nil || len(rels) != 1 || rels[0].Version != "8.14.1-2+deb13u6" {
		t.Errorf("curl after the update: %+v %v", rels, err)
	}
	if _, err := f.Releases(context.Background(), "vim"); !IsPermanent(err) {
		t.Errorf("vim after it was removed: %v", err)
	}
}

// Ubuntu publishes no binary-all; arch-all packages are in binary-amd64.
func TestAptUbuntu(t *testing.T) {
	srv := newFixtureServer(t)
	suite := aptRender(t, fixture(t, "apt", "InRelease-noble-updates"), "noble-updates",
		map[string][]byte{"main/binary-amd64": fixture(t, "apt", "Packages-noble-updates-main-amd64")})
	suite.serve(srv, `"1ecad-66057503e62ce"`)
	env := testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "noble-updates"})
	f := mustFeed(t, env).(*aptFeed)
	batches, _ := aptDrainBootstrap(t, f)
	checkGolden(t, "apt", "bootstrap-noble-updates", batches)
	backend := aptTestBackend(t, env)
	for _, name := range []string{"bind9-libs", "libstdc++6", "tzdata"} {
		rels, err := f.Releases(context.Background(), name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "apt", "releases-noble-updates-"+name, viewReleases(rels))
		expectServed(t, backend, rels, aptServedAs(name))
	}
	// Ubuntu lists no binary-all (its packages of architecture all are in
	// binary-amd64): "all" in the option is skipped there, and the feed
	// reads binary-amd64 alone; "all" alone has nothing to follow.
	before := len(srv.requests())
	f = mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "noble-updates", "architectures": "amd64,all"})).(*aptFeed)
	if _, err := f.Bootstrap(context.Background(), ""); err != nil {
		t.Fatalf("amd64,all on Ubuntu: %v", err)
	}
	if got := srv.requests()[before:]; len(got) != 2 || !strings.Contains(got[1], "/binary-amd64/") {
		t.Errorf("amd64,all on Ubuntu read %v", got)
	}
	if rels, err := f.Releases(context.Background(), "tzdata"); err != nil || len(rels) != 1 {
		t.Errorf("tzdata (architecture all) on Ubuntu: %+v %v", rels, err)
	}
	f = mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "noble-updates", "architectures": "all"})).(*aptFeed)
	_, err := f.Bootstrap(context.Background(), "")
	mustErr(t, err, true, false, "lists no Packages index of the components")
}

// Architecture all: read when configured, or when a Release keeps those
// packages in binary-all only (it lists "all" without
// No-Support-for-Architecture-all).
func TestAptArchitectureAll(t *testing.T) {
	recorded := fixture(t, "apt", "InRelease-trixie")
	amd64 := fixture(t, "apt", "Packages-trixie-main-amd64")
	all := fixture(t, "apt", "Packages-trixie-main-all")
	for name, tc := range map[string]struct {
		release []byte
		archs   string
	}{
		"configured": {recorded, "amd64,all"},
		"implicit":   {bytes.Replace(recorded, []byte("No-Support-for-Architecture-all: Packages\n"), nil, 1), "amd64"},
		"all alone":  {recorded, "all"},
	} {
		srv := newFixtureServer(t)
		aptRender(t, tc.release, "trixie", map[string][]byte{"main/binary-amd64": amd64, "main/binary-all": all}).serve(srv, `"a"`)
		f := mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie", "architectures": tc.archs})).(*aptFeed)
		if _, err := f.Bootstrap(context.Background(), ""); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var read []string
		for _, r := range srv.requests() {
			if strings.Contains(r, "/by-hash/") {
				read = append(read, strings.Split(r, "/")[4])
			}
		}
		want := "[binary-amd64 binary-all]"
		if tc.archs == "all" {
			want = "[binary-all]"
		}
		if fmt.Sprint(read) != want {
			t.Errorf("%s: indexes read %v, want %s", name, read, want)
		}
		// 0ad-data is in both indexes: one release, one file.
		rels, err := f.Releases(context.Background(), "0ad-data")
		if err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 1 {
			t.Errorf("%s: 0ad-data %+v %v", name, rels, err)
		}
	}
}

// Two suites of one archive: a poll reads only the index whose content
// changed and copies the others' records from the stored copy.
func TestAptCopiesUnchangedIndexes(t *testing.T) {
	recorded := fixture(t, "apt", "InRelease-trixie")
	amd64 := fixture(t, "apt", "Packages-trixie-main-amd64")
	all := fixture(t, "apt", "Packages-trixie-main-all")
	updates := aptReplaceStanza(t, amd64, "0ad", "")
	srv := newFixtureServer(t)
	aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": amd64, "main/binary-all": all}).serve(srv, `"t1"`)
	upd := aptRender(t, bytes.Replace(recorded, []byte("Suite: stable"), []byte("Suite: stable-updates"), 1), "trixie-updates",
		map[string][]byte{"main/binary-amd64": updates, "main/binary-all": all})
	upd.serve(srv, `"u1"`)
	f := mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie,trixie-updates", "architectures": "amd64,all"})).(*aptFeed)
	_, cursor := aptDrainBootstrap(t, f)
	// trixie-updates: its binary-amd64 changes (a new version of curl), its
	// binary-all does not; trixie answers 304.
	newer := []byte(strings.Replace(string(updates), "8.14.1-2+deb13u5", "8.14.1-2+deb13u7", -1))
	aptRender(t, upd.release, "trixie-updates", map[string][]byte{"main/binary-amd64": newer, "main/binary-all": all}).serve(srv, `"u2"`)
	before := len(srv.requests())
	b, err := f.Changes(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range srv.requests()[before:] {
		got = append(got, regexp.MustCompile(`[0-9a-f]{64}`).ReplaceAllString(r, "<sha256>"))
	}
	if strings.Join(got, " ") != "GET /dists/trixie/InRelease GET /dists/trixie-updates/InRelease GET /dists/trixie-updates/main/binary-amd64/by-hash/SHA256/<sha256>" {
		t.Errorf("requests: %v", got)
	}
	var items []string
	for _, c := range b.Items {
		s := c.String()
		if c.Deleted {
			s += " (deleted)"
		}
		items = append(items, s)
	}
	sort.Strings(items)
	// The versions trixie-updates replaced are reported too: their files are
	// now listed by trixie alone (the engine finds them cached).
	if fmt.Sprint(items) != "[curl@8.14.1-2+deb13u5 curl@8.14.1-2+deb13u7 libcurl4t64@8.14.1-2+deb13u5 libcurl4t64@8.14.1-2+deb13u7]" {
		t.Errorf("difference: %v", items)
	}
	// curl now has two versions, one per suite, in dpkg's order; the copied
	// indexes' packages are all still there.
	rels, err := f.Releases(context.Background(), "curl")
	if err != nil || len(rels) != 2 || rels[0].Version != "8.14.1-2+deb13u5" || rels[1].Version != "8.14.1-2+deb13u7" {
		t.Errorf("curl: %+v %v", rels, err)
	}
	for _, name := range []string{"0ad", "0ad-data-common", "vim"} {
		if _, err := f.Releases(context.Background(), name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An archive without InRelease, or without by-hash, or without the smallest
// form it lists, is still read.
func TestAptFallbacks(t *testing.T) {
	recorded := fixture(t, "apt", "InRelease-trixie")
	amd64 := fixture(t, "apt", "Packages-trixie-main-amd64")
	parts := map[string][]byte{"main/binary-amd64": amd64}

	// Release only (no InRelease), no Acquire-By-Hash: named files, and the
	// Release's validators are what the next poll presents.
	suite := aptRender(t, bytes.Replace(recorded, []byte("Acquire-By-Hash: yes\n"), nil, 1), "trixie", parts)
	srv := newFixtureServer(t)
	srv.on("GET", "/dists/trixie/InRelease").reply(404, nil)
	srv.on("GET", "/dists/trixie/Release").reply(200, aptStripClearsign(suite.release)).withHeader("ETag", `"rel"`)
	srv.on("GET", "/dists/trixie/Release").requireHeader("If-None-Match", `"rel"`).reply(http.StatusNotModified, nil)
	for p, body := range suite.files {
		if !strings.Contains(p, "/by-hash/") {
			srv.on("GET", p).requireHeader("Accept-Encoding", "identity").reply(200, body)
		}
	}
	f := mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie"})).(*aptFeed)
	_, cursor := aptDrainBootstrap(t, f)
	b, err := f.Changes(context.Background(), cursor)
	if err != nil || len(b.Items) != 0 || b.Next != cursor {
		t.Errorf("the Release's 304: %+v %v", b, err)
	}
	if rels, err := f.Releases(context.Background(), "curl"); err != nil || len(rels) != 1 {
		t.Errorf("curl: %+v %v", rels, err)
	}

	// by-hash missing, then the xz form missing: the gzip form by name.
	suite = aptRender(t, recorded, "trixie", parts)
	srv = newFixtureServer(t)
	suite.serve(srv, `"a"`)
	for p := range suite.files {
		if strings.HasSuffix(p, ".gz") {
			continue
		}
		srv.on("GET", p).reply(404, nil)
	}
	f = mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie"})).(*aptFeed)
	if _, err := f.Bootstrap(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	last := srv.requests()[len(srv.requests())-1]
	if !strings.HasSuffix(last, "/dists/trixie/main/binary-amd64/Packages.gz") {
		t.Errorf("the last request: %s (all: %v)", last, srv.requests())
	}
	// Nothing served at all (the uncompressed form is not served either).
	for p := range suite.files {
		srv.on("GET", p).reply(404, nil)
	}
	f = mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie"})).(*aptFeed)
	_, err = f.Bootstrap(context.Background(), "")
	mustErr(t, err, false, false, "none of the forms")
}

func TestAptMalformedAndRefused(t *testing.T) {
	recorded := fixture(t, "apt", "InRelease-trixie")
	amd64 := fixture(t, "apt", "Packages-trixie-main-amd64")
	bootstrap := func(srv *fixtureServer, opts map[string]string) error {
		if opts == nil {
			opts = map[string]string{"suites": "trixie"}
		}
		f := mustFeed(t, testEnv(t, "apt", srv.URL(), nil, opts)).(*aptFeed)
		_, err := f.Bootstrap(context.Background(), "")
		return err
	}
	for name, tc := range map[string]struct {
		release string
		want    string
	}{
		"html":         {"<html><body>Not here</body></html>", "not a field"},
		"no digests":   {"Origin: Debian\nSuite: stable\nMD5Sum:\n e08be5a2aa84e0f84bd976c3ce580092 56620099 main/binary-amd64/Packages\n", "lists no Packages index"},
		"empty":        {"\n\n", "no field"},
		"bad digest":   {"Origin: x\nSHA256:\n nothex 12 main/binary-amd64/Packages\n zz 1 2 3\n", "lists no Packages index"},
		"escape":       {"Origin: x\nSHA256:\n " + strings.Repeat("a", 64) + " 12 ../binary-amd64/Packages\n", "lists no Packages index"},
		"no component": {"Origin: x\nComponents: contrib\nSHA256:\n " + strings.Repeat("a", 64) + " 12 main/binary-amd64/Packages\n", "has no component main"},
		"no arch":      {"Origin: x\nArchitectures: arm64\nSHA256:\n " + strings.Repeat("a", 64) + " 12 main/binary-amd64/Packages\n", "has no architecture amd64"},
		"no index":     {"Origin: x\nSHA256:\n " + strings.Repeat("a", 64) + " 12 contrib/binary-amd64/Packages\n", "lists no Packages index of the components"},
		"oversized":    {"Origin: x\nSHA256:\n " + strings.Repeat("a", 64) + " 300000000 main/binary-amd64/Packages.xz\n", "the feed reads at most"},
	} {
		srv := newFixtureServer(t)
		srv.on("GET", "/dists/trixie/InRelease").reply(200, []byte(tc.release))
		mustErr(t, bootstrap(srv, nil), true, false, tc.want)
		_ = name
	}

	// A suite the archive does not have (misspelt, or end-of-life and moved
	// to an archive host): neither InRelease nor Release. It stops the feed —
	// a configuration error — and the error names it and says what to do.
	srv := newFixtureServer(t)
	srv.on("GET", "/dists/trixie/InRelease").reply(404, nil)
	srv.on("GET", "/dists/trixie/Release").reply(404, nil)
	mustErr(t, bootstrap(srv, nil), true, false, "has neither dists/trixie/InRelease nor dists/trixie/Release")
	srv = newFixtureServer(t)
	aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": amd64}).serve(srv, `"e"`)
	srv.on("GET", "/dists/bullseye/InRelease").reply(404, nil)
	srv.on("GET", "/dists/bullseye/Release").reply(404, nil)
	mustErr(t, bootstrap(srv, map[string]string{"suites": "trixie,bullseye"}), true, false, "suite bullseye: ")
	mustErr(t, bootstrap(srv, map[string]string{"suites": "trixie,bullseye"}), true, false, "remove it from fullMirror.feed.suites")
	// An archive that answers 304 to a request it was not asked
	// conditionally.
	srv = newFixtureServer(t)
	srv.on("GET", "/dists/trixie/InRelease").reply(http.StatusNotModified, nil)
	mustErr(t, bootstrap(srv, nil), false, false, "not conditional")
	// An archive that refuses: held, not given up.
	srv = newFixtureServer(t)
	srv.on("GET", "/dists/trixie/InRelease").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "120")
	err := bootstrap(srv, nil)
	if d, ok := RetryAfterOf(err); !ok || d.Seconds() != 120 {
		t.Errorf("a 503: %v", err)
	}

	// An index whose bytes are not those the Release lists (the archive
	// changed while it was read; a cache damaged it): retried, not given up.
	suite := aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": amd64})
	other := aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": aptReplaceStanza(t, amd64, "vim", "")})
	srv = newFixtureServer(t)
	suite.serve(srv, `"a"`)
	for p := range suite.files {
		if strings.HasSuffix(p, ".xz") || strings.Contains(p, "/by-hash/") {
			for q, body := range other.files {
				if strings.HasSuffix(q, ".xz") {
					srv.on("GET", p).reply(200, body)
				}
			}
		}
	}
	mustErr(t, bootstrap(srv, nil), false, false, "the archive changed while it was read")

	// An index that is the one the Release lists but not a Packages index:
	// the archive's fault.
	garbage := []byte("<html>\n<body>maintenance</body>\n</html>\n")
	suite = aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": garbage})
	srv = newFixtureServer(t)
	suite.serve(srv, `"a"`)
	mustErr(t, bootstrap(srv, nil), true, false, "not a Packages index")

	// Stanzas the proxy cannot fetch or name are left out; the rest stay.
	odd := string(amd64) + `
Package: Bad_Name
Version: 1.0
Filename: pool/main/b/bad/bad_1.0_amd64.deb

Package: badversion
Version: 1:2:3 x
Filename: pool/main/b/badversion/badversion_1_amd64.deb

Package: escape
Version: 1.0
Filename: pool/../../etc/escape_1.0_amd64.deb

Package: notadeb
Version: 1.0
Filename: pool/main/n/notadeb/notadeb_1.0.tar.xz

Package: twice
Version: 1.0
Version: 2.0
Filename: pool/main/t/twice/twice_1.0_amd64.deb

Package: nofile
Version: 1.0

Package: flat
Version: 1.0
Filename: ./flat_1.0_amd64.deb

Package: kept
Version: 1.0
Filename: /pool/main/k/kept/kept_1.0_amd64.deb
Size: not-a-number
SHA256: short
`
	suite = aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": []byte(odd)})
	srv = newFixtureServer(t)
	suite.serve(srv, `"a"`)
	f := mustFeed(t, testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie"})).(*aptFeed)
	batches, _ := aptDrainBootstrap(t, f)
	var listed []string
	for _, b := range batches {
		for _, c := range b.Items {
			listed = append(listed, c.Name)
		}
	}
	if got := fmt.Sprint(listed); got != "[0ad 0ad-data bind9-libs curl kept libcurl4t64 libstdc++6 tzdata vim]" {
		t.Errorf("packages kept: %s", got)
	}
	rels, err := f.Releases(context.Background(), "kept")
	if err != nil || len(rels) != 1 || rels[0].Artifacts[0] != (Artifact{Path: "/pool/main/k/kept/kept_1.0_amd64.deb"}) {
		t.Errorf("kept: %+v %v", rels, err)
	}
}

// The cursor's copy must read back; a state this source did not write, or
// wrote for other suites, reads the suites afresh.
func TestAptCursorResets(t *testing.T) {
	recorded := fixture(t, "apt", "InRelease-trixie")
	srv := newFixtureServer(t)
	aptRender(t, recorded, "trixie", map[string][]byte{"main/binary-amd64": fixture(t, "apt", "Packages-trixie-main-amd64")}).serve(srv, `"a"`)
	env := testEnv(t, "apt", srv.URL(), nil, map[string]string{"suites": "trixie"})
	f := mustFeed(t, env).(*aptFeed)
	_, cursor := aptDrainBootstrap(t, f)
	var c indexCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		t.Fatal(err)
	}
	for _, cur := range []string{"[]", `{"format":"yum/1","snap":"` + c.Snap + `"}`, `{"format":"apt/1","snap":"` + strings.Repeat("0", 64) + `"}`} {
		_, err := f.Changes(context.Background(), cur)
		mustErr(t, err, false, true, "")
	}
	for name, tc := range map[string]struct {
		state    string
		requests int
	}{
		// Read afresh: InRelease unconditionally (a 200), then its index.
		"unreadable":    {`"not a state"`, 2},
		"missing suite": {`{"config":"` + f.src.(*aptSource).config + `","suites":[]}`, 2},
		// Written for other suites: InRelease unconditionally, and the
		// index whose digest the state names is copied, not read.
		"other suites": {strings.Replace(string(c.State), `"config":"`, `"config":"0`, 1), 1},
	} {
		c2 := c
		c2.State = json.RawMessage(tc.state)
		before := len(srv.requests())
		b, err := f.Changes(context.Background(), encodeCursor(&c2))
		if err != nil || len(b.Items) != 0 {
			t.Errorf("%s: %+v %v", name, b, err)
		}
		if got := srv.requests()[before:]; len(got) != tc.requests || strings.Contains(got[0], "If-None-Match") {
			t.Errorf("%s: requests %v, want %d", name, got, tc.requests)
		}
	}
}

func TestAptVersionOrder(t *testing.T) {
	for _, tc := range [][3]string{
		{"1.0", "1.0", "0"}, {"1.0", "1.1", "-1"}, {"1.0-1", "1.0-2", "-1"}, {"1:1.0", "2.0", "1"}, {"0:1.0", "1.0", "0"},
		{"1.0~rc1", "1.0", "-1"}, {"1.0~~", "1.0~", "-1"}, {"1.0~~a", "1.0~~", "1"}, {"1.0~", "1.0", "-1"}, {"1.0+b1", "1.0", "1"},
		{"1.0a", "1.0", "1"}, {"1.0a", "1.0+", "-1"}, {"1.0", "1.0.0", "-1"}, {"1.2.3-1", "1.2.3-1ubuntu1", "-1"},
		{"9.20.26-1~deb13u1", "9.20.26-1", "-1"}, {"2:9.1.1230-2", "1:9.20.26-1~deb13u1", "1"}, {"1.0", "1.0-0", "0"},
		{"1.10", "1.9", "1"}, {"1.001", "1.1", "0"}, {"a", "b", "-1"}, {"8.14.1-2+deb13u5", "8.14.1-2+deb13u6", "-1"},
		{"2026c-0+deb13u1", "2026e-0ubuntu0.24.04.1", "-1"}, {"1.0-1", "1.0-1~bpo1", "1"}, {"10:1", "9:2", "1"},
	} {
		if got := fmt.Sprint(aptCompareVersions(tc[0], tc[1])); got != tc[2] {
			t.Errorf("compare(%q, %q) = %s, want %s", tc[0], tc[1], got, tc[2])
		}
	}
}
