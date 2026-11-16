package fullmirror

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/conan"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestConanFeedLocation(t *testing.T) {
	f, err := newConanFeed(Env{Upstream: "cc", Type: "conan", URL: "https://center2.conan.io"})
	if err != nil {
		t.Fatal(err)
	}
	cf := f.(*conanFeed)
	if got := cf.git.remote.repo.String(); got != conanPublicRepo {
		t.Errorf("ConanCenter's repository %s", got)
	}
	if cf.settle != conanDefaultSettle || cf.binaries.mode != conanBinariesNone {
		t.Errorf("defaults: settle %s binaries %+v", cf.settle, cf.binaries)
	}
	// Artifactory, Nexus and conan_server have no feed: refused at load time,
	// saying what to set.
	err = Check(Env{Upstream: "corp", Type: "conan", URL: "https://artifactory.internal.example/artifactory/api/conan/conan-remote"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a private remote without a feed URL: %v", err)
	}
	if err := Check(Env{Upstream: "corp", Type: "conan", URL: "https://conan.internal.example",
		Options: map[string]string{"url": "https://git.internal.example/recipes.git", "branch": "master", "binaries": "all", "settle": "2h"}}); err != nil {
		t.Errorf("a private remote with a recipe repository: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"branch": "a..b"}, {"settle": "1d"}, {"binaries": "some"},
		{"binaries": "os"}, {"binaries": "os="}, {"binaries": "=Linux"}, {"binaries": "os=a=b"}, {"binaries": "options.=x"},
		{"binaries": "os=Linux;arch"}, {"binaries": ";"}, {"binaries": "o s=Linux"}} {
		if err := Check(Env{Upstream: "c", Type: "conan", URL: "https://center2.conan.io", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestConanAreaAndCoordinates(t *testing.T) {
	for dir, want := range map[string]bool{"": true, "recipes": true, "recipes/zlib": true, "recipes/zlib/all": true,
		"recipes/zlib/all/patches": true, "recipes/zlib/all/patches/1.x": true, "recipes/zlib/all/test_package": false,
		"recipes/zlib/all/test_v1_package": false, "recipes/zlib/all/test_package/src": false, "recipes/x": false,
		"docs": false, ".github": false, "linter": false, "recipes/.hidden": false} {
		if got := conanArea(dir); got != want {
			t.Errorf("area %q: %v, want %v", dir, got, want)
		}
	}
	for _, tc := range []struct {
		path   string
		change gitChange
		want   string
	}{
		{"recipes/zlib/config.yml", gitModified, "zlib"},
		{"recipes/zlib/all/conanfile.py", gitAdded, "zlib"},
		{"recipes/zlib/all/patches/0001-fix.patch", gitDeleted, "zlib"},
		{"recipes/zlib/config.yml", gitDeleted, "zlib deleted"},
		{"recipes/zlib/README.md", gitAdded, "zlib"},
		{"recipes/x/config.yml", gitAdded, ""},
		{"recipes/config.yml", gitAdded, ""},
		{"docs/recipes/zlib/x", gitAdded, ""},
		{"README.md", gitModified, ""},
	} {
		c, ok := conanCoordinate(tc.path, tc.change)
		got := ""
		if ok {
			got = c.String()
			if c.Deleted {
				got += " deleted"
			}
		}
		if got != tc.want {
			t.Errorf("%s (%d): %q, want %q", tc.path, tc.change, got, tc.want)
		}
	}
}

// conanTestFiles is a repository laid out as conan-center-index.
func conanTestFiles() map[string]string {
	return map[string]string{
		"README.md":                                      "# Conan Center Index\n",
		".github/workflows/stale.yml":                    "on: schedule\n",
		"docs/adding_packages/README.md":                 "how to\n",
		"linter/conanv2_transition.py":                   "x\n",
		"recipes/zlib/config.yml":                        "versions:\n  \"1.3.1\":\n    folder: all\n",
		"recipes/zlib/all/conanfile.py":                  "class ZlibConan(ConanFile): pass\n",
		"recipes/zlib/all/conandata.yml":                 "sources: {}\n",
		"recipes/zlib/all/test_package/conanfile.py":     "x\n",
		"recipes/zlib/all/test_package/test_package.c":   "int main(){}\n",
		"recipes/zlib/all/test_v1_package/conanfile.py":  "x\n",
		"recipes/boost/config.yml":                       "versions: {}\n",
		"recipes/boost/all/conanfile.py":                 "class BoostConan(ConanFile): pass\n",
		"recipes/boost/all/dependencies/deps-1.86.0.yml": "x\n",
		"recipes/fmt/config.yml":                         "versions: {}\n",
		"recipes/fmt/all/conanfile.py":                   "x\n",
		"recipes/fmt/all/test_package/conanfile.py":      "x\n",
		"recipes/x/config.yml":                           "not a recipe name\n",
	}
}

func TestConanFollowsTheRecipesRepository(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 13, 15, 0, 0, 0, time.UTC)
	files := conanTestFiles()
	repo.commit(files, t0, false)
	git := newGitTestServer(t, repo)
	env := testEnv(t, "conan", "https://center2.conan.io", newFakeReads(), map[string]string{"url": git.URL(), "settle": "0"})
	f := mustFeed(t, env).(*conanFeed)
	f.git.page = 2
	ctx := context.Background()
	b1, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f.Bootstrap(ctx, b1.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b1.Items), b1.More, names(b2.Items), b2.More); got != "[boost fmt] true [zlib] false" {
		t.Fatalf("bootstrap %s", got)
	}
	var c gitCursor
	if err := decodeCursor(b2.Next, f.git.format(), &c); err != nil || c.Commit != repo.head.String() || c.Listing {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	// zlib's recipe changes (a new version, a patch), fmt's test package
	// only, boost is removed, spdlog added; the docs change.
	files["recipes/zlib/config.yml"] += "  \"1.4\":\n    folder: all\n"
	files["recipes/zlib/all/patches/1.4-0001-fix.patch"] = "--- a\n"
	files["recipes/fmt/all/test_package/conanfile.py"] = "y\n"
	for p := range files {
		if strings.HasPrefix(p, "recipes/boost/") {
			delete(files, p)
		}
	}
	files["recipes/spdlog/config.yml"] = "versions: {}\n"
	files["recipes/spdlog/all/conanfile.py"] = "x\n"
	files["docs/adding_packages/README.md"] = "how to, again\n"
	repo.commit(files, t0.Add(time.Minute), false)
	f.git.page = gitDefaultPage
	ch, err := f.Changes(ctx, b2.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "conan", "changes", viewBatch(t, ch))

	// The default settle period holds a commit back for an hour.
	f.settle = conanDefaultSettle
	f.now = func() time.Time { return t0.Add(90 * time.Minute) }
	files["recipes/fmt/all/conanfile.py"] = "z\n"
	repo.commit(files, t0.Add(80*time.Minute), false)
	held, err := f.Changes(ctx, ch.Next)
	if err != nil || len(held.Items) != 0 || held.Next != ch.Next {
		t.Errorf("a commit ten minutes old was reported: %+v %v", held, err)
	}
	f.now = func() time.Time { return t0.Add(141 * time.Minute) }
	settled, err := f.Changes(ctx, ch.Next)
	if err != nil || fmt.Sprint(names(settled.Items)) != "[fmt]" {
		t.Errorf("the settled commit: %+v %v", settled, err)
	}
}

// conanTestFeed builds the conan adapter with a fixture server standing in
// for the remote (the search goes to it directly) and a fake pipeline.
func conanTestFeed(t *testing.T, binaries string) (*conanFeed, *fixtureServer, *fakeReads, backends.Backend) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	opts := map[string]string{"url": "https://git.internal.example/recipes.git"}
	if binaries != "" {
		opts["binaries"] = binaries
	}
	env := testEnv(t, "conan", srv.URL(), reads, opts)
	f := mustFeed(t, env).(*conanFeed)
	b, err := conan.New(conan.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return f, srv, reads, b
}

const (
	conanTestRrev131 = "cac0f6daea041b0ccf42934163defb20"
	conanTestRrev14  = "f51abf05ab684e2283b6d4c1243b624f"
)

// conanTestRecorded loads the recorded zlib documents into the fake
// pipeline: the latest revisions and file lists of zlib 1.3.1 and 1.4, and
// 1.3.1's package search with four packages' latest revisions and files.
func conanTestRecorded(t *testing.T, reads *fakeReads) {
	t.Helper()
	ref := "/v2/conans/zlib/%s/_/_"
	reads.set(fmt.Sprintf(ref, "1.3.1")+"/latest", fixture(t, "conan", "latest-zlib-1.3.1.json"))
	reads.set(fmt.Sprintf(ref, "1.3.1")+"/revisions/"+conanTestRrev131+"/files", fixture(t, "conan", "files-zlib-1.3.1.json"))
	reads.set(fmt.Sprintf(ref, "1.4")+"/latest", fixture(t, "conan", "latest-zlib-1.4.json"))
	reads.set(fmt.Sprintf(ref, "1.4")+"/revisions/"+conanTestRrev14+"/files", fixture(t, "conan", "files-zlib-1.4.json"))
	rev := fmt.Sprintf(ref, "1.3.1") + "/revisions/" + conanTestRrev131
	reads.set(rev+"/search", fixture(t, "conan", "pkgsearch-zlib-1.3.1.json"))
	for pid, prev := range map[string]string{
		"c81087b06d1a5beef0ad711fc32d45f7a425a8f3": "d3a7706ae25c74b78bafbb0b63cb5dcf",
		"17561cbc2922b459119809d525458e11e7bcb047": "40bdae4d2cc35cdad193f96988c64922",
		"2f813e311fb9c41521c47949c9a19c12f085829b": "33cfeaccf313173285cfc3fd1d9b0ac4",
		"0d6dd492a7d31822b2f2686ec67bbaef586416a3": "35731faa85afc1b85b1951d87e71dea7",
	} {
		reads.set(rev+"/packages/"+pid+"/latest", fixture(t, "conan", "pkglatest-zlib-1.3.1-"+pid[:8]+".json"))
		reads.set(rev+"/packages/"+pid+"/revisions/"+prev+"/files", fixture(t, "conan", "pkgfiles-zlib-1.3.1-"+pid[:8]+".json"))
	}
}

func TestConanReleasesComeFromTheSearchAndTheLatestRevisions(t *testing.T) {
	f, srv, reads, backend := conanTestFeed(t, "")
	srv.on("GET", "/v2/conans/search?q=zlib/*").reply(200, fixture(t, "conan", "search-zlib.json"))
	conanTestRecorded(t, reads)
	ctx := context.Background()
	// The remote lists seven versions; the pipeline here serves the
	// revisions of two (the others answer 404 and are left out).
	rels, err := f.Releases(ctx, "zlib")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "conan", "releases-zlib", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "zlib", r.Version })
	if n := reads.count("/v2/conans/zlib/1.3.1/_/_/revisions/" + conanTestRrev131 + "/search"); n != 0 {
		t.Errorf("the package search was read without binaries: %d", n)
	}
	// The search went to the remote with the name's pattern.
	if got := srv.requests(); len(got) != 1 || got[0] != "GET /v2/conans/search?q=zlib%2F%2A" {
		t.Errorf("requests %v", got)
	}
}

func TestConanReleasesWithBinaries(t *testing.T) {
	f, srv, reads, backend := conanTestFeed(t, "os=Linux,arch=x86_64,compiler.version=13,options.shared=False;os=MACOS,arch=armv8,options.shared=True")
	srv.on("GET", "/v2/conans/search?q=zlib/*").json(`{"results":["zlib/1.3.1@_/_"]}`)
	conanTestRecorded(t, reads)
	ctx := context.Background()
	rels, err := f.Releases(ctx, "zlib")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "conan", "releases-zlib-binaries", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "zlib", r.Version })

	// Every binary package; one whose latest revision the remote does not
	// serve is left out, the others stay.
	f.binaries, _ = conanParseBinaries("all")
	reads.setDoc("/v2/conans/zlib/1.3.1/_/_/revisions/"+conanTestRrev131+"/packages/0d6dd492a7d31822b2f2686ec67bbaef586416a3/latest", fakeDoc{status: 404})
	rels, err = f.Releases(ctx, "zlib")
	if err != nil {
		t.Fatal(err)
	}
	pkgs := map[string]bool{}
	for _, a := range rels[0].Artifacts {
		if _, rest, ok := strings.Cut(a.Path, "/packages/"); ok {
			pkgs[rest[:8]] = true
		}
	}
	if fmt.Sprint(len(rels[0].Artifacts), pkgs) != "13 map[17561cbc:true 2f813e31:true c81087b0:true]" {
		t.Errorf("all binaries: %d files of %v", len(rels[0].Artifacts), pkgs)
	}
	// A package search that fails for now fails the listing; one the
	// remote does not serve leaves the recipe alone.
	reads.setDoc("/v2/conans/zlib/1.3.1/_/_/revisions/"+conanTestRrev131+"/search", fakeDoc{status: 503})
	_, err = f.Releases(ctx, "zlib")
	mustErr(t, err, false, false, "503")
	reads.setDoc("/v2/conans/zlib/1.3.1/_/_/revisions/"+conanTestRrev131+"/search", fakeDoc{status: 404})
	rels, err = f.Releases(ctx, "zlib")
	if err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 4 {
		t.Errorf("without a package search: %v %v", rels, err)
	}
}

func TestConanMalformedAndRefused(t *testing.T) {
	f, srv, reads, _ := conanTestFeed(t, "")
	ctx := context.Background()
	for _, tc := range []struct{ name, body, want string }{
		{"garbage", "<html/>", "search for garbage"},
		{"shape", `{"results":"zlib/1.0@_/_"}`, "search for shape"},
		{"missing", `{"refs":[]}`, "no results"},
		{"none", string(fixture(t, "conan", "search-none.json")), "no recipe none"},
		{"others", `{"results":["others-ng/1.0@_/_","others/1.0@user/stable","others/../x@_/_",7]}`, "no recipe others"},
	} {
		srv.on("GET", "/v2/conans/search?q="+tc.name+"/*").json(tc.body)
		_, err := f.Releases(ctx, tc.name)
		mustErr(t, err, true, false, tc.want)
	}
	// The remote asks for a wait, or fails for now.
	srv.on("GET", "/v2/conans/search?q=busy/*").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "30")
	_, err := f.Releases(ctx, "busy")
	if d, ok := RetryAfterOf(err); !ok || d != 30*time.Second {
		t.Errorf("a 429: %v", err)
	}
	srv.on("GET", "/v2/conans/search?q=down/*").reply(http.StatusBadGateway, nil)
	_, err = f.Releases(ctx, "down")
	mustErr(t, err, false, false, "502")
	// A version whose pointer or file list is malformed is left out; when
	// every version is, the first reason is the package's error.
	srv.on("GET", "/v2/conans/search?q=lib/*").json(`{"results":["lib/1.0@_/_","lib/2.0@_/_","lib/3.0@_/_"]}`)
	reads.set("/v2/conans/lib/1.0/_/_/latest", []byte(`{"revision":"../../x"}`))
	reads.set("/v2/conans/lib/2.0/_/_/latest", []byte(`{"revision":"abc"}`))
	reads.set("/v2/conans/lib/2.0/_/_/revisions/abc/files", []byte(`{"files":["conanfile.py"]}`))
	reads.set("/v2/conans/lib/3.0/_/_/latest", []byte(`{"revision":"def","time":"2026-01-02T03:04:05.000+0000"}`))
	reads.set("/v2/conans/lib/3.0/_/_/revisions/def/files", []byte(`{"files":{"conanfile.py":{},"metadata/logs/build.log":{},"../x":{}}}`))
	rels, err := f.Releases(ctx, "lib")
	if err != nil || len(rels) != 1 || rels[0].Version != "3.0" || len(rels[0].Artifacts) != 1 || rels[0].Published.Format(time.RFC3339) != "2026-01-02T03:04:05Z" {
		t.Errorf("lib: %+v %v", rels, err)
	}
	// A gate's verdict on a version's pointer: that version is left out, and
	// with every version refused the verdict is the package's error.
	srv.on("GET", "/v2/conans/search?q=typo/*").json(`{"results":["typo/1.0@_/_"]}`)
	reads.setDoc("/v2/conans/typo/1.0/_/_/latest", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typo")
	mustErr(t, err, true, false, "nameguard")
	// Access control is not a verdict on the recipe: the listing waits.
	srv.on("GET", "/v2/conans/search?q=held/*").json(`{"results":["held/1.0@_/_"]}`)
	reads.setDoc("/v2/conans/held/1.0/_/_/latest", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	_, err = f.Releases(ctx, "../etc")
	mustErr(t, err, true, false, "not a Conan recipe name")
}

func TestConanVersionOrder(t *testing.T) {
	// Conan 2's own order (conan/internal/model/version.py): items by value,
	// trailing zeros ignored, pre-releases first, build metadata last.
	ordered := []string{"0.9", "1.0-alpha", "1.0-beta.2", "1.0-beta.10", "1", "1.0.0", "1.0+build.1", "1.0.1", "1.2.11", "1.2.12",
		"1.2.13", "1.3", "1.3.1", "1.3.1.1", "1.3.2", "1.4", "1.10", "1.a", "2.0", "10.0", "20240722.0", "cci.20230101"}
	shuffled := append([]string(nil), ordered...)
	sort.Strings(shuffled)
	sort.SliceStable(shuffled, func(i, j int) bool { return conanVersionCompare(shuffled[i], shuffled[j]) < 0 })
	if fmt.Sprint(shuffled) != fmt.Sprint(ordered) {
		t.Errorf("order\n got %v\nwant %v", shuffled, ordered)
	}
	for _, p := range [][2]string{{"1.3", "1.3.0"}, {"01", "1"}, {"1.0", "1.0.0"}} {
		if c := conanVersionCompare(p[0], p[1]); c >= 0 || conanVersionCompare(p[1], p[0]) <= 0 {
			t.Errorf("%s vs %s: %d (ties break by text)", p[0], p[1], c)
		}
	}
	// The search lists versions as text ("1.3" after "1.3.2"); the feed
	// lists them in version order.
	vs, err := conanParseSearch("zlib", fixture(t, "conan", "search-zlib.json"))
	if err != nil || fmt.Sprint(vs) != "[1.2.11 1.2.12 1.2.13 1.3 1.3.1 1.3.2 1.4]" {
		t.Errorf("search order %v %v", vs, err)
	}
}

func TestConanBinariesFilter(t *testing.T) {
	pkgs, err := conanParsePackages(fixture(t, "conan", "pkgsearch-zlib-1.3.1.json"))
	if err != nil || len(pkgs) != 4 {
		t.Fatalf("packages %v %v", pkgs, err)
	}
	for filter, want := range map[string]string{
		"all":                                   "[0d6dd492 17561cbc 2f813e31 c81087b0]",
		"none":                                  "[]",
		"os=Linux":                              "[17561cbc c81087b0]",
		"os=linux,options.shared=true":          "[17561cbc]",
		"os=Windows;os=Macos,arch=armv8":        "[0d6dd492 2f813e31]",
		"compiler=msvc,compiler.runtime=static": "[]",
		"options.fPIC=True":                     "[c81087b0]",
		"os=FreeBSD":                            "[]",
	} {
		b, err := conanParseBinaries(filter)
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		got := []string{}
		for _, p := range pkgs {
			if b.selects(p) {
				got = append(got, p.id[:8])
			}
		}
		if fmt.Sprint(got) != want {
			t.Errorf("%s: %v, want %s", filter, got, want)
		}
	}
}

func TestConanCursorResets(t *testing.T) {
	repo := newGitTestRepo()
	repo.commit(conanTestFiles(), time.Now().Add(-2*time.Hour), false)
	git := newGitTestServer(t, repo)
	f := mustFeed(t, testEnv(t, "conan", "https://center2.conan.io", newFakeReads(), map[string]string{"url": git.URL()})).(*conanFeed)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, cur := range map[string]string{
		"garbage":    "{",
		"bazel's":    encodeCursor(&gitCursor{Format: cursorFormat("bazel-git", 1), Commit: repo.head.String()}),
		"not stored": f.git.cursor(gitCursor{Commit: strings.Repeat("0f", 20)}),
		"listing":    f.git.cursor(gitCursor{Commit: repo.head.String(), Listing: true}),
	} {
		_, err := f.Changes(ctx, cur)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, false, true, "")
	}
	if _, err := f.Bootstrap(ctx, b.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
	// The trees the cursor names are gone (a restored backup without them):
	// the registry is enumerated again rather than the cursor trusted.
	f.git.files.prune(gitStorePrefix)
	_, err = f.Changes(ctx, b.Next)
	mustErr(t, err, false, true, "not stored")
}
