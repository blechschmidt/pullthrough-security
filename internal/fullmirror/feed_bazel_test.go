package fullmirror

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/bazel"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestBazelFeedLocation(t *testing.T) {
	f, err := newBazelFeed(Env{Upstream: "bcr", Type: "bazel", URL: "https://bcr.bazel.build/"})
	if err != nil {
		t.Fatal(err)
	}
	bf := f.(*bazelFeed)
	if got := bf.git.remote.repo.String(); got != bazelPublicRepo {
		t.Errorf("the BCR's repository %s", got)
	}
	if bf.settle != bazelDefaultSettle {
		t.Errorf("settle %s", bf.settle)
	}
	// A private registry is a static tree: refused at load time, saying what
	// to set.
	err = Check(Env{Upstream: "corp", Type: "bazel", URL: "https://bazel-registry.internal.example"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a private registry without a feed URL: %v", err)
	}
	if err := Check(Env{Upstream: "corp", Type: "bazel", URL: "https://bazel-registry.internal.example",
		Options: map[string]string{"url": "https://git.internal.example/registry.git", "branch": "main", "settle": "0"}}); err != nil {
		t.Errorf("a private registry with its Git repository: %v", err)
	}
	for _, opts := range []map[string]string{{"branch": "a..b"}, {"branch": "-x"}, {"since": "x"}, {"settle": "soon"},
		{"settle": "-1m"}, {"settle": "800h"}, {"url": "ftp://x"}, {"url": "https://u:p@git.example/r.git"}} {
		if err := Check(Env{Upstream: "b", Type: "bazel", URL: "https://bcr.bazel.build", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestBazelAreaAndCoordinates(t *testing.T) {
	for dir, want := range map[string]bool{"": true, "modules": true, "modules/zlib": true, "modules/zlib/1.3.1": true,
		"modules/zlib/1.3.1/patches": false, "modules/zlib/1.3.1/overlay": false, "modules/Zlib": false, "modules/zlib/1 0": false,
		".github": false, "tools": false, "docs/modules": false} {
		if got := bazelArea(dir); got != want {
			t.Errorf("area %q: %v, want %v", dir, got, want)
		}
	}
	for _, tc := range []struct {
		path   string
		change gitChange
		want   string // "" for no coordinate
	}{
		{"modules/zlib/1.3.1/MODULE.bazel", gitAdded, "zlib@1.3.1"},
		{"modules/zlib/1.3.1/source.json", gitModified, "zlib@1.3.1"},
		{"modules/zlib/1.3.1/presubmit.yml", gitModified, "zlib@1.3.1"},
		{"modules/zlib/1.3.1/overlay/lib/defs.h", gitAdded, "zlib@1.3.1"},
		{"modules/zlib/1.3.1/MODULE.bazel", gitDeleted, "zlib@1.3.1 deleted"},
		{"modules/zlib/1.3.1/source.json", gitDeleted, "zlib@1.3.1 deleted"},
		{"modules/zlib/1.3.1/presubmit.yml", gitDeleted, ""},
		{"modules/zlib/1.3.1/patches/x.patch", gitDeleted, ""},
		{"modules/zlib/metadata.json", gitModified, ""},
		{"modules/zlib/README.md", gitAdded, ""},
		{"modules/Zlib/1.0/MODULE.bazel", gitAdded, ""},
		{"modules/zlib/1.0~x/MODULE.bazel", gitAdded, ""},
		{"bazel_registry.json", gitModified, ""},
		{"tools/modules/zlib/1.0/MODULE.bazel", gitAdded, ""},
	} {
		c, ok := bazelCoordinate(tc.path, tc.change)
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

// bazelCollect maps changed files, given as "<change> <path>" lines, to the
// coordinates the bazel feed reports for them.
func bazelCollect(t *testing.T, lines []string) []Coordinate {
	t.Helper()
	g := &gitIndex{spec: gitIndexSpec{typ: "bazel", area: bazelArea, coordinate: bazelCoordinate}}
	items, err := g.collect(func(fn func(string, gitChange) error) error {
		for _, l := range lines {
			var c int
			var p string
			if _, err := fmt.Sscanf(l, "%d %s", &c, &p); err != nil {
				return err
			}
			if err := fn(p, gitChange(c)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestBazelCoordinatesOfARealHeadCommit(t *testing.T) {
	// The files the Bazel Central Registry's head 4410f9ba changed against
	// its parent (recorded 2026-11-16, see gitfeed_test.go): seven new
	// module versions, each with its metadata.json, MODULE.bazel,
	// presubmit.yml, source.json and overlay files.
	var lines []string
	if err := json.Unmarshal(fixture(t, "git", "golden/bcr-incremental-diff.json"), &lines); err != nil {
		t.Fatal(err)
	}
	mapped := bazelCollect(t, lines)
	checkGolden(t, "bazel", "real-head-coordinates", mapped)
	if len(mapped) != 7 {
		t.Errorf("%d coordinates, want the 7 module versions", len(mapped))
	}

	// The same commit diffed with the feed's own area: the recorded pack and
	// the parent's stored trees give the same seven versions without the
	// overlay trees ever being read.
	pack, err := readFetchResponse(bytes.NewReader(fixture(t, "git", "fetch-incremental.bin")), maxGitPack)
	if err != nil {
		t.Fatal(err)
	}
	objs, err := parsePack(pack)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := parseOID("4410f9ba1bf91c2edae641c93b511f3010ded389")
	parent, _ := parseOID("9ee49c80e1216155e15ee08c43525438b2e17ffc")
	co, _ := objs.get(head)
	ci, err := parseGitCommit(co.data)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/"+gitStoreName("trees-", parent), fixture(t, "git", "bcr-parent-trees.gz"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := loadGitTreeStore(files{dir: dir}, "trees-", parent)
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	look := func(id gitOID) ([]byte, bool) {
		read++
		if o, ok := objs.get(id); ok {
			return o.data, true
		}
		return st.lookup(id)
	}
	g := &gitIndex{spec: gitIndexSpec{typ: "bazel", area: bazelArea, coordinate: bazelCoordinate}}
	diffed, err := g.collect(func(fn func(string, gitChange) error) error {
		return diffGitTrees(look, bazelArea, st.root, ci.tree, "", fn)
	})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(diffed) != fmt.Sprint(mapped) {
		t.Errorf("the diff with the feed's area %v, want %v", diffed, mapped)
	}
	// 2 roots, 2 modules trees, 7 module and 7 version trees; not the
	// overlay trees beneath.
	if read != 18 {
		t.Errorf("%d trees read", read)
	}
}

// bazelTestFiles is a repository laid out as the Bazel Central Registry.
func bazelTestFiles() map[string]string {
	return map[string]string{
		".bazelversion":                   "8.4.2\n",
		"README.md":                       "# Bazel Central Registry\n",
		"bazel_registry.json":             `{"mirrors": []}`,
		".github/workflows/presubmit.yml": "on: pull_request\n",
		"tools/registry.py":               "#!/usr/bin/env python3\n",

		"modules/zlib/metadata.json":                          `{"versions": ["1.3.1"], "yanked_versions": {}}`,
		"modules/zlib/README.md":                              "notes",
		"modules/zlib/1.3.1/MODULE.bazel":                     `module(name = "zlib", version = "1.3.1")`,
		"modules/zlib/1.3.1/source.json":                      `{"url": "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"}`,
		"modules/zlib/1.3.1/presubmit.yml":                    "matrix: {}\n",
		"modules/zlib/1.3.1/patches/add_build_file.patch":     "--- a\n+++ b\n",
		"modules/zlib/1.3.1/patches/module_dot_bazel.patch":   "--- a\n+++ b\n",
		"modules/libnl/metadata.json":                         `{"versions": ["3.7.0"], "yanked_versions": {}}`,
		"modules/libnl/3.7.0/MODULE.bazel":                    `module(name = "libnl", version = "3.7.0")`,
		"modules/libnl/3.7.0/source.json":                     `{"url": "https://github.com/thom311/libnl/releases/download/libnl3_7_0/libnl-3.7.0.tar.gz"}`,
		"modules/libnl/3.7.0/presubmit.yml":                   "matrix: {}\n",
		"modules/libnl/3.7.0/overlay/BUILD.bazel":             "cc_library()\n",
		"modules/libnl/3.7.0/overlay/lib/defs.h":              "#define X 1\n",
		"modules/rules_cc/metadata.json":                      `{"versions": ["0.0.9", "0.1.0"], "yanked_versions": {}}`,
		"modules/rules_cc/0.0.9/MODULE.bazel":                 `module(name = "rules_cc", version = "0.0.9")`,
		"modules/rules_cc/0.0.9/source.json":                  `{"url": "https://github.com/bazelbuild/rules_cc/releases/download/0.0.9/rules_cc-0.0.9.tar.gz"}`,
		"modules/rules_cc/0.0.9/presubmit.yml":                "matrix: {}\n",
		"modules/rules_cc/0.1.0/MODULE.bazel":                 `module(name = "rules_cc", version = "0.1.0")`,
		"modules/rules_cc/0.1.0/source.json":                  `{"url": "https://github.com/bazelbuild/rules_cc/releases/download/0.1.0/rules_cc-0.1.0.tar.gz"}`,
		"modules/rules_cc/0.1.0/presubmit.yml":                "matrix: {}\n",
		"modules/Not_A_Module/1.0/MODULE.bazel":               "x",
		"modules/zlib/1.3.1/patches/nested/not-followed.diff": "x",
	}
}

func TestBazelFollowsTheRegistryRepository(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 15, 18, 0, 0, 0, time.UTC)
	files := bazelTestFiles()
	repo.commit(files, t0, false)
	git := newGitTestServer(t, repo)
	env := testEnv(t, "bazel", "https://bcr.bazel.build", newFakeReads(), map[string]string{"url": git.URL(), "settle": "0"})
	f := mustFeed(t, env).(*bazelFeed)
	f.git.page = 2
	ctx := context.Background()

	// Bootstrap lists every module once; rules_cc's two versions straddle
	// the pages and it is listed in both.
	b1, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f.Bootstrap(ctx, b1.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b1.Items), b1.More, names(b2.Items), b2.More); got != "[libnl rules_cc] true [rules_cc zlib] false" {
		t.Fatalf("bootstrap %s", got)
	}
	var c gitCursor
	if err := decodeCursor(b2.Next, f.git.format(), &c); err != nil || c.Commit != repo.head.String() || c.Listing || c.To != "" {
		t.Errorf("final cursor %+v (%v), want the follow cursor at the head", c, err)
	}
	if !b2.HeadTime.Equal(t0) {
		t.Errorf("head time %v", b2.HeadTime)
	}

	// A new version (with its metadata.json), a yank (metadata.json only),
	// a fixed source.json and overlay file, a removed version, a removed
	// presubmit.yml, changes outside the modules.
	files["modules/zlib/metadata.json"] = `{"versions": ["1.3.1", "1.3.1.bcr.5"], "yanked_versions": {}}`
	files["modules/zlib/1.3.1.bcr.5/MODULE.bazel"] = `module(name = "zlib", version = "1.3.1.bcr.5")`
	files["modules/zlib/1.3.1.bcr.5/source.json"] = `{"url": "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"}`
	files["modules/zlib/1.3.1.bcr.5/presubmit.yml"] = "matrix: {}\n"
	files["modules/zlib/1.3.1.bcr.5/patches/add_build_file.patch"] = "--- a\n+++ b\n"
	files["modules/rules_cc/metadata.json"] = `{"versions": ["0.0.9", "0.1.0"], "yanked_versions": {"0.1.0": "broken"}}`
	files["modules/libnl/3.7.0/source.json"] = `{"url": "https://github.com/thom311/libnl/releases/download/libnl3_7_0/libnl-3.7.0.tar.gz", "overlay": {}}`
	files["modules/libnl/3.7.0/overlay/lib/defs.h"] = "#define X 2\n"
	for _, p := range []string{"MODULE.bazel", "source.json", "presubmit.yml"} {
		delete(files, "modules/rules_cc/0.0.9/"+p)
	}
	delete(files, "modules/zlib/1.3.1/presubmit.yml")
	files["tools/registry.py"] = "#!/usr/bin/env python3\n# v2\n"
	files["README.md"] = "# BCR\n"
	repo.commit(files, t0.Add(time.Minute), false)
	f.git.page = gitDefaultPage
	ch, err := f.Changes(ctx, b2.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "bazel", "changes", viewBatch(t, ch))
}

func TestBazelChangesWaitForCommitsToSettle(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 15, 18, 0, 0, 0, time.UTC)
	files := map[string]string{"modules/zlib/metadata.json": "{}", "modules/zlib/1.3.1/MODULE.bazel": "m"}
	repo.commit(files, t0, false)
	git := newGitTestServer(t, repo)
	env := testEnv(t, "bazel", "https://bcr.bazel.build", newFakeReads(), map[string]string{"url": git.URL(), "settle": "30m"})
	f := mustFeed(t, env).(*bazelFeed)
	now := t0
	f.now = func() time.Time { return now }
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	cursor := b.Next
	// Two commits, ten and forty minutes after the first.
	files["modules/zlib/1.3.2/MODULE.bazel"] = "m"
	c1 := repo.commit(files, t0.Add(10*time.Minute), false)
	files["modules/zlib/1.3.3/MODULE.bazel"] = "m"
	c2 := repo.commit(files, t0.Add(40*time.Minute), false)

	// At 0:45 only the first has settled: its version is reported, the head
	// is shown ahead of the cursor.
	now = t0.Add(45 * time.Minute)
	b, err = f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[zlib@1.3.2]" || b.Head != c2.String() || b.LagKnown || b.More {
		t.Fatalf("at 0:45: %s head %s lagKnown %v", got, b.Head, b.LagKnown)
	}
	var c gitCursor
	if err := decodeCursor(b.Next, f.git.format(), &c); err != nil || c.Commit != c1.String() {
		t.Fatalf("cursor %+v, want the settled commit %s", c, c1)
	}
	cursor = b.Next

	// At 0:50 the second has not: nothing, the cursor stays.
	now = t0.Add(50 * time.Minute)
	b, err = f.Changes(ctx, cursor)
	if err != nil || len(b.Items) != 0 || b.Next != cursor || b.Head != c2.String() || !b.HeadTime.Equal(t0.Add(40*time.Minute)) {
		t.Fatalf("at 0:50: %+v %v", b, err)
	}

	// At 1:15 it has.
	now = t0.Add(75 * time.Minute)
	b, err = f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[zlib@1.3.3]" || b.Head != c2.String() || !b.LagKnown {
		t.Fatalf("at 1:15: %s %+v", got, b)
	}
	cursor = b.Next
	fetches := len(git.fetches)
	if b, err := f.Changes(ctx, cursor); err != nil || len(b.Items) != 0 || b.Next != cursor || len(git.fetches) != fetches {
		t.Fatalf("idle: %+v %v (fetches %d → %d)", b, err, fetches, len(git.fetches))
	}

	// A settled difference too long for one batch is paged.
	f.git.page = 1
	files["modules/zlib/1.4.0/MODULE.bazel"] = "m"
	files["modules/zlib/1.4.1/MODULE.bazel"] = "m"
	repo.commit(files, t0.Add(80*time.Minute), false)
	now = t0.Add(3 * time.Hour)
	var got []string
	for i := 0; i < 3; i++ {
		nb, err := f.Changes(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, names(nb.Items)...)
		cursor = nb.Next
		if !nb.More {
			break
		}
	}
	if fmt.Sprint(got) != "[zlib@1.4.0 zlib@1.4.1]" {
		t.Errorf("paged: %v", got)
	}
	f.git.page = gitDefaultPage

	// A squashed history has no order to settle by: the head is diffed at
	// once, and exactly.
	files["modules/zlib/1.5.0/MODULE.bazel"] = "m"
	repo.commit(files, now, true)
	b, err = f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[zlib@1.5.0]" {
		t.Errorf("after the squash: %s", got)
	}
}

// The settle helper's choice of commit (feed_gitsettle.go), on histories the
// test repository cannot build.
func TestBazelSettlePicksTheNewestSettledCommit(t *testing.T) {
	t0 := time.Date(2026, 11, 15, 18, 0, 0, 0, time.UTC)
	tree := strings.Repeat("ab", 20)
	commit := func(objs *gitObjects, when int64, parents ...gitOID) gitOID {
		body := "tree " + tree + "\n"
		for _, p := range parents {
			body += "parent " + p.String() + "\n"
		}
		body += fmt.Sprintf("committer C <c@example.org> %d +0000\n\nchange\n", when)
		id := hashObject(gitCommit, []byte(body))
		objs.objs[id] = gitObject{typ: gitCommit, data: []byte(body)}
		return id
	}
	from, _ := parseOID(strings.Repeat("01", 20))
	objs := &gitObjects{objs: map[gitOID]gitObject{}}
	c1 := commit(objs, t0.Add(10*time.Minute).Unix(), from)
	c2 := commit(objs, t0.Add(20*time.Minute).Unix(), c1)
	c3 := commit(objs, t0.Add(40*time.Minute).Unix(), c2)
	cutoff := t0.Add(25 * time.Minute)
	if got, ht, ok := gitSettlePick(objs, c3, from, cutoff); got != c2 || !ok || !ht.Equal(t0.Add(40*time.Minute)) {
		t.Errorf("linear: %s %v %v, want %s", got, ok, ht, c2)
	}
	if _, _, ok := gitSettlePick(objs, c3, from, t0); ok {
		t.Errorf("nothing has settled at the stored commit's time")
	}
	// A commit that states no time counts as settled — once the commits
	// beneath it have.
	c4 := commit(objs, 0, c3)
	if got, _, ok := gitSettlePick(objs, c4, from, t0.Add(45*time.Minute)); got != c4 || !ok {
		t.Errorf("no time: %s %v", got, ok)
	}
	if _, _, ok := gitSettlePick(objs, c4, from, t0); ok {
		t.Errorf("a timeless commit atop unsettled ones counted as settled")
	}
	// Commit times need not grow along the chain (a merge queue stamps a
	// commit when it queues it): a commit stamped early atop an unsettled
	// one has not settled either.
	q := commit(objs, t0.Add(5*time.Minute).Unix(), c3)
	if got, _, ok := gitSettlePick(objs, q, from, cutoff); got != c2 || !ok {
		t.Errorf("out of order: %s %v, want %s", got, ok, c2)
	}
	// No order to settle by: the head.
	missing, _ := parseOID(strings.Repeat("02", 20))
	c5 := commit(objs, t0.Add(50*time.Minute).Unix(), missing)
	root := commit(objs, t0.Add(50*time.Minute).Unix())
	bad := hashObject(gitCommit, []byte("tree "+tree+"\nparent nothex\n\n"))
	objs.objs[bad] = gitObject{typ: gitCommit, data: []byte("tree " + tree + "\nparent nothex\n\n")}
	c6 := commit(objs, t0.Add(55*time.Minute).Unix(), bad)
	for name, head := range map[string]gitOID{"a commit the fetch lacks": c5, "a root": root, "a commit that does not read": c6} {
		if got, _, ok := gitSettlePick(objs, head, from, cutoff); got != head || !ok {
			t.Errorf("%s: %s %v, want the head", name, got, ok)
		}
	}
}

func TestBazelCursorResets(t *testing.T) {
	repo := newGitTestRepo()
	repo.commit(bazelTestFiles(), time.Now().Add(-time.Hour), false)
	git := newGitTestServer(t, repo)
	env := testEnv(t, "bazel", "https://bcr.bazel.build", newFakeReads(), map[string]string{"url": git.URL()})
	f := mustFeed(t, env).(*bazelFeed)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, cur := range map[string]string{
		"garbage":      "12345",
		"cargo's":      encodeCursor(&gitCursor{Format: cursorFormat("cargo-git", 1), Commit: repo.head.String()}),
		"unknown":      `{"format":"bazel-git/1","commit":"` + repo.head.String() + `","extra":1}`,
		"not stored":   f.git.cursor(gitCursor{Commit: strings.Repeat("ab", 20)}),
		"not a commit": f.git.cursor(gitCursor{Commit: "HEAD"}),
	} {
		_, err := f.Changes(ctx, cur)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, false, true, "")
	}
	// A listing cursor is not a follow cursor, and the other way round.
	if _, err := f.Changes(ctx, f.git.cursor(gitCursor{Commit: repo.head.String(), Listing: true})); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, b.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

// bazelServed serves recorded registry documents through the real bazel
// backend and returns the fake pipeline holding what it served:
// metadata.json as it is, source.json with its url rewritten to the proxy's
// archive endpoint and its mirror_urls dropped.
func bazelServed(t *testing.T, upstreamName string, docs map[string][]byte) *fakeReads {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	b, err := bazel.New(bazel.Options{Name: upstreamName, UpstreamURL: srv.URL, PublicBaseURL: "https://proxy.example/v1/" + upstreamName,
		Client: upstream.NewWithHTTPClient(srv.Client(), "test")})
	if err != nil {
		t.Fatal(err)
	}
	reads := newFakeReads()
	for p := range docs {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		fr, err := b.Fetch(context.Background(), res)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		body, err := io.ReadAll(fr.Content)
		fr.Content.Close()
		if err != nil {
			t.Fatal(err)
		}
		reads.set(p, body)
	}
	return reads
}

// bazelTestBackend is the backend the adapter's paths are checked against.
func bazelTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := bazel.New(bazel.Options{Name: env.Upstream, UpstreamURL: env.URL, PublicBaseURL: "https://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBazelReleasesListEachVersionsFiles(t *testing.T) {
	docs := map[string][]byte{}
	for _, m := range []struct{ name, versions string }{
		{"zlib", "1.2.11 1.2.12 1.2.13 1.3 1.3.1 1.3.1.bcr.5"},
		{"libnl", "3.7.0"},
		{"wireguard-tools", "1.0.20260223"},
	} {
		docs["/modules/"+m.name+"/metadata.json"] = fixture(t, "bazel", "metadata-"+m.name+".json")
		for _, v := range strings.Fields(m.versions) {
			docs["/modules/"+m.name+"/"+v+"/source.json"] = fixture(t, "bazel", "source-"+m.name+"-"+v+".json")
		}
	}
	env := testEnv(t, "bazel", "https://bcr.bazel.build", nil, nil)
	reads := bazelServed(t, env.Upstream, docs)
	if served := string(reads.docs["/modules/zlib/1.3.1/source.json"].body); !strings.Contains(served, "https://proxy.example/v1/bazel-test/modules/zlib/1.3.1/archive/zlib-1.3.1.tar.gz") {
		t.Fatalf("source.json was not rewritten: %s", served)
	}
	env.Read = reads.read
	f := mustFeed(t, env).(*bazelFeed)
	backend := bazelTestBackend(t, env)
	ctx := context.Background()
	for _, name := range []string{"zlib", "libnl", "wireguard-tools"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "bazel", "releases-"+name, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	// A version's source.json is read once: asking again reads the
	// metadata.json only.
	if _, err := f.Releases(ctx, "zlib"); err != nil {
		t.Fatal(err)
	}
	if n, m := reads.count("/modules/zlib/1.3.1/source.json"), reads.count("/modules/zlib/metadata.json"); n != 1 || m != 2 {
		t.Errorf("source.json read %d times, metadata.json %d", n, m)
	}
}

func TestBazelReleasesWhenSourceJSONCannotBeUsed(t *testing.T) {
	reads := newFakeReads()
	env := testEnv(t, "bazel", "https://bcr.bazel.build", reads, nil)
	f := mustFeed(t, env).(*bazelFeed)
	ctx := context.Background()
	reads.set("/modules/rules_license/metadata.json", []byte(`{"versions": ["0.0.7", "0.0.8", "1.0.0", "1.0.1", "2.0.0", "bad version", 7], "yanked_versions": {"0.0.7": "old", "9.9": "not listed"}}`))
	// 0.0.7: the source.json is refused by a gate; 0.0.8: it is missing;
	// 1.0.0: as recorded; 1.0.1: not a JSON object; 2.0.0: a Git source,
	// which names no archive the proxy serves.
	reads.setDoc("/modules/rules_license/0.0.7/source.json", fakeDoc{status: 403, gate: "policy", code: "denied"})
	reads.set("/modules/rules_license/1.0.0/source.json", fixture(t, "bazel", "source-rules_license-1.0.0.json"))
	reads.set("/modules/rules_license/1.0.1/source.json", []byte(`["not", "an", "object"]`))
	reads.set("/modules/rules_license/2.0.0/source.json", []byte(`{"type": "git_repository", "remote": "https://github.com/bazelbuild/rules_license", "commit": "abc", "patches": {"fix.patch": "sha256-x"}}`))
	rels, err := f.Releases(ctx, "rules_license")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "bazel", "releases-unusable-sources", viewReleases(rels))
	expectServed(t, bazelTestBackend(t, env), rels, func(r Release, _ Artifact) (string, string) { return "rules_license", r.Version })
	// A source.json the registry fails to serve for now fails the listing:
	// the engine tries again.
	reads.setDoc("/modules/rules_license/0.0.8/source.json", fakeDoc{status: 502})
	_, err = f.Releases(ctx, "rules_license")
	mustErr(t, err, false, false, "status 502")
	// So does a gate that cannot judge yet, with its wait.
	reads.setDoc("/modules/rules_license/0.0.8/source.json", fakeDoc{status: 403, gate: "llmscan", code: "pending", retry: 2 * time.Minute})
	_, err = f.Releases(ctx, "rules_license")
	if d, ok := RetryAfterOf(err); !ok || d != 2*time.Minute || IsPermanent(err) {
		t.Errorf("a gate that cannot judge yet: %v", err)
	}
}

func TestBazelMalformedAndRefusedMetadata(t *testing.T) {
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "bazel", "https://bcr.bazel.build", reads, nil)).(*bazelFeed)
	ctx := context.Background()
	for name, body := range map[string]string{
		"garbage":     "<html>not json</html>",
		"versions":    `{"versions": "1.0"}`,
		"no versions": `{"homepage": "https://example.org"}`,
		"array":       `["1.0"]`,
	} {
		reads.set("/modules/m"+strings.ReplaceAll(name, " ", "")+"/metadata.json", []byte(body))
		_, err := f.Releases(ctx, "m"+strings.ReplaceAll(name, " ", ""))
		mustErr(t, err, true, false, "metadata.json of")
	}
	// Versions none of which the layout can hold.
	reads.set("/modules/odd/metadata.json", []byte(`{"versions": ["1 0", "a/b", "../x"]}`))
	_, err := f.Releases(ctx, "odd")
	mustErr(t, err, true, false, "not a version")
	// More versions than are followed.
	many := make([]string, bazelMaxVersions+1)
	for i := range many {
		many[i] = fmt.Sprintf("1.%d", i)
	}
	body, _ := json.Marshal(map[string]any{"versions": many})
	reads.set("/modules/huge/metadata.json", body)
	_, err = f.Releases(ctx, "huge")
	mustErr(t, err, true, false, "at most")
	// An unknown module, a name that is none.
	_, err = f.Releases(ctx, "nope")
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(ctx, "../etc")
	mustErr(t, err, true, false, "not a Bazel module name")
	// A gate's verdict on the metadata is final; access control is not a
	// verdict on the module.
	reads.setDoc("/modules/typosquat/metadata.json", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typosquat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/modules/held/metadata.json", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	// A module that lists no version yet has nothing to mirror.
	reads.set("/modules/empty/metadata.json", []byte(`{"versions": []}`))
	if rels, err := f.Releases(ctx, "empty"); err != nil || len(rels) != 0 {
		t.Errorf("an empty module: %v %v", rels, err)
	}
}

func TestBazelReportedVersionsAreReadAgain(t *testing.T) {
	// BCR edits a published version's source.json in place (URLs, patches):
	// a change the feed reports for a version drops what is remembered of it.
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "bazel", "https://bcr.bazel.build", reads, nil)).(*bazelFeed)
	reads.set("/modules/rules_license/1.0.0/source.json", fixture(t, "bazel", "source-rules_license-1.0.0.json"))
	ctx := context.Background()
	if _, err := f.source(ctx, "rules_license", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.source(ctx, "rules_license", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	f.forget([]Coordinate{{Name: "rules_license", Version: "1.0.0"}, {Name: "other", Version: "1"}})
	if _, err := f.source(ctx, "rules_license", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if n := reads.count("/modules/rules_license/1.0.0/source.json"); n != 2 {
		t.Errorf("source.json read %d times, want 2 (once, and again after the change)", n)
	}
	if len(f.order) != len(f.sources) {
		t.Errorf("the memo's order (%d) and entries (%d) disagree", len(f.order), len(f.sources))
	}
}
