package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/homebrew"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestHomebrewFeedLocation(t *testing.T) {
	f, err := newHomebrewFeed(Env{Upstream: "brew", Type: "homebrew", URL: "https://formulae.brew.sh"})
	if err != nil {
		t.Fatal(err)
	}
	hf := f.(*homebrewFeed)
	if got := hf.git.remote.repo.String(); got != homebrewPublicRepo {
		t.Errorf("homebrew-core's repository %s", got)
	}
	if hf.settle != homebrewDefaultSettle || hf.platforms != nil {
		t.Errorf("defaults: settle %s platforms %v", hf.settle, hf.platforms)
	}
	// A Homebrew mirror is a static copy: its history cannot be followed —
	// refused at load time in git mode, saying what to set (mode auto follows
	// its formula index instead: TestHomebrewModeSelection).
	err = Check(Env{Upstream: "mirror", Type: "homebrew", URL: "https://brew-api.internal.example", Options: map[string]string{"mode": "git"}})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a mirror without a feed URL: %v", err)
	}
	if err := Check(Env{Upstream: "mirror", Type: "homebrew", URL: "https://brew-api.internal.example",
		Options: map[string]string{"url": "https://git.internal.example/homebrew-core.git", "platforms": "arm64_sequoia, x86_64_linux", "settle": "1h"}}); err != nil {
		t.Errorf("a mirror with a homebrew-core clone: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"branch": "-x"}, {"settle": "x"}, {"platforms": "macOS"},
		{"platforms": "arm64_sequoia,"}, {"platforms": "x86-64"}, {"url": "file:///srv/homebrew-core"}} {
		if err := Check(Env{Upstream: "b", Type: "homebrew", URL: "https://formulae.brew.sh", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestHomebrewAreaAndCoordinates(t *testing.T) {
	for dir, want := range map[string]bool{"": true, "Formula": true, "Formula/j": true, "Formula/lib": true,
		"Formula/j/x": false, "Formula/.hidden": false, "Aliases": false, "Casks": false, ".github": false, "cmd": false} {
		if got := homebrewArea(dir); got != want {
			t.Errorf("area %q: %v, want %v", dir, got, want)
		}
	}
	for _, tc := range []struct {
		path   string
		change gitChange
		want   string
	}{
		{"Formula/j/jq.rb", gitModified, "jq"},
		{"Formula/o/openssl@3.rb", gitAdded, "openssl@3"},
		{"Formula/lib/libxml++.rb", gitAdded, "libxml++"},
		{"Formula/w/wget.rb", gitDeleted, "wget deleted"},
		{"Formula/wget.rb", gitModified, "wget"},
		{"Formula/j/README.md", gitAdded, ""},
		{"Formula/j/Bad Name.rb", gitAdded, ""},
		{"Formula/j/.rb", gitAdded, ""},
		{"Formula/j/x/y.rb", gitAdded, ""},
		{"Aliases/jq.rb", gitAdded, ""},
		{"Abstract/portable-formula.rb", gitAdded, ""},
		{"formula_renames.json", gitModified, ""},
	} {
		c, ok := homebrewCoordinate(tc.path, tc.change)
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

// homebrewTestFiles is a repository laid out as homebrew-core.
func homebrewTestFiles() map[string]string {
	return map[string]string{
		"README.md":                    "# Homebrew Core\n",
		".github/workflows/tests.yml":  "on: pull_request\n",
		"Abstract/portable-formula.rb": "class PortableFormula < Formula; end\n",
		"Aliases/jq-1":                 "../Formula/j/jq.rb",
		"formula_renames.json":         "{}\n",
		"tap_migrations.json":          "{}\n",
		"Formula/c/ca-certificates.rb": "class CaCertificates < Formula; end\n",
		"Formula/j/jq.rb":              "class Jq < Formula; end\n",
		"Formula/legacy-flat.rb":       "class LegacyFlat < Formula; end\n",
		"Formula/lib/libxml++.rb":      "class Libxmlxx < Formula; end\n",
		"Formula/o/openssl@3.rb":       "class OpensslAT3 < Formula; end\n",
		"Formula/x/Bad Name.rb":        "not a formula name\n",
	}
}

func TestHomebrewFollowsHomebrewCore(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 16, 2, 0, 0, 0, time.UTC)
	files := homebrewTestFiles()
	repo.commit(files, t0, false)
	git := newGitTestServer(t, repo)
	env := testEnv(t, "homebrew", "https://formulae.brew.sh", newFakeReads(), map[string]string{"url": git.URL(), "settle": "0"})
	f := mustFeed(t, env).(*homebrewFeed)
	f.git.page = 3
	ctx := context.Background()
	b1, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f.Bootstrap(ctx, b1.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b1.Items), b1.More, names(b2.Items), b2.More); got != "[ca-certificates jq legacy-flat] true [libxml++ openssl@3] false" {
		t.Fatalf("bootstrap %s", got)
	}
	var c gitCursor
	if err := decodeCursor(b2.Next, f.git.format(), &c); err != nil || c.Commit != repo.head.String() || c.Listing {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	// jq is bottled anew, openssl@3 removed, wget added, the flat formula
	// moves into its shard; aliases and the README change.
	files["Formula/j/jq.rb"] = "class Jq < Formula; bottle do; end; end\n"
	delete(files, "Formula/o/openssl@3.rb")
	files["Formula/w/wget.rb"] = "class Wget < Formula; end\n"
	files["Formula/l/legacy-flat.rb"] = files["Formula/legacy-flat.rb"]
	delete(files, "Formula/legacy-flat.rb")
	files["Aliases/jq-1"] = "../Formula/j/jq.rb\n"
	files["README.md"] = "# Homebrew/homebrew-core\n"
	repo.commit(files, t0.Add(time.Minute), false)
	f.git.page = gitDefaultPage
	ch, err := f.Changes(ctx, b2.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "homebrew", "changes", viewBatch(t, ch))

	// The default settle period holds a commit back for half an hour.
	f.settle = homebrewDefaultSettle
	files["Formula/j/jq.rb"] = "class Jq < Formula; revision 1; end\n"
	repo.commit(files, t0.Add(10*time.Minute), false)
	f.now = func() time.Time { return t0.Add(20 * time.Minute) }
	if held, err := f.Changes(ctx, ch.Next); err != nil || len(held.Items) != 0 || held.Next != ch.Next {
		t.Errorf("a commit ten minutes old was reported: %+v %v", held, err)
	}
	f.now = func() time.Time { return t0.Add(41 * time.Minute) }
	if settled, err := f.Changes(ctx, ch.Next); err != nil || fmt.Sprint(names(settled.Items)) != "[jq]" {
		t.Errorf("the settled commit: %+v %v", settled, err)
	}
}

// homebrewServed serves recorded formula documents through the real
// homebrew backend — what the gated pipeline hands the adapter, bottle URLs
// rewritten to the backend's synthetic endpoint — into a fake pipeline.
func homebrewServed(t *testing.T, upstreamName string, docs map[string][]byte) *fakeReads {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	b, err := homebrew.New(homebrew.Options{Name: upstreamName, UpstreamURL: srv.URL, PublicBaseURL: "https://proxy.example/v1/" + upstreamName,
		Client: upstream.NewWithHTTPClient(srv.Client(), "test"), Offline: true})
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

// homebrewTestBackend is the backend the adapter's paths are checked against.
func homebrewTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := homebrew.New(homebrew.Options{Name: env.Upstream, UpstreamURL: env.URL, PublicBaseURL: "https://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHomebrewReleasesComeFromTheRewrittenFormula(t *testing.T) {
	docs := map[string][]byte{}
	for _, name := range []string{"jq", "ca-certificates", "openssl@3"} {
		docs["/api/formula/"+name+".json"] = fixture(t, "homebrew", "formula-"+name+".json")
	}
	// A deprecated formula is mirrored; a disabled one is not. A bottle on
	// another host than the bottle registry is left by the backend at its
	// origin, which the proxy does not serve.
	variant := func(name string, edits ...string) {
		doc := strings.Replace(string(fixture(t, "homebrew", "formula-jq.json")), `{"name":"jq",`, `{"name":"`+name+`",`, 1)
		for i := 0; i < len(edits); i += 2 {
			if !strings.Contains(doc, edits[i]) {
				t.Fatalf("%s: the fixture has no %s", name, edits[i])
			}
			doc = strings.ReplaceAll(doc, edits[i], edits[i+1])
		}
		docs["/api/formula/"+name+".json"] = []byte(doc)
	}
	variant("jq-deprecated", `"deprecated":false`, `"deprecated":true`)
	variant("jq-disabled", `"disabled":false`, `"disabled":true`)
	variant("jq-elsewhere", `"https://ghcr.io/v2/`, `"https://bottles.example.org/v2/`)
	env := testEnv(t, "homebrew", "https://formulae.brew.sh", nil, nil)
	reads := homebrewServed(t, env.Upstream, docs)
	if served := reads.docs["/api/formula/jq.json"].body; !bytes.Contains(served, []byte(`"https://proxy.example/v1/homebrew-test/bottle/jq/1.8.2/v2/homebrew/core/jq/blobs/sha256:`)) {
		t.Fatalf("the formula was not rewritten: %.300s", served)
	}
	env.Read = reads.read
	f := mustFeed(t, env).(*homebrewFeed)
	backend := homebrewTestBackend(t, env)
	ctx := context.Background()
	for _, name := range []string{"jq", "ca-certificates", "openssl@3"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "homebrew", "releases-"+name, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
		// The synthetic path and the registry-native one brew requests
		// (HOMEBREW_ARTIFACT_DOMAIN) are one cache entry: what the mirror
		// fetches is what brew is served.
		for _, a := range rels[0].Artifacts {
			native := a.Path[strings.Index(a.Path, "/v2/"):]
			keys := map[string]bool{}
			for _, p := range []string{a.Path, native} {
				res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
				if err != nil || !res.Cacheable {
					t.Fatalf("%s: %v", p, err)
				}
				keys[res.CacheKey] = true
			}
			if len(keys) != 1 {
				t.Errorf("%s and %s are cached apart: %v", a.Path, native, keys)
			}
		}
	}
	if rels, err := f.Releases(ctx, "jq-deprecated"); err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 7 {
		t.Errorf("deprecated: %v %v", rels, err)
	}
	for _, name := range []string{"jq-disabled", "jq-elsewhere"} {
		if rels, err := f.Releases(ctx, name); err != nil || len(rels) != 0 {
			t.Errorf("%s: %v %v", name, rels, err)
		}
	}

	// The platforms option keeps those bottles, and an "all" bottle.
	f.platforms, _ = homebrewParsePlatforms("arm64_sequoia,x86_64_linux")
	got := map[string]int{}
	for _, name := range []string{"jq", "ca-certificates", "openssl@3"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rels {
			got[name] += len(r.Artifacts)
		}
	}
	if fmt.Sprint(got) != "map[ca-certificates:1 jq:2 openssl@3:2]" {
		t.Errorf("platforms: %v", got)
	}
}

func TestHomebrewMalformedAndRefused(t *testing.T) {
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "homebrew", "https://formulae.brew.sh", reads, nil)).(*homebrewFeed)
	ctx := context.Background()
	for name, tc := range map[string]struct{ body, want string }{
		"garbage":   {"<html>rate limited</html>", "formula document of garbage"},
		"index":     {`[{"name":"index"}]`, "formula document of index"},
		"shape":     {`{"name":"shape","versions":{"stable":"1.0"},"bottle":{"stable":{"files":[]}}}`, "formula document of shape"},
		"noversion": {`{"name":"noversion","versions":{"stable":null},"bottle":{}}`, "no stable version"},
		"notone":    {`{"desc":"not a formula"}`, "not a formula"},
	} {
		reads.set("/api/formula/"+name+".json", []byte(tc.body))
		_, err := f.Releases(ctx, name)
		mustErr(t, err, true, false, tc.want)
	}
	// Bottle URLs the backend did not rewrite, or rewrote for another
	// formula or version, are not this formula's.
	reads.set("/api/formula/odd.json", []byte(`{"name":"odd","versions":{"stable":"1.0"},"bottle":{"stable":{"files":{
		"arm64_sequoia":{"url":"https://ghcr.io/v2/homebrew/core/odd/blobs/sha256:`+strings.Repeat("a", 64)+`"},
		"sonoma":{"url":"/v1/homebrew-test/bottle/other/1.0/v2/homebrew/core/other/blobs/sha256:`+strings.Repeat("b", 64)+`"},
		"x86_64_linux":{"url":"/v1/homebrew-test/bottle/odd/0.9/v2/homebrew/core/odd/blobs/sha256:`+strings.Repeat("c", 64)+`"},
		"arm64_linux":{"url":"/v1/homebrew-test/api/formula.json"},
		"Bad Tag":{"url":"/v1/homebrew-test/bottle/odd/1.0/v2/homebrew/core/odd/blobs/sha256:`+strings.Repeat("d", 64)+`"},
		"all":{"url":"/v1/homebrew-test/bottle/odd/1.0/v2/homebrew/core/odd/blobs/sha256:`+strings.Repeat("e", 64)+`"}}}}}`))
	rels, err := f.Releases(ctx, "odd")
	if err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 1 || !strings.HasSuffix(rels[0].Artifacts[0].Path, strings.Repeat("e", 64)) {
		t.Errorf("odd: %+v %v", rels, err)
	}
	_, err = f.Releases(ctx, "nope")
	mustErr(t, err, true, false, "not found")
	for _, bad := range []string{"../etc", "Jq", "a b", "x.jws", ""} {
		_, err = f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a formula name")
	}
	reads.setDoc("/api/formula/typosquat.json", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typosquat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/api/formula/held.json", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	reads.setDoc("/api/formula/later.json", fakeDoc{status: 503, retry: 90 * time.Second})
	_, err = f.Releases(ctx, "later")
	if d, ok := RetryAfterOf(err); !ok || d != 90*time.Second {
		t.Errorf("a 503: %v", err)
	}
}

func TestHomebrewCursorResets(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Now().Add(-3 * time.Hour)
	repo.commit(homebrewTestFiles(), t0, false)
	git := newGitTestServer(t, repo)
	f := mustFeed(t, testEnv(t, "homebrew", "https://formulae.brew.sh", newFakeReads(), map[string]string{"url": git.URL()})).(*homebrewFeed)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, cur := range []string{
		"null",
		encodeCursor(&gitCursor{Format: cursorFormat("conan-git", 1), Commit: repo.head.String()}),
		f.git.cursor(gitCursor{Commit: strings.Repeat("0f", 20)}),
		f.git.cursor(gitCursor{Commit: repo.head.String(), Listing: true}),
		`{"format":"homebrew-git/1","commit":"` + repo.head.String() + `","since":1}`,
	} {
		_, err := f.Changes(ctx, cur)
		if err == nil {
			t.Errorf("%s: accepted", cur)
			continue
		}
		mustErr(t, err, false, true, "")
	}
	if _, err := f.Bootstrap(ctx, b.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
	// A formula added, then the branch force-pushed back without it: the
	// difference is exact, the formula is reported removed.
	files := homebrewTestFiles()
	files["Formula/w/wget.rb"] = "class Wget < Formula; end\n"
	repo.commit(files, t0.Add(time.Hour), false)
	b2, err := f.Changes(ctx, b.Next)
	if err != nil || fmt.Sprint(names(b2.Items)) != "[wget]" {
		t.Fatalf("changes %+v %v", b2, err)
	}
	repo.commit(homebrewTestFiles(), t0.Add(2*time.Hour), true)
	b3, err := f.Changes(ctx, b2.Next)
	if err != nil || len(b3.Items) != 1 || b3.Items[0] != (Coordinate{Name: "wget", Deleted: true}) {
		t.Errorf("after the force-push %+v %v", b3, err)
	}
}

// The index-mode fixture, formula-index.json, is formulae.brew.sh's
// /api/formula.json of 2026-11-16 trimmed to six of its 8,731 formulae — a
// disabled one, one without bottles, libxml++, and the three whose documents
// are recorded too — each line as served.

func TestHomebrewModeSelection(t *testing.T) {
	build := func(up string, opts map[string]string) *homebrewFeed {
		t.Helper()
		f, err := newHomebrewFeed(Env{Upstream: "brew", Type: "homebrew", URL: up, Options: opts})
		if err != nil {
			t.Fatalf("%s %v: %v", up, opts, err)
		}
		return f.(*homebrewFeed)
	}
	indexURL := func(f *homebrewFeed) string {
		if f.index == nil || f.git != nil {
			return "git"
		}
		return f.index.src.(*homebrewIndexSource).url
	}
	for _, tc := range []struct {
		up   string
		opts map[string]string
		want string
	}{
		{"https://formulae.brew.sh", nil, "git"},
		{"https://formulae.brew.sh", map[string]string{"mode": "AUTO"}, "git"},
		{"https://mirrors.ustc.edu.cn/homebrew-bottles", nil, "https://mirrors.ustc.edu.cn/homebrew-bottles/api/formula.json"},
		{"https://mirrors.ustc.edu.cn/homebrew-bottles", map[string]string{"url": "https://git.internal.example/homebrew-core.git"}, "git"},
		{"https://formulae.brew.sh", map[string]string{"mode": "index"}, "https://formulae.brew.sh/api/formula.json"},
		{"https://formulae.brew.sh", map[string]string{"mode": "index", "url": "https://brew-api.internal.example/api/formula.json", "platforms": "arm64_sequoia"}, "https://brew-api.internal.example/api/formula.json"},
		{"https://brew-api.internal.example", map[string]string{"mode": "git", "url": "https://git.internal.example/homebrew-core.git"}, "git"},
	} {
		if got := indexURL(build(tc.up, tc.opts)); got != tc.want {
			t.Errorf("%s %v: %s, want %s", tc.up, tc.opts, got, tc.want)
		}
	}
	if f := build("https://formulae.brew.sh", map[string]string{"mode": "index", "platforms": "arm64_sequoia, x86_64_linux"}); fmt.Sprint(f.platforms) != "map[arm64_sequoia:true x86_64_linux:true]" ||
		fmt.Sprint(f.index.src.(*homebrewIndexSource).platforms) != fmt.Sprint(f.platforms) {
		t.Errorf("platforms in index mode: %v", f.platforms)
	}
	for _, opts := range []map[string]string{{"mode": "svn"}, {"mode": "index", "settle": "1h"}, {"mode": "index", "branch": "main"},
		{"mode": "index", "url": "https://brew-api.internal.example/api"}, {"mode": "index", "url": "https://x.example/formula.json?x=1"},
		{"mode": "index", "url": "https://brew-api.internal.example/api/formula.jws.json"},
		{"mode": "index", "platforms": "macOS"}, {"settle": "1h"}} {
		if err := Check(Env{Upstream: "b", Type: "homebrew", URL: "https://brew-api.internal.example", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

// homebrewIndexLines returns the recorded index's formula lines.
func homebrewIndexLines(t *testing.T) []string {
	t.Helper()
	doc := strings.TrimSuffix(string(fixture(t, "homebrew", "formula-index.json")), "\n]\n")
	lines := strings.Split(strings.TrimPrefix(doc, "[\n"), ",\n")
	if len(lines) != 6 {
		t.Fatalf("%d formulae in the fixture", len(lines))
	}
	return lines
}

// homebrewIndexDoc lays formula lines out as the index is served.
func homebrewIndexDoc(lines []string) []byte {
	return []byte("[\n" + strings.Join(lines, ",\n") + "\n]\n")
}

// homebrewIndexEdit returns lines with the formula's line edited (old, new
// pairs) — or dropped when no edit is given.
func homebrewIndexEdit(t *testing.T, lines []string, name string, edits ...string) []string {
	t.Helper()
	var out []string
	found := false
	for _, l := range lines {
		if !strings.HasPrefix(l, `  {"name":"`+name+`",`) {
			out = append(out, l)
			continue
		}
		found = true
		if len(edits) == 0 {
			continue
		}
		for i := 0; i < len(edits); i += 2 {
			if !strings.Contains(l, edits[i]) {
				t.Fatalf("%s: no %s in its line", name, edits[i])
			}
			l = strings.ReplaceAll(l, edits[i], edits[i+1])
		}
		out = append(out, l)
	}
	if !found {
		t.Fatalf("no formula %s", name)
	}
	return out
}

// homebrewBottleSHA returns a formula's bottle digest for a tag, from the
// recorded index.
func homebrewBottleSHA(t *testing.T, lines []string, name, tag string) string {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l, `  {"name":"`+name+`",`) {
			var f homebrewIndexFormula
			if err := json.Unmarshal([]byte(l), &f); err != nil {
				t.Fatal(err)
			}
			if f.Bottle.Stable != nil {
				if _, sha, ok := strings.Cut(f.Bottle.Stable.Files[tag].URL, "/blobs/sha256:"); ok && sha != "" {
					return sha
				}
			}
		}
	}
	t.Fatalf("%s has no %s bottle", name, tag)
	return ""
}

// homebrewServeIndex has the fixture server serve an index with an ETag and a
// Last-Modified; a request carrying the ETag is answered 304.
func homebrewServeIndex(srv *fixtureServer, doc []byte, etag string) {
	srv.on("GET", "/api/formula.json").reply(http.StatusOK, doc).withHeader("ETag", `"`+etag+`"`).withHeader("Last-Modified", "Mon, 16 Nov 2026 05:35:12 GMT").withHeader("Content-Type", "application/json; charset=utf-8")
	srv.on("GET", "/api/formula.json").requireHeader("If-None-Match", `"`+etag+`"`).reply(http.StatusNotModified, nil)
}

func TestHomebrewIndexFollowsTheFormulaIndex(t *testing.T) {
	lines := homebrewIndexLines(t)
	srv := newFixtureServer(t)
	homebrewServeIndex(srv, homebrewIndexDoc(lines), "i1")
	reads := newFakeReads()
	env := testEnv(t, "homebrew", srv.URL(), reads, nil)
	f := mustFeed(t, env).(*homebrewFeed)
	if f.index == nil {
		t.Fatalf("a mirror of the JSON API is followed in git mode")
	}
	ctx := context.Background()
	// The disabled formula and the one without bottles are not followed.
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "homebrew", "index-bootstrap", viewBatch(t, b))
	// Paged, the same names, the same final cursor.
	f.index.page = 3
	b1, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f.Bootstrap(ctx, b1.Next)
	if err != nil || !b1.More || b2.More || len(b1.Items)+len(b2.Items) != 4 || b2.Next != b.Next {
		t.Fatalf("paged bootstrap: %+v %+v %v", b1, b2, err)
	}
	f.index.page = indexPage

	// Releases answers from the copy: the current version, its bottles at
	// the paths the backend rewrites them to — without reading a document.
	backend := homebrewTestBackend(t, env)
	for _, name := range []string{"jq", "openssl@3", "ca-certificates", "libxml++"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "jq" {
			checkGolden(t, "homebrew", "index-releases-jq", viewReleases(rels))
		}
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	for _, name := range []string{"aescrypt-packetizer", "portable-zlib", "wget"} {
		_, err := f.Releases(ctx, name)
		mustErr(t, err, true, false, "not in the homebrew index")
	}
	if len(reads.reads) != 0 {
		t.Errorf("index mode read documents: %v", reads.reads)
	}

	// Unchanged: a 304, nothing reported, the cursor stays.
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 || ch.Next != b.Next {
		t.Fatalf("unchanged: %+v %v", ch, err)
	}

	// jq is updated (a new version, a bottle rebuilt), openssl@3's rebuild
	// number moves without a bottle changing (nothing to mirror),
	// aescrypt-packetizer is enabled again, libxml++3 is new, portable-zlib
	// (never followed: no bottles) is gone; ca-certificates' description
	// changes, which leaves nothing to mirror.
	sha := homebrewBottleSHA(t, lines, "jq", "x86_64_linux")
	edited := homebrewIndexEdit(t, lines, "jq", `"versions":{"stable":"1.8.2"`, `"versions":{"stable":"1.8.3"`, sha, strings.Repeat("0", 64))
	edited = homebrewIndexEdit(t, edited, "openssl@3", `"bottle":{"stable":{"rebuild":0`, `"bottle":{"stable":{"rebuild":1`)
	edited = homebrewIndexEdit(t, edited, "aescrypt-packetizer", `"disabled":true`, `"disabled":false`)
	edited = homebrewIndexEdit(t, edited, "ca-certificates", `"desc":"`, `"desc":"Mozilla's `)
	edited = homebrewIndexEdit(t, edited, "portable-zlib")
	for _, l := range lines {
		if strings.HasPrefix(l, `  {"name":"libxml++",`) {
			edited = append(edited, strings.Replace(l, `{"name":"libxml++","full_name":"libxml++"`, `{"name":"libxml++3","full_name":"libxml++3"`, 1))
		}
	}
	homebrewServeIndex(srv, homebrewIndexDoc(edited), "i2")
	ch, err = f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "homebrew", "index-changes", viewBatch(t, ch))
	// Every version a change names is one Releases lists.
	for _, c := range ch.Items {
		if c.Deleted {
			continue
		}
		rels, err := f.Releases(ctx, c.Name)
		if err != nil || len(rels) == 0 || (c.Version != "" && !hasVersion(rels, c.Version)) {
			t.Errorf("%s: %+v %v", c, rels, err)
		}
	}
}

// The index names a version the formula's own document does not have yet —
// the CDN caches the two apart, a mirror rebuilds them apart: the change and
// Releases both name the index's version (a Releases answering from the
// stale document would have the change consumed and the version never
// mirrored), and nothing is reported again once the copy is reached.
func TestHomebrewIndexReleasesFollowTheIndex(t *testing.T) {
	lines := homebrewIndexLines(t)
	srv := newFixtureServer(t)
	homebrewServeIndex(srv, homebrewIndexDoc(lines), "i1")
	env := testEnv(t, "homebrew", srv.URL(), nil, nil)
	reads := homebrewServed(t, env.Upstream, map[string][]byte{"/api/formula/jq.json": fixture(t, "homebrew", "formula-jq.json")})
	env.Read = reads.read // the document stays 1.8.2's
	f := mustFeed(t, env).(*homebrewFeed)
	ctx := context.Background()
	_, cursor := drainBootstrap(t, f)

	sha := homebrewBottleSHA(t, lines, "jq", "x86_64_linux")
	edited := homebrewIndexEdit(t, lines, "jq", `"versions":{"stable":"1.8.2"`, `"versions":{"stable":"1.8.3"`, sha, strings.Repeat("0", 64))
	homebrewServeIndex(srv, homebrewIndexDoc(edited), "i2")
	got, next := drainChanges(t, f, cursor)
	if fmt.Sprint(got) != "[jq@1.8.3 jq@1.8.2 (deleted)]" {
		t.Fatalf("changes %v", got)
	}
	rels, err := f.Releases(ctx, "jq")
	if err != nil || len(rels) != 1 || rels[0].Version != "1.8.3" || len(rels[0].Artifacts) != 7 {
		t.Fatalf("Releases: %+v %v", rels, err)
	}
	expectServed(t, homebrewTestBackend(t, env), rels, func(r Release, _ Artifact) (string, string) { return "jq", "1.8.3" })
	if n := reads.count("/api/formula/jq.json"); n != 0 {
		t.Errorf("the formula's document was read %d times", n)
	}
	if again, _ := drainChanges(t, f, next); len(again) != 0 {
		t.Errorf("reported again: %v", again)
	}
}

// With the option platforms, a bottle of another platform changing leaves
// nothing to mirror.
func TestHomebrewIndexPlatforms(t *testing.T) {
	lines := homebrewIndexLines(t)
	srv := newFixtureServer(t)
	homebrewServeIndex(srv, homebrewIndexDoc(lines), "p1")
	f := mustFeed(t, testEnv(t, "homebrew", srv.URL(), newFakeReads(), map[string]string{"platforms": "arm64_sequoia"}))
	_, cursor := drainBootstrap(t, f)
	if rels, err := f.Releases(context.Background(), "jq"); err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 1 {
		t.Errorf("jq on arm64_sequoia: %+v %v", rels, err)
	}
	for i, tc := range []struct {
		name, tag string
		want      string
	}{
		{"jq", "x86_64_linux", "[]"},
		{"jq", "arm64_sequoia", "[jq@1.8.2]"},
		{"ca-certificates", "all", "[ca-certificates@2026-11-05]"},
	} {
		sha := homebrewBottleSHA(t, lines, tc.name, tc.tag)
		lines = homebrewIndexEdit(t, lines, tc.name, sha, strings.Repeat("f", 64))
		homebrewServeIndex(srv, homebrewIndexDoc(lines), fmt.Sprintf("p%d", i+2))
		got, next := drainChanges(t, f, cursor)
		if fmt.Sprint(got) != tc.want {
			t.Errorf("%s's %s bottle changed: %v, want %s", tc.name, tc.tag, got, tc.want)
		}
		cursor = next
	}
}

func TestHomebrewIndexMalformed(t *testing.T) {
	var entries []homebrewIndexEntry
	parse := func(doc string) ([]string, string, error) {
		var got []string
		entries = nil
		head, err := homebrewParseIndex(strings.NewReader(doc), func(e homebrewIndexEntry) error {
			var tags []string
			for _, b := range e.bottles {
				tags = append(tags, b.tag)
			}
			got = append(got, fmt.Sprintf("%s %q %v %v", e.name, e.version, e.disabled, tags))
			entries = append(entries, e)
			return nil
		})
		return got, head, err
	}
	blob := func(name, c string) string {
		return `{"url":"https://ghcr.io/v2/homebrew/core/` + name + `/blobs/sha256:` + strings.Repeat(c, 64) + `"}`
	}
	many := map[string]any{}
	for i := 0; i <= homebrewMaxBottles; i++ {
		many[fmt.Sprintf("tag_%d", i)] = map[string]string{"url": "https://ghcr.io/v2/homebrew/core/many/blobs/sha256:" + strings.Repeat("a", 64)}
	}
	manyJSON, _ := json.Marshal(map[string]any{"name": "many", "versions": map[string]string{"stable": "1"}, "bottle": map[string]any{"stable": map[string]any{"files": many}}})
	got, head, err := parse(`[{"name":"shape","versions":"1.0"},{"name":"rev","versions":{"stable":"1.0"},"revision":"x"},` +
		`{"name":"good","versions":{"stable":" 2.0 "},"revision":1,"tap_git_head":"` + strings.Repeat("ab", 20) + `","bottle":{"stable":{"rebuild":2,"files":{` +
		`"sonoma":` + blob("good", "b") + `,"arm64_sequoia":` + blob("good", "a") + `,"Bad Tag":` + blob("good", "c") + `,"x86_64_linux":{"url":""},` +
		`"arm64_linux":{"url":"https://bottles.example.org/v2/homebrew/core/good/blobs/sha256:` + strings.Repeat("d", 64) + `"},` +
		`"arm64_tahoe":{"url":"https://ghcr.io/v2/homebrew/core/good/manifests/2.0"}}}}},` +
		`{"name":"Bad Name"},{"name":"x.jws"},{"name":""},7,null,"str",[],` +
		`{"name":"nover","versions":{"stable":"1/2"},"bottle":{"stable":{"files":{"all":` + blob("nover", "e") + `}}},"tap_git_head":"not a commit"},` +
		`{"name":"off","versions":{"stable":"3.0"},"disabled":true,"bottle":{"stable":{"files":{"all":` + blob("off", "f") + `}}}},` + string(manyJSON) + `]`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[rev "1.0" false [] good "2.0" false [arm64_linux arm64_sequoia arm64_tahoe sonoma] nover "" false [all] off "3.0" true [all]]`; fmt.Sprint(got) != want {
		t.Errorf("entries %v, want %s", got, want)
	}
	if head != strings.Repeat("ab", 20) {
		t.Errorf("head %q", head)
	}
	// Records: the bottles the backend rewrites (on the bottle registry, an
	// OCI blob), of the platforms kept; none for a formula without a stable
	// version or a disabled one.
	var recs []string
	for _, e := range entries {
		for _, r := range homebrewIndexRecords(e, nil, "") {
			recs = append(recs, r.Name+"@"+r.Version+" "+r.Path[:strings.Index(r.Path, "/v2/")])
		}
	}
	if want := "[good@2.0 /bottle/good/2.0 good@2.0 /bottle/good/2.0]"; fmt.Sprint(recs) != want {
		t.Errorf("records %v, want %s", recs, want)
	}
	kept, _ := homebrewParsePlatforms("arm64_sequoia")
	if r := homebrewIndexRecords(entries[1], kept, ""); len(r) != 1 || !strings.HasSuffix(r[0].Path, strings.Repeat("a", 64)) {
		t.Errorf("platforms: %+v", r)
	}
	// The bottle registry is the upstream's bottleRegistryUrl.
	if r := homebrewIndexRecords(entries[1], nil, "https://bottles.example.org"); len(r) != 1 || !strings.HasSuffix(r[0].Path, strings.Repeat("d", 64)) {
		t.Errorf("another bottle registry: %+v", r)
	}
	for name, doc := range map[string]string{
		"garbage":   "<html>rate limited</html>",
		"object":    `{"name":"jq"}`,
		"empty":     "",
		"truncated": `[{"name":"jq","versions":{"stable":"1.0"}`,
		"unclosed":  `[{"name":"jq"}`,
		"big":       `[{"name":"big","desc":"` + strings.Repeat("x", homebrewMaxIndexEntry+1) + `"}]`,
	} {
		_, _, err := parse(doc)
		mustErr(t, err, true, false, "")
		if t.Failed() {
			t.Fatalf("%s", name)
		}
	}
	_, err = homebrewParseIndex(io.MultiReader(strings.NewReader(`[{"name":"jq"},`), homebrewFailingReader{}), func(homebrewIndexEntry) error { return nil })
	if err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "connection reset") {
		t.Errorf("a failing stream: %v", err)
	}

	// Through the feed: a missing index, and a gzip-encoded one.
	srv := newFixtureServer(t)
	srv.on("GET", "/api/formula.json").reply(http.StatusNotFound, nil)
	_, err = mustFeed(t, testEnv(t, "homebrew", srv.URL(), newFakeReads(), nil)).Bootstrap(context.Background(), "")
	mustErr(t, err, true, false, "not found")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(fixture(t, "homebrew", "formula-index.json"))
	_ = zw.Close()
	srv.on("GET", "/api/formula.json").requireHeader("Accept-Encoding", "gzip").reply(http.StatusOK, gz.Bytes()).withHeader("Content-Encoding", "gzip")
	if b, err := mustFeed(t, testEnv(t, "homebrew", srv.URL(), newFakeReads(), nil)).Bootstrap(context.Background(), ""); err != nil || len(b.Items) != 4 {
		t.Errorf("a gzip-encoded index: %+v %v", b, err)
	}
	// A cursor's validators that cannot go back into a header: read in full.
	srv = newFixtureServer(t)
	homebrewServeIndex(srv, fixture(t, "homebrew", "formula-index.json"), "v1")
	f := mustFeed(t, testEnv(t, "homebrew", srv.URL(), newFakeReads(), nil))
	b, err := f.Bootstrap(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var c indexCursor
	_ = json.Unmarshal([]byte(b.Next), &c)
	c.State = json.RawMessage(`{"etag":"\"v1\"\n"}`)
	if ch, err := f.Changes(context.Background(), encodeCursor(&c)); err != nil || len(ch.Items) != 0 {
		t.Errorf("a damaged state: %+v %v", ch, err)
	}
	if log := srv.requests(); len(log) != 2 {
		t.Errorf("requests %v", log)
	}
	// A cursor of git mode is not this mode's (and the other way round): the
	// engine enumerates the registry again.
	_, err = f.Changes(context.Background(), `{"format":"homebrew-git/1","commit":"`+strings.Repeat("0f", 20)+`"}`)
	mustErr(t, err, false, true, "")
	git := mustFeed(t, testEnv(t, "homebrew", "https://formulae.brew.sh", newFakeReads(), map[string]string{"url": srv.URL() + "/homebrew-core.git"}))
	_, err = git.Changes(context.Background(), b.Next)
	mustErr(t, err, false, true, "")
}

// homebrewFailingReader fails as a dropped connection does.
type homebrewFailingReader struct{}

func (homebrewFailingReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("read: connection reset by peer")
}

// homebrewIndexStream generates an index of n formulae as it is read, each
// the size of a real one (about 4 KB).
type homebrewIndexStream struct {
	n, i int
	buf  []byte
}

func (s *homebrewIndexStream) Read(p []byte) (int, error) {
	if len(s.buf) == 0 {
		switch {
		case s.i > s.n:
			return 0, io.EOF
		case s.i == s.n:
			s.buf = []byte("\n]\n")
		default:
			sep := ",\n"
			if s.i == 0 {
				sep = "[\n"
			}
			d := fmt.Sprintf("%064x", s.i)
			s.buf = fmt.Appendf(s.buf[:0], `%s  {"name":"formula-%d","full_name":"formula-%d","desc":"%s","versions":{"stable":"1.%d.0","head":null,"bottle":true},"revision":0,`+
				`"bottle":{"stable":{"rebuild":0,"root_url":"https://ghcr.io/v2/homebrew/core","files":{"arm64_sequoia":{"cellar":":any","url":"https://ghcr.io/v2/homebrew/core/formula-%d/blobs/sha256:%s","sha256":"%s"},`+
				`"x86_64_linux":{"cellar":":any","url":"https://ghcr.io/v2/homebrew/core/formula-%d/blobs/sha256:%s","sha256":"%s"}}}},"disabled":false,"tap_git_head":"%040x"}`,
				sep, s.i, s.i, strings.Repeat("d", 3500), s.i, s.i, d, d, s.i, d, d, 1)
		}
		s.i++
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// The index is read as a stream: memory stays flat however long it is.
func TestHomebrewIndexStreamsInBoundedMemory(t *testing.T) {
	n := 16_000 // 64 MB, twice formulae.brew.sh's index
	if raceEnabled {
		n = 2_000
	}
	k, err := newKit(Env{Upstream: "brew", Type: "homebrew", URL: "https://brew-api.internal.example"})
	if err != nil {
		t.Fatal(err)
	}
	b := files{dir: t.TempDir()}.newSnapBuilder("homebrew")
	defer b.Abort()
	src := &homebrewIndexSource{k: k}
	peak := sampleHeap(t, func() {
		_, err = homebrewParseIndex(&homebrewIndexStream{n: n}, func(e homebrewIndexEntry) error {
			for _, r := range homebrewIndexRecords(e, src.platforms, src.registry) {
				b.Add(r)
			}
			return nil
		})
	})
	if err != nil || b.Added() != 2*n {
		t.Fatalf("%d records of %d formulae: %v", b.Added(), n, err)
	}
	if !raceEnabled && peak > 48<<20 {
		t.Errorf("reading a %d MB index took %d MB of heap", n*4/1000, peak>>20)
	}
}
