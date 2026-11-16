package fullmirror

import (
	"bytes"
	"context"
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
	// A Homebrew mirror is a static copy: refused at load time, saying what
	// to set.
	err = Check(Env{Upstream: "mirror", Type: "homebrew", URL: "https://brew-api.internal.example"})
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
