package fullmirror

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestCargoFeedLocation(t *testing.T) {
	f, err := newCargoFeed(Env{Upstream: "crates", Type: "cargo", URL: "https://index.crates.io"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*cargoFeed).git.remote.repo.String(); got != cargoPublicIndex {
		t.Errorf("crates.io's index %s", got)
	}
	// A private sparse registry has no known Git index: the configuration is
	// refused at load time, with what to set.
	err = Check(Env{Upstream: "corp", Type: "cargo", URL: "https://cargo.internal.example/api/v1/crates"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a private registry without a feed URL: %v", err)
	}
	if err := Check(Env{Upstream: "corp", Type: "cargo", URL: "https://cargo.internal.example", Options: map[string]string{"url": "https://git.internal.example/index.git", "branch": "main"}}); err != nil {
		t.Errorf("a private registry with its Git index: %v", err)
	}
	for _, opts := range []map[string]string{{"branch": "a..b"}, {"branch": "-x"}, {"since": "x"}} {
		if err := Check(Env{Upstream: "c", Type: "cargo", URL: "https://index.crates.io", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestCargoIndexLayout(t *testing.T) {
	for name, want := range map[string]string{"a": "1/a", "cc": "2/cc", "syn": "3/s/syn", "Serde": "se/rd/serde", "cfg-if": "cf/g-/cfg-if"} {
		if got := cargoIndexPath(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	for p, want := range map[string]bool{"1/a": true, "3/s/syn": true, "cf/g-/cfg-if": true, "config.json": false, "se/rd/other": false,
		".github/workflows/ci.yml": false, "3/x/syn": false, "README.md": false} {
		_, ok := cargoCoordinate(p, gitAdded)
		if ok != want {
			t.Errorf("%s: crate %v, want %v", p, ok, want)
		}
	}
	for dir, want := range map[string]bool{"": true, "1": true, "3": true, "3/s": true, "se": true, "se/rd": true, ".github": false, "se/rd/x": false, "3/ab": false} {
		if got := cargoArea(dir); got != want {
			t.Errorf("area %q: %v, want %v", dir, got, want)
		}
	}
}

func TestCargoFollowsTheGitIndex(t *testing.T) {
	// A Git index laid out as crates.io's: config.json, crate files by name.
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	files := map[string]string{
		"config.json":              `{"dl":"https://static.crates.io/crates","api":"https://crates.io"}`,
		"cf/g-/cfg-if":             "{}\n",
		"se/rd/serde_derive":       "{}\n",
		"1/a":                      "{}\n",
		".github/workflows/ci.yml": "x",
	}
	repo.commit(files, t0, false)
	git := newGitTestServer(t, repo)
	reads := newFakeReads()
	env := testEnv(t, "cargo", "https://index.crates.io", reads, map[string]string{"url": git.URL()})
	f := mustFeed(t, env).(*cargoFeed)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[a cfg-if serde_derive]" || b.More {
		t.Fatalf("bootstrap %s more=%v", got, b.More)
	}
	// A publish (cfg-if's file changes), a new crate, a removed crate, and
	// an edit of config.json.
	files["cf/g-/cfg-if"] = "{}\n{}\n"
	files["3/s/syn"] = "{}\n"
	delete(files, "1/a")
	files["config.json"] = `{"dl":"x"}`
	repo.commit(files, t0.Add(time.Minute), false)
	c, err := f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cargo", "changes", viewBatch(t, c))
}

func TestCargoReleasesComeFromTheSparseIndex(t *testing.T) {
	reads := newFakeReads()
	reads.set("/cf/g-/cfg-if", fixture(t, "cargo", "index-cfg-if.jsonl"))
	reads.set("/se/rd/serde_derive", fixture(t, "cargo", "index-serde_derive.jsonl"))
	env := testEnv(t, "cargo", "https://index.crates.io", reads, nil)
	f := mustFeed(t, env).(*cargoFeed)
	backend, err := pkgmgr.NewCargo(pkgmgr.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cfg-if", "serde_derive"} {
		rels, err := f.Releases(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		checkGolden(t, "cargo", "releases-"+name, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	// Malformed and unknown.
	reads.set("/3/b/bad", []byte("not json\n{\"vers\":1}\n"))
	_, err = f.Releases(context.Background(), "bad")
	mustErr(t, err, true, false, "none of its 2 lines")
	_, err = f.Releases(context.Background(), "nope")
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(context.Background(), "../x")
	mustErr(t, err, true, false, "not a crate name")
}
