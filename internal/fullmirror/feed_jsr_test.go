package fullmirror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/jsr"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The jsr fixtures are real, recorded on 2026-11-16: pages of
// api.jsr.io/packages (limit 3, pages 1, 2 and one past the end), the list
// items of @luca/flag, @std/fmt and @std/path from a full pass over the list
// (limit 100), and jsr.io's meta.json and <version>_meta.json documents of
// those packages — @std/fmt's and @std/path's meta.json trimmed to a few
// versions, @std/path's manifest to a few files. JSR's documents name no
// absolute URL of the registry, so the backend's rewrite leaves them as they
// are.

// jsrTestFeed builds the jsr adapter for the public registry with the
// fixture server as its management API.
func jsrTestFeed(t *testing.T, limit int) (*jsrFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "jsr", "https://jsr.io", reads, map[string]string{"url": srv.URL()})).(*jsrFeed)
	f.indexFeed.src.(*jsrSource).limit = limit
	return f, srv, reads
}

// jsrTestBackend is the backend the adapter's paths are checked against.
func jsrTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := jsr.New(jsr.Options{Name: env.Upstream, UpstreamURL: "https://jsr.io", PublicBaseURL: "https://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jsrServeList serves the list pages the tests read (limit 3).
func jsrServeList(t *testing.T, srv *fixtureServer, third []byte) {
	t.Helper()
	srv.on("GET", "/packages?limit=3&page=1").reply(200, fixture(t, "jsr", "packages-limit3-page1.json"))
	srv.on("GET", "/packages?limit=3&page=2").reply(200, fixture(t, "jsr", "packages-limit3-page2.json"))
	srv.on("GET", "/packages?limit=3&page=3").reply(200, third)
	srv.on("GET", "/packages?limit=3&page=4").reply(200, fixture(t, "jsr", "packages-limit3-past-end.json"))
}

func TestJSRFeedLocation(t *testing.T) {
	f, err := newJSRFeed(Env{Upstream: "jsr", Type: "jsr", URL: "https://jsr.io"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*jsrFeed).indexFeed.src.(*jsrSource).api.String(); got != jsrPublicAPI {
		t.Errorf("the public registry's API %s", got)
	}
	err = Check(Env{Upstream: "jsr", Type: "jsr", URL: "https://jsr.internal.example"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("another upstream without a feed URL: %v", err)
	}
	f, err = newJSRFeed(Env{Upstream: "jsr", Type: "jsr", URL: "https://jsr.internal.example", Options: map[string]string{"url": "https://api.jsr.internal.example/"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*jsrFeed).indexFeed.src.(*jsrSource).api.String(); got != "https://api.jsr.internal.example" {
		t.Errorf("the feed option url gives %s", got)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"url": "ftp://api.jsr.io"}, {"url": "https://u:p@api.jsr.io"}, {"url": "https://api.jsr.io/?x=1"}} {
		if err := Check(Env{Upstream: "jsr", Type: "jsr", URL: "https://jsr.io", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

// Bootstrap reads every page of the list, up to the first that is not full,
// and lists the packages that have a version.
func TestJSRBootstrapReadsTheWholeList(t *testing.T) {
	f, srv, _ := jsrTestFeed(t, 3)
	f.page = 2
	jsrServeList(t, srv, fixture(t, "jsr", "packages-page-trimmed.json"))
	ctx := context.Background()
	var pages []batchView
	cursor := ""
	for i := 0; i < 10; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, viewBatch(t, b))
		cursor = b.Next
		if !b.More {
			break
		}
	}
	checkGolden(t, "jsr", "bootstrap", pages)
	if got := strings.Join(srv.requests(), " "); strings.Count(got, "GET /packages") != 4 {
		t.Errorf("requests %s", got)
	}

	// An unchanged list: no change, the cursor stays.
	b, err := f.Changes(ctx, cursor)
	if err != nil || len(b.Items) != 0 || b.Next != cursor {
		t.Errorf("an unchanged list: %+v %v", b, err)
	}

	// A publish moves the version count (the update time is the metadata's:
	// a publish leaves it); a package is gone, another new.
	var page struct {
		Items []map[string]any `json:"items"`
		Total int64            `json:"total"`
	}
	if err := json.Unmarshal(fixture(t, "jsr", "packages-page-trimmed.json"), &page); err != nil {
		t.Fatal(err)
	}
	flag := page.Items[0]
	page.Items[1]["versionCount"] = page.Items[1]["versionCount"].(float64) + 1
	page.Items[1]["latestVersion"] = "1.0.11"
	added := map[string]any{}
	for k, v := range flag {
		added[k] = v
	}
	added["name"] = "flags"
	page.Items[0] = added
	edited, _ := json.Marshal(page)
	jsrServeList(t, srv, edited)
	got, _ := drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "@luca/flag (deleted),@luca/flags,@std/fmt" {
		t.Errorf("Changes = %v", got)
	}
}

func TestJSRReleasesComeFromTheManifests(t *testing.T) {
	f, _, reads := jsrTestFeed(t, 3)
	for _, p := range []string{"meta-std-fmt.json", "std-fmt-1.0.10_meta.json", "std-fmt-0.225.0_meta.json", "std-fmt-1.0.0-rc.1_meta.json",
		"meta-luca-flag.json", "luca-flag-1.0.1_meta.json", "meta-std-path.json", "std-path-1.1.6_meta.json"} {
		scope, rest, _ := strings.Cut(strings.TrimPrefix(p, "meta-"), "-")
		name, file, _ := strings.Cut(rest, "-")
		target := "/@" + scope + "/" + name + "/" + file
		if strings.HasPrefix(p, "meta-") {
			target = "/@" + scope + "/" + strings.TrimSuffix(rest, ".json") + "/meta.json"
		}
		reads.set(target, fixture(t, "jsr", p))
	}
	backend := jsrTestBackend(t, f.k.env)
	ctx := context.Background()
	for _, name := range []string{"@std/fmt", "@luca/flag", "@std/path"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "jsr", "releases-"+strings.NewReplacer("@", "", "/", "-").Replace(name), viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
		for _, r := range rels {
			for _, a := range r.Artifacts {
				if a.Size <= 0 {
					t.Errorf("%s %s: no size", name, a.Path)
				}
			}
		}
	}
	// A version whose manifest is gone (0.224.0, 1.0.0 of the flag) is
	// skipped; every package keeps its file lists, so asking again reads
	// the meta.json alone.
	if n := reads.count("/@std/fmt/0.224.0_meta.json"); n != 1 {
		t.Errorf("the missing manifest was read %d times", n)
	}
	if m, _ := filepath.Glob(filepath.Join(f.cache.dir, jsrCachePrefix+"*")); len(m) != 3 {
		t.Errorf("file lists kept: %v", m)
	}
	if _, err := f.Releases(ctx, "@std/fmt"); err != nil {
		t.Fatal(err)
	}
	if n := reads.count("/@std/fmt/1.0.10_meta.json"); n != 1 {
		t.Errorf("a kept manifest was read %d times", n)
	}
	if n := reads.count("/@std/fmt/0.224.0_meta.json"); n != 2 {
		t.Errorf("a missing manifest is asked for again (it may appear): read %d times", n)
	}
}

// A package of few versions keeps its file lists too: a publish costs the
// meta.json and the new version's manifest (review of Task 191: a 60-version
// package re-read every manifest).
func TestJSRSmallPackagesReadEachManifestOnce(t *testing.T) {
	f, _, reads := jsrTestFeed(t, 3)
	versions := map[string]any{}
	meta := func(n int) []byte {
		for i := 0; i < n; i++ {
			v := fmt.Sprintf("1.0.%d", i)
			versions[v] = map[string]any{"createdAt": time.Date(2026, 1, 1, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano)}
			reads.set("/@mid/pkg/"+v+"_meta.json", []byte(fmt.Sprintf(`{"manifest":{"/mod.ts":{"size":%d,"checksum":"sha256-%064d"}}}`, 100+i, i)))
		}
		doc, _ := json.Marshal(map[string]any{"scope": "mid", "name": "pkg", "versions": versions})
		return doc
	}
	for _, n := range []int{1, 2, 60} {
		reads.set("/@mid/pkg/meta.json", meta(n))
		if _, err := f.Releases(context.Background(), "@mid/pkg"); err != nil {
			t.Fatal(err)
		}
	}
	reads.set("/@mid/pkg/meta.json", meta(61)) // one publish
	if _, err := f.Releases(context.Background(), "@mid/pkg"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 60; i++ {
		if c := reads.count(fmt.Sprintf("/@mid/pkg/1.0.%d_meta.json", i)); c != 1 {
			t.Errorf("1.0.%d's manifest read %d times", i, c)
		}
	}
}

// The file lists of a package with many versions are kept: a publish costs
// the package's meta.json and the new version's manifest.
func TestJSRKeepsTheFileListsOfLargePackages(t *testing.T) {
	f, _, reads := jsrTestFeed(t, 3)
	versions := map[string]any{}
	meta := func(n int) []byte {
		for i := 0; i < n; i++ {
			v := fmt.Sprintf("1.0.%d", i)
			versions[v] = map[string]any{"createdAt": time.Date(2026, 1, 1, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano)}
			reads.set("/@big/pkg/"+v+"_meta.json", []byte(fmt.Sprintf(`{"manifest":{"/mod.ts":{"size":%d,"checksum":"sha256-%064d"},"/src/a b.ts":{"size":7,"checksum":"sha256-%064d"}},"exports":{".":"./mod.ts"}}`, 100+i, i, i)))
		}
		doc, _ := json.Marshal(map[string]any{"scope": "big", "name": "pkg", "latest": fmt.Sprintf("1.0.%d", n-1), "versions": versions})
		return doc
	}
	n := 70
	reads.set("/@big/pkg/meta.json", meta(n))
	ctx := context.Background()
	rels, err := f.Releases(ctx, "@big/pkg")
	if err != nil || len(rels) != n || rels[0].Version != "1.0.0" || rels[n-1].Version != fmt.Sprintf("1.0.%d", n-1) {
		t.Fatalf("%d releases %v", len(rels), err)
	}
	expectServed(t, jsrTestBackend(t, f.k.env), rels, func(r Release, _ Artifact) (string, string) { return "@big/pkg", r.Version })
	files, _ := filepath.Glob(filepath.Join(f.cache.dir, jsrCachePrefix+"*.json.gz"))
	if len(files) != 1 {
		t.Fatalf("file lists kept: %v", files)
	}
	// A publish: the new version's manifest is read, no other.
	reads.set("/@big/pkg/meta.json", meta(n+1))
	again, err := f.Releases(ctx, "@big/pkg")
	if err != nil || len(again) != n+1 {
		t.Fatalf("%d releases %v", len(again), err)
	}
	for i := 0; i <= n; i++ {
		if c := reads.count(fmt.Sprintf("/@big/pkg/1.0.%d_meta.json", i)); c != 1 {
			t.Errorf("1.0.%d's manifest read %d times", i, c)
		}
	}
	if fmt.Sprint(viewReleases(again[:n])) != fmt.Sprint(viewReleases(rels)) {
		t.Errorf("the kept lists list other files")
	}
	// A damaged file is no list: the manifests are read again.
	if err := os.WriteFile(files[0], []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if third, err := f.Releases(ctx, "@big/pkg"); err != nil || len(third) != n+1 {
		t.Fatalf("after damage: %d %v", len(third), err)
	}
	if c := reads.count("/@big/pkg/1.0.0_meta.json"); c != 2 {
		t.Errorf("after damage 1.0.0's manifest was read %d times", c)
	}
	// Another package's list under this one's name is not trusted.
	other := f.loadCache("@big/other")
	if other == nil || len(other.Versions) != 0 {
		t.Errorf("a missing list: %+v", other)
	}
	data, _ := os.ReadFile(files[0])
	if err := os.WriteFile(filepath.Join(f.cache.dir, jsrCacheName("@big/other")), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if c := f.loadCache("@big/other"); len(c.Versions) != 0 {
		t.Errorf("another package's list was taken: %d versions", len(c.Versions))
	}
	for _, e := range mustReadDir(t, f.cache.dir) {
		if strings.HasPrefix(e, snapPrefix) && !strings.HasSuffix(e, snapSuffix) && e != snapCurrent {
			t.Errorf("a file of the adapter in the toolkit's namespace: %s", e)
		}
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestJSRMalformed(t *testing.T) {
	ctx := context.Background()
	f, srv, reads := jsrTestFeed(t, 3)
	page1 := fixture(t, "jsr", "packages-limit3-page1.json")
	for name, tc := range map[string]struct {
		page1, page2 string
		want         string
	}{
		"garbage":       {"<html>blocked</html>", "", "page 1 is not the list expected"},
		"no items":      {`{"total":5}`, "", "has no items"},
		"wrong shape":   {`{"items":{"a":1}}`, "", "not the list expected"},
		"too many":      {`{"items":[{},{},{},{}],"total":4}`, "", "lists 4 packages, more than the 3"},
		"not advancing": {string(page1), string(page1), "does not advance"},
	} {
		srv.on("GET", "/packages?limit=3&page=1").reply(200, []byte(tc.page1))
		if tc.page2 != "" {
			srv.on("GET", "/packages?limit=3&page=2").reply(200, []byte(tc.page2))
		}
		_, err := f.Bootstrap(ctx, "")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, true, false, tc.want)
	}
	// Items no path carries, or without a version, are left out.
	srv.on("GET", "/packages?limit=3&page=1").json(`{"items":[{"scope":"Bad","name":"x","latestVersion":"1.0.0","versionCount":1},
		{"scope":"ok","name":"pre","latestVersion":null,"versionCount":3},{"scope":"ok","name":"bad-version","latestVersion":"1.0.0/x","versionCount":2}],"total":3}`)
	srv.on("GET", "/packages?limit=3&page=2").json(`{"items":[{"scope":"ok","name":"a/b","latestVersion":"1.0.0","versionCount":1},{"scope":"ok","name":"none","latestVersion":null,"versionCount":0}],"total":5}`)
	srv.on("GET", "/packages?limit=3&page=3").json(`{"items":[],"total":5}`)
	listed, _ := drainBootstrap(t, f)
	if strings.Join(listed, ",") != "@ok/bad-version,@ok/pre" {
		t.Errorf("listed %v", listed)
	}
	srv.on("GET", "/packages?limit=3&page=1").reply(503, nil).withHeader("Retry-After", "30")
	_, err := f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 30*time.Second {
		t.Errorf("a 503: %v", err)
	}

	// Releases.
	for _, bad := range []string{"std/fmt", "@std", "@std/", "@Std/fmt", "@std/fmt/x", "@std/f mt", ""} {
		_, err := f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a JSR package name")
	}
	_, err = f.Releases(ctx, "@std/missing")
	mustErr(t, err, true, false, "not found")
	for name, tc := range map[string]struct{ body, want string }{
		"garbage":     {"<html>", "meta.json of @t/garbage"},
		"no versions": {`{"scope":"t","name":"noversions"}`, "lists no versions"},
		"another":     {`{"scope":"t","name":"other","versions":{}}`, "describes @t/other"},
		"shape":       {`{"versions":[]}`, "meta.json of @t/shape"},
	} {
		pkg := strings.ReplaceAll(name, " ", "")
		reads.set("/@t/"+pkg+"/meta.json", []byte(tc.body))
		_, err := f.Releases(ctx, "@t/"+pkg)
		mustErr(t, err, true, false, tc.want)
	}
	// A version whose manifest is malformed, too large or refused is skipped;
	// files no path carries are left out; a hold stops the call.
	reads.set("/@t/v/meta.json", []byte(`{"scope":"t","name":"v","versions":{"1.0.0":{},"1.1.0":{"yanked":true},"1.2.0":{},"1.3.0":{},"1.4.0":{},"bad/1":{},"2.0.0":{}}}`))
	reads.set("/@t/v/1.0.0_meta.json", []byte(`{"manifest":{"/ok.ts":{"size":5},"/../x.ts":{"size":1},"relative.ts":{"size":1},"//a.ts":{"size":1},"/neg.ts":{"size":-4}}}`))
	reads.set("/@t/v/1.1.0_meta.json", []byte(`{"manifest":{"/mod.ts":{"size":9}}}`))
	reads.set("/@t/v/1.2.0_meta.json", []byte(`not json`))
	var many strings.Builder
	many.WriteString(`{"manifest":{`)
	for i := 0; i <= jsrMaxFiles; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		fmt.Fprintf(&many, `"/f%d.ts":{"size":1}`, i)
	}
	many.WriteString(`}}`)
	reads.set("/@t/v/1.3.0_meta.json", []byte(many.String()))
	reads.setDoc("/@t/v/1.4.0_meta.json", fakeDoc{status: 403, gate: "policy", code: "denied"})
	reads.set("/@t/v/2.0.0_meta.json", []byte(`{"manifest":{"/../only-bad.ts":{"size":1}}}`))
	rels, err := f.Releases(ctx, "@t/v")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(viewReleases(rels)); string(got) != `[{"version":"1.0.0","artifacts":[{"path":"/@t/v/1.0.0/neg.ts"},{"path":"/@t/v/1.0.0/ok.ts","size":5}]},{"version":"1.1.0","yanked":true,"artifacts":[{"path":"/@t/v/1.1.0/mod.ts","size":9}]}]` {
		t.Errorf("releases %s", got)
	}
	reads.setDoc("/@t/v/1.2.0_meta.json", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "@t/v")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal of a manifest: %v", err)
	}
	reads.setDoc("/@t/squat/meta.json", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "@t/squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/@t/held/meta.json", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "@t/held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	// Cursors of another adapter or format, and garbage, are not trusted.
	for _, bad := range []string{"x", `{"format":"maven/1","snap":"` + strings.Repeat("a", 64) + `"}`, `{"format":"jsr/1","snap":"` + strings.Repeat("c", 64) + `"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

// Versions are ordered by SemVer and bounded to the newest.
func TestJSRParseMeta(t *testing.T) {
	vs, err := jsrParseMeta([]byte(`{"scope":"s","name":"n","versions":{"1.10.0":{},"1.9.0":{"createdAt":"2025-01-01T00:00:00.5Z"},"1.0.0-rc.1":{},"1.0.0":{"yanked":true},"x y":{}}}`), "s", "n")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range vs {
		s := v.version
		if v.yanked {
			s += "(yanked)"
		}
		if !v.created.IsZero() {
			s += "@" + v.created.Format(time.RFC3339Nano)
		}
		got = append(got, s)
	}
	if strings.Join(got, " ") != "1.0.0-rc.1 1.0.0(yanked) 1.9.0@2025-01-01T00:00:00.5Z 1.10.0" {
		t.Errorf("versions %v", got)
	}
	var b strings.Builder
	b.WriteString(`{"versions":{`)
	for i := 0; i < jsrMaxVersions+10; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"0.0.%d":{}`, i)
	}
	b.WriteString(`}}`)
	vs, err = jsrParseMeta([]byte(b.String()), "s", "n")
	if err != nil || len(vs) != jsrMaxVersions || vs[0].version != "0.0.10" || vs[len(vs)-1].version != fmt.Sprintf("0.0.%d", jsrMaxVersions+9) {
		t.Errorf("bounded to %d versions from %s (%v)", len(vs), vs[0].version, err)
	}
}

// A page shorter than asked for is not the end of the list: the pass goes on
// to the first empty page (a server may leave out an item it cannot render).
func TestJSRShortPageIsNotTheEnd(t *testing.T) {
	f, srv, _ := jsrTestFeed(t, 3)
	item := func(scope, name string) string {
		return `{"scope":"` + scope + `","name":"` + name + `","latestVersion":"1.0.0","versionCount":1,"updatedAt":"2026-01-01T00:00:00Z"}`
	}
	srv.on("GET", "/packages?limit=3&page=1").json(`{"items":[` + item("a", "one") + `,` + item("a", "two") + `,` + item("a", "three") + `],"total":6}`)
	srv.on("GET", "/packages?limit=3&page=2").json(`{"items":[` + item("b", "four") + `],"total":6}`)
	srv.on("GET", "/packages?limit=3&page=3").json(`{"items":[` + item("c", "five") + `,` + item("c", "six") + `],"total":6}`)
	srv.on("GET", "/packages?limit=3&page=4").reply(200, fixture(t, "jsr", "packages-limit3-past-end.json"))
	listed, _ := drainBootstrap(t, f)
	sort.Strings(listed)
	if strings.Join(listed, ",") != "@a/one,@a/three,@a/two,@b/four,@c/five,@c/six" {
		t.Errorf("listed %v", listed)
	}
}
