package fullmirror

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/julia"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The General registry as pkg.julialang.org served it on 2026-11-16: two
// snapshots' tree hashes (juliaHashB is the conservative /registries answer
// recorded in testdata/feeds/julia/registries.txt), and real files of six of
// its packages under testdata/feeds/julia/registry/ (Registry.toml's header
// and their [packages] lines, their Package.toml and Versions.toml).
const (
	juliaGeneral = "23338594-aafe-5451-b93e-139f81909106"
	juliaHashA   = "549badb7b44063a4bae7d3db30480a17665e6f90"
	juliaHashB   = "d6419a1850d259a1145e4846c3bc71dea7fa09c2"
)

// juliaRegistryFiles reads the recorded registry files.
func juliaRegistryFiles(t *testing.T) map[string][]byte {
	t.Helper()
	root := filepath.Join("testdata", "feeds", "julia", "registry")
	out := map[string][]byte{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		data, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// juliaSnapshots builds the two snapshots: B is the recorded files without
// Swizzling; A, the earlier one, lacks TuringGLM and Example's newest version
// and still has Swizzling.
func juliaSnapshots(t *testing.T) (a, b map[string][]byte) {
	t.Helper()
	files := juliaRegistryFiles(t)
	a, b = map[string][]byte{}, map[string][]byte{}
	for p, d := range files {
		a[p], b[p] = d, d
	}
	dropLine := func(doc []byte, substr string) []byte {
		var keep []string
		for _, l := range strings.Split(string(doc), "\n") {
			if !strings.Contains(l, substr) {
				keep = append(keep, l)
			}
		}
		return []byte(strings.Join(keep, "\n"))
	}
	b["Registry.toml"] = dropLine(files["Registry.toml"], `name = "Swizzling"`)
	delete(b, "S/Swizzling/Package.toml")
	delete(b, "S/Swizzling/Versions.toml")
	a["Registry.toml"] = dropLine(files["Registry.toml"], `name = "TuringGLM"`)
	delete(a, "T/TuringGLM/Package.toml")
	delete(a, "T/TuringGLM/Versions.toml")
	ex := string(files["E/Example/Versions.toml"])
	a["E/Example/Versions.toml"] = []byte(strings.TrimRight(ex[:strings.LastIndex(ex, "\n[")], "\n") + "\n")
	return a, b
}

// juliaTarball packs registry files as a Pkg server serves a registry: a
// gzip-compressed tar of its tree, directories included, paths relative to
// its root.
func juliaTarball(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	dirs := map[string]bool{}
	var names []string
	for p := range files {
		names = append(names, p)
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, n := range names {
		var err error
		if dirs[n] {
			err = tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR})
		} else {
			if err = tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(files[n])), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err == nil {
				_, err = tw.Write(files[n])
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// juliaTestFeed builds the adapter against a fixture server standing in for
// pkg.julialang.org, with the registry snapshots readable through the fake
// pipeline.
func juliaTestFeed(t *testing.T, opts map[string]string) (*juliaFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	a, b := juliaSnapshots(t)
	reads.set("/registry/"+juliaGeneral+"/"+juliaHashA, juliaTarball(t, a))
	reads.set("/registry/"+juliaGeneral+"/"+juliaHashB, juliaTarball(t, b))
	f := mustFeed(t, testEnv(t, "julia", srv.URL(), reads, opts)).(*juliaFeed)
	return f, srv, reads
}

// juliaServe makes the server list one snapshot of General, redirecting
// /registries to the flavour's list as pkg.julialang.org does.
func juliaServe(srv *fixtureServer, flavor, hash string) {
	srv.on("GET", "/registries").requireHeader("Julia-Registry-Preference", flavor).reply(http.StatusFound, nil).withHeader("Location", "/registries."+flavor)
	srv.on("GET", "/registries."+flavor).reply(http.StatusOK, []byte("/registry/"+juliaGeneral+"/"+hash+"\n")).withHeader("Content-Type", "text/plain")
}

func TestJuliaFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url    string
		opts   map[string]string
		flavor string
	}{
		{"https://pkg.julialang.org", nil, "conservative"},
		{"https://pkgserver.internal.example/julia/", map[string]string{"flavor": "eager"}, "eager"},
		{"https://pkg.julialang.org", map[string]string{"flavor": "Conservative"}, "conservative"},
	} {
		f, err := juliaNewFeed(Env{Upstream: "j", Type: "julia", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		jf := f.(*juliaFeed)
		if jf.flavor != tc.flavor || join(jf.k.upstream, "registries") != strings.TrimRight(tc.url, "/")+"/registries" {
			t.Errorf("%s: flavor %s, registries at %s", tc.url, jf.flavor, join(jf.k.upstream, "registries"))
		}
	}
	// The feed is the Pkg server itself: there is no url option.
	for _, opts := range []map[string]string{{"url": "https://pkg.julialang.org"}, {"flavor": "lazy"}, {"since": "1"}} {
		if err := Check(Env{Upstream: "j", Type: "julia", URL: "https://pkg.julialang.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestJuliaBootstrapIndexesTheCurrentSnapshot(t *testing.T) {
	f, srv, reads := juliaTestFeed(t, nil)
	f.page = 3
	// The recorded conservative answer, behind the redirect.
	srv.on("GET", "/registries").requireHeader("Julia-Registry-Preference", "conservative").reply(http.StatusFound, nil).withHeader("Location", "/registries.conservative")
	srv.on("GET", "/registries.conservative").reply(http.StatusOK, fixture(t, "julia", "registries.txt"))
	ctx := context.Background()
	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "julia", "bootstrap-page-1", viewBatch(t, first))
	second, err := f.Bootstrap(ctx, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "julia", "bootstrap-page-2", viewBatch(t, second))
	if !first.More || second.More {
		t.Fatalf("paging: %v %v", first.More, second.More)
	}
	if got := strings.Join(append(names(first.Items), names(second.Items)...), " "); got != "ADTypes AbstractMCMC Example PTI_jll TuringGLM" {
		t.Errorf("listed %s", got)
	}
	var c juliaCursor
	if err := f.decode(second.Next, &c); err != nil || c.Listing || len(c.Registries) != 1 || c.Registries[0] != juliaGeneral+"/"+juliaHashB {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	// The registry was read once, through the proxy; the second page came
	// from the stored index.
	if n := reads.count("/registry/" + juliaGeneral + "/" + juliaHashB); n != 1 {
		t.Errorf("the registry was read %d times", n)
	}
	if _, err := f.Changes(ctx, first.Next); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, second.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
	// Only the snapshot's index, and the file naming it, are kept; the
	// downloaded tarball is gone.
	entries, _ := os.ReadDir(f.files.dir)
	var kept []string
	for _, e := range entries {
		kept = append(kept, e.Name())
	}
	if len(kept) != 2 || kept[0] != juliaCurrentFile || kept[1] != juliaIndexName(c.Registries) {
		t.Errorf("files kept: %v", kept)
	}
	// A new enumeration of the same snapshot (after a restart) reuses its
	// index rather than downloading the registry again.
	restarted := mustFeed(t, f.k.env).(*juliaFeed)
	if b, err := restarted.Bootstrap(ctx, ""); err != nil || len(b.Items) != 5 {
		t.Errorf("bootstrap again: %v, %v", names(b.Items), err)
	}
	if n := reads.count("/registry/" + juliaGeneral + "/" + juliaHashB); n != 1 {
		t.Errorf("the registry was read %d times", n)
	}
}

func TestJuliaChangesDiffTwoSnapshots(t *testing.T) {
	f, srv, reads := juliaTestFeed(t, nil)
	ctx := context.Background()
	juliaServe(srv, "conservative", juliaHashA)
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	start := b.Next
	// The server publishes snapshot B: Example has a new version, TuringGLM
	// was registered, Swizzling is gone.
	juliaServe(srv, "conservative", juliaHashB)
	ch, err := f.Changes(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "julia", "changes", viewBatch(t, ch))
	if reads.count("/registry/"+juliaGeneral+"/"+juliaHashA) != 1 || reads.count("/registry/"+juliaGeneral+"/"+juliaHashB) != 1 {
		t.Errorf("registry reads: A %d, B %d", reads.count("/registry/"+juliaGeneral+"/"+juliaHashA), reads.count("/registry/"+juliaGeneral+"/"+juliaHashB))
	}
	// Both indexes are kept: the engine may ask again from the same cursor.
	again, err := f.Changes(ctx, start)
	if err != nil || len(again.Items) != len(ch.Items) || again.Next != ch.Next {
		t.Errorf("the same cursor again: %d items, %v", len(again.Items), err)
	}
	// Nothing changed since: no item, no download.
	idle, err := f.Changes(ctx, ch.Next)
	if err != nil || len(idle.Items) != 0 || idle.Next != ch.Next || !idle.LagKnown {
		t.Errorf("unchanged snapshot: %+v, %v", idle, err)
	}
	if n := reads.count("/registry/" + juliaGeneral + "/" + juliaHashB); n != 1 {
		t.Errorf("the registry was read %d times", n)
	}
	// A difference spans several batches when it is long.
	f.page = 5
	var paged []Coordinate
	cur := start
	for i := 0; i < 20; i++ {
		p, err := f.Changes(ctx, cur)
		if err != nil {
			t.Fatal(err)
		}
		paged = append(paged, p.Items...)
		cur = p.Next
		if !p.More {
			break
		}
	}
	if len(paged) != len(ch.Items) || cur != ch.Next {
		t.Errorf("paged %d changes ending at %s; want %d ending at %s", len(paged), cur, len(ch.Items), ch.Next)
	}
	for i := range paged {
		if i < len(ch.Items) && paged[i] != ch.Items[i] {
			t.Errorf("change %d: %v, want %v", i, paged[i], ch.Items[i])
		}
	}
}

func TestJuliaReleasesComeFromTheNewestIndex(t *testing.T) {
	f, srv, reads := juliaTestFeed(t, map[string]string{"flavor": "eager"})
	ctx := context.Background()
	juliaServe(srv, "eager", juliaHashB)
	if _, err := f.Bootstrap(ctx, ""); err != nil {
		t.Fatal(err)
	}
	backend, err := julia.New(julia.Options{Name: f.k.env.Upstream, UpstreamURL: "https://pkg.julialang.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	files := juliaRegistryFiles(t)
	uuids := map[string]string{"ADTypes": "47edcb42-4c32-4615-8424-f2b9edc5f35b", "Example": "7876af07-990d-54b4-ab0e-23690620f79a", "PTI_jll": "00038326-6c92-5172-8bc1-19e163662d45"}
	dirs := map[string]string{"ADTypes": "A/ADTypes", "Example": "E/Example", "PTI_jll": "jll/P/PTI_jll"}
	tables := regexp.MustCompile(`\["([^"]+)"\]\ngit-tree-sha1 = "([0-9a-f]{40})"`)
	check := func(f *juliaFeed, golden bool) {
		t.Helper()
		for _, name := range []string{"ADTypes", "Example", "PTI_jll"} {
			rels, err := f.Releases(ctx, name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if golden {
				checkGolden(t, "julia", "releases-"+strings.ToLower(name), viewReleases(rels))
			}
			// Each version's tree, as Versions.toml records it: the backend
			// resolves the path to the package's uuid and that tree.
			trees := map[string]string{}
			for _, m := range tables.FindAllStringSubmatch(string(files[dirs[name]+"/Versions.toml"]), -1) {
				trees[m[1]] = m[2]
			}
			if len(rels) != len(trees) {
				t.Errorf("%s: %d releases, Versions.toml has %d", name, len(rels), len(trees))
			}
			expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return uuids[name], trees[r.Version] })
		}
	}
	check(f, true)
	rels, _ := f.Releases(ctx, "ADTypes")
	var yanked []string
	for _, r := range rels {
		if r.Yanked {
			yanked = append(yanked, r.Version)
		}
	}
	if len(yanked) == 0 {
		t.Errorf("no yanked version of ADTypes")
	}
	// After a restart the newest index is read from the directory: no
	// request, no read through the proxy.
	env := f.k.env
	env.HTTP, env.Read = &http.Client{Transport: juliaFailingTransport{t}}, nil
	restarted := mustFeed(t, env).(*juliaFeed)
	check(restarted, false)
	if n := len(srv.requests()); n != 2 {
		t.Errorf("%d requests to the server; the restarted feed made some", n)
	}
	// A name no registry has, a name that is not one.
	_, err = f.Releases(ctx, "Swizzling") // removed in snapshot B
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(ctx, "../x")
	mustErr(t, err, true, false, "not a Julia package name")
	_ = reads
}

func TestJuliaReleasesConcurrently(t *testing.T) {
	// The engine calls Releases from several workers at once; right after a
	// restart the first calls load the stored index.
	f, srv, _ := juliaTestFeed(t, nil)
	juliaServe(srv, "conservative", juliaHashB)
	if _, err := f.Bootstrap(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	restarted := mustFeed(t, f.k.env).(*juliaFeed)
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		name := []string{"ADTypes", "AbstractMCMC", "Example", "PTI_jll"}[i%4]
		go func() {
			_, err := restarted.Releases(context.Background(), name)
			errs <- err
		}()
	}
	for i := 0; i < 32; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

// juliaFailingTransport fails a test that makes a request.
type juliaFailingTransport struct{ t *testing.T }

func (f juliaFailingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
	return nil, errorf("no network")
}

func TestJuliaCursorThatDoesNotMatchTheStoredIndexIsInvalid(t *testing.T) {
	f, srv, _ := juliaTestFeed(t, nil)
	ctx := context.Background()
	juliaServe(srv, "conservative", juliaHashA)
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	juliaServe(srv, "conservative", juliaHashB)
	// A snapshot whose index is not stored (the directory was lost, a
	// backup restored without it).
	other := f.cursor(juliaCursor{Registries: []string{juliaGeneral + "/" + strings.Repeat("0", 40)}})
	_, err = f.Changes(ctx, other)
	mustErr(t, err, false, true, "not stored")
	// An index file that holds another snapshot than its name says.
	fresh := mustFeed(t, f.k.env).(*juliaFeed)
	name := juliaIndexName([]string{juliaGeneral + "/" + juliaHashA})
	data, err := os.ReadFile(fresh.files.path(name))
	if err != nil {
		t.Fatal(err)
	}
	otherName := juliaIndexName([]string{juliaGeneral + "/" + strings.Repeat("0", 40)})
	if err := os.WriteFile(fresh.files.path(otherName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = fresh.Changes(ctx, other)
	mustErr(t, err, false, true, "another snapshot")
	// A damaged index file.
	if err := os.WriteFile(fresh.files.path(name), []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = fresh.Changes(ctx, b.Next)
	mustErr(t, err, false, true, "not stored")
	// Cursors that do not read.
	for _, bad := range []string{"x", `{"format":"julia/1","registries":["x/y"]}`, `{"format":"julia/1","registries":[],"skip":-1}`,
		`{"format":"julia/1","registries":["` + juliaGeneral + "/" + juliaHashB + `","` + juliaGeneral + "/" + juliaHashA + `"]}`,
		`{"format":"julia/1","registries":[],"listing":true,"to":[]}`, `{"format":"julia/1","registries":[],"extra":1}`, `{"format":"cargo-git/1","commit":"x"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestJuliaMalformedAnswers(t *testing.T) {
	f, srv, reads := juliaTestFeed(t, nil)
	ctx := context.Background()
	for body, want := range map[string]string{
		"<html>maintenance</html>\n": "names a registry",
		"/registry/" + juliaGeneral + "/" + juliaHashA + "\n/registry/" + juliaGeneral + "/" + juliaHashB + "\n": "twice",
	} {
		srv.on("GET", "/registries").json(body)
		_, err := f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, want)
	}
	srv.on("GET", "/registries").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "60")
	_, err := f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != time.Minute {
		t.Errorf("a 503 with Retry-After: %v", err)
	}
	// Registry tarballs that are not one.
	bad := strings.Repeat("1", 40)
	srv.on("GET", "/registries").json("/registry/" + juliaGeneral + "/" + bad + "\n")
	_, b := juliaSnapshots(t)
	noRegistry := map[string][]byte{"A/ADTypes/Versions.toml": b["A/ADTypes/Versions.toml"]}
	otherUUID := map[string][]byte{"Registry.toml": []byte("uuid = \"" + strings.Repeat("a", 8) + "-aaaa-aaaa-aaaa-" + strings.Repeat("a", 12) + "\"\n[packages]\n")}
	broken := map[string][]byte{"Registry.toml": []byte("uuid = \"" + juliaGeneral + "\"\ndescription = \"\"\"\nnever ends\n")}
	for body, want := range map[string]string{
		"not gzip":                          "not a gzip file",
		string(juliaTarball(t, noRegistry)): "no Registry.toml",
		string(juliaTarball(t, otherUUID)):  "it is registry aaaaaaaa",
		string(juliaTarball(t, broken)):     "does not end",
	} {
		reads.set("/registry/"+juliaGeneral+"/"+bad, []byte(body))
		_, err := f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, want)
	}
	// A gate's verdict on the registry is final; a lockdown is not.
	reads.setDoc("/registry/"+juliaGeneral+"/"+bad, fakeDoc{status: http.StatusForbidden, gate: "contentscan", code: "suspicious"})
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "contentscan")
	reads.setDoc("/registry/"+juliaGeneral+"/"+bad, fakeDoc{status: http.StatusServiceUnavailable, gate: "lockdown", code: "lockdown"})
	_, err = f.Bootstrap(ctx, "")
	if _, ok := RetryAfterOf(err); !ok || IsPermanent(err) {
		t.Errorf("a lockdown: %v", err)
	}
	// A package whose Versions.toml does not parse is left out; the others
	// are indexed.
	damaged := map[string][]byte{}
	for p, d := range b {
		damaged[p] = d
	}
	damaged["E/Example/Versions.toml"] = []byte("[\"0.1.0\"\ngit-tree-sha1 = 1\n")
	reads.set("/registry/"+juliaGeneral+"/"+bad, juliaTarball(t, damaged))
	got, err := f.Bootstrap(ctx, "")
	if err != nil || strings.Join(names(got.Items), " ") != "ADTypes AbstractMCMC PTI_jll TuringGLM" {
		t.Errorf("with a damaged Versions.toml: %v, %v", names(got.Items), err)
	}
}

func TestJuliaRegistryTOML(t *testing.T) {
	files := juliaRegistryFiles(t)
	reg, err := juliaParseRegistryTOML(files["Registry.toml"])
	if err != nil {
		t.Fatal(err)
	}
	if reg.uuid != juliaGeneral || len(reg.packages) != 6 || reg.packages[1] != (juliaRegistryEntry{uuid: "00038326-6c92-5172-8bc1-19e163662d45", name: "PTI_jll", path: "jll/P/PTI_jll"}) {
		t.Errorf("parsed %+v", reg)
	}
	// Other shapes TOML allows for the same data, and entries left out.
	doc := `# a private registry
name = 'Corp'   # literal string
uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
description = """one line"""
weight = 1.5
created = 2026-11-16T00:00:00Z
flag = true

[packages]
"aaaaaaaa-0000-0000-0000-000000000001" = {path="A/Alpha",name="Alpha"}
aaaaaaaa-0000-0000-0000-000000000002 = { name = "Beta", path = "B/Beta", extra = "x" } # comment
aaaaaaaa-0000-0000-0000-000000000003 = { name = "Gamma", path = "../escape" }
aaaaaaaa-0000-0000-0000-000000000004 = { name = "bad name", path = "B/bad" }
not-a-uuid = { name = "Delta", path = "D/Delta" }
aaaaaaaa-0000-0000-0000-000000000005 = { name = "Eps", path = "E/Eps"
aaaaaaaa-0000-0000-0000-000000000001 = { name = "Again", path = "A/Again" }

[other]
key = "value"
`
	reg, err = juliaParseRegistryTOML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if reg.uuid != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || len(reg.packages) != 2 || reg.packages[0].name != "Alpha" || reg.packages[1].path != "B/Beta" {
		t.Errorf("parsed %+v", reg)
	}
	for doc, want := range map[string]string{
		"name = \"x\"\n": "no uuid",
		"uuid = \"x\"\n": "not a UUID",
		"uuid = \"" + juliaGeneral + "\"\n[packages.x]\n":           "sub-tables",
		"uuid = \"" + juliaGeneral + "\"\nlist = [1, 2]\n":          "does not read",
		"uuid = \"" + juliaGeneral + "\"\n= 1\n":                    "not `key = value`",
		"[packages\n":                                               "not a table header",
		"uuid = \"" + juliaGeneral + "\"\nx = \"\"\"a\nb\"\"\" y\n": "after a multi-line",
		"\xff\xfe": "not UTF-8",
		"x = \"" + strings.Repeat("a", juliaMaxTOMLLine) + "\"\n": "longer than",
	} {
		_, err := juliaParseRegistryTOML([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", truncate(doc, 40), err, want)
		}
	}
}

func TestJuliaVersionsTOML(t *testing.T) {
	files := juliaRegistryFiles(t)
	vs, err := juliaParseVersionsTOML(files["A/AbstractMCMC/Versions.toml"])
	if err != nil {
		t.Fatal(err)
	}
	yanked := 0
	for _, v := range vs {
		if v.Yanked {
			yanked++
		}
	}
	if len(vs) != 67 || yanked == 0 || vs[0].Version != "0.1.0" || len(vs[0].Tree) != 40 {
		t.Errorf("%d versions, %d yanked, first %+v", len(vs), yanked, vs[0])
	}
	vs, err = juliaParseVersionsTOML([]byte(`# comment
["1.0.0"]   # trailing
git-tree-sha1 = "ABCDEFabcdef0123456789abcdef0123456789ab"
yanked = false
nonfree = "x"

['1.1.0']
git-tree-sha1 = 'abcdefabcdef0123456789abcdef0123456789ab'
yanked = true

["1.2.0"]
yanked = true

["v-bad"]
git-tree-sha1 = "abcdefabcdef0123456789abcdef0123456789ab"

["1.3.0"]
git-tree-sha1 = "not hex"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0] != (juliaVersion{Version: "1.0.0", Tree: "abcdefabcdef0123456789abcdef0123456789ab"}) || !vs[1].Yanked {
		t.Errorf("parsed %+v", vs)
	}
	for doc, want := range map[string]string{
		"git-tree-sha1 = \"x\"\n":              "outside a version",
		"[\"1.0\"]\n[\"1.0\"]\n":               "again",
		"[1.0.0]\n":                            "header",
		"[\"1.0\"]\ngit-tree-sha1 = [\"x\"]\n": "does not read",
		"[\"1.0\"]\nyanked = truest\n":         "after a boolean",
		"[\"1.0\"]\ngit-tree-sha1 = \"abc\n":   "does not end",
		"[\"1.0\"]\ngit-tree-sha1 = \"\\q\"\n": "does not end",
		"[\"1.0\"] x\n":                        "header",
	} {
		_, err := juliaParseVersionsTOML([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
	// Escapes in basic strings.
	p := &juliaTOMLScanner{s: `"a\"b\\c\u00e9\U0001F600\t"`}
	if s, ok := p.str(); !ok || s != "a\"b\\cé😀\t" {
		t.Errorf("escapes: %q %v", s, ok)
	}
}

func TestJuliaRegistriesList(t *testing.T) {
	got, err := juliaParseRegistries(fixture(t, "julia", "registries.txt"))
	if err != nil || len(got) != 1 || got[0] != juliaGeneral+"/"+juliaHashB {
		t.Errorf("recorded list: %v, %v", got, err)
	}
	got, err = juliaParseRegistries([]byte("\n/registry/" + juliaGeneral + "/" + juliaHashA + "\r\n/registry/BAD/" + juliaHashA + "\n/registry/aaaaaaaa-0000-0000-0000-000000000001/" + strings.Repeat("ab", 32) + "\n"))
	if err != nil || len(got) != 2 || got[0] != juliaGeneral+"/"+juliaHashA {
		t.Errorf("list: %v, %v", got, err)
	}
	if got, err := juliaParseRegistries(nil); err != nil || len(got) != 0 {
		t.Errorf("an empty list: %v, %v", got, err)
	}
	for _, c := range []struct{ a, b string }{{"1.10.0", "1.9.0"}, {"1.0.0", "1.0.0-rc1"}, {"1.2.0+1", "1.2.0+0"}, {"0.1.0", "x"}} {
		if juliaCompareVersions(c.a, c.b) <= 0 {
			t.Errorf("%s should come after %s", c.a, c.b)
		}
	}
}
