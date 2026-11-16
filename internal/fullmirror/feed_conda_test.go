package fullmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/conda"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The recorded repodata (testdata/feeds/conda): conda-forge's noarch (served
// as repodata.json.zst, 29.6 MB; 196 MB decompressed) and win-arm64
// repodata.json and current_repodata.json, trimmed to a few packages in both
// sections ("packages" for .tar.bz2, "packages.conda" for .conda), compact
// JSON with sorted keys as published.
const (
	condaNoarchETag     = `"cc735e87c358de7dedc9394b12e864d0"`
	condaNoarchModified = "Mon, 16 Nov 2026 04:48:24 GMT"
	condaWinARMETag     = `"abd58de45adac9f6411dc4d0480e24eb"`
)

// condaTestFeed builds the conda adapter against a fixture server standing in
// for the channel (at /conda-forge).
func condaTestFeed(t *testing.T, opts map[string]string) (*condaFeed, *fixtureServer) {
	t.Helper()
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "conda", srv.URL()+"/conda-forge", nil, opts)).(*condaFeed)
	return f, srv
}

// condaZstd compresses a document as the channel serves its .zst form.
func condaZstd(t testing.TB, data []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(data, nil)
}

// condaView is a batch as the golden files show it, the fixture server's
// address replaced.
func condaView(t *testing.T, b Batch, srv *fixtureServer) batchView {
	t.Helper()
	v := viewBatch(t, b)
	v.Next = bytes.ReplaceAll(v.Next, []byte(srv.URL()), []byte("http://channel.example"))
	return v
}

func TestCondaFeedLocation(t *testing.T) {
	f, err := newCondaFeed(Env{Upstream: "cf", Type: "conda", URL: "https://conda.anaconda.org/conda-forge"})
	if err != nil {
		t.Fatal(err)
	}
	src := f.(*condaFeed).src
	if src.channel.String() != "https://conda.anaconda.org/conda-forge" || src.index != "repodata" ||
		strings.Join(src.subdirs, ",") != "linux-64,linux-aarch64,noarch,osx-64,osx-arm64,win-64" || src.settle != 30*time.Minute {
		t.Errorf("defaults: %s %s %v %v", src.channel, src.index, src.subdirs, src.settle)
	}
	f, err = newCondaFeed(Env{Upstream: "art", Type: "conda", URL: "https://artifactory.internal.example/artifactory/api/conda/conda-remote",
		Options: map[string]string{"url": "https://conda.internal.example/channels/main/", "subdirs": " noarch , linux-64,noarch", "index": "Current"}})
	if err != nil {
		t.Fatal(err)
	}
	src = f.(*condaFeed).src
	if src.channel.String() != "https://conda.internal.example/channels/main" || src.index != "current" || strings.Join(src.subdirs, ",") != "linux-64,noarch" {
		t.Errorf("options: %s %s %v", src.channel, src.index, src.subdirs)
	}
	for v, want := range map[string]time.Duration{"0": 0, "2h": 2 * time.Hour, "168h": 7 * 24 * time.Hour} {
		f, err := newCondaFeed(Env{Upstream: "cf", Type: "conda", URL: "https://conda.anaconda.org/conda-forge", Options: map[string]string{"settle": v}})
		if err != nil || f.(*condaFeed).src.settle != want {
			t.Errorf("settle %q: %v", v, err)
		}
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("linux-a%d", i)
	}
	for _, opts := range []map[string]string{{"subdirs": "plan9-64"}, {"subdirs": "Linux-64"}, {"subdirs": "noarch,,linux-64"}, {"subdirs": "noarch/x"},
		{"subdirs": strings.Join(many, ",")}, {"index": "all"}, {"channel": "x"}, {"url": "ftp://x"}, {"url": "https://u:p@x/c"},
		{"settle": "-1m"}, {"settle": "8d"}, {"settle": "169h"}, {"settle": "soon"}} {
		if err := Check(Env{Upstream: "cf", Type: "conda", URL: "https://conda.anaconda.org/conda-forge", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestCondaBootstrapThenChanges(t *testing.T) {
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "noarch,win-arm64,linux-64", "settle": "0"})
	f.page = 3
	noarch := fixture(t, "conda", "noarch-repodata.json")
	winARM := fixture(t, "conda", "win-arm64-repodata.json")
	// noarch as repodata.json.zst; win-arm64 only as repodata.json (an older
	// channel server); linux-64 not at all.
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(200, condaZstd(t, noarch)).withHeader("ETag", condaNoarchETag).withHeader("Last-Modified", condaNoarchModified)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").reply(http.StatusNotFound, nil)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json").reply(200, winARM).withHeader("ETag", condaWinARMETag)
	srv.on("GET", "/conda-forge/linux-64/repodata.json.zst").reply(http.StatusNotFound, nil)
	srv.on("GET", "/conda-forge/linux-64/repodata.json").reply(http.StatusNotFound, nil)
	ctx := context.Background()
	var batches []batchView
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, condaView(t, b, srv))
		cursor = b.Next
		if !b.More {
			break
		}
		if i > 5 {
			t.Fatal("the listing does not end")
		}
	}
	checkGolden(t, "conda", "bootstrap", batches)
	backend, err := conda.New(conda.Options{Name: f.src.k.env.Upstream, UpstreamURL: f.src.k.env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"requests", "six", "tzdata", "micromamba", "7zip"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "conda", "releases-"+name, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	_, err = f.Releases(ctx, "numpy")
	mustErr(t, err, true, false, "not in the conda index")

	// win-arm64 changes — 7zip 26.07 is published, micromamba 2.9.0 removed —
	// while noarch answers 304 and linux-64 is still absent: noarch's records
	// are copied from the stored copy, not read again.
	f.page = indexPage
	changed := strings.Replace(string(winARM), `"micromamba-2.9.0-0.tar.bz2":`, `"micromamba-2.9.0-0.tar.bz2.gone":`, 1)
	changed = strings.Replace(changed, `"packages.conda":{`, `"packages.conda":{"7zip-26.07-h11ae69d_0.conda":{"build":"h11ae69d_0","build_number":0,"depends":[],"md5":"00000000000000000000000000000000","name":"7zip","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size":1888888,"subdir":"win-arm64","timestamp":1794810000000,"version":"26.07"},`, 1)
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").requireHeader("If-None-Match", condaNoarchETag).requireHeader("If-Modified-Since", condaNoarchModified).reply(http.StatusNotModified, nil)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json").requireHeader("If-None-Match", condaWinARMETag).reply(200, []byte(changed)).withHeader("ETag", `"win-arm64-2"`)
	before := len(srv.requests())
	ch, err := f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "conda", "changes", condaView(t, ch, srv))
	// linux-64 is looked for again; noarch is asked for conditionally; for
	// win-arm64 the .zst is asked for first (it may be back), then the
	// plain document conditionally.
	if got := strings.Join(srv.requests()[before:], " "); got != "GET /conda-forge/linux-64/repodata.json.zst GET /conda-forge/linux-64/repodata.json GET /conda-forge/noarch/repodata.json.zst GET /conda-forge/win-arm64/repodata.json.zst GET /conda-forge/win-arm64/repodata.json" {
		t.Errorf("requests: %s", got)
	}
	if rels, err := f.Releases(ctx, "requests"); err != nil || len(rels) != 5 {
		t.Errorf("the copied subdir's package: %d %v", len(rels), err)
	}
	if rels, err := f.Releases(ctx, "7zip"); err != nil || len(rels) != 3 || rels[2].Version != "26.07" || rels[2].Artifacts[0].Size != 1888888 {
		t.Errorf("the new version: %+v %v", viewReleases(rels), err)
	}
	// Nothing changes: every subdir 304 (or still absent), the cursor stays.
	srv.on("GET", "/conda-forge/win-arm64/repodata.json").requireHeader("If-None-Match", `"win-arm64-2"`).reply(http.StatusNotModified, nil)
	same, err := f.Changes(ctx, ch.Next)
	if err != nil || len(same.Items) != 0 || same.Next != ch.Next {
		t.Errorf("an unchanged channel: %+v %v", same, err)
	}
	// A state the source cannot read is no state: everything is read again,
	// and the difference from the stored copy is empty.
	var c indexCursor
	if err := decodeCursor(ch.Next, f.format(), &c); err != nil {
		t.Fatal(err)
	}
	c.State = []byte(`{"url":7}`)
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(200, condaZstd(t, noarch)).withHeader("ETag", condaNoarchETag)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json").reply(200, []byte(changed)).withHeader("ETag", `"win-arm64-2"`)
	again, err := f.Changes(ctx, encodeCursor(&c))
	if err != nil || len(again.Items) != 0 {
		t.Errorf("an unreadable state: %+v %v", again, err)
	}
}

func TestCondaCurrentRepodata(t *testing.T) {
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "win-arm64", "index": "current"})
	srv.on("GET", "/conda-forge/win-arm64/current_repodata.json.zst").reply(200, condaZstd(t, fixture(t, "conda", "win-arm64-current_repodata.json")))
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[7zip micromamba]" {
		t.Fatalf("%v %v", names(b.Items), err)
	}
	rels, err := f.Releases(ctx, "micromamba")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "conda", "releases-current-micromamba", viewReleases(rels))
}

// condaDoc is a repodata document with the given package records.
func condaDoc(info string, packages, conda map[string]string) string {
	section := func(m map[string]string) string {
		var parts []string
		for k, v := range m {
			key, _ := json.Marshal(k)
			parts = append(parts, string(key)+":"+v)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return `{"info":` + info + `,"packages":` + section(packages) + `,"packages.conda":` + section(conda) + `,"removed":[],"repodata_version":1}`
}

func TestCondaMalformedAndRefused(t *testing.T) {
	ctx := context.Background()
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "noarch", "settle": "0"})
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(http.StatusNotFound, nil)
	for name, tc := range map[string]struct{ body, want string }{
		"garbage":      {"<html>rate limited</html>", "not a repodata"},
		"array":        {`[1,2]`, "not a repodata"},
		"section":      {`{"packages":[1,2]}`, "is not an object"},
		"trailing":     {`{"packages":{}} {"x":1}`, "after the document"},
		"truncated":    {`{"packages":{"a-1-0.tar.bz2":{"name":"a"`, "not a repodata"},
		"key":          {`{"packages":{"a-1-0.tar.bz2" 1}}`, "not a repodata"},
		"foreign base": {`{"info":{"subdir":"noarch","base_url":"https://elsewhere.example/files/"},"packages":{},"repodata_version":2}`, "base_url"},
	} {
		srv.on("GET", "/conda-forge/noarch/repodata.json").reply(200, []byte(tc.body))
		_, err := f.Bootstrap(ctx, "")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, true, false, tc.want)
	}
	// A base_url beside the repodata, or one in a version-1 document (which
	// clients ignore), is fine.
	for _, doc := range []string{
		`{"info":{"subdir":"noarch","base_url":"./"},"packages":{"ok-1.0-0.tar.bz2":{"name":"ok","version":"1.0"}},"repodata_version":2}`,
		`{"info":{"subdir":"noarch","base_url":"https://elsewhere.example/"},"packages":{"ok-1.0-0.tar.bz2":{"name":"ok","version":"1.0"}},"repodata_version":1}`,
	} {
		srv.on("GET", "/conda-forge/noarch/repodata.json").reply(200, []byte(doc))
		if b, err := f.Bootstrap(ctx, ""); err != nil || fmt.Sprint(names(b.Items)) != "[ok]" {
			t.Errorf("%s: %v %v", doc, names(b.Items), err)
		}
	}
	// Records the backend would not serve as the package they name are left
	// out; the rest of the subdir is read.
	doc := condaDoc(`{"subdir":"noarch"}`, map[string]string{
		"good-1.0-py_0.tar.bz2":       `{"name":"good","version":"1.0","size":"2048","timestamp":1600000000,"sha256":"` + strings.Repeat("A", 64) + `"}`,
		"good-1.1-py_0.conda":         `{"name":"good","version":"1.1"}`,
		"other-1.0-0.tar.bz2":         `{"name":"mismatch","version":"1.0"}`,
		"vers-2.0-0.tar.bz2":          `{"name":"vers","version":"3.0"}`,
		"sub/dir-1.0-0.tar.bz2":       `{"name":"sub/dir","version":"1.0"}`,
		"noext-1.0-0":                 `{"name":"noext","version":"1.0"}`,
		"nameless-1.0-0.tar.bz2":      `{"version":"1.0"}`,
		"notobj-1.0-0.tar.bz2":        `"a string"`,
		"nullrec-1.0-0.tar.bz2":       `null`,
		"oddsize-1.0-0.tar.bz2":       `{"name":"oddsize","version":"1.0","size":"big","timestamp":[1],"md5":"` + strings.Repeat("b", 32) + `"}`,
		"..-1.0-0.tar.bz2":            `{"name":"..","version":"1.0"}`,
		"spaced name-1.0-0.tar.bz2":   `{"name":"spaced name","version":"1.0"}`,
		"control\u0001-1.0-0.tar.bz2": `{"name":"control\u0001","version":"1.0"}`,
	}, map[string]string{
		"good-1.2-py_0.conda":   `{"name":"good","version":"1.2","size":4096,"timestamp":1700000000000}`,
		"wrong-1.0-0.tar.bz2":   `{"name":"wrong","version":"1.0"}`,
		"neg-1.0-0.conda":       `{"name":"neg","version":"1.0","size":-5,"timestamp":-1}`,
		"hugetime-1.0-0.conda":  `{"name":"hugetime","version":"1.0","timestamp":1e300}`,
		"floattime-1.0-0.conda": `{"name":"floattime","version":"1.0","timestamp":1.6000000005e12}`,
	})
	srv.on("GET", "/conda-forge/noarch/repodata.json").reply(200, []byte(doc))
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b.Items)); got != "[floattime good hugetime neg oddsize]" {
		t.Errorf("packages kept: %s", got)
	}
	rels, err := f.Releases(ctx, "good")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "conda", "releases-validated-good", viewReleases(rels))
	for name, want := range map[string]string{"oddsize": "", "neg": "", "hugetime": "", "floattime": "2020-09-13T12:26:40Z"} {
		rels, err := f.Releases(ctx, name)
		if err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 1 || rels[0].Artifacts[0].Size != 0 {
			t.Errorf("%s: %+v %v", name, rels, err)
			continue
		}
		got := ""
		if !rels[0].Published.IsZero() {
			got = rels[0].Published.UTC().Format(time.RFC3339)
		}
		if got != want {
			t.Errorf("%s: published %q, want %q", name, got, want)
		}
	}
	// A channel serving none of the subdirs, and what the channel answers.
	srv.on("GET", "/conda-forge/noarch/repodata.json").reply(http.StatusNotFound, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "serves no repodata.json")
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "60")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != time.Minute || IsPermanent(err) {
		t.Errorf("a 503: %v", err)
	}
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(http.StatusBadGateway, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(200, []byte("\x28\xb5\x2f\xfd broken zstd"))
	_, err = f.Bootstrap(ctx, "")
	if err == nil {
		t.Errorf("a broken zstd stream was read")
	}
}

// condaGenerator streams a synthetic repodata document of n records without
// holding it.
type condaGenerator struct {
	n, i int
	buf  bytes.Buffer
	done bool
}

func (g *condaGenerator) Read(p []byte) (int, error) {
	for g.buf.Len() < len(p) && !g.done {
		switch {
		case g.i == 0:
			g.buf.WriteString(`{"info":{"subdir":"linux-64"},"packages":{},"packages.conda":{`)
		case g.i > g.n:
			g.buf.WriteString(`},"removed":[],"repodata_version":1}`)
			g.done = true
			continue
		}
		if g.i > 0 {
			if g.i > 1 {
				g.buf.WriteByte(',')
			}
			k := g.i - 1
			name := fmt.Sprintf("package-%06d", k/5)
			fmt.Fprintf(&g.buf, `"%s-%d.%d.%d-py312h%07x_%d.conda":{"build":"py312h%07x_%d","build_number":%d,"constrains":["other >=1.0"],"depends":["libgcc >=13","python >=3.12,<3.13.0a0","python_abi 3.12.* *_cp312","numpy >=1.26.4,<2.0a0"],"license":"BSD-3-Clause","md5":"%032x","name":"%s","sha256":"%064x","size":%d,"subdir":"linux-64","timestamp":%d,"version":"%d.%d.%d"}`,
				name, k%5, k%3, k%7, k, k%4, k, k%4, k%4, k, name, k, 1000+k, 1700000000000+int64(k), k%5, k%3, k%7)
		}
		g.i++
	}
	n, _ := g.buf.Read(p)
	if n == 0 && g.done {
		return 0, io.EOF
	}
	return n, nil
}

// A large subdir is read in bounded memory.
func TestCondaLargeRepodataInBoundedMemory(t *testing.T) {
	n := 150_000
	if raceEnabled || testing.Short() {
		n = 5_000
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/c/linux-64/repodata.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(w, &condaGenerator{n: n})
	}))
	t.Cleanup(srv.Close)
	f := mustFeed(t, testEnv(t, "conda", srv.URL+"/c", nil, map[string]string{"subdirs": "linux-64"})).(*condaFeed)
	var b Batch
	var err error
	start := time.Now()
	peak := sampleHeap(t, func() { b, err = f.Bootstrap(context.Background(), "") })
	if err != nil {
		t.Fatal(err)
	}
	h, _ := f.current()
	t.Logf("a subdir of %d package files (about %d MB of JSON): read in %v, peak heap %d MiB", n, n*480>>20, time.Since(start), peak>>20)
	if h.Records != n || h.Names != (n+4)/5 || len(b.Items) == 0 {
		t.Errorf("%d records of %d packages", h.Records, h.Names)
	}
	if raceEnabled {
		return
	}
	const ceiling = 96 << 20
	if peak > ceiling {
		t.Errorf("reading the subdir held %d MiB of heap; the bound is %d MiB", peak>>20, ceiling>>20)
	}
}

func TestCondaVersionOrder(t *testing.T) {
	// conda's own documented order (conda.models.version), where "==" pairs
	// are equal to conda and ordered here by their text.
	ordered := []string{"0.4", "0.4.0", "0.4.1.RC", "0.4.1.rc", "0.4.1", "0.5a1", "0.5b3", "0.5C1", "0.5", "0.9.6", "0.960923", "1.0", "1.1dev1", "1.1_", "1.1a1",
		"1.1.0dev1", "1.1.dev1", "1.1.a1", "1.1.0rc1", "1.1", "1.1.0", "1.1.0post1", "1.1.post1", "1.1post1", "1996.07.12", "1!0.4.1", "1!3.1.1.6", "2!0.4.1"}
	for i := range ordered {
		for j := range ordered {
			c := condaCompareVersions(ordered[i], ordered[j])
			if (i < j && c >= 0) || (i > j && c <= 0) || (i == j && c != 0) {
				t.Errorf("compare(%s, %s) = %d", ordered[i], ordered[j], c)
			}
		}
	}
	for _, bad := range []string{"", "1..2", "1.2+", "+1", "1!2!3", "a!1", "1 2", "1.0+a+b"} {
		if _, ok := condaParseVersion(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if condaCompareVersions("1.0-1", "1.0_2") >= 0 || condaCompareVersions("1.0-1", "1.0.1") >= 0 {
		t.Errorf("a dash stands for an underscore")
	}
	if condaCompareVersions("2023.10.11123456789123456789", "2023.10.11123456789123456788") <= 0 {
		t.Errorf("long numbers compare by value")
	}
}

// condaTestFile is a package file of a test channel's noarch subdir: its
// repodata key and record, and its bytes.
type condaTestFile struct {
	filename, record string
	body             []byte
}

// condaTestPackage makes a .conda file built at built.
func condaTestPackage(name, version string, built time.Time) condaTestFile {
	body := []byte("the bytes of " + name + " " + version)
	sum := sha256.Sum256(body)
	return condaTestFile{
		filename: name + "-" + version + "-pyhd8ed1ab_0.conda",
		record: fmt.Sprintf(`{"build":"pyhd8ed1ab_0","build_number":0,"depends":["python >=3.9"],"license":"MIT","name":%q,"noarch":"python","sha256":"%x","size":%d,"subdir":"noarch","timestamp":%d,"version":%q}`,
			name, sum, len(body), built.UnixMilli(), version),
		body: body,
	}
}

// condaTestRepodata is a noarch repodata listing files.
func condaTestRepodata(files ...condaTestFile) []byte {
	m := map[string]string{}
	for _, f := range files {
		m[f.filename] = f.record
	}
	return []byte(condaDoc(`{"subdir":"noarch"}`, nil, m))
}

// condaBackendFetch fetches a package through the real backend, reading it
// whole, and returns how the backend verified it and what reading it gave.
func condaBackendFetch(t *testing.T, backend *conda.Backend, path string) (string, error) {
	t.Helper()
	ctx := context.Background()
	res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	fr, err := backend.Fetch(ctx, res)
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Content.Close()
	_, err = io.Copy(io.Discard, fr.Content)
	return res.Metadata[conda.MetaChecksumVerified], err
}

// A package file is reported once it has been listed for the settle period
// (30 minutes by default), on the channel's clock, counted from the poll that
// first saw it — conda's timestamp is when a package was built, hours before
// it may be indexed. Until then the CDN may hand the backend a plain
// repodata.json that predates the file, and the backend would serve the file
// unverified.
func TestCondaSettleHoldsNewFiles(t *testing.T) {
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "noarch"})
	t0 := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	clock := t0
	f.src.now = func() time.Time { return clock }
	date := func() string { return clock.Format(http.TimeFormat) }
	old := condaTestPackage("old", "1.0", t0.Add(-72*time.Hour))
	// fresh was built two hours ago and indexed a minute ago.
	fresh := condaTestPackage("fresh", "1.0", t0.Add(-2*time.Hour))
	newer := condaTestPackage("newer", "2.0", t0.Add(-3*time.Hour))
	const zst, plain = "/conda-forge/noarch/repodata.json.zst", "/conda-forge/noarch/repodata.json"
	for _, file := range []condaTestFile{old, fresh, newer} {
		srv.on("GET", "/conda-forge/noarch/"+file.filename).reply(200, file.body)
	}
	// The CDN's plain repodata.json still predates fresh.
	srv.on("GET", plain).reply(200, condaTestRepodata(old))
	srv.on("GET", zst).reply(200, condaZstd(t, condaTestRepodata(old, fresh))).once().
		withHeader("ETag", `"z0"`).withHeader("Last-Modified", t0.Add(-time.Minute).Format(http.TimeFormat)).withHeader("Date", date())
	backend, err := conda.New(conda.Options{Name: f.src.k.env.Upstream, UpstreamURL: f.src.k.env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[old]" || b.More {
		t.Fatalf("the first read: %v %v", names(b.Items), err)
	}
	_, err = f.Releases(ctx, "fresh")
	mustErr(t, err, true, false, "not in the conda index")
	// What the mirror would have fetched: the backend finds no digest for
	// fresh in the plain repodata.json, and serves it unverified.
	if got, err := condaBackendFetch(t, backend, "/noarch/"+fresh.filename); got != "none" || err != nil {
		t.Fatalf("the premise: the backend verified fresh (%q, %v) against a repodata.json that does not list it", got, err)
	}

	// Ten minutes on: the poll is conditional, answered 304.
	clock = t0.Add(10 * time.Minute)
	srv.on("GET", zst).requireHeader("If-None-Match", `"z0"`).reply(http.StatusNotModified, nil).once().withHeader("Date", date())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 {
		t.Fatalf("ten minutes on: %+v %v", ch, err)
	}
	// Twenty minutes on, newer is published (built three hours ago): first
	// seen now. fresh has not settled yet.
	clock = t0.Add(20 * time.Minute)
	srv.on("GET", zst).requireHeader("If-None-Match", `"z0"`).reply(200, condaZstd(t, condaTestRepodata(old, fresh, newer))).once().
		withHeader("ETag", `"z1"`).withHeader("Last-Modified", clock.Add(-time.Minute).Format(http.TimeFormat)).withHeader("Date", date())
	ch, err = f.Changes(ctx, ch.Next)
	if err != nil || len(ch.Items) != 0 {
		t.Fatalf("twenty minutes on: %+v %v", ch, err)
	}
	// Thirty minutes on, fresh has settled (listed since t0 - 1m): the
	// document is read again, unconditionally, and fresh is reported. The
	// plain repodata.json has caught up meanwhile: the backend verifies it.
	clock = t0.Add(30 * time.Minute)
	srv.on("GET", zst).requireHeader("If-None-Match", "").reply(200, condaZstd(t, condaTestRepodata(old, fresh, newer))).once().
		withHeader("ETag", `"z1"`).withHeader("Date", date())
	srv.on("GET", plain).reply(200, condaTestRepodata(old, fresh, newer))
	ch, err = f.Changes(ctx, ch.Next)
	if err != nil || fmt.Sprint(ch.Items) != "[fresh]" {
		t.Fatalf("thirty minutes on: %+v %v", ch, err)
	}
	rels, err := f.Releases(ctx, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	expectServed(t, backend, rels, func(Release, Artifact) (string, string) { return "fresh", "1.0" })
	if got, err := condaBackendFetch(t, backend, rels[0].Artifacts[0].Path); got != "sha256" || err != nil {
		t.Errorf("fresh, once reported: verified %q, %v", got, err)
	}
	// newer settles thirty minutes after it was first seen; the poll before
	// that is conditional again.
	clock = t0.Add(40 * time.Minute)
	srv.on("GET", zst).requireHeader("If-None-Match", `"z1"`).reply(http.StatusNotModified, nil).once().withHeader("Date", date())
	if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
		t.Fatalf("forty minutes on: %+v %v", ch, err)
	}
	clock = t0.Add(51 * time.Minute)
	srv.on("GET", zst).requireHeader("If-None-Match", "").reply(200, condaZstd(t, condaTestRepodata(old, fresh, newer))).once().
		withHeader("ETag", `"z1"`).withHeader("Date", date())
	if ch, err = f.Changes(ctx, ch.Next); err != nil || fmt.Sprint(ch.Items) != "[newer]" {
		t.Fatalf("fifty-one minutes on: %+v %v", ch, err)
	}
	clock = t0.Add(55 * time.Minute)
	srv.on("GET", zst).requireHeader("If-None-Match", `"z1"`).reply(http.StatusNotModified, nil).once().withHeader("Date", date())
	if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
		t.Fatalf("nothing held: %+v %v", ch, err)
	}
}

// S3 (and CloudFront in front of it) answers 403 for a key that does not
// exist: a refused document is passed over like a missing one. A subdir none
// of whose documents answers is not served when another subdir is; the
// channel is held only when no subdir answers and one was refused.
func TestCondaRefusedDocuments(t *testing.T) {
	ctx := context.Background()
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "noarch,win-arm64,linux-64", "settle": "0"})
	denied := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	// noarch has no .zst, win-arm64 both documents, linux-64 none: the
	// store refuses whatever it does not hold.
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(http.StatusForbidden, denied)
	srv.on("GET", "/conda-forge/noarch/repodata.json").reply(200, fixture(t, "conda", "noarch-repodata.json")).withHeader("ETag", `"n1"`)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").reply(200, condaZstd(t, fixture(t, "conda", "win-arm64-repodata.json"))).withHeader("ETag", `"w1"`)
	srv.on("GET", "/conda-forge/linux-64/repodata.json.zst").reply(http.StatusForbidden, denied)
	srv.on("GET", "/conda-forge/linux-64/repodata.json").reply(http.StatusForbidden, denied)
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[7zip micromamba requests six tzdata]" {
		t.Fatalf("a channel on S3: %v %v", names(b.Items), err)
	}
	// The next poll asks for noarch's .zst again (refused still), then for
	// its plain document conditionally; nothing is asked for twice.
	srv.on("GET", "/conda-forge/noarch/repodata.json").requireHeader("If-None-Match", `"n1"`).reply(http.StatusNotModified, nil)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").requireHeader("If-None-Match", `"w1"`).reply(http.StatusNotModified, nil)
	before := len(srv.requests())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 || ch.Next != b.Next {
		t.Fatalf("an unchanged channel on S3: %+v %v", ch, err)
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET /conda-forge/linux-64/repodata.json.zst GET /conda-forge/linux-64/repodata.json GET /conda-forge/noarch/repodata.json.zst GET /conda-forge/noarch/repodata.json GET /conda-forge/win-arm64/repodata.json.zst" {
		t.Errorf("requests: %s", got)
	}
	// Everything refused (a token expired): the channel is held, at the
	// first read and later, not taken for one that serves nothing.
	for _, p := range []string{"noarch/repodata.json.zst", "noarch/repodata.json", "win-arm64/repodata.json.zst", "win-arm64/repodata.json"} {
		srv.on("GET", "/conda-forge/"+p).reply(http.StatusUnauthorized, nil)
	}
	_, err = f.Changes(ctx, ch.Next)
	if d, ok := RetryAfterOf(err); !ok || d != holdAfterRefusal || IsPermanent(err) {
		t.Errorf("every document refused: %v", err)
	}
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != holdAfterRefusal || IsPermanent(err) {
		t.Errorf("every document refused at the first read: %v", err)
	}
	// Some not found, the rest refused: held as well.
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(http.StatusNotFound, nil)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json").reply(http.StatusNotFound, nil)
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != holdAfterRefusal || IsPermanent(err) {
		t.Errorf("none served, some refused: %v", err)
	}
	// None found: not a channel.
	for _, p := range []string{"noarch/repodata.json", "win-arm64/repodata.json.zst", "linux-64/repodata.json.zst", "linux-64/repodata.json"} {
		srv.on("GET", "/conda-forge/"+p).reply(http.StatusNotFound, nil)
	}
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "serves no repodata.json")
}

// A subdir that was served and stops answering (a CDN's hiccup) keeps its
// packages for a few polls: none is reported deleted, nor reported again when
// it is back. Gone for condaMissingPolls polls in a row, its packages are
// reported deleted.
func TestCondaSubdirGoneForAWhileIsKept(t *testing.T) {
	ctx := context.Background()
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "noarch,win-arm64", "settle": "0"})
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(200, condaZstd(t, fixture(t, "conda", "noarch-repodata.json"))).withHeader("ETag", `"n1"`)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").reply(200, condaZstd(t, fixture(t, "conda", "win-arm64-repodata.json"))).withHeader("ETag", `"w1"`)
	b, err := f.Bootstrap(ctx, "")
	if err != nil || b.More {
		t.Fatal(err, b.More)
	}
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").requireHeader("If-None-Match", `"n1"`).reply(http.StatusNotModified, nil)
	// win-arm64 answers 404, in both forms, for one poll.
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").reply(http.StatusNotFound, nil)
	srv.on("GET", "/conda-forge/win-arm64/repodata.json").reply(http.StatusNotFound, nil)
	before := len(srv.requests())
	gone, err := f.Changes(ctx, b.Next)
	if err != nil || len(gone.Items) != 0 {
		t.Fatalf("one 404: %+v %v", gone, err)
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET /conda-forge/noarch/repodata.json.zst GET /conda-forge/win-arm64/repodata.json.zst GET /conda-forge/win-arm64/repodata.json" {
		t.Errorf("requests: %s", got)
	}
	if rels, err := f.Releases(ctx, "7zip"); err != nil || len(rels) != 2 {
		t.Errorf("the subdir's packages while it is missing: %+v %v", viewReleases(rels), err)
	}
	// It is back as it was.
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").requireHeader("If-None-Match", `"w1"`).reply(http.StatusNotModified, nil)
	back, err := f.Changes(ctx, gone.Next)
	if err != nil || len(back.Items) != 0 {
		t.Fatalf("back: %+v %v", back, err)
	}
	// Gone for good (S3 refusing the .zst, the plain document not found):
	// kept at the first polls, its packages deleted at the third.
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").reply(http.StatusForbidden, nil)
	cursor := back.Next
	for i := 1; i <= condaMissingPolls; i++ {
		ch, err := f.Changes(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		want := "[]"
		if i == condaMissingPolls {
			want = "[7zip micromamba]"
		}
		var deleted []string
		for _, c := range ch.Items {
			if c.Deleted {
				deleted = append(deleted, c.String())
			}
		}
		if got := fmt.Sprint(deleted); got != want || len(deleted) != len(ch.Items) {
			t.Errorf("poll %d without the subdir: %v, deleted %s, want %s", i, ch.Items, got, want)
		}
		cursor = ch.Next
	}
	_, err = f.Releases(ctx, "7zip")
	mustErr(t, err, true, false, "not in the conda index")
}

// After a 404 of repodata.json.zst (a CDN's hiccup) the feed reads
// repodata.json — eight times the bytes — only until the .zst answers again:
// it is asked for at every poll. A .zst that does not answer otherwise (a 5xx)
// does not fail the poll: the plain document is read as before.
func TestCondaAsksForTheCompressedRepodataAgain(t *testing.T) {
	ctx := context.Background()
	f, srv := condaTestFeed(t, map[string]string{"subdirs": "noarch", "settle": "0"})
	noarch := fixture(t, "conda", "noarch-repodata.json")
	const zst, plain = "/conda-forge/noarch/repodata.json.zst", "/conda-forge/noarch/repodata.json"
	srv.on("GET", zst).reply(http.StatusNotFound, nil)
	srv.on("GET", plain).reply(200, noarch).withHeader("ETag", `"plain-1"`)
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.on("GET", plain).requireHeader("If-None-Match", `"plain-1"`).reply(http.StatusNotModified, nil)
	before := len(srv.requests())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 {
		t.Fatalf("still no .zst: %+v %v", ch, err)
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET "+zst+" GET "+plain {
		t.Errorf("requests: %s", got)
	}
	srv.on("GET", zst).reply(http.StatusServiceUnavailable, nil)
	if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
		t.Fatalf("a .zst answering 503: %+v %v", ch, err)
	}
	// It is back: read once whole, then asked for conditionally; the plain
	// document is not read again.
	srv.on("GET", zst).reply(200, condaZstd(t, noarch)).withHeader("ETag", `"zst-1"`)
	srv.on("GET", zst).requireHeader("If-None-Match", `"zst-1"`).reply(http.StatusNotModified, nil)
	before = len(srv.requests())
	for i := 0; i < 3; i++ {
		if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
			t.Fatalf("poll %d with the .zst back: %+v %v", i, ch, err)
		}
	}
	if got := strings.Join(srv.requests()[before:], " "); got != "GET "+zst+" GET "+zst+" GET "+zst {
		t.Errorf("requests: %s", got)
	}
}

// condaRepeat streams n copies of a byte.
type condaRepeat struct {
	c byte
	n int
}

func (r *condaRepeat) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	for i := range p {
		p[i] = r.c
	}
	r.n -= len(p)
	return len(p), nil
}

// A record is decoded whole: one past condaMaxRecord (a 64 MiB license here)
// fails the document permanently instead of being held, as does a skipped
// value nested deeper than condaMaxDepth. A record just under the bound is
// read.
func TestCondaOversizedRecordInBoundedMemory(t *testing.T) {
	big := 64 << 20
	if raceEnabled || testing.Short() {
		big = 8 << 20
	}
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/c/noarch/repodata.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(w, body.Load().(func() io.Reader)())
	}))
	t.Cleanup(srv.Close)
	f := mustFeed(t, testEnv(t, "conda", srv.URL+"/c", nil, map[string]string{"subdirs": "noarch", "settle": "0"})).(*condaFeed)
	license := func(n int) func() io.Reader {
		return func() io.Reader {
			return io.MultiReader(strings.NewReader(`{"info":{"subdir":"noarch"},"packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0","license":"`),
				&condaRepeat{c: 'x', n: n}, strings.NewReader(`"},"b-1.0-0.tar.bz2":{"name":"b","version":"1.0"}},"repodata_version":1}`))
		}
	}
	ctx := context.Background()
	body.Store(license(big))
	var err error
	peak := sampleHeap(t, func() { _, err = f.Bootstrap(ctx, "") })
	mustErr(t, err, true, false, "larger than")
	t.Logf("a record of %d MiB: %v; peak heap %d MiB", big>>20, err, peak>>20)
	if !raceEnabled && peak > 24<<20 {
		t.Errorf("refusing a record of %d MiB held %d MiB of heap", big>>20, peak>>20)
	}
	body.Store(license(condaMaxRecord - 4096))
	if b, err := f.Bootstrap(ctx, ""); err != nil || fmt.Sprint(names(b.Items)) != "[a b]" {
		t.Errorf("a record just under the bound: %v %v", names(b.Items), err)
	}
	nested := func(depth int) func() io.Reader {
		return func() io.Reader {
			return strings.NewReader(`{"removed":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `,"packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0"}}}`)
		}
	}
	body.Store(nested(condaMaxDepth + 1))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "nested deeper")
	body.Store(nested(condaMaxDepth))
	if b, err := f.Bootstrap(ctx, ""); err != nil || fmt.Sprint(names(b.Items)) != "[a]" {
		t.Errorf("a value nested %d deep: %v %v", condaMaxDepth, names(b.Items), err)
	}
}

// A connection cut in the middle of a repodata is the connection's failure —
// the poll is retried — not a document that is not one.
func TestCondaCutConnectionIsRetried(t *testing.T) {
	noarch := fixture(t, "conda", "noarch-repodata.json")
	for name, tc := range map[string]struct {
		path string
		body []byte
	}{
		"zst":   {"/c/noarch/repodata.json.zst", condaZstd(t, noarch)},
		"plain": {"/c/noarch/repodata.json", noarch},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != tc.path {
				http.NotFound(w, r)
				return
			}
			// The whole document announced, half of it sent.
			w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tc.body[:len(tc.body)/2])
		}))
		f := mustFeed(t, testEnv(t, "conda", srv.URL+"/c", nil, map[string]string{"subdirs": "noarch", "settle": "0"})).(*condaFeed)
		_, err := f.Bootstrap(context.Background(), "")
		srv.Close()
		if err == nil || IsPermanent(err) || errors.Is(err, ErrCursorInvalid) || strings.Contains(err.Error(), "not a repodata") {
			t.Errorf("%s: a cut connection: %v", name, err)
		}
	}
}

// Each subdir followed keeps a table of when the feed first saw its files
// (8 bytes a file); the tables of subdirs no longer followed are removed.
func TestCondaFirstSeenTablesFollowTheSubdirs(t *testing.T) {
	srv := newFixtureServer(t)
	srv.on("GET", "/conda-forge/noarch/repodata.json.zst").reply(200, condaZstd(t, fixture(t, "conda", "noarch-repodata.json")))
	srv.on("GET", "/conda-forge/win-arm64/repodata.json.zst").reply(200, condaZstd(t, fixture(t, "conda", "win-arm64-repodata.json")))
	env := testEnv(t, "conda", srv.URL()+"/conda-forge", nil, map[string]string{"subdirs": "noarch,win-arm64"})
	tables := func() string {
		m, _ := filepath.Glob(filepath.Join(env.Dir, "conda-firstseen-*"))
		for i := range m {
			m[i] = filepath.Base(m[i])
		}
		return fmt.Sprint(m)
	}
	if _, err := mustFeed(t, env).Bootstrap(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got := tables(); got != "[conda-firstseen-noarch.bin conda-firstseen-win-arm64.bin]" {
		t.Errorf("tables: %s", got)
	}
	env.Options = map[string]string{"subdirs": "noarch"}
	if _, err := mustFeed(t, env).Bootstrap(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got := tables(); got != "[conda-firstseen-noarch.bin]" {
		t.Errorf("tables after win-arm64 is no longer followed: %s", got)
	}
}
