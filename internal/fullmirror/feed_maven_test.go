package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/maven"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The maven fixtures are real: the properties files and the full indexes of
// repo.clojars.org (Clojars' S3 bucket) and repo.jenkins-ci.org (an
// Artifactory instance) and the properties file of repository.apache.org (a
// Nexus 2), recorded on 2026-11-16 — Clojars' full index a run earlier than
// its properties (its header states 2026-11-15 12:08:52, the properties
// 2026-11-16 04:09:18, Clojars packing a new chain every run), so a copy read
// from that pair is marked partial, as one from a stale copy at a CDN is;
// the full indexes trimmed to a few of their documents, byte for byte (only
// the two group lists are shortened);
// and a real incremental chunk, Clojars' nexus-maven-repository-index.1.gz,
// still published from an earlier chain of 2024. Chains and chunks the tests
// need beyond those are written in the same format by mavenTestIndex.

const (
	mavenIndexPath  = "/.index/nexus-maven-repository-index.gz"
	mavenPropsPath  = "/.index/nexus-maven-repository-index.properties"
	mavenClojarsTag = `"ca8b205816946c982dfd0ac1538ae8e0"`
)

// mavenTestFeed builds the maven adapter against a fixture server standing
// in for the repository.
func mavenTestFeed(t *testing.T, opts map[string]string) (*mavenFeed, *fixtureServer) {
	t.Helper()
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "maven", srv.URL(), newFakeReads(), opts)).(*mavenFeed)
	return f, srv
}

// mavenTestBackend is the backend the adapter's paths are checked against.
func mavenTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := maven.New(maven.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mavenTestIndex writes an index data file in Maven Indexer's format: the
// version byte, the time stamp, then each document's field count and fields
// (flags, writeUTF name, int-length value), gzip-compressed.
func mavenTestIndex(ts int64, docs ...[][2]string) []byte {
	var raw bytes.Buffer
	raw.WriteByte(1)
	_ = binary.Write(&raw, binary.BigEndian, ts)
	for _, d := range docs {
		_ = binary.Write(&raw, binary.BigEndian, int32(len(d)))
		for _, f := range d {
			raw.WriteByte(4)
			_ = binary.Write(&raw, binary.BigEndian, uint16(len(f[0])))
			raw.WriteString(f[0])
			_ = binary.Write(&raw, binary.BigEndian, int32(len(f[1])))
			raw.WriteString(f[1])
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	return gz.Bytes()
}

// mavenDocOf is an artifact document as Maven Indexer writes one (u, m, i
// and, when given, the SHA-1).
func mavenDocOf(uinfo, info, sha1 string) [][2]string {
	d := [][2]string{{"u", uinfo}, {"m", "1794744429803"}, {"i", info}, {"n", "name"}}
	if sha1 != "" {
		d = append(d, [2]string{"1", sha1})
	}
	return d
}

// mavenDeletion is a deletion marker.
func mavenDeletion(uinfo string) [][2]string {
	return [][2]string{{"del", uinfo}, {"m", "1794744439803"}}
}

// mavenTestProps is a properties file of a chain with chunks. Its time stamp
// is the one the tests' full indexes state in their headers (Clojars' of
// 2026-11-15, 1794744532150): a packing run writes both alike.
func mavenTestProps(chain string, last int, chunks ...int) []byte {
	var b strings.Builder
	b.WriteString("#Sun Nov 15 12:08:52 UTC 2026\n")
	fmt.Fprintf(&b, "nexus.index.chain-id=%s\nnexus.index.id=test\nnexus.index.last-incremental=%d\nnexus.index.timestamp=20261115120852.150 +0000\n", chain, last)
	for i, c := range chunks {
		fmt.Fprintf(&b, "nexus.index.incremental-%d=%d\n", i, c)
	}
	return []byte(b.String())
}

func mavenChunkPath(n int) string {
	return fmt.Sprintf("/.index/nexus-maven-repository-index.%d.gz", n)
}

func TestMavenFeedLocation(t *testing.T) {
	// Maven Central's terms forbid mirroring it: refused at load time, on
	// every name Central is known by, upstream or feed option.
	for _, u := range []string{"https://repo1.maven.org/maven2", "https://repo.maven.apache.org/maven2/", "https://central.maven.org/maven2", "http://repo.maven.org/maven2",
		// Google's copies of Central, and a name with its root's dot.
		"https://maven-central.storage-download.googleapis.com/maven2", "https://maven-central-eu.storage-download.googleapis.com/maven2",
		"https://MAVEN-CENTRAL-ASIA.storage-download.googleapis.com/maven2", "https://repo1.maven.org./maven2", "https://repo1.maven.org:443/maven2"} {
		err := Check(Env{Upstream: "central", Type: "maven", URL: u})
		if err == nil || !strings.Contains(err.Error(), "terms of service forbid mirroring") || !strings.Contains(err.Error(), "docs/full-mirroring.md#maven") {
			t.Errorf("%s: %v", u, err)
		}
	}
	err := Check(Env{Upstream: "nexus", Type: "maven", URL: "https://nexus.example/repository/maven-releases", Options: map[string]string{"url": "https://repo1.maven.org/maven2/.index"}})
	if err == nil || !strings.Contains(err.Error(), "the feed option url https://repo1.maven.org/maven2/.index is Maven Central") {
		t.Errorf("a feed URL on Central: %v", err)
	}
	err = Check(Env{Upstream: "central", Type: "maven", URL: "https://repo1.maven.org/maven2", Options: map[string]string{"url": "https://nexus.example/.index"}})
	if err == nil || !strings.Contains(err.Error(), "upstream https://repo1.maven.org/maven2 is Maven Central") {
		t.Errorf("Central with another index: %v", err)
	}

	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://nexus.example/repository/maven-releases", nil, "https://nexus.example/repository/maven-releases/.index"},
		{"https://repo.clojars.org/", nil, "https://repo.clojars.org/.index"},
		{"https://artifactory.example/artifactory/libs-release", map[string]string{"url": "https://artifactory.example/artifactory/api/maven/index/libs-release/"}, "https://artifactory.example/artifactory/api/maven/index/libs-release"},
	} {
		f, err := newMavenFeed(Env{Upstream: "m", Type: "maven", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*mavenFeed).src.dir.String(); got != tc.want {
			t.Errorf("%s: index directory %s, want %s", tc.url, got, tc.want)
		}
	}
	f, err := newMavenFeed(Env{Upstream: "m", Type: "maven", URL: "https://repo.jenkins-ci.org/releases", Options: map[string]string{"classifiers": " sources, javadoc ,linux-x86_64"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*mavenFeed).src.selection(); got != "javadoc,linux-x86_64,sources" {
		t.Errorf("classifiers %q", got)
	}
	if f, _ := newMavenFeed(Env{Upstream: "m", Type: "maven", URL: "https://repo.jenkins-ci.org/releases", Options: map[string]string{"classifiers": "*"}}); !f.(*mavenFeed).src.all {
		t.Errorf("classifiers * does not mirror every classifier")
	}
	many := make([]string, mavenMaxClassifiers+1)
	for i := range many {
		many[i] = fmt.Sprintf("c%d", i)
	}
	for _, opts := range []map[string]string{{"index": "x"}, {"url": "ftp://nexus.example/.index"}, {"url": "https://u:p@nexus.example/.index"},
		{"url": "https://nexus.example/.index?x=1"}, {"classifiers": "a b"}, {"classifiers": "*,sources"}, {"classifiers": "sources,,javadoc"},
		{"classifiers": "x/y"}, {"classifiers": strings.Join(many, ",")}} {
		if err := Check(Env{Upstream: "m", Type: "maven", URL: "https://nexus.example/repository/r", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
	if err := Check(Env{Upstream: "m", Type: "maven", URL: "ftp://nexus.example/r"}); err == nil {
		t.Errorf("an ftp upstream was accepted")
	}
}

// Maven Central's own index is refused wherever it is served from — Google's
// copies, a redirect, a repository manager republishing its proxy of
// Central — by the index id and chain id its properties state.
func TestMavenRefusesCentralsIndexWherever(t *testing.T) {
	ctx := context.Background()
	for name, props := range map[string][]byte{
		// As maven-central.storage-download.googleapis.com serves it.
		"central's properties": fixture(t, "maven", "central-index.properties"),
		"central's chain":      []byte("nexus.index.id=mirror\nnexus.index.chain-id=1318453614498\nnexus.index.last-incremental=941\n"),
		"a proxy named so":     []byte("nexus.index.id=central\nnexus.index.chain-id=1700000000000\nnexus.index.last-incremental=0\n"),
		"in capitals":          []byte("nexus.index.id=Central\nnexus.index.chain-id=1700000000000\nnexus.index.last-incremental=0\n"),
	} {
		f, srv := mavenTestFeed(t, nil)
		srv.on("GET", mavenPropsPath).reply(200, props)
		_, err := f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, "terms of service forbid mirroring")
		if err != nil && !strings.Contains(err.Error(), "docs/full-mirroring.md#maven") {
			t.Errorf("%s: %v", name, err)
		}
		// And at every later read: a repository that switched to Central's
		// index.
		srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("5", 0))
		srv.on("GET", mavenIndexPath).reply(200, mavenChainFull())
		_, cursor := drainBootstrap(t, f)
		srv.on("GET", mavenPropsPath).reply(200, props)
		_, err = f.Changes(ctx, cursor)
		mustErr(t, err, true, false, "terms of service forbid mirroring")
		for _, r := range srv.requests() {
			if r == "GET "+mavenChunkPath(941) {
				t.Errorf("%s: a chunk of Central's index was read", name)
			}
		}
	}
}

// A chunk the properties list that the repository does not serve, or that is
// not an index (a partial sync of the index directory, a clean-up racing the
// properties), has the full index read instead: it must not stop the feed.
func TestMavenAMissingChunkReadsTheFullIndex(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 0)).withHeader("ETag", `"p0"`)
	srv.on("GET", mavenIndexPath).reply(200, mavenChainFull())
	_, cursor := drainBootstrap(t, f)
	one, _ := mavenChainChunks()
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 2, 2, 1)).withHeader("ETag", `"p2"`)
	srv.on("GET", mavenChunkPath(1)).reply(200, one)
	srv.on("GET", mavenChunkPath(2)).reply(404, nil)
	srv.on("GET", mavenIndexPath).reply(200, mavenTestIndex(1794745000000,
		mavenDocOf("com.example|lib|1.0|NA|jar", "jar|1700000000000|1000|0|0|0|jar", "1111111111111111111111111111111111111111"),
		mavenDocOf("com.example|lib|1.2|NA|jar", "jar|1700000400000|1200|0|0|0|jar", "4444444444444444444444444444444444444444"),
	))
	got, next := drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "com.example:lib@1.1 (deleted),com.example:lib@1.2,com.example:tool (deleted),com.other:gone (deleted)" {
		t.Errorf("Changes = %v", got)
	}
	var c indexCursor
	_ = decodeCursor(next, f.format(), &c)
	var st mavenState
	if err := json.Unmarshal(c.State, &st); err != nil || st.Chain != "100" || st.Last != 2 {
		t.Errorf("state after the full read %s (%v)", c.State, err)
	}
	// The next polls go on from there.
	for poll := 1; poll <= 2; poll++ {
		if _, err := f.Changes(context.Background(), next); err != nil {
			t.Errorf("poll %d: %v", poll, err)
		}
	}
}

// A change of the classifier selection reads the index again, although the
// repository did not change: the stored copy was made with another selection.
func TestMavenClassifierChangeRereadsTheIndex(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 0)).withHeader("ETag", `"p0"`)
	srv.on("GET", mavenIndexPath).reply(200, mavenChainFull())
	_, cursor := drainBootstrap(t, f)
	f2 := mustFeed(t, testEnv(t, "maven", srv.URL(), newFakeReads(), map[string]string{"classifiers": "sources"})).(*mavenFeed)
	f2.indexFeed.files = f.indexFeed.files
	srv.on("GET", mavenPropsPath).requireHeader("If-None-Match", `"p0"`).reply(304, nil)
	got, next := drainChanges(t, f2, cursor)
	if strings.Join(got, ",") != "com.example:tool@2.0" {
		t.Errorf("after classifiers=sources, the repository unchanged: Changes = %v; want tool 2.0 (its sources jar)", got)
	}
	// The same selection again: the conditional read's 304 is unchanged.
	if got, _ := drainChanges(t, f2, next); len(got) != 0 {
		t.Errorf("then: %v", got)
	}
}

// A full index older than the properties that name the chunk the copy is at
// (a repository that rebuilds only its chunks, a stale copy at a CDN) lacks
// the chunks between: no chunk is applied on top of it, the next change is a
// full read.
func TestMavenStaleFullIndexIsNotPatched(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	stale := strings.Replace(string(mavenTestProps("100", 5, 5, 4, 3)), "20261115120852.150", "20261116120000.000", 1)
	srv.on("GET", mavenPropsPath).reply(200, []byte(stale))
	srv.on("GET", mavenIndexPath).reply(200, mavenChainFull()).once()
	_, cursor := drainBootstrap(t, f)
	var c indexCursor
	_ = decodeCursor(cursor, f.format(), &c)
	var st mavenState
	if err := json.Unmarshal(c.State, &st); err != nil || !st.Partial || st.Last != 5 {
		t.Fatalf("state %s (%v)", c.State, err)
	}
	// Nothing new: unchanged, still partial.
	b, err := f.Changes(context.Background(), cursor)
	if err != nil || len(b.Items) != 0 {
		t.Fatalf("unchanged: %+v %v", b, err)
	}
	cursor = b.Next
	// Chunk 6 is listed: the full index is read, not the chunk.
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 6, 6, 5, 4))
	srv.on("GET", mavenIndexPath).reply(200, mavenTestIndex(1794744532150,
		mavenDocOf("com.example|lib|1.0|NA|jar", "jar|1700000000000|1000|0|0|0|jar", "1111111111111111111111111111111111111111"),
	)).once()
	got, next := drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "com.example:lib@1.1 (deleted),com.example:tool (deleted),com.other:gone (deleted)" {
		t.Errorf("Changes = %v", got)
	}
	for _, r := range srv.requests() {
		if strings.Contains(r, ".6.gz") {
			t.Errorf("a chunk was applied to a partial copy: %s", r)
		}
	}
	_ = decodeCursor(next, f.format(), &c)
	var after mavenState
	if err := json.Unmarshal(c.State, &after); err != nil || after.Partial || after.Last != 6 {
		t.Errorf("state after the full read %s (%v)", c.State, err)
	}
}

// Bootstrap reads the full index once and lists its coordinates; Releases
// answers from the stored copy, with paths the real backend serves.
func TestMavenBootstrapReadsTheFullIndex(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	f.page = 3
	srv.on("GET", mavenPropsPath).reply(200, fixture(t, "maven", "clojars-index.properties")).withHeader("ETag", mavenClojarsTag)
	srv.on("GET", mavenIndexPath).reply(200, fixture(t, "maven", "clojars-index.gz")).once()
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
	checkGolden(t, "maven", "bootstrap-clojars", pages)
	var c indexCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil || c.Listing {
		t.Fatalf("final cursor %s (%v)", cursor, err)
	}
	var st mavenState
	// The recorded index is older than the recorded properties: partial.
	if err := json.Unmarshal(c.State, &st); err != nil || st.Chain != "1794802161106" || st.Last != 0 || st.Props.ETag != mavenClojarsTag || !st.Partial {
		t.Errorf("state %s (%v)", c.State, err)
	}

	backend := mavenTestBackend(t, f.src.k.env)
	for _, name := range []string{"readyforzero:borg", "thheller:shadow-cljs", "org.ring-clojure:ring-websocket-protocols", "org.akvo.flow:akvo-flow",
		"puppetlabs.org.jruby:jruby-parent", "umlaut:umlaut", "org.clojars.tcrawley:clojure-maven-plugin", "org.danielsz:system"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "maven", "releases-clojars-"+strings.NewReplacer(":", "-", ".", "-").Replace(name), viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	// A snapshot is revalidated by the backend and never cached: not listed.
	_, err := f.Releases(ctx, "readux-starter:boot-template")
	mustErr(t, err, true, false, "not in the maven index")
	for _, bad := range []string{"borg", "readyforzero:", ":borg", "a:b:c", "a b:c", "../x:y"} {
		_, err := f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a Maven coordinate")
	}

	// Nothing changed: the properties are asked for conditionally and the
	// cursor stays.
	srv.on("GET", mavenPropsPath).requireHeader("If-None-Match", mavenClojarsTag).reply(http.StatusNotModified, nil)
	b, err := f.Changes(ctx, cursor)
	if err != nil || len(b.Items) != 0 || b.Next != cursor {
		t.Errorf("an unchanged index: %+v %v", viewBatch(t, b), err)
	}
	for _, r := range srv.requests() {
		if strings.HasSuffix(r, ".gz") && r != "GET "+mavenIndexPath {
			t.Errorf("unexpected request %s", r)
		}
	}
}

// The Jenkins index (Artifactory) lists a plugin's .hpi and .jar as two main
// artifacts of one release, and many classifiers.
func TestMavenReleasesOfTheJenkinsIndex(t *testing.T) {
	for _, tc := range []struct {
		classifiers string
		golden      string
	}{{"", "releases-jenkins"}, {"sources", "releases-jenkins-sources"}, {"*", "releases-jenkins-all"}} {
		f, srv := mavenTestFeed(t, map[string]string{"classifiers": tc.classifiers})
		srv.on("GET", mavenPropsPath).reply(200, fixture(t, "maven", "jenkins-index.properties"))
		srv.on("GET", mavenIndexPath).reply(200, fixture(t, "maven", "jenkins-index.gz"))
		listed, _ := drainBootstrap(t, f)
		got := map[string][]releaseView{"listed": {{Version: strings.Join(listed, " ")}}}
		backend := mavenTestBackend(t, f.src.k.env)
		for _, name := range listed {
			rels, err := f.Releases(context.Background(), name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got[name] = viewReleases(rels)
			expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
		}
		checkGolden(t, "maven", tc.golden, got)
		// A version spelt with an unresolved property is no path.
		_, err := f.Releases(context.Background(), "org.jenkins-ci.plugins:sauce-ondemand")
		mustErr(t, err, true, false, "not in the maven index")
	}
}

// mavenChain is a repository whose index the tests change: a full index of
// a chain, then chunks.
func mavenChainFull() []byte {
	return mavenTestIndex(1794744532150,
		mavenDocOf("com.example|lib|1.0|NA|jar", "jar|1700000000000|1000|0|0|0|jar", "1111111111111111111111111111111111111111"),
		mavenDocOf("com.example|lib|1.1|NA|pom", "jar|1700000100000|-1|0|0|0|pom", ""),
		mavenDocOf("com.example|tool|2.0|NA|jar", "jar|1700000200000|2000|0|0|0|jar", "2222222222222222222222222222222222222222"),
		mavenDocOf("com.example|tool|2.0|sources|jar", "jar|1700000200000|300|2|2|0|jar", "3333333333333333333333333333333333333333"),
		mavenDocOf("com.other|gone|0.1|NA|pom", "pom|1700000300000|400|0|0|0|pom", ""),
		mavenDeletion("com.example|lib|0.9|NA|jar"),
		[][2]string{{"DESCRIPTOR", "NexusIndex"}, {"IDXINFO", "1.0|test"}},
		[][2]string{{"allGroups", "allGroups"}, {"allGroupsList", "com.example|com.other"}},
	)
}

func mavenChainChunks() (one, two []byte) {
	one = mavenTestIndex(1794744600000,
		mavenDocOf("com.example|lib|1.2|NA|jar", "jar|1700000400000|1200|0|0|0|jar", "4444444444444444444444444444444444444444"),
		mavenDeletion("com.other|gone|0.1|NA|pom"),
	)
	two = mavenTestIndex(1794744700000,
		// lib 1.0's jar republished: the document changes.
		mavenDocOf("com.example|lib|1.0|NA|jar", "jar|1700000500000|1001|0|0|0|jar", "5555555555555555555555555555555555555555"),
		mavenDocOf("com.newer|webapp|1.0|NA|pom", "war|1700000600000|-1|0|0|0|pom", ""),
		// Added and deleted within the run: never there.
		mavenDocOf("com.example|lib|1.3|NA|jar", "jar|1700000700000|1300|0|0|0|jar", ""),
		mavenDeletion("com.example|lib|1.3|NA|jar"),
	)
	return one, two
}

// A chain's chunks are fetched from the one after the copy's and applied to
// the copy: the full index is not read again.
func TestMavenChangesApplyIncrementalChunks(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	ctx := context.Background()
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 0)).withHeader("ETag", `"p0"`)
	srv.on("GET", mavenIndexPath).reply(200, mavenChainFull()).once()
	listed, cursor := drainBootstrap(t, f)
	if strings.Join(listed, ",") != "com.example:lib,com.example:tool,com.other:gone" {
		t.Fatalf("listed %v", listed)
	}
	if rels, err := f.Releases(ctx, "com.example:tool"); err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 2 {
		t.Fatalf("tool (the sources jar is not mirrored by default): %+v %v", viewReleases(rels), err)
	}

	one, two := mavenChainChunks()
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 2, 2, 1)).withHeader("ETag", `"p2"`)
	srv.on("GET", mavenChunkPath(1)).reply(200, one).once()
	srv.on("GET", mavenChunkPath(2)).reply(200, two).once()
	got, next := drainChanges(t, f, cursor)
	if strings.Join(got, ",") != "com.example:lib@1.0,com.example:lib@1.2,com.newer:webapp,com.other:gone (deleted)" {
		t.Errorf("Changes = %v", got)
	}
	rels, err := f.Releases(ctx, "com.example:lib")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "maven", "releases-chain-lib", viewReleases(rels))
	expectServed(t, mavenTestBackend(t, f.src.k.env), rels, func(r Release, _ Artifact) (string, string) { return "com.example:lib", r.Version })
	if _, err := f.Releases(ctx, "com.other:gone"); !IsPermanent(err) {
		t.Errorf("a deleted coordinate: %v", err)
	}
	if rels, err := f.Releases(ctx, "com.newer:webapp"); err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 2 ||
		!strings.HasSuffix(rels[0].Artifacts[1].Path, "/webapp-1.0.war") {
		t.Errorf("a war's POM stands for its war: %+v %v", viewReleases(rels), err)
	}
	var c indexCursor
	_ = decodeCursor(next, f.format(), &c)
	var st mavenState
	if err := json.Unmarshal(c.State, &st); err != nil || st.Chain != "100" || st.Last != 2 || st.Props.ETag != `"p2"` {
		t.Errorf("state after the chunks %s (%v)", c.State, err)
	}
	full := 0
	for _, r := range srv.requests() {
		if r == "GET "+mavenIndexPath {
			full++
		}
	}
	if full != 1 {
		t.Errorf("the full index was read %d times: %v", full, srv.requests())
	}

	// The same chain, nothing new: unchanged even without a 304.
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 2, 2, 1)).withHeader("ETag", `"p2b"`)
	b, err := f.Changes(ctx, next)
	if err != nil || len(b.Items) != 0 {
		t.Fatalf("no new chunk: %+v %v", b, err)
	}
	next = b.Next

	// The follower fell behind the chunks still kept: the full index is
	// read again and diffed.
	var kept []int
	for n := 40; n > 10; n-- {
		kept = append(kept, n)
	}
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("100", 40, kept...))
	srv.on("GET", mavenIndexPath).reply(200, mavenTestIndex(1794745000000,
		mavenDocOf("com.example|lib|1.0|NA|jar", "jar|1700000500000|1001|0|0|0|jar", "5555555555555555555555555555555555555555"),
		mavenDocOf("com.example|lib|2.0|NA|jar", "jar|1700000800000|2000|0|0|0|jar", ""),
	)).once()
	got, next = drainChanges(t, f, next)
	if strings.Join(got, ",") != "com.example:lib@2.0,com.example:lib@1.1 (deleted),com.example:lib@1.2 (deleted),com.example:tool (deleted),com.newer:webapp (deleted)" {
		t.Errorf("after the gap: %v", got)
	}

	// A new chain is a new full index.
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("200", 0))
	srv.on("GET", mavenIndexPath).reply(200, mavenTestIndex(1794746000000,
		mavenDocOf("com.example|lib|2.0|NA|jar", "jar|1700000800000|2000|0|0|0|jar", ""),
	)).once()
	got, next = drainChanges(t, f, next)
	if strings.Join(got, ",") != "com.example:lib@1.0 (deleted)" {
		t.Errorf("a new chain: %v", got)
	}

	// Another classifier selection is a new full read, chunk or not.
	f2 := mustFeed(t, testEnv(t, "maven", srv.URL(), newFakeReads(), map[string]string{"classifiers": "sources"})).(*mavenFeed)
	f2.indexFeed.files = f.indexFeed.files
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("200", 1, 1))
	srv.on("GET", mavenIndexPath).reply(200, mavenTestIndex(1794746000000,
		mavenDocOf("com.example|lib|2.0|NA|jar", "jar|1700000800000|2000|0|0|0|jar", ""),
		mavenDocOf("com.example|lib|2.0|sources|jar", "jar|1700000800000|200|2|2|0|jar", ""),
	)).once()
	got, _ = drainChanges(t, f2, next)
	if strings.Join(got, ",") != "com.example:lib@2.0" {
		t.Errorf("another classifier selection: %v", got)
	}
}

// Clojars' real chunk (of an older chain) applied to a copy: its documents
// write UINFO without the extension, which the INFO field states.
func TestMavenAppliesARealChunk(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("1714868764455", 0))
	srv.on("GET", mavenIndexPath).reply(200, fixture(t, "maven", "clojars-index.gz"))
	_, cursor := drainBootstrap(t, f)
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("1714868764455", 1, 1))
	srv.on("GET", mavenChunkPath(1)).reply(200, fixture(t, "maven", "clojars-index.1.gz"))
	b, err := f.Changes(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "maven", "changes-clojars-chunk", viewBatch(t, b))
	rels, err := f.Releases(context.Background(), "org.soulspace.clj:cmp.poi")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "maven", "releases-clojars-chunk-cmp-poi", viewReleases(rels))
	expectServed(t, mavenTestBackend(t, f.src.k.env), rels, func(r Release, _ Artifact) (string, string) { return "org.soulspace.clj:cmp.poi", r.Version })
}

// The index documents' records, rule by rule.
func TestMavenRecords(t *testing.T) {
	src := &mavenSource{classifiers: map[string]bool{"natives": true}}
	for _, tc := range []struct {
		name string
		doc  mavenDoc
		want string
	}{
		{"a POM document stands for its jar", mavenDoc{uinfo: "g.x|a|1.0|NA|pom", info: "jar|1700000000000|-1|0|0|0|pom"},
			"/g/x/a/1.0/a-1.0.pom t1700000000; /g/x/a/1.0/a-1.0.jar"},
		{"packaging pom is the POM alone", mavenDoc{uinfo: "g|a|1.0|NA|pom", info: "pom|1700000000000|570|0|0|0|pom"}, "/g/a/1.0/a-1.0.pom s570 t1700000000"},
		{"a war's POM stands for its war", mavenDoc{uinfo: "g|a|1.0|NA|pom", info: "war|0|-1|0|0|0|pom"}, "/g/a/1.0/a-1.0.pom; /g/a/1.0/a-1.0.war"},
		{"a bundle is a jar", mavenDoc{uinfo: "g|a|1.0|NA|pom", info: "bundle|0|-1|0|0|0|pom"}, "/g/a/1.0/a-1.0.pom; /g/a/1.0/a-1.0.jar"},
		{"an unknown packaging is taken for a jar", mavenDoc{uinfo: "g|a|1.0|NA|pom", info: "clojure|0|-1|0|0|0|pom"}, "/g/a/1.0/a-1.0.pom; /g/a/1.0/a-1.0.jar"},
		{"a garbled packaging too", mavenDoc{uinfo: "g|a|1.0|NA|pom", info: "extension 'x' property 'y'|0|-1|0|0|0|pom"}, "/g/a/1.0/a-1.0.pom; /g/a/1.0/a-1.0.jar"},
		{"a jar document stands for its POM", mavenDoc{uinfo: "g|a|1.0|NA|jar", info: "jar|1700000000000|31975|0|0|0|jar", sha1: "3B8989E49E98A2B58CF77038692A500EAD0F446A"},
			"/g/a/1.0/a-1.0.jar s31975 t1700000000 d3b8989e49e98a2b58cf77038692a500ead0f446a; /g/a/1.0/a-1.0.pom"},
		{"an hpi", mavenDoc{uinfo: "g|p|1.0|NA|hpi", info: "hpi|0|69622|0|0|0|hpi"}, "/g/p/1.0/p-1.0.hpi s69622; /g/p/1.0/p-1.0.pom"},
		{"a classifier not selected", mavenDoc{uinfo: "g|a|1.0|sources|jar", info: "jar|0|300|2|2|0|jar"}, ""},
		{"a classifier selected", mavenDoc{uinfo: "g|a|1.0|natives|jar", info: "jar|0|300|2|2|0|jar"}, "/g/a/1.0/a-1.0-natives.jar s300"},
		{"a UINFO without the extension: INFO's", mavenDoc{uinfo: "g|a|1.0|NA", info: "jar|0|10|0|0|0|aar"}, "/g/a/1.0/a-1.0.aar s10; /g/a/1.0/a-1.0.pom"},
		{"neither states it: Maven Indexer's rule", mavenDoc{uinfo: "g|a|1.0|NA", info: "jar|0|10|0|0|0"}, "/g/a/1.0/a-1.0.jar s10; /g/a/1.0/a-1.0.pom"},
		{"neither states it, a war", mavenDoc{uinfo: "g|a|1.0|NA", info: "war|0|10|0|0|0"}, "/g/a/1.0/a-1.0.war s10; /g/a/1.0/a-1.0.pom"},
		{"no INFO at all", mavenDoc{uinfo: "g|a|1.0|NA|pom"}, "/g/a/1.0/a-1.0.pom; /g/a/1.0/a-1.0.jar"},
		{"a signature", mavenDoc{uinfo: "g|a|1.0|NA|jar.sig", info: "jar|0|294|0|0|0|jar.sig"}, ""},
		{"a checksum", mavenDoc{uinfo: "g|a|1.0|NA|jar.sha1", info: "jar|0|40|0|0|0|jar.sha1"}, ""},
		{"a snapshot", mavenDoc{uinfo: "g|a|1.0-SNAPSHOT|NA|jar", info: "jar|0|10|0|0|0|jar"}, ""},
		{"a release that names a snapshot", mavenDoc{uinfo: "g|a|2.3.5-SNAPSHOT-1220.v8e3|NA|jar", info: "jar|0|10|0|0|0|jar"},
			"/g/a/2.3.5-SNAPSHOT-1220.v8e3/a-2.3.5-SNAPSHOT-1220.v8e3.jar s10; /g/a/2.3.5-SNAPSHOT-1220.v8e3/a-2.3.5-SNAPSHOT-1220.v8e3.pom"},
		{"an unresolved property", mavenDoc{uinfo: "g|a|1.213${changelist}|NA|jar", info: "jar|0|10|0|0|0|jar"}, ""},
		{"a bad UINFO", mavenDoc{uinfo: "g|a|1.0", info: "jar|0|10|0|0|0|jar"}, ""},
		{"a UINFO of six parts", mavenDoc{uinfo: "g|a|1.0|NA|jar|x"}, ""},
		{"an empty group", mavenDoc{uinfo: "|a|1.0|NA|jar"}, ""},
		{"a path segment", mavenDoc{uinfo: "g|..|1.0|NA|jar"}, ""},
		{"a negative size and time", mavenDoc{uinfo: "g|a|1.0|NA|zip", info: "zip|-5|-1|0|0|0|zip"}, "/g/a/1.0/a-1.0.zip; /g/a/1.0/a-1.0.pom"},
		{"a bad SHA-1", mavenDoc{uinfo: "g|a|1.0|NA|jar", info: "jar|0|1|0|0|0|jar", sha1: "xyz"}, "/g/a/1.0/a-1.0.jar s1; /g/a/1.0/a-1.0.pom"},
		{"a UINFO too long to keep", mavenDoc{uinfo: "g|" + strings.Repeat("a", 260) + "|1.0|NA|jar"}, ""},
	} {
		var got []string
		for _, r := range src.records(tc.doc) {
			if r.Index != tc.doc.uinfo || r.Name == "" || !r.valid() {
				t.Errorf("%s: record %+v", tc.name, r)
			}
			s := r.Path
			if r.Size > 0 {
				s += fmt.Sprintf(" s%d", r.Size)
			}
			if r.Time > 0 {
				s += fmt.Sprintf(" t%d", r.Time)
			}
			if r.Digest != "" {
				s += " d" + r.Digest
			}
			got = append(got, s)
		}
		if strings.Join(got, "; ") != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, strings.Join(got, "; "), tc.want)
		}
	}
	// Every classifier with "*".
	if recs := (&mavenSource{all: true}).records(mavenDoc{uinfo: "g|a|1.0|tests|jar"}); len(recs) != 1 {
		t.Errorf("classifiers *: %+v", recs)
	}
}

// A release's files are merged across the documents that stand for them:
// each path once, with the size its own document states.
func TestMavenReleasesMergeDocuments(t *testing.T) {
	src := &mavenSource{}
	var recs []snapRecord
	for _, d := range []mavenDoc{
		{uinfo: "g|p|1.0|NA|jar", info: "hpi|1700000002000|91567|0|0|0|jar"},
		{uinfo: "g|p|1.0|NA|hpi", info: "hpi|1700000001000|69931|0|0|0|hpi"},
		{uinfo: "g|p|1.0|NA|pom", info: "hpi|1700000003000|6049|0|0|0|pom"},
		{uinfo: "g|p|0.9|NA|pom", info: "hpi|0|-1|0|0|0|pom"},
	} {
		recs = append(recs, src.records(d)...)
	}
	sort.Slice(recs, func(i, j int) bool { return string(recs[i].appendLine(nil)) < string(recs[j].appendLine(nil)) })
	rels := mavenReleases(recs)
	orderReleases("maven", rels)
	got, _ := json.Marshal(viewReleases(rels))
	want := `[{"version":"0.9","artifacts":[{"path":"/g/p/0.9/p-0.9.jar"},{"path":"/g/p/0.9/p-0.9.pom"}]},` +
		`{"version":"1.0","published":"2023-11-14T22:13:21Z","artifacts":[{"path":"/g/p/1.0/p-1.0.hpi","size":69931},{"path":"/g/p/1.0/p-1.0.jar","size":91567},{"path":"/g/p/1.0/p-1.0.pom","size":6049}]}]`
	if string(got) != want {
		t.Errorf("releases\n%s\nwant\n%s", got, want)
	}
}

func TestMavenPropertiesParse(t *testing.T) {
	for name, tc := range map[string]struct {
		body  string
		chain string
		last  int
		head  string
	}{
		"apache (Nexus 2)":      {string(fixture(t, "maven", "apache-index.properties")), "1793593200161", 0, "1793593200161/0"},
		"jenkins (Artifactory)": {string(fixture(t, "maven", "jenkins-index.properties")), "1794801459569", 0, "1794801459569/0"},
		"chunks":                {"nexus.index.chain-id = 7\r\nnexus.index.last-incremental: 941\nnexus.index.incremental-0=941\nnexus.index.incremental-1=940\\\n  \n! comment\n", "7", 941, "7/941"},
		"no chain":              {"nexus.index.id=x\n", "", 0, ""},
	} {
		p, err := mavenParseProps([]byte(tc.body))
		if err != nil || p.chain != tc.chain || p.last != tc.last || p.head() != tc.head {
			t.Errorf("%s: %+v %v", name, p, err)
		}
	}
	// A continued line is joined to the next, its leading blanks dropped; a
	// file of one long continued line parses in linear time.
	if p, err := mavenParseProps([]byte("nexus.index.chain-id=12\\\n   34\nnexus.index.id=a\\\\\n")); err != nil || p.chain != "1234" {
		t.Errorf("continuation: %+v %v", p, err)
	}
	start := time.Now()
	if _, err := mavenParseProps([]byte(strings.Repeat("a\\\n", mavenMaxProps/3))); err != nil || time.Since(start) > 5*time.Second {
		t.Errorf("a long continued line: %v after %s", err, time.Since(start))
	}
	p, _ := mavenParseProps(fixture(t, "maven", "clojars-index.properties"))
	if p.timestamp.Format("2006-01-02T15:04:05.000Z") != "2026-11-16T04:09:18.722Z" || len(p.chunks) != 0 {
		t.Errorf("clojars: %+v", p)
	}
	for name, body := range map[string]string{
		"chain with a space": "nexus.index.chain-id=a b\n",
		"long chain":         "nexus.index.chain-id=" + strings.Repeat("1", 65) + "\n",
		"bad counter":        "nexus.index.last-incremental=-1\n",
		"huge counter":       "nexus.index.last-incremental=99999999999\n",
		"too many":           strings.Repeat("k=v\n", 5000),
	} {
		if _, err := mavenParseProps([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Malformed indexes, properties and answers.
func TestMavenMalformed(t *testing.T) {
	ctx := context.Background()
	parse := func(data []byte, limit int64) (int, error) {
		n := 0
		_, err := mavenParse(ctx, bytes.NewReader(data), "index", limit, func(mavenDoc) bool { n++; return true })
		return n, err
	}
	raw := func(b ...[]byte) []byte { return bytes.Join(b, nil) }
	be32 := func(v int32) []byte { var b [4]byte; binary.BigEndian.PutUint32(b[:], uint32(v)); return b[:] }
	head := raw([]byte{1}, make([]byte, 8))
	for name, tc := range map[string]struct {
		data      []byte
		permanent bool
		want      string
	}{
		"html":            {[]byte("<html>login</html>"), true, "not a Maven Indexer index (data format 60"},
		"empty":           {nil, true, "ends before its header"},
		"short header":    {[]byte{1, 0, 0}, true, "ends before its header"},
		"version 2":       {raw([]byte{2}, make([]byte, 8)), true, "data format 2"},
		"negative fields": {raw(head, be32(-1)), true, "-1 fields"},
		"negative value":  {raw(head, be32(1), []byte{4, 0, 1, 'u'}, be32(-5)), true, "a value of -5"},
		"truncated count": {raw(head, []byte{0, 0}), false, "truncated"},
		"truncated field": {raw(head, be32(2), []byte{4, 0, 1, 'u'}, be32(3), []byte("a|b")), false, "ends inside document 1"},
		"truncated value": {raw(head, be32(1), []byte{4, 0, 1, 'u'}, be32(30), []byte("g|a")), false, "truncated"},
		"long name":       {raw(head, be32(1), []byte{4, 0, 200}, bytes.Repeat([]byte("n"), 100)), false, "truncated"},
		"corrupt gzip":    {[]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5}, false, ""},
	} {
		_, err := parse(tc.data, 1<<20)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if IsPermanent(err) != tc.permanent || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (permanent %v)", name, err, IsPermanent(err))
		}
	}
	// A long field name and a long value are skipped, not refused; a value
	// that is not printable ASCII is not kept.
	n, err := parse(raw(head, be32(3), []byte{4, 0, 20}, []byte("classnamesclassnames"), be32(5000), bytes.Repeat([]byte("x"), 5000),
		[]byte{4, 0, 1, 'u'}, be32(int32(mavenMaxKept+1)), bytes.Repeat([]byte("y"), mavenMaxKept+1),
		[]byte{4, 0, 1, 'i'}, be32(3), []byte("\xc3\xa4b")), 1<<20)
	if err != nil || n != 1 {
		t.Errorf("skipped values: %d %v", n, err)
	}
	// A document of more fields than mavenMaxFields, or with a value past
	// mavenMaxValue, is dropped; the index goes on.
	valid := raw(be32(2), []byte{4, 0, 1, 'u'}, be32(14), []byte("g|a|1.0|NA|jar"), []byte{4, 0, 1, 'i'}, be32(3), []byte("jar"))
	many := raw(be32(mavenMaxFields + 1))
	for i := 0; i <= mavenMaxFields; i++ {
		many = raw(many, []byte{4, 0, 1, 'u'}, be32(14), []byte("g|a|9.9|NA|jar"))
	}
	var docs []mavenDoc
	stream := io.MultiReader(bytes.NewReader(raw(head, many, valid, be32(2), []byte{4, 0, 1, 'u'}, be32(14), []byte("g|b|1.0|NA|jar"),
		[]byte{4, 0, 10}, []byte("classnames"), be32(mavenMaxValue+1))), io.LimitReader(mavenZeros{}, mavenMaxValue+1), bytes.NewReader(valid))
	_, err = mavenParse(ctx, stream, "index", 1<<30, func(d mavenDoc) bool { docs = append(docs, d); return true })
	if err != nil || len(docs) != 4 || docs[0] != (mavenDoc{}) || docs[1].uinfo == "" || docs[2] != (mavenDoc{}) || docs[3].uinfo == "" {
		t.Errorf("oversized documents: %+v %v", docs, err)
	}
	// Past the decompressed bound: refused, not truncated.
	_, err = parse(fixture(t, "maven", "clojars-index.gz"), 1000)
	mustErr(t, err, true, false, "larger than the adapter reads")

	// The adapter's answers.
	f, srv := mavenTestFeed(t, nil)
	srv.on("GET", mavenPropsPath).reply(404, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "publishes no Maven Indexer index at "+srv.URL()+"/.index (set fullMirror.feed.url")
	srv.on("GET", mavenPropsPath).reply(200, []byte("nexus.index.chain-id=x y\n"))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "chain id")
	srv.on("GET", mavenPropsPath).reply(200, bytes.Repeat([]byte("#"), mavenMaxProps+1))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "larger than the adapter reads")
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("1", 0))
	srv.on("GET", mavenIndexPath).reply(200, []byte("<html>not here</html>"))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "not a Maven Indexer index")
	srv.on("GET", mavenIndexPath).reply(503, nil).withHeader("Retry-After", "60")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d.Seconds() != 60 {
		t.Errorf("a 503 with Retry-After: %v", err)
	}
	srv.on("GET", mavenPropsPath).reply(401, nil)
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("a refused authorization holds the upstream: %v", err)
	}
	// A chunk that fails for a while (a 5xx) fails the poll, to be asked for
	// again; one that is not there or not an index has the full index read
	// instead (TestMavenAMissingChunkReadsTheFullIndex).
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("9", 0))
	srv.on("GET", mavenIndexPath).reply(200, mavenChainFull())
	_, cursor := drainBootstrap(t, f)
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("9", 1, 1))
	srv.on("GET", mavenChunkPath(1)).reply(502, nil)
	_, err = f.Changes(ctx, cursor)
	mustErr(t, err, false, false, "chunk 1 of the Maven index")
	srv.on("GET", mavenChunkPath(1)).reply(200, []byte("garbage"))
	if _, err = f.Changes(ctx, cursor); err != nil {
		t.Errorf("a chunk that is not an index: %v", err)
	}
	// Cursors of another adapter or format, and garbage, are not trusted.
	for _, bad := range []string{"x", `{"format":"jsr/1","snap":"` + strings.Repeat("a", 64) + `"}`, `{"format":"maven/1","snap":"` + strings.Repeat("b", 64) + `"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
	// A copy whose chunks cannot be applied (it was damaged): the
	// enumeration starts over.
	var c indexCursor
	_ = decodeCursor(cursor, f.format(), &c)
	srv.on("GET", mavenChunkPath(1)).reply(200, mavenChainChunksOne())
	if err := mavenCorrupt(f.files.path(snapName(c.Snap))); err != nil {
		t.Fatal(err)
	}
	f.indexFeed.headers = map[string]*snapHeader{}
	_, err = f.Changes(ctx, cursor)
	if !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("a damaged copy: %v", err)
	}
}

func mavenChainChunksOne() []byte { one, _ := mavenChainChunks(); return one }

// mavenCorrupt flips a byte near a file's end (inside the last block).
func mavenCorrupt(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data[len(data)-12] ^= 0xff
	return os.WriteFile(path, data, 0o644)
}

// mavenZeros reads zero bytes, endlessly.
type mavenZeros struct{}

func (mavenZeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// The chunks of a run that changes too much to hold in memory are not
// applied: the full index is read instead.
func TestMavenTooManyChangesReadTheFullIndex(t *testing.T) {
	f, srv := mavenTestFeed(t, nil)
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("5", 0))
	srv.on("GET", mavenIndexPath).reply(200, mavenChainFull()).once()
	_, cursor := drainBootstrap(t, f)
	var docs [][][2]string
	for i := 0; i <= mavenMaxChunkDocs; i++ {
		docs = append(docs, mavenDocOf(fmt.Sprintf("com.example|lib|9.%d|NA|jar", i), "jar|0|1|0|0|0|jar", ""))
	}
	srv.on("GET", mavenPropsPath).reply(200, mavenTestProps("5", 1, 1))
	srv.on("GET", mavenChunkPath(1)).reply(200, mavenTestIndex(1, docs...)).once()
	srv.on("GET", mavenIndexPath).reply(200, mavenTestIndex(2, mavenDocOf("com.example|lib|9.0|NA|jar", "jar|0|1|0|0|0|jar", ""))).once()
	got, _ := drainChanges(t, f, cursor)
	if len(got) == 0 || got[0] != "com.example:lib@9.0" {
		t.Errorf("Changes = %v", got)
	}
	n := 0
	for _, r := range srv.requests() {
		if r == "GET "+mavenIndexPath {
			n++
		}
	}
	if n != 2 {
		t.Errorf("the full index was read %d times", n)
	}
}

// Parsing an index holds a bounded amount of memory however large it is:
// documents are read one at a time and the values the adapter does not use —
// a jar's class names run to megabytes — are skipped unread.
func TestMavenParseMemoryIsBounded(t *testing.T) {
	docs, classnames := 40_000, 16<<10
	if raceEnabled || testing.Short() {
		docs = 2_000
	}
	pr, pw := io.Pipe()
	go func() {
		bw := &bytes.Buffer{}
		bw.WriteByte(1)
		bw.Write(make([]byte, 8))
		pad := bytes.Repeat([]byte("org.example.Klass/"), classnames/18)
		for i := 0; i < docs; i++ {
			u := fmt.Sprintf("com.example.group%d|artifact-%d|1.%d|NA|jar", i%97, i, i%13)
			_ = binary.Write(bw, binary.BigEndian, int32(3))
			for _, f := range [][2][]byte{{[]byte("u"), []byte(u)}, {[]byte("i"), []byte("jar|1700000000000|12345|0|0|0|jar")}, {[]byte("classnames"), pad}} {
				bw.WriteByte(4)
				_ = binary.Write(bw, binary.BigEndian, uint16(len(f[0])))
				bw.Write(f[0])
				_ = binary.Write(bw, binary.BigEndian, int32(len(f[1])))
				bw.Write(f[1])
			}
			if bw.Len() > 1<<20 || i == docs-1 {
				if _, err := pw.Write(bw.Bytes()); err != nil {
					return
				}
				bw.Reset()
			}
		}
		pw.Close()
	}()
	n := 0
	peak := sampleHeap(t, func() {
		_, err := mavenParse(context.Background(), pr, "a large index", 1<<40, func(d mavenDoc) bool {
			if d.uinfo != "" && d.info != "" {
				n++
			}
			return true
		})
		if err != nil {
			t.Error(err)
		}
	})
	if n != docs {
		t.Fatalf("read %d documents, want %d", n, docs)
	}
	t.Logf("peak heap while parsing %d documents (%d MiB): %d MiB", docs, int64(docs)*int64(classnames)>>20, peak>>20)
	if !raceEnabled && peak > 32<<20 {
		t.Errorf("parsing held %d MiB of heap; the bound is 32 MiB", peak>>20)
	}
	runtime.KeepAlive(pr)
}

// A cancelled poll stops the parse.
func TestMavenParseStopsWhenCancelled(t *testing.T) {
	var docs [][][2]string
	for i := 0; i < 10_000; i++ {
		docs = append(docs, mavenDocOf(fmt.Sprintf("g|a|1.%d|NA|jar", i), "jar|0|1|0|0|0|jar", ""))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := mavenParse(ctx, bytes.NewReader(mavenTestIndex(1, docs...)), "index", 1<<30, func(mavenDoc) bool { return true })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled parse: %v", err)
	}
}
