package fullmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/helm"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The recorded indexes (testdata/feeds/helm): prometheus-community's
// (GitHub Pages, chart-releaser), Bitnami's (charts.bitnami.com redirecting
// to repo.broadcom.com; archives as oci:// references and https URLs) and
// JFrog's (an Artifactory Helm repository: unquoted time stamps, archive
// names that are not "<chart>-<version>.tgz"), each trimmed to a few chart
// versions, maintainers' e-mail addresses replaced.
const (
	helmPromETag     = `"6afa4110-679879"`
	helmPromModified = "Sun, 15 Nov 2026 23:32:32 GMT"
)

// helmTestFeed builds the helm adapter against a fixture server standing in
// for the chart repository.
func helmTestFeed(t *testing.T, opts map[string]string) (*helmFeed, *fixtureServer) {
	t.Helper()
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "helm", srv.URL(), nil, opts)).(*helmFeed)
	return f, srv
}

func TestHelmFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://charts.bitnami.com/bitnami", nil, "https://charts.bitnami.com/bitnami/index.yaml"},
		{"https://chartmuseum.internal.example/", nil, "https://chartmuseum.internal.example/index.yaml"},
		{"https://artifactory.internal.example/artifactory/api/helm/charts", map[string]string{"url": "https://mirror.internal.example/charts/index.yaml"}, "https://mirror.internal.example/charts/index.yaml"},
		{"https://charts.example.com", map[string]string{"url": "https://mirror.example.com/helm/"}, "https://mirror.example.com/helm/index.yaml"},
		{"https://charts.example.com", map[string]string{"url": "https://mirror.example.com/helm/index.json"}, "https://mirror.example.com/helm/index.json"},
	} {
		f, err := newHelmFeed(Env{Upstream: "h", Type: "helm", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*helmFeed).src.index; got != tc.want {
			t.Errorf("%s %v: index %s, want %s", tc.url, tc.opts, got, tc.want)
		}
		if got := f.(*helmFeed).src.settle; got != 15*time.Minute {
			t.Errorf("%s %v: settle %v", tc.url, tc.opts, got)
		}
	}
	for v, want := range map[string]time.Duration{"0": 0, "45m": 45 * time.Minute} {
		f, err := newHelmFeed(Env{Upstream: "h", Type: "helm", URL: "https://charts.bitnami.com/bitnami", Options: map[string]string{"settle": v}})
		if err != nil || f.(*helmFeed).src.settle != want {
			t.Errorf("settle %q: %v", v, err)
		}
	}
	// A repository in an OCI registry has no index: refused at load time,
	// pointing at the documentation.
	err := Check(Env{Upstream: "bitnami-oci", Type: "helm", URL: "https://registry-1.docker.io", Settings: map[string]string{"oci": " TRUE "}})
	if err == nil || !strings.Contains(err.Error(), "docs/full-mirroring.md#helm") || !strings.Contains(err.Error(), "OCI") {
		t.Errorf("an OCI upstream: %v", err)
	}
	if err := Check(Env{Upstream: "h", Type: "helm", URL: "https://charts.bitnami.com/bitnami", Settings: map[string]string{"oci": "false"}}); err != nil {
		t.Errorf("a classic upstream: %v", err)
	}
	for _, opts := range []map[string]string{{"subdirs": "x"}, {"url": "ftp://x/index.yaml"}, {"url": "https://u:p@x/index.yaml"}, {"url": "https://x/index.yaml?token=1"}, {"url": "not a url"},
		{"settle": "-1s"}, {"settle": "15"}, {"settle": "169h"}} {
		if err := Check(Env{Upstream: "h", Type: "helm", URL: "https://charts.bitnami.com/bitnami", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
	if err := Check(Env{Upstream: "h", Type: "helm", URL: "file:///srv/charts"}); err == nil {
		t.Errorf("a file upstream accepted")
	}
}

// helmEdit applies text replacements to a fixture, each of which must apply.
func helmEdit(t *testing.T, doc string, edits ...string) []byte {
	t.Helper()
	for i := 0; i+1 < len(edits); i += 2 {
		if !strings.Contains(doc, edits[i]) {
			t.Fatalf("the fixture has no %q", edits[i])
		}
		doc = strings.Replace(doc, edits[i], edits[i+1], 1)
	}
	return []byte(doc)
}

func TestHelmBootstrapThenChanges(t *testing.T) {
	f, srv := helmTestFeed(t, map[string]string{"settle": "0"})
	f.page = 2
	index := fixture(t, "helm", "index-prometheus-community.yaml")
	srv.on("GET", "/index.yaml").reply(200, index).withHeader("ETag", helmPromETag).withHeader("Last-Modified", helmPromModified)
	ctx := context.Background()
	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.Bootstrap(ctx, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "helm", "bootstrap", []batchView{helmView(t, first, srv), helmView(t, second, srv)})
	if !first.More || second.More {
		t.Fatalf("paging: %v %v", first.More, second.More)
	}
	// The listing came from one read of the index.
	if n := len(srv.requests()); n != 1 {
		t.Errorf("%d requests: %v", n, srv.requests())
	}
	for _, name := range []string{"alertmanager", "kube-state-metrics", "prometheus-node-exporter"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "helm", "releases-"+name, viewReleases(rels))
	}
	_, err = f.Releases(ctx, "grafana")
	mustErr(t, err, true, false, "not in the helm index")

	f.page = indexPage
	// Unchanged: one conditional request, answered 304; the cursor stays.
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", helmPromETag).requireHeader("If-Modified-Since", helmPromModified).reply(http.StatusNotModified, nil)
	same, err := f.Changes(ctx, second.Next)
	if err != nil || len(same.Items) != 0 || same.Next != second.Next {
		t.Fatalf("an unchanged index: %+v %v", same, err)
	}

	// alertmanager 2.5.2 is published, kube-state-metrics 9.0.0 republished
	// with another digest, prometheus-node-exporter removed.
	doc := string(index)
	cut := strings.Index(doc, "  prometheus-node-exporter:\n")
	end := strings.Index(doc, "generated: ")
	changed := helmEdit(t, doc[:cut]+doc[end:],
		"  alertmanager:\n", "  alertmanager:\n  - created: \"2026-11-16T05:00:00Z\"\n    digest: 1111111111111111111111111111111111111111111111111111111111111111\n    name: alertmanager\n    urls:\n    - https://github.com/prometheus-community/helm-charts/releases/download/alertmanager-2.5.2/alertmanager-2.5.2.tgz\n    version: 2.5.2\n",
		"digest: d187c099", "digest: 0000c099",
		`generated: "2026-11-15T23:31:53.852118585Z"`, `generated: "2026-11-16T05:01:02.5Z"`)
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", helmPromETag).reply(200, changed).withHeader("ETag", `"6afa4111-1"`)
	ch, err := f.Changes(ctx, second.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "helm", "changes", helmView(t, ch, srv))
	rels, err := f.Releases(ctx, "alertmanager")
	if err != nil || len(rels) != 4 || rels[3].Version != "2.5.2" {
		t.Errorf("Releases reads the newest copy: %+v %v", viewReleases(rels), err)
	}
	if _, err := f.Releases(ctx, "prometheus-node-exporter"); !IsPermanent(err) {
		t.Errorf("a chart gone from the index: %v", err)
	}
	// The next poll is conditioned on the new copy's validators.
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", `"6afa4111-1"`).reply(http.StatusNotModified, nil)
	if b, err := f.Changes(ctx, ch.Next); err != nil || len(b.Items) != 0 {
		t.Errorf("after the difference: %+v %v", b, err)
	}
}

// helmView is a batch as the golden files show it, the fixture server's
// address (which the cursor's state names) replaced.
func helmView(t *testing.T, b Batch, srv *fixtureServer) batchView {
	t.Helper()
	v := viewBatch(t, b)
	v.Next = bytes.ReplaceAll(v.Next, []byte(srv.URL()), []byte("http://repository.example"))
	return v
}

// helmTestBackend is the real helm backend fronting the fixture server, as
// the proxy builds it for the upstream.
func helmTestBackend(t *testing.T, env Env) *helm.Backend {
	t.Helper()
	b, err := helm.New(helm.Options{Name: env.Upstream, UpstreamURL: env.URL, PublicBaseURL: "http://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(&http.Client{Timeout: 30 * time.Second}, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The archive paths are the links the backend's rewritten index hands a
// client — also where an archive's name is not "<chart>-<version>.tgz", which
// repos/locate's helm locator assumes — and the backend serves each of them.
func TestHelmReleasesAreTheRewrittenLinks(t *testing.T) {
	for _, fx := range []string{"index-prometheus-community.yaml", "index-bitnami.yaml", "index-artifactory.yaml"} {
		t.Run(fx, func(t *testing.T) {
			f, srv := helmTestFeed(t, nil)
			srv.on("GET", "/index.yaml").reply(200, fixture(t, "helm", fx))
			ctx := context.Background()
			b, err := f.Bootstrap(ctx, "")
			if err != nil {
				t.Fatal(err)
			}
			backend := helmTestBackend(t, f.src.k.env)
			res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: "/index.yaml", Query: url.Values{}, Header: http.Header{}})
			if err != nil {
				t.Fatal(err)
			}
			fr, err := backend.Fetch(ctx, res)
			if err != nil {
				t.Fatal(err)
			}
			rewritten, _ := io.ReadAll(fr.Content)
			fr.Content.Close()
			idx, err := helm.ParseIndex(rewritten)
			if err != nil {
				t.Fatal(err)
			}
			differ := 0
			for _, c := range b.Items {
				rels, err := f.Releases(ctx, c.Name)
				if err != nil {
					t.Fatalf("%s: %v", c.Name, err)
				}
				if fx != "index-prometheus-community.yaml" {
					checkGolden(t, "helm", "releases-"+strings.TrimSuffix(strings.TrimPrefix(fx, "index-"), ".yaml")+"-"+c.Name, viewReleases(rels))
				}
				expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return c.Name, r.Version })
				for _, r := range rels {
					cv, ok := idx.FindVersion(c.Name, r.Version)
					if !ok || len(cv.URLs) == 0 || len(r.Artifacts) != 1 {
						t.Fatalf("%s %s: %+v %+v", c.Name, r.Version, cv, r.Artifacts)
					}
					if p, ok := f.src.k.proxyPath(cv.URLs[0]); !ok || p != r.Artifacts[0].Path {
						t.Errorf("%s %s: the rewritten index links %s (%s), the feed lists %s", c.Name, r.Version, cv.URLs[0], p, r.Artifacts[0].Path)
					}
					loc, err := f.src.k.locate(ctx, lockfiles.Dependency{Name: c.Name, Version: r.Version}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if loc[0].Path != r.Artifacts[0].Path {
						differ++
					}
				}
			}
			if want := map[string]int{"index-artifactory.yaml": 1}[fx]; differ != want {
				t.Errorf("%d versions whose archive the locator names otherwise, want %d", differ, want)
			}
		})
	}
}

// The streaming reader reads every recorded index as yaml.v3 and the
// backend's parser do.
func TestHelmStreamingReadsAsYAMLDoes(t *testing.T) {
	for _, fx := range []string{"index-prometheus-community.yaml", "index-bitnami.yaml", "index-artifactory.yaml"} {
		data := fixture(t, "helm", fx)
		var streamed []helmEntry
		genS, err := helmScanIndex(bytes.NewReader(data), func(e helmEntry) error {
			streamed = append(streamed, e)
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", fx, err)
		}
		whole, genW, err := helmReadIndexWhole(data)
		if err != nil {
			t.Fatalf("%s: %v", fx, err)
		}
		if !reflect.DeepEqual(streamed, whole) || genS != genW || len(streamed) == 0 {
			t.Errorf("%s: streamed %+v (%q), yaml.v3 %+v (%q)", fx, streamed, genS, whole, genW)
		}
	}
}

// helmIndex renders an index as `helm repo index` does.
func helmIndex(charts map[string][]string, extra string) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nentries:\n")
	names := make([]string, 0, len(charts))
	for n := range charts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteString("  " + n + ":\n")
		for _, v := range charts[n] {
			fmt.Fprintf(&b, "  - apiVersion: v2\n    created: \"2026-01-02T03:04:05.123456789Z\"\n    description: A chart\n    digest: %064x\n    name: %s\n    urls:\n    - https://charts.example.com/%s-%s.tgz\n    version: %s\n", len(n)+len(v), n, n, v, v)
		}
	}
	b.WriteString(extra)
	b.WriteString("generated: \"2026-01-02T03:04:05Z\"\n")
	return b.String()
}

func TestHelmMalformedAndRefused(t *testing.T) {
	ctx := context.Background()
	f, srv := helmTestFeed(t, map[string]string{"settle": "0"})
	for name, tc := range map[string]struct{ body, want string }{
		"garbage":     {"<html><body>rate limited</body></html>", "not an index"},
		"a list":      {"- apiVersion: v1\n", "not an index"},
		"no entries":  {"apiVersion: v1\ngenerated: x\n", "no entries"},
		"entries seq": {"apiVersion: v1\nentries:\n- a\n", "not an index"},
		"merge key":   {"apiVersion: v1\nentries:\n  a:\n  - <<: {urls: [x.tgz]}\n    version: 1.0.0\n", "merge key"},
		"versions":    {"apiVersion: v1\nentries:\n  a: 1.0.0\n", "not a list"},
		"two docs":    {"apiVersion: v1\nentries: {}\n---\napiVersion: v1\nentries: {}\n", "more than one"},
		"empty":       {"", "empty"},
	} {
		srv.on("GET", "/index.yaml").reply(200, []byte(tc.body))
		_, err := f.Bootstrap(ctx, "")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, true, false, "")
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", name, err, tc.want)
		}
	}
	// Entries the backend cannot address — and those without a version or
	// a URL — are not mirrored; the rest of the index is.
	srv.on("GET", "/index.yaml").reply(200, []byte(helmIndex(map[string][]string{"good": {"1.0.0"}},
		"  bad/name:\n  - version: 1.0.0\n    urls:\n    - x\n"+
			"  dotdot:\n  - version: ../1\n    urls:\n    - dotdot.tgz\n"+
			"  noversion:\n  - urls:\n    - noversion.tgz\n"+
			"  nourl:\n  - version: 1.0.0\n    urls: []\n"+
			"  emptyurl:\n  - version: 1.0.0\n    urls:\n    - \"\"\n    -\n"+
			"  nulls:\n  -\n  - null\n")))
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[good]" {
		t.Errorf("addressable entries only: %v %v", names(b.Items), err)
	}
	// A small index outside the streaming reader's subset (JSON here) is
	// read whole; a large one is refused.
	jsonIndex := `{"apiVersion":"v1","entries":{"json-chart":[{"version":"1.2.3","digest":"` + strings.Repeat("ab", 32) + `","created":"2026-01-02T03:04:05Z","urls":["https:\/\/charts.example.com\/json-chart-1.2.3.tgz"]}]}}`
	srv.on("GET", "/index.yaml").reply(200, []byte(jsonIndex))
	if b, err := f.Bootstrap(ctx, ""); err != nil || fmt.Sprint(names(b.Items)) != "[json-chart]" {
		t.Fatalf("a JSON index: %+v %v", b, err)
	}
	rels, err := f.Releases(ctx, "json-chart")
	if err != nil || len(rels) != 1 || rels[0].Artifacts[0].Path != "/-/json-chart/1.2.3/json-chart-1.2.3.tgz" || !rels[0].Published.IsZero() {
		t.Errorf("the JSON index's chart: %+v %v", viewReleases(rels), err)
	}
	f.src.wholeMax = 64
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "streaming reader does not handle")
	f.src.wholeMax = helmWholeMax
	// A line longer than the streaming reader takes is read whole too.
	srv.on("GET", "/index.yaml").reply(200, []byte(helmIndex(map[string][]string{"long": {"1.0.0"}}, "")+"description: "+strings.Repeat("x", helmMaxLine+10)+"\n"))
	if b, err := f.Bootstrap(ctx, ""); err != nil || fmt.Sprint(names(b.Items)) != "[long]" {
		t.Errorf("a long line: %v %v", names(b.Items), err)
	}
	// What the repository answers.
	srv.on("GET", "/index.yaml").reply(http.StatusNotFound, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "not found")
	srv.on("GET", "/index.yaml").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "90")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 90*time.Second || IsPermanent(err) {
		t.Errorf("a 503: %v", err)
	}
	srv.on("GET", "/index.yaml").reply(http.StatusUnauthorized, nil)
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != holdAfterRefusal {
		t.Errorf("a 401: %v", err)
	}
	// A 304 to a request that named no validators is not "unchanged".
	srv.on("GET", "/index.yaml").reply(http.StatusNotModified, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, false, false, "unconditional")
	// Cursors of another adapter, or naming no stored copy, are not trusted.
	for _, c := range []string{"{", `{"format":"conda/1","snap":"` + strings.Repeat("a", 64) + `"}`, `{"format":"helm/1","snap":"` + strings.Repeat("b", 64) + `"}`} {
		_, err := f.Changes(ctx, c)
		mustErr(t, err, false, true, "")
	}
	_, err = f.Releases(ctx, "../etc")
	mustErr(t, err, true, false, "not in the helm index")
}

// A repository whose index redirects to another host (Bitnami's): the
// credentials stay on the upstream's origin, and the next poll is still
// answered 304 behind the redirect.
func TestHelmIndexBehindARedirect(t *testing.T) {
	index := fixture(t, "helm", "index-bitnami.yaml")
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("the upstream's credentials reached another host")
		}
		if r.URL.Path != "/bitnami-files/index.yaml" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == `"ff3e61732b9d545e9ca5760232716f2e"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"ff3e61732b9d545e9ca5760232716f2e"`)
		_, _ = w.Write(index)
	}))
	t.Cleanup(files.Close)
	authorized := 0
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer secret" {
			authorized++
		}
		http.Redirect(w, r, files.URL+"/bitnami-files/index.yaml", http.StatusFound)
	}))
	t.Cleanup(repo.Close)
	env := testEnv(t, "helm", repo.URL+"/bitnami", nil, nil)
	env.Authorize = func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") }
	f := mustFeed(t, env).(*helmFeed)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[airflow external-dns]" {
		t.Fatalf("%v %v", names(b.Items), err)
	}
	if b.Head != "2026-11-14T02:35:18.335903141Z" || b.HeadTime.IsZero() {
		t.Errorf("head %q %v", b.Head, b.HeadTime)
	}
	same, err := f.Changes(ctx, b.Next)
	if err != nil || len(same.Items) != 0 || same.Next != b.Next {
		t.Errorf("behind the redirect: %+v %v", same, err)
	}
	if authorized != 2 {
		t.Errorf("the upstream saw its credentials %d times", authorized)
	}
}

// A ~30 MB index is read in bounded memory.
func TestHelmLargeIndexInBoundedMemory(t *testing.T) {
	charts, versions := 120, 400
	if raceEnabled || testing.Short() {
		charts, versions = 12, 100
	}
	var doc strings.Builder
	doc.WriteString("apiVersion: v1\nentries:\n")
	for c := 0; c < charts; c++ {
		fmt.Fprintf(&doc, "  chart-%04d:\n", c)
		for v := 0; v < versions; v++ {
			fmt.Fprintf(&doc, "  - annotations:\n      artifacthub.io/links: |\n        - name: Chart Source\n          url: https://github.com/example/charts\n    apiVersion: v2\n    appVersion: v%d.%d.0\n"+
				"    created: \"2026-%02d-%02dT10:00:00.123456789Z\"\n    description: A Helm chart that installs version %d of an application with a description long\n      enough to wrap onto a second line.\n"+
				"    digest: %064x\n    home: https://example.com/\n    keywords:\n    - one\n    - two\n    maintainers:\n    - email: maintainer@example.org\n      name: someone\n"+
				"    name: chart-%04d\n    sources:\n    - https://github.com/example/charts\n    type: application\n    urls:\n    - https://github.com/example/charts/releases/download/chart-%04d-1.%d.0/chart-%04d-1.%d.0.tgz\n    version: 1.%d.0\n",
				v/10, v%10, v%12+1, v%28+1, v, c*versions+v, c, c, v, c, v, v)
		}
	}
	doc.WriteString("generated: \"2026-11-16T00:00:00Z\"\n")
	body := []byte(doc.String())
	f, srv := helmTestFeed(t, map[string]string{"settle": "0"})
	srv.on("GET", "/index.yaml").reply(200, body)
	var b Batch
	var err error
	start := time.Now()
	peak := sampleHeap(t, func() { b, err = f.Bootstrap(context.Background(), "") })
	if err != nil {
		t.Fatal(err)
	}
	h, _ := f.current()
	t.Logf("an index of %d MB (%d chart versions): read in %v, peak heap %d MiB", len(body)>>20, h.Records, time.Since(start), peak>>20)
	if h.Records != charts*versions || h.Names != charts || len(b.Items) != charts {
		t.Errorf("%d records of %d charts, %d listed", h.Records, h.Names, len(b.Items))
	}
	if raceEnabled {
		return
	}
	// yaml.v3 holds about ten times the document (361 MiB for Bitnami's
	// 27.6 MB index); the stream holds a line and the copy's sort buffer.
	const ceiling = 80 << 20
	if peak > ceiling {
		t.Errorf("reading the index held %d MiB of heap; the bound is %d MiB", peak>>20, ceiling>>20)
	}
}

func TestHelmVersionOrder(t *testing.T) {
	ordered := []string{"latest", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "v1.0.1", "1.2", "1.2.1+build.5", "1.10.0", "2.0.0"}
	for i := range ordered {
		for j := range ordered {
			c := helmCompareVersions(ordered[i], ordered[j])
			if (i < j && c >= 0) || (i > j && c <= 0) || (i == j && c != 0) {
				t.Errorf("compare(%s, %s) = %d", ordered[i], ordered[j], c)
			}
		}
	}
	f, srv := helmTestFeed(t, nil)
	srv.on("GET", "/index.yaml").reply(200, []byte(helmIndex(map[string][]string{"c": {"1.10.0", "1.2.0", "1.9.0-rc.1", "1.9.0"}}, "")))
	if _, err := f.Bootstrap(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	rels, err := f.Releases(context.Background(), "c")
	var got []string
	for _, r := range rels {
		got = append(got, r.Version)
	}
	if err != nil || fmt.Sprint(got) != "[1.2.0 1.9.0-rc.1 1.9.0 1.10.0]" {
		t.Errorf("releases in version order: %v %v", got, err)
	}
}

// The reader refuses what it cannot vouch for reading as yaml.v3 does, and
// reads what it accepts exactly as yaml.v3 does.
func TestHelmStreamingReaderSubset(t *testing.T) {
	head := "apiVersion: v1\nentries:\n  c:\n  - name: c\n"
	tail := "    urls:\n    - https://x.example/c-1.tgz\n"
	for _, tc := range []struct {
		name, doc string
		ok        bool
	}{
		{"plain", head + "    version: 1.0.0\n" + tail, true},
		{"quoted", head + "    version: '1.0.0'\n    digest: \"a\\x62c\"\n" + tail, true},
		{"crlf", strings.ReplaceAll(head+"    version: 1.0.0\n"+tail, "\n", "\r\n"), true},
		{"bom", "\xef\xbb\xbf" + head + "    version: 1.0.0\n" + tail, true},
		{"comments", "# an index\n" + head + "    # a comment\n    version: 1.0.0 # the version\n" + tail + "\n# end\n", true},
		{"indented seq", "apiVersion: v1\nentries:\n  c:\n    - name: c\n      version: 1.0.0\n      urls:\n        - https://x.example/c-1.tgz\n", true},
		{"item on next line", "apiVersion: v1\nentries:\n  c:\n  -\n    version: 1.0.0\n    urls:\n    - https://x.example/c-1.tgz\n", true},
		{"block scalars", head + "    description: |-\n      line one\n\n      line two\n    notes: >2\n       indented\n    version: 1.0.0\n" + tail, true},
		{"folded plain", head + "    description: a long\n      description - with a dash\n    version: 1.0.0\n" + tail, true},
		{"multi-line quoted", head + "    description: \"a long\n      quoted one\"\n    version: 1.0.0\n" + tail, true},
		{"empty collections", head + "    keywords: []\n    annotations: {}\n    version: 1.0.0\n" + tail, true},
		{"trailing docs", head + "    version: 1.0.0\n" + tail + "---\n...\n", true},
		{"explicit start", "--- # index\n" + head + "    version: 1.0.0\n" + tail, true},
		{"tab", head + "\tversion: 1.0.0\n" + tail, false},
		{"anchor", head + "    version: &v 1.0.0\n" + tail, false},
		{"alias", head + "    version: *v\n" + tail, false},
		{"tag", head + "    version: !!str 1.0.0\n" + tail, false},
		{"flow", head + "    version: 1.0.0\n    urls: [https://x.example/c-1.tgz]\n", false},
		{"json", `{"apiVersion":"v1","entries":{}}`, false},
		{"multi-line version", head + "    version: 1.0\n      .0\n" + tail, false},
		{"block version", head + "    version: |\n      1.0.0\n" + tail, false},
		{"repeated field", head + "    version: 1.0.0\n    Version: 2.0.0\n" + tail, false},
		{"repeated chart", head + "    version: 1.0.0\n" + tail + "  c:\n  - version: 2.0.0\n", false},
		{"mapping in value", head + "    version: a: b\n" + tail, false},
		{"bad escape", head + "    version: \"1\\/0\"\n" + tail, false},
		{"lone cr", head + "    version: 1.0.0\r    x: y\n" + tail, false},
		{"nel", head + "    version: 1.0.0\u0085\n" + tail, false},
		{"directive", "%YAML 1.1\n---\n" + head + "    version: 1.0.0\n" + tail, false},
		{"complex key", head + "    ? version\n    : 1.0.0\n" + tail, false},
		{"bad indent", head + "    version: 1.0.0\n   urls: []\n", false},
		{"two chompings", head + "    description: |--\n      x\n    version: 1.0.0\n" + tail, false},
	} {
		var got []helmEntry
		_, err := helmScanIndex(strings.NewReader(tc.doc), func(e helmEntry) error {
			got = append(got, e)
			return nil
		})
		var unsupported *helmUnsupportedError
		if tc.ok != (err == nil) {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if err != nil {
			if !errors.As(err, &unsupported) {
				t.Errorf("%s: %v is not an unsupported construct", tc.name, err)
			}
			continue
		}
		whole, _, werr := helmReadIndexWhole([]byte(tc.doc))
		if werr != nil || !reflect.DeepEqual(got, whole) {
			t.Errorf("%s: streamed %+v, yaml.v3 %+v (%v)", tc.name, got, whole, werr)
		}
	}
}

// helmCreatedIndex renders an index of chart c's versions, each created at
// the time given, its archive (relative, beside the index) digested.
func helmCreatedIndex(created map[string]time.Time, archives map[string][]byte, generated time.Time) []byte {
	versions := make([]string, 0, len(created))
	for v := range created {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	var b strings.Builder
	b.WriteString("apiVersion: v1\nentries:\n  c:\n")
	for _, v := range versions {
		fmt.Fprintf(&b, "  - apiVersion: v2\n    created: %q\n    digest: %x\n    name: c\n    urls:\n    - c-%s.tgz\n    version: %s\n",
			created[v].Format(time.RFC3339Nano), sha256.Sum256(archives[v]), v, v)
	}
	fmt.Fprintf(&b, "generated: %q\n", generated.Format(time.RFC3339Nano))
	return []byte(b.String())
}

// helmBackendFetch fetches an archive link through the real backend, reading
// it whole.
func helmBackendFetch(t *testing.T, backend *helm.Backend, path string) error {
	t.Helper()
	ctx := context.Background()
	res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	fr, err := backend.Fetch(ctx, res)
	if err != nil {
		return err
	}
	defer fr.Content.Close()
	_, err = io.Copy(io.Discard, fr.Content)
	return err
}

// A version is reported once it has been listed for the settle period (15
// minutes by default), on the repository's clock: the backend serves an
// archive only once its own copy of the index lists it, and a CDN may hand it
// an older index meanwhile — the archive would be answered 404, which the
// engine does not retry.
func TestHelmSettleHoldsNewVersions(t *testing.T) {
	f, srv := helmTestFeed(t, nil)
	t0 := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	clock := t0
	f.src.now = func() time.Time { return clock }
	date := func() string { return clock.Format(http.TimeFormat) }
	archives := map[string][]byte{"1.0.0": []byte("c 1.0.0 archive"), "1.1.0": []byte("c 1.1.0 archive"), "1.2.0": []byte("c 1.2.0 archive")}
	for v, body := range archives {
		srv.on("GET", "/c-"+v+".tgz").reply(200, body)
	}
	// 1.1.0 was created two minutes ago; the backend's CDN edge still hands
	// it the index before.
	created := map[string]time.Time{"1.0.0": t0.Add(-72 * time.Hour), "1.1.0": t0.Add(-2 * time.Minute)}
	srv.on("GET", "/index.yaml").requireHeader("User-Agent", "test").reply(200, helmCreatedIndex(map[string]time.Time{"1.0.0": created["1.0.0"]}, archives, t0.Add(-time.Hour)))
	srv.on("GET", "/index.yaml").requireHeader("User-Agent", "pullthrough-feed-test").reply(200, helmCreatedIndex(created, archives, t0.Add(-time.Minute))).once().
		withHeader("ETag", `"i0"`).withHeader("Last-Modified", t0.Add(-time.Minute).Format(http.TimeFormat)).withHeader("Date", date())
	backend := helmTestBackend(t, f.src.k.env)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[c]" {
		t.Fatalf("the first read: %v %v", names(b.Items), err)
	}
	if rels, err := f.Releases(ctx, "c"); err != nil || len(rels) != 1 || rels[0].Version != "1.0.0" {
		t.Fatalf("the first read lists 1.1.0: %+v %v", viewReleases(rels), err)
	}
	if err := helmBackendFetch(t, backend, "/-/c/1.1.0/c-1.1.0.tgz"); err == nil {
		t.Fatal("the premise: the backend served 1.1.0 from an index that does not list it")
	}
	// Ten minutes on: conditional, 304.
	clock = t0.Add(10 * time.Minute)
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", `"i0"`).reply(http.StatusNotModified, nil).once().withHeader("Date", date())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 {
		t.Fatalf("ten minutes on: %+v %v", ch, err)
	}
	// 1.1.0 has been listed for fifteen minutes (since t0 - 1m): the index is
	// read again although it did not change, and 1.1.0 is reported; the
	// backend's index has caught up, it serves the archive. 1.2.0, published
	// meanwhile, is first seen now.
	clock = t0.Add(14*time.Minute + time.Second)
	created["1.2.0"] = clock.Add(-time.Minute)
	srv.on("GET", "/index.yaml").requireHeader("User-Agent", "test").reply(200, helmCreatedIndex(created, archives, clock))
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", "").requireHeader("User-Agent", "pullthrough-feed-test").reply(200, helmCreatedIndex(created, archives, clock)).once().
		withHeader("ETag", `"i1"`).withHeader("Date", date())
	ch, err = f.Changes(ctx, ch.Next)
	if err != nil || fmt.Sprint(ch.Items) != "[c@1.1.0]" {
		t.Fatalf("1.1.0 settled: %+v %v", ch, err)
	}
	rels, err := f.Releases(ctx, "c")
	if err != nil || len(rels) != 2 {
		t.Fatalf("%+v %v", viewReleases(rels), err)
	}
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "c", r.Version })
	if err := helmBackendFetch(t, backend, rels[1].Artifacts[0].Path); err != nil {
		t.Errorf("1.1.0, once reported: %v", err)
	}
	clock = t0.Add(29*time.Minute + 2*time.Second)
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", "").requireHeader("User-Agent", "pullthrough-feed-test").reply(200, helmCreatedIndex(created, archives, clock)).once().
		withHeader("ETag", `"i1"`).withHeader("Date", date())
	if ch, err = f.Changes(ctx, ch.Next); err != nil || fmt.Sprint(ch.Items) != "[c@1.2.0]" {
		t.Fatalf("1.2.0 settled: %+v %v", ch, err)
	}
	srv.on("GET", "/index.yaml").requireHeader("If-None-Match", `"i1"`).reply(http.StatusNotModified, nil).once()
	if ch, err = f.Changes(ctx, ch.Next); err != nil || len(ch.Items) != 0 {
		t.Fatalf("nothing held: %+v %v", ch, err)
	}
}

// `helm repo index` without --merge stamps every entry with a new `created`:
// a repository whose CI regenerates its index so is reported only what was
// published, not every version again — nor are the versions it lists held
// back again for the settle period.
func TestHelmRegeneratedIndexReportsOnlyWhatChanged(t *testing.T) {
	for _, settle := range []string{"0", ""} {
		opts := map[string]string{"settle": settle}
		if settle == "" {
			opts = nil
		}
		f, srv := helmTestFeed(t, opts)
		charts := map[string][]string{"a": {"1.0.0", "1.1.0", "1.2.0"}, "b": {"0.1.0", "0.2.0"}, "c": {"3.0.0"}}
		srv.on("GET", "/index.yaml").reply(200, []byte(helmIndex(charts, ""))).withHeader("ETag", `"1"`)
		ctx := context.Background()
		b, err := f.Bootstrap(ctx, "")
		if err != nil || fmt.Sprint(names(b.Items)) != "[a b c]" {
			t.Fatalf("settle %q: %v %v", settle, names(b.Items), err)
		}
		charts["c"] = append(charts["c"], "3.1.0")
		regenerated := strings.ReplaceAll(helmIndex(charts, ""), "2026-01-02T03:04:05.123456789Z", time.Now().UTC().Format(time.RFC3339Nano))
		srv.on("GET", "/index.yaml").reply(200, []byte(regenerated)).withHeader("ETag", `"2"`)
		ch, err := f.Changes(ctx, b.Next)
		want := "[c@3.1.0]"
		if settle == "" {
			want = "[]" // 3.1.0 is held; the regenerated entries are not
		}
		if err != nil || fmt.Sprint(ch.Items) != want {
			t.Errorf("settle %q: one version published, %v reported (%v)", settle, ch.Items, err)
		}
		if rels, err := f.Releases(ctx, "a"); err != nil || len(rels) != 3 {
			t.Errorf("settle %q: the regenerated chart a: %+v %v", settle, viewReleases(rels), err)
		}
	}
}

// A null element of urls ("- ~", "- null") is read as the backend reads it —
// by its text, which the backend rewrites to a link it hands Helm — and an
// empty one is skipped, as the backend skips it: the feed mirrors the link the
// backend's rewritten index lists first.
func TestHelmNullURLsAreReadAsTheBackendReadsThem(t *testing.T) {
	for _, first := range []string{"~", "null", "NULL", "", `""`} {
		doc := "apiVersion: v1\nentries:\n  c:\n  - name: c\n    version: 1.0.0\n    urls:\n    -" + map[bool]string{true: "", false: " " + first}[first == ""] + "\n    - https://charts.example.com/c-1.0.0.tgz\n"
		var streamed []helmEntry
		if _, err := helmScanIndex(strings.NewReader(doc), func(e helmEntry) error { streamed = append(streamed, e); return nil }); err != nil {
			t.Fatalf("%q: %v", first, err)
		}
		whole, _, err := helmReadIndexWhole([]byte(doc))
		if err != nil || !reflect.DeepEqual(streamed, whole) || len(streamed) != 1 {
			t.Errorf("%q: streamed %+v, yaml.v3 %+v (%v)", first, streamed, whole, err)
			continue
		}
		f, srv := helmTestFeed(t, map[string]string{"settle": "0"})
		srv.on("GET", "/index.yaml").reply(200, []byte(doc))
		ctx := context.Background()
		if _, err := f.Bootstrap(ctx, ""); err != nil {
			t.Fatal(err)
		}
		rels, err := f.Releases(ctx, "c")
		if err != nil || len(rels) != 1 {
			t.Fatalf("%q: %+v %v", first, viewReleases(rels), err)
		}
		backend := helmTestBackend(t, f.src.k.env)
		res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: "/index.yaml", Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatal(err)
		}
		fr, err := backend.Fetch(ctx, res)
		if err != nil {
			t.Fatal(err)
		}
		rewritten, _ := io.ReadAll(fr.Content)
		fr.Content.Close()
		idx, err := helm.ParseIndex(rewritten)
		if err != nil {
			t.Fatal(err)
		}
		cv, ok := idx.FindVersion("c", "1.0.0")
		if !ok || len(cv.URLs) == 0 {
			t.Fatalf("%q: the rewritten index: %s", first, rewritten)
		}
		if p, ok := f.src.k.proxyPath(cv.URLs[0]); !ok || p != rels[0].Artifacts[0].Path {
			t.Errorf("%q: the backend hands Helm %s first (%s), the feed mirrors %s", first, cv.URLs[0], p, rels[0].Artifacts[0].Path)
		}
		expectServed(t, backend, rels, func(Release, Artifact) (string, string) { return "c", "1.0.0" })
	}
}
