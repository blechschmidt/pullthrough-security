package helm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// publicBase is the mount the backend under test is served at.
const publicBase = "https://proxy.example.com/v1/charts"

// repoSetup is a chart repository as real ones are laid out: the index on one
// host, and chart archives in the places an index puts them — on the
// repository's own host by absolute URL, next to the index by relative URL, on
// a different host altogether (the GitHub-Pages-index, release-asset layout),
// and in an OCI registry (the layout Bitnami's index uses).
type repoSetup struct {
	repo     *fakeRepo     // serves index.yaml and the repository's own archives
	cdn      *fakeRepo     // a different host, serving the externally hosted archives
	registry *fakeRegistry // an OCI registry holding charts as artifacts
}

// chart archive payloads, by the path they are served at.
var (
	sameHostChart = []byte("same-host chart archive")
	relativeChart = []byte("relative chart archive")
	foreignChart  = []byte("foreign-host chart archive")
	mirroredChart = []byte("mirrored chart archive")
	foreignProv   = []byte("-----BEGIN PGP SIGNED MESSAGE-----\nforeign prov\n")
)

// genuineDigest is the digest the index declares for the "tampered" charts: the
// hash of an archive nobody serves.
var genuineDigest = sha256Hex([]byte("the genuine archive"))

func newRepoSetup(t *testing.T) *repoSetup {
	t.Helper()
	s := &repoSetup{repo: newEmptyRepo(t), cdn: newEmptyRepo(t), registry: newFakeRegistry(t)}

	s.repo.put("/charts/samehost-1.0.0.tgz", sameHostChart)
	s.repo.put("/charts/relative-2.0.0.tgz", relativeChart)
	s.cdn.put("/releases/download/foreign-3.0.0/foreign-3.0.0.tgz", foreignChart)
	s.cdn.put("/releases/download/foreign-3.0.0/foreign-3.0.0.tgz.prov", foreignProv)
	// Served bytes that do not match the digest the index declares.
	s.cdn.put("/releases/tampered-6.6.6.tgz", []byte("TAMPERED ARCHIVE"))
	// A file the cdn has but the index never mentions.
	s.cdn.put("/private/unlisted-1.0.0.tgz", []byte("not for you"))
	// Only the second mirror has the archive.
	s.cdn.put("/mirror-b/mirrored-4.0.0.tgz", mirroredChart)

	s.registry.push("charts/ocihosted", "5.0.0", map[string][]byte{ociChartLayer: ociChart, ociProvenanceLayer: ociProv})
	s.registry.push("charts/ocibare", "5.1.0", map[string][]byte{ociChartLayer: ociChart})
	s.registry.push("charts/ocinotchart", "5.4.0", map[string][]byte{"application/vnd.example.other": []byte("not a chart")})
	s.registry.push("charts/ocitampered", "5.6.6", map[string][]byte{ociChartLayer: []byte("TAMPERED OCI LAYER")})
	corrupted := []byte("chart layer the registry will not serve intact")
	s.registry.push("charts/ocicorrupt", "5.7.0", map[string][]byte{ociChartLayer: corrupted})
	s.registry.corrupt("sha256:"+sha256Hex(corrupted), []byte("something else entirely"))

	s.repo.put("/index.yaml", []byte(s.index("")))
	return s
}

// renderEntry renders one chart with a single version; digest may be empty.
func renderEntry(chart, version, digest string, urls ...string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %s:\n  - name: %s\n    version: %s\n", chart, chart, version)
	if digest != "" {
		fmt.Fprintf(&sb, "    digest: %s\n", digest)
	}
	sb.WriteString("    urls:\n")
	for _, u := range urls {
		fmt.Fprintf(&sb, "    - %s\n", u)
	}
	return sb.String()
}

// index renders the repository index; extra is appended to the entries.
func (s *repoSetup) index(extra string) string {
	repo, cdn, oci := s.repo.srv.URL, s.cdn.srv.URL, "oci://"+s.registry.host()
	return "apiVersion: v1\nentries:\n" +
		renderEntry("samehost", "1.0.0", sha256Hex(sameHostChart), repo+"/charts/samehost-1.0.0.tgz") +
		renderEntry("relative", "2.0.0", sha256Hex(relativeChart), "charts/relative-2.0.0.tgz") +
		renderEntry("foreign", "3.0.0", sha256Hex(foreignChart), cdn+"/releases/download/foreign-3.0.0/foreign-3.0.0.tgz") +
		renderEntry("tampered", "6.6.6", genuineDigest, cdn+"/releases/tampered-6.6.6.tgz") +
		renderEntry("mirrored", "4.0.0", sha256Hex(mirroredChart), cdn+"/mirror-a/mirrored-4.0.0.tgz", cdn+"/mirror-b/mirrored-4.0.0.tgz") +
		renderEntry("ocihosted", "5.0.0", sha256Hex(ociChart), oci+"/charts/ocihosted:5.0.0") +
		renderEntry("ocibare", "5.1.0", sha256Hex(ociChart), oci+"/charts/ocibare:5.1.0") +
		renderEntry("ocipinned", "5.2.0", sha256Hex(ociChart), oci+"/charts/ocihosted@"+s.registry.manifestDigest("charts/ocihosted", "5.0.0")) +
		renderEntry("ocimissing", "5.3.0", "", oci+"/charts/ocimissing:5.3.0") +
		renderEntry("ocinotchart", "5.4.0", "", oci+"/charts/ocinotchart:5.4.0") +
		renderEntry("ocitagless", "5.5.0", "", oci+"/charts/ocitagless") +
		renderEntry("ocitampered", "5.6.6", genuineDigest, oci+"/charts/ocitampered:5.6.6") +
		renderEntry("ocicorrupt", "5.7.0", "", oci+"/charts/ocicorrupt:5.7.0") +
		renderEntry("unfetchable", "8.0.0", "", "ftp://files.example/unfetchable-8.0.0.tgz") +
		extra +
		"generated: \"2024-01-02T03:04:05Z\"\n"
}

// backend builds a classic-mode backend over the setup. The test servers listen
// on loopback; the client trusts the registry's test certificate and reaches
// the plain-HTTP hosts as any client would.
func (s *repoSetup) backend(t *testing.T, opts Options) *Backend {
	t.Helper()
	opts.Name = "charts"
	opts.UpstreamURL = s.repo.srv.URL
	if opts.Client == nil {
		opts.Client = upstream.NewWithHTTPClient(s.registry.srv.Client(), "test/1")
	}
	b, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// fetchPath resolves and fetches a path, returning the fully read body.
func fetchPath(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	return fetchAll(t, b, resolve(t, b, path))
}

// servedIndexURLs fetches the index through the backend and returns each
// entry's chart URLs, keyed "chart@version".
func servedIndexURLs(t *testing.T, b *Backend) map[string][]string {
	t.Helper()
	_, body, err := fetchPath(t, b, "/index.yaml")
	if err != nil {
		t.Fatalf("fetching the index: %v", err)
	}
	idx, err := ParseIndex(body)
	if err != nil {
		t.Fatalf("the served index does not parse: %v\n%s", err, body)
	}
	out := map[string][]string{}
	for chart, versions := range idx.Entries {
		for _, cv := range versions {
			out[chart+"@"+cv.Version] = cv.URLs
		}
	}
	return out
}

func TestIndexChartURLsLeadBackThroughThePublicBase(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	got := servedIndexURLs(t, b)
	want := map[string][]string{
		"samehost@1.0.0": {publicBase + "/-/samehost/1.0.0/samehost-1.0.0.tgz"},
		"relative@2.0.0": {publicBase + "/-/relative/2.0.0/relative-2.0.0.tgz"},
		"foreign@3.0.0":  {publicBase + "/-/foreign/3.0.0/foreign-3.0.0.tgz"},
		"tampered@6.6.6": {publicBase + "/-/tampered/6.6.6/tampered-6.6.6.tgz"},
		// Mirrors of one archive collapse onto one proxied URL.
		"mirrored@4.0.0": {publicBase + "/-/mirrored/4.0.0/mirrored-4.0.0.tgz", publicBase + "/-/mirrored/4.0.0/mirrored-4.0.0.tgz"},
		// An OCI reference is replaced like any URL; the link is named the way
		// Helm names a chart it pulled from a registry.
		"ocihosted@5.0.0": {publicBase + "/-/ocihosted/5.0.0/ocihosted-5.0.0.tgz"},
		"ocipinned@5.2.0": {publicBase + "/-/ocipinned/5.2.0/ocipinned-5.2.0.tgz"},
		// So is a location the backend will not be able to fetch.
		"unfetchable@8.0.0": {publicBase + "/-/unfetchable/8.0.0/unfetchable-8.0.0.tgz"},
	}
	for key, urls := range want {
		if strings.Join(got[key], " ") != strings.Join(urls, " ") {
			t.Errorf("%s: urls = %q, want %q", key, got[key], urls)
		}
	}
	for key, urls := range got {
		for _, u := range urls {
			if !strings.HasPrefix(u, publicBase+"/-/") {
				t.Errorf("%s: chart URL %q does not lead back through the proxy", key, u)
			}
		}
	}

	// No upstream host is left anywhere in the served document: there is nothing
	// in it that would send a client around the proxy.
	_, body, _ := fetchPath(t, b, "/index.yaml")
	for _, host := range []string{s.repo.srv.URL, s.cdn.srv.URL, s.registry.host(), "files.example"} {
		if strings.Contains(string(body), host) {
			t.Errorf("served index still mentions upstream host %s:\n%s", host, body)
		}
	}
}

// With no public URL configured the cmd wiring passes the root-relative mount
// ("/v1/<name>"); a library user may pass nothing at all. Either way the index
// is still rewritten — to references relative to the repository URL, which a
// Helm client resolves against the URL it added the repository under.
func TestIndexChartURLsFallBackToRelativeReferences(t *testing.T) {
	for _, base := range []string{"", "/v1/charts", "proxy.example.com/v1/charts"} {
		t.Run("base="+base, func(t *testing.T) {
			s := newRepoSetup(t)
			b := s.backend(t, Options{PublicBaseURL: base})

			got := servedIndexURLs(t, b)
			want := map[string]string{
				"samehost@1.0.0": "-/samehost/1.0.0/samehost-1.0.0.tgz",
				"relative@2.0.0": "-/relative/2.0.0/relative-2.0.0.tgz",
				"foreign@3.0.0":  "-/foreign/3.0.0/foreign-3.0.0.tgz",
			}
			for key, link := range want {
				if len(got[key]) != 1 || got[key][0] != link {
					t.Errorf("%s: urls = %q, want [%q]", key, got[key], link)
				}
			}

			// Resolved the way Helm resolves a relative chart URL (against the
			// repository URL taken as a directory), each lands on this mount...
			repoURL, _ := url.Parse("http://proxy.internal:8080/some/prefix/v1/charts/")
			for key, link := range want {
				ref, err := url.Parse(link)
				if err != nil {
					t.Fatalf("%s: %v", key, err)
				}
				abs := repoURL.ResolveReference(ref)
				if abs.Host != repoURL.Host || !strings.HasPrefix(abs.Path, repoURL.Path+"-/") {
					t.Errorf("%s: %q resolves to %s, outside the mount", key, link, abs)
				}
				// ...and the path under the mount is one the backend serves.
				_, body, err := fetchPath(t, b, strings.TrimPrefix(abs.Path, strings.TrimSuffix(repoURL.Path, "/")))
				if err != nil || len(body) == 0 {
					t.Errorf("%s: fetching %s through the backend: %v", key, abs, err)
				}
			}
		})
	}
}

func TestIndexedArchiveResolvesToACacheableCoordinate(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	res := resolve(t, b, "/-/foreign/3.0.0/foreign-3.0.0.tgz")
	if res.Coordinate != (backends.Coordinate{Name: "foreign", Version: "3.0.0"}) {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error("an index-resolved archive must be cacheable")
	}
	if res.CacheKey != "charts:-/foreign/3.0.0/foreign-3.0.0.tgz" {
		t.Errorf("cache key = %q", res.CacheKey)
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error("an index-resolved archive must be flagged for verification")
	}
	// The content gates read the artifact's filename off the upstream locator.
	if got := res.UpstreamURL; got != s.repo.srv.URL+"/index.yaml#foreign/3.0.0/foreign-3.0.0.tgz" {
		t.Errorf("upstream locator = %q", got)
	}
	// Resolve performs no I/O (sealed mode relies on that).
	if n := s.repo.servedCount("/index.yaml") + s.cdn.servedCount("/releases/download/foreign-3.0.0/foreign-3.0.0.tgz"); n != 0 {
		t.Errorf("Resolve made %d upstream requests", n)
	}

	// The coordinate is the index's own: no filename heuristic is involved, so a
	// name the heuristic would split wrongly ("foo-2go" reads as chart "foo",
	// version "2go-1.0.0") is carried intact.
	res = resolve(t, b, "/-/foo-2go/1.0.0/foo-2go-1.0.0.tgz")
	if res.Coordinate != (backends.Coordinate{Name: "foo-2go", Version: "1.0.0"}) {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}

	// A write is never cacheable.
	post, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodPost, Path: "/-/foreign/3.0.0/foreign-3.0.0.tgz"})
	if err != nil || post.Cacheable {
		t.Errorf("POST: cacheable=%v err=%v", post != nil && post.Cacheable, err)
	}
}

// The three places an index puts an archive: each is fetched from the location
// the index records and verified against the digest the index declares.
func TestIndexedArchiveIsFetchedFromTheListedLocation(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		host     func(*repoSetup) *fakeRepo
		upstream string
		want     []byte
	}{
		{"same host, absolute URL", "/-/samehost/1.0.0/samehost-1.0.0.tgz",
			func(s *repoSetup) *fakeRepo { return s.repo }, "/charts/samehost-1.0.0.tgz", sameHostChart},
		{"relative URL", "/-/relative/2.0.0/relative-2.0.0.tgz",
			func(s *repoSetup) *fakeRepo { return s.repo }, "/charts/relative-2.0.0.tgz", relativeChart},
		{"different host", "/-/foreign/3.0.0/foreign-3.0.0.tgz",
			func(s *repoSetup) *fakeRepo { return s.cdn }, "/releases/download/foreign-3.0.0/foreign-3.0.0.tgz", foreignChart},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newRepoSetup(t)
			m := &Metrics{}
			b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

			fres, body, err := fetchPath(t, b, tc.path)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if string(body) != string(tc.want) {
				t.Errorf("served bytes = %q, want %q", body, tc.want)
			}
			host := tc.host(s)
			if n := host.servedCount(tc.upstream); n != 1 {
				t.Errorf("upstream %s was fetched %d times, want 1", tc.upstream, n)
			}
			if got := fres.Resolved.Metadata[MetaArchiveURL]; got != host.srv.URL+tc.upstream {
				t.Errorf("recorded archive URL = %q, want %q", got, host.srv.URL+tc.upstream)
			}
			if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" || fres.Header.Get("X-Checksum-Verified") != "sha256" {
				t.Errorf("archive not marked verified: metadata=%q header=%q",
					fres.Resolved.Metadata[MetaChecksumVerified], fres.Header.Get("X-Checksum-Verified"))
			}
			if st := m.Stats(); st.ChartsVerified != 1 || st.ChecksumMismatch != 0 {
				t.Errorf("metrics = %+v", st)
			}
		})
	}
}

func TestIndexedArchiveDigestMismatchIsRefused(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	_, _, err := fetchPath(t, b, "/-/tampered/6.6.6/tampered-6.6.6.tgz")
	var mismatch *ChecksumMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected a ChecksumMismatchError, got %v", err)
	}
	if mismatch.Expected != "sha256:"+genuineDigest {
		t.Errorf("mismatch expected digest = %s", mismatch.Expected)
	}
	if !strings.HasPrefix(mismatch.URL, s.cdn.srv.URL) {
		t.Errorf("mismatch names %q, want the URL actually fetched", mismatch.URL)
	}
	if st := m.Stats(); st.ChecksumMismatch != 1 || st.ChartsVerified != 0 {
		t.Errorf("metrics = %+v", st)
	}
}

// The backend fetches only what the upstream index lists for the requested
// chart name and version. Anything else is refused without a single request to
// an archive host — the request path never becomes part of an upstream URL.
func TestIndexedRequestForSomethingUnlistedIsRefused(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	for _, path := range []string{
		"/-/foreign/9.9.9/foreign-9.9.9.tgz",      // version the index does not list
		"/-/nosuchchart/3.0.0/foreign-3.0.0.tgz",  // chart the index does not list
		"/-/foreign/3.0.0/unlisted-1.0.0.tgz",     // a file that entry does not list
		"/-/samehost/1.0.0/foreign-3.0.0.tgz",     // another entry's file
		"/-/unlisted/1.0.0/unlisted-1.0.0.tgz",    // exists on the cdn, absent from the index
		"/-/foreign/3.0.0/foreign-9.9.9.tgz.prov", // provenance of an unlisted file
	} {
		_, _, err := fetchPath(t, b, path)
		se, ok := backends.AsStatusError(err)
		if !ok || se.Status != http.StatusNotFound {
			t.Errorf("%s: expected a 404 StatusError, got %v", path, err)
		}
	}
	for path, n := range s.cdn.servedPaths() {
		t.Errorf("an unlisted request reached the archive host: %s fetched %d times", path, n)
	}
	for path, n := range s.repo.servedPaths() {
		if path != "/index.yaml" {
			t.Errorf("an unlisted request reached the repository host: %s fetched %d times", path, n)
		}
	}

	// Paths under the reserved prefix that are not <chart>/<version>/<file> are
	// not resources at all.
	for _, path := range []string{
		"/-", "/-/", "/-/foreign", "/-/foreign/3.0.0", "/-/foreign/3.0.0/a/b.tgz",
		"/-/unaddressable-entry", "/-/foreign/../foreign-3.0.0.tgz", "/-/a\\b/1.0.0/x.tgz",
	} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q): expected ErrNotSupported, got %v", path, err)
		}
	}
}

// An entry may list mirrors; they are tried in the index's order.
func TestIndexedArchiveFallsBackToTheNextListedMirror(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	fres, body, err := fetchPath(t, b, "/-/mirrored/4.0.0/mirrored-4.0.0.tgz")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(mirroredChart) {
		t.Errorf("served bytes = %q", body)
	}
	if got := fres.Resolved.Metadata[MetaArchiveURL]; got != s.cdn.srv.URL+"/mirror-b/mirrored-4.0.0.tgz" {
		t.Errorf("recorded archive URL = %q, want the second mirror", got)
	}

	// When every listed location fails, the upstream's answer is relayed.
	s.cdn.remove("/mirror-b/mirrored-4.0.0.tgz")
	_, _, err = fetchPath(t, b, "/-/mirrored/4.0.0/mirrored-4.0.0.tgz")
	if se, ok := backends.AsStatusError(err); !ok || se.Status != http.StatusNotFound {
		t.Errorf("expected the upstream 404 to be relayed, got %v", err)
	}
}

func TestIndexedProvenanceFollowsTheArchive(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	res := resolve(t, b, "/-/foreign/3.0.0/foreign-3.0.0.tgz.prov")
	if res.Coordinate != (backends.Coordinate{Name: "foreign", Version: "3.0.0"}) || !res.Cacheable {
		t.Errorf("provenance: coordinate=%+v cacheable=%v", res.Coordinate, res.Cacheable)
	}
	if res.Metadata[MetaProvenance] != "1" || res.Metadata[metaVerify] == "1" {
		t.Errorf("provenance flags wrong: %v", res.Metadata)
	}
	if res.CacheKey != "charts:-/foreign/3.0.0/foreign-3.0.0.tgz.prov" {
		t.Errorf("cache key = %q", res.CacheKey)
	}

	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(foreignProv) {
		t.Errorf("served provenance = %q", body)
	}
	if m.Stats().ProvenanceServed != 1 {
		t.Errorf("ProvenanceServed = %v, want 1", m.Stats().ProvenanceServed)
	}

	// An archive published without provenance has none through the proxy either.
	_, _, err = fetchPath(t, b, "/-/samehost/1.0.0/samehost-1.0.0.tgz.prov")
	if se, ok := backends.AsStatusError(err); !ok || se.Status != http.StatusNotFound {
		t.Errorf("expected a 404 for a missing sidecar, got %v", err)
	}
}

// The repository's credentials go to the repository, never to another host an
// index entry happens to point at.
func TestCredentialsAreOnlySentToTheUpstreamHost(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{
		PublicBaseURL: publicBase,
		Credentials:   upstream.Credentials{Token: "repo-secret"},
	})

	for _, path := range []string{
		"/-/samehost/1.0.0/samehost-1.0.0.tgz",
		"/-/relative/2.0.0/relative-2.0.0.tgz",
		"/-/foreign/3.0.0/foreign-3.0.0.tgz",
		"/-/foreign/3.0.0/foreign-3.0.0.tgz.prov",
	} {
		if _, _, err := fetchPath(t, b, path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	for _, path := range []string{"/index.yaml", "/charts/samehost-1.0.0.tgz", "/charts/relative-2.0.0.tgz"} {
		if got := s.repo.authSeen(path); got != "Bearer repo-secret" {
			t.Errorf("repository %s: Authorization = %q, want the upstream credentials", path, got)
		}
	}
	for _, path := range []string{
		"/releases/download/foreign-3.0.0/foreign-3.0.0.tgz",
		"/releases/download/foreign-3.0.0/foreign-3.0.0.tgz.prov",
	} {
		if got := s.cdn.authSeen(path); got != "" {
			t.Errorf("foreign host %s was sent Authorization %q", path, got)
		}
	}
}

// The backend fetches over the transports a Helm client would use for a chart:
// HTTP(S) and OCI. A location with any other scheme is still rewritten in the
// index (the client must not be left to fetch it directly), and refused when
// asked for.
func TestIndexedArchiveAtAnUnfetchableLocationIsRefused(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	_, _, err := fetchPath(t, b, "/-/unfetchable/8.0.0/unfetchable-8.0.0.tgz")
	if err == nil {
		t.Fatal("expected an error for an ftp:// location")
	}
	if _, isStatus := backends.AsStatusError(err); isStatus {
		t.Errorf("expected a descriptive error rather than an upstream status, got %v", err)
	}
	for _, want := range []string{"ftp://files.example/unfetchable-8.0.0.tgz", `chart "unfetchable" version "8.0.0"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

// The upstream index is parsed once per change, however often the index is
// served and however many archives are resolved against it.
func TestIndexIsParsedOncePerUpstreamChange(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	for i := 0; i < 3; i++ {
		if _, _, err := fetchPath(t, b, "/index.yaml"); err != nil {
			t.Fatalf("index fetch %d: %v", i, err)
		}
	}
	for _, path := range []string{
		"/-/samehost/1.0.0/samehost-1.0.0.tgz",
		"/-/relative/2.0.0/relative-2.0.0.tgz",
		"/-/foreign/3.0.0/foreign-3.0.0.tgz",
		"/charts/samehost-1.0.0.tgz", // the repository-relative form shares the same copy
	} {
		if _, _, err := fetchPath(t, b, path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if got := m.Stats().IndexParsed; got != 1 {
		t.Errorf("IndexParsed = %v, want 1", got)
	}
	// The index was downloaded once; every later index request revalidated it
	// with a conditional request, and the archive fetches reused the copy.
	if got := s.repo.servedCount("/index.yaml"); got != 1 {
		t.Errorf("the upstream index was downloaded %d times, want 1", got)
	}
	if got := s.repo.revalidatedCount("/index.yaml"); got != 2 {
		t.Errorf("the upstream index was revalidated %d times, want 2", got)
	}

	// A change upstream is picked up by the next index request.
	s.repo.put("/index.yaml", []byte(s.index("")+"# republished\n"))
	if _, _, err := fetchPath(t, b, "/index.yaml"); err != nil {
		t.Fatalf("index fetch after change: %v", err)
	}
	if got := m.Stats().IndexParsed; got != 2 {
		t.Errorf("IndexParsed after an upstream change = %v, want 2", got)
	}
}

// An upstream that offers no validators resends the whole index every time. The
// unchanged document is recognized by its hash and not parsed again.
func TestUnchangedIndexWithoutValidatorsIsNotReparsed(t *testing.T) {
	s := newRepoSetup(t)
	s.repo.noValidators = true
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	var first []byte
	for i := 0; i < 3; i++ {
		_, body, err := fetchPath(t, b, "/index.yaml")
		if err != nil {
			t.Fatalf("index fetch %d: %v", i, err)
		}
		if first == nil {
			first = body
		} else if string(body) != string(first) {
			t.Errorf("index fetch %d served a different document", i)
		}
	}
	if got := s.repo.servedCount("/index.yaml"); got != 3 {
		t.Errorf("the upstream index was downloaded %d times, want 3", got)
	}
	if got := m.Stats().IndexParsed; got != 1 {
		t.Errorf("IndexParsed = %v, want 1", got)
	}
}

// Archive lookups share one revalidation of the index for a short while, but a
// request for an entry the copy at hand does not have revalidates before it is
// refused — a version published a moment ago must be found.
func TestIndexedLookupRevalidatesBeforeRefusing(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})
	clock := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	b.now = func() time.Time { return clock }

	if _, _, err := fetchPath(t, b, "/-/foreign/3.0.0/foreign-3.0.0.tgz"); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	requests := func() int { return s.repo.servedCount("/index.yaml") + s.repo.revalidatedCount("/index.yaml") }
	if got := requests(); got != 1 {
		t.Fatalf("index requests after the first fetch = %d, want 1", got)
	}

	// Within the window a listed entry is resolved from the copy at hand.
	clock = clock.Add(indexLookupMaxAge / 2)
	if _, _, err := fetchPath(t, b, "/-/samehost/1.0.0/samehost-1.0.0.tgz"); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := requests(); got != 1 {
		t.Errorf("index requests within the window = %d, want still 1", got)
	}

	// The upstream publishes a new version; the copy at hand predates it.
	fresh := []byte("freshly published archive")
	s.repo.put("/charts/fresh-7.0.0.tgz", fresh)
	s.repo.put("/index.yaml", []byte(s.index(fmt.Sprintf(
		"  fresh:\n  - name: fresh\n    version: 7.0.0\n    digest: %s\n    urls:\n    - charts/fresh-7.0.0.tgz\n", sha256Hex(fresh)))))
	clock = clock.Add(time.Second)
	_, body, err := fetchPath(t, b, "/-/fresh/7.0.0/fresh-7.0.0.tgz")
	if err != nil {
		t.Fatalf("fetching the freshly published version: %v", err)
	}
	if string(body) != string(fresh) {
		t.Errorf("served bytes = %q", body)
	}

	// Past the window the copy is revalidated even for a listed entry.
	before := requests()
	clock = clock.Add(indexLookupMaxAge + time.Second)
	if _, _, err := fetchPath(t, b, "/-/relative/2.0.0/relative-2.0.0.tgz"); err != nil {
		t.Fatalf("fetch past the window: %v", err)
	}
	if got := requests(); got != before+1 {
		t.Errorf("index requests past the window = %d, want %d", got, before+1)
	}
}

// An index the backend cannot fully account for is refused, not passed through:
// served as-is it could carry a chart URL that was not rewritten.
func TestIndexThatCannotBeRewrittenIsRefused(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	// A Helm client honors the alias and would download from evil.example.
	smuggled := "apiVersion: v1\nserverInfo:\n  x: &u [https://evil.example/c-1.0.0.tgz]\n" +
		"entries:\n  c:\n  - name: c\n    version: 1.0.0\n    urls: *u\n"
	s.repo.put("/index.yaml", []byte(smuggled))

	for i := 0; i < 2; i++ {
		fres, body, err := fetchPath(t, b, "/index.yaml")
		if err == nil {
			t.Fatalf("the index was served: %q", body)
		}
		if fres != nil {
			t.Error("no result expected alongside the error")
		}
		if _, isStatus := backends.AsStatusError(err); isStatus {
			t.Errorf("expected a refusal, not an upstream status: %v", err)
		}
	}
	// The refusal is remembered for the unchanged document: it is parsed once.
	if st := m.Stats(); st.IndexErrors != 1 || st.IndexParsed != 0 || st.IndexServed != 0 {
		t.Errorf("metrics = %+v", st)
	}
	// Nothing can be resolved against it either.
	if _, _, err := fetchPath(t, b, "/-/c/1.0.0/c-1.0.0.tgz"); err == nil {
		t.Error("an archive was resolved against a refused index")
	}

	// Once the upstream publishes a sound index again, it is served.
	s.repo.put("/index.yaml", []byte(s.index("")))
	if _, _, err := fetchPath(t, b, "/index.yaml"); err != nil {
		t.Errorf("a sound index was not served after a refused one: %v", err)
	}
}

func TestIndexUpstreamErrorsAreRelayed(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})
	s.repo.remove("/index.yaml")

	for _, path := range []string{"/index.yaml", "/-/foreign/3.0.0/foreign-3.0.0.tgz"} {
		_, _, err := fetchPath(t, b, path)
		if se, ok := backends.AsStatusError(err); !ok || se.Status != http.StatusNotFound {
			t.Errorf("%s: expected the upstream 404, got %v", path, err)
		}
	}
	if n := s.cdn.servedCount("/releases/download/foreign-3.0.0/foreign-3.0.0.tgz"); n != 0 {
		t.Errorf("an archive was fetched without an index to resolve it against (%d requests)", n)
	}
}

// The served index carries its own validator: the upstream's ETag names the
// upstream's bytes, not the rewritten ones.
func TestIndexConditionalRequests(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	fres, body, err := fetchPath(t, b, "/index.yaml")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	etag := fres.Header.Get("ETag")
	if etag == "" || etag == `"`+sha256Hex(s.repo.file("/index.yaml"))[:16]+`"` {
		t.Fatalf("served ETag %q must be set and must not be the upstream's", etag)
	}
	if fres.Size != int64(len(body)) {
		t.Errorf("declared size %d, served %d bytes", fres.Size, len(body))
	}

	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		res := resolve(t, b, "/index.yaml")
		res.IfNoneMatch = inm
		fres, err := b.Fetch(context.Background(), res)
		if err != nil || !fres.NotModified || fres.Content != nil {
			t.Errorf("If-None-Match %q: notModified=%v err=%v", inm, fres != nil && fres.NotModified, err)
		}
	}

	// A stale validator gets the document; so does a client holding the
	// upstream's ETag for the upstream's (unrewritten) bytes.
	for _, inm := range []string{`"stale"`, `"` + sha256Hex(s.repo.file("/index.yaml"))[:16] + `"`} {
		res := resolve(t, b, "/index.yaml")
		res.IfNoneMatch = inm
		if _, body, err := fetchAll(t, b, res); err != nil || len(body) == 0 {
			t.Errorf("If-None-Match %q: expected the document, got %d bytes, err=%v", inm, len(body), err)
		}
	}

	// The same upstream document under a different public base is a different
	// representation and must not share a validator.
	other := s.backend(t, Options{PublicBaseURL: "https://other.example.com/v1/charts"})
	ofres, _, err := fetchPath(t, other, "/index.yaml")
	if err != nil {
		t.Fatalf("fetch via the other base: %v", err)
	}
	if ofres.Header.Get("ETag") == etag {
		t.Error("two different rewritten documents share an ETag")
	}
}

// Only the repository's own index is rewritten. An index.yaml deeper in the
// tree belongs to some other repository and is proxied as it always was.
func TestNestedIndexIsProxiedUnchanged(t *testing.T) {
	s := newRepoSetup(t)
	nested := []byte("apiVersion: v1\nentries:\n  n:\n  - version: 1.0.0\n    urls: [https://elsewhere.example/n-1.0.0.tgz]\n")
	s.repo.put("/stable/index.yaml", nested)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	res := resolve(t, b, "/stable/index.yaml")
	if res.Cacheable || res.UpstreamURL != s.repo.srv.URL+"/stable/index.yaml" {
		t.Errorf("nested index: cacheable=%v upstream=%q", res.Cacheable, res.UpstreamURL)
	}
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(nested) {
		t.Errorf("nested index was modified: %q", body)
	}
}

// Requests by repository-relative path — what a client derives from an index
// with relative URLs, and the only form that existed before the rewrite — keep
// working alongside the index-resolved form.
func TestRepositoryRelativePathsKeepWorking(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	res := resolve(t, b, "/charts/relative-2.0.0.tgz")
	if res.UpstreamURL != s.repo.srv.URL+"/charts/relative-2.0.0.tgz" || !res.Cacheable ||
		res.Coordinate != (backends.Coordinate{Name: "relative", Version: "2.0.0"}) {
		t.Errorf("resolved = %+v", res)
	}
	fres, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(relativeChart) || fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("body=%q verified=%q", body, fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChartsVerified != 1 {
		t.Errorf("ChartsVerified = %v, want 1", m.Stats().ChartsVerified)
	}
}

// Many clients at once: the index is refreshed by one of them at a time and
// every one is served the same document.
func TestConcurrentIndexAndArchiveRequests(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers*4)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for _, path := range []string{
				"/index.yaml",
				"/-/foreign/3.0.0/foreign-3.0.0.tgz",
				"/-/relative/2.0.0/relative-2.0.0.tgz",
				"/charts/samehost-1.0.0.tgz",
			} {
				res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path})
				if err != nil {
					errs <- fmt.Errorf("worker %d: resolve %s: %w", i, path, err)
					continue
				}
				if _, body, err := fetchAll(t, b, res); err != nil || len(body) == 0 {
					errs <- fmt.Errorf("worker %d: fetch %s: %d bytes, %v", i, path, len(body), err)
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := m.Stats().IndexParsed; got != 1 {
		t.Errorf("IndexParsed = %v, want 1", got)
	}
	if got := s.repo.servedCount("/index.yaml"); got != 1 {
		t.Errorf("the upstream index was downloaded %d times, want 1", got)
	}
}

// A caller that gives up while another request is refreshing the index is
// released instead of waiting the refresh out.
func TestIndexRefreshWaitHonorsCancellation(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	b.indexRefresh <- struct{}{} // a refresh is in flight
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := resolve(t, b, "/index.yaml")
	if _, err := b.Fetch(ctx, res); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	<-b.indexRefresh

	if _, _, err := fetchPath(t, b, "/index.yaml"); err != nil {
		t.Errorf("fetch after the refresh finished: %v", err)
	}
}

// OCI mode is a different protocol and ignores the public base entirely.
func TestOCIModeIsUnaffectedByThePublicBase(t *testing.T) {
	b, err := New(Options{
		Name:          "ocicharts",
		UpstreamURL:   "https://registry-1.docker.io",
		PublicBaseURL: publicBase,
		Client:        upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		OCI:           true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet, Path: "/v2/library/nginx/manifests/1.2.3", Query: url.Values{},
	})
	if err != nil || res.Coordinate.Name != "library/nginx" || res.Metadata[metaOCI] != "1" {
		t.Errorf("OCI resolve: res=%+v err=%v", res, err)
	}
	// A classic-mode path means nothing to a registry.
	if _, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/index.yaml"}); !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("OCI mode resolved a chart-repository path: %v", err)
	}
}
