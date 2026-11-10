package helm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// fakeRepo is an in-memory classic Helm chart repository serving index.yaml,
// chart .tgz archives, and .prov provenance sidecars. It honors conditional
// requests the way a static host does, and records what it was asked for.
type fakeRepo struct {
	srv *httptest.Server

	mu    sync.Mutex
	files map[string][]byte
	// served counts the requests answered with a body, per path; revalidated
	// counts those answered 304 Not Modified.
	served      map[string]int
	revalidated map[string]int
	// auth records the Authorization header of the last request, per path.
	auth map[string]string
	// noValidators makes the host ignore conditional requests (it sends no ETag
	// and always answers with the full body).
	noValidators bool
}

// handler serves fr.files.
func (fr *fakeRepo) handler(w http.ResponseWriter, r *http.Request) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.auth[r.URL.Path] = r.Header.Get("Authorization")
	body, ok := fr.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !fr.noValidators {
		etag := `"` + sha256Hex(body)[:16] + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			fr.revalidated[r.URL.Path]++
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	fr.served[r.URL.Path]++
	_, _ = w.Write(body)
}

// put publishes (or replaces) a file.
func (fr *fakeRepo) put(path string, body []byte) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.files[path] = body
}

// remove unpublishes a file.
func (fr *fakeRepo) remove(path string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	delete(fr.files, path)
}

// file returns a published file.
func (fr *fakeRepo) file(path string) []byte {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.files[path]
}

// servedPaths returns every path answered with a body, with its request count.
func (fr *fakeRepo) servedPaths() map[string]int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	out := make(map[string]int, len(fr.served))
	for path, n := range fr.served {
		out[path] = n
	}
	return out
}

// servedCount reports how many requests for path were answered with a body.
func (fr *fakeRepo) servedCount(path string) int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.served[path]
}

// revalidatedCount reports how many requests for path were answered 304.
func (fr *fakeRepo) revalidatedCount(path string) int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.revalidated[path]
}

// authSeen returns the Authorization header of the last request for path.
func (fr *fakeRepo) authSeen(path string) string {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.auth[path]
}

// newEmptyRepo starts a fake repository host with no files.
func newEmptyRepo(t *testing.T) *fakeRepo {
	t.Helper()
	fr := &fakeRepo{
		files:       map[string][]byte{},
		served:      map[string]int{},
		revalidated: map[string]int{},
		auth:        map[string]string{},
	}
	fr.srv = httptest.NewServer(http.HandlerFunc(fr.handler))
	t.Cleanup(fr.srv.Close)
	return fr
}

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	fr := newEmptyRepo(t)

	// A good chart whose index digest matches its bytes.
	good := []byte("fake nginx chart tarball payload")
	fr.files["/nginx-1.2.3.tgz"] = good

	// A poisoned chart: the index digest names a different artifact's hash.
	poison := []byte("POISONED CHART PAYLOAD")
	fr.files["/evil-9.9.9.tgz"] = poison

	// A chart with a hyphenated name (heuristic split would mis-parse, but the
	// index URL match recovers it authoritatively).
	hyph := []byte("kube-state-metrics chart payload")
	fr.files["/kube-state-metrics-5.0.1.tgz"] = hyph

	// A chart that the index does not list a digest for (fail-open).
	nosum := []byte("chart without a published digest")
	fr.files["/nodigest-1.0.0.tgz"] = nosum

	// A provenance sidecar for the good chart.
	fr.files["/nginx-1.2.3.tgz.prov"] = []byte("-----BEGIN PGP SIGNED MESSAGE-----\nfake prov\n")

	index := fmt.Sprintf(`apiVersion: v1
entries:
  nginx:
    - name: nginx
      version: 1.2.3
      appVersion: "1.25.3"
      digest: %s
      urls:
        - nginx-1.2.3.tgz
  evil:
    - name: evil
      version: 9.9.9
      digest: %s
      urls:
        - evil-9.9.9.tgz
  kube-state-metrics:
    - name: kube-state-metrics
      version: 5.0.1
      digest: %s
      urls:
        - https://charts.example.com/kube-state-metrics-5.0.1.tgz
  nodigest:
    - name: nodigest
      version: 1.0.0
      urls:
        - nodigest-1.0.0.tgz
generated: "2024-01-02T03:04:05Z"
`, sha256Hex(good), sha256Hex([]byte("the real untampered chart")), sha256Hex(hyph))
	fr.files["/index.yaml"] = []byte(index)
	return fr
}

func testBackend(t *testing.T, fr *fakeRepo, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "charts",
		UpstreamURL: fr.srv.URL,
		Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:     m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolve(t *testing.T, b *Backend, path string) *backends.Resolved {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	return res
}

func fetchAll(t *testing.T, b *Backend, res *backends.Resolved) (*backends.FetchResult, []byte, error) {
	t.Helper()
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	if fr.Content == nil {
		return fr, nil, nil
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	return fr, body, rerr
}

func TestResolveAttachesCoordinate(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	res := resolve(t, b, "/nginx-1.2.3.tgz")
	if res.Coordinate.Name != "nginx" || res.Coordinate.Version != "1.2.3" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error("chart should be cacheable")
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error("chart should be flagged for verification")
	}
}

func TestResolveIndexNotCacheable(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	res := resolve(t, b, "/index.yaml")
	if res.Cacheable {
		t.Error("index.yaml must not be cacheable")
	}
	if res.Coordinate.Name != "" {
		t.Errorf("index carries no coordinate, got %+v", res.Coordinate)
	}
}

func TestResolveProvenanceCacheable(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	res := resolve(t, b, "/nginx-1.2.3.tgz.prov")
	if !res.Cacheable {
		t.Error("provenance should be cacheable")
	}
	if res.Metadata[MetaProvenance] != "1" {
		t.Error("provenance flag not set")
	}
	if res.Coordinate.Name != "nginx" || res.Coordinate.Version != "1.2.3" {
		t.Errorf("provenance coordinate = %+v", res.Coordinate)
	}
	if res.Metadata[metaVerify] == "1" {
		t.Error("provenance must not be checksum-verified as a chart")
	}
}

func TestResolveRejectsNonHelmPath(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	for _, p := range []string{"/not/a/chart", "/foo.txt", "/", "/charts/../etc/passwd.tgz"} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q): expected ErrNotSupported, got %v", p, err)
		}
	}
}

func TestFetchChartVerifiesChecksum(t *testing.T) {
	fr := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, fr, m)

	res := resolve(t, b, "/nginx-1.2.3.tgz")
	fres, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch+read: %v", err)
	}
	if string(body) != string(fr.files["/nginx-1.2.3.tgz"]) {
		t.Error("served chart bytes differ from upstream")
	}
	if m.Stats().ChartsVerified != 1 {
		t.Errorf("ChartsVerified = %v, want 1", m.Stats().ChartsVerified)
	}
	if fres.Header.Get("X-Checksum-Verified") != "sha256" {
		t.Errorf("X-Checksum-Verified = %q", fres.Header.Get("X-Checksum-Verified"))
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
}

func TestFetchHyphenatedChartVerifies(t *testing.T) {
	fr := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, fr, m)

	// The index URL is absolute; FindByFilename must match on the basename to
	// recover the digest even though the chart name contains hyphens.
	res := resolve(t, b, "/kube-state-metrics-5.0.1.tgz")
	if res.Coordinate.Name != "kube-state-metrics" || res.Coordinate.Version != "5.0.1" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(fr.files["/kube-state-metrics-5.0.1.tgz"]) {
		t.Error("served bytes differ")
	}
	if m.Stats().ChartsVerified != 1 {
		t.Errorf("ChartsVerified = %v, want 1", m.Stats().ChartsVerified)
	}
}

func TestFetchPoisonedChartFailsClosed(t *testing.T) {
	fr := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, fr, m)

	res := resolve(t, b, "/evil-9.9.9.tgz")
	_, _, err := fetchAll(t, b, res)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
}

func TestFetchChartWithoutDigest(t *testing.T) {
	fr := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, fr, m)

	res := resolve(t, b, "/nodigest-1.0.0.tgz")
	fres, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(fr.files["/nodigest-1.0.0.tgz"]) {
		t.Error("served bytes differ")
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("ChecksumMissing = %v, want 1", m.Stats().ChecksumMissing)
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
}

func TestFetchIndexServedLive(t *testing.T) {
	fr := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, fr, m)

	res := resolve(t, b, "/index.yaml")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch index: %v", err)
	}
	if m.Stats().IndexServed != 1 {
		t.Errorf("IndexServed = %v, want 1", m.Stats().IndexServed)
	}

	// The index is served with its chart URLs rewritten and nothing else touched:
	// putting the upstream's URLs back must reproduce the upstream document byte
	// for byte. (With no public base the links are relative references.)
	restored := string(body)
	for link, upstreamURL := range map[string]string{
		`"-/nginx/1.2.3/nginx-1.2.3.tgz"`:                           "nginx-1.2.3.tgz",
		`"-/evil/9.9.9/evil-9.9.9.tgz"`:                             "evil-9.9.9.tgz",
		`"-/kube-state-metrics/5.0.1/kube-state-metrics-5.0.1.tgz"`: "https://charts.example.com/kube-state-metrics-5.0.1.tgz",
		`"-/nodigest/1.0.0/nodigest-1.0.0.tgz"`:                     "nodigest-1.0.0.tgz",
	} {
		if strings.Count(restored, link) != 1 {
			t.Errorf("served index should contain %s exactly once:\n%s", link, body)
		}
		restored = strings.Replace(restored, link, upstreamURL, 1)
	}
	if restored != string(fr.file("/index.yaml")) {
		t.Errorf("served index differs from the upstream beyond its chart URLs:\n%s", body)
	}

	// It is live: a change upstream shows on the next request.
	fr.put("/index.yaml", []byte("apiVersion: v1\nentries: {}\n"))
	_, body, err = fetchAll(t, b, resolve(t, b, "/index.yaml"))
	if err != nil {
		t.Fatalf("fetch updated index: %v", err)
	}
	if string(body) != "apiVersion: v1\nentries: {}\n" {
		t.Errorf("updated index not served live: %q", body)
	}
}

func TestFetchProvenanceServed(t *testing.T) {
	fr := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, fr, m)

	res := resolve(t, b, "/nginx-1.2.3.tgz.prov")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch prov: %v", err)
	}
	if string(body) != string(fr.files["/nginx-1.2.3.tgz.prov"]) {
		t.Error("served prov bytes differ")
	}
	if m.Stats().ProvenanceServed != 1 {
		t.Errorf("ProvenanceServed = %v, want 1", m.Stats().ProvenanceServed)
	}
}

func TestNewValidation(t *testing.T) {
	cli := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	cases := []struct {
		name string
		opts Options
	}{
		{"no name", Options{UpstreamURL: "https://charts.example.com", Client: cli}},
		{"no url", Options{Name: "charts", Client: cli}},
		{"bad scheme", Options{Name: "charts", UpstreamURL: "ftp://x", Client: cli}},
		{"no client", Options{Name: "charts", UpstreamURL: "https://charts.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNewOCIMode(t *testing.T) {
	b, err := New(Options{
		Name:        "ocicharts",
		UpstreamURL: "https://registry-1.docker.io",
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		OCI:         true,
	})
	if err != nil {
		t.Fatalf("New OCI: %v", err)
	}
	if b.oci == nil {
		t.Fatal("OCI backend not constructed")
	}
	// In OCI mode the backend delegates Registry v2 routing to the docker backend.
	res, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet,
		Path:   "/v2/library/nginx/manifests/1.2.3",
		Query:  url.Values{},
	})
	if err != nil {
		t.Fatalf("OCI resolve: %v", err)
	}
	if res.Coordinate.Name != "library/nginx" || res.Coordinate.Version != "1.2.3" {
		t.Errorf("OCI coordinate = %+v", res.Coordinate)
	}
	if res.Metadata[metaOCI] != "1" {
		t.Error("manifest request should be flagged for OCI chart metric")
	}
}
