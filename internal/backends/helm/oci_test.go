package helm

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// fakeRegistry is a minimal OCI registry (TLS, as a registry is always reached)
// holding Helm chart artifacts: a manifest per repository:tag and its blobs.
type fakeRegistry struct {
	srv *httptest.Server

	mu        sync.Mutex
	manifests map[string][]byte // "<repository>:<reference>" -> manifest JSON
	blobs     map[string][]byte // "sha256:<hex>" -> content
	requests  []string          // every request path, in order
	auth      []string          // the Authorization header of every request
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	r := &fakeRegistry{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.srv.Close)
	return r
}

// host is the registry's host:port, as it appears in an oci:// reference.
func (r *fakeRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "https://") }

// push stores a chart artifact: one layer per media type given.
func (r *fakeRegistry) push(repository, tag string, layers map[string][]byte) {
	type descriptor struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	manifest := struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json"}

	r.mu.Lock()
	defer r.mu.Unlock()
	config := []byte(`{"name":"` + repository + `","version":"` + tag + `"}`)
	manifest.Config = descriptor{"application/vnd.cncf.helm.config.v1+json", "sha256:" + sha256Hex(config), len(config)}
	r.blobs[manifest.Config.Digest] = config
	// Provenance first, so picking "the first layer" would be wrong.
	for _, mediaType := range []string{ociProvenanceLayer, ociChartLayer, "application/vnd.example.other"} {
		content, ok := layers[mediaType]
		if !ok {
			continue
		}
		d := descriptor{mediaType, "sha256:" + sha256Hex(content), len(content)}
		r.blobs[d.Digest] = content
		manifest.Layers = append(manifest.Layers, d)
	}
	body, _ := json.Marshal(manifest)
	r.manifests[repository+":"+tag] = body
	r.manifests[repository+":sha256:"+sha256Hex(body)] = body
}

// manifestDigest returns the digest of a pushed artifact's manifest.
func (r *fakeRegistry) manifestDigest(repository, tag string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return "sha256:" + sha256Hex(r.manifests[repository+":"+tag])
}

// corrupt replaces the content served for a blob without changing its digest.
func (r *fakeRegistry) corrupt(digest string, content []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs[digest] = content
}

func (r *fakeRegistry) handle(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req.URL.Path)
	r.auth = append(r.auth, req.Header.Get("Authorization"))

	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	if repository, reference, ok := strings.Cut(rest, "/manifests/"); ok {
		body, found := r.manifests[repository+":"+reference]
		if !found {
			http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write(body)
		return
	}
	if _, digest, ok := strings.Cut(rest, "/blobs/"); ok {
		body, found := r.blobs[digest]
		if !found {
			http.Error(w, `{"errors":[{"code":"BLOB_UNKNOWN"}]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
		return
	}
	http.NotFound(w, req)
}

// requested reports whether any request path so far contains fragment.
func (r *fakeRegistry) requested(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.requests {
		if strings.Contains(p, fragment) {
			return true
		}
	}
	return false
}

var (
	ociChart = []byte("chart archive stored as an OCI layer")
	ociProv  = []byte("-----BEGIN PGP SIGNED MESSAGE-----\noci prov\n")
)

// An index that lists a chart as an OCI reference: the backend pulls the chart
// layer from the registry and holds it to the digest the index declares.
func TestIndexedArchiveInAnOCIRegistry(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{
		PublicBaseURL: publicBase,
		Metrics:       m,
		Credentials:   upstream.Credentials{Token: "repo-secret"},
	})

	res := resolve(t, b, "/-/ocihosted/5.0.0/ocihosted-5.0.0.tgz")
	if res.Coordinate != (backends.Coordinate{Name: "ocihosted", Version: "5.0.0"}) || !res.Cacheable {
		t.Errorf("coordinate=%+v cacheable=%v", res.Coordinate, res.Cacheable)
	}
	fres, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(ociChart) {
		t.Errorf("served bytes = %q, want the chart layer", body)
	}
	if got, want := fres.Resolved.Metadata[MetaArchiveURL], "oci://"+s.registry.host()+"/charts/ocihosted:5.0.0"; got != want {
		t.Errorf("recorded archive URL = %q, want %q", got, want)
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" || m.Stats().ChartsVerified != 1 {
		t.Errorf("chart layer not verified against the index digest: %q, %+v",
			fres.Resolved.Metadata[MetaChecksumVerified], m.Stats())
	}
	// The repository's credentials are not the registry's.
	s.registry.mu.Lock()
	for i, auth := range s.registry.auth {
		if auth != "" {
			t.Errorf("registry request %s was sent Authorization %q", s.registry.requests[i], auth)
		}
	}
	s.registry.mu.Unlock()

	// Its provenance is the artifact's provenance layer.
	_, body, err = fetchPath(t, b, "/-/ocihosted/5.0.0/ocihosted-5.0.0.tgz.prov")
	if err != nil {
		t.Fatalf("fetch provenance: %v", err)
	}
	if string(body) != string(ociProv) || m.Stats().ProvenanceServed != 1 {
		t.Errorf("provenance = %q, ProvenanceServed = %v", body, m.Stats().ProvenanceServed)
	}

	// An artifact pushed without provenance has none: a 404, like a missing file.
	_, _, err = fetchPath(t, b, "/-/ocibare/5.1.0/ocibare-5.1.0.tgz.prov")
	if se, ok := backends.AsStatusError(err); !ok || se.Status != http.StatusNotFound {
		t.Errorf("expected a 404 for a chart artifact without provenance, got %v", err)
	}
	// A reference pinned by digest is honored as such.
	if _, body, err = fetchPath(t, b, "/-/ocipinned/5.2.0/ocipinned-5.2.0.tgz"); err != nil || string(body) != string(ociChart) {
		t.Errorf("digest-pinned reference: %q, %v", body, err)
	}
}

func TestIndexedOCIArchiveDigestMismatchIsRefused(t *testing.T) {
	s := newRepoSetup(t)
	m := &Metrics{}
	b := s.backend(t, Options{PublicBaseURL: publicBase, Metrics: m})

	// The registry serves a well-formed artifact whose chart layer is not the
	// archive the index vouches for.
	_, _, err := fetchPath(t, b, "/-/ocitampered/5.6.6/ocitampered-5.6.6.tgz")
	var mismatch *ChecksumMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected a ChecksumMismatchError, got %v", err)
	}
	if st := m.Stats(); st.ChecksumMismatch != 1 || st.ChartsVerified != 0 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestIndexedOCIArchiveFailures(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	// The registry does not have the referenced tag: its 404 is relayed.
	_, _, err := fetchPath(t, b, "/-/ocimissing/5.3.0/ocimissing-5.3.0.tgz")
	if se, ok := backends.AsStatusError(err); !ok || se.Status != http.StatusNotFound {
		t.Errorf("missing tag: expected the registry's 404, got %v", err)
	}

	// The reference names something that is not a chart: no blob is fetched.
	_, _, err = fetchPath(t, b, "/-/ocinotchart/5.4.0/ocinotchart-5.4.0.tgz")
	if err == nil || !strings.Contains(err.Error(), "not a Helm chart artifact") {
		t.Errorf("non-chart artifact: got %v", err)
	}
	if s.registry.requested("/charts/ocinotchart/blobs/") {
		t.Error("a blob of a non-chart artifact was fetched")
	}

	// A reference without a tag names no particular version and is refused
	// without contacting the registry.
	_, _, err = fetchPath(t, b, "/-/ocitagless/5.5.0/ocitagless-5.5.0.tgz")
	if err == nil || !strings.Contains(err.Error(), "not a complete OCI reference") {
		t.Errorf("tagless reference: got %v", err)
	}
	if s.registry.requested("/charts/ocitagless/") {
		t.Error("the registry was contacted for a tagless reference")
	}

	// The registry serves bytes that do not match the layer digest the manifest
	// declares; the index publishes no digest for this chart, yet it is refused.
	_, _, err = fetchPath(t, b, "/-/ocicorrupt/5.7.0/ocicorrupt-5.7.0.tgz")
	if err == nil {
		t.Error("a blob that does not match its own digest was served")
	}
}

func TestParseOCIReference(t *testing.T) {
	cases := []struct {
		in   string
		want ociReference
		ok   bool
	}{
		{"oci://registry-1.docker.io/bitnamicharts/nginx:25.2.14", ociReference{"registry-1.docker.io", "bitnamicharts/nginx", "25.2.14"}, true},
		{"oci://ghcr.io/org/charts/app:1.0.0_build.5", ociReference{"ghcr.io", "org/charts/app", "1.0.0_build.5"}, true},
		{"oci://localhost:5000/app:1.0.0", ociReference{"localhost:5000", "app", "1.0.0"}, true},
		{"oci://ghcr.io/org/app@sha256:" + strings.Repeat("a", 64), ociReference{"ghcr.io", "org/app", "sha256:" + strings.Repeat("a", 64)}, true},
		{"oci://ghcr.io/org/app:1.0.0@sha256:" + strings.Repeat("a", 64), ociReference{"ghcr.io", "org/app", "sha256:" + strings.Repeat("a", 64)}, true},
		{"oci://docker.io/bitnamicharts/nginx:1.0.0", ociReference{"registry-1.docker.io", "bitnamicharts/nginx", "1.0.0"}, true},
		{"oci://index.docker.io/bitnamicharts/nginx:1.0.0", ociReference{"registry-1.docker.io", "bitnamicharts/nginx", "1.0.0"}, true},
		// Incomplete references.
		{"oci://ghcr.io/org/app", ociReference{}, false},
		{"oci://ghcr.io/org/app:", ociReference{}, false},
		{"oci://ghcr.io/:1.0.0", ociReference{}, false},
		{"oci://ghcr.io", ociReference{}, false},
		{"oci:///org/app:1.0.0", ociReference{}, false},
		{"oci://localhost:5000/app", ociReference{}, false},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.in)
		if err != nil {
			t.Fatalf("%q does not parse: %v", tc.in, err)
		}
		got, err := parseOCIReference(u)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseOCIReference(%q) = %+v, %v; want %+v, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}
