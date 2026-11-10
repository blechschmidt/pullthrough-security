package ansible

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
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const (
	indexPrefix = "/api/v3/plugin/ansible/content/published/collections/index"
	artPrefix   = "/api/v3/plugin/ansible/content/published/collections/artifacts"
)

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	artifact := artPrefix + "/community-general-8.0.0.tar.gz"
	res, ok := classify(artifact)
	if !ok || res.kind != kindArtifact {
		t.Fatalf("classify(%q) = %+v ok=%v", artifact, res, ok)
	}
	if res.namespace != "community" || res.name != "general" || res.version != "8.0.0" {
		t.Errorf("artifact coordinate = %q/%q/%q", res.namespace, res.name, res.version)
	}
	if res.coordinateName() != "community.general" {
		t.Errorf("coordinateName = %q", res.coordinateName())
	}
	if res.indexBase != "/api/v3/plugin/ansible/content/published/collections" {
		t.Errorf("indexBase = %q", res.indexBase)
	}
	if !res.cacheable() {
		t.Error("collection artifact must be cacheable")
	}

	// A prerelease version keeps its hyphen.
	pre, ok := classify(artPrefix + "/my_ns-my_coll-1.0.0-rc1.tar.gz")
	if !ok || pre.kind != kindArtifact || pre.version != "1.0.0-rc1" {
		t.Errorf("prerelease classify = %+v ok=%v", pre, ok)
	}

	// Metadata paths are served live (never cached) and are permissive.
	for _, p := range []string{
		indexPrefix + "/community/general/",
		indexPrefix + "/community/general/versions/",
		indexPrefix + "/community/general/versions/8.0.0/",
		"/api/v1/roles/?namespace=geerlingguy",
		"/api/", "", "/",
	} {
		m, ok := classify(p)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", p)
			continue
		}
		if m.cacheable() {
			t.Errorf("classify(%q) must not be cacheable", p)
		}
	}

	// Best-effort coordinate extraction from an index path.
	vd, _ := classify(indexPrefix + "/community/general/versions/8.0.0/")
	if vd.coordinateName() != "community.general" || vd.version != "8.0.0" {
		t.Errorf("version-detail coordinate = %q/%q", vd.coordinateName(), vd.version)
	}

	// Traversal / empty segments are rejected outright.
	for _, bad := range []string{
		artPrefix + "/../x.tar.gz",
		"/api/v3/../../etc/passwd",
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}

	// A file under artifacts/ we cannot decompose falls back to live metadata.
	weird, ok := classify(artPrefix + "/not_a_valid_slug.tar.gz")
	if !ok || weird.cacheable() {
		t.Errorf("undecodable artifact file should be live metadata, got %+v ok=%v", weird, ok)
	}
}

// --- checksum helpers -------------------------------------------------------

func TestNormalizeSHA256(t *testing.T) {
	good := fmt.Sprintf("%064x", 1)
	if h, ok := normalizeSHA256(good); !ok || h != good {
		t.Errorf("normalizeSHA256(hex) = %q ok=%v", h, ok)
	}
	if h, ok := normalizeSHA256("sha256:" + good); !ok || h != good {
		t.Errorf("normalizeSHA256(prefixed) = %q ok=%v", h, ok)
	}
	for _, bad := range []string{"", "deadbeef", "md5:" + good, good + "zz"} {
		if _, ok := normalizeSHA256(bad); ok {
			t.Errorf("normalizeSHA256(%q) unexpectedly ok", bad)
		}
	}
}

func TestRewriteMetadata(t *testing.T) {
	origin := "https://galaxy.ansible.com"
	public := "https://proxy.example.com/v1/ansible"
	body := []byte(`{"download_url":"https://galaxy.ansible.com/api/v3/.../community-general-8.0.0.tar.gz","rel":"./x","n":{"href":"https://galaxy.ansible.com/api/v3/next"}}`)
	out, changed := rewriteMetadata(body, origin, public)
	if !changed {
		t.Fatal("expected rewrite")
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["download_url"] != public+"/api/v3/.../community-general-8.0.0.tar.gz" {
		t.Errorf("download_url = %v", m["download_url"])
	}
	if m["rel"] != "./x" {
		t.Errorf("relative link must be untouched, got %v", m["rel"])
	}
	if _, changed := rewriteMetadata([]byte(`{"a":"./b"}`), origin, public); changed {
		t.Error("body without an upstream URL must not be marked changed")
	}
	if _, changed := rewriteMetadata([]byte("not json"), origin, public); changed {
		t.Error("non-JSON body must not be marked changed")
	}
}

func TestVerifyingReaderMismatch(t *testing.T) {
	served := []byte("POISONED")
	real := sha256.Sum256([]byte("the real bytes"))
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), fmt.Sprintf("%x", real), "community.general", "http://x", func(ok bool) { result = ok })
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if result {
		t.Error("onResult should report failure")
	}
}

// --- integration: fake registry + backend -----------------------------------

type fakeRemote struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := fr.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func newTestBackend(t *testing.T, fr *fakeRemote, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "ansible",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/ansible",
		Client:        upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:       m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		return nil, nil, err
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	var body []byte
	var rerr error
	if fres.Content != nil {
		body, rerr = io.ReadAll(fres.Content)
		_ = fres.Content.Close()
	}
	fres.Resolved = res
	return fres, body, rerr
}

// seedArtifact registers a collection artifact and the sibling version-detail
// document. When tamper is true, the version detail declares a sha256 that does
// not match the bytes.
func seedArtifact(t *testing.T, fr *fakeRemote, tamper bool) (content []byte, artPath string) {
	t.Helper()
	content = []byte("fake collection tarball bytes\n")
	declared := content
	if tamper {
		declared = []byte("a completely different tarball")
	}
	sum := sha256.Sum256(declared)
	detail := map[string]any{
		"version": "8.0.0",
		"artifact": map[string]any{
			"sha256":   fmt.Sprintf("%x", sum),
			"size":     len(declared),
			"filename": "community-general-8.0.0.tar.gz",
		},
		"download_url": fr.srv.URL + artPrefix + "/community-general-8.0.0.tar.gz",
	}
	db, _ := json.Marshal(detail)
	fr.files[indexPrefix+"/community/general/versions/8.0.0/"] = db
	artPath = artPrefix + "/community-general-8.0.0.tar.gz"
	fr.files[artPath] = content
	return content, artPath
}

func TestArtifactVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	content, path := seedArtifact(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatal("artifact body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("collection artifact should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Header.Get("X-Checksum-Verified") != "sha256" {
		t.Errorf("X-Checksum-Verified = %q", fres.Header.Get("X-Checksum-Verified"))
	}
	if fres.Resolved.Coordinate.Name != "community.general" || fres.Resolved.Coordinate.Version != "8.0.0" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.ArtifactsVerified != 1 || st.VersionMetaFetched != 1 || st.ArtifactsServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestArtifactChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedArtifact(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, path)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if st := m.Stats(); st.ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %+v", st)
	}
}

func TestArtifactMissingDigestServedUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	content := []byte("tarball without a sibling version detail\n")
	path := artPrefix + "/community-general-8.0.0.tar.gz"
	fr.files[path] = content
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatal("body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.ChecksumMissing != 1 {
		t.Errorf("missing metric = %+v", st)
	}
}

func TestMetadataRewrittenAndNotCached(t *testing.T) {
	fr := newFakeRemote(t)
	detailPath := indexPrefix + "/community/general/versions/8.0.0/"
	fr.files[detailPath] = []byte(`{"download_url":"` + fr.srv.URL + artPrefix + `/community-general-8.0.0.tar.gz"}`)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, detailPath)
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	if fres.Resolved.Cacheable {
		t.Error("metadata must not be cacheable")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal served metadata: %v", err)
	}
	want := "https://proxy.example.com/v1/ansible" + artPrefix + "/community-general-8.0.0.tar.gz"
	if doc["download_url"] != want {
		t.Errorf("download_url = %v, want %v", doc["download_url"], want)
	}
	if st := m.Stats(); st.MetadataServed != 1 || st.MetadataRewritten != 1 {
		t.Errorf("metadata metrics = %+v", st)
	}
}

func TestResolveRejectsTraversal(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/api/../../etc/passwd", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
}
