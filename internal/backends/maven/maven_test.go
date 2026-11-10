package maven

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// fakeRepo is an in-memory Maven repository serving a known artifact, its
// checksum sidecars, a POM, and release/snapshot metadata.
type fakeRepo struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	fr := &fakeRepo{files: map[string][]byte{}}

	jar := []byte("PK\x03\x04 fake jar bytes for guava")
	jarPath := "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar"
	fr.files[jarPath] = jar
	fr.files[jarPath+".sha1"] = []byte(sha1Hex(jar) + "  guava-31.1-jre.jar")
	fr.files[jarPath+".sha256"] = []byte(sha256Hex(jar))

	pom := []byte(fullPOM)
	pomPath := "/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom"
	fr.files[pomPath] = pom
	fr.files[pomPath+".sha1"] = []byte(sha1Hex(pom))

	// A poisoned artifact: the served bytes do not match the published sha256.
	poisonPath := "/com/evil/lib/1.0/lib-1.0.jar"
	fr.files[poisonPath] = []byte("POISONED PAYLOAD")
	fr.files[poisonPath+".sha256"] = []byte(sha256Hex([]byte("the real, untampered bytes")))

	// An artifact with no checksum sidecar at all.
	nosumPath := "/com/example/nochk/1.0/nochk-1.0.jar"
	fr.files[nosumPath] = []byte("artifact without any checksum")

	fr.files["/com/google/guava/guava/maven-metadata.xml"] = []byte(releaseMetadataXML)
	fr.files["/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml"] = []byte(snapshotMetadataXML)

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

func testBackend(t *testing.T, fr *fakeRepo, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "maven-central",
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

func TestResolveAttachesCoordinate(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	res := resolve(t, b, "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar")
	if res.Coordinate.Name != "com.google.guava:guava" || res.Coordinate.Version != "31.1-jre" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error("release jar should be cacheable")
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error("jar should be flagged for checksum verification")
	}
}

func TestResolveMetadataNotCacheable(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	res := resolve(t, b, "/com/google/guava/guava/maven-metadata.xml")
	if res.Cacheable {
		t.Error("maven-metadata.xml must not be cached")
	}
	if res.Coordinate.Name != "com.google.guava:guava" {
		t.Errorf("metadata coordinate name = %q", res.Coordinate.Name)
	}
	if res.Coordinate.Version != "" {
		t.Errorf("release metadata should carry no version, got %q", res.Coordinate.Version)
	}
}

func TestResolveRejectsNonMavenPath(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/notmaven", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
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

func TestFetchJarVerifiesChecksum(t *testing.T) {
	repo := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, repo, m)

	res := resolve(t, b, "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch+read: %v", err)
	}
	if string(body) != string(repo.files["/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar"]) {
		t.Error("served jar bytes differ from upstream")
	}
	// Verification result is reported at end-of-stream (after ReadAll).
	if got := m.Stats().ArtifactsVerified; got != 1 {
		t.Errorf("ArtifactsVerified = %v, want 1", got)
	}
	if m.Stats().ChecksumMismatch != 0 {
		t.Errorf("unexpected mismatch count: %v", m.Stats().ChecksumMismatch)
	}
	// The strongest available algorithm (sha256) should have been used.
	if hv := fr.Header.Get("X-Checksum-Verified"); hv != "sha256" {
		t.Errorf("X-Checksum-Verified = %q, want sha256", hv)
	}
}

func TestFetchPoisonedArtifactFailsClosed(t *testing.T) {
	repo := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, repo, m)

	res := resolve(t, b, "/com/evil/lib/1.0/lib-1.0.jar")
	_, _, err := fetchAll(t, b, res)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError reading poisoned artifact, got %v", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
}

func TestFetchArtifactWithoutSidecar(t *testing.T) {
	repo := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, repo, m)

	res := resolve(t, b, "/com/example/nochk/1.0/nochk-1.0.jar")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != "artifact without any checksum" {
		t.Errorf("body = %q", body)
	}
	if m.Stats().SidecarMissing != 1 {
		t.Errorf("SidecarMissing = %v, want 1", m.Stats().SidecarMissing)
	}
	if m.Stats().ArtifactsVerified != 0 {
		t.Errorf("ArtifactsVerified = %v, want 0 (no sidecar)", m.Stats().ArtifactsVerified)
	}
}

func TestFetchPOMParsesAndEnriches(t *testing.T) {
	repo := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, repo, m)

	res := resolve(t, b, "/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch pom: %v", err)
	}
	if string(body) != fullPOM {
		t.Error("served POM bytes differ from upstream")
	}
	if m.Stats().POMsParsed != 1 {
		t.Errorf("POMsParsed = %v, want 1", m.Stats().POMsParsed)
	}
	if got := fr.Resolved.Metadata[MetaPackaging]; got != "jar" {
		t.Errorf("packaging metadata = %q, want jar", got)
	}
	if got := fr.Resolved.Metadata[MetaLicenses]; got != "Apache License, Version 2.0" {
		t.Errorf("licenses metadata = %q", got)
	}
	if m.Stats().CoordinateMismatch != 0 {
		t.Errorf("unexpected coordinate mismatch for a consistent POM")
	}
}

func TestFetchMetadataServedLive(t *testing.T) {
	repo := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, repo, m)

	res := resolve(t, b, "/com/google/guava/guava/maven-metadata.xml")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	if string(body) != releaseMetadataXML {
		t.Error("metadata body differs from upstream")
	}
	if m.Stats().ReleaseMetadata != 1 {
		t.Errorf("ReleaseMetadata = %v, want 1", m.Stats().ReleaseMetadata)
	}

	// And the parsed view is usable for release resolution.
	parsed, perr := ParseMetadata(body)
	if perr != nil {
		t.Fatalf("ParseMetadata: %v", perr)
	}
	if parsed.Release != "31.1-jre" {
		t.Errorf("release = %q", parsed.Release)
	}
}

func TestFetchSnapshotMetadataCounted(t *testing.T) {
	repo := newFakeRepo(t)
	m := &Metrics{}
	b := testBackend(t, repo, m)

	res := resolve(t, b, "/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml")
	if res.Cacheable {
		t.Error("snapshot metadata must not be cached")
	}
	_, _, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch snapshot metadata: %v", err)
	}
	if m.Stats().SnapshotMetadata != 1 {
		t.Errorf("SnapshotMetadata = %v, want 1", m.Stats().SnapshotMetadata)
	}
}

func TestFetchUpstream404(t *testing.T) {
	repo := newFakeRepo(t)
	b := testBackend(t, repo, nil)
	res := resolve(t, b, "/com/missing/lib/1.0/lib-1.0.war")
	_, _, err := fetchAll(t, b, res)
	se, ok := backends.AsStatusError(err)
	if !ok {
		t.Fatalf("expected StatusError, got %v", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []Options{
		{Name: "", UpstreamURL: "https://x", Client: upstream.NewWithHTTPClient(http.DefaultClient, "t")},
		{Name: "m", UpstreamURL: "", Client: upstream.NewWithHTTPClient(http.DefaultClient, "t")},
		{Name: "m", UpstreamURL: "ftp://x", Client: upstream.NewWithHTTPClient(http.DefaultClient, "t")},
		{Name: "m", UpstreamURL: "https://x", Client: nil},
	}
	for i, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
