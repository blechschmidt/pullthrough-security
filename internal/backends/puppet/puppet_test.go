package puppet

import (
	"bytes"
	"context"
	"crypto/md5"
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

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	art := "/v3/files/puppetlabs-stdlib-9.4.1.tar.gz"
	res, ok := classify(art)
	if !ok || res.kind != kindArtifact {
		t.Fatalf("classify(%q) = %+v ok=%v", art, res, ok)
	}
	if res.owner != "puppetlabs" || res.name != "stdlib" || res.version != "9.4.1" {
		t.Errorf("artifact coordinate = %q/%q/%q", res.owner, res.name, res.version)
	}
	if res.coordinateName() != "puppetlabs-stdlib" || res.releaseSlug() != "puppetlabs-stdlib-9.4.1" {
		t.Errorf("slug = %q / %q", res.coordinateName(), res.releaseSlug())
	}
	if !res.cacheable() {
		t.Error("release tarball must be cacheable")
	}

	// Prerelease version keeps its hyphen.
	pre, ok := classify("/v3/files/owner1-mod_name-2.0.0-rc1.tar.gz")
	if !ok || pre.kind != kindArtifact || pre.version != "2.0.0-rc1" {
		t.Errorf("prerelease classify = %+v ok=%v", pre, ok)
	}

	// Metadata paths are live and permissive; a release path yields a coordinate.
	rel, _ := classify("/v3/releases/puppetlabs-stdlib-9.4.1")
	if rel.cacheable() || rel.coordinateName() != "puppetlabs-stdlib" || rel.version != "9.4.1" {
		t.Errorf("release-metadata resource = %+v", rel)
	}
	mod, _ := classify("/v3/modules/puppetlabs-stdlib")
	if mod.cacheable() || mod.coordinateName() != "puppetlabs-stdlib" {
		t.Errorf("module-metadata resource = %+v", mod)
	}
	for _, p := range []string{"/v3/modules", "/v3/releases?module=puppetlabs-stdlib", "", "/"} {
		m, ok := classify(p)
		if !ok || m.cacheable() {
			t.Errorf("classify(%q) = %+v ok=%v", p, m, ok)
		}
	}

	// Traversal rejected.
	for _, bad := range []string{"/v3/files/../x.tar.gz", "/v3/../../etc/passwd"} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}

	// An undecodable file under files/ falls back to live metadata.
	weird, ok := classify("/v3/files/UPPER-Case-1.0.0.tar.gz")
	if !ok || weird.cacheable() {
		t.Errorf("undecodable release file should be live metadata, got %+v ok=%v", weird, ok)
	}
}

// --- checksum selection -----------------------------------------------------

func TestReleaseMetaChecksum(t *testing.T) {
	sha := fmt.Sprintf("%064x", 1)
	md5h := fmt.Sprintf("%032x", 2)

	// SHA-256 preferred over MD5.
	rm := releaseMeta{FileSHA256: sha, FileMD5: md5h}
	c, ok := rm.checksum()
	if !ok || c.algo != algoSHA256 || c.hex != sha {
		t.Errorf("prefer sha256: %+v ok=%v", c, ok)
	}
	// MD5 fallback when no SHA-256.
	rm = releaseMeta{FileMD5: md5h}
	c, ok = rm.checksum()
	if !ok || c.algo != algoMD5 || c.hex != md5h {
		t.Errorf("md5 fallback: %+v ok=%v", c, ok)
	}
	// Neither present.
	if _, ok := (releaseMeta{}).checksum(); ok {
		t.Error("empty release metadata must yield no checksum")
	}
	// Malformed digests rejected.
	if _, ok := (releaseMeta{FileSHA256: "zz", FileMD5: "nothex"}).checksum(); ok {
		t.Error("malformed digests must be rejected")
	}
}

func TestVerifyingReaderMD5Mismatch(t *testing.T) {
	served := []byte("POISONED")
	real := md5.Sum([]byte("the real bytes"))
	exp := expectedChecksum{algo: algoMD5, hex: fmt.Sprintf("%x", real)}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "puppetlabs-stdlib", "http://x", func(ok bool) { result = ok })
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if mm.Algo != "md5" {
		t.Errorf("algo = %q", mm.Algo)
	}
	if result {
		t.Error("onResult should report failure")
	}
}

func TestRewriteMetadata(t *testing.T) {
	origin := "https://forgeapi.puppet.com"
	public := "https://proxy.example.com/v1/puppet"
	body := []byte(`{"file_uri":"/v3/files/puppetlabs-stdlib-9.4.1.tar.gz","pagination":{"next":"https://forgeapi.puppet.com/v3/releases?offset=20"}}`)
	out, changed := rewriteMetadata(body, origin, public)
	if !changed {
		t.Fatal("expected rewrite of the absolute next link")
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["file_uri"] != "/v3/files/puppetlabs-stdlib-9.4.1.tar.gz" {
		t.Errorf("relative file_uri must be untouched, got %v", m["file_uri"])
	}
	pg := m["pagination"].(map[string]any)
	if pg["next"] != public+"/v3/releases?offset=20" {
		t.Errorf("next = %v", pg["next"])
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
		Name:          "puppet",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/puppet",
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

// seedRelease registers a release tarball and the sibling release-metadata
// document. algo selects which digest the metadata declares; when tamper is
// true the declared digest does not match the bytes.
func seedRelease(t *testing.T, fr *fakeRemote, algo checksumAlgo, tamper bool) (content []byte, filePath string) {
	t.Helper()
	content = []byte("fake puppet module tarball bytes\n")
	declared := content
	if tamper {
		declared = []byte("a completely different tarball")
	}
	rm := map[string]any{
		"file_uri":  "/v3/files/puppetlabs-stdlib-9.4.1.tar.gz",
		"file_size": len(declared),
	}
	switch algo {
	case algoMD5:
		sum := md5.Sum(declared)
		rm["file_md5"] = fmt.Sprintf("%x", sum)
	default:
		sum := sha256.Sum256(declared)
		rm["file_sha256"] = fmt.Sprintf("%x", sum)
	}
	mb, _ := json.Marshal(rm)
	fr.files["/v3/releases/puppetlabs-stdlib-9.4.1"] = mb
	filePath = "/v3/files/puppetlabs-stdlib-9.4.1.tar.gz"
	fr.files[filePath] = content
	return content, filePath
}

func TestReleaseVerifiesSHA256(t *testing.T) {
	fr := newFakeRemote(t)
	content, path := seedRelease(t, fr, algoSHA256, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch release: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatal("release body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("release tarball should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Header.Get("X-Checksum-Verified") != "sha256" {
		t.Errorf("X-Checksum-Verified = %q", fres.Header.Get("X-Checksum-Verified"))
	}
	if fres.Resolved.Coordinate.Name != "puppetlabs-stdlib" || fres.Resolved.Coordinate.Version != "9.4.1" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.ReleasesVerified != 1 || st.ReleaseMetaFetch != 1 || st.MD5Fallback != 0 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestReleaseVerifiesMD5Fallback(t *testing.T) {
	fr := newFakeRemote(t)
	content, path := seedRelease(t, fr, algoMD5, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch release: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatal("release body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "md5" {
		t.Errorf("checksum metadata = %q, want md5", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.ReleasesVerified != 1 || st.MD5Fallback != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestReleaseChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedRelease(t, fr, algoSHA256, true)
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

func TestReleaseMissingDigestServedUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	content := []byte("tarball without release metadata\n")
	path := "/v3/files/puppetlabs-stdlib-9.4.1.tar.gz"
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
	relPath := "/v3/releases/puppetlabs-stdlib-9.4.1"
	fr.files[relPath] = []byte(`{"file_uri":"/v3/files/puppetlabs-stdlib-9.4.1.tar.gz","module":{"uri":"` + fr.srv.URL + `/v3/modules/puppetlabs-stdlib"}}`)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, relPath)
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
	mod := doc["module"].(map[string]any)
	if mod["uri"] != "https://proxy.example.com/v1/puppet/v3/modules/puppetlabs-stdlib" {
		t.Errorf("module.uri = %v", mod["uri"])
	}
	if st := m.Stats(); st.MetadataServed != 1 || st.MetadataRewritten != 1 {
		t.Errorf("metadata metrics = %+v", st)
	}
}

func TestResolveRejectsTraversal(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/v3/../../etc/passwd", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
}
