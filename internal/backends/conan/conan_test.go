package conan

import (
	"bytes"
	"context"
	"crypto/md5"
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

func md5Hex(b []byte) string { return fmt.Sprintf("%x", md5.Sum(b)) }

// --- backend-detection / path-classification unit tests ---------------------

// TestClassify is the backend-detection test: it confirms that the Conan v2
// route table is recognized exactly, that each path maps to the right resource
// kind, and that non-Conan paths are rejected (so the gateway reports them as
// unsupported rather than blindly proxying them).
func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/v2/ping", kindPing},
		{"/v2/users/authenticate", kindUsers},
		{"/v2/users/check_credentials", kindUsers},
		{"/v2/conans/search", kindSearch},
		{"/v2/conans/zlib/1.2.13/_/_/latest", kindRecipeLatest},
		{"/v2/conans/zlib/1.2.13/_/_/revisions", kindRecipeRevisions},
		{"/v2/conans/zlib/1.2.13/_/_/search", kindSearch},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files", kindRecipeFiles},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py", kindRecipeFile},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/search", kindSearch},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/pid9/latest", kindPackageLatest},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/pid9/revisions", kindPackageRevisions},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/pid9/revisions/pr7/files", kindPackageFiles},
		{"/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/pid9/revisions/pr7/files/conan_package.tgz", kindPackageFile},
		{"/v2/conans/fmt/10.1.1/bincrafters/stable/revisions/r1/files/conanfile.py", kindRecipeFile},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", c.path)
			continue
		}
		if res.kind != c.want {
			t.Errorf("classify(%q).kind = %v, want %v", c.path, res.kind, c.want)
		}
	}

	for _, bad := range []string{
		"", "/", "////",
		"/v1/ping",                                         // wrong API version
		"/v2/ping/extra",                                   // ping takes no suffix
		"/v2/users/logout",                                 // unknown user endpoint
		"/v2/conans/zlib",                                  // incomplete reference
		"/v2/conans/zlib/1.2.13/_",                         // incomplete reference
		"/v2/conans/zlib/1.2.13/_/_",                       // bare reference, not an endpoint
		"/v2/conans/zlib/1.2.13/_/_/bogus",                 // unknown recipe sub-resource
		"/v2/conans/zlib/1.2.13/_/_/revisions/r1",          // bare revision (DELETE only)
		"/v2/conans/zlib/1.2.13/_/_/revisions/r1/packages", // missing package id
		"/v2/conans/a/b/c/../../../etc/passwd",             // traversal
		"/v2/other/thing",                                  // unknown namespace
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinateAndReference(t *testing.T) {
	res, _ := classify("/v2/conans/fmt/10.1.1/bincrafters/stable/revisions/r1/files/conanfile.py")
	if res.coordinateName() != "fmt" || res.version != "10.1.1" {
		t.Errorf("coordinate = %q@%q", res.coordinateName(), res.version)
	}
	if res.reference() != "fmt/10.1.1@bincrafters/stable" {
		t.Errorf("reference = %q", res.reference())
	}
	if res.rrev != "r1" || res.filename != "conanfile.py" {
		t.Errorf("rrev/filename = %q/%q", res.rrev, res.filename)
	}

	cc, _ := classify("/v2/conans/zlib/1.2.13/_/_/revisions/abc/files/conanfile.py")
	if cc.reference() != "zlib/1.2.13" {
		t.Errorf("ConanCenter reference should drop _/_ : %q", cc.reference())
	}
}

func TestResourcePredicates(t *testing.T) {
	file, _ := classify("/v2/conans/zlib/1.2.13/_/_/revisions/r1/files/conan_sources.tgz")
	if !file.verifiableFile() || !file.cacheable() {
		t.Error("a pinned recipe file should be verifiable and cacheable")
	}
	manifest, _ := classify("/v2/conans/zlib/1.2.13/_/_/revisions/r1/files/conanmanifest.txt")
	if manifest.verifiableFile() {
		t.Error("the manifest itself must not be checksum-verified against itself")
	}
	if !manifest.cacheable() {
		t.Error("the manifest is immutable under a pinned revision and should be cacheable")
	}
	info, _ := classify("/v2/conans/zlib/1.2.13/_/_/revisions/r1/packages/pid/revisions/pr/files/conaninfo.txt")
	if !info.isConanInfo() {
		t.Error("conaninfo.txt should be recognized")
	}
	latest, _ := classify("/v2/conans/zlib/1.2.13/_/_/latest")
	if latest.cacheable() {
		t.Error("the latest-revision pointer is mutable and must not be cached")
	}
}

// --- manifest parsing -------------------------------------------------------

func TestParseManifest(t *testing.T) {
	pySum := md5Hex([]byte("recipe"))
	srcSum := md5Hex([]byte("sources"))
	body := "1700000000\n" +
		"conanfile.py: " + pySum + "\n" +
		"conan_sources.tgz: " + srcSum + "\n" +
		"garbage line without digest\n" +
		"short.txt: deadbeef\n" + // too short → skipped
		"\n"
	m := ParseManifest([]byte(body))
	if got, _ := m.digestFor("conanfile.py"); got != pySum {
		t.Errorf("conanfile.py digest = %q, want %q", got, pySum)
	}
	if got, _ := m.digestFor("conan_sources.tgz"); got != srcSum {
		t.Errorf("conan_sources.tgz digest = %q", got)
	}
	if _, ok := m.digestFor("short.txt"); ok {
		t.Error("malformed short digest should be skipped")
	}
	if _, ok := m.digestFor("absent"); ok {
		t.Error("absent file must not resolve")
	}
	// Basename fallback: manifest records a path, request is the flat name.
	m2 := ParseManifest([]byte("1\nexport/conanfile.py: " + pySum + "\n"))
	if got, ok := m2.digestFor("export/conanfile.py"); !ok || got != pySum {
		t.Errorf("exact path lookup failed: %q %v", got, ok)
	}
}

// --- verifying reader / verifyBytes -----------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine conan package bytes")
	exp := expectedChecksum{filename: "conan_package.tgz", md5hex: md5Hex(data)}
	var called, result bool
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(data)), exp, "http://x", func(ok bool) {
		called, result = true, ok
	})
	out, err := io.ReadAll(vr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("content mangled")
	}
	if !called || !result {
		t.Errorf("onResult called=%v result=%v, want true/true", called, result)
	}
}

func TestVerifyingReaderMismatch(t *testing.T) {
	served := []byte("POISONED PAYLOAD")
	exp := expectedChecksum{filename: "conan_package.tgz", md5hex: md5Hex([]byte("the real bytes"))}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "http://x/p.tgz", func(ok bool) {
		result = ok
	})
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if result {
		t.Error("onResult should report failure")
	}
}

func TestSiblingURL(t *testing.T) {
	got, ok := siblingURL("https://u/v2/conans/z/1/_/_/revisions/r1/files/conanfile.py", manifestFile)
	if !ok || got != "https://u/v2/conans/z/1/_/_/revisions/r1/files/conanmanifest.txt" {
		t.Errorf("siblingURL = %q ok=%v", got, ok)
	}
}

// --- integration: fake remote + backend -------------------------------------

type fakeRemote struct {
	srv   *httptest.Server
	files map[string][]byte
	hdrs  map[string]http.Header
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}, hdrs: map[string]http.Header{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if h, ok := fr.hdrs[r.URL.Path]; ok {
			for k, vs := range h {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}
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
		Name:        "conancenter",
		UpstreamURL: fr.srv.URL,
		Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:     m,
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

// seedPackageFile registers a package revision with a conan_package.tgz and its
// manifest. When tamper is true, the manifest declares a digest that does not
// match the served bytes.
func seedPackageFile(t *testing.T, fr *fakeRemote, tamper bool) ([]byte, string) {
	t.Helper()
	tgz := []byte("\x1f\x8b fake conan_package.tgz payload")
	sum := md5Hex(tgz)
	if tamper {
		sum = md5Hex([]byte("a different artifact"))
	}
	dir := "/v2/conans/zlib/1.2.13/_/_/revisions/rrev1/packages/pid9/revisions/prev1/files/"
	fr.files[dir+"conan_package.tgz"] = tgz
	fr.files[dir+"conanmanifest.txt"] = []byte("1700000000\nconan_package.tgz: " + sum + "\nconaninfo.txt: " + md5Hex([]byte("[settings]\n")) + "\n")
	fr.files[dir+"conaninfo.txt"] = []byte("[settings]\n")
	fr.hdrs[dir+"conan_package.tgz"] = http.Header{"X-Checksum-Sha256": {"deadbeef"}}
	return tgz, dir
}

func TestPackageFileVerifiesAndPassesChecksumHeader(t *testing.T) {
	fr := newFakeRemote(t)
	tgz, dir := seedPackageFile(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, dir+"conan_package.tgz")
	if err != nil {
		t.Fatalf("fetch package: %v", err)
	}
	if !bytes.Equal(body, tgz) {
		t.Fatal("package body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "md5" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "application/gzip" {
		t.Errorf("media type = %q, want application/gzip", fres.MediaType)
	}
	if got := fres.Header.Get("X-Checksum-Sha256"); got != "deadbeef" {
		t.Errorf("upstream checksum header not passed through: %q", got)
	}
	if got := m.Stats(); got.FilesVerified != 1 || got.ManifestParsed != 1 {
		t.Errorf("metrics = %+v", got)
	}
	if fres.Resolved.Metadata[MetaReference] != "zlib/1.2.13" {
		t.Errorf("reference metadata = %q", fres.Resolved.Metadata[MetaReference])
	}
	if fres.Resolved.Metadata[MetaPackageRevision] != "prev1" {
		t.Errorf("package revision metadata = %q", fres.Resolved.Metadata[MetaPackageRevision])
	}
}

func TestPackageFileChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, dir := seedPackageFile(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, dir+"conan_package.tgz")
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestConanInfoVerifiedInMemory(t *testing.T) {
	fr := newFakeRemote(t)
	_, dir := seedPackageFile(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, dir+"conaninfo.txt")
	if err != nil {
		t.Fatalf("fetch conaninfo: %v", err)
	}
	if !bytes.Equal(body, []byte("[settings]\n")) {
		t.Errorf("conaninfo body = %q", body)
	}
	if fres.Resolved.Metadata[MetaConanInfo] != "1" {
		t.Error("conaninfo flag not set in metadata")
	}
	if fres.MediaType != "text/plain; charset=utf-8" {
		t.Errorf("conaninfo media type = %q", fres.MediaType)
	}
	if m.Stats().ConanInfoServed != 1 || m.Stats().FilesVerified != 1 {
		t.Errorf("metrics = %+v", m.Stats())
	}
}

func TestManifestMissingServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	dir := "/v2/conans/zlib/1.2.13/_/_/revisions/rrev1/files/"
	fr.files[dir+"conanfile.py"] = []byte("from conan import ConanFile\n")
	// No conanmanifest.txt present.
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, dir+"conanfile.py")
	if err != nil {
		t.Fatalf("fetch conanfile: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty body")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "text/x-python; charset=utf-8" {
		t.Errorf("conanfile media type = %q", fres.MediaType)
	}
	if m.Stats().ManifestMissing != 1 {
		t.Errorf("manifest-missing metric = %v", m.Stats().ManifestMissing)
	}
}

func TestManifestServedAsIs(t *testing.T) {
	fr := newFakeRemote(t)
	_, dir := seedPackageFile(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{})

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dir + "conanmanifest.txt", Query: url.Values{}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Metadata[metaVerify] == "1" {
		t.Error("manifest must not be marked for verification")
	}
	if !res.Cacheable {
		t.Error("manifest under a pinned revision should be cacheable")
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	body, _ := io.ReadAll(fres.Content)
	_ = fres.Content.Close()
	if !bytes.Contains(body, []byte("conan_package.tgz")) {
		t.Errorf("manifest body unexpected: %q", body)
	}
}

func TestLatestRevalidatedNotCached(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/v2/conans/zlib/1.2.13/_/_/latest"] = []byte(`{"revision":"rrev1","time":"2024-01-01T00:00:00Z"}`)
	b := newTestBackend(t, fr, &Metrics{})

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/v2/conans/zlib/1.2.13/_/_/latest", Query: url.Values{}})
	if err != nil {
		t.Fatalf("resolve latest: %v", err)
	}
	if res.Cacheable {
		t.Error("latest-revision pointer must not be cacheable")
	}
}

func TestPingProxied(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/v2/ping"] = []byte("")
	fr.hdrs["/v2/ping"] = http.Header{"X-Conan-Server-Capabilities": {"revisions,complex_search"}}
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, _, err := resolveFetch(t, b, "/v2/ping")
	if err != nil {
		t.Fatalf("fetch ping: %v", err)
	}
	if got := fres.Header.Get("X-Conan-Server-Capabilities"); got != "revisions,complex_search" {
		t.Errorf("capabilities header not propagated: %q", got)
	}
	if m.Stats().MetadataServed != 1 {
		t.Errorf("metadata metric = %v", m.Stats().MetadataServed)
	}
}

func TestResolveRejectsNonConanPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/conan/path", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	// No file seeded → upstream 404.
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/v2/conans/zlib/1.2.13/_/_/revisions/r1/files/conanfile.py")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}
