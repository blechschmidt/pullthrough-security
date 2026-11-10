package conan

import (
	"bytes"
	"context"
	"crypto/md5"
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
		{"/v1/ping", kindPing}, // the capability probe a real Conan 2.x client sends
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
		"/v3/ping",                                         // wrong API version
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

		// The v1 prefix serves the capability probe and nothing else.
		"/v1",
		"/v1/ping/extra",
		"/v1/users/authenticate",
		"/v1/conans/search",
		"/v1/conans/zlib/1.2.13/_/_/latest",
		"/ping",
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

	mu   sync.Mutex
	seen []string // request paths, in arrival order
}

// requests reports how many times the remote was asked for path.
func (fr *fakeRemote) requests(path string) int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	n := 0
	for _, p := range fr.seen {
		if p == path {
			n++
		}
	}
	return n
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}, hdrs: map[string]http.Header{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.seen = append(fr.seen, r.URL.Path)
		fr.mu.Unlock()
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

// --- real-client regressions (Conan 2.34 against ConanCenter) ----------------
//
// The fixtures below reproduce what https://center2.conan.io actually serves,
// as observed with a real `conan download` through the proxy: the capability
// probe lives at /v1/ping (and /v2/ping is a 404), and a conanmanifest.txt lists
// the unpacked files of a revision — never the .tgz archives.

const conanCenterCapabilities = "complex_search,checksum_deploy,revisions,matrix_params"

// seedConanCenterPing makes the fake remote answer the capability probe the way
// ConanCenter does: 200 with an empty body and the capabilities in a header on
// /v1/ping, nothing at all on /v2/ping.
func seedConanCenterPing(fr *fakeRemote, prefix string) {
	fr.files[prefix+"/v1/ping"] = []byte{}
	fr.hdrs[prefix+"/v1/ping"] = http.Header{
		"X-Conan-Server-Capabilities": {conanCenterCapabilities},
		"X-Conan-Server-Version":      {"0.20.0"},
	}
}

// TestV1PingRelaysCapabilities is the regression test for the first request a
// real Conan 2.x client makes. It probes GET /v1/ping — not /v2/ping — reads
// X-Conan-Server-Capabilities, and aborts with "Server exception 501" when the
// proxy rejects the route. The probe must resolve to the upstream's /v1/ping,
// be served live (a cached entry would not replay the header), carry no package
// coordinate, and hand the capabilities header back for relay.
func TestV1PingRelaysCapabilities(t *testing.T) {
	fr := newFakeRemote(t)
	seedConanCenterPing(fr, "")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: method, Path: "/v1/ping", Query: url.Values{}})
		if err != nil {
			t.Fatalf("%s /v1/ping: Resolve: %v", method, err)
		}
		if want := fr.srv.URL + "/v1/ping"; res.UpstreamURL != want {
			t.Errorf("%s /v1/ping: upstream URL = %q, want %q", method, res.UpstreamURL, want)
		}
		if res.Cacheable {
			t.Errorf("%s /v1/ping must be served live, not cached", method)
		}
		if res.Coordinate != (backends.Coordinate{}) {
			t.Errorf("%s /v1/ping must carry no package coordinate, got %+v", method, res.Coordinate)
		}
		fres, err := b.Fetch(context.Background(), res)
		if err != nil {
			t.Fatalf("%s /v1/ping: Fetch: %v", method, err)
		}
		_ = fres.Content.Close()
		if fres.Status != http.StatusOK {
			t.Errorf("%s /v1/ping: status = %d, want 200", method, fres.Status)
		}
		if got := fres.Header.Get("X-Conan-Server-Capabilities"); got != conanCenterCapabilities {
			t.Errorf("%s /v1/ping: capabilities header = %q, want %q", method, got, conanCenterCapabilities)
		}
	}
	if got := fr.requests("/v1/ping"); got != 2 {
		t.Errorf("upstream /v1/ping requests = %d, want 2", got)
	}
	if got := fr.requests("/v2/ping"); got != 0 {
		t.Errorf("the v1 probe must not be rewritten to /v2/ping (ConanCenter 404s it); got %d requests", got)
	}
	if got := m.Stats().MetadataServed; got != 2 {
		t.Errorf("metadata metric = %v, want 2", got)
	}
}

// TestV1PingHonorsUpstreamBasePath covers an Artifactory-style remote mounted
// beneath a path prefix: the probe must stay inside the repository's subtree.
func TestV1PingHonorsUpstreamBasePath(t *testing.T) {
	const prefix = "/artifactory/api/conan/conan-remote"
	fr := newFakeRemote(t)
	seedConanCenterPing(fr, prefix)
	b, err := New(Options{
		Name:        "art",
		UpstreamURL: fr.srv.URL + prefix + "/",
		Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fres, _, err := resolveFetch(t, b, "/v1/ping")
	if err != nil {
		t.Fatalf("fetch ping: %v", err)
	}
	if got := fres.Resolved.UpstreamURL; got != fr.srv.URL+prefix+"/v1/ping" {
		t.Errorf("upstream URL = %q", got)
	}
	if got := fres.Header.Get("X-Conan-Server-Capabilities"); got != conanCenterCapabilities {
		t.Errorf("capabilities header = %q", got)
	}
}

// TestV1OnlyServesThePing pins the scope of the v1 route: the probe is the one
// v1 request a Conan 2.x client sends, and the rest of the Conan 1.x API stays
// unsupported rather than being proxied blindly.
func TestV1OnlyServesThePing(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	for _, p := range []string{"/v1/users/authenticate", "/v1/conans/search", "/v1/ping/x", "/v1"} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q) error = %v, want ErrNotSupported", p, err)
		}
	}
}

// conanCenterRevision is a recipe revision and one of its package revisions in
// the shape ConanCenter serves them (modeled on zlib/1.3.1).
type conanCenterRevision struct {
	recipeDir  string
	packageDir string
	files      map[string][]byte // full path -> bytes
}

// seedConanCenterRevision registers a recipe revision and a package revision
// whose conanmanifest.txt files have the real format: they list conanfile.py /
// conaninfo.txt and the files *inside* the archives, but no .tgz. When
// checksumHeaders is true every file also carries Artifactory's X-Checksum-Md5
// (and -Sha256) response headers, as ConanCenter sends them; false models the
// reference conan_server, which sends none.
func seedConanCenterRevision(t *testing.T, fr *fakeRemote, checksumHeaders bool) conanCenterRevision {
	t.Helper()
	const (
		recipeDir  = "/v2/conans/zlib/1.3.1/_/_/revisions/cac0f6daea041b0ccf42934163defb20/files/"
		packageDir = "/v2/conans/zlib/1.3.1/_/_/revisions/cac0f6daea041b0ccf42934163defb20/packages/" +
			"b647c43bfefae3f830561ca202b6cfd935b56205/revisions/a45f5d44261c7453cca170255117367c/files/"
	)
	conanfile := []byte("from conan import ConanFile\n\nclass ZlibConan(ConanFile):\n    name = \"zlib\"\n")
	conandata := []byte("sources:\n  \"1.3.1\":\n    url: https://zlib.net/zlib-1.3.1.tar.gz\n")
	patch := []byte("--- a/CMakeLists.txt\n+++ b/CMakeLists.txt\n")
	conaninfo := []byte("[settings]\narch=x86_64\nbuild_type=Release\ncompiler=gcc\ncompiler.version=11\nos=Linux\n")
	libz := []byte("!<arch>\nlibz.a member bytes")

	rev := conanCenterRevision{recipeDir: recipeDir, packageDir: packageDir, files: map[string][]byte{
		recipeDir + "conanfile.py":      conanfile,
		recipeDir + "conan_export.tgz":  []byte("\x1f\x8b conan_export.tgz: conandata.yml"),
		recipeDir + "conan_sources.tgz": []byte("\x1f\x8b conan_sources.tgz: patches/1.3.1/0001-fix-cmake.patch"),
		recipeDir + manifestFile: []byte("1765284693\n" +
			"conandata.yml: " + md5Hex(conandata) + "\n" +
			"conanfile.py: " + md5Hex(conanfile) + "\n" +
			"export_source/patches/1.3.1/0001-fix-cmake.patch: " + md5Hex(patch) + "\n"),
		packageDir + conaninfoFile:       conaninfo,
		packageDir + "conan_package.tgz": []byte("\x1f\x8b conan_package.tgz: include/zlib.h lib/libz.a licenses/LICENSE"),
		packageDir + manifestFile: []byte("1765284769\n" +
			"conaninfo.txt: " + md5Hex(conaninfo) + "\n" +
			"include/zlib.h: " + md5Hex([]byte("#define ZLIB_VERSION \"1.3.1\"\n")) + "\n" +
			"lib/libz.a: " + md5Hex(libz) + "\n" +
			"licenses/LICENSE: " + md5Hex([]byte("zlib license\n")) + "\n"),
	}}
	for p, body := range rev.files {
		fr.files[p] = body
		if checksumHeaders {
			fr.hdrs[p] = http.Header{
				"X-Checksum-Md5":    {md5Hex(body)},
				"X-Checksum-Sha256": {fmt.Sprintf("%x", sha256.Sum256(body))},
			}
		}
	}
	return rev
}

// TestArchivesVerifiedAgainstUpstreamChecksumHeader is the regression test for
// what the real ConanCenter manifests look like: no .tgz is listed, so the
// archives — which carry all the sources and binaries — used to be cached with
// conan.checksumVerified=none. They must be MD5-verified against the
// X-Checksum-Md5 header the upstream sends with the file.
func TestArchivesVerifiedAgainstUpstreamChecksumHeader(t *testing.T) {
	fr := newFakeRemote(t)
	rev := seedConanCenterRevision(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	archives := []string{
		rev.recipeDir + "conan_export.tgz",
		rev.recipeDir + "conan_sources.tgz",
		rev.packageDir + "conan_package.tgz",
	}
	for _, p := range archives {
		fres, body, err := resolveFetch(t, b, p)
		if err != nil {
			t.Fatalf("fetch %s: %v", p, err)
		}
		if !bytes.Equal(body, rev.files[p]) {
			t.Errorf("%s: body mismatch", p)
		}
		md := fres.Resolved.Metadata
		if md[MetaChecksumVerified] != "md5" || md[MetaChecksumSource] != checksumSourceHeader {
			t.Errorf("%s: verified=%q source=%q, want md5/%s", p, md[MetaChecksumVerified], md[MetaChecksumSource], checksumSourceHeader)
		}
		if !fres.Resolved.Cacheable {
			t.Errorf("%s: must be cacheable", p)
		}
		if c := fres.Resolved.Coordinate; c.Name != "zlib" || c.Version != "1.3.1" {
			t.Errorf("%s: coordinate = %+v, want zlib@1.3.1", p, c)
		}
	}
	st := m.Stats()
	if st.FilesVerified != 3 || st.ManifestMissing != 0 || st.ChecksumMismatch != 0 {
		t.Errorf("metrics = %+v, want 3 verified / 0 missing / 0 mismatched", st)
	}
}

// TestManifestDigestTakesPrecedenceOverHeader confirms the designed check is
// unchanged where the manifest does record the file: conanfile.py and
// conaninfo.txt are verified against conanmanifest.txt, and the header is not
// consulted (here it is deliberately wrong).
func TestManifestDigestTakesPrecedenceOverHeader(t *testing.T) {
	fr := newFakeRemote(t)
	rev := seedConanCenterRevision(t, fr, true)
	bogus := http.Header{"X-Checksum-Md5": {md5Hex([]byte("unrelated bytes"))}}
	fr.hdrs[rev.recipeDir+"conanfile.py"] = bogus
	fr.hdrs[rev.packageDir+conaninfoFile] = bogus
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	for _, p := range []string{rev.recipeDir + "conanfile.py", rev.packageDir + conaninfoFile} {
		fres, body, err := resolveFetch(t, b, p)
		if err != nil {
			t.Fatalf("fetch %s: %v", p, err)
		}
		if !bytes.Equal(body, rev.files[p]) {
			t.Errorf("%s: body mismatch", p)
		}
		md := fres.Resolved.Metadata
		if md[MetaChecksumVerified] != "md5" || md[MetaChecksumSource] != checksumSourceManifest {
			t.Errorf("%s: verified=%q source=%q, want md5/%s", p, md[MetaChecksumVerified], md[MetaChecksumSource], checksumSourceManifest)
		}
	}
	if st := m.Stats(); st.FilesVerified != 2 || st.ManifestParsed != 2 {
		t.Errorf("metrics = %+v, want 2 verified / 2 manifests parsed", st)
	}
}

// TestArchiveChecksumHeaderMismatchRefused: bytes that do not hash to the MD5
// the upstream declared for them must fail the read (and thereby the cache
// write) instead of being served.
func TestArchiveChecksumHeaderMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	rev := seedConanCenterRevision(t, fr, true)
	p := rev.packageDir + "conan_package.tgz"
	fr.files[p] = []byte("\x1f\x8b truncated or swapped payload") // header still declares the genuine MD5
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, p)
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if cm.Filename != "conan_package.tgz" || !strings.HasPrefix(cm.Expected, "md5:") {
		t.Errorf("mismatch error = %+v", cm)
	}
	if st := m.Stats(); st.ChecksumMismatch != 1 || st.FilesVerified != 0 {
		t.Errorf("metrics = %+v, want 1 mismatch / 0 verified", st)
	}
}

// TestArchiveWithoutAnyDigestServedUnverified models the reference conan_server,
// which sends no X-Checksum-* headers: an archive the manifest cannot vouch for
// is still served (fail-open), and the gap is recorded rather than hidden.
func TestArchiveWithoutAnyDigestServedUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	rev := seedConanCenterRevision(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	p := rev.packageDir + "conan_package.tgz"
	fres, body, err := resolveFetch(t, b, p)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(body, rev.files[p]) {
		t.Error("body mismatch")
	}
	md := fres.Resolved.Metadata
	if md[MetaChecksumVerified] != "none" {
		t.Errorf("verified = %q, want none", md[MetaChecksumVerified])
	}
	if _, ok := md[MetaChecksumSource]; ok {
		t.Errorf("no checksum source must be recorded for an unverified file, got %q", md[MetaChecksumSource])
	}
	if st := m.Stats(); st.ManifestMissing != 1 || st.FilesVerified != 0 {
		t.Errorf("metrics = %+v, want 1 missing / 0 verified", st)
	}

	// The manifest still covers the files it names, headers or not.
	fres, _, err = resolveFetch(t, b, rev.packageDir+conaninfoFile)
	if err != nil {
		t.Fatalf("fetch conaninfo: %v", err)
	}
	if md := fres.Resolved.Metadata; md[MetaChecksumVerified] != "md5" || md[MetaChecksumSource] != checksumSourceManifest {
		t.Errorf("conaninfo.txt: verified=%q source=%q", md[MetaChecksumVerified], md[MetaChecksumSource])
	}
}

func TestHeaderMD5(t *testing.T) {
	sum := md5Hex([]byte("payload"))
	cases := []struct {
		name  string
		value string
		want  string
		ok    bool
	}{
		{"lowercase hex", sum, sum, true},
		{"uppercase hex is normalized", strings.ToUpper(sum), sum, true},
		{"surrounding whitespace", "  " + sum + " ", sum, true},
		{"absent", "", "", false},
		{"too short", sum[:31], "", false},
		{"too long (a sha1)", sum + "00000000", "", false},
		{"not hex", strings.Repeat("z", 32), "", false},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.value != "" {
			h.Set("X-Checksum-Md5", c.value)
		}
		got, ok := headerMD5(h)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: headerMD5 = %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}
