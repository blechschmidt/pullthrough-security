package swift

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
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// --- backend-detection / path-classification unit tests ---------------------

// TestClassify confirms the Swift registry route table is recognized exactly,
// that each path maps to the right resource kind, and that non-Swift or
// malformed paths are rejected (so the gateway reports them as unsupported
// rather than blindly proxying them).
func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/mona/LinkedList", kindReleases},
		{"/mona/LinkedList/1.1.1", kindRelease},
		{"/mona/LinkedList/1.1.1/Package.swift", kindManifest},
		{"/mona/LinkedList/1.1.1/Package@swift-5.3.swift", kindManifest},
		{"/mona/LinkedList/1.1.1.zip", kindArchive},
		{"/mona/Linked-List/2.0.0-beta.1.zip", kindArchive},
		{"/identifiers", kindIdentifiers},
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
		"/mona",                              // scope only, no name
		"/mona/LinkedList/1.1.1/other.txt",   // unknown file under version
		"/mona/LinkedList/1.1.1/sub/deep",    // too deep
		"/mona/LinkedList/.zip",              // empty version archive
		"/mona/-bad/1.0.0",                   // name may not lead with hyphen
		"/-bad/LinkedList",                   // scope may not lead with hyphen
		"/mo--na/LinkedList",                 // consecutive hyphens in scope
		"/mona/Linked__List",                 // consecutive underscores in name
		"/mona/LinkedList/1.1.1/../../etc/x", // traversal
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, _ := classify("/mona/LinkedList/1.1.1.zip")
	if res.coordinateName() != "mona.LinkedList" || res.version != "1.1.1" {
		t.Errorf("coordinate = %q@%q", res.coordinateName(), res.version)
	}
	if !res.isArchive() || !res.cacheable() {
		t.Error("archive should be an archive and cacheable")
	}
	rel, _ := classify("/mona/LinkedList")
	if rel.cacheable() {
		t.Error("release list is mutable and must not be cached")
	}
}

// --- metadata parsing -------------------------------------------------------

func TestParseReleaseMetadata(t *testing.T) {
	sum := sha256Hex([]byte("archive bytes"))
	body := fmt.Sprintf(`{
		"id": "mona.LinkedList",
		"version": "1.1.1",
		"resources": [
			{"name": "source-archive", "type": "application/zip", "checksum": %q}
		],
		"metadata": {"repositoryURLs": ["https://github.com/mona/LinkedList"]}
	}`, sum)
	rm, err := parseReleaseMetadata([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := rm.sourceArchiveChecksum()
	if !ok || got != sum {
		t.Errorf("checksum = %q ok=%v, want %q", got, ok, sum)
	}
	if rm.repositoryURL() != "https://github.com/mona/LinkedList" {
		t.Errorf("repositoryURL = %q", rm.repositoryURL())
	}

	// A metadata document with no source-archive checksum yields ok=false.
	rm2, _ := parseReleaseMetadata([]byte(`{"resources":[{"name":"other","checksum":"x"}]}`))
	if _, ok := rm2.sourceArchiveChecksum(); ok {
		t.Error("expected no checksum for non-source-archive resource")
	}
}

func TestNormalizeDigest(t *testing.T) {
	valid := sha256Hex([]byte("x"))
	if got, ok := normalizeDigest("sha256:" + valid); !ok || got != valid {
		t.Errorf("prefixed digest = %q ok=%v", got, ok)
	}
	if _, ok := normalizeDigest("md5:deadbeef"); ok {
		t.Error("non-sha256 algorithm should be rejected")
	}
	if _, ok := normalizeDigest("notlongenough"); ok {
		t.Error("short digest should be rejected")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine swift archive")
	exp := expectedChecksum{hex: sha256Hex(data)}
	var called, result bool
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(data)), exp, "http://x", func(ok bool) {
		called, result = true, ok
	})
	out, err := io.ReadAll(vr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, data) || !called || !result {
		t.Errorf("content/result wrong: eq=%v called=%v result=%v", bytes.Equal(out, data), called, result)
	}
}

func TestVerifyingReaderMismatch(t *testing.T) {
	exp := expectedChecksum{hex: sha256Hex([]byte("the real bytes"))}
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader([]byte("POISONED"))), exp, "http://x/a.zip", nil)
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
}

// --- integration: fake registry + backend -----------------------------------

type fakeRegistry struct {
	srv   *httptest.Server
	files map[string][]byte
	hdrs  map[string]http.Header
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	fr := &fakeRegistry{files: map[string][]byte{}, hdrs: map[string]http.Header{}}
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

func newTestBackend(t *testing.T, fr *fakeRegistry, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "swiftpm",
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
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
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

// seedArchive registers a release's metadata and source archive. When tamper is
// true, the metadata declares a checksum that does not match the served bytes.
func seedArchive(t *testing.T, fr *fakeRegistry, tamper bool) []byte {
	t.Helper()
	zip := []byte("PK\x03\x04 fake swift source archive")
	sum := sha256Hex(zip)
	if tamper {
		sum = sha256Hex([]byte("a different artifact"))
	}
	fr.files["/mona/LinkedList/1.1.1"] = []byte(fmt.Sprintf(
		`{"id":"mona.LinkedList","version":"1.1.1","resources":[{"name":"source-archive","type":"application/zip","checksum":%q}],"metadata":{"repositoryURLs":["https://github.com/mona/LinkedList"]}}`, sum))
	fr.files["/mona/LinkedList/1.1.1.zip"] = zip
	fr.hdrs["/mona/LinkedList/1.1.1.zip"] = http.Header{
		"Digest":       {"sha-256=" + sum},
		contentVersion: {"1"},
	}
	return zip
}

func TestArchiveVerifiesAndPropagatesHeaders(t *testing.T) {
	fr := newFakeRegistry(t)
	zip := seedArchive(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/mona/LinkedList/1.1.1.zip")
	if err != nil {
		t.Fatalf("fetch archive: %v", err)
	}
	if !bytes.Equal(body, zip) {
		t.Fatal("archive body mismatch")
	}
	if fres.MediaType != "application/zip" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Resolved.Metadata[MetaRepositoryURL] != "https://github.com/mona/LinkedList" {
		t.Errorf("repository URL metadata = %q", fres.Resolved.Metadata[MetaRepositoryURL])
	}
	if fres.Resolved.Coordinate.Name != "mona.LinkedList" || fres.Resolved.Coordinate.Version != "1.1.1" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if got := fres.Header.Get("Content-Version"); got != "1" {
		t.Errorf("content-version not propagated: %q", got)
	}
	if got := fres.Header.Get("Digest"); got == "" {
		t.Error("digest header not propagated")
	}
	if s := m.Stats(); s.ArchivesVerified != 1 || s.MetadataFetched != 1 {
		t.Errorf("metrics = %+v", s)
	}
}

func TestArchiveChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRegistry(t)
	seedArchive(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, "/mona/LinkedList/1.1.1.zip")
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestArchiveNoChecksumServedUnverified(t *testing.T) {
	fr := newFakeRegistry(t)
	zip := []byte("PK\x03\x04 archive without metadata checksum")
	fr.files["/mona/LinkedList/1.1.1.zip"] = zip
	// Metadata present but without a source-archive checksum.
	fr.files["/mona/LinkedList/1.1.1"] = []byte(`{"id":"mona.LinkedList","version":"1.1.1","resources":[]}`)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/mona/LinkedList/1.1.1.zip")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(body, zip) {
		t.Fatal("body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("checksum-missing metric = %v", m.Stats().ChecksumMissing)
	}
}

func TestReleaseMetadataProxiedAndCacheable(t *testing.T) {
	fr := newFakeRegistry(t)
	fr.files["/mona/LinkedList/1.1.1"] = []byte(`{"id":"mona.LinkedList","version":"1.1.1"}`)
	fr.hdrs["/mona/LinkedList/1.1.1"] = http.Header{contentVersion: {"1"}}
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/mona/LinkedList/1.1.1", Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Cacheable {
		t.Error("release metadata should be cacheable")
	}
	if res.Metadata[metaAccept] != acceptJSON {
		t.Errorf("default accept = %q", res.Metadata[metaAccept])
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	_ = fres.Content.Close()
	if fres.Header.Get("Content-Version") != "1" {
		t.Error("content-version not propagated for metadata")
	}
	if m.Stats().MetadataServed != 1 {
		t.Errorf("metadata metric = %v", m.Stats().MetadataServed)
	}
}

func TestManifestForwardsAcceptAndMediaType(t *testing.T) {
	fr := newFakeRegistry(t)
	fr.files["/mona/LinkedList/1.1.1/Package.swift"] = []byte("// swift-tools-version:5.7\n")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	res, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet,
		Path:   "/mona/LinkedList/1.1.1/Package.swift",
		Query:  url.Values{},
		Header: http.Header{"Accept": {acceptSwift}},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Metadata[metaAccept] != acceptSwift {
		t.Errorf("accept not forwarded: %q", res.Metadata[metaAccept])
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	_ = fres.Content.Close()
	if fres.MediaType != "text/x-swift; charset=utf-8" {
		t.Errorf("manifest media type = %q", fres.MediaType)
	}
	if m.Stats().ManifestsServed != 1 {
		t.Errorf("manifest metric = %v", m.Stats().ManifestsServed)
	}
}

func TestResolveRejectsNonSwiftPath(t *testing.T) {
	b := newTestBackend(t, newFakeRegistry(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/-bad//path", Query: url.Values{}, Header: http.Header{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRegistry(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/mona/LinkedList/9.9.9")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

// TestCachedResourcesDeclareProtocolHeaders pins the headers a cached Swift
// resource must be served with. A cacheable resource is always served from its
// cache entry, which carries only the headers the backend declares
// (backends.SetResponseHeader). SwiftPM refuses release metadata and a manifest
// without "Content-Version: 1" — found by running the real client through the
// proxy — and reads a release's version-specific manifests from the Link header
// of the manifest response. Link headers of release metadata (latest-version,
// successor-version) change when a release is published and are not replayed.
func TestCachedResourcesDeclareProtocolHeaders(t *testing.T) {
	fr := newFakeRegistry(t)
	zip := seedArchive(t, fr, false)
	// The archive comes from an object store the registry redirects to, which
	// sends no Content-Version (SwiftPM treats it as optional there).
	fr.hdrs["/mona/LinkedList/1.1.1.zip"] = http.Header{}
	fr.hdrs["/mona/LinkedList/1.1.1"] = http.Header{
		contentVersion: {"1"},
		"Link":         {`<https://registry.example/mona/LinkedList/1.2.0>; rel="latest-version"`},
	}
	fr.files["/mona/LinkedList/1.1.1/Package.swift"] = []byte("// swift-tools-version:5.7\n")
	fr.hdrs["/mona/LinkedList/1.1.1/Package.swift"] = http.Header{
		contentVersion: {"1"},
		"Link": {
			`</mona/LinkedList/1.1.1/Package.swift?swift-version=5.8>; rel="alternate"; filename="Package@swift-5.8.swift"; swift-tools-version="5.8"`,
			`</mona/LinkedList/1.1.1/Package.swift?swift-version=6.0>; rel="alternate"; filename="Package@swift-6.swift"; swift-tools-version="6.0"`,
		},
	}
	b := newTestBackend(t, fr, &Metrics{})

	cases := []struct {
		path string
		want map[string]string
	}{
		{"/mona/LinkedList/1.1.1", map[string]string{"Content-Version": "1"}},
		{"/mona/LinkedList/1.1.1/Package.swift", map[string]string{
			"Content-Version": "1",
			"Link": `</mona/LinkedList/1.1.1/Package.swift?swift-version=5.8>; rel="alternate"; filename="Package@swift-5.8.swift"; swift-tools-version="5.8", ` +
				`</mona/LinkedList/1.1.1/Package.swift?swift-version=6.0>; rel="alternate"; filename="Package@swift-6.swift"; swift-tools-version="6.0"`,
		}},
		{"/mona/LinkedList/1.1.1.zip", nil},
	}
	for _, c := range cases {
		fres, body, err := resolveFetch(t, b, c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if !fres.Resolved.Cacheable {
			t.Errorf("%s: not cacheable — the test would not cover the cache path", c.path)
		}
		if c.path == "/mona/LinkedList/1.1.1.zip" && !bytes.Equal(body, zip) {
			t.Errorf("%s: archive body mismatch", c.path)
		}
		got := backends.ResponseHeaders(fres.Resolved.Metadata)
		if len(got) != len(c.want) {
			t.Errorf("%s: declared response headers %v, want %v", c.path, got, c.want)
			continue
		}
		for name, value := range c.want {
			if got[name] != value {
				t.Errorf("%s: declared %s = %q, want %q", c.path, name, got[name], value)
			}
		}
	}
}
