package hex

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// --- protobuf fixture builders ----------------------------------------------
//
// These mirror the subset of the Hex registry-v2 wire format the backend reads:
// a gzip-compressed Signed{payload=Package} envelope whose Package carries
// releases with a version and an outer_checksum.

func pbVarint(x uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], x)
	return buf[:n]
}

func pbTag(field, wire int) []byte { return pbVarint(uint64(field<<3 | wire)) }

func pbLenField(field int, val []byte) []byte {
	out := pbTag(field, wireLen)
	out = append(out, pbVarint(uint64(len(val)))...)
	return append(out, val...)
}

func pbString(field int, s string) []byte { return pbLenField(field, []byte(s)) }

// encodeRelease builds a Release{version, outer_checksum}.
func encodeRelease(version string, outer []byte) []byte {
	var b []byte
	b = append(b, pbString(fieldReleaseVersion, version)...)
	b = append(b, pbLenField(fieldReleaseOuter, outer)...)
	return b
}

// encodePackageResource builds the full on-wire /packages/<name> body: a
// gzip(Signed{payload=Package{releases...}}). versions maps version -> tarball
// bytes; the outer_checksum is the SHA-256 of those bytes.
func encodePackageResource(t *testing.T, name string, versions map[string][]byte) []byte {
	t.Helper()
	var pkg []byte
	for v, tarball := range versions {
		sum := sha256.Sum256(tarball)
		pkg = append(pkg, pbLenField(fieldPackageRelease, encodeRelease(v, sum[:]))...)
	}
	pkg = append(pkg, pbString(2, name)...) // Package.name = field 2
	signed := pbLenField(fieldSignedPayload, pkg)
	signed = append(signed, pbLenField(2, []byte("fake-signature"))...) // Signed.signature
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	if _, err := zw.Write(signed); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return zbuf.Bytes()
}

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/names", kindNames},
		{"/versions", kindVersions},
		{"/packages/jason", kindPackageIndex},
		{"/packages/plug_cowboy", kindPackageIndex},
		{"/tarballs/jason-1.4.1.tar", kindTarball},
		{"/tarballs/plug_cowboy-2.6.1.tar", kindTarball},
		{"/tarballs/foo-1.0.0-rc.1.tar", kindTarball}, // pre-release version
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
		"/names/extra",             // names takes no trailing segment
		"/versions/x",              // versions takes no trailing segment
		"/packages",                // missing name
		"/packages/Foo",            // uppercase not a valid hex name
		"/packages/a/b",            // too many segments
		"/packages/foo-bar",        // hyphen not allowed in a package name
		"/tarballs/noversion.tar",  // no hyphen -> no version
		"/tarballs/-1.0.tar",       // empty name
		"/tarballs/foo-.tar",       // empty version
		"/tarballs/foo-1.0",        // missing .tar
		"/docs/foo-1.0.tar",        // not a hex route
		"/tarballs/../etc/passwd",  // traversal
		"/packages/../../etc/pass", // traversal
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, ok := classify("/tarballs/ecto_sql-3.11.1.tar")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "ecto_sql" || res.version != "3.11.1" {
		t.Errorf("coordinate = %q/%q", res.name, res.version)
	}
	if !res.cacheable() || !res.verifiableFile() {
		t.Error("a pinned tarball should be cacheable and verifiable")
	}

	pkgIdx, _ := classify("/packages/ecto_sql")
	if pkgIdx.cacheable() || pkgIdx.verifiableFile() {
		t.Error("/packages/<name> is mutable and must not be cacheable/verifiable")
	}
	if pkgIdx.coordinateName() != "ecto_sql" {
		t.Errorf("package-index coordinate = %q", pkgIdx.coordinateName())
	}

	names, _ := classify("/names")
	if names.cacheable() || names.coordinateName() != "" {
		t.Error("/names is mutable and carries no coordinate")
	}
}

func TestParseTarballFilename(t *testing.T) {
	n, v, ok := parseTarballFilename("phoenix-1.7.11.tar")
	if !ok || n != "phoenix" || v != "1.7.11" {
		t.Errorf("parse = %q/%q ok=%v", n, v, ok)
	}
	n, v, ok = parseTarballFilename("foo-1.0.0-rc.1.tar")
	if !ok || n != "foo" || v != "1.0.0-rc.1" {
		t.Errorf("prerelease parse = %q/%q ok=%v", n, v, ok)
	}
	if _, _, ok := parseTarballFilename("noext-1.0"); ok {
		t.Error("filename without .tar should not parse")
	}
}

// --- registry (protobuf) parsing --------------------------------------------

func TestParsePackageResource(t *testing.T) {
	jasonTar := []byte("jason tarball bytes")
	plugTar := []byte("plug tarball bytes v2")
	body := encodePackageResource(t, "jason", map[string][]byte{
		"1.4.1": jasonTar,
		"1.4.0": plugTar,
	})
	idx, err := ParsePackageResource(body)
	if err != nil {
		t.Fatalf("ParsePackageResource: %v", err)
	}
	wantJason := sha256.Sum256(jasonTar)
	if got, ok := idx.outerFor("1.4.1"); !ok || got != toHex(wantJason[:]) {
		t.Errorf("outer 1.4.1 = %q ok=%v, want %q", got, ok, toHex(wantJason[:]))
	}
	if _, ok := idx.outerFor("9.9.9"); ok {
		t.Error("absent version must not resolve")
	}
	if _, ok := idx.outerFor(""); ok {
		t.Error("empty version must not resolve")
	}
}

func TestParsePackageResourceRejectsGarbage(t *testing.T) {
	if _, err := ParsePackageResource([]byte("not gzip, not protobuf, random bytes \x00\x01")); err == nil {
		// The bytes are not gzip, so they are treated as the raw Signed payload;
		// a malformed Signed envelope (no payload) must be an error.
		t.Error("expected error for a body that is neither valid gzip nor a valid Signed envelope")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine hex tarball bytes")
	sum := sha256.Sum256(data)
	exp := expectedChecksum{filename: "p-1.0.0.tar", sha256: toHex(sum[:])}
	var called, result bool
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(data)), exp, "http://x", func(ok bool) {
		called, result = true, ok
	})
	out, err := io.ReadAll(vr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Error("content mangled")
	}
	if !called || !result {
		t.Errorf("onResult called=%v result=%v", called, result)
	}
}

func TestVerifyingReaderMismatch(t *testing.T) {
	served := []byte("POISONED PAYLOAD")
	real := sha256.Sum256([]byte("the real bytes"))
	exp := expectedChecksum{filename: "p-1.0.0.tar", sha256: toHex(real[:])}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "http://x/p.tar", func(ok bool) {
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

// --- integration: fake repository + backend ---------------------------------

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
		Name:        "hex",
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

// seedPackage registers a release tarball and the sibling /packages/<name>
// resource. When tamper is true, the resource declares an outer_checksum that
// does not match the bytes.
func seedPackage(t *testing.T, fr *fakeRemote, tamper bool) (tarball []byte, path string) {
	t.Helper()
	tar := []byte("jason-1.4.1 outer tarball bytes")
	declared := tar
	if tamper {
		declared = []byte("a completely different artifact")
	}
	fr.files["/tarballs/jason-1.4.1.tar"] = tar
	fr.files["/packages/jason"] = encodePackageResource(t, "jason", map[string][]byte{"1.4.1": declared})
	fr.hdrs["/tarballs/jason-1.4.1.tar"] = http.Header{"X-Hex-Something": {"v"}}
	return tar, "/tarballs/jason-1.4.1.tar"
}

func TestTarballVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	tar, path := seedPackage(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch tarball: %v", err)
	}
	if !bytes.Equal(body, tar) {
		t.Fatal("tarball body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("tarball should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Header.Get("X-Checksum-Verified") != "sha256" {
		t.Errorf("X-Checksum-Verified = %q", fres.Header.Get("X-Checksum-Verified"))
	}
	if fres.MediaType != "application/octet-stream" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Coordinate.Name != "jason" || fres.Resolved.Coordinate.Version != "1.4.1" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.TarballsVerified != 1 || st.ResourceFetched != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestTarballChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedPackage(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, path)
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

func TestTarballMissingResourceServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	// Tarball present but no sibling /packages/<name> resource.
	path := "/tarballs/orphan-0.1.0.tar"
	fr.files[path] = []byte("orphan tarball, no package resource")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty body")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("checksum-missing metric = %v", m.Stats().ChecksumMissing)
	}
}

func TestRegistryResourceServed(t *testing.T) {
	fr := newFakeRemote(t)
	body := encodePackageResource(t, "jason", map[string][]byte{"1.4.1": []byte("x")})
	fr.files["/packages/jason"] = body
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, got, err := resolveFetch(t, b, "/packages/jason")
	if err != nil {
		t.Fatalf("fetch /packages/jason: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("registry resource must be served byte-exact")
	}
	if fres.Resolved.Cacheable {
		t.Error("/packages/<name> must not be cacheable")
	}
	if fres.MediaType != "application/octet-stream" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if m.Stats().RegistryServed != 1 {
		t.Errorf("registry-served metric = %v", m.Stats().RegistryServed)
	}
}

func TestResolveRejectsNonHexPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/hex/file.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/tarballs/absent-1.0.0.tar")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestPackageResourceURL(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	got := b.packageResourceURL("jason")
	if want := b.base.String() + "/packages/jason"; got != want {
		t.Errorf("packageResourceURL = %q, want %q", got, want)
	}
}
