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
	"strings"
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
		{"/installs/hex-1.x.csv", kindInstall},        // Hex's update check, `mix local.hex`
		{"/installs/hex-1.x.csv.signed", kindInstall},
		{"/installs/1.16.0/hex-2.7.0.ez", kindInstall},
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
		"/installs",                // the tree root is not a file
		"/installs/../names",       // traversal
		"/installs/secrets.txt",    // not an install list
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
	// redirects maps a request path to the location it 301-redirects to, the way
	// repo.hex.pm sends the whole /installs/ tree to builds.hex.pm.
	redirects map[string]string
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}, hdrs: map[string]http.Header{}, redirects: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if to, ok := fr.redirects[r.URL.Path]; ok {
			http.Redirect(w, r, to, http.StatusMovedPermanently)
			return
		}
		if h, ok := fr.hdrs[r.URL.Path]; ok {
			for k, vs := range h {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			// Honor a conditional request against the configured validator.
			if inm := r.Header.Get("If-None-Match"); inm != "" && inm == w.Header().Get("ETag") {
				w.WriteHeader(http.StatusNotModified)
				return
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

// --- /installs/ tree (real-client regression: mix/hex 2.7 with HEX_MIRROR) ----
//
// With HEX_MIRROR set, Hex's update check fetches <mirror>/installs/hex-1.x.csv
// and `mix local.hex` / `mix local.rebar` fetch a builds list, its .signed
// sibling, and the build itself from the mirror. The backend used to answer 501
// ("Failed to check for new Hex version / request not supported by backend").

// TestClassifyInstall pins the exact /installs/ shapes the real clients request
// (across Elixir generations) and that nothing else in the tree is proxied.
func TestClassifyInstall(t *testing.T) {
	good := []string{
		// Elixir <= 1.17: versioned list names, signed.
		"/installs/hex-1.x.csv",
		"/installs/hex-1.x.csv.signed",
		"/installs/rebar3-1.x.csv",
		"/installs/rebar3-1.x.csv.signed",
		"/installs/rebar-1.x.csv", // Rebar 2 list (Elixir <= 1.13)
		"/installs/rebar-1.x.csv.signed",
		// Elixir 1.18+: unversioned list names.
		"/installs/hex.csv",
		"/installs/hex.csv.signed",
		"/installs/rebar.csv",
		"/installs/rebar.csv.signed",
		// Builds, without and with the OTP-release qualifier.
		"/installs/1.16.0/hex-2.7.0.ez",
		"/installs/1.18.0/hex-2.7.0-otp-27.ez",
		"/installs/1.14.5/rebar3-3.22.0",
		"/installs/1.15.0-rc.0/rebar3-3.22.0",
		"/installs/1.18.4/rebar3-3.28.0-otp-28",
		"/installs/1.13.0/rebar-2.6.4",
		"/installs/1.0.0/hex-0.14.0.ez",
	}
	for _, p := range good {
		res, ok := classify(p)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", p)
			continue
		}
		if res.kind != kindInstall {
			t.Errorf("classify(%q).kind = %v, want kindInstall", p, res.kind)
		}
		if want := p[len("/installs/"):]; res.filename != want {
			t.Errorf("classify(%q).filename = %q, want %q", p, res.filename, want)
		}
		// Live pass-through: never cached, never verified here, and no package
		// coordinate (the Hex and Rebar tools are not hex.pm packages).
		if res.cacheable() || res.verifiableFile() || res.isRegistryResource() {
			t.Errorf("classify(%q): cacheable=%v verifiable=%v registry=%v, want all false",
				p, res.cacheable(), res.verifiableFile(), res.isRegistryResource())
		}
		if res.coordinateName() != "" || res.version != "" {
			t.Errorf("classify(%q): unexpected coordinate %q@%q", p, res.coordinateName(), res.version)
		}
		if res.kindLabel() != "install" {
			t.Errorf("classify(%q).kindLabel = %q", p, res.kindLabel())
		}
	}

	bad := []string{
		"/installs",                                              // the tree root
		"/installs/",                                             // ditto
		"/installs/list.csv",                                     // unknown tool
		"/installs/hex-1.x.txt",                                  // not a csv
		"/installs/hex-1.x.csv.sig",                              // unknown signature suffix
		"/installs/hex-1.x.csv.signed.signed",                    // doubled suffix
		"/installs/hex-.csv",                                     // empty series
		"/installs/hex-x.csv",                                    // series without a major
		"/installs/hex-1.y.csv",                                  // not an "<N>.x" series
		"/installs/hex-1.x.csv/extra",                            // a list has no children
		"/installs/npm.csv",                                      // unknown tool
		"/installs/Hex.csv",                                      // case matters
		"/installs/.csv",                                         // no tool
		"/installs/hex.ez",                                       // unversioned build at the root
		"/installs/1.16.0",                                       // directory, not a file
		"/installs/1.16.0/hex.ez",                                // unversioned build
		"/installs/1.16.0/hex-2.7.0",                             // Hex build without .ez
		"/installs/1.16.0/hex-.ez",                               // empty version
		"/installs/1.16.0/hex-latest.ez",                         // version must start with a digit
		"/installs/1.16.0/hex-2.7.0.ez/x",                        // a build has no children
		"/installs/1.16.0/erlang-26.tar.gz",                      // unknown tool
		"/installs/1.16.0/rebar3",                                // unversioned escript
		"/installs/latest/hex-2.7.0.ez",                          // Elixir dir must be a version
		"/installs/1.16.0/hex-2.7.0%2e.ez",                       // escapes are not version characters
		"/installs/1.16.0/hex-2.7.0 .ez",                         // nor is whitespace
		"/installs/1.16.0/hex-2.7.0?.ez",                         // nor a query delimiter
		"/installs/../packages/jason",                            // traversal out of the tree
		"/installs/1.16.0/../../names",                           // traversal out of the tree
		"/installs/./hex-1.x.csv",                                // dot segment
		"/installs//hex-1.x.csv",                                 // empty segment
		"/installs/1.16.0\\hex-2.7.0.ez",                         // backslash is not a separator
		"/installs/1.16.0/sub/hex-2.7.0.ez",                      // too deep
		"/installs/" + strings.Repeat("1", 65) + "/hex-2.7.0.ez", // overlong version segment
	}
	for _, p := range bad {
		if res, ok := classify(p); ok {
			t.Errorf("classify(%q) unexpectedly ok: %+v", p, res)
		}
	}
}

// seedInstalls registers a builds list, its signature, and one build. The list
// bytes deliberately include a CRLF and a trailing line without a newline: Mix
// verifies an RSA signature over the exact bytes, so pass-through must not
// normalize anything.
func seedInstalls(fr *fakeRemote) (csv, sig, ez []byte) {
	csv = []byte("2.6.0,aaaa,1.15.0\r\n2.7.0,c40a728a81ca98aa,1.16.0\n2.7.0,ffff,1.17.0")
	sig = []byte("qTLRsB5hHxqrLv3jj/q7sugskNuJgHmUrX/RRTEKB0sIp7BZPxWMyD4nnNaGLTPU\nVUSHYRkCigye3AEJ\n")
	ez = append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x00, 0xff, 0x1f, 0x8b}, 64)...)

	fr.files["/installs/hex-1.x.csv"] = csv
	h := http.Header{}
	h.Set("Content-Type", "text/csv")
	h.Set("ETag", `"9f20e2f4154c24c306198bc8507b8589"`)
	fr.hdrs["/installs/hex-1.x.csv"] = h

	fr.files["/installs/hex-1.x.csv.signed"] = sig
	fr.hdrs["/installs/hex-1.x.csv.signed"] = http.Header{"Content-Type": {"binary/octet-stream"}}

	fr.files["/installs/1.16.0/hex-2.7.0.ez"] = ez
	fr.hdrs["/installs/1.16.0/hex-2.7.0.ez"] = http.Header{"Content-Type": {"application/andrew-inset"}}
	return csv, sig, ez
}

// TestInstallsServedLiveByteExact is the regression test for the 501: every
// file of the self-install flow resolves to the same path on the upstream, is
// served live (not cacheable, no coordinate, no verification), and is returned
// byte for byte with the upstream's content type.
func TestInstallsServedLiveByteExact(t *testing.T) {
	fr := newFakeRemote(t)
	csv, sig, ez := seedInstalls(fr)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	cases := []struct {
		path string
		want []byte
		ct   string
	}{
		{"/installs/hex-1.x.csv", csv, "text/csv"},
		{"/installs/hex-1.x.csv.signed", sig, "binary/octet-stream"},
		{"/installs/1.16.0/hex-2.7.0.ez", ez, "application/andrew-inset"},
	}
	for _, c := range cases {
		fres, body, err := resolveFetch(t, b, c.path)
		if err != nil {
			t.Fatalf("fetch %s: %v", c.path, err)
		}
		if !bytes.Equal(body, c.want) {
			t.Errorf("%s: body is not byte-exact (got %d bytes, want %d)", c.path, len(body), len(c.want))
		}
		res := fres.Resolved
		if want := fr.srv.URL + c.path; res.UpstreamURL != want {
			t.Errorf("%s: upstream URL = %q, want %q", c.path, res.UpstreamURL, want)
		}
		if res.Cacheable {
			t.Errorf("%s: must be served live, not cached", c.path)
		}
		if res.Coordinate != (backends.Coordinate{}) {
			t.Errorf("%s: must carry no package coordinate, got %+v", c.path, res.Coordinate)
		}
		if res.Metadata[metaVerify] == "1" {
			t.Errorf("%s: must not be marked for proxy-side verification", c.path)
		}
		if _, ok := res.Metadata[MetaChecksumVerified]; ok {
			t.Errorf("%s: no checksum verdict should be recorded for a pass-through file", c.path)
		}
		if fres.MediaType != c.ct {
			t.Errorf("%s: media type = %q, want %q", c.path, fres.MediaType, c.ct)
		}
		if fres.Size != int64(len(c.want)) {
			t.Errorf("%s: size = %d, want %d", c.path, fres.Size, len(c.want))
		}
	}
	st := m.Stats()
	if st.InstallsServed != 3 {
		t.Errorf("installs-served metric = %v, want 3", st.InstallsServed)
	}
	// Pass-through files are not registry resources, tarballs, or digest lookups.
	if st.RegistryServed != 0 || st.TarballsServed != 0 || st.ResourceFetched != 0 || st.ChecksumMissing != 0 {
		t.Errorf("unrelated metrics moved: %+v", st)
	}
}

// TestInstallsFollowUpstreamRedirect mirrors the real upstream: repo.hex.pm
// answers every /installs/ request with a 301 to builds.hex.pm. The backend must
// follow it and still hand back the exact bytes.
func TestInstallsFollowUpstreamRedirect(t *testing.T) {
	builds := newFakeRemote(t)
	csv, _, ez := seedInstalls(builds)

	repo := newFakeRemote(t)
	repo.redirects["/installs/hex-1.x.csv"] = builds.srv.URL + "/installs/hex-1.x.csv"
	repo.redirects["/installs/1.16.0/hex-2.7.0.ez"] = builds.srv.URL + "/installs/1.16.0/hex-2.7.0.ez"
	b := newTestBackend(t, repo, &Metrics{})

	for path, want := range map[string][]byte{
		"/installs/hex-1.x.csv":         csv,
		"/installs/1.16.0/hex-2.7.0.ez": ez,
	} {
		_, body, err := resolveFetch(t, b, path)
		if err != nil {
			t.Fatalf("fetch %s: %v", path, err)
		}
		if !bytes.Equal(body, want) {
			t.Errorf("%s: body after redirect is not byte-exact", path)
		}
	}
}

// TestInstallsConditionalRequest: a live resource is revalidated with the
// client's validator, and an upstream 304 is reported so the gateway can relay
// it instead of re-sending the list.
func TestInstallsConditionalRequest(t *testing.T) {
	fr := newFakeRemote(t)
	seedInstalls(fr)
	b := newTestBackend(t, fr, &Metrics{})

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/installs/hex-1.x.csv", Query: url.Values{}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	res.IfNoneMatch = `"9f20e2f4154c24c306198bc8507b8589"`
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !fres.NotModified || fres.Content != nil {
		t.Errorf("want a 304 with no body, got NotModified=%v content=%v", fres.NotModified, fres.Content != nil)
	}
}

// TestInstallsUpstreamMissPropagated: an install file the upstream does not have
// (e.g. a build for an Elixir release Hex never targeted) surfaces as the
// upstream's 404, not as a proxy error.
func TestInstallsUpstreamMissPropagated(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, _, err := resolveFetch(t, b, "/installs/9.9.9/hex-2.7.0.ez")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

// TestInstallsRejectedPathsNeverReachUpstream: a path outside the allowlist is
// refused at Resolve, so the upstream is never asked for it.
func TestInstallsRejectedPathsNeverReachUpstream(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	for _, p := range []string{"/installs/secrets.txt", "/installs/../names", "/installs/1.16.0/hex.ez", "/installs"} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q) error = %v, want ErrNotSupported", p, err)
		}
	}
}
