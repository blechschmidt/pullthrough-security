package cpan

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

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/modules/02packages.details.txt.gz", kindIndex},
		{"/modules/03modlist.data.gz", kindIndex},
		{"/authors/id/E/ET/ETHER/CHECKSUMS", kindIndex},
		{"/authors/id/E/ET/ETHER/Try-Tiny-0.32.meta", kindIndex},
		{"/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz", kindDistribution},
		{"/authors/id/A/AB/ABC/Acme-CPANAuthors-Canadian-0.0108.tar.gz", kindDistribution},
		{"/authors/id/M/MO/MONGER/Foo-v1.2.3.tar.gz", kindDistribution},
		{"/authors/id/X/XY/XYZ/Thing-2.0.zip", kindDistribution},
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
		"/etc/passwd", // not under authors/ or modules/
		"/authors/id/E/ET/ETHER/../../../etc/passwd", // traversal
		"/favicon.ico", // top-level stray
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, ok := classify("/authors/id/A/AB/ABC/Acme-CPANAuthors-Canadian-0.0108.tar.gz")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "Acme-CPANAuthors-Canadian" || res.version != "0.0108" {
		t.Errorf("coordinate = %q/%q", res.name, res.version)
	}
	if !res.cacheable() || !res.verifiableFile() {
		t.Error("a distribution should be cacheable and verifiable")
	}

	// CHECKSUMS and module indices are mutable and not verifiable.
	for _, p := range []string{"/authors/id/E/ET/ETHER/CHECKSUMS", "/modules/02packages.details.txt.gz"} {
		idx, _ := classify(p)
		if idx.cacheable() {
			t.Errorf("%q is mutable and must not be cacheable", p)
		}
		if idx.verifiableFile() {
			t.Errorf("%q is not a verifiable distribution", p)
		}
	}
}

func TestParseDistFilename(t *testing.T) {
	cases := []struct {
		in        string
		name, ver string
		ok        bool
	}{
		{"Try-Tiny-0.32.tar.gz", "Try-Tiny", "0.32", true},
		{"Mojolicious-9.35.tar.gz", "Mojolicious", "9.35", true},
		{"Acme-CPANAuthors-Canadian-0.0108.tar.gz", "Acme-CPANAuthors-Canadian", "0.0108", true},
		{"Foo-v1.2.3.tar.gz", "Foo", "v1.2.3", true},
		{"Bar-2.0.zip", "Bar", "2.0", true},
		{"Baz-1.0.tar.bz2", "Baz", "1.0", true},
		{"Qux-3.1.tar.xz", "Qux", "3.1", true},
	}
	for _, c := range cases {
		n, v, ok := parseDistFilename(c.in)
		if ok != c.ok || n != c.name || v != c.ver {
			t.Errorf("parseDistFilename(%q) = %q/%q ok=%v, want %q/%q ok=%v", c.in, n, v, ok, c.name, c.ver, c.ok)
		}
	}

	// No recognized extension -> not a distribution.
	if _, _, ok := parseDistFilename("README"); ok {
		t.Error("README should not parse as a distribution")
	}
	// Archive extension but no version boundary -> still a distribution (verified
	// by filename) but with no coordinate.
	n, v, ok := parseDistFilename("Foo-Bar.tar.gz")
	if !ok || n != "" || v != "" {
		t.Errorf("Foo-Bar.tar.gz = %q/%q ok=%v, want empty coordinate ok=true", n, v, ok)
	}
}

// --- CHECKSUMS parsing ------------------------------------------------------

const sampleChecksums = `0&&<<''; # this PGP-signed message is also valid perl
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

$cksum = {
  'Try-Tiny-0.32.meta' => {
    'mtime' => '2024-08-16',
    'size' => 2048
  },
  'Try-Tiny-0.32.tar.gz' => {
    'cpan_path' => 'E/ET/ETHER',
    'md5' => '964424fcada4654bede745a7a2fb870b',
    'md5-ungz' => 'deadbeefdeadbeefdeadbeefdeadbeef',
    'mtime' => '2024-08-16',
    'sha256' => '%s',
    'sha256-ungz' => 'bf7a517c6a1577242f36d9a7a6580e0bbb3a0cb79043cf3184ba6b33741e867e',
    'size' => 83456
  }
};
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE...
-----END PGP SIGNATURE-----
`

func TestParseChecksums(t *testing.T) {
	want := sha256Hex([]byte("try-tiny tarball"))
	body := fmt.Sprintf(sampleChecksums, want)
	cs, err := ParseChecksums([]byte(body))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	got, ok := cs.sha256For("Try-Tiny-0.32.tar.gz")
	if !ok || got != want {
		t.Errorf("sha256For = %q ok=%v, want %q", got, ok, want)
	}
	// The .meta entry has no sha256 field and must not resolve.
	if _, ok := cs.sha256For("Try-Tiny-0.32.meta"); ok {
		t.Error(".meta entry without sha256 should not resolve")
	}
	if _, ok := cs.sha256For("absent.tar.gz"); ok {
		t.Error("absent file must not resolve")
	}
}

func TestParseChecksumsRejectsMalformedDigest(t *testing.T) {
	body := `$cksum = {
  'p-1.0.tar.gz' => {
    'sha256' => 'deadbeef',
    'size' => 1
  }
};
`
	cs, err := ParseChecksums([]byte(body))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	if _, ok := cs.sha256For("p-1.0.tar.gz"); ok {
		t.Error("malformed short digest should be skipped")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine cpan distribution bytes")
	exp := expectedChecksum{filename: "p-1.0.tar.gz", sha256: sha256Hex(data)}
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
	exp := expectedChecksum{filename: "p-1.0.tar.gz", sha256: sha256Hex([]byte("the real bytes"))}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "http://x/p.tar.gz", func(ok bool) {
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

// --- integration: fake mirror + backend -------------------------------------

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
		Name:        "cpan",
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

// seedDistribution registers a distribution tarball and the sibling CHECKSUMS
// file. When tamper is true, CHECKSUMS declares a SHA-256 that does not match the
// bytes.
func seedDistribution(t *testing.T, fr *fakeRemote, tamper bool) (tarball []byte, path string) {
	t.Helper()
	tgz := []byte("\x1f\x8b fake Try-Tiny distribution tarball")
	sum := sha256Hex(tgz)
	if tamper {
		sum = sha256Hex([]byte("a different artifact"))
	}
	dir := "/authors/id/E/ET/ETHER/"
	fname := "Try-Tiny-0.32.tar.gz"
	fr.files[dir+fname] = tgz
	fr.files[dir+"CHECKSUMS"] = []byte(fmt.Sprintf(sampleChecksums, sum))
	fr.hdrs[dir+fname] = http.Header{"X-Cpan-Something": {"v"}}
	return tgz, dir + fname
}

func TestDistributionVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	tgz, path := seedDistribution(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch distribution: %v", err)
	}
	if !bytes.Equal(body, tgz) {
		t.Fatal("tarball body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("distribution should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "application/gzip" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Coordinate.Name != "Try-Tiny" || fres.Resolved.Coordinate.Version != "0.32" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.DistributionsVerified != 1 || st.ChecksumsFetched != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestDistributionChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedDistribution(t, fr, true)
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

func TestDistributionMissingChecksumsServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	// Distribution with no sibling CHECKSUMS file.
	path := "/authors/id/N/NO/NONE/Lonely-1.0.tar.gz"
	fr.files[path] = []byte("tarball, no CHECKSUMS here")
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

func TestIndexServed(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/modules/02packages.details.txt.gz"] = []byte("File: 02packages.details.txt\nURL: ...\n")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/modules/02packages.details.txt.gz")
	if err != nil {
		t.Fatalf("fetch index: %v", err)
	}
	if !bytes.Contains(body, []byte("02packages")) {
		t.Errorf("index body unexpected: %q", body)
	}
	if fres.Resolved.Cacheable {
		t.Error("module index must not be cacheable")
	}
	if fres.MediaType != "application/gzip" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if m.Stats().IndexServed != 1 {
		t.Errorf("index-served metric = %v", m.Stats().IndexServed)
	}
}

func TestChecksumsServedLive(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/authors/id/E/ET/ETHER/CHECKSUMS"] = []byte("$cksum = {};\n")
	b := newTestBackend(t, fr, &Metrics{})

	fres, _, err := resolveFetch(t, b, "/authors/id/E/ET/ETHER/CHECKSUMS")
	if err != nil {
		t.Fatalf("fetch CHECKSUMS: %v", err)
	}
	if fres.Resolved.Cacheable {
		t.Error("CHECKSUMS must not be cacheable")
	}
	if v := fres.Resolved.Metadata[MetaChecksumVerified]; v != "" {
		t.Errorf("CHECKSUMS should not carry verification metadata, got %q", v)
	}
}

func TestResolveRejectsNonCpanPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/cpan/file.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/authors/id/A/AB/ABC/Absent-1.0.tar.gz")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestSiblingURL(t *testing.T) {
	got, ok := siblingURL("https://u/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz", checksumsFile)
	if !ok || got != "https://u/authors/id/E/ET/ETHER/CHECKSUMS" {
		t.Errorf("siblingURL = %q ok=%v", got, ok)
	}
}
