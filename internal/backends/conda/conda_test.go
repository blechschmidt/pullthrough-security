package conda

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
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func md5Hex(b []byte) string    { return fmt.Sprintf("%x", md5.Sum(b)) }

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/noarch/repodata.json", kindRepodata},
		{"/linux-64/repodata.json", kindRepodata},
		{"/linux-64/repodata.json.bz2", kindRepodata},
		{"/osx-arm64/current_repodata.json", kindRepodata},
		{"/channeldata.json", kindChannelData},
		{"/conda-forge/channeldata.json", kindChannelData},
		{"/linux-64/numpy-1.26.0-py312h0_0.tar.bz2", kindPackage},
		{"/linux-aarch64/numpy-1.26.0-py312h0_0.conda", kindPackage},
		{"/noarch/tzdata-2024a-h0c530f3_0.conda", kindPackage},
		{"/win-64/some-pkg-name-1.2.3-build_0.conda", kindPackage},
		{"/conda-forge/linux-64/zlib-1.3.1-h0_0.conda", kindPackage},
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
		"/repodata.json",                   // repodata without a subdir
		"/numpy-1.0-0.conda",               // package without a subdir
		"/bogus/repodata.json",             // not a valid subdir
		"/linux-64/notapackage.txt",        // unknown file
		"/linux-64/missingcoords.conda",    // no version/build to parse
		"/linux-64/../../etc/passwd.conda", // traversal
		"/linux-64/foo",                    // no recognized extension
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, ok := classify("/linux-64/scikit-learn-1.4.0-py312h0_0.conda")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "scikit-learn" || res.version != "1.4.0" || res.build != "py312h0_0" {
		t.Errorf("coordinate = %q/%q/%q", res.name, res.version, res.build)
	}
	if res.subdir != "linux-64" {
		t.Errorf("subdir = %q", res.subdir)
	}
	if !res.cacheable() || !res.verifiableFile() {
		t.Error("a pinned package should be cacheable and verifiable")
	}

	idx, _ := classify("/linux-64/repodata.json")
	if idx.cacheable() {
		t.Error("repodata.json is mutable and must not be cacheable")
	}
	if idx.verifiableFile() {
		t.Error("repodata.json is not a verifiable package")
	}
}

func TestParsePackageFilename(t *testing.T) {
	n, v, b, ok := parsePackageFilename("numpy-1.26.0-py312h0_0.tar.bz2")
	if !ok || n != "numpy" || v != "1.26.0" || b != "py312h0_0" {
		t.Errorf("parse = %q/%q/%q ok=%v", n, v, b, ok)
	}
	n, v, b, ok = parsePackageFilename("python-dateutil-2.9.0-pyhd8ed1ab_0.conda")
	if !ok || n != "python-dateutil" || v != "2.9.0" || b != "pyhd8ed1ab_0" {
		t.Errorf("hyphenated name parse = %q/%q/%q ok=%v", n, v, b, ok)
	}
	if _, _, _, ok := parsePackageFilename("nover.conda"); ok {
		t.Error("filename without version/build should not parse")
	}
}

// --- repodata parsing -------------------------------------------------------

func TestRepodataChecksum(t *testing.T) {
	tgz := []byte("legacy archive")
	conda := []byte("v2 archive")
	body := fmt.Sprintf(`{
	  "info": {"subdir": "linux-64"},
	  "packages": {
	    "numpy-1.0-0.tar.bz2": {"sha256": %q, "md5": %q, "size": 10, "depends": ["python"]}
	  },
	  "packages.conda": {
	    "numpy-1.0-0.conda": {"sha256": %q, "md5": %q, "size": 9}
	  }
	}`, sha256Hex(tgz), md5Hex(tgz), sha256Hex(conda), md5Hex(conda))

	sha, m, found, err := repodataChecksum(strings.NewReader(body), "numpy-1.0-0.tar.bz2")
	if err != nil || !found {
		t.Fatalf("legacy lookup: found=%v err=%v", found, err)
	}
	if sha != sha256Hex(tgz) || m != md5Hex(tgz) {
		t.Errorf("legacy digests = %q / %q", sha, m)
	}

	sha, _, found, err = repodataChecksum(strings.NewReader(body), "numpy-1.0-0.conda")
	if err != nil || !found {
		t.Fatalf(".conda lookup: found=%v err=%v", found, err)
	}
	if sha != sha256Hex(conda) {
		t.Errorf(".conda sha = %q", sha)
	}

	if _, _, found, _ := repodataChecksum(strings.NewReader(body), "absent-1.0-0.conda"); found {
		t.Error("absent package must not resolve")
	}

	if _, _, _, err := repodataChecksum(strings.NewReader("not json"), "x.conda"); err == nil {
		t.Error("non-JSON body should error")
	}
}

func TestChooseChecksumPrefersSHA256(t *testing.T) {
	e, ok := chooseChecksum("f", sha256Hex([]byte("x")), md5Hex([]byte("x")))
	if !ok || e.algo != "sha256" {
		t.Errorf("should prefer sha256: %+v ok=%v", e, ok)
	}
	e, ok = chooseChecksum("f", "", md5Hex([]byte("x")))
	if !ok || e.algo != "md5" {
		t.Errorf("should fall back to md5: %+v ok=%v", e, ok)
	}
	if _, ok := chooseChecksum("f", "", ""); ok {
		t.Error("no digest should yield ok=false")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine conda package bytes")
	exp := expectedChecksum{filename: "p.conda", algo: "sha256", hex: sha256Hex(data)}
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
	exp := expectedChecksum{filename: "p.conda", algo: "sha256", hex: sha256Hex([]byte("the real bytes"))}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "http://x/p.conda", func(ok bool) {
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

// --- integration: fake channel + backend ------------------------------------

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
		Name:        "conda-forge",
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

// seedPackage registers a .conda package and the subdir repodata.json. When
// tamper is true, the index declares a sha256 that does not match the bytes.
func seedPackage(t *testing.T, fr *fakeRemote, tamper bool) (pkgBytes []byte, pkgPath string) {
	t.Helper()
	pkg := []byte("fake .conda archive payload")
	sha := sha256Hex(pkg)
	if tamper {
		sha = sha256Hex([]byte("a different artifact"))
	}
	dir := "/linux-64/"
	fname := "numpy-1.26.0-py312h0_0.conda"
	fr.files[dir+fname] = pkg
	fr.files[dir+"repodata.json"] = []byte(fmt.Sprintf(
		`{"packages.conda": {%q: {"sha256": %q, "md5": %q, "size": %d}}}`,
		fname, sha, md5Hex(pkg), len(pkg)))
	fr.hdrs[dir+fname] = http.Header{"X-Conda-Something": {"v"}}
	return pkg, dir + fname
}

func TestPackageVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	pkg, path := seedPackage(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch package: %v", err)
	}
	if !bytes.Equal(body, pkg) {
		t.Fatal("package body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("package should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "application/octet-stream" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Coordinate.Name != "numpy" || fres.Resolved.Coordinate.Version != "1.26.0" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if fres.Resolved.Metadata[MetaSubdir] != "linux-64" {
		t.Errorf("subdir metadata = %q", fres.Resolved.Metadata[MetaSubdir])
	}
	if st := m.Stats(); st.PackagesVerified != 1 || st.RepodataFetched != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestPackageChecksumMismatchRefused(t *testing.T) {
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

func TestRepodataMissingServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	dir := "/linux-64/"
	fname := "numpy-1.26.0-py312h0_0.conda"
	fr.files[dir+fname] = []byte("payload, but no repodata.json present")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, dir+fname)
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

func TestRepodataServedAsIndex(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/linux-64/repodata.json"] = []byte(`{"packages":{}}`)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/linux-64/repodata.json")
	if err != nil {
		t.Fatalf("fetch repodata: %v", err)
	}
	if !bytes.Contains(body, []byte("packages")) {
		t.Errorf("repodata body unexpected: %q", body)
	}
	if fres.Resolved.Cacheable {
		t.Error("repodata index must not be cacheable")
	}
	if fres.MediaType != "application/json" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if m.Stats().IndexServed != 1 {
		t.Errorf("index-served metric = %v", m.Stats().IndexServed)
	}
}

func TestResolveRejectsNonCondaPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/conda/path.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/linux-64/absent-1.0-0.conda")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestSiblingURL(t *testing.T) {
	got, ok := siblingURL("https://u/conda-forge/linux-64/numpy-1.0-0.conda", repodataFile)
	if !ok || got != "https://u/conda-forge/linux-64/repodata.json" {
		t.Errorf("siblingURL = %q ok=%v", got, ok)
	}
}
