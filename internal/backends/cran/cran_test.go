package cran

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

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/src/contrib/PACKAGES", kindIndex},
		{"/src/contrib/PACKAGES.gz", kindIndex},
		{"/bin/windows/contrib/4.3/PACKAGES", kindIndex},
		{"/src/contrib/jsonlite_1.8.8.tar.gz", kindPackage},
		{"/src/contrib/Archive/jsonlite/jsonlite_1.8.7.tar.gz", kindPackage},
		{"/bin/windows/contrib/4.3/jsonlite_1.8.8.zip", kindPackage},
		{"/bin/macosx/big-sur-arm64/contrib/4.3/jsonlite_1.8.8.tgz", kindPackage},
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
		"/src/contrib/README.html",             // unknown file
		"/src/contrib/noversion.tar.gz",        // no underscore -> no version
		"/src/contrib/_1.0.tar.gz",             // empty name
		"/src/contrib/pkg_.tar.gz",             // empty version
		"/src/contrib/../../etc/passwd.tar.gz", // traversal
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, ok := classify("/src/contrib/data.table_1.15.0.tar.gz")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "data.table" || res.version != "1.15.0" {
		t.Errorf("coordinate = %q/%q", res.name, res.version)
	}
	if !res.cacheable() || !res.verifiableFile() {
		t.Error("a pinned package should be cacheable and verifiable")
	}

	idx, _ := classify("/src/contrib/PACKAGES")
	if idx.cacheable() {
		t.Error("PACKAGES is mutable and must not be cacheable")
	}
	if idx.verifiableFile() {
		t.Error("PACKAGES is not a verifiable package")
	}
}

func TestParsePackageFilename(t *testing.T) {
	n, v, ok := parsePackageFilename("Rcpp_1.0.12.tar.gz")
	if !ok || n != "Rcpp" || v != "1.0.12" {
		t.Errorf("parse = %q/%q ok=%v", n, v, ok)
	}
	n, v, ok = parsePackageFilename("ggplot2_3.5.0.zip")
	if !ok || n != "ggplot2" || v != "3.5.0" {
		t.Errorf("zip parse = %q/%q ok=%v", n, v, ok)
	}
	if _, _, ok := parsePackageFilename("noext"); ok {
		t.Error("filename without extension should not parse")
	}
}

// --- PACKAGES parsing -------------------------------------------------------

func TestParsePackages(t *testing.T) {
	jsonSum := md5Hex([]byte("jsonlite tarball"))
	rcppSum := md5Hex([]byte("Rcpp tarball"))
	body := "Package: jsonlite\n" +
		"Version: 1.8.8\n" +
		"Depends: methods\n" +
		" R (>= 3.0.0)\n" + // continuation line, ignored
		"License: MIT + file LICENSE\n" +
		"MD5sum: " + jsonSum + "\n" +
		"NeedsCompilation: yes\n" +
		"\n" +
		"Package: Rcpp\n" +
		"Version: 1.0.12\n" +
		"MD5sum: " + rcppSum + "\n" +
		"\n" +
		"Package: broken\n" + // missing Version and MD5sum -> skipped
		"Title: nothing\n"
	idx, err := ParsePackages([]byte(body))
	if err != nil {
		t.Fatalf("ParsePackages: %v", err)
	}
	if got, _ := idx.md5For("jsonlite_1.8.8"); got != jsonSum {
		t.Errorf("jsonlite md5 = %q, want %q", got, jsonSum)
	}
	if got, _ := idx.md5For("Rcpp_1.0.12"); got != rcppSum {
		t.Errorf("Rcpp md5 = %q", got)
	}
	if _, ok := idx.md5For("broken_1.0"); ok {
		t.Error("incomplete stanza should be skipped")
	}
	if _, ok := idx.md5For("absent_1.0"); ok {
		t.Error("absent package must not resolve")
	}
}

func TestParsePackagesRejectsShortDigest(t *testing.T) {
	idx, err := ParsePackages([]byte("Package: p\nVersion: 1.0\nMD5sum: deadbeef\n"))
	if err != nil {
		t.Fatalf("ParsePackages: %v", err)
	}
	if _, ok := idx.md5For("p_1.0"); ok {
		t.Error("malformed short digest should be skipped")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine cran tarball bytes")
	exp := expectedChecksum{filename: "p_1.0.tar.gz", md5hex: md5Hex(data)}
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
	exp := expectedChecksum{filename: "p_1.0.tar.gz", md5hex: md5Hex([]byte("the real bytes"))}
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
		Name:        "cran",
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

// seedPackage registers a source tarball and the sibling PACKAGES index. When
// tamper is true, the index declares an MD5 that does not match the bytes.
func seedPackage(t *testing.T, fr *fakeRemote, tamper bool) (tarball []byte, path string) {
	t.Helper()
	tgz := []byte("\x1f\x8b fake jsonlite source tarball")
	sum := md5Hex(tgz)
	if tamper {
		sum = md5Hex([]byte("a different artifact"))
	}
	dir := "/src/contrib/"
	fname := "jsonlite_1.8.8.tar.gz"
	fr.files[dir+fname] = tgz
	fr.files[dir+"PACKAGES"] = []byte(
		"Package: jsonlite\nVersion: 1.8.8\nMD5sum: " + sum + "\n\n")
	fr.hdrs[dir+fname] = http.Header{"X-Cran-Something": {"v"}}
	return tgz, dir + fname
}

func TestPackageVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	tgz, path := seedPackage(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch package: %v", err)
	}
	if !bytes.Equal(body, tgz) {
		t.Fatal("tarball body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("package should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "md5" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "application/gzip" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Coordinate.Name != "jsonlite" || fres.Resolved.Coordinate.Version != "1.8.8" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.PackagesVerified != 1 || st.PackagesFetched != 1 {
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

func TestPackagesMissingServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	// Archived package with no sibling PACKAGES index.
	path := "/src/contrib/Archive/jsonlite/jsonlite_1.8.7.tar.gz"
	fr.files[path] = []byte("archived tarball, no PACKAGES here")
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
	fr.files["/src/contrib/PACKAGES"] = []byte("Package: jsonlite\nVersion: 1.8.8\n\n")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/src/contrib/PACKAGES")
	if err != nil {
		t.Fatalf("fetch PACKAGES: %v", err)
	}
	if !bytes.Contains(body, []byte("jsonlite")) {
		t.Errorf("PACKAGES body unexpected: %q", body)
	}
	if fres.Resolved.Cacheable {
		t.Error("PACKAGES index must not be cacheable")
	}
	if fres.MediaType != "text/plain; charset=utf-8" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if m.Stats().IndexServed != 1 {
		t.Errorf("index-served metric = %v", m.Stats().IndexServed)
	}
}

func TestResolveRejectsNonCranPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/cran/file.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/src/contrib/absent_1.0.tar.gz")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestSiblingURL(t *testing.T) {
	got, ok := siblingURL("https://u/src/contrib/jsonlite_1.8.8.tar.gz", packagesFile)
	if !ok || got != "https://u/src/contrib/PACKAGES" {
		t.Errorf("siblingURL = %q ok=%v", got, ok)
	}
}
