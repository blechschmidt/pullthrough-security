package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
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

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// fakeRepo is an in-memory APT repository serving a Release/InRelease index, a
// gzipped Packages index, and pool .deb artifacts.
type fakeRepo struct {
	srv   *httptest.Server
	files map[string][]byte
}

const (
	goodDebPath  = "pool/main/h/hello/hello_1.0_amd64.deb"
	poisonPath   = "pool/main/e/evil/evil_9.9_amd64.deb"
	unlistedPath = "pool/main/g/ghost/ghost_1.0_amd64.deb"
)

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	fr := &fakeRepo{files: map[string][]byte{}}

	goodDeb := []byte("the genuine hello package payload")
	poisonDeb := []byte("POISONED payload that no longer matches its digest")
	ghostDeb := []byte("a package the index never listed")

	fr.files["/"+goodDebPath] = goodDeb
	// The poisoned .deb: the Packages index will declare a digest for a DIFFERENT
	// content, so verification must fail at stream end.
	fr.files["/"+poisonPath] = poisonDeb
	fr.files["/"+unlistedPath] = ghostDeb

	packages := fmt.Sprintf(`Package: hello
Version: 1.0
Architecture: amd64
Filename: %s
Size: %d
SHA256: %s

Package: evil
Version: 9.9
Architecture: amd64
Filename: %s
Size: 1
SHA256: %s
`, goodDebPath, len(goodDeb), sha256Hex(goodDeb),
		poisonPath, sha256Hex([]byte("the ORIGINAL evil payload")))

	packagesGz := gzipBytes([]byte(packages))
	fr.files["/dists/bookworm/main/binary-amd64/Packages.gz"] = packagesGz
	fr.files["/dists/bookworm/main/binary-amd64/Packages"] = []byte(packages)

	release := fmt.Sprintf(`Origin: Test
Suite: bookworm
Codename: bookworm
SHA256:
 %s %d main/binary-amd64/Packages.gz
 %s %d main/binary-amd64/Packages
`, sha256Hex(packagesGz), len(packagesGz), sha256Hex([]byte(packages)), len(packages))
	fr.files["/dists/bookworm/Release"] = []byte(release)
	fr.files["/dists/bookworm/InRelease"] = []byte(release)

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

func testBackend(t *testing.T, fr *fakeRepo, opts Options) *Backend {
	t.Helper()
	opts.Name = "debian"
	opts.UpstreamURL = fr.srv.URL
	opts.Client = upstream.NewWithHTTPClient(fr.srv.Client(), "test/1")
	b, err := New(opts)
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

func TestResolveClassifies(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), Options{})
	res := resolve(t, b, "/"+goodDebPath)
	if res.Coordinate.Name != "hello" || res.Coordinate.Version != "1.0" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error(".deb should be cacheable")
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error(".deb should be flagged for verification")
	}

	rel := resolve(t, b, "/dists/bookworm/InRelease")
	if rel.Cacheable {
		t.Error("InRelease must not be cacheable")
	}
	if rel.Metadata[metaKind] != "inrelease" {
		t.Errorf("kind = %q", rel.Metadata[metaKind])
	}
}

// TestVerifyChain exercises the full Release -> Packages -> .deb verification: a
// client fetches the index (populating the digest store) then the package, which
// must verify against the index-declared SHA-256.
func TestVerifyChain(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})

	// Fetch the Packages index first (as an APT client does).
	idxRes := resolve(t, b, "/dists/bookworm/main/binary-amd64/Packages.gz")
	if _, _, err := fetchAll(t, b, idxRes); err != nil {
		t.Fatalf("fetch Packages: %v", err)
	}
	if b.digests.len() == 0 {
		t.Fatal("digest store not populated from Packages index")
	}
	if m.Stats().IndexVerified != 1 {
		t.Errorf("IndexVerified = %v, want 1", m.Stats().IndexVerified)
	}
	if m.Stats().PackagesParsed != 1 {
		t.Errorf("PackagesParsed = %v, want 1", m.Stats().PackagesParsed)
	}

	// Now the genuine .deb must verify.
	debRes := resolve(t, b, "/"+goodDebPath)
	fr, body, err := fetchAll(t, b, debRes)
	if err != nil {
		t.Fatalf("fetch good .deb: %v", err)
	}
	if string(body) != "the genuine hello package payload" {
		t.Errorf("unexpected body %q", body)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksumVerified = %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().DebsVerified != 1 {
		t.Errorf("DebsVerified = %v, want 1", m.Stats().DebsVerified)
	}
}

// TestPoisonedDebRejected verifies that a .deb whose content does not match the
// index-declared digest fails at stream end, so the cache write aborts.
func TestPoisonedDebRejected(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})

	idxRes := resolve(t, b, "/dists/bookworm/main/binary-amd64/Packages.gz")
	if _, _, err := fetchAll(t, b, idxRes); err != nil {
		t.Fatalf("fetch Packages: %v", err)
	}

	debRes := resolve(t, b, "/"+poisonPath)
	_, _, err := fetchAll(t, b, debRes)
	if err == nil {
		t.Fatal("expected checksum mismatch for poisoned .deb")
	}
	var mm *ChecksumMismatchError
	if !asMismatch(err, &mm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
}

// TestUnlistedDebFailOpen verifies that a package with no recorded digest is
// served unverified and counted, rather than blocked.
func TestUnlistedDebFailOpen(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})

	res := resolve(t, b, "/"+unlistedPath)
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch unlisted .deb: %v", err)
	}
	if string(body) != "a package the index never listed" {
		t.Errorf("unexpected body %q", body)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksumVerified = %q, want none", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("ChecksumMissing = %v, want 1", m.Stats().ChecksumMissing)
	}
}

func TestReleaseServedWithoutKeyring(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})
	res := resolve(t, b, "/dists/bookworm/InRelease")
	fr, _, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch InRelease: %v", err)
	}
	if fr.Resolved.Metadata[MetaSignatureVerified] != "unsigned" {
		t.Errorf("signatureVerified = %q, want unsigned", fr.Resolved.Metadata[MetaSignatureVerified])
	}
	if m.Stats().SignatureSkipped != 1 {
		t.Errorf("SignatureSkipped = %v, want 1", m.Stats().SignatureSkipped)
	}
}

func asMismatch(err error, target **ChecksumMismatchError) bool {
	for err != nil {
		if mm, ok := err.(*ChecksumMismatchError); ok {
			*target = mm
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
