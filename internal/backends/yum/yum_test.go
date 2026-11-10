package yum

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

const (
	goodRPM   = "Packages/hello-1.0-1.x86_64.rpm"
	poisonRPM = "Packages/evil-9.9-1.x86_64.rpm"
	ghostRPM  = "Packages/ghost-1.0-1.x86_64.rpm"
)

type fakeRepo struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	fr := &fakeRepo{files: map[string][]byte{}}

	goodBytes := []byte("the genuine hello rpm payload")
	poisonBytes := []byte("POISONED rpm payload not matching its digest")
	ghostBytes := []byte("an rpm primary.xml never listed")
	fr.files["/"+goodRPM] = goodBytes
	fr.files["/"+poisonRPM] = poisonBytes
	fr.files["/"+ghostRPM] = ghostBytes

	primary := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
  <package type="rpm">
    <name>hello</name>
    <version epoch="0" ver="1.0" rel="1"/>
    <checksum type="sha256" pkgid="YES">%s</checksum>
    <location href="%s"/>
  </package>
  <package type="rpm">
    <name>evil</name>
    <version epoch="0" ver="9.9" rel="1"/>
    <checksum type="sha256" pkgid="YES">%s</checksum>
    <location href="%s"/>
  </package>
</metadata>
`, sha256Hex(goodBytes), goodRPM, sha256Hex([]byte("the ORIGINAL evil payload")), poisonRPM)

	primaryGz := gzipBytes([]byte(primary))
	const primaryLoc = "repodata/1234-primary.xml.gz"
	fr.files["/"+primaryLoc] = primaryGz

	repomd := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1700000000</revision>
  <data type="primary">
    <checksum type="sha256">%s</checksum>
    <location href="%s"/>
    <size>%d</size>
  </data>
</repomd>
`, sha256Hex(primaryGz), primaryLoc, len(primaryGz))
	fr.files["/repodata/repomd.xml"] = []byte(repomd)

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
	opts.Name = "fedora"
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
	res := resolve(t, b, "/"+goodRPM)
	if res.Coordinate.Name != "hello" || res.Coordinate.Version != "1.0" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error(".rpm should be cacheable")
	}
	rm := resolve(t, b, "/repodata/repomd.xml")
	if rm.Cacheable {
		t.Error("repomd.xml must not be cacheable")
	}
	if rm.Metadata[metaKind] != "repomd" {
		t.Errorf("kind = %q", rm.Metadata[metaKind])
	}
}

// TestVerifyChain exercises repomd -> primary -> .rpm: fetching the primary.xml
// populates the digest store, and the .rpm then verifies.
func TestVerifyChain(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})

	idxRes := resolve(t, b, "/repodata/1234-primary.xml.gz")
	if _, _, err := fetchAll(t, b, idxRes); err != nil {
		t.Fatalf("fetch primary: %v", err)
	}
	if b.digests.len() == 0 {
		t.Fatal("digest store not populated from primary.xml")
	}
	if m.Stats().RepodataVerified != 1 {
		t.Errorf("RepodataVerified = %v, want 1", m.Stats().RepodataVerified)
	}
	if m.Stats().PrimaryParsed != 1 {
		t.Errorf("PrimaryParsed = %v, want 1", m.Stats().PrimaryParsed)
	}

	debRes := resolve(t, b, "/"+goodRPM)
	fr, body, err := fetchAll(t, b, debRes)
	if err != nil {
		t.Fatalf("fetch good .rpm: %v", err)
	}
	if string(body) != "the genuine hello rpm payload" {
		t.Errorf("unexpected body %q", body)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksumVerified = %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().RPMsVerified != 1 {
		t.Errorf("RPMsVerified = %v, want 1", m.Stats().RPMsVerified)
	}
}

// TestRPMColdCacheOnDemand verifies that an .rpm fetched before its primary.xml
// was proxied still verifies, via the on-demand repomd->primary population.
func TestRPMColdCacheOnDemand(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})

	res := resolve(t, b, "/"+goodRPM)
	fr, _, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch .rpm cold: %v", err)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("cold-cache .rpm not verified: %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().RPMsVerified != 1 {
		t.Errorf("RPMsVerified = %v, want 1", m.Stats().RPMsVerified)
	}
}

func TestPoisonedRPMRejected(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})

	idxRes := resolve(t, b, "/repodata/1234-primary.xml.gz")
	if _, _, err := fetchAll(t, b, idxRes); err != nil {
		t.Fatalf("fetch primary: %v", err)
	}
	res := resolve(t, b, "/"+poisonRPM)
	if _, _, err := fetchAll(t, b, res); err == nil {
		t.Fatal("expected checksum mismatch for poisoned .rpm")
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
}

func TestUnlistedRPMFailOpen(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})
	res := resolve(t, b, "/"+ghostRPM)
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch unlisted .rpm: %v", err)
	}
	if string(body) != "an rpm primary.xml never listed" {
		t.Errorf("unexpected body %q", body)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksumVerified = %q, want none", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("ChecksumMissing = %v, want 1", m.Stats().ChecksumMissing)
	}
}

func TestRepomdServedWithoutKeyring(t *testing.T) {
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})
	res := resolve(t, b, "/repodata/repomd.xml")
	fr, _, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch repomd.xml: %v", err)
	}
	if fr.Resolved.Metadata[MetaSignatureVerified] != "unsigned" {
		t.Errorf("signatureVerified = %q, want unsigned", fr.Resolved.Metadata[MetaSignatureVerified])
	}
	if m.Stats().SignatureSkipped != 1 {
		t.Errorf("SignatureSkipped = %v, want 1", m.Stats().SignatureSkipped)
	}
	if m.Stats().RepomdParsed != 1 {
		t.Errorf("RepomdParsed = %v, want 1", m.Stats().RepomdParsed)
	}
}
