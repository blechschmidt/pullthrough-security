package composer

import (
	"context"
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

// fakeServer is an in-memory Composer repository serving packages.json, v2
// metadata, and the raw dist archives the metadata points at.
type fakeServer struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{files: map[string][]byte{}}

	// The handler reads fs.files at request time, so the server can be started
	// before the fixtures (which embed the server's own URL) are populated.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := fs.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	fs.srv = httptest.NewServer(mux)
	t.Cleanup(fs.srv.Close)
	base := fs.srv.URL

	// A good dist whose metadata shasum matches its bytes.
	goodZip := []byte("PK\x03\x04 fake console dist zip")
	fs.files["/raw/console-3.2.0.zip"] = goodZip

	// A poisoned dist: metadata names a shasum that the served bytes do not match.
	poisonZip := []byte("POISONED DIST PAYLOAD")
	fs.files["/raw/evil-1.0.0.zip"] = poisonZip

	// A dist whose metadata carries no usable shasum (fail-open).
	nosumZip := []byte("dist without a shasum")
	fs.files["/raw/nosum-1.0.0.zip"] = nosumZip

	fs.files["/p2/symfony/console.json"] = []byte(fmt.Sprintf(`{
      "minified": "composer/2.0",
      "packages": {
        "symfony/console": [
          {"name":"symfony/console","version":"3.2.0","license":["MIT"],"dist":{"type":"zip","url":"%s/raw/console-3.2.0.zip","reference":"good","shasum":"%s"}}
        ]
      }
    }`, base, sha1Hex(goodZip)))

	fs.files["/p2/evil/pkg.json"] = []byte(fmt.Sprintf(`{
      "packages": {"evil/pkg": [
        {"name":"evil/pkg","version":"1.0.0","dist":{"type":"zip","url":"%s/raw/evil-1.0.0.zip","reference":"bad","shasum":"%s"}}
      ]}
    }`, base, sha1Hex([]byte("the real untampered dist"))))

	fs.files["/p2/no/sum.json"] = []byte(fmt.Sprintf(`{
      "packages": {"no/sum": [
        {"name":"no/sum","version":"1.0.0","dist":{"type":"zip","url":"%s/raw/nosum-1.0.0.zip","reference":"nochk","shasum":""}}
      ]}
    }`, base))

	fs.files["/packages.json"] = []byte(`{"metadata-url":"/p2/%package%.json"}`)

	return fs
}

func testBackend(t *testing.T, fs *fakeServer, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "packagist",
		UpstreamURL: fs.srv.URL,
		Client:      upstream.NewWithHTTPClient(fs.srv.Client(), "test/1"),
		Metrics:     m,
	})
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

func TestResolveDistCoordinate(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	res := resolve(t, b, "/dist/symfony/console/good.zip")
	if res.Coordinate.Name != "symfony/console" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error("dist should be cacheable")
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error("dist should be flagged for verification")
	}
}

func TestResolveMetadataNotCacheable(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	for _, p := range []string{"/packages.json", "/p2/symfony/console.json"} {
		res := resolve(t, b, p)
		if res.Cacheable {
			t.Errorf("%q must not be cacheable", p)
		}
	}
}

func TestResolveRejectsBadPath(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/nope", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
}

func TestFetchDistVerifiesShasum(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/dist/symfony/console/good.zip")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch+read: %v", err)
	}
	if string(body) != string(fs.files["/raw/console-3.2.0.zip"]) {
		t.Error("served dist bytes differ from upstream")
	}
	if m.Stats().DistVerified != 1 {
		t.Errorf("DistVerified = %v, want 1", m.Stats().DistVerified)
	}
	if fr.Header.Get("X-Checksum-Verified") != "sha1" {
		t.Errorf("X-Checksum-Verified = %q", fr.Header.Get("X-Checksum-Verified"))
	}
	if fr.Resolved.Coordinate.Version != "3.2.0" {
		t.Errorf("version enriched = %q", fr.Resolved.Coordinate.Version)
	}
	if fr.Resolved.Metadata[MetaLicenses] != "MIT" {
		t.Errorf("licenses = %q", fr.Resolved.Metadata[MetaLicenses])
	}
}

func TestFetchPoisonedDistFailsClosed(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/dist/evil/pkg/bad.zip")
	_, _, err := fetchAll(t, b, res)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
}

func TestFetchDistWithoutShasum(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/dist/no/sum/nochk.zip")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(fs.files["/raw/nosum-1.0.0.zip"]) {
		t.Error("served bytes differ")
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("ChecksumMissing = %v, want 1", m.Stats().ChecksumMissing)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
}

func TestFetchUnknownReference404(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, &Metrics{})

	res := resolve(t, b, "/dist/symfony/console/doesnotexist.zip")
	_, _, err := fetchAll(t, b, res)
	var se *backends.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Fatalf("expected 404 StatusError, got %v", err)
	}
}

func TestFetchMetadataParsedAndServed(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/p2/symfony/console.json")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	if string(body) != string(fs.files["/p2/symfony/console.json"]) {
		t.Error("served metadata bytes differ")
	}
	if m.Stats().MetadataParsed != 1 {
		t.Errorf("MetadataParsed = %v, want 1", m.Stats().MetadataParsed)
	}
	if m.Stats().MetadataServed != 1 {
		t.Errorf("MetadataServed = %v, want 1", m.Stats().MetadataServed)
	}
}

func TestNewValidation(t *testing.T) {
	cli := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	cases := []Options{
		{Name: "", UpstreamURL: "https://x", Client: cli},
		{Name: "x", UpstreamURL: "", Client: cli},
		{Name: "x", UpstreamURL: "ftp://x", Client: cli},
		{Name: "x", UpstreamURL: "https://x", Client: nil},
	}
	for i, o := range cases {
		if _, err := New(o); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
