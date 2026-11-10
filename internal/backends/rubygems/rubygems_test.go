package rubygems

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// fakeServer is an in-memory gem server serving .gem files, compact-index
// documents, and a per-gem /info document carrying the SHA-256 of each .gem.
type fakeServer struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{files: map[string][]byte{}}

	// A good gem whose /info checksum matches its bytes.
	gem := []byte("GEM\x00 fake rails gem payload")
	fs.files["/gems/rails-7.0.4.gem"] = gem
	fs.files["/info/rails"] = []byte("---\n7.0.4 |checksum:" + sha256Hex(gem) + ",ruby:>= 2.7.0\n")

	// A poisoned gem: the /info checksum names a different digest than the bytes.
	poison := []byte("POISONED GEM PAYLOAD")
	fs.files["/gems/evilgem-1.0.0.gem"] = poison
	fs.files["/info/evilgem"] = []byte("---\n1.0.0 |checksum:" + sha256Hex([]byte("the real untampered gem")) + "\n")

	// A gem whose /info lists no checksum for the requested version (fail-open).
	nosum := []byte("gem without a published checksum")
	fs.files["/gems/nosum-2.0.0.gem"] = nosum
	fs.files["/info/nosum"] = []byte("---\n1.0.0 |checksum:" + zeroSHA256 + "\n") // only 1.0.0 listed

	fs.files["/versions"] = []byte("created_at: 2024-01-01\n---\nrails 7.0.4 abc123\n")
	fs.files["/names"] = []byte("---\nrails\nnosum\n")
	fs.files["/specs.4.8.gz"] = []byte("\x1f\x8b fake gzipped marshal index")

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
	return fs
}

func testBackend(t *testing.T, fs *fakeServer, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "rubygems",
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

func TestResolveAttachesCoordinate(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	res := resolve(t, b, "/gems/rails-7.0.4.gem")
	if res.Coordinate.Name != "rails" || res.Coordinate.Version != "7.0.4" {
		t.Errorf("coordinate = %+v", res.Coordinate)
	}
	if !res.Cacheable {
		t.Error("gem should be cacheable")
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error("gem should be flagged for verification")
	}
}

func TestResolveIndexNotCacheable(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	for _, p := range []string{"/versions", "/names", "/info/rails", "/specs.4.8.gz"} {
		res := resolve(t, b, p)
		if res.Cacheable {
			t.Errorf("%q must not be cacheable", p)
		}
	}
}

func TestResolveRejectsNonGemPath(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/gem/path", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
}

func TestFetchGemVerifiesChecksum(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/gems/rails-7.0.4.gem")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch+read: %v", err)
	}
	if string(body) != string(fs.files["/gems/rails-7.0.4.gem"]) {
		t.Error("served gem bytes differ from upstream")
	}
	if m.Stats().GemsVerified != 1 {
		t.Errorf("GemsVerified = %v, want 1", m.Stats().GemsVerified)
	}
	if fr.Header.Get("X-Checksum-Verified") != "sha256" {
		t.Errorf("X-Checksum-Verified = %q", fr.Header.Get("X-Checksum-Verified"))
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
}

func TestFetchPoisonedGemFailsClosed(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/gems/evilgem-1.0.0.gem")
	_, _, err := fetchAll(t, b, res)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
}

func TestFetchGemWithoutChecksum(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/gems/nosum-2.0.0.gem")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(fs.files["/gems/nosum-2.0.0.gem"]) {
		t.Error("served bytes differ")
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("ChecksumMissing = %v, want 1", m.Stats().ChecksumMissing)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fr.Resolved.Metadata[MetaChecksumVerified])
	}
}

func TestFetchIndexServedLive(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/info/rails")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch info: %v", err)
	}
	if string(body) != string(fs.files["/info/rails"]) {
		t.Error("served info bytes differ")
	}
	if m.Stats().IndexServed != 1 {
		t.Errorf("IndexServed = %v, want 1", m.Stats().IndexServed)
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
