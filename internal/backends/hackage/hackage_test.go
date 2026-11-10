package hackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/01-index.tar.gz", kindIndex},
		{"/01-index.tar", kindIndex},
		{"/root.json", kindTUFMetadata},
		{"/snapshot.json", kindTUFMetadata},
		{"/package/text-2.1/text-2.1.tar.gz", kindSdist},
		{"/package/aeson-pretty-0.8.10/aeson-pretty-0.8.10.tar.gz", kindSdist},
		{"/package/text-2.1.tar.gz", kindSdist},
		{"/package/text-2.1/text.cabal", kindCabal},
		{"/package/text-2.1/package.json", kindTargetMetadata},
		{"/package/text-2.1", kindPackagePage},
		{"/package/text", kindPackagePage},
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
		"/02-index.tar.gz",                    // unknown top-level file
		"/notpackage/text-2.1",                // unknown root
		"/package/text-2.1/../../etc/passwd",  // traversal
		"/package/text-2.1/wrongname.cabal",   // cabal name must match package
		"/package/text-2.1/extra/deep.tar.gz", // too many segments
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestParsePkgID(t *testing.T) {
	cases := []struct {
		id      string
		name    string
		version string
		ok      bool
	}{
		{"text-2.1", "text", "2.1", true},
		{"aeson-pretty-0.8.10", "aeson-pretty", "0.8.10", true},
		{"HUnit-1.6.2.0", "HUnit", "1.6.2.0", true},
		{"text", "", "", false},    // no version
		{"text-", "", "", false},   // empty version
		{"-2.1", "", "", false},    // empty name
		{"foo-bar", "", "", false}, // version component has a letter
	}
	for _, c := range cases {
		n, v, ok := parsePkgID(c.id)
		if ok != c.ok || n != c.name || v != c.version {
			t.Errorf("parsePkgID(%q) = %q/%q ok=%v, want %q/%q ok=%v", c.id, n, v, ok, c.name, c.version, c.ok)
		}
	}
}

// --- TUF target metadata parsing --------------------------------------------

func TestParseTargetSHA256(t *testing.T) {
	data := []byte("the real sdist bytes")
	sum := sha256.Sum256(data)
	body := targetJSON(t, "text-2.1.tar.gz", sum[:])
	got, ok := parseTargetSHA256(body, "text-2.1.tar.gz")
	if !ok {
		t.Fatal("expected a target match")
	}
	if got != fmt.Sprintf("%x", sum) {
		t.Errorf("sha256 = %q", got)
	}
	if _, ok := parseTargetSHA256(body, "absent-1.0.tar.gz"); ok {
		t.Error("absent target must not match")
	}
	if _, ok := parseTargetSHA256([]byte("not json"), "text-2.1.tar.gz"); ok {
		t.Error("garbage body must not match")
	}
}

// targetJSON builds a minimal hackage-security package.json TUF Targets body
// whose single target names the given tarball filename with the given sha256.
func targetJSON(t *testing.T, filename string, sha []byte) []byte {
	t.Helper()
	doc := map[string]any{
		"signed": map[string]any{
			"_type": "Targets",
			"targets": map[string]any{
				"<repo>/package/" + filename: map[string]any{
					"hashes": map[string]any{
						"md5":    "ignored",
						"sha256": fmt.Sprintf("%x", sha),
					},
					"length": len(sha),
				},
			},
			"version": 0,
		},
		"signatures": []any{},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal target json: %v", err)
	}
	return b
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderMismatch(t *testing.T) {
	served := []byte("POISONED")
	real := sha256.Sum256([]byte("the real bytes"))
	exp := expectedChecksum{filename: "p-1.0.tar.gz", hex: fmt.Sprintf("%x", real)}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "http://x", func(ok bool) { result = ok })
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
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}}
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

func newTestBackend(t *testing.T, fr *fakeRemote, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "hackage",
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

// seedSdist registers an sdist tarball and the sibling package.json TUF target
// metadata. When tamper is true, the metadata declares a sha256 that does not
// match the bytes.
func seedSdist(t *testing.T, fr *fakeRemote, tamper bool) (tarball []byte, path string) {
	t.Helper()
	tar := []byte("text-2.1 sdist tarball bytes")
	declared := tar
	if tamper {
		declared = []byte("a completely different artifact")
	}
	sum := sha256.Sum256(declared)
	fr.files["/package/text-2.1/text-2.1.tar.gz"] = tar
	fr.files["/package/text-2.1/package.json"] = targetJSON(t, "text-2.1.tar.gz", sum[:])
	return tar, "/package/text-2.1/text-2.1.tar.gz"
}

func TestSdistVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	tar, path := seedSdist(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch sdist: %v", err)
	}
	if !bytes.Equal(body, tar) {
		t.Fatal("sdist body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("sdist should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "application/gzip" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Coordinate.Name != "text" || fres.Resolved.Coordinate.Version != "2.1" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.SdistsVerified != 1 || st.TargetsFetched != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestSdistChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedSdist(t, fr, true)
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

func TestSdistMissingTargetServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	// Tarball present but no sibling package.json.
	path := "/package/orphan-0.1/orphan-0.1.tar.gz"
	fr.files[path] = []byte("orphan sdist, no target metadata")
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
	body := []byte("fake 01-index tarball bytes")
	fr.files["/01-index.tar.gz"] = body
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, got, err := resolveFetch(t, b, "/01-index.tar.gz")
	if err != nil {
		t.Fatalf("fetch index: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("index must be served byte-exact")
	}
	if fres.Resolved.Cacheable {
		t.Error("index must not be cacheable")
	}
	if m.Stats().IndexServed != 1 {
		t.Errorf("index-served metric = %v", m.Stats().IndexServed)
	}
}

func TestResolveRejectsNonHackagePath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/hackage/file.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/package/absent-1.0/absent-1.0.tar.gz")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}
