package dart

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

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// --- backend-detection / path-classification unit tests ---------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/api/packages/path", kindVersions},
		{"/api/packages/path/advisories", kindAdvisories},
		{"/api/archives/path-1.2.3.tar.gz", kindArchive},
		{"/api/archives/my_pkg-2.0.0-beta.1.tar.gz", kindArchive},
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
		"/api/packages",                 // missing package
		"/api/packages/Bad-Name",        // uppercase + hyphen invalid
		"/api/packages/9lives",          // may not start with digit
		"/api/packages/path/versions/1", // deprecated endpoint not proxied
		"/api/archives/path.tar.gz",     // no version delimiter
		"/api/archives/path-.tar.gz",    // empty version
		"/api/archives/-1.0.0.tar.gz",   // empty name
		"/api/archives/path-1.0.0.zip",  // wrong extension
		"/api/packages/a/../../etc",     // traversal
		"/other/thing",                  // unknown namespace
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyArchiveSplit(t *testing.T) {
	res, ok := classify("/api/archives/my_pkg-2.0.0-beta.1.tar.gz")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "my_pkg" || res.version != "2.0.0-beta.1" {
		t.Errorf("name/version = %q/%q, want my_pkg/2.0.0-beta.1", res.name, res.version)
	}
	if res.coordinateName() != "my_pkg" || !res.isArchive() || !res.cacheable() {
		t.Errorf("predicates wrong for %+v", res)
	}
}

// --- metadata parsing / rewriting -------------------------------------------

func versionsDoc(t *testing.T, pkg, archiveBase string, sums map[string][]byte) []byte {
	t.Helper()
	type ver struct {
		Version       string         `json:"version"`
		ArchiveURL    string         `json:"archive_url"`
		ArchiveSha256 string         `json:"archive_sha256"`
		Pubspec       map[string]any `json:"pubspec"`
	}
	var vers []ver
	var latest ver
	for v, b := range sums {
		e := ver{
			Version:       v,
			ArchiveURL:    archiveBase + "/" + pkg + "-" + v + ".tar.gz",
			ArchiveSha256: sha256Hex(b),
			Pubspec:       map[string]any{"name": pkg, "version": v, "repository": "https://github.com/x/" + pkg},
		}
		vers = append(vers, e)
		latest = e
	}
	doc := map[string]any{
		"name":           pkg,
		"isDiscontinued": false,
		"latest":         latest,
		"versions":       vers,
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestRewriteArchiveURLs(t *testing.T) {
	body := versionsDoc(t, "path", "https://pub.dev/api/archives", map[string][]byte{"1.2.3": []byte("a")})
	out, err := rewriteArchiveURLs(body, func(version string) string {
		return "https://proxy.example/v1/pub/api/archives/path-" + version + ".tar.gz"
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Top-level unknown field preserved.
	if _, ok := doc["isDiscontinued"]; !ok {
		t.Error("unknown top-level field dropped")
	}
	versions := doc["versions"].([]any)
	v0 := versions[0].(map[string]any)
	if v0["archive_url"] != "https://proxy.example/v1/pub/api/archives/path-1.2.3.tar.gz" {
		t.Errorf("archive_url not rewritten: %v", v0["archive_url"])
	}
	// Pubspec preserved.
	if _, ok := v0["pubspec"]; !ok {
		t.Error("pubspec dropped")
	}
	latest := doc["latest"].(map[string]any)
	if latest["archive_url"] != "https://proxy.example/v1/pub/api/archives/path-1.2.3.tar.gz" {
		t.Errorf("latest archive_url not rewritten: %v", latest["archive_url"])
	}
}

func TestParseVersionListLookup(t *testing.T) {
	body := versionsDoc(t, "path", "https://pub.dev/api/archives", map[string][]byte{"1.2.3": []byte("a")})
	vl, err := parseVersionList(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e, ok := vl.archiveFor("1.2.3")
	if !ok {
		t.Fatal("version not found")
	}
	if e.repository() != "https://github.com/x/path" {
		t.Errorf("repository = %q", e.repository())
	}
	if _, ok := vl.archiveFor("9.9.9"); ok {
		t.Error("absent version must not resolve")
	}
}

// --- integration: fake repository + backend ---------------------------------

type fakeRepo struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeRepo(t *testing.T) *fakeRepo {
	t.Helper()
	fr := &fakeRepo{files: map[string][]byte{}}
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

func newTestBackend(t *testing.T, fr *fakeRepo, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "pub",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: "https://proxy.example/v1/pub",
		Client:        upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:       m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
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

// seed registers a package's list-versions document (whose archive_url points at
// the upstream's own /api/archives path) and the archive bytes. When tamper is
// true, the declared archive_sha256 does not match the served bytes.
func seed(t *testing.T, fr *fakeRepo, tamper bool) []byte {
	t.Helper()
	tgz := []byte("\x1f\x8b fake dart package archive")
	sum := sha256Hex(tgz)
	if tamper {
		sum = sha256Hex([]byte("a different artifact"))
	}
	doc := map[string]any{
		"name": "path",
		"latest": map[string]any{
			"version":        "1.2.3",
			"archive_url":    fr.srv.URL + "/api/archives/path-1.2.3.tar.gz",
			"archive_sha256": sum,
			"pubspec":        map[string]any{"name": "path", "version": "1.2.3", "repository": "https://github.com/dart-lang/path"},
		},
		"versions": []map[string]any{
			{
				"version":        "1.2.3",
				"archive_url":    fr.srv.URL + "/api/archives/path-1.2.3.tar.gz",
				"archive_sha256": sum,
				"pubspec":        map[string]any{"name": "path", "version": "1.2.3", "repository": "https://github.com/dart-lang/path"},
			},
		},
	}
	body, _ := json.Marshal(doc)
	fr.files["/api/packages/path"] = body
	fr.files["/api/archives/path-1.2.3.tar.gz"] = tgz
	return tgz
}

func TestArchiveVerifiesAndSurfacesRepository(t *testing.T) {
	fr := newFakeRepo(t)
	tgz := seed(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/api/archives/path-1.2.3.tar.gz")
	if err != nil {
		t.Fatalf("fetch archive: %v", err)
	}
	if !bytes.Equal(body, tgz) {
		t.Fatal("archive body mismatch")
	}
	if fres.MediaType != "application/gzip" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Resolved.Metadata[MetaRepository] != "https://github.com/dart-lang/path" {
		t.Errorf("repository metadata = %q", fres.Resolved.Metadata[MetaRepository])
	}
	if fres.Resolved.Coordinate.Name != "path" || fres.Resolved.Coordinate.Version != "1.2.3" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if s := m.Stats(); s.ArchivesVerified != 1 {
		t.Errorf("metrics = %+v", s)
	}
}

func TestArchiveChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRepo(t)
	seed(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, "/api/archives/path-1.2.3.tar.gz")
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestArchiveVersionNotFound(t *testing.T) {
	fr := newFakeRepo(t)
	seed(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{})

	_, _, err := resolveFetch(t, b, "/api/archives/path-9.9.9.tar.gz")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestVersionsDocumentRewritten(t *testing.T) {
	fr := newFakeRepo(t)
	seed(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/api/packages/path")
	if err != nil {
		t.Fatalf("fetch versions: %v", err)
	}
	if fres.Resolved.Cacheable {
		// list-versions is mutable → must NOT be cacheable
		t.Error("list-versions must not be cacheable")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal served doc: %v", err)
	}
	latest := doc["latest"].(map[string]any)
	want := "https://proxy.example/v1/pub/api/archives/path-1.2.3.tar.gz"
	if latest["archive_url"] != want {
		t.Errorf("served archive_url = %v, want %v", latest["archive_url"], want)
	}
	if m.Stats().VersionsRewritten != 1 || m.Stats().VersionsServed != 1 {
		t.Errorf("metrics = %+v", m.Stats())
	}
}

func TestVersionsNotCacheable(t *testing.T) {
	fr := newFakeRepo(t)
	seed(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{})
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/api/packages/path", Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Cacheable {
		t.Error("list-versions document must not be cacheable")
	}
}

func TestResolveRejectsNonPubPath(t *testing.T) {
	b := newTestBackend(t, newFakeRepo(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/pub", Query: url.Values{}, Header: http.Header{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestResolveArchiveURL(t *testing.T) {
	// Relative archive_url resolves against the list-versions URL.
	got, err := resolveArchiveURL("https://pub.dev/api/packages/path", "../archives/path-1.0.0.tar.gz")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "https://pub.dev/api/archives/path-1.0.0.tar.gz" {
		t.Errorf("resolved = %q", got)
	}
	// A non-http scheme is rejected.
	if _, err := resolveArchiveURL("https://pub.dev/api/packages/path", "file:///etc/passwd"); err == nil {
		t.Error("expected rejection of file:// archive URL")
	}
}
