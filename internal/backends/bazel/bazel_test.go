package bazel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
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

// sri256 renders the SRI integrity string for the SHA-256 of b.
func sri256(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func sri512(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/bazel_registry.json", kindRegistry},
		{"/modules/platforms/metadata.json", kindMetadata},
		{"/modules/platforms/0.0.10/MODULE.bazel", kindModuleBazel},
		{"/modules/rules_cc/0.0.9/source.json", kindSource},
		{"/modules/rules_cc/0.0.9/archive", kindArchive},
		{"/modules/abseil-cpp/20230802.0/patches/fix.patch", kindPatch},
		{"/modules/zlib/1.3.1.bcr.1/patches/module_dot_bazel.diff", kindPatch},
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
		"/registry.json",                              // wrong root file
		"/modules",                                    // no module
		"/modules/platforms",                          // module without a leaf
		"/modules/Platforms/metadata.json",            // uppercase module name
		"/modules/plat forms/metadata.json",           // space in name
		"/modules/platforms/0.0.10/BUILD",             // unknown per-version file
		"/modules/platforms/0.0.10/source.txt",        // unknown descriptor
		"/modules/platforms/0.0.10/patches/x.txt",     // non-patch extension
		"/modules/platforms/0.0.10/patches/a/b.patch", // nested patch path
		"/modules/platforms/../../etc/passwd",         // traversal
		"/modules/platforms/0.0.10/../source.json",    // traversal mid-path
		"/modules/foo/bad version/MODULE.bazel",       // space in version
	} {
		if r, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok: %+v", bad, r)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, ok := classify("/modules/rules_cc/0.0.9/archive")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "rules_cc" || res.version != "0.0.9" {
		t.Errorf("coordinate = %q@%q", res.name, res.version)
	}
	if !res.cacheable() || !res.verifiableArchive() {
		t.Error("archive should be cacheable and verifiable")
	}

	src, _ := classify("/modules/rules_cc/0.0.9/source.json")
	if src.cacheable() {
		t.Error("source.json is rewritten/live and must not be cacheable")
	}
	if src.verifiableArchive() {
		t.Error("source.json is not the verifiable archive")
	}

	mb, _ := classify("/modules/rules_cc/0.0.9/MODULE.bazel")
	if !mb.cacheable() {
		t.Error("MODULE.bazel is immutable and should be cacheable")
	}

	meta, _ := classify("/modules/rules_cc/metadata.json")
	if meta.cacheable() {
		t.Error("metadata.json is mutable and must not be cacheable")
	}
	if meta.version != "" {
		t.Errorf("metadata.json should have no version, got %q", meta.version)
	}
}

// --- integrity parsing ------------------------------------------------------

func TestParseIntegrity(t *testing.T) {
	payload := []byte("the archive bytes")

	e, ok := parseIntegrity(sri256(payload))
	if !ok || e.algo != "sha256" {
		t.Fatalf("sha256 parse: %+v ok=%v", e, ok)
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(e.raw, sum[:]) {
		t.Error("decoded sha256 digest mismatch")
	}

	// The strongest candidate wins when several are listed.
	multi := sri256(payload) + " " + sri512(payload)
	e, ok = parseIntegrity(multi)
	if !ok || e.algo != "sha512" {
		t.Errorf("strongest candidate should win: %+v ok=%v", e, ok)
	}

	for _, bad := range []string{
		"",
		"sha256-not-base64!!!",
		"md5-" + base64.StdEncoding.EncodeToString([]byte("x")),        // unknown algo
		"sha256-" + base64.StdEncoding.EncodeToString([]byte("short")), // wrong length
		"garbage",
		"sha256",
	} {
		if _, ok := parseIntegrity(bad); ok {
			t.Errorf("parseIntegrity(%q) unexpectedly ok", bad)
		}
	}
}

// --- source.json parse + rewrite --------------------------------------------

func TestParseSource(t *testing.T) {
	body := `{"url":"https://example.com/a.tar.gz","integrity":"sha256-abc","strip_prefix":"a-1.0","patch_strip":1}`
	info, err := parseSource([]byte(body))
	if err != nil {
		t.Fatalf("parseSource: %v", err)
	}
	if info.URL != "https://example.com/a.tar.gz" || info.Integrity != "sha256-abc" {
		t.Errorf("parsed = %+v", info)
	}
	u, ok := info.primaryURL()
	if !ok || u != "https://example.com/a.tar.gz" {
		t.Errorf("primaryURL = %q ok=%v", u, ok)
	}

	// urls[] fallback, preferring the first http(s) entry.
	multi := `{"urls":["ftp://skip/me","https://mirror/a.tar.gz"],"integrity":"sha256-x"}`
	info, _ = parseSource([]byte(multi))
	if u, ok := info.primaryURL(); !ok || u != "https://mirror/a.tar.gz" {
		t.Errorf("urls fallback = %q ok=%v", u, ok)
	}

	// No http(s) URL.
	info, _ = parseSource([]byte(`{"integrity":"sha256-x"}`))
	if _, ok := info.primaryURL(); ok {
		t.Error("descriptor with no http url should yield ok=false")
	}

	if _, err := parseSource([]byte("not json")); err == nil {
		t.Error("non-JSON source.json should error")
	}
}

func TestRewriteSourceJSON(t *testing.T) {
	body := `{"url":"https://github.com/o/r/archive/v1.tar.gz","integrity":"sha256-ABC=","strip_prefix":"r-1","patches":{"p.patch":"sha256-DEF="},"patch_strip":1}`
	out, err := rewriteSourceJSON([]byte(body), "https://proxy/v1/bazel/modules/r/1/archive")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("rewritten not JSON: %v", err)
	}
	if m["url"] != "https://proxy/v1/bazel/modules/r/1/archive" {
		t.Errorf("url not rewritten: %v", m["url"])
	}
	// Integrity and other fields must survive byte-for-byte in meaning.
	if m["integrity"] != "sha256-ABC=" {
		t.Errorf("integrity altered: %v", m["integrity"])
	}
	if m["strip_prefix"] != "r-1" {
		t.Errorf("strip_prefix altered: %v", m["strip_prefix"])
	}
	if _, ok := m["patches"]; !ok {
		t.Error("patches dropped")
	}

	// urls[] is collapsed to the single synthetic url.
	out, err = rewriteSourceJSON([]byte(`{"urls":["https://a/x.tgz","https://b/x.tgz"],"integrity":"sha256-ABC="}`), "https://proxy/archive")
	if err != nil {
		t.Fatalf("rewrite urls: %v", err)
	}
	_ = json.Unmarshal(out, &m)
	if m["url"] != "https://proxy/archive" {
		t.Errorf("url not set from urls: %v", m["url"])
	}
	if _, ok := m["urls"]; ok {
		t.Error("urls should be removed")
	}

	// A descriptor with no archive URL is not rewritten (error → caller passes through).
	if _, err := rewriteSourceJSON([]byte(`{"integrity":"sha256-ABC="}`), "https://proxy/archive"); err == nil {
		t.Error("descriptor with no url should not rewrite")
	}
	if _, err := rewriteSourceJSON([]byte("not json"), "https://proxy/archive"); err == nil {
		t.Error("non-object source.json should error")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("genuine bazel module archive bytes")
	exp, _ := parseIntegrity(sri256(data))
	var called, result bool
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(data)), exp, "m", "1", "http://x", func(ok bool) {
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
	exp, _ := parseIntegrity(sri256([]byte("the real bytes")))
	served := []byte("POISONED PAYLOAD")
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "m", "1", "http://x/archive", func(ok bool) {
		result = ok
	})
	_, err := io.ReadAll(vr)
	var mm *IntegrityMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected IntegrityMismatchError, got %v", err)
	}
	if result {
		t.Error("onResult should report failure")
	}
}

// --- integration: fake registry + backend -----------------------------------

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

func newTestBackend(t *testing.T, fr *fakeRemote, m *Metrics, publicBase string) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "bazel",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: publicBase,
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

// seedModule registers a module version's source.json and the external archive
// it references (hosted on the same fake server for the test). When tamper is
// true, source.json declares an integrity that does not match the archive bytes.
func seedModule(t *testing.T, fr *fakeRemote, tamper bool) (archive []byte) {
	t.Helper()
	archive = []byte("fake bazel module source archive tarball")
	integrity := sri256(archive)
	if tamper {
		integrity = sri256([]byte("a completely different artifact"))
	}
	fr.files["/archive-store/platforms-0.0.10.tar.gz"] = archive
	src := fmt.Sprintf(`{"url":%q,"integrity":%q,"strip_prefix":"platforms-0.0.10"}`,
		fr.srv.URL+"/archive-store/platforms-0.0.10.tar.gz", integrity)
	fr.files["/modules/platforms/0.0.10/source.json"] = []byte(src)
	fr.files["/modules/platforms/0.0.10/MODULE.bazel"] = []byte(`module(name = "platforms", version = "0.0.10")`)
	fr.files["/modules/platforms/metadata.json"] = []byte(`{"versions":["0.0.10"]}`)
	fr.files["/bazel_registry.json"] = []byte(`{"mirrors":[]}`)
	return archive
}

func TestArchiveVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	archive := seedModule(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "")

	fres, body, err := resolveFetch(t, b, "/modules/platforms/0.0.10/archive")
	if err != nil {
		t.Fatalf("fetch archive: %v", err)
	}
	if !bytes.Equal(body, archive) {
		t.Fatal("archive body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("archive should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Resolved.Coordinate.Name != "platforms" || fres.Resolved.Coordinate.Version != "0.0.10" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if !strings.Contains(fres.Resolved.Metadata[MetaArchiveURL], "platforms-0.0.10.tar.gz") {
		t.Errorf("archive URL metadata = %q", fres.Resolved.Metadata[MetaArchiveURL])
	}
	if fres.MediaType != "application/octet-stream" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if st := m.Stats(); st.ArchivesVerified != 1 || st.SourceFetched != 1 || st.ArchivesServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestArchiveTamperedRefused(t *testing.T) {
	fr := newFakeRemote(t)
	seedModule(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "")

	_, _, err := resolveFetch(t, b, "/modules/platforms/0.0.10/archive")
	if err == nil {
		t.Fatal("expected integrity mismatch error")
	}
	var mm *IntegrityMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("error = %v, want IntegrityMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestArchiveNoIntegrityServedUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	archive := []byte("archive with no declared integrity")
	fr.files["/archive-store/x.tar.gz"] = archive
	fr.files["/modules/foo/1.0/source.json"] = []byte(fmt.Sprintf(`{"url":%q}`, fr.srv.URL+"/archive-store/x.tar.gz"))
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "")

	fres, body, err := resolveFetch(t, b, "/modules/foo/1.0/archive")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(body, archive) {
		t.Fatal("archive body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("checksum-missing metric = %v", m.Stats().ChecksumMissing)
	}
}

func TestArchiveSourceMissing(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{}, "")
	_, _, err := resolveFetch(t, b, "/modules/absent/9.9/archive")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestSourceJSONRewrittenWithPublicBase(t *testing.T) {
	fr := newFakeRemote(t)
	seedModule(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "https://proxy.example.com/v1/bazel")

	fres, body, err := resolveFetch(t, b, "/modules/platforms/0.0.10/source.json")
	if err != nil {
		t.Fatalf("fetch source.json: %v", err)
	}
	if fres.Resolved.Cacheable {
		t.Error("rewritten source.json must not be cacheable")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("source.json not JSON: %v", err)
	}
	wantURL := "https://proxy.example.com/v1/bazel/modules/platforms/0.0.10/archive"
	if doc["url"] != wantURL {
		t.Errorf("url = %v, want %q", doc["url"], wantURL)
	}
	// The integrity (what Bazel re-verifies) must be preserved.
	if _, ok := doc["integrity"]; !ok {
		t.Error("integrity dropped from rewritten source.json")
	}
	if fres.MediaType != "application/json" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if m.Stats().SourceRewritten != 1 {
		t.Errorf("source-rewritten metric = %v", m.Stats().SourceRewritten)
	}
}

func TestSourceJSONPassthroughWithoutPublicBase(t *testing.T) {
	fr := newFakeRemote(t)
	seedModule(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{}, "")

	fres, body, err := resolveFetch(t, b, "/modules/platforms/0.0.10/source.json")
	if err != nil {
		t.Fatalf("fetch source.json: %v", err)
	}
	if fres.Resolved.Metadata[metaRewrite] == "1" {
		t.Error("rewrite should be disabled without a public base")
	}
	if !bytes.Contains(body, []byte("/archive-store/platforms-0.0.10.tar.gz")) {
		t.Errorf("source.json should be passed through unchanged, got %q", body)
	}
}

func TestModuleBazelCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	seedModule(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "")

	fres, body, err := resolveFetch(t, b, "/modules/platforms/0.0.10/MODULE.bazel")
	if err != nil {
		t.Fatalf("fetch MODULE.bazel: %v", err)
	}
	if !bytes.Contains(body, []byte(`module(name = "platforms"`)) {
		t.Errorf("MODULE.bazel body unexpected: %q", body)
	}
	if !fres.Resolved.Cacheable {
		t.Error("MODULE.bazel should be cacheable")
	}
	if fres.Resolved.Coordinate.Name != "platforms" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if m.Stats().IndexServed < 1 {
		t.Errorf("index-served metric = %v", m.Stats().IndexServed)
	}
}

func TestMetadataAndRegistryLive(t *testing.T) {
	fr := newFakeRemote(t)
	seedModule(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{}, "")

	for _, path := range []string{"/modules/platforms/metadata.json", "/bazel_registry.json"} {
		fres, body, err := resolveFetch(t, b, path)
		if err != nil {
			t.Fatalf("fetch %q: %v", path, err)
		}
		if len(body) == 0 {
			t.Fatalf("%q empty body", path)
		}
		if fres.Resolved.Cacheable {
			t.Errorf("%q must not be cacheable", path)
		}
		if fres.MediaType != "application/json" {
			t.Errorf("%q media type = %q", path, fres.MediaType)
		}
	}
}

func TestResolveRejectsNonBazelPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{}, "")
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/bazel/path.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestSourceURLAndArchiveURL(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{}, "https://proxy/v1/bazel")
	if got := b.sourceURL("rules_cc", "0.0.9"); !strings.HasSuffix(got, "/modules/rules_cc/0.0.9/source.json") {
		t.Errorf("sourceURL = %q", got)
	}
	if got := b.publicArchiveURL("rules_cc", "0.0.9"); got != "https://proxy/v1/bazel/modules/rules_cc/0.0.9/archive" {
		t.Errorf("publicArchiveURL = %q", got)
	}
	// Fallback to root-relative without a public base.
	b2 := newTestBackend(t, fr, &Metrics{}, "")
	if got := b2.publicArchiveURL("rules_cc", "0.0.9"); got != "/v1/bazel/modules/rules_cc/0.0.9/archive" {
		t.Errorf("fallback publicArchiveURL = %q", got)
	}
}
