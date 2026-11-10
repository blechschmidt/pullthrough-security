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
	"reflect"
	"slices"
	"strings"
	"sync"
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
		// The archive endpoint followed by the upstream archive's file name — the
		// form a rewritten source.json points at, in every format Bazel unpacks.
		{"/modules/platforms/0.0.10/archive/platforms-0.0.10.tar.gz", kindArchive},
		{"/modules/abc/0.0.0-20250408-yosyshq/archive/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip", kindArchive},
		{"/modules/binutils/2.47/archive/binutils-2.47.tar.xz", kindArchive},
		{"/modules/eigen/3.4.1/archive/download.tar.gz", kindArchive},
		{"/modules/foo/1.0/archive/v1.0+build.5_x.tgz", kindArchive},
		// Overlay files, at the root of the source tree and nested.
		{"/modules/abc/0.0.0-20250408-yosyshq/overlay/BUILD.bazel", kindOverlay},
		{"/modules/abc/0.0.0-20250408-yosyshq/overlay/MODULE.bazel", kindOverlay},
		{"/modules/foo/1.0/overlay/src/lib/internal/BUILD.bazel", kindOverlay},
		{"/modules/foo/1.0/overlay/packages/@scope/pkg/defs.bzl", kindOverlay},
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

	// The client-supplied tails of the archive and overlay routes are validated
	// segment by segment: nothing that could redirect the upstream request.
	for _, bad := range []string{
		"/modules/foo/1.0/archive/a/b.tar.gz",       // the archive file name is a single segment
		"/modules/foo/1.0/archive/..",               // traversal after the endpoint
		"/modules/foo/1.0/archive/../source.json",   // traversal through the endpoint
		"/modules/foo/1.0/archive/a b.tar.gz",       // space in the file name
		"/modules/foo/1.0/archive/a%2Fb.tar.gz",     // escapes are not file-name characters
		"/modules/foo/1.0/archive/a?b.tar.gz",       // nor is a query delimiter
		"/modules/foo/1.0/archive/a\\b.tar.gz",      // nor a backslash
		"/modules/foo/1.0/archives/x.tar.gz",        // not the endpoint
		"/modules/foo/1.0/overlay",                  // overlay directory, no file
		"/modules/foo/1.0/overlay/../source.json",   // traversal out of the overlay
		"/modules/foo/1.0/overlay/src/../../x",      // traversal mid-path
		"/modules/foo/1.0/overlay/./BUILD.bazel",    // dot segment
		"/modules/foo/1.0/overlay//BUILD.bazel",     // empty segment
		"/modules/foo/1.0/overlay/a b/BUILD.bazel",  // space in a segment
		"/modules/foo/1.0/overlay/a\\b/BUILD.bazel", // backslash in a segment
		"/modules/foo/1.0/overlay/a%2e%2e/BUILD",    // escapes are not path characters
		"/modules/foo/1.0/overlay/a?b",              // query delimiter
		"/modules/foo/1.0/overlays/BUILD.bazel",     // not the overlay directory
		"/modules/foo/1.0/archive/" + strings.Repeat("a", maxArchiveFileName+1),
		"/modules/foo/1.0/overlay/" + strings.Repeat("s", maxOverlaySegment+1),
		"/modules/foo/1.0/overlay/" + strings.Repeat("d/", maxOverlayDepth) + "BUILD.bazel",
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

	// The named form of the endpoint is the same resource: same coordinate, same
	// verification, with the file name carried only as a label.
	named, ok := classify("/modules/rules_cc/0.0.9/archive/rules_cc-0.0.9.tar.gz")
	if !ok {
		t.Fatal("classify of the named archive endpoint failed")
	}
	if named.kind != kindArchive || named.name != "rules_cc" || named.version != "0.0.9" {
		t.Errorf("named archive = %+v", named)
	}
	if !named.cacheable() || !named.verifiableArchive() {
		t.Error("named archive should be cacheable and verifiable")
	}
	if named.filename != "rules_cc-0.0.9.tar.gz" {
		t.Errorf("named archive filename = %q", named.filename)
	}

	ov, ok := classify("/modules/rules_cc/0.0.9/overlay/src/BUILD.bazel")
	if !ok {
		t.Fatal("classify of an overlay file failed")
	}
	if ov.name != "rules_cc" || ov.version != "0.0.9" || ov.filename != "src/BUILD.bazel" {
		t.Errorf("overlay = %+v", ov)
	}
	if !ov.cacheable() {
		t.Error("an overlay file is immutable and should be cacheable")
	}
	if ov.verifiableArchive() {
		t.Error("an overlay file is not the verifiable archive")
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
	for _, notObject := range []string{`null`, `[]`, `"url"`, `42`} {
		if _, err := parseSource([]byte(notObject)); err == nil {
			t.Errorf("parseSource(%s) should error: not a JSON object", notObject)
		}
	}

	// The fields Bazel added later: mirror_urls (backups, tried after url),
	// archive_type, and type.
	full := `{"type":"archive","url":"https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.xz",
		"mirror_urls":["https://mirrors.kernel.org/gnu/binutils/binutils-2.47.tar.xz","https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.xz"],
		"archive_type":"tar.xz","integrity":"sha256-x"}`
	info, err = parseSource([]byte(full))
	if err != nil {
		t.Fatalf("parseSource(full): %v", err)
	}
	if info.Type != "archive" || info.ArchiveType != "tar.xz" || len(info.MirrorURLs) != 2 || !info.isArchive() {
		t.Errorf("parsed = %+v", info)
	}
	// Candidates keep Bazel's order (url first, then the mirrors) without repeats.
	want := []string{
		"https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.xz",
		"https://mirrors.kernel.org/gnu/binutils/binutils-2.47.tar.xz",
	}
	if got := info.archiveURLs(); !slices.Equal(got, want) {
		t.Errorf("archiveURLs = %q, want %q", got, want)
	}

	// A git_repository descriptor has no archive, whatever else it carries.
	info, _ = parseSource([]byte(`{"type":"git_repository","remote":"https://github.com/o/r.git","commit":"abc","url":"https://evil/x.tgz"}`))
	if info.isArchive() || len(info.archiveURLs()) != 0 {
		t.Errorf("git_repository must yield no archive candidates: %+v -> %q", info, info.archiveURLs())
	}
	// Nor does a descriptor whose type is not even a string.
	info, _ = parseSource([]byte(`{"type":7,"url":"https://h/x.tgz"}`))
	if info.isArchive() {
		t.Errorf("a non-string type must not default to archive: %+v", info)
	}

	// Fields of the wrong JSON type are ignored instead of failing the descriptor,
	// and keys match exactly (Bazel does not read "URL").
	info, err = parseSource([]byte(`{"url":123,"URL":"https://wrong/x.tgz","mirror_urls":["https://m/x.tgz",5,null],"integrity":["x"]}`))
	if err != nil {
		t.Fatalf("parseSource(lenient): %v", err)
	}
	if info.URL != "" || info.Integrity != "" {
		t.Errorf("mistyped fields should be absent: %+v", info)
	}
	if got := info.archiveURLs(); !slices.Equal(got, []string{"https://m/x.tgz"}) {
		t.Errorf("archiveURLs = %q", got)
	}

	// The scheme is matched case-insensitively (as Bazel does); non-web locators
	// never qualify.
	info, _ = parseSource([]byte(`{"url":"HTTPS://Example.com/a.zip","mirror_urls":["file:///etc/passwd","ftp://h/a.zip","//h/a.zip","https:///a.zip"]}`))
	if got := info.archiveURLs(); !slices.Equal(got, []string{"HTTPS://Example.com/a.zip"}) {
		t.Errorf("archiveURLs = %q", got)
	}

	// A descriptor cannot fan one request out to an unbounded number of mirrors.
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, fmt.Sprintf("https://m%d.example/x.tgz", i))
	}
	raw, _ := json.Marshal(map[string]any{"url": "https://primary.example/x.tgz", "mirror_urls": many})
	info, _ = parseSource(raw)
	if got := info.archiveURLs(); len(got) != maxArchiveCandidates || got[0] != "https://primary.example/x.tgz" {
		t.Errorf("archiveURLs: %d candidates (first %q), want %d with the primary first", len(got), got[0], maxArchiveCandidates)
	}
}

// TestArchiveFileName pins how the synthetic archive URL's file name is derived:
// Bazel names the downloaded file after the URL's last path segment and picks
// the decompressor from that name's suffix, so the suffix must survive intact.
func TestArchiveFileName(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		archiveType string
		want        string
	}{
		// Every format in BCR, with the upstream base name kept verbatim.
		{"tar.gz release asset", "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz", "", "platforms-0.0.10.tar.gz"},
		{"tag archive", "https://github.com/Thalhammer/jwt-cpp/archive/refs/tags/v0.7.0.tar.gz", "", "v0.7.0.tar.gz"},
		{"zip of a commit", "https://github.com/YosysHQ/abc/archive/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip", "", "e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip"},
		{"tar.xz", "https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.xz", "", "binutils-2.47.tar.xz"},
		{"tgz", "https://registry.npmjs.org/typescript/-/typescript-5.4.5.tgz", "", "typescript-5.4.5.tgz"},
		{"tar.bz2", "https://downloads.sourceforge.net/project/boost/boost_1_84_0.tar.bz2", "", "boost_1_84_0.tar.bz2"},
		{"tar.zst", "https://example.com/dist/pkg-1.0.tar.zst", "", "pkg-1.0.tar.zst"},
		{"plain tar", "https://example.com/dist/pkg-1.0.tar", "", "pkg-1.0.tar"},

		// No telling suffix in the URL: the declared archive_type is appended the
		// way Bazel appends it (eigen in BCR).
		{"extension-less url with archive_type", "https://gitlab.com/libeigen/eigen/-/package_files/233618439/download", "tar.gz", "download.tar.gz"},
		{"archive_type already present", "https://example.com/pkg-1.0.tar.gz", "tar.gz", "pkg-1.0.tar.gz"},
		{"archive_type disagrees with the name", "https://example.com/pkg-1.0.zip", "tar.gz", "pkg-1.0.zip.tar.gz"},
		{"archive_type spelled with a leading dot", "https://example.com/download", ".tar.zst", "download.tar.zst"},
		{"implausible archive_type is ignored", "https://example.com/pkg.tgz", "../../etc", "pkg.tgz"},
		{"no path at all, but a type", "https://example.com", "zip", "archive.zip"},

		// The query string and fragment are not part of the name (Bazel uses the
		// URL path only).
		{"query string", "https://example.com/dl/pkg-1.0.tar.gz?token=abc&x=y.zip", "", "pkg-1.0.tar.gz"},
		{"fragment", "https://example.com/dl/pkg-1.0.tar.gz#sha256=ff", "", "pkg-1.0.tar.gz"},
		{"trailing slash", "https://example.com/dl/pkg-1.0.tar.gz/", "", "pkg-1.0.tar.gz"},

		// Bytes outside [A-Za-z0-9._+-] are replaced, never passed through; the
		// suffix is unaffected.
		{"escaped space and parens", "https://example.com/My%20Pkg%20(1).tar.gz", "", "My_Pkg__1_.tar.gz"},
		{"escaped slash stays a separator", "https://example.com/a%2Fb.tar.gz", "", "b.tar.gz"},
		{"non-ascii", "https://example.com/pakét.zip", "", "pak__t.zip"},
		{"plus and tilde", "https://example.com/libfoo-1.0+dfsg~rc1.tar.xz", "", "libfoo-1.0+dfsg_rc1.tar.xz"},

		// Nothing usable: the bare endpoint is used instead.
		{"no path", "https://example.com", "", ""},
		{"root path", "https://example.com/", "", ""},
		{"dot-dot base name", "https://example.com/a/..", "", ""},
		{"unparseable url", "https://exa mple.com/%zz", "", ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		got := archiveFileName(c.url, c.archiveType)
		if got != c.want {
			t.Errorf("%s: archiveFileName(%q, %q) = %q, want %q", c.name, c.url, c.archiveType, got, c.want)
		}
		if got != "" && !isArchiveFileName(got) {
			t.Errorf("%s: derived name %q is not accepted by the classifier", c.name, got)
		}
	}

	// An overlong base name keeps its tail, where the suffix lives.
	long := archiveFileName("https://example.com/"+strings.Repeat("a", 400)+".tar.gz", "")
	if len(long) != maxArchiveFileName || !strings.HasSuffix(long, ".tar.gz") {
		t.Errorf("overlong name: len=%d suffix ok=%v", len(long), strings.HasSuffix(long, ".tar.gz"))
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
	// The synthetic URL ends in the upstream archive's file name: Bazel infers the
	// archive format from that suffix and cannot extract ".../archive".
	if m["url"] != "https://proxy/v1/bazel/modules/r/1/archive/v1.tar.gz" {
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
	m = nil
	_ = json.Unmarshal(out, &m)
	if m["url"] != "https://proxy/archive/x.tgz" {
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

	// A URL the proxy cannot fetch is still rewritten, so the archive endpoint
	// fails closed instead of the client fetching around the proxy.
	out, err = rewriteSourceJSON([]byte(`{"url":"ftp://ftp.example.org/pub/x-1.0.tar.gz","integrity":"sha256-ABC="}`), "https://proxy/archive")
	if err != nil {
		t.Fatalf("rewrite non-http url: %v", err)
	}
	m = nil
	_ = json.Unmarshal(out, &m)
	if m["url"] != "https://proxy/archive/x-1.0.tar.gz" {
		t.Errorf("non-http url not rewritten: %v", m["url"])
	}

	// No usable file name: the bare endpoint is the rewrite target.
	out, err = rewriteSourceJSON([]byte(`{"url":"https://example.com/","integrity":"sha256-ABC="}`), "https://proxy/archive")
	if err != nil {
		t.Fatalf("rewrite nameless url: %v", err)
	}
	m = nil
	_ = json.Unmarshal(out, &m)
	if m["url"] != "https://proxy/archive" {
		t.Errorf("nameless url = %v, want the bare endpoint", m["url"])
	}
}

// Real source.json descriptors from the Bazel Central Registry, one per shape
// the registry uses. Long "patches" / "overlay" maps are abridged; everything
// else is verbatim.
const (
	// The plain shape: a release tarball and its integrity.
	bcrPlatforms = `{
    "url": "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
    "integrity": "sha256-IY7+juc20mo1cmY7N0olPAErcW2K8MB+hC6C8jigp+4="
}`
	// A .zip of a commit plus overlay files (31% of BCR versions use "overlay").
	bcrABC = `{
    "url": "https://github.com/YosysHQ/abc/archive/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip",
    "strip_prefix": "abc-e55d316cc9a7f72a84a76eda555aa6ec083c9d0d",
    "integrity": "sha256-ZWxkLDxo/U1Me0DZ7P4YUTOYQ+bnNaKGd4PZuhGhDCM=",
    "overlay": {
        "BUILD.bazel": "sha256-HQ584so/5x2/zGoDKTItk2CmQZ3FN8KRbT2r9B/26QU=",
        "MODULE.bazel": "sha256-XBSS0qrjEKL0x3maScu3HSwZi7nV6URJz7HBz24vJaM="
    }
}`
	// Patches, including the "../.." keys a few modules use to share patch files.
	bcrJwtCpp = `{
    "url": "https://github.com/Thalhammer/jwt-cpp/archive/refs/tags/v0.7.0.tar.gz",
    "integrity": "sha256-uesnDjuoIh5LK8OHI8mhy0+mwkGkKQi5ozTa/zETdAY=",
    "strip_prefix": "jwt-cpp-0.7.0",
    "patch_strip": 1,
    "patches": {
        "../../0.7.0/patches/add-build.patch": "sha256-893niHcbMlUl7JFb82Wr3tmirBTWi5pSUQQR64pnTIo=",
        "add-module_dot_bazel.patch": "sha256-tOqAVlsM3aO+huevBLLylAPna16s5wvZ1IB/I/uE5pE="
    }
}`
	// mirror_urls: backups Bazel tries after "url" (bison 3.8.2.bcr.10).
	bcrBison = `{
    "url": "https://mirror.bazel.build/ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz",
    "mirror_urls": [
        "https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz",
        "https://mirrors.kernel.org/gnu/bison/bison-3.8.2.tar.xz"
    ],
    "integrity": "sha256-m7oCFMz38QecXVkhAEUie89hlRmEDr+oDNOEnP9aW/I=",
    "strip_prefix": "bison-3.8.2",
    "overlay": {
        "BUILD.bazel": "sha256-muiH08QkXREL5LRQd7UAnMsf9ntFcpt8x4qPlj6MeNo=",
        "examples/BUILD.bazel": "sha256-cmljboFmjiBFTcB64zXGwT/mtyX/4hWlCZxN+mcwDCI="
    },
    "patch_strip": 1,
    "patches": {
        "bison_runfiles.patch": "sha256-AMd+T8MoIyUq9bNl+iOi1HmzG+syDPVwNEXj89+qIWI="
    }
}`
	// A URL with no telling suffix, typed by archive_type (eigen 3.4.1).
	bcrEigen = `{
    "url": "https://gitlab.com/libeigen/eigen/-/package_files/233618439/download",
    "mirror_urls": [
        "https://github.com/eigen-mirror/eigen/archive/refs/tags/3.4.1.tar.gz",
        "https://gitlab.com/libeigen/eigen/-/archive/3.4.1/eigen-3.4.1.tar.gz"
    ],
    "archive_type": "tar.gz",
    "integrity": "sha256-uTxmfRtpJlzbTZ8w7CH4+su+izB880wLmUKDTG1P2+I=",
    "strip_prefix": "eigen-3.4.1",
    "overlay": {
        "BUILD.bazel": "sha256-FLG3o0e8uef58dPphOjnCjAfXYUMBvJQYbr1tfkNYO0=",
        "MODULE.bazel": "sha256-iW8NAkNgkQ2JOrEyKaKDGrWxL0GNaKGae3csbXcI+KQ="
    }
}`
	// docs_url: registry-UI metadata Bazel never fetches (aspect_rules_js 3.1.1).
	bcrRulesJS = `{
    "integrity": "sha256-uItzpXwFOasMFWnWlVIWmU7hdAiSHYmmTHyoMj6vs8g=",
    "strip_prefix": "rules_js-3.1.1",
    "docs_url": "https://github.com/aspect-build/rules_js/releases/download/v3.1.1/rules_js-v3.1.1.docs.tar.gz",
    "url": "https://github.com/aspect-build/rules_js/releases/download/v3.1.1/rules_js-v3.1.1.tar.gz",
    "patches": {
        "module_dot_bazel_version.patch": "sha256-f66j9HVu+oeg7eAHDik5MuS+8+U5cU3sCmc2BveNIws="
    },
    "patch_strip": 1
}`
	// Not an archive at all: Bazel clones the remote itself.
	bcrPicoSDK = `{
    "type": "git_repository",
    "remote": "https://github.com/raspberrypi/pico-sdk.git",
    "commit": "4b6e647590213f253f2789ad9026df1d00f38c5d",
    "patch_strip": 1,
    "patches": {
        "0001-Patch-version-string.patch": "sha256-F9pUZ3+9yNBDmWdIC+Dg3L19J+3FL0/xpxF88lSPBVQ="
    }
}`
)

// TestRewriteRealRegistryShapes runs each real BCR descriptor shape through the
// rewrite and checks what a Bazel client would then see: one archive URL — the
// proxy's, ending in a file name Bazel can infer the format from — and every
// other field exactly as published.
func TestRewriteRealRegistryShapes(t *testing.T) {
	const endpoint = "https://proxy.example.com/v1/bazel/modules/m/1.0/archive"
	cases := []struct {
		name    string
		body    string
		wantURL string
	}{
		{"platforms (tar.gz)", bcrPlatforms, endpoint + "/platforms-0.0.10.tar.gz"},
		{"abc (zip + overlay)", bcrABC, endpoint + "/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip"},
		{"jwt-cpp (patches)", bcrJwtCpp, endpoint + "/v0.7.0.tar.gz"},
		{"bison (mirror_urls, tar.xz)", bcrBison, endpoint + "/bison-3.8.2.tar.xz"},
		{"eigen (archive_type, extension-less url)", bcrEigen, endpoint + "/download.tar.gz"},
		{"rules_js (docs_url)", bcrRulesJS, endpoint + "/rules_js-v3.1.1.tar.gz"},
	}
	for _, c := range cases {
		out, err := rewriteSourceJSON([]byte(c.body), endpoint)
		if err != nil {
			t.Errorf("%s: rewrite: %v", c.name, err)
			continue
		}
		var before, after map[string]any
		if err := json.Unmarshal([]byte(c.body), &before); err != nil {
			t.Fatalf("%s: fixture is not JSON: %v", c.name, err)
		}
		if err := json.Unmarshal(out, &after); err != nil {
			t.Errorf("%s: rewritten descriptor is not JSON: %v", c.name, err)
			continue
		}
		if after["url"] != c.wantURL {
			t.Errorf("%s: url = %v, want %q", c.name, after["url"], c.wantURL)
		}
		// No other location may survive: Bazel would fall back to it whenever the
		// proxy refused or failed the archive, fetching around the proxy.
		for _, k := range []string{"mirror_urls", "urls"} {
			if _, ok := after[k]; ok {
				t.Errorf("%s: %q must be removed from the rewritten descriptor", c.name, k)
			}
		}
		// Every other field is preserved exactly — the integrity above all, since
		// Bazel re-verifies the archive (and each patch / overlay file) against it.
		for k, v := range before {
			if k == "url" || k == "mirror_urls" || k == "urls" {
				continue
			}
			if !reflect.DeepEqual(after[k], v) {
				t.Errorf("%s: field %q changed: %v -> %v", c.name, k, v, after[k])
			}
		}
		if len(after) != len(before)-countKeys(before, "mirror_urls", "urls") {
			t.Errorf("%s: rewritten descriptor has unexpected fields: %v", c.name, after)
		}
		// The proxy's URL must lead back to this module version's archive.
		u, err := url.Parse(c.wantURL)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		res, ok := classify(strings.TrimPrefix(u.Path, "/v1/bazel"))
		if !ok || res.kind != kindArchive || res.name != "m" || res.version != "1.0" {
			t.Errorf("%s: rewritten url does not classify as the module's archive: %+v ok=%v", c.name, res, ok)
		}
	}

	// A git_repository descriptor is not an archive: it is left for the caller to
	// pass through byte-for-byte, patches and all.
	if _, err := rewriteSourceJSON([]byte(bcrPicoSDK), endpoint); !errors.Is(err, errNotArchiveSource) {
		t.Errorf("git_repository: error = %v, want errNotArchiveSource", err)
	}
	// So is a local_path one, and any type the proxy does not know — even if it
	// happens to carry a "url" key.
	for _, body := range []string{
		`{"type":"local_path","path":"../some/module"}`,
		`{"type":"future_kind","url":"https://example.com/x.tar.gz"}`,
		`{"type":7,"url":"https://example.com/x.tar.gz"}`,
	} {
		if _, err := rewriteSourceJSON([]byte(body), endpoint); !errors.Is(err, errNotArchiveSource) {
			t.Errorf("%s: error = %v, want errNotArchiveSource", body, err)
		}
	}
	// An explicit "archive" type is the default spelled out.
	out, err := rewriteSourceJSON([]byte(`{"type":"archive","url":"https://example.com/x-1.0.zip","integrity":"sha256-ABC="}`), endpoint)
	if err != nil || !bytes.Contains(out, []byte(endpoint+"/x-1.0.zip")) {
		t.Errorf("explicit archive type: out=%s err=%v", out, err)
	}
}

func countKeys(m map[string]any, keys ...string) int {
	n := 0
	for _, k := range keys {
		if _, ok := m[k]; ok {
			n++
		}
	}
	return n
}

// TestRewriteIsDeterministic: Bazel records the hash of the source.json it was
// served in MODULE.bazel.lock and re-checks it, so the rewritten bytes must be
// identical on every request, whatever order the upstream wrote its keys in.
func TestRewriteIsDeterministic(t *testing.T) {
	const endpoint = "https://proxy.example.com/v1/bazel/modules/bison/3.8.2/archive"
	first, err := rewriteSourceJSON([]byte(bcrBison), endpoint)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := rewriteSourceJSON([]byte(bcrBison), endpoint)
		if err != nil || !bytes.Equal(first, again) {
			t.Fatalf("rewrite %d differs:\n%s\n%s (err=%v)", i, first, again, err)
		}
	}

	// The same descriptor with its keys in the opposite order and different
	// whitespace must rewrite to the very same bytes.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bcrBison), &obj); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	slices.Reverse(keys)
	var reordered strings.Builder
	reordered.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			reordered.WriteString(",")
		}
		fmt.Fprintf(&reordered, "\n\t%q :\t%s", k, obj[k])
	}
	reordered.WriteString("\n}\n")
	other, err := rewriteSourceJSON([]byte(reordered.String()), endpoint)
	if err != nil || !bytes.Equal(first, other) {
		t.Errorf("key order or whitespace leaked into the output:\n%s\n%s (err=%v)", first, other, err)
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

	mu   sync.Mutex
	seen []string          // request paths, in arrival order
	auth map[string]string // path -> Authorization header of its last request
}

// requests reports how many times the remote was asked for path.
func (fr *fakeRemote) requests(path string) int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	n := 0
	for _, p := range fr.seen {
		if p == path {
			n++
		}
	}
	return n
}

// authorization returns the Authorization header the remote last received for
// path ("" when none was sent or the path was never requested).
func (fr *fakeRemote) authorization(path string) string {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.auth[path]
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}, auth: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.seen = append(fr.seen, r.URL.Path)
		fr.auth[r.URL.Path] = r.Header.Get("Authorization")
		fr.mu.Unlock()
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
	// Regression (Bazel 7.4.1: "Expected a file with a .zip, ... .tar.gz, ...
	// suffix (got .../archive)"): the rewritten URL must end in the upstream
	// archive's file name, because Bazel infers the format from that suffix.
	wantURL := "https://proxy.example.com/v1/bazel/modules/platforms/0.0.10/archive/platforms-0.0.10.tar.gz"
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
	if fres.Size != int64(len(body)) {
		t.Errorf("size = %d, want the rewritten length %d", fres.Size, len(body))
	}
	if m.Stats().SourceRewritten != 1 {
		t.Errorf("source-rewritten metric = %v", m.Stats().SourceRewritten)
	}
}

// --- real-client regressions (Bazel 7.4.1 against the BCR) --------------------

// TestRewrittenArchiveURLRoundTrips follows the path a Bazel client takes: read
// the rewritten source.json, request the URL it names, and receive the archive
// that source.json's integrity vouches for.
func TestRewrittenArchiveURLRoundTrips(t *testing.T) {
	const publicBase = "https://proxy.example.com/v1/bazel"
	fr := newFakeRemote(t)
	archive := seedModule(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m, publicBase)

	_, body, err := resolveFetch(t, b, "/modules/platforms/0.0.10/source.json")
	if err != nil {
		t.Fatalf("fetch source.json: %v", err)
	}
	var doc struct {
		URL       string `json:"url"`
		Integrity string `json:"integrity"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("source.json not JSON: %v", err)
	}
	if !strings.HasPrefix(doc.URL, publicBase+"/") {
		t.Fatalf("rewritten url %q does not point at the proxy", doc.URL)
	}
	if !strings.HasSuffix(doc.URL, ".tar.gz") {
		t.Fatalf("rewritten url %q lost the archive suffix Bazel needs", doc.URL)
	}

	fres, got, err := resolveFetch(t, b, strings.TrimPrefix(doc.URL, publicBase))
	if err != nil {
		t.Fatalf("fetch %s: %v", doc.URL, err)
	}
	if !bytes.Equal(got, archive) {
		t.Fatal("archive body mismatch")
	}
	if doc.Integrity != sri256(got) {
		t.Errorf("served bytes do not match the integrity the client was given: %s vs %s", sri256(got), doc.Integrity)
	}
	res := fres.Resolved
	if !res.Cacheable || res.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("cacheable=%v verified=%q, want true/sha256", res.Cacheable, res.Metadata[MetaChecksumVerified])
	}
	if res.Coordinate.Name != "platforms" || res.Coordinate.Version != "0.0.10" {
		t.Errorf("coordinate = %+v, want platforms@0.0.10", res.Coordinate)
	}
	if st := m.Stats(); st.ArchivesVerified != 1 || st.ArchivesServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

// TestArchiveEndpointSpellingsShareOneCacheEntry: the file name after
// ".../archive/" is a label for Bazel, not a selector. The bare endpoint (what
// earlier proxy versions handed out, and what the test-set fixture pulls) and
// any named form must resolve to the same module version, the same source.json,
// and the same cache key — so a client cannot multiply cached copies of an
// archive, or reach different bytes, by varying the name.
func TestArchiveEndpointSpellingsShareOneCacheEntry(t *testing.T) {
	fr := newFakeRemote(t)
	archive := seedModule(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{}, "")

	const bare = "/modules/platforms/0.0.10/archive"
	want, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: bare, Query: url.Values{}})
	if err != nil {
		t.Fatalf("resolve %s: %v", bare, err)
	}
	if want.CacheKey != "bazel:modules/platforms/0.0.10/archive" {
		t.Errorf("bare endpoint cache key = %q; it must stay what it has always been", want.CacheKey)
	}
	for _, p := range []string{
		bare + "/platforms-0.0.10.tar.gz",
		bare + "/anything-else.zip",
		bare + "/archive",
		bare + "/",
	} {
		got, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}})
		if err != nil {
			t.Errorf("resolve %s: %v", p, err)
			continue
		}
		if got.CacheKey != want.CacheKey {
			t.Errorf("%s: cache key = %q, want %q", p, got.CacheKey, want.CacheKey)
		}
		if got.UpstreamURL != want.UpstreamURL || got.Coordinate != want.Coordinate || got.Cacheable != want.Cacheable {
			t.Errorf("%s: resolved differently from the bare endpoint: %+v vs %+v", p, got, want)
		}
		if got.Metadata[metaVerify] != "1" {
			t.Errorf("%s: must be integrity-verified", p)
		}
		fres, err := b.Fetch(context.Background(), got)
		if err != nil {
			t.Errorf("fetch %s: %v", p, err)
			continue
		}
		body, rerr := io.ReadAll(fres.Content)
		_ = fres.Content.Close()
		if rerr != nil || !bytes.Equal(body, archive) {
			t.Errorf("%s: served different bytes (err=%v)", p, rerr)
		}
	}
}

// seedMirroredModule registers a module whose source.json declares a primary
// archive URL plus mirror_urls, with the archive present only at the locations
// named in have ("primary", "mirror1", "mirror2").
func seedMirroredModule(fr *fakeRemote, archive []byte, integrity string, have ...string) {
	locations := map[string]string{
		"primary": "/primary/tool-1.0.tar.xz",
		"mirror1": "/mirror-one/tool-1.0.tar.xz",
		"mirror2": "/mirror-two/tool-1.0.tar.xz",
	}
	for _, h := range have {
		fr.files[locations[h]] = archive
	}
	fr.files["/modules/tool/1.0/source.json"] = []byte(fmt.Sprintf(
		`{"url":%q,"mirror_urls":[%q,%q],"integrity":%q,"strip_prefix":"tool-1.0"}`,
		fr.srv.URL+locations["primary"], fr.srv.URL+locations["mirror1"], fr.srv.URL+locations["mirror2"], integrity))
}

// TestSourceJSONDropsMirrorURLs: Bazel tries "mirror_urls" after "url". Left in
// the rewritten descriptor they would point straight at the internet, so a
// client would fetch around the proxy whenever the proxy refused or failed the
// archive. The client must be given the proxy's URL and nothing else.
func TestSourceJSONDropsMirrorURLs(t *testing.T) {
	const publicBase = "https://proxy.example.com/v1/bazel"
	fr := newFakeRemote(t)
	archive := []byte("tool-1.0 archive bytes")
	seedMirroredModule(fr, archive, sri256(archive), "primary")
	b := newTestBackend(t, fr, &Metrics{}, publicBase)

	_, body, err := resolveFetch(t, b, "/modules/tool/1.0/source.json")
	if err != nil {
		t.Fatalf("fetch source.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("source.json not JSON: %v", err)
	}
	if _, ok := doc["mirror_urls"]; ok {
		t.Errorf("mirror_urls survived the rewrite: %s", body)
	}
	if want := publicBase + "/modules/tool/1.0/archive/tool-1.0.tar.xz"; doc["url"] != want {
		t.Errorf("url = %v, want %q", doc["url"], want)
	}
	// Nothing in the document may still name the upstream archive hosts.
	if bytes.Contains(body, []byte(fr.srv.URL)) {
		t.Errorf("rewritten source.json still references an upstream archive location: %s", body)
	}
	if doc["integrity"] != sri256(archive) || doc["strip_prefix"] != "tool-1.0" {
		t.Errorf("other fields changed: %s", body)
	}
}

// TestArchiveFallsBackToMirrorURLs: the mirrors the client no longer sees are
// used by the proxy itself, in order, when the primary location fails — and the
// bytes are verified against the integrity whichever location served them.
func TestArchiveFallsBackToMirrorURLs(t *testing.T) {
	archive := []byte("tool-1.0 archive bytes")

	t.Run("primary healthy: mirrors untouched", func(t *testing.T) {
		fr := newFakeRemote(t)
		seedMirroredModule(fr, archive, sri256(archive), "primary", "mirror1", "mirror2")
		b := newTestBackend(t, fr, &Metrics{}, "")
		fres, body, err := resolveFetch(t, b, "/modules/tool/1.0/archive/tool-1.0.tar.xz")
		if err != nil || !bytes.Equal(body, archive) {
			t.Fatalf("fetch: err=%v", err)
		}
		if got := fres.Resolved.Metadata[MetaArchiveURL]; got != fr.srv.URL+"/primary/tool-1.0.tar.xz" {
			t.Errorf("archive URL metadata = %q, want the primary", got)
		}
		if fr.requests("/mirror-one/tool-1.0.tar.xz")+fr.requests("/mirror-two/tool-1.0.tar.xz") != 0 {
			t.Error("mirrors must not be contacted while the primary serves the archive")
		}
	})

	t.Run("primary gone: second mirror serves, verified", func(t *testing.T) {
		fr := newFakeRemote(t)
		seedMirroredModule(fr, archive, sri256(archive), "mirror2")
		m := &Metrics{}
		b := newTestBackend(t, fr, m, "")
		fres, body, err := resolveFetch(t, b, "/modules/tool/1.0/archive/tool-1.0.tar.xz")
		if err != nil || !bytes.Equal(body, archive) {
			t.Fatalf("fetch: err=%v", err)
		}
		md := fres.Resolved.Metadata
		if md[MetaArchiveURL] != fr.srv.URL+"/mirror-two/tool-1.0.tar.xz" {
			t.Errorf("archive URL metadata = %q, want the mirror that served", md[MetaArchiveURL])
		}
		if md[MetaChecksumVerified] != "sha256" {
			t.Errorf("checksum metadata = %q", md[MetaChecksumVerified])
		}
		// Tried in the descriptor's order, each exactly once.
		for _, p := range []string{"/primary/tool-1.0.tar.xz", "/mirror-one/tool-1.0.tar.xz", "/mirror-two/tool-1.0.tar.xz"} {
			if got := fr.requests(p); got != 1 {
				t.Errorf("requests for %s = %d, want 1", p, got)
			}
		}
		if st := m.Stats(); st.ArchivesServed != 1 || st.ArchivesVerified != 1 {
			t.Errorf("metrics = %+v", st)
		}
	})

	t.Run("mirror with the wrong bytes is refused", func(t *testing.T) {
		fr := newFakeRemote(t)
		seedMirroredModule(fr, []byte("a different artifact"), sri256(archive), "mirror1")
		m := &Metrics{}
		b := newTestBackend(t, fr, m, "")
		_, _, err := resolveFetch(t, b, "/modules/tool/1.0/archive/tool-1.0.tar.xz")
		var mm *IntegrityMismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("error = %v, want IntegrityMismatchError", err)
		}
		if m.Stats().ChecksumMismatch != 1 {
			t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
		}
	})

	t.Run("every location gone: the primary's status is reported", func(t *testing.T) {
		fr := newFakeRemote(t)
		seedMirroredModule(fr, archive, sri256(archive))
		b := newTestBackend(t, fr, &Metrics{}, "")
		_, _, err := resolveFetch(t, b, "/modules/tool/1.0/archive/tool-1.0.tar.xz")
		var se *backends.StatusError
		if !errors.As(err, &se) {
			t.Fatalf("error = %v, want StatusError", err)
		}
		if se.Status != http.StatusNotFound || !strings.HasSuffix(se.URL, "/primary/tool-1.0.tar.xz") {
			t.Errorf("status error = %d %s, want the primary's 404", se.Status, se.URL)
		}
	})
}

// TestArchiveCredentialsStayOnRegistryHost: the registry token is sent to the
// registry (source.json, and an archive hosted there) but never to an external
// archive host — primary or mirror.
func TestArchiveCredentialsStayOnRegistryHost(t *testing.T) {
	registry := newFakeRemote(t)
	external := newFakeRemote(t)
	archive := []byte("externally hosted archive")
	external.files["/releases/x-1.0.tar.gz"] = archive
	registry.files["/modules/x/1.0/source.json"] = []byte(fmt.Sprintf(
		`{"url":%q,"mirror_urls":[%q],"integrity":%q}`,
		registry.srv.URL+"/gone/x-1.0.tar.gz", external.srv.URL+"/releases/x-1.0.tar.gz", sri256(archive)))

	b, err := New(Options{
		Name:        "bazel",
		UpstreamURL: registry.srv.URL,
		Client:      upstream.NewWithHTTPClient(registry.srv.Client(), "test/1"),
		Credentials: upstream.Credentials{Token: "registry-secret"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, body, err := resolveFetch(t, b, "/modules/x/1.0/archive/x-1.0.tar.gz")
	if err != nil || !bytes.Equal(body, archive) {
		t.Fatalf("fetch: err=%v", err)
	}
	if got := registry.authorization("/modules/x/1.0/source.json"); !strings.Contains(got, "registry-secret") {
		t.Errorf("source.json request should carry the registry credentials, got %q", got)
	}
	if got := registry.authorization("/gone/x-1.0.tar.gz"); !strings.Contains(got, "registry-secret") {
		t.Errorf("an archive on the registry host should carry the registry credentials, got %q", got)
	}
	if got := external.authorization("/releases/x-1.0.tar.gz"); got != "" {
		t.Errorf("registry credentials leaked to an external archive host: %q", got)
	}
}

// TestGitRepositorySourcePassedThrough: a "git_repository" descriptor (4 module
// versions in BCR) has no archive. It must reach the client byte-for-byte —
// rewriting it, or inventing a "url", would break the module — and the archive
// endpoint has nothing to serve for it.
func TestGitRepositorySourcePassedThrough(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/modules/pico-sdk/2.1.1/source.json"] = []byte(bcrPicoSDK)
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "https://proxy.example.com/v1/bazel")

	fres, body, err := resolveFetch(t, b, "/modules/pico-sdk/2.1.1/source.json")
	if err != nil {
		t.Fatalf("fetch source.json: %v", err)
	}
	if string(body) != bcrPicoSDK {
		t.Errorf("git_repository source.json was altered:\n%s", body)
	}
	if fres.Size != int64(len(bcrPicoSDK)) {
		t.Errorf("size = %d, want %d", fres.Size, len(bcrPicoSDK))
	}
	if m.Stats().SourceRewritten != 0 {
		t.Errorf("source-rewritten metric = %v, want 0", m.Stats().SourceRewritten)
	}

	_, _, err = resolveFetch(t, b, "/modules/pico-sdk/2.1.1/archive")
	var se *backends.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusBadGateway {
		t.Errorf("archive endpoint of a git_repository module: error = %v, want a 502 StatusError", err)
	}
}

// TestNonArchiveTypeNeverFetchedAsArchive: a descriptor that is not an archive
// source but smuggles a "url" must not make the archive endpoint fetch it.
func TestNonArchiveTypeNeverFetchedAsArchive(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/elsewhere/x.tar.gz"] = []byte("should never be fetched")
	fr.files["/modules/x/1.0/source.json"] = []byte(fmt.Sprintf(
		`{"type":"git_repository","remote":"https://example.com/x.git","commit":"abc","url":%q}`, fr.srv.URL+"/elsewhere/x.tar.gz"))
	b := newTestBackend(t, fr, &Metrics{}, "")

	_, _, err := resolveFetch(t, b, "/modules/x/1.0/archive/x.tar.gz")
	var se *backends.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusBadGateway {
		t.Fatalf("error = %v, want a 502 StatusError", err)
	}
	if got := fr.requests("/elsewhere/x.tar.gz"); got != 0 {
		t.Errorf("the smuggled url was fetched %d time(s)", got)
	}
}

// TestOverlayFileServedAndCacheable is the regression test for the 501 on
// ".../overlay/<path>": 31% of BCR module versions declare overlay files, which
// Bazel 7.2+ downloads from the registry itself.
func TestOverlayFileServedAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	build := []byte("cc_library(name = \"abc\")\n")
	nested := []byte("exports_files([\"defs.bzl\"])\n")
	fr.files["/modules/abc/0.0.0-20250408-yosyshq/overlay/BUILD.bazel"] = build
	fr.files["/modules/abc/0.0.0-20250408-yosyshq/overlay/src/base/BUILD.bazel"] = nested
	m := &Metrics{}
	b := newTestBackend(t, fr, m, "https://proxy.example.com/v1/bazel")

	for path, want := range map[string][]byte{
		"/modules/abc/0.0.0-20250408-yosyshq/overlay/BUILD.bazel":          build,
		"/modules/abc/0.0.0-20250408-yosyshq/overlay/src/base/BUILD.bazel": nested,
	} {
		fres, body, err := resolveFetch(t, b, path)
		if err != nil {
			t.Fatalf("fetch %s: %v", path, err)
		}
		if !bytes.Equal(body, want) {
			t.Errorf("%s: body mismatch", path)
		}
		res := fres.Resolved
		if want := fr.srv.URL + path; res.UpstreamURL != want {
			t.Errorf("%s: upstream URL = %q, want %q", path, res.UpstreamURL, want)
		}
		if !res.Cacheable {
			t.Errorf("%s: an overlay file is immutable and should be cacheable", path)
		}
		if res.CacheKey != "bazel:"+strings.TrimPrefix(path, "/") {
			t.Errorf("%s: cache key = %q", path, res.CacheKey)
		}
		if res.Coordinate.Name != "abc" || res.Coordinate.Version != "0.0.0-20250408-yosyshq" {
			t.Errorf("%s: coordinate = %+v", path, res.Coordinate)
		}
		if res.Metadata[metaKind] != "overlay" || res.Metadata[metaVerify] == "1" || res.Metadata[metaRewrite] == "1" {
			t.Errorf("%s: metadata = %v", path, res.Metadata)
		}
	}
	if got := m.Stats().IndexServed; got != 2 {
		t.Errorf("index-served metric = %v, want 2", got)
	}

	// An overlay file the registry does not have is the registry's 404.
	_, _, err := resolveFetch(t, b, "/modules/abc/0.0.0-20250408-yosyshq/overlay/missing/BUILD.bazel")
	var se *backends.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Errorf("missing overlay file: error = %v, want a 404 StatusError", err)
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
