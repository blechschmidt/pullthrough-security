package julia

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const (
	generalUUID   = "23338594-aafe-5451-b93e-139f81909106"
	exampleUUID   = "7876af07-990d-54b4-ab0e-23690620f79a"
	sampleTreeSHA = "46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc"
)

// --- classification / URL construction ("rewriting") -----------------------

func TestClassify(t *testing.T) {
	tests := []struct {
		path       string
		ok         bool
		kind       resourceKind
		uuid       string
		hash       string
		cacheable  bool
		verifiable bool
	}{
		{path: "/registries", ok: true, kind: kindRegistries, cacheable: false, verifiable: false},
		{
			path: "/registry/" + generalUUID + "/" + sampleTreeSHA, ok: true, kind: kindRegistry,
			uuid: generalUUID, hash: sampleTreeSHA, cacheable: true, verifiable: true,
		},
		{
			path: "/package/" + exampleUUID + "/" + sampleTreeSHA, ok: true, kind: kindPackage,
			uuid: exampleUUID, hash: sampleTreeSHA, cacheable: true, verifiable: true,
		},
		{
			path: "/artifact/" + sampleTreeSHA, ok: true, kind: kindArtifact,
			hash: sampleTreeSHA, cacheable: true, verifiable: true,
		},
		// Reserved SHA3-256-length hash: cacheable (content-addressed) but not
		// verifiable by this backend.
		{
			path: "/artifact/" + strings.Repeat("a", 64), ok: true, kind: kindArtifact,
			hash: strings.Repeat("a", 64), cacheable: true, verifiable: false,
		},
		// Rejections.
		{path: "/", ok: false},
		{path: "", ok: false},
		{path: "/registry/" + generalUUID, ok: false},                                // missing hash
		{path: "/registry/not-a-uuid/" + sampleTreeSHA, ok: false},                   // bad uuid
		{path: "/package/" + exampleUUID + "/ZZZ", ok: false},                        // bad hash
		{path: "/package/" + exampleUUID + "/" + strings.Repeat("a", 39), ok: false}, // wrong length
		{path: "/artifact/" + strings.ToUpper(sampleTreeSHA), ok: false},             // uppercase hex rejected
		{path: "/registry/../../etc/passwd/" + sampleTreeSHA, ok: false},             // traversal
		{path: "/package/" + exampleUUID + "/" + sampleTreeSHA + "/extra", ok: false},
		{path: "/unknown/x", ok: false},
	}
	for _, tt := range tests {
		res, ok := classify(tt.path)
		if ok != tt.ok {
			t.Errorf("classify(%q) ok = %v, want %v", tt.path, ok, tt.ok)
			continue
		}
		if !ok {
			continue
		}
		if res.kind != tt.kind {
			t.Errorf("classify(%q) kind = %v, want %v", tt.path, res.kind, tt.kind)
		}
		if res.uuid != tt.uuid {
			t.Errorf("classify(%q) uuid = %q, want %q", tt.path, res.uuid, tt.uuid)
		}
		if res.hash != tt.hash {
			t.Errorf("classify(%q) hash = %q, want %q", tt.path, res.hash, tt.hash)
		}
		if res.cacheable() != tt.cacheable {
			t.Errorf("classify(%q) cacheable = %v, want %v", tt.path, res.cacheable(), tt.cacheable)
		}
		if res.verifiable() != tt.verifiable {
			t.Errorf("classify(%q) verifiable = %v, want %v", tt.path, res.verifiable(), tt.verifiable)
		}
	}
}

func newTestBackend(t *testing.T, doer upstream.Doer, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{Name: "julia", UpstreamURL: "https://pkg.example.com", Client: doer, Metrics: m})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// TestResolveURLConstruction verifies the inbound path is rewritten onto the
// upstream base URL correctly (the Julia analog of URL rewriting: path → upstream
// URL), that cacheability/coordinate/verify metadata are set, and that query
// strings are preserved.
func TestResolveURLConstruction(t *testing.T) {
	b := newTestBackend(t, doerFunc(func(context.Context, upstream.Request) (*upstream.Response, error) {
		t.Fatal("Resolve must not perform I/O")
		return nil, nil
	}), &Metrics{})

	pkgPath := "/package/" + exampleUUID + "/" + sampleTreeSHA
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: pkgPath, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantURL := "https://pkg.example.com/package/" + exampleUUID + "/" + sampleTreeSHA
	if res.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, wantURL)
	}
	if !res.Cacheable {
		t.Error("package tarball should be cacheable")
	}
	if res.Coordinate.Name != exampleUUID || res.Coordinate.Version != sampleTreeSHA {
		t.Errorf("Coordinate = %+v, want %s/%s", res.Coordinate, exampleUUID, sampleTreeSHA)
	}
	if res.Metadata[metaVerify] != "1" || res.Metadata[metaHash] != sampleTreeSHA {
		t.Errorf("verify metadata not set: %+v", res.Metadata)
	}
	if res.CacheKey != "julia:package/"+exampleUUID+"/"+sampleTreeSHA {
		t.Errorf("CacheKey = %q", res.CacheKey)
	}

	// /registries is mutable: live, not cacheable, no verify.
	res2, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/registries", Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(/registries): %v", err)
	}
	if res2.Cacheable {
		t.Error("/registries must not be cacheable")
	}
	if res2.Metadata[metaVerify] == "1" {
		t.Error("/registries must not be marked verify")
	}

	// Unsupported path → ErrNotSupported.
	if _, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/nope", Query: url.Values{}}); !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("Resolve(/nope) err = %v, want ErrNotSupported", err)
	}
}

func TestResolvePreservesBasePathAndQuery(t *testing.T) {
	b, err := New(Options{Name: "julia", UpstreamURL: "https://host.example/pkg", Client: doerFunc(nil)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	q := url.Values{"depwarn": {"no"}}
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/registries", Query: q})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.UpstreamURL != "https://host.example/pkg/registries?depwarn=no" {
		t.Errorf("UpstreamURL = %q", res.UpstreamURL)
	}
}

// --- integrity verification ------------------------------------------------

// fileSpec describes one entry used to build both a git working tree (for the
// reference hash) and an in-memory gzipped tar (for the verifier under test).
type fileSpec struct {
	path    string
	mode    int64
	content string
	symlink string // when non-empty, this entry is a symlink to this target
}

var sampleTree = []fileSpec{
	{path: "README.md", mode: 0o644, content: "hello\n"},
	{path: "src/main.jl", mode: 0o644, content: "print(\"hi\")\n"},
	{path: "run.sh", mode: 0o755, content: "#!/bin/sh\necho run\n"},
	{path: "link.txt", mode: 0o777, symlink: "README.md"},
}

// gzipTar builds a gzip-compressed tar of specs, including explicit directory
// entries, in a deliberately non-sorted order to exercise the hasher's ordering.
func gzipTar(t *testing.T, specs []fileSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	// Emit directory entries for every parent directory.
	seenDir := map[string]bool{}
	emitDir := func(dir string) {
		if dir == "." || dir == "" || seenDir[dir] {
			return
		}
		seenDir[dir] = true
		if err := tw.WriteHeader(&tar.Header{Name: dir + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatalf("write dir header %q: %v", dir, err)
		}
	}
	for _, s := range specs {
		if d := filepath.Dir(s.path); d != "." {
			emitDir(d)
		}
		if s.symlink != "" {
			if err := tw.WriteHeader(&tar.Header{Name: s.path, Typeflag: tar.TypeSymlink, Linkname: s.symlink, Mode: s.mode}); err != nil {
				t.Fatalf("write symlink header: %v", err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: s.path, Typeflag: tar.TypeReg, Mode: s.mode, Size: int64(len(s.content))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(s.content)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// gitTreeHashOf builds specs into a real git working tree and returns git's own
// tree SHA, the authoritative reference. It skips the test if git is absent.
func gitTreeHashOf(t *testing.T, specs []fileSpec) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available for reference tree hash")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	for _, s := range specs {
		full := filepath.Join(dir, s.path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if s.symlink != "" {
			if err := os.Symlink(s.symlink, full); err != nil {
				t.Fatalf("symlink: %v", err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(s.content), os.FileMode(s.mode)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	run("add", "-A")
	return run("write-tree")
}

func TestGitTreeHashMatchesGit(t *testing.T) {
	want := gitTreeHashOf(t, sampleTree)
	got, err := gitTreeHashGzip(bytes.NewReader(gzipTar(t, sampleTree)))
	if err != nil {
		t.Fatalf("gitTreeHashGzip: %v", err)
	}
	if got != want {
		t.Fatalf("tree hash = %s, want %s (git)", got, want)
	}
}

// TestGitTreeHashKnownAnswer is a git-independent regression anchor: the hash of
// sampleTree computed once with git 2.43 (so the implementation stays pinned even
// where git is unavailable at test time).
func TestGitTreeHashKnownAnswer(t *testing.T) {
	const want = "1f3e7c648e372e178c0fcaf5da210cb75b6aff1f"
	got, err := gitTreeHashGzip(bytes.NewReader(gzipTar(t, sampleTree)))
	if err != nil {
		t.Fatalf("gitTreeHashGzip: %v", err)
	}
	if got != want {
		t.Fatalf("tree hash = %s, want known-answer %s", got, want)
	}
}

func TestGitTreeHashEmptyAndNestedEmptyDirs(t *testing.T) {
	// A tree whose only directory entry is empty hashes like the empty tree —
	// git does not represent empty directories.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "emptydir/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "emptydir/nested/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.Close()
	_ = zw.Close()
	got, err := gitTreeHashGzip(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gitTreeHashGzip: %v", err)
	}
	if got != emptyTreeSHA1 {
		t.Fatalf("empty-dir tree hash = %s, want %s", got, emptyTreeSHA1)
	}
}

// --- Fetch end-to-end with the verifier ------------------------------------

func fetchThrough(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	fr.Resolved = res
	return fr, body, rerr
}

func TestFetchVerifiesMatchingTarball(t *testing.T) {
	want := gitTreeHashOf(t, sampleTree) // skips if git absent; also pins to known answer below
	tarball := gzipTar(t, sampleTree)
	m := &Metrics{}
	b := newTestBackend(t, doerFunc(func(_ context.Context, r upstream.Request) (*upstream.Response, error) {
		return respBody(tarball), nil
	}), m)

	fr, body, err := fetchThrough(t, b, "/package/"+exampleUUID+"/"+want)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(body, tarball) {
		t.Fatal("served body differs from upstream")
	}
	if fr.Resolved.Metadata[MetaTreeHashVerified] != "git-sha1" {
		t.Errorf("MetaTreeHashVerified = %q", fr.Resolved.Metadata[MetaTreeHashVerified])
	}
	if fr.Header.Get("X-Tree-Hash-Verified") != "git-sha1" {
		t.Errorf("missing X-Tree-Hash-Verified header")
	}
	if st := m.Stats(); st.TarballsVerified != 1 || st.TreeHashMismatch != 0 {
		t.Errorf("metrics = %+v, want 1 verified / 0 mismatch", st)
	}
}

func TestFetchRejectsTamperedTarball(t *testing.T) {
	tarball := gzipTar(t, sampleTree)
	// Request under a different (wrong) but well-formed git-tree-sha1.
	wrong := strings.Repeat("0", 40)
	m := &Metrics{}
	b := newTestBackend(t, doerFunc(func(_ context.Context, r upstream.Request) (*upstream.Response, error) {
		return respBody(tarball), nil
	}), m)

	_, _, err := fetchThrough(t, b, "/package/"+exampleUUID+"/"+wrong)
	if err == nil {
		t.Fatal("expected a tree-hash mismatch error")
	}
	var mm *TreeHashMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("error = %v, want *TreeHashMismatchError", err)
	}
	if st := m.Stats(); st.TreeHashMismatch != 1 || st.TarballsVerified != 0 {
		t.Errorf("metrics = %+v, want 0 verified / 1 mismatch", st)
	}
}

func TestFetchRejectsCorruptGzip(t *testing.T) {
	b := newTestBackend(t, doerFunc(func(_ context.Context, r upstream.Request) (*upstream.Response, error) {
		return respBody([]byte("this is not a gzip stream at all, just junk bytes")), nil
	}), &Metrics{})
	_, _, err := fetchThrough(t, b, "/artifact/"+sampleTreeSHA)
	if err == nil {
		t.Fatal("expected an error for a corrupt gzip body")
	}
	var mm *TreeHashMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("error = %v, want *TreeHashMismatchError", err)
	}
}

func TestFetchRegistriesPassThrough(t *testing.T) {
	listing := []byte("/registry/" + generalUUID + "/" + sampleTreeSHA + "\n")
	m := &Metrics{}
	b := newTestBackend(t, doerFunc(func(_ context.Context, r upstream.Request) (*upstream.Response, error) {
		return respBody(listing), nil
	}), m)
	fr, body, err := fetchThrough(t, b, "/registries")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(body, listing) {
		t.Fatal("listing body altered")
	}
	if fr.Resolved.Metadata[MetaTreeHashVerified] != "none" {
		t.Errorf("MetaTreeHashVerified = %q, want none", fr.Resolved.Metadata[MetaTreeHashVerified])
	}
	if st := m.Stats(); st.ListingServed != 1 {
		t.Errorf("ListingServed = %v, want 1", st.ListingServed)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []Options{
		{Name: "", UpstreamURL: "https://x", Client: doerFunc(nil)},
		{Name: "j", UpstreamURL: "", Client: doerFunc(nil)},
		{Name: "j", UpstreamURL: "ftp://x", Client: doerFunc(nil)},
		{Name: "j", UpstreamURL: "https://x", Client: nil},
	}
	for i, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// --- test doubles ----------------------------------------------------------

type doerFunc func(context.Context, upstream.Request) (*upstream.Response, error)

func (f doerFunc) Do(ctx context.Context, r upstream.Request) (*upstream.Response, error) {
	return f(ctx, r)
}

func respBody(b []byte) *upstream.Response {
	return &upstream.Response{
		Status:        http.StatusOK,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(b)),
		ContentLength: int64(len(b)),
	}
}
