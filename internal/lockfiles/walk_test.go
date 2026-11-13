package lockfiles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/git"
)

// testRepo is a repository built with the git binary.
type testRepo struct {
	t   *testing.T
	dir string
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	r := &testRepo{t: t, dir: t.TempDir()}
	r.git("init", "--quiet", "--initial-branch=main")
	r.git("config", "user.email", "t@example.com")
	r.git("config", "user.name", "T")
	r.git("config", "commit.gpgsign", "false")
	return r
}

func (r *testRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+r.dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *testRepo) write(rel string, data []byte) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// copyFixture copies testdata/fixtures/<name> to <dest> in the repository.
func (r *testRepo) copyFixture(name, dest string) {
	r.t.Helper()
	src := filepath.Join("testdata/fixtures", name)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		r.write(dest+"/"+filepath.ToSlash(rel), data)
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *testRepo) commit() string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "--quiet", "-m", "c")
	return r.git("rev-parse", "HEAD")
}

func (r *testRepo) scan(rev string, opts Options) *Report {
	r.t.Helper()
	objs, err := git.OpenObjectReader(r.dir, git.ObjectReaderOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	defer objs.Close()
	rep, err := Scan(context.Background(), objs, rev, opts)
	if err != nil {
		r.t.Fatal(err)
	}
	return rep
}

func filePaths(rep *Report) []string {
	var out []string
	for _, f := range rep.Files {
		out = append(out, f.Path)
	}
	return out
}

func skippedReasons(rep *Report) map[string]string {
	out := map[string]string{}
	for _, s := range rep.Skipped {
		out[s.Path] = s.Reason
	}
	return out
}

// TestScanMatchesGolden: every fixture, committed into one monorepo, is read
// by the tree walk exactly as the golden test reads it from disk.
func TestScanMatchesGolden(t *testing.T) {
	repo := newTestRepo(t)
	var names []string
	for _, name := range fixtureNames(t) {
		// Git reads .gitmodules only at the root of a tree: such a fixture is
		// scanned on its own (TestScanPinsSubmodulesAsTheGoldenSays).
		if _, err := os.Stat(filepath.Join("testdata/fixtures", name, gitmodulesPath)); err == nil {
			continue
		}
		names = append(names, name)
	}
	for _, name := range names {
		repo.copyFixture(name, "cases/"+name)
	}
	commit := repo.commit()
	rep := repo.scan("HEAD", Options{Proxy: goldenProxy})
	if rep.Commit != commit {
		t.Fatalf("scanned %s, want %s", rep.Commit, commit)
	}
	if rep.Truncated != "" {
		t.Fatalf("truncated: %s", rep.Truncated)
	}
	byCase := map[string][]*File{}
	for _, f := range rep.Files {
		rest := strings.TrimPrefix(f.Path, "cases/")
		name, rel, _ := strings.Cut(rest, "/")
		// Golden files hold paths relative to the fixture.
		copied := *f
		copied.Path = rel
		copied.Dependencies = append([]Dependency{}, f.Dependencies...)
		for i := range copied.Dependencies {
			copied.Dependencies[i].File = rel
		}
		byCase[name] = append(byCase[name], &copied)
	}
	for _, name := range names {
		want, err := os.ReadFile(filepath.Join("testdata/golden", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if got := marshalFiles(t, byCase[name]); !bytes.Equal(got, want) {
			t.Errorf("%s: the scan differs from the golden file\n%s", name, firstDiff(string(want), string(got)))
		}
	}
	if raw, _ := json.Marshal(rep); bytes.Contains(raw, []byte("ptl1abc")) {
		t.Error("the report contains the link token")
	}
}

func TestScanWalk(t *testing.T) {
	repo := newTestRepo(t)
	repo.copyFixture("npm-lock-v3", "web")
	repo.copyFixture("cargo-v4", "svc")
	repo.copyFixture("go-modules", "tools")
	// Vendored code and test fixtures are skipped by default.
	repo.copyFixture("npm-lock-v1", "web/node_modules/dep")
	repo.copyFixture("composer", "php/vendor/pkg")
	repo.copyFixture("bundler", "spec/fixtures/app")
	repo.copyFixture("uv", "testdata/py")
	// A lock file too large to read, one nested too deep, a symlink.
	repo.write("big/poetry.lock", bytes.Repeat([]byte("# padding\n"), 2000))
	repo.copyFixture("cargo-v1", "d1/d2/d3/d4/d5")
	if err := os.Symlink("../web/package-lock.json", filepath.Join(repo.dir, "svc", "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	head := repo.commit()
	// A submodule: a gitlink in the tree.
	repo.git("update-index", "--add", "--cacheinfo", "160000,"+head+",third/sub")
	repo.git("commit", "--quiet", "-m", "submodule")

	rep := repo.scan("HEAD", Options{MaxDepth: 4, MaxFileBytes: 8 << 10})
	if got := strings.Join(filePaths(rep), ","); got != "svc/Cargo.lock,tools/go.mod,tools/go.sum,tools/local/go.mod,web/package-lock.json" {
		t.Errorf("files %s", got)
	}
	skipped := skippedReasons(rep)
	for p, want := range map[string]string{
		"web/node_modules/":     "skip glob",
		"php/vendor/":           "skip glob",
		"spec/fixtures/":        "skip glob",
		"testdata/":             "skip glob",
		"big/poetry.lock":       "limit",
		"d1/d2/d3/d4/d5/":       "deeper than 4",
		"svc/package-lock.json": "symbolic link",
	} {
		if !strings.Contains(skipped[p], want) {
			t.Errorf("skipped[%q] = %q, want it to mention %q (all: %v)", p, skipped[p], want, skipped)
		}
	}
	if len(rep.Submodules) != 1 || rep.Submodules[0].Path != "third/sub" || rep.Submodules[0].Commit != head {
		t.Errorf("submodules %+v", rep.Submodules)
	}
	if rep.Stats.LockFiles != 5 || rep.Stats.BytesRead == 0 || rep.Stats.Trees == 0 || rep.Stats.SkippedDirs != 5 {
		t.Errorf("stats %+v", rep.Stats)
	}
	if deps := rep.Dependencies(); len(deps) < 10 {
		t.Errorf("%d dependencies", len(deps))
	}

	// Nothing skipped: the vendored lock files are read too.
	all := repo.scan("HEAD", Options{Skip: []string{}, MaxDepth: 10, MaxFileBytes: 1 << 20})
	paths := strings.Join(filePaths(all), ",")
	for _, want := range []string{"web/node_modules/dep/package-lock.json", "php/vendor/pkg/composer.lock", "big/poetry.lock", "d1/d2/d3/d4/d5/Cargo.lock"} {
		if !strings.Contains(paths, want) {
			t.Errorf("without skip globs %s was not read: %s", want, paths)
		}
	}
	for _, f := range all.Files {
		if f.Path == "big/poetry.lock" && f.Error == "" {
			t.Error("a padding-only poetry.lock parsed without an error")
		}
	}
}

func TestScanRootAndRevision(t *testing.T) {
	repo := newTestRepo(t)
	repo.copyFixture("cargo-v4", "svc")
	repo.copyFixture("npm-lock-v3", "web")
	first := repo.commit()
	repo.copyFixture("go-modules", "svc/go")
	repo.commit()
	// Uncommitted changes are not what a commit holds.
	repo.write("web/package-lock.json", []byte("not even JSON"))
	repo.write("web/yarn.lock", []byte("# yarn lockfile v1\n"))

	rep := repo.scan("HEAD", Options{Root: "svc"})
	if got := strings.Join(filePaths(rep), ","); got != "svc/Cargo.lock,svc/go/go.mod,svc/go/go.sum,svc/go/local/go.mod" {
		t.Errorf("root svc: %s", got)
	}
	if rep.Root != "svc" {
		t.Errorf("root %q", rep.Root)
	}
	old := repo.scan(first, Options{})
	if got := strings.Join(filePaths(old), ","); got != "svc/Cargo.lock,web/package-lock.json" {
		t.Errorf("first commit: %s", got)
	}
	for _, f := range old.Files {
		if f.Error != "" {
			t.Errorf("%s: %s (the working tree was read?)", f.Path, f.Error)
		}
	}

	objs, err := git.OpenObjectReader(repo.dir, git.ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	for _, root := range []string{"nope", "svc/Cargo.lock"} {
		if _, err := Scan(context.Background(), objs, "HEAD", Options{Root: root}); err == nil {
			t.Errorf("root %q accepted", root)
		}
	}
	if _, err := Scan(context.Background(), objs, "no-such-rev", Options{}); !errors.Is(err, git.ErrObjectNotFound) {
		t.Errorf("unknown revision: %v", err)
	}
	if _, err := Scan(context.Background(), objs, "HEAD", Options{Skip: []string{"a//b"}}); err == nil {
		t.Error("a malformed skip glob was accepted")
	}
}

func TestScanLimits(t *testing.T) {
	repo := newTestRepo(t)
	for _, d := range []string{"a", "b", "c", "d"} {
		repo.copyFixture("cargo-v4", d)
	}
	repo.commit()
	if rep := repo.scan("HEAD", Options{MaxFiles: 2}); len(rep.Files) != 2 || !strings.Contains(rep.Truncated, "lock files") {
		t.Errorf("MaxFiles: %d files, truncated %q", len(rep.Files), rep.Truncated)
	}
	if rep := repo.scan("HEAD", Options{MaxTotalBytes: 1000}); len(rep.Files) != 1 || !strings.Contains(rep.Truncated, "bytes") {
		t.Errorf("MaxTotalBytes: %d files, truncated %q", len(rep.Files), rep.Truncated)
	}
	if rep := repo.scan("HEAD", Options{MaxTreeEntries: 3}); !strings.Contains(rep.Truncated, "entries") {
		t.Errorf("MaxTreeEntries: truncated %q", rep.Truncated)
	}
}

// TestScanPartialClone: a lock file a size-filtered clone left out is
// reported, not fetched and not fatal.
func TestScanPartialClone(t *testing.T) {
	src := newTestRepo(t)
	src.git("config", "uploadpack.allowFilter", "true")
	src.copyFixture("cargo-v4", "small")
	src.copyFixture("uv", "large")
	src.commit()

	dir := filepath.Join(t.TempDir(), "clone.git")
	commit, err := git.CloneForScan(context.Background(), git.ScanCloneOptions{URL: "file://" + src.dir, Dir: dir, MaxBlobBytes: 16 << 10})
	if err != nil {
		t.Fatal(err)
	}
	objs, err := git.OpenObjectReader(dir, git.ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	rep, err := Scan(context.Background(), objs, commit, Options{MaxFileBytes: 16 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(filePaths(rep), ","); got != "small/Cargo.lock" {
		t.Errorf("files %s", got)
	}
	if reason := skippedReasons(rep)["large/uv.lock"]; !strings.Contains(reason, "partial clone") {
		t.Errorf("large/uv.lock: %q", reason)
	}
}

// fakeObjects serves a tree from memory, to reach what a real repository
// cannot hold.
type fakeObjects struct {
	trees map[string][]git.TreeEntry
	blobs map[string][]byte
	errs  map[string]error
}

func (f *fakeObjects) ResolveCommit(context.Context, string) (string, string, error) {
	return strings.Repeat("c", 40), "root", nil
}

func (f *fakeObjects) Info(_ context.Context, name string) (git.ObjectInfo, error) {
	if err := f.errs[name]; err != nil {
		return git.ObjectInfo{}, err
	}
	if b, ok := f.blobs[name]; ok {
		return git.ObjectInfo{ID: name, Type: git.ObjectBlob, Size: int64(len(b))}, nil
	}
	return git.ObjectInfo{}, git.ErrObjectNotFound
}

func (f *fakeObjects) ReadTree(_ context.Context, id string) ([]git.TreeEntry, error) {
	if err := f.errs[id]; err != nil {
		return nil, err
	}
	return f.trees[id], nil
}

func (f *fakeObjects) ReadBlob(_ context.Context, id string, _ int64) ([]byte, error) {
	return f.blobs[id], nil
}

func TestScanSurvivesHostileTrees(t *testing.T) {
	objs := &fakeObjects{
		trees: map[string][]git.TreeEntry{
			"root": {
				{Name: "bad", Kind: git.EntryTree, ID: "badtree"},
				{Name: "gone", Kind: git.EntryTree, ID: "missing"},
				{Name: "ok", Kind: git.EntryTree, ID: "oktree"},
			},
			"oktree": {
				{Name: "go.sum", Kind: git.EntryFile, ID: "sum"},
				{Name: "Cargo.lock", Kind: git.EntryFile, ID: "panicky"},
			},
		},
		blobs: map[string][]byte{
			"sum":     []byte("example.com/a v1.0.0 h1:" + strings.Repeat("A", 43) + "=\n"),
			"panicky": []byte("version = 4\n[[package]]\nname = \"x\"\nversion = \"1\"\nsource = \"registry+https://a\"\n"),
		},
		errs: map[string]error{
			"badtree": errors.Join(git.ErrMalformedObject, errors.New("tree entry name contains '/'")),
			"missing": git.ErrObjectNotFound,
		},
	}
	rep, err := Scan(context.Background(), objs, "HEAD", Options{})
	if err != nil {
		t.Fatal(err)
	}
	skipped := skippedReasons(rep)
	if !strings.Contains(skipped["bad"], "not readable") || !strings.Contains(skipped["gone"], "not readable") {
		t.Errorf("skipped %v", skipped)
	}
	if got := strings.Join(filePaths(rep), ","); got != "ok/Cargo.lock,ok/go.sum" {
		t.Errorf("files %s", got)
	}
}

// panicParser fails the way a buggy parser might.
type panicParser struct{}

func (panicParser) Type() string            { return "npm" }
func (panicParser) Format() string          { return "panic.lock" }
func (panicParser) Detect(path string) bool { return baseName(path) == "panic.lock" }
func (panicParser) Parse([]byte) (*Result, error) {
	var m map[string]int
	m["boom"]++
	return nil, nil
}

func TestScanSurvivesAPanickingParser(t *testing.T) {
	reg, err := NewRegistry(panicParser{}, cargoLock{})
	if err != nil {
		t.Fatal(err)
	}
	repo := newTestRepo(t)
	repo.write("x/panic.lock", []byte("anything"))
	repo.copyFixture("cargo-v4", "y")
	repo.commit()
	rep := repo.scan("HEAD", Options{Registry: reg})
	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].Path < rep.Files[j].Path })
	if len(rep.Files) != 2 || !strings.Contains(rep.Files[0].Error, "failed") || len(rep.Files[1].Dependencies) == 0 {
		t.Fatalf("files %+v", rep.Files)
	}
}

func TestNewRegistryRejectsDuplicates(t *testing.T) {
	if _, err := NewRegistry(cargoLock{}, cargoLock{}); err == nil {
		t.Error("two parsers of one format accepted")
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Error("a nil parser accepted")
	}
}
