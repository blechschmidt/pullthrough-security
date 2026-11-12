package git

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// objRepo is a throwaway repository built with the git binary.
type objRepo struct {
	t   *testing.T
	dir string
}

func newObjRepo(t *testing.T, args ...string) *objRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	r := &objRepo{t: t, dir: t.TempDir()}
	r.git(append([]string{"init", "--quiet", "--initial-branch=main"}, args...)...)
	r.git("config", "user.email", "t@example.com")
	r.git("config", "user.name", "T")
	r.git("config", "commit.gpgsign", "false")
	return r
}

func (r *objRepo) git(args ...string) string {
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

func (r *objRepo) write(rel, content string) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *objRepo) commit(msg string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "--quiet", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func openReader(t *testing.T, dir string) *ObjectReader {
	t.Helper()
	r, err := OpenObjectReader(dir, ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestObjectReaderWalksACommit(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			repo := newObjRepo(t, "--object-format="+format)
			repo.write("package-lock.json", `{"lockfileVersion": 3}`)
			repo.write("sub/dir/go.mod", "module example.com/m\n")
			repo.write("run.sh", "#!/bin/sh\n")
			if err := os.Chmod(filepath.Join(repo.dir, "run.sh"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("package-lock.json", filepath.Join(repo.dir, "link.json")); err != nil {
				t.Fatal(err)
			}
			first := repo.commit("first")
			repo.write("package-lock.json", `{"lockfileVersion": 2}`)
			repo.commit("second")

			r := openReader(t, repo.dir)
			commit, tree, err := r.ResolveCommit(context.Background(), first)
			if err != nil {
				t.Fatal(err)
			}
			if commit != first {
				t.Fatalf("commit = %s, want %s", commit, first)
			}
			wantHex := map[string]int{"sha1": 40, "sha256": 64}[format]
			if len(tree) != wantHex || r.HexLen() != wantHex {
				t.Fatalf("tree ID %q / HexLen %d, want %d hex digits", tree, r.HexLen(), wantHex)
			}
			entries, err := r.ReadTree(context.Background(), tree)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]TreeEntry{}
			var names []string
			for _, e := range entries {
				got[e.Name] = e
				names = append(names, e.Name)
			}
			if strings.Join(names, ",") != "link.json,package-lock.json,run.sh,sub" {
				t.Fatalf("entries %v", names)
			}
			for name, want := range map[string]EntryKind{"link.json": EntrySymlink, "package-lock.json": EntryFile, "run.sh": EntryFile, "sub": EntryTree} {
				if got[name].Kind != want {
					t.Errorf("%s kind = %v, want %v", name, got[name].Kind, want)
				}
			}
			if got["run.sh"].Mode != 0o100755 || got["package-lock.json"].Mode != 0o100644 {
				t.Errorf("modes %o / %o", got["run.sh"].Mode, got["package-lock.json"].Mode)
			}
			blob, err := r.ReadBlob(context.Background(), got["package-lock.json"].ID, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if string(blob) != `{"lockfileVersion": 3}` {
				t.Fatalf("blob = %q (the first commit's content, not the working tree's)", blob)
			}
			if _, err := r.ReadBlob(context.Background(), got["package-lock.json"].ID, 5); !errors.Is(err, ErrObjectTooLarge) {
				t.Fatalf("over-limit read: %v, want ErrObjectTooLarge", err)
			}
			// A refused read leaves the reader in step with git.
			if _, err := r.ReadTree(context.Background(), got["sub"].ID); err != nil {
				t.Fatalf("read after a refused read: %v", err)
			}
			if _, err := r.ReadTree(context.Background(), got["package-lock.json"].ID); !errors.Is(err, ErrObjectNotFound) {
				t.Fatalf("a blob read as a tree: %v", err)
			}
			if _, _, err := r.ResolveCommit(context.Background(), "no-such-branch"); !errors.Is(err, ErrObjectNotFound) {
				t.Fatalf("missing revision: %v", err)
			}
			info, err := r.Info(context.Background(), first+":sub/dir")
			if err != nil || info.Type != ObjectTree {
				t.Fatalf("subtree lookup: %+v, %v", info, err)
			}
		})
	}
}

func TestObjectReaderRejectsProtocolInjection(t *testing.T) {
	repo := newObjRepo(t)
	repo.write("a", "a")
	repo.commit("c")
	r := openReader(t, repo.dir)
	for _, name := range []string{"HEAD\ncontents HEAD", "HEAD\x00", "", "HEAD\r"} {
		if _, err := r.Info(context.Background(), name); err == nil {
			t.Errorf("Info(%q) succeeded", name)
		}
	}
	for _, id := range []string{"HEAD", strings.Repeat("A", 40), strings.Repeat("0", 39)} {
		if _, err := r.ReadBlob(context.Background(), id, 10); err == nil {
			t.Errorf("ReadBlob(%q) succeeded", id)
		}
	}
	// Still usable.
	if _, _, err := r.ResolveCommit(context.Background(), "HEAD"); err != nil {
		t.Fatal(err)
	}
}

func TestObjectReaderNotARepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	r, err := OpenObjectReader(t.TempDir(), ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, _, err = r.ResolveCommit(context.Background(), "HEAD")
	if err == nil || !strings.Contains(err.Error(), "not a git repository") {
		t.Fatalf("err = %v", err)
	}
	if _, err := OpenObjectReader(filepath.Join(t.TempDir(), "missing"), ObjectReaderOptions{}); err == nil {
		t.Fatal("opened a missing directory")
	}
}

func TestObjectReaderCancelledReadKillsTheProcess(t *testing.T) {
	repo := newObjRepo(t)
	repo.write("a", "a")
	repo.commit("c")
	r := openReader(t, repo.dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := r.ResolveCommit(ctx, "HEAD"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
	// A context that ends during an exchange leaves the reader closed.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel2()
	time.Sleep(time.Millisecond)
	_, _ = r.Info(ctx2, "HEAD")
	if _, err := r.Info(context.Background(), "HEAD"); err != nil {
		t.Fatalf("a context that had ended before the call must not break the reader: %v", err)
	}
}

func TestObjectReaderClosed(t *testing.T) {
	repo := newObjRepo(t)
	repo.write("a", "a")
	repo.commit("c")
	r, err := OpenObjectReader(repo.dir, ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Info(context.Background(), "HEAD"); !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("read after Close: %v", err)
	}
	_ = r.Close() // idempotent
}

func TestParseTree(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 20)
	entry := func(mode, name string) []byte {
		return append([]byte(mode+" "+name+"\x00"), hash...)
	}
	good := bytes.Join([][]byte{entry("100644", "a"), entry("40000", "d"), entry("160000", "m"), entry("120000", "s"), entry("100755", "x")}, nil)
	entries, err := parseTree(good, 20)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []EntryKind{EntryFile, EntryTree, EntrySubmodule, EntrySymlink, EntryFile}
	for i, e := range entries {
		if e.Kind != kinds[i] || e.ID != strings.Repeat("ab", 20) {
			t.Errorf("entry %d = %+v", i, e)
		}
	}
	bad := map[string][]byte{
		"slash in name":   entry("100644", "a/b"),
		"dot-dot":         entry("40000", ".."),
		"dot":             entry("40000", "."),
		"empty name":      entry("100644", ""),
		"short hash":      []byte("100644 a\x00abc"),
		"no NUL":          []byte("100644 a"),
		"non-octal mode":  entry("100648", "a"),
		"unknown mode":    entry("70000", "a"),
		"no mode":         entry("", "a"),
		"long mode":       entry("1000644", "a"),
		"trailing junk":   append(entry("100644", "a"), 'x'),
		"hash for sha256": entry("100644", "a")[:len(entry("100644", "a"))-1],
	}
	for name, data := range bad {
		if _, err := parseTree(data, 20); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := parseTree(good, 21); err == nil {
		t.Error("accepted a hash length of 21")
	}
	if e, err := parseTree(nil, 32); err != nil || len(e) != 0 {
		t.Errorf("empty tree: %v, %v", e, err)
	}
}

func TestRedactURLSecrets(t *testing.T) {
	in := "fatal: repository 'https://bob:hunter2@proxy.example.com/u/ptl1abcdefghijklmnopqrstuvwxyz234567abcdefg/v1/github/o/r.git/' not found"
	out := RedactURLSecrets(in)
	for _, secret := range []string{"hunter2", "bob:", "ptl1abc"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%q survived: %s", secret, out)
		}
	}
	if !strings.Contains(out, "https://***@proxy.example.com/u/<link>/v1/github/o/r.git/") {
		t.Fatalf("redacted text lost its shape: %s", out)
	}
}

func TestCloneForScan(t *testing.T) {
	src := newObjRepo(t)
	src.git("config", "uploadpack.allowFilter", "true")
	src.git("config", "uploadpack.allowAnySHA1InWant", "true")
	src.write("small.txt", "small\n")
	src.write("big.bin", strings.Repeat("x", 4096))
	first := src.commit("first")
	src.git("tag", "v1")
	src.write("small.txt", "changed\n")
	head := src.commit("second")
	url := "file://" + src.dir

	t.Run("default branch, big blob left out", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "clone.git")
		commit, err := CloneForScan(context.Background(), ScanCloneOptions{URL: url, Dir: dir, MaxBlobBytes: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if commit != head {
			t.Fatalf("commit %s, want %s", commit, head)
		}
		r := openReader(t, dir)
		_, tree, err := r.ResolveCommit(context.Background(), commit)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := r.ReadTree(context.Background(), tree)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			_, err := r.ReadBlob(context.Background(), e.ID, 1<<20)
			switch e.Name {
			case "small.txt":
				if err != nil {
					t.Errorf("small blob: %v", err)
				}
			case "big.bin":
				if !errors.Is(err, ErrObjectNotFound) {
					t.Errorf("big blob: %v, want it left out of the clone", err)
				}
			}
		}
	})
	for name, rev := range map[string]string{"tag": "v1", "commit": first, "abbreviated commit": first[:12], "branch": "main"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "clone.git")
			commit, err := CloneForScan(context.Background(), ScanCloneOptions{URL: url, Dir: dir, Rev: rev})
			if err != nil {
				t.Fatal(err)
			}
			want := first
			if rev == "main" {
				want = head
			}
			if commit != want {
				t.Fatalf("commit %s, want %s", commit, want)
			}
		})
	}
	t.Run("unknown revision", func(t *testing.T) {
		_, err := CloneForScan(context.Background(), ScanCloneOptions{URL: url, Dir: filepath.Join(t.TempDir(), "c"), Rev: "nope"})
		if err == nil {
			t.Fatal("cloned an unknown revision")
		}
	})
	for _, bad := range []string{"", "-oProxyCommand=x", "ext::sh -c touch% /tmp/pwned", "relative/path", "https://h/r\n"} {
		if _, err := CloneForScan(context.Background(), ScanCloneOptions{URL: bad, Dir: t.TempDir()}); err == nil {
			t.Errorf("accepted URL %q", bad)
		}
	}
	for _, bad := range []string{"--upload-pack=x", "a b", "a\nb"} {
		if _, err := CloneForScan(context.Background(), ScanCloneOptions{URL: url, Dir: filepath.Join(t.TempDir(), "c"), Rev: bad}); err == nil {
			t.Errorf("accepted revision %q", bad)
		}
	}
}

func TestLocateRepository(t *testing.T) {
	repo := newObjRepo(t)
	repo.write("a/b/c.txt", "x")
	repo.commit("c")
	got, err := LocateRepository(context.Background(), filepath.Join(repo.dir, "a", "b"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != "a/b" || !strings.HasSuffix(got.GitDir, ".git") {
		t.Fatalf("%+v", got)
	}
	top, err := LocateRepository(context.Background(), repo.dir, "")
	if err != nil || top.Prefix != "" {
		t.Fatalf("top: %+v, %v", top, err)
	}
	if _, err := LocateRepository(context.Background(), t.TempDir(), ""); err == nil {
		t.Fatal("a plain directory was taken for a repository")
	}
}

// TestMirrorOpenObjects reads a mirrored repository through the mirror's own
// directory, the way the lock-file scanner reads tracked repositories.
func TestMirrorOpenObjects(t *testing.T) {
	src := newObjRepo(t)
	src.write("go.mod", "module example.com/m\n")
	head := src.commit("c")

	m, err := NewMirror(MirrorOptions{Root: t.TempDir(), RefreshInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	up, err := NewUpstream(UpstreamOptions{Name: "gh", URL: "https://git.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	// A mirror already in place and fresh: Ensure serves it without fetching.
	dir := m.mirrorDir(up, "o/r")
	cmd := exec.Command("git", "clone", "--quiet", "--mirror", src.dir, dir)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m.markRefreshed(dir)

	r, err := m.OpenObjects(context.Background(), up, "/o/r/", ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	commit, _, err := r.ResolveCommit(context.Background(), "HEAD")
	if err != nil || commit != head {
		t.Fatalf("commit %s, %v; want %s", commit, err, head)
	}
	if _, err := m.OpenObjects(context.Background(), up, "../escape", ObjectReaderOptions{}); err == nil {
		t.Fatal("a traversing repository path was accepted")
	}
}

// TestCloneForScanHonoursItsContext: a server that accepts and never answers
// must not hold the caller past its deadline, nor leave git's helpers running.
func TestCloneForScanHonoursItsContext(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c) // never answered
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	}()
	url := "http://" + ln.Addr().String() + "/stall.git"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = CloneForScan(ctx, ScanCloneOptions{URL: url, Dir: filepath.Join(t.TempDir(), "c.git")})
	if err == nil {
		t.Fatal("a stalled fetch succeeded")
	}
	if d := time.Since(start); d > 2*time.Second+processWaitDelay+3*time.Second {
		t.Fatalf("CloneForScan returned %s after its 2s deadline", d)
	}
	out, _ := exec.Command("pgrep", "-f", ln.Addr().String()).Output()
	if pids := strings.TrimSpace(string(out)); pids != "" {
		t.Fatalf("git helpers still running for the stalled URL: %s", pids)
	}
}
