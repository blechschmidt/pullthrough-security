package repos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/git"
)

func TestTreeFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet")
	files := map[string]string{
		"package.json":                `{"name":"a"}`,
		"pkg/b/package.json":          `{"name":"b"}`,
		"node_modules/x/package.json": `{"name":"x"}`,
		"vendor/y/go.mod":             "module y\n",
		"big.bin":                     strings.Repeat("x", 4096),
		"pkg/b/src/main.rs":           "fn main() {}\n",
	}
	for p, c := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "pkg", "link.json")); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "--quiet", "-m", "x")
	commit := run("rev-parse", "HEAD")
	objs, err := git.OpenObjectReader(dir, git.ObjectReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	ctx := context.Background()

	got, err := ReadTreeFiles(ctx, objs, commit, []string{"package.json", "pkg/b/package.json", "pkg/link.json", "missing", "pkg", "../x"}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["pkg/b/package.json"]) != `{"name":"b"}` {
		t.Fatalf("read: %v", got)
	}
	if _, err := ReadTreeFiles(ctx, objs, commit, []string{"package.json", "big.bin"}, 1000); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the budget: %v", err)
	}
	list, err := ListTreeFiles(ctx, objs, commit, "", func(p string) bool { return filepath.Base(p) == "package.json" || filepath.Base(p) == "go.mod" }, 10)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(list, ",") != "package.json,pkg/b/package.json" {
		t.Fatalf("listed %v (vendored and installed trees must be skipped)", list)
	}
	list, _ = ListTreeFiles(ctx, objs, commit, "pkg", nil, 10)
	if strings.Join(list, ",") != "pkg/b/package.json,pkg/b/src/main.rs" {
		t.Fatalf("listed below pkg: %v (a symbolic link is no regular file)", list)
	}
	if list, _ := ListTreeFiles(ctx, objs, commit, "", nil, 1); len(list) != 2 {
		t.Fatalf("one more than max reports more: %v", list)
	}
}
