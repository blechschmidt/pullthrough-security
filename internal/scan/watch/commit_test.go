package watch

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/gitsign"
)

// pushFixture is a repository as the maintenance updater sees it: a remote
// (a bare repository reached over file://) with a refspec mirror of it, as
// production keeps one, and a working repository the remote was cloned from.
type pushFixture struct {
	t      *testing.T
	origin *gitRepo
	remote string
	gs     *GitSource
	ref    RepoRef
	// base is the remote's main.
	base string
}

const testBranch = "pullthrough/update-main"

func newPushFixture(t *testing.T) *pushFixture {
	t.Helper()
	origin := newGitRepo(t)
	for path, file := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"package-lock.json":   {"{\"lockfileVersion\": 3}\n", 0o644},
		"services/api/go.mod": {"module api\n", 0o644},
		"services/api/go.sum": {"example.com/a v1.0.0 h1:old=\n", 0o644},
		"tools/run.sh":        {"#!/bin/sh\necho run\n", 0o755},
		"docs/readme.md":      {"# docs\n", 0o644},
	} {
		full := filepath.Join(origin.dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(file.content), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("docs/readme.md", filepath.Join(origin.dir, "link")); err != nil {
		t.Fatal(err)
	}
	origin.git("add", "-A")
	// A submodule: a gitlink entry (the commit it names need not exist here).
	origin.git("update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("ab", 20)+",vendor/sub")
	origin.git("commit", "--quiet", "-m", "initial")
	origin.git("tag", "-a", "-m", "release", "v1")

	remote := filepath.Join(t.TempDir(), "remote.git")
	runT(t, "", nil, "", "clone", "--bare", "--quiet", origin.dir, remote)

	gs, err := NewGitSource(GitSourceOptions{
		Root:             t.TempDir(),
		Refspecs:         []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"},
		AllowedProtocols: []string{"file", "http"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &pushFixture{t: t, origin: origin, remote: remote, gs: gs, ref: RepoRef{Name: "widgets", URL: "file://" + remote}}
	f.base = f.sync()
	return f
}

// sync refreshes the mirror and returns the remote's main.
func (f *pushFixture) sync() string {
	f.t.Helper()
	snap, err := f.gs.RefSnapshot(context.Background(), f.ref, []string{"refs/heads/"})
	if err != nil {
		f.t.Fatal(err)
	}
	main := snap["refs/heads/main"].Commit
	if main == "" {
		f.t.Fatalf("no main in %+v", snap)
	}
	return main
}

func (f *pushFixture) mirror(args ...string) string {
	f.t.Helper()
	return runT(f.t, f.gs.MirrorDir(f.ref), nil, "", args...)
}

func (f *pushFixture) remoteGit(args ...string) string {
	f.t.Helper()
	return runT(f.t, f.remote, nil, "", args...)
}

// remoteBranch is the remote's testBranch, read from the remote itself.
func (f *pushFixture) remoteBranch() string {
	f.t.Helper()
	cmd := exec.Command("git", "rev-parse", "--verify", "--quiet", "refs/heads/"+testBranch)
	cmd.Dir = f.remote
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

var testSig = Signature{Name: "Pullthrough", Email: "pullthrough@example.com", When: time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC)}

// build commits one change of go.sum on top of the base.
func (f *pushFixture) build(content string) string {
	f.t.Helper()
	commit, _, err := f.gs.BuildCommit(context.Background(), f.ref, CommitRequest{
		Base:    f.base,
		Files:   []FileChange{{Path: "services/api/go.sum", Content: []byte(content)}},
		Message: "Update go.sum",
		Author:  testSig, Committer: testSig,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return commit
}

// runT runs git in dir and fails the test when it fails.
func runT(t *testing.T, dir string, env []string, stdin string, args ...string) string {
	t.Helper()
	out, err := runGitT(dir, env, stdin, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func runGitT(dir string, env []string, stdin string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GIT_TERMINAL_PROMPT=0"), env...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// treeListing maps every path of a commit to "<mode> <object>".
func (f *pushFixture) treeListing(commit string) map[string]string {
	f.t.Helper()
	out := f.mirror("ls-tree", "-r", "-z", commit)
	m := map[string]string{}
	for _, rec := range strings.Split(out, "\x00") {
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta)
		m[path] = fields[0] + " " + fields[2]
	}
	return m
}

func TestBuildCommitWritesNestedChanges(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	refsBefore := f.mirror("for-each-ref")
	before := f.treeListing(f.base)

	commit, tree, err := f.gs.BuildCommit(ctx, f.ref, CommitRequest{
		Base: f.base,
		Files: []FileChange{
			{Path: "services/api/go.sum", Content: []byte("example.com/a v1.1.0 h1:new=\n")},
			{Path: "tools/run.sh", Content: []byte("#!/bin/sh\necho run v2\n")},
			{Path: "services/web/package-lock.json", Content: []byte("{}\n")},
			{Path: "new/deep/dir/Cargo.lock", Content: []byte("version = 3\n")},
			{Path: "empty.lock", Content: nil},
		},
		Message: "Update lock files",
		Author:  testSig, Committer: testSig,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotTree, parents, err := f.gs.CommitInfo(ctx, f.ref, commit)
	if err != nil {
		t.Fatal(err)
	}
	if gotTree != tree || len(parents) != 1 || parents[0] != f.base {
		t.Fatalf("commit info: tree %s parents %v; want tree %s parent %s", gotTree, parents, tree, f.base)
	}

	after := f.treeListing(commit)
	for path, want := range map[string]string{
		"services/api/go.sum":            "100644 example.com/a v1.1.0 h1:new=\n",
		"tools/run.sh":                   "100755 #!/bin/sh\necho run v2\n",
		"services/web/package-lock.json": "100644 {}\n",
		"new/deep/dir/Cargo.lock":        "100644 version = 3\n",
		"empty.lock":                     "100644 ",
	} {
		mode, content, _ := strings.Cut(want, " ")
		got := after[path]
		if !strings.HasPrefix(got, mode+" ") {
			t.Fatalf("%s is %q, want mode %s", path, got, mode)
		}
		if blob := f.mirror("cat-file", "blob", strings.Fields(got)[1]); blob != content {
			t.Fatalf("%s holds %q, want %q", path, blob, content)
		}
	}
	// Everything else is untouched: the same entries, the same objects.
	for _, path := range []string{"package-lock.json", "services/api/go.mod", "docs/readme.md", "link", "vendor/sub"} {
		if after[path] != before[path] {
			t.Fatalf("%s changed: %q -> %q", path, before[path], after[path])
		}
	}
	if len(after) != len(before)+3 {
		t.Fatalf("%d paths after, %d before", len(after), len(before))
	}
	if a, b := f.mirror("rev-parse", commit+":docs"), f.mirror("rev-parse", f.base+":docs"); a != b {
		t.Fatal("an untouched directory was rewritten")
	}
	// Objects only: not a ref of the mirror moved.
	if refs := f.mirror("for-each-ref"); refs != refsBefore {
		t.Fatalf("refs changed:\n%s\n->\n%s", refsBefore, refs)
	}
	f.mirror("fsck", "--strict", "--no-progress")
}

func TestBuildCommitLeavingTheTreeUnchanged(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	baseTree := strings.TrimSpace(f.mirror("rev-parse", f.base+"^{tree}"))
	for _, files := range [][]FileChange{
		nil,
		{{Path: "services/api/go.sum", Content: []byte("example.com/a v1.0.0 h1:old=\n")}, {Path: "tools/run.sh", Content: []byte("#!/bin/sh\necho run\n")}},
	} {
		commit, tree, err := f.gs.BuildCommit(ctx, f.ref, CommitRequest{Base: f.base, Files: files, Message: "Nothing", Author: testSig, Committer: testSig})
		if err != nil {
			t.Fatal(err)
		}
		if tree != baseTree {
			t.Fatalf("tree %s, want the base's %s", tree, baseTree)
		}
		if gotTree, parents, err := f.gs.CommitInfo(ctx, f.ref, commit); err != nil || gotTree != baseTree || len(parents) != 1 || parents[0] != f.base {
			t.Fatalf("commit %s: tree %s parents %v err %v", commit, gotTree, parents, err)
		}
	}
}

// The commit object is what git commit-tree writes from the same tree, parent,
// identities (git trims the same characters off their ends) and message.
func TestBuildCommitIsWhatGitCommitTreeWrites(t *testing.T) {
	f := newPushFixture(t)
	author := Signature{Name: ` "Pullthrough Bot", `, Email: " bot@example.com ", When: time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("", 5*3600+30*60))}
	committer := Signature{Name: "Ünïcode Maintainer", Email: "m@example.com", When: time.Date(2026, 11, 13, 11, 0, 0, 0, time.FixedZone("", -7*3600))}
	msg := "Update lock files\n\nBumps example.com/a from 1.0.0 to 1.1.0."
	commit, tree, err := f.gs.BuildCommit(context.Background(), f.ref, CommitRequest{
		Base:    f.base,
		Files:   []FileChange{{Path: "services/api/go.sum", Content: []byte("x\n")}},
		Message: msg, Author: author, Committer: committer,
	})
	if err != nil {
		t.Fatal(err)
	}
	gitDate := func(s Signature, zone string) string { return fmt.Sprintf("%d %s", s.When.Unix(), zone) }
	got := strings.TrimSpace(runT(t, f.gs.MirrorDir(f.ref), []string{
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=" + author.Name, "GIT_AUTHOR_EMAIL=" + author.Email, "GIT_AUTHOR_DATE=" + gitDate(author, "+0530"),
		"GIT_COMMITTER_NAME=" + committer.Name, "GIT_COMMITTER_EMAIL=" + committer.Email, "GIT_COMMITTER_DATE=" + gitDate(committer, "-0700"),
	}, "", "commit-tree", "--no-gpg-sign", tree, "-p", f.base, "-m", msg))
	if got != commit {
		t.Fatalf("git commit-tree wrote %s, BuildCommit %s:\n%s\n---\n%s", got, commit,
			f.mirror("cat-file", "commit", got), f.mirror("cat-file", "commit", commit))
	}
}

func TestBuildCommitRefusals(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	objectsBefore := f.mirror("count-objects")
	tag := strings.TrimSpace(f.mirror("rev-parse", "refs/tags/v1"))
	tree := strings.TrimSpace(f.mirror("rev-parse", f.base+"^{tree}"))
	req := func(paths ...string) CommitRequest {
		r := CommitRequest{Base: f.base, Message: "m", Author: testSig, Committer: testSig}
		for _, p := range paths {
			r.Files = append(r.Files, FileChange{Path: p, Content: []byte("x")})
		}
		return r
	}
	for _, tc := range []struct {
		name string
		req  CommitRequest
		want string
	}{
		{"empty path", req(""), "empty file path"},
		{"absolute", req("/etc/passwd"), "absolute"},
		{"empty component", req("a//b"), "empty component"},
		{"trailing slash", req("a/"), "empty component"},
		{"dot-dot", req("../x"), `".." component`},
		{"inner dot-dot", req("a/../b"), `".." component`},
		{"dot", req("./a"), `"." component`},
		{".git", req(".git/config"), ".git"},
		{".GIT inside", req("a/.GIT/hooks/pre-commit"), ".git"},
		{".git file", req("sub/.git"), ".git"},
		{"NTFS trailing dot", req("a/.git./x"), ".git"},
		{"NTFS trailing space", req(".git /x"), ".git"},
		{"NTFS short name", req("GIT~1/config"), ".git"},
		{"NTFS stream", req(".git::$INDEX_ALLOCATION/x"), ".git"},
		{"HFS ignorable", req(".g\u200cit/config"), ".git"},
		{"backslash", req(`a\b`), "backslash"},
		{"newline", req("a\nb"), "control character"},
		{"NUL", req("a\x00b"), "control character"},
		{"invalid UTF-8", req("a\xffb"), "UTF-8"},
		{"twice", req("a.txt", "a.txt"), "twice"},
		{"file then directory", req("a", "a/b"), "both a file and a directory"},
		{"directory then file", req("a/b", "a"), "both a file and a directory"},
		{"replaces a directory", req("docs"), "is a directory in the base commit"},
		{"replaces a symlink", req("link"), "is a symbolic link in the base commit"},
		{"replaces a submodule", req("vendor/sub"), "is a submodule in the base commit"},
		{"through a file", req("docs/readme.md/x"), "docs/readme.md is a file in the base commit, not a directory"},
		{"through a symlink", req("link/x"), "link is a symbolic link in the base commit, not a directory"},
		{"through a submodule", req("vendor/sub/x"), "vendor/sub is a submodule in the base commit, not a directory"},
		{"base not an ID", CommitRequest{Base: "main", Message: "m", Author: testSig, Committer: testSig}, "not a commit ID"},
		{"unknown base", CommitRequest{Base: strings.Repeat("0", 40), Message: "m", Author: testSig, Committer: testSig}, "not found"},
		{"tree as base", CommitRequest{Base: tree, Message: "m", Author: testSig, Committer: testSig}, "not found"},
		{"tag as base", CommitRequest{Base: tag, Message: "m", Author: testSig, Committer: testSig}, "is not a commit"},
		{"empty message", CommitRequest{Base: f.base, Message: " \n", Author: testSig, Committer: testSig}, "message is empty"},
		{"NUL in message", CommitRequest{Base: f.base, Message: "a\x00b", Author: testSig, Committer: testSig}, "NUL"},
		{"invalid UTF-8 message", CommitRequest{Base: f.base, Message: "a\xff", Author: testSig, Committer: testSig}, "UTF-8"},
		{"angle bracket in name", CommitRequest{Base: f.base, Message: "m", Author: Signature{Name: "a<b", Email: "e@x"}, Committer: testSig}, "author name"},
		{"newline in email", CommitRequest{Base: f.base, Message: "m", Author: testSig, Committer: Signature{Name: "n", Email: "e@x\ncommitter evil"}}, "committer email"},
		{"name of crud only", CommitRequest{Base: f.base, Message: "m", Author: Signature{Name: ` ,"; `, Email: "e@x"}, Committer: testSig}, "author name is empty"},
		{"no email", CommitRequest{Base: f.base, Message: "m", Author: Signature{Name: "n"}, Committer: testSig}, "author email is empty"},
		{"before 1970", CommitRequest{Base: f.base, Message: "m", Author: Signature{Name: "n", Email: "e@x", When: time.Unix(-1, 0)}, Committer: testSig}, "before 1970"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := f.gs.BuildCommit(ctx, f.ref, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
	// Every refusal came before anything was written.
	if after := f.mirror("count-objects"); after != objectsBefore {
		t.Fatalf("objects were written: %s -> %s", objectsBefore, after)
	}
	if _, _, err := f.gs.BuildCommit(ctx, RepoRef{Name: "unknown", URL: f.ref.URL}, req("a")); err == nil || !strings.Contains(err.Error(), "not there yet") {
		t.Fatalf("a repository without a mirror: %v", err)
	}
}

func TestCommitInfo(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	if tree, parents, err := f.gs.CommitInfo(ctx, f.ref, f.base); err != nil || tree == "" || len(parents) != 0 {
		t.Fatalf("root commit: tree %q parents %v err %v", tree, parents, err)
	}
	// A merge commit lists both parents, in order.
	f.origin.git("checkout", "--quiet", "-b", "side")
	f.origin.commit("side.txt", "side\n", "side")
	side := trim(f.origin.git("rev-parse", "HEAD"))
	f.origin.git("checkout", "--quiet", "main")
	f.origin.commit("main.txt", "main\n", "main")
	first := trim(f.origin.git("rev-parse", "HEAD"))
	f.origin.git("merge", "--quiet", "--no-ff", "-m", "merge", "side")
	merge := trim(f.origin.git("rev-parse", "HEAD"))
	f.origin.git("push", "--quiet", f.remote, "main", "side")
	f.sync()
	_, parents, err := f.gs.CommitInfo(ctx, f.ref, merge)
	if err != nil || len(parents) != 2 || parents[0] != first || parents[1] != side {
		t.Fatalf("merge parents %v err %v; want %s %s", parents, err, first, side)
	}
	if _, _, err := f.gs.CommitInfo(ctx, f.ref, strings.Repeat("0", 40)); !errors.Is(err, git.ErrObjectNotFound) {
		t.Fatalf("missing commit: %v", err)
	}
	tree := strings.TrimSpace(f.mirror("rev-parse", f.base+"^{tree}"))
	if _, _, err := f.gs.CommitInfo(ctx, f.ref, tree); !errors.Is(err, git.ErrObjectNotFound) || !strings.Contains(err.Error(), "is a tree") {
		t.Fatalf("a tree: %v", err)
	}
	if _, _, err := f.gs.CommitInfo(ctx, f.ref, "HEAD"); err == nil {
		t.Fatal("a revision expression was accepted")
	}
}

func TestPushBranchCreatesUpdatesAndHoldsTheLease(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	refsBefore := f.mirror("for-each-ref")

	if got, err := f.gs.RemoteBranch(ctx, f.ref, testBranch); err != nil || got != "" {
		t.Fatalf("branch before the first push: %q %v", got, err)
	}
	c1 := f.build("v1\n")
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c1, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := f.gs.RemoteBranch(ctx, f.ref, testBranch); err != nil || got != c1 || f.remoteBranch() != c1 {
		t.Fatalf("after creating: %q %v (remote %s), want %s", got, err, f.remoteBranch(), c1)
	}
	// The push left the mirror's refs alone: the branch arrives with the next
	// refresh, like any other.
	if refs := f.mirror("for-each-ref"); refs != refsBefore {
		t.Fatalf("the push moved refs of the mirror:\n%s", refs)
	}
	// A branch already at the commit is success, whatever the lease.
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c1, c1); err != nil {
		t.Fatal(err)
	}
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c1, ""); err != nil {
		t.Fatal(err)
	}

	// An update with the right lease replaces the branch (not a fast-forward:
	// both commits sit on the base).
	c2 := f.build("v2\n")
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c2, c1); err != nil {
		t.Fatal(err)
	}
	if f.remoteBranch() != c2 {
		t.Fatalf("remote at %s, want %s", f.remoteBranch(), c2)
	}

	// Somebody else pushes to the branch: the lease no longer holds.
	f.origin.commit("theirs.txt", "theirs\n", "a human's change")
	theirs := trim(f.origin.git("rev-parse", "HEAD"))
	f.origin.git("push", "--quiet", "--force", f.remote, "HEAD:refs/heads/"+testBranch)
	c3 := f.build("v3\n")
	err := f.gs.PushBranch(ctx, f.ref, testBranch, c3, c2)
	if !errors.Is(err, ErrLeaseRejected) || errors.Is(err, ErrPushRejected) {
		t.Fatalf("stale lease: %v", err)
	}
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c3, ""); !errors.Is(err, ErrLeaseRejected) {
		t.Fatalf("expecting absence of a branch that exists: %v", err)
	}
	if f.remoteBranch() != theirs {
		t.Fatalf("the other push was overwritten: remote at %s", f.remoteBranch())
	}

	// The branch is deleted: a lease on its old commit fails, absence holds.
	f.remoteGit("update-ref", "-d", "refs/heads/"+testBranch)
	if got, err := f.gs.RemoteBranch(ctx, f.ref, testBranch); err != nil || got != "" {
		t.Fatalf("deleted branch: %q %v", got, err)
	}
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c3, theirs); !errors.Is(err, ErrLeaseRejected) {
		t.Fatalf("lease on a deleted branch: %v", err)
	}
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c3, ""); err != nil {
		t.Fatal(err)
	}
	if f.remoteBranch() != c3 {
		t.Fatalf("remote at %s, want %s", f.remoteBranch(), c3)
	}
}

// The push sends the branch and nothing else, and runs no hook of this side —
// whatever the host's git configuration asks for.
func TestPushBranchSendsNoTagsAndRunsNoHooks(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	c1 := f.build("v1\n")
	mirror := f.gs.MirrorDir(f.ref)
	f.mirror("config", "push.followTags", "true")
	// An annotated tag needs a tagger: CI runners have no git identity.
	f.mirror("-c", "user.name=Local Tagger", "-c", "user.email=tagger@example.invalid", "tag", "-a", "-m", "local", "local-tag", c1)
	marker := filepath.Join(t.TempDir(), "hook-ran")
	hook := filepath.Join(mirror, "hooks", "pre-push")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the pre-push hook ran")
	}
	if tags := f.remoteGit("tag", "--list"); strings.Contains(tags, "local-tag") {
		t.Fatalf("a tag was pushed: %s", tags)
	}
	if refs := f.remoteGit("for-each-ref", "--format=%(refname)"); strings.Count(refs, "\n") != 3 {
		t.Fatalf("remote refs:\n%s", refs) // main, the maintenance branch, v1
	}
}

// What the remote itself refuses: a hook that declines is a rejection; a
// branch that moved while the push was under way is a lease that failed. A
// remote's words never carry the repository's token into the error.
func TestPushBranchRemoteRejections(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	f.ref.Token = "s3cr3t-token-value"
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + f.ref.Token))
	hook := filepath.Join(f.remote, "hooks", "pre-receive")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	c1 := f.build("v1\n")

	declining := "#!/bin/sh\necho 'protected branch; token=" + f.ref.Token + " auth=" + basic + "' >&2\nprintf '\\033[31mred\\033[0m\\n' >&2\nexit 1\n"
	if err := os.WriteFile(hook, []byte(declining), 0o755); err != nil {
		t.Fatal(err)
	}
	err := f.gs.PushBranch(ctx, f.ref, testBranch, c1, "")
	if !errors.Is(err, ErrPushRejected) || errors.Is(err, ErrLeaseRejected) {
		t.Fatalf("declined push: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "pre-receive hook declined") || !strings.Contains(msg, "protected branch") {
		t.Fatalf("the remote's reason is missing: %v", err)
	}
	if strings.Contains(msg, f.ref.Token) || strings.Contains(msg, basic) || strings.Contains(msg, "\033") {
		t.Fatalf("the error carries a secret or a terminal escape: %q", msg)
	}

	// The hook moves the branch, as a concurrent push would, before the
	// remote updates it: the remote's compare-and-swap fails.
	moving := "#!/bin/sh\nunset GIT_QUARANTINE_PATH\ngit update-ref refs/heads/" + testBranch + " " + f.base + "\nexit 0\n"
	if err := os.WriteFile(hook, []byte(moving), 0o755); err != nil {
		t.Fatal(err)
	}
	err = f.gs.PushBranch(ctx, f.ref, testBranch, c1, "")
	if !errors.Is(err, ErrLeaseRejected) {
		t.Fatalf("a branch moved during the push: %v", err)
	}
	if f.remoteBranch() != f.base {
		t.Fatalf("remote at %s", f.remoteBranch())
	}
}

// Credentials reach an HTTPS remote in the Authorization header git sends
// (from the environment), and never come back in an error.
func TestPushBranchSendsCredentialsOverHTTP(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	c1 := f.build("v1\n")
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Query().Get("service")+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(w, "denied for "+r.Header.Get("Authorization"), http.StatusForbidden)
	}))
	defer srv.Close()
	ref := f.ref
	ref.URL = srv.URL + "/widgets.git"
	ref.Token = "tok-0123456789"
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + ref.Token))

	_, lsErr := f.gs.RemoteBranch(ctx, ref, testBranch)
	pushErr := f.gs.PushBranch(ctx, ref, testBranch, c1, "")
	for _, err := range []error{lsErr, pushErr} {
		if err == nil {
			t.Fatal("a refused request succeeded")
		}
		if errors.Is(err, ErrPushRejected) || errors.Is(err, ErrLeaseRejected) {
			t.Fatalf("refused credentials are not a rejection of the push: %v", err)
		}
		if strings.Contains(err.Error(), ref.Token) || strings.Contains(err.Error(), basic) {
			t.Fatalf("the error carries the credentials: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]bool{"git-upload-pack Basic " + basic: false, "git-receive-pack Basic " + basic: false}
	for _, s := range seen {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, ok := range want {
		if !ok {
			t.Fatalf("the server never saw %q; it saw %q", s, seen)
		}
	}
}

func TestPushBranchValidation(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	c1 := f.build("v1\n")
	for _, b := range []string{"", "-x", "a..b", "a//b", ".hidden", "a/.b", "a.lock", "a.lock/b", "a.", "a/", "a b", "a~1", "a^", "a:b", "a@{1}", "a*", `a\b`, "a\nb"} {
		if err := f.gs.PushBranch(ctx, f.ref, b, c1, ""); err == nil || !strings.Contains(err.Error(), "not a branch name") {
			t.Fatalf("branch %q: %v", b, err)
		}
		if _, err := f.gs.RemoteBranch(ctx, f.ref, b); err == nil {
			t.Fatalf("branch %q was asked for", b)
		}
	}
	for _, tc := range []struct{ commit, expect, want string }{
		{"HEAD", "", "not a commit ID"},
		{c1[:12], "", "not a commit ID"},
		{c1, "main", "lease"},
		{strings.Repeat("0", 40), "", "not in the mirror"},
	} {
		if err := f.gs.PushBranch(ctx, f.ref, testBranch, tc.commit, tc.expect); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("push %q lease %q: %v", tc.commit, tc.expect, err)
		}
	}
	for _, url := range []string{"ext::sh -c touch% /tmp/pwned", "-uhelper", ""} {
		ref := f.ref
		ref.URL = url
		if err := f.gs.PushBranch(ctx, ref, testBranch, c1, ""); err == nil {
			t.Fatalf("URL %q was pushed to", url)
		}
	}
	if f.remoteBranch() != "" {
		t.Fatal("a refused push reached the remote")
	}
}

// A signed commit verifies with git's own verify-commit (gpg.format=ssh), and
// the signature covers exactly the unsigned commit: a tampered copy fails.
func TestSignedCommitVerifiesWithGit(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	f := newPushFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing-key")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "bot", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gitsign.NewSSHSigner(pemBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(allowed, []byte("pullthrough@example.com "+signer.PublicKey()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := CommitRequest{
		Base:    f.base,
		Files:   []FileChange{{Path: "services/api/go.sum", Content: []byte("signed\n")}},
		Message: "Update go.sum\n\nSigned by the proxy.\n",
		Author:  testSig, Committer: testSig,
	}
	unsigned, _, err := f.gs.BuildCommit(ctx, f.ref, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Signer = signer
	signed, _, err := f.gs.BuildCommit(ctx, f.ref, req)
	if err != nil {
		t.Fatal(err)
	}

	mirror := f.gs.MirrorDir(f.ref)
	verify := func(commit string) (string, error) {
		return runGitT(mirror, nil, "", "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "-v", commit)
	}
	out, err := verify(signed)
	if err != nil {
		t.Fatalf("git verify-commit: %v\n%s", err, out)
	}
	if !strings.Contains(out, `Good "git" signature for pullthrough@example.com`) || !strings.Contains(out, signer.Fingerprint()) {
		t.Fatalf("verify-commit said:\n%s", out)
	}

	// The signed commit is the unsigned one plus a gpgsig header after the
	// committer: git's payload, which is what was signed.
	raw := f.mirror("cat-file", "commit", signed)
	head, body, _ := strings.Cut(raw, "\n\n")
	var kept []string
	inSig := false
	for _, l := range strings.Split(head, "\n") {
		switch {
		case strings.HasPrefix(l, "gpgsig "):
			inSig = true
		case inSig && strings.HasPrefix(l, " "):
		default:
			inSig = false
			kept = append(kept, l)
		}
	}
	if stripped := strings.Join(kept, "\n") + "\n\n" + body; stripped != f.mirror("cat-file", "commit", unsigned) {
		t.Fatalf("the signed commit without its signature is not the unsigned commit:\n%s", raw)
	}

	tampered := strings.Replace(raw, "Signed by the proxy.", "Signed by somebody else.", 1)
	forged := strings.TrimSpace(runT(t, mirror, nil, tampered, "hash-object", "-t", "commit", "-w", "--stdin"))
	if out, err := verify(forged); err == nil {
		t.Fatalf("a tampered commit verified:\n%s", out)
	}
	if out, err := verify(unsigned); err == nil {
		t.Fatalf("an unsigned commit verified:\n%s", out)
	}

	// The signed commit travels as it is.
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, signed, ""); err != nil {
		t.Fatal(err)
	}
	if out, err := runGitT(f.remote, nil, "", "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "refs/heads/"+testBranch); err != nil {
		t.Fatalf("verify-commit on the remote: %v\n%s", err, out)
	}
}

func TestPushStatusParsing(t *testing.T) {
	out := "To file:///tmp/r.git\n" +
		"!\tabc:refs/heads/other\t[rejected] (stale info)\n" +
		"!\tdef:refs/heads/b\t[remote rejected] (protected branch hook declined (see docs))\n" +
		"Done\n"
	st, ok := pushStatusOf([]byte(out), "refs/heads/b")
	if !ok || st.flag != '!' || st.summary != "[remote rejected]" || st.reason != "protected branch hook declined (see docs)" {
		t.Fatalf("%+v %v", st, ok)
	}
	if _, ok := pushStatusOf([]byte(out), "refs/heads/c"); ok {
		t.Fatal("found a ref that is not there")
	}
	st, ok = pushStatusOf([]byte("*\tabc:refs/heads/b\t[new branch]\n"), "refs/heads/b")
	if !ok || !st.accepted() || st.summary != "[new branch]" {
		t.Fatalf("%+v %v", st, ok)
	}
}

func TestRemoteTextRedactsAndCleans(t *testing.T) {
	ref := RepoRef{Token: "tok-abcdef", Username: "bot"}
	basic := base64.StdEncoding.EncodeToString([]byte("bot:tok-abcdef"))
	got := remoteText(ref, "remote: fatal https://bot:pw@example.com/x tok-abcdef "+basic+"   \n\x1b[2Kremote:   \nremote: second line\n")
	for _, bad := range []string{"tok-abcdef", basic, "pw@", "\x1b"} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q survived in %q", bad, got)
		}
	}
	if !strings.Contains(got, "second line") || strings.Contains(got, "\n") {
		t.Fatalf("cleaned text %q", got)
	}
	if long := cleanText(strings.Repeat("é", 1000)); len(long) > 610 || !strings.HasSuffix(long, "…") {
		t.Fatalf("long text kept %d bytes", len(long))
	}
}

// TestDeleteBranchWithLease deletes a branch only while it is at the lease.
func TestDeleteBranchWithLease(t *testing.T) {
	f := newPushFixture(t)
	ctx := context.Background()
	c1 := f.build("v1\n")
	if err := f.gs.PushBranch(ctx, f.ref, testBranch, c1, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.gs.DeleteBranch(ctx, f.ref, testBranch, f.base); !errors.Is(err, ErrLeaseRejected) {
		t.Fatalf("a delete against a stale lease: %v", err)
	}
	if f.remoteBranch() != c1 {
		t.Fatalf("the branch moved to %q", f.remoteBranch())
	}
	if err := f.gs.DeleteBranch(ctx, f.ref, testBranch, c1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := f.gs.RemoteBranch(ctx, f.ref, testBranch); got != "" || f.remoteBranch() != "" {
		t.Fatalf("the branch is still at %q", got)
	}
	if err := f.gs.DeleteBranch(ctx, f.ref, testBranch, c1); err != nil {
		t.Fatalf("deleting a branch that is gone: %v", err)
	}
	if err := f.gs.DeleteBranch(ctx, f.ref, "-x", c1); err == nil {
		t.Fatal("an option-like branch name was accepted")
	}
}
