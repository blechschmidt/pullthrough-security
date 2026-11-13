package watch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// gitRepo is a throwaway origin repository driven by the real git binary.
type gitRepo struct {
	t   *testing.T
	dir string
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	dir := t.TempDir()
	r := &gitRepo{t: t, dir: dir}
	r.git("init", "--quiet", "-b", "main")
	r.git("config", "user.email", "test@example.com")
	r.git("config", "user.name", "Test")
	r.git("config", "commit.gpgsign", "false")
	return r
}

func (r *gitRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (r *gitRepo) commit(file, content, msg string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, file), []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", file)
	r.git("commit", "--quiet", "-m", msg)
}

func newTestGitSource(t *testing.T) *GitSource {
	t.Helper()
	gs, err := NewGitSource(GitSourceOptions{Root: t.TempDir()})
	if err != nil {
		t.Fatalf("NewGitSource: %v", err)
	}
	return gs
}

func TestGitSourceIncremental(t *testing.T) {
	origin := newGitRepo(t)
	origin.commit("a.txt", "first\n", "add a")
	origin.commit("b.txt", "second\n", "add b")

	gs := newTestGitSource(t)
	repo := RepoRef{Name: "test", URL: origin.dir}
	ctx := context.Background()

	// First enumeration from scratch: both commits, oldest-first.
	batch, err := gs.NewCommits(ctx, repo, nil, nil, 100)
	if err != nil {
		t.Fatalf("NewCommits: %v", err)
	}
	if len(batch.Commits) != 2 {
		t.Fatalf("commits = %d, want 2", len(batch.Commits))
	}
	if batch.Commits[0].Subject() != "add a" || batch.Commits[1].Subject() != "add b" {
		t.Fatalf("order wrong: %q, %q", batch.Commits[0].Subject(), batch.Commits[1].Subject())
	}
	// The newest commit carried its file diff.
	last := batch.Commits[1]
	if len(last.Files) == 0 || last.Files[0].Path != "b.txt" {
		t.Fatalf("diff not parsed for b.txt: %+v", last.Files)
	}
	tip := batch.Tips["refs/heads/main"]
	if tip == "" {
		t.Fatalf("no tip recorded for refs/heads/main")
	}

	// Second enumeration with the cursor caught up: nothing new.
	batch2, err := gs.NewCommits(ctx, repo, batch.Tips, nil, 100)
	if err != nil {
		t.Fatalf("NewCommits 2: %v", err)
	}
	if len(batch2.Commits) != 0 {
		t.Fatalf("expected no new commits, got %d", len(batch2.Commits))
	}

	// A new commit upstream is picked up incrementally.
	origin.commit("c.txt", "third\n", "add c")
	batch3, err := gs.NewCommits(ctx, repo, batch.Tips, nil, 100)
	if err != nil {
		t.Fatalf("NewCommits 3: %v", err)
	}
	if len(batch3.Commits) != 1 || batch3.Commits[0].Subject() != "add c" {
		t.Fatalf("incremental enumeration wrong: %+v", batch3.Commits)
	}
}

func TestGitSourceBaselineSentinel(t *testing.T) {
	origin := newGitRepo(t)
	origin.commit("a.txt", "x\n", "a")
	origin.commit("b.txt", "y\n", "b")

	gs := newTestGitSource(t)
	repo := RepoRef{Name: "test", URL: origin.dir}

	batch, err := gs.NewCommits(context.Background(), repo, map[string]string{"__skip__": ""}, nil, 0)
	if err != nil {
		t.Fatalf("baseline NewCommits: %v", err)
	}
	if len(batch.Commits) != 0 {
		t.Fatalf("baseline returned %d commits, want 0", len(batch.Commits))
	}
	if batch.Tips["refs/heads/main"] == "" {
		t.Fatalf("baseline did not record tip")
	}
	if _, ok := batch.Tips["__skip__"]; ok {
		t.Fatalf("baseline leaked sentinel key")
	}
}

func TestGitSourceLimitTruncates(t *testing.T) {
	origin := newGitRepo(t)
	for _, m := range []string{"c1", "c2", "c3", "c4"} {
		origin.commit(m+".txt", m+"\n", m)
	}
	gs := newTestGitSource(t)
	repo := RepoRef{Name: "test", URL: origin.dir}

	batch, err := gs.NewCommits(context.Background(), repo, nil, nil, 2)
	if err != nil {
		t.Fatalf("NewCommits: %v", err)
	}
	if len(batch.Commits) != 2 {
		t.Fatalf("commits = %d, want 2 (limited)", len(batch.Commits))
	}
	if !batch.Truncated {
		t.Fatalf("expected truncated=true")
	}
	// The tip should advance only to the last scanned commit so the next cycle
	// resumes.
	resumeTip := batch.Tips["refs/heads/main"]
	if resumeTip == "" {
		t.Fatalf("no resume tip recorded")
	}
	batch2, err := gs.NewCommits(context.Background(), repo, batch.Tips, nil, 100)
	if err != nil {
		t.Fatalf("NewCommits resume: %v", err)
	}
	if len(batch2.Commits) != 2 {
		t.Fatalf("resume commits = %d, want 2", len(batch2.Commits))
	}
	if batch2.Commits[0].Subject() != "c3" {
		t.Fatalf("resume order wrong, first = %q want c3", batch2.Commits[0].Subject())
	}
}

func TestGitSourceWebhookHint(t *testing.T) {
	origin := newGitRepo(t)
	origin.commit("a.txt", "x\n", "a")
	first := trim(origin.git("rev-parse", "HEAD"))
	origin.commit("b.txt", "y\n", "b")
	second := trim(origin.git("rev-parse", "HEAD"))

	gs := newTestGitSource(t)
	repo := RepoRef{Name: "test", URL: origin.dir}

	// Prime the mirror so the pushed SHAs exist locally.
	if _, err := gs.NewCommits(context.Background(), repo, map[string]string{"__skip__": ""}, nil, 0); err != nil {
		t.Fatal(err)
	}

	hint := &UpdateHint{Refs: []RefUpdate{{Ref: "refs/heads/main", Before: first, After: second}}}
	batch, err := gs.NewCommits(context.Background(), repo, nil, hint, 100)
	if err != nil {
		t.Fatalf("NewCommits hint: %v", err)
	}
	if len(batch.Commits) != 1 || batch.Commits[0].Subject() != "b" {
		t.Fatalf("hint range wrong: %+v", batch.Commits)
	}
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func TestServiceEndToEndWithGitSource(t *testing.T) {
	origin := newGitRepo(t)
	origin.commit("a.txt", "x\n", "first")
	origin.commit("b.txt", "y\n", "second")

	gs := newTestGitSource(t)
	sc := newFakeScanner("sig-e2e")
	repo := RepoRef{Name: "e2e", URL: origin.dir}
	obs := &recordObserver{}
	svc, err := NewService(sc, gs, NewMemoryStateStore(), obs, Config{
		Repos:    []RepoRef{repo},
		Backfill: true,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// A polling sweep scans the two historical commits.
	svc.PollOnce(context.Background())
	if n := len(sc.scannedList()); n != 2 {
		t.Fatalf("scanned = %d, want 2", n)
	}
	if obs.count() != 2 {
		t.Fatalf("observer events = %d, want 2", obs.count())
	}

	// A second sweep with no upstream change scans nothing (cursor is caught up).
	before := len(sc.scannedList())
	svc.PollOnce(context.Background())
	if len(sc.scannedList()) != before {
		t.Fatalf("second sweep re-scanned commits: %d -> %d", before, len(sc.scannedList()))
	}

	// A new upstream commit is picked up on the next sweep.
	origin.commit("c.txt", "z\n", "third")
	svc.PollOnce(context.Background())
	if len(sc.scannedList()) != before+1 {
		t.Fatalf("incremental sweep scanned %d, want %d", len(sc.scannedList()), before+1)
	}

	// The scanned commit carried a parsed file diff through the whole pipeline.
	last := obs.events[len(obs.events)-1]
	if last.Commit.Subject() != "third" || len(last.Commit.Files) == 0 {
		t.Fatalf("end-to-end commit not fully built: subject=%q files=%d", last.Commit.Subject(), len(last.Commit.Files))
	}
}

// A refspec mirror (Task 180) lists every tag with the commit it resolves to —
// lightweight, annotated, a tag of a tag — and leaves out a tag of a tree. When
// the repository's URL changes, the mirror fetches from the new URL; a commit
// it was asked to keep survives the old tags being pruned.
func TestRefSnapshotOfARefspecMirror(t *testing.T) {
	origin := newGitRepo(t)
	origin.commit("a.txt", "a", "first")
	first := trim(origin.git("rev-parse", "HEAD"))
	origin.commit("a.txt", "b", "second")
	second := trim(origin.git("rev-parse", "HEAD"))
	origin.git("tag", "v1", first)
	origin.git("tag", "-a", "-m", "v2", "v2", second)
	origin.git("-c", "advice.nestedTag=false", "tag", "-a", "-m", "v3", "v3", "v2")
	origin.git("tag", "-a", "-m", "tree", "t-tree", trim(origin.git("rev-parse", "HEAD^{tree}")))

	gs, err := NewGitSource(GitSourceOptions{
		Root:             t.TempDir(),
		Refspecs:         []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"},
		AllowedProtocols: []string{"file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ref := RepoRef{Name: "widgets", URL: "file://" + origin.dir}
	snap, err := gs.RefSnapshot(ctx, ref, []string{"refs/tags/"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		commit    string
		annotated bool
	}{"refs/tags/v1": {first, false}, "refs/tags/v2": {second, true}, "refs/tags/v3": {second, true}}
	if len(snap) != len(want) {
		t.Fatalf("snapshot %+v", snap)
	}
	for name, w := range want {
		if tip := snap[name]; tip.Commit != w.commit || tip.Annotated != w.annotated {
			t.Fatalf("%s = %+v, want %s annotated=%v", name, tip, w.commit, w.annotated)
		}
	}
	if err := gs.KeepCommit(ctx, ref, first); err != nil {
		t.Fatal(err)
	}

	// The repository moves: the mirror follows the new URL.
	moved := newGitRepo(t)
	moved.commit("b.txt", "other", "elsewhere")
	other := trim(moved.git("rev-parse", "HEAD"))
	moved.git("tag", "v9", other)
	ref.URL = "file://" + moved.dir
	snap, err = gs.RefSnapshot(ctx, ref, []string{"refs/tags/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 1 || snap["refs/tags/v9"].Commit != other {
		t.Fatalf("snapshot after the move: %+v", snap)
	}
	if !gs.HasCommit(ctx, ref, first) {
		t.Fatal("a kept commit was lost when its tags were pruned")
	}
}
