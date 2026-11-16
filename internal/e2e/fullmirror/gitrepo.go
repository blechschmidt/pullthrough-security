//go:build integration
// +build integration

package fullmirror

import (
	"fmt"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// gitRepo is a Git repository the stub registry serves over smart HTTP with
// the real `git http-backend`: the feed of a registry whose index is a Git
// repository (crates.io-index, bazel-central-registry, conan-center-index).
// The adapter's own Git client (protocol v2, a filtered fetch) talks to the
// server Git ships, not to a fake of it.
//
// Commits are made in a work tree of the suite's and pushed to the served
// bare repository. Every git command runs with an identity of the suite's and
// without the user's or the system's configuration: on CI the runner user has
// no identity configured (git refuses to commit without one), and a
// developer's configuration (signing, hooks, URL rewrites) has no business in
// the stub.
type gitRepo struct {
	name string
	bare string
	work string
	url  string

	mu      sync.Mutex
	commits int
}

// gitBackdate is how far back the suite dates its commits.
const gitBackdate = 2 * time.Hour

// gitIdentity is the author and committer of the suite's commits.
var gitIdentity = []string{
	"GIT_AUTHOR_NAME=pullthrough full-mirror e2e", "GIT_AUTHOR_EMAIL=fullmirror-e2e@example.invalid",
	"GIT_COMMITTER_NAME=pullthrough full-mirror e2e", "GIT_COMMITTER_EMAIL=fullmirror-e2e@example.invalid",
}

// gitEnv is the environment of every git command the suite runs: the
// process's, without what a surrounding git (a hook) set, without the user's
// and the system's configuration, with the suite's identity.
func gitEnv(extra ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	out = append(out, gitIdentity...)
	return append(out, extra...)
}

// runGit runs git in dir.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// newGitRepo creates an empty repository, served by the stub at
// <stub>/git/<name>.git with branch main.
func newGitRepo(env *feedEnv, name string) (*gitRepo, error) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("the Git-backed feeds need the git binary: %w", err)
	}
	root, err := env.mkdir("git-served")
	if err != nil {
		return nil, err
	}
	work, err := env.mkdir("git-work/" + name)
	if err != nil {
		return nil, err
	}
	g := &gitRepo{name: name, bare: filepath.Join(root, name+".git"), work: work, url: env.URL() + "/git/" + name + ".git"}
	for _, step := range [][]string{
		{"init", "--quiet", "--bare", "--initial-branch=main", g.bare},
		// The adapter fetches trees without blobs; the server must offer it.
		{"-C", g.bare, "config", "uploadpack.allowFilter", "true"},
		{"-C", g.bare, "config", "http.receivepack", "false"},
		{"init", "--quiet", "--initial-branch=main", g.work},
	} {
		if _, err := runGit(env.Dir, step...); err != nil {
			return nil, err
		}
	}
	backend := &cgi.Handler{
		Path: gitBin,
		Root: "/git",
		Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1"},
	}
	prefix := "/git/" + name + ".git/"
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			return false
		}
		backend.ServeHTTP(w, r)
		return true
	})
	return g, nil
}

// URL is the repository's URL, the feed option "url" of the adapter.
func (g *gitRepo) URL() string { return g.url }

// commit writes files (path → content; nil content removes the file) into the
// work tree, commits them and pushes the commit to the served repository.
func (g *gitRepo) commit(message string, files map[string][]byte) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		full := filepath.Join(g.work, filepath.FromSlash(p))
		if files[p] == nil {
			if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(full, files[p], 0o644); err != nil {
			return "", err
		}
	}
	if _, err := runGit(g.work, "add", "--all"); err != nil {
		return "", err
	}
	// Dated two hours back: the Git-backed feeds report a commit once it has
	// settled (feed option settle: Bazel 10m, Conan 1h by default), and every
	// commit of the suite has — so the rows run with the production defaults,
	// through the settle path, without waiting.
	when := time.Now().Add(-gitBackdate).UTC().Format(time.RFC3339)
	commit := exec.Command("git", "commit", "--quiet", "--allow-empty", "--no-gpg-sign", "-m", message)
	commit.Dir = g.work
	commit.Env = gitEnv("GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	if out, err := commit.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git commit: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if _, err := runGit(g.work, "push", "--quiet", g.bare, "HEAD:refs/heads/main"); err != nil {
		return "", err
	}
	g.commits++
	return runGit(g.work, "rev-parse", "HEAD")
}

// read returns a file of the work tree's head (nil when there is none).
func (g *gitRepo) read(path string) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(g.work, filepath.FromSlash(path)))
	if err != nil {
		return nil
	}
	return data
}
