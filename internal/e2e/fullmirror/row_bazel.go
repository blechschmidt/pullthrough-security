//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Bazel: the adapter follows the Bazel Central Registry's Git repository,
// bazelbuild/bazel-central-registry, from which bcr.bazel.build is uploaded:
// a module version is the directory "modules/<name>/<version>/" — its
// MODULE.bazel, source.json and presubmit.yml — and the module's
// metadata.json lists its versions. The adapter diffs the trees of the head
// commits and reports each version whose directory changed; for each it reads
// the module's metadata.json and the version's source.json from the registry
// through the proxy, and has the mirror fetch the version's MODULE.bazel and
// its source archive at the proxy's own "/modules/<name>/<version>/archive"
// (the backend fetches the archive source.json names and checks it against
// source.json's integrity), with the patches and overlay files source.json
// lists — the stub's list none.
//
// The stub's Git repository is a real one served by `git http-backend` (feed
// option url, as for a registry other than the BCR). A publication is a
// commit adding the module's metadata.json, MODULE.bazel and source.json as
// the stub registry serves them, and a presubmit.yml as every version
// directory of the BCR holds one: one commit per module version, as the BCR
// merges one pull request per version. The adapter reports a commit once it
// has settled (feed option settle, by default ten minutes: bcr.bazel.build is
// uploaded after a push); the suite's commits are dated two hours back, so the
// row runs with the default, through the settle path, and every commit has
// settled when the mirror polls.
//
// A client asks for the archive at "…/archive/<file>", the name source.json's
// rewritten url carries; the mirror fetches the bare "…/archive" that
// repos/locate names. Both spellings are one cache entry in the backend, so
// the client's pull is served from what the mirror cached — and the full scan,
// which names an artifact by the path it was first fetched by, names the
// mirror's.

func init() {
	register(row{
		Type:    "bazel",
		Feed:    "Git repository (bazel-central-registry layout) over smart HTTP, `git http-backend`",
		Start:   bazelFeedStart,
		Publish: bazelPublish,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": bazelRepo(env).URL()}
		},
		Files: func(env *feedEnv, p publication) []file {
			return []file{{Path: bazelArchive(p)}, {Path: bazelVersionDir(p) + "/MODULE.bazel"}}
		},
		Refused: func(env *feedEnv, p publication) []string { return []string{bazelArchive(p)} },
		Resumed: func(env *feedEnv, _ []string) error { return gitHaveResumed(env, "bcr") },
		Notes: []string{
			"the mirror fetches each source archive as `/modules/<name>/<version>/archive`, a client as `…/archive/<file>`: one cache entry",
			"the stub's source.json lists no patches or overlay files: their fetch is not covered",
		},
	})
}

func bazelRepo(env *feedEnv) *gitRepo { return env.get("repo").(*gitRepo) }

func bazelFeedStart(env *feedEnv) error {
	fetches := newGitHaveLog(env, "bcr")
	repo, err := newGitRepo(env, "bcr")
	if err != nil {
		return err
	}
	env.set("repo", repo)
	env.set("fetches", fetches)
	registry, err := env.fetch("/bazel_registry.json")
	if err != nil {
		return err
	}
	if _, err := repo.commit("Initial registry", map[string][]byte{
		"bazel_registry.json": registry,
		"README.md":           []byte("# pullthrough full-mirror e2e: a Bazel registry laid out as bazel-central-registry\n"),
	}); err != nil {
		return err
	}
	return bazelPublish(env, env.Publications())
}

// bazelPublish commits each module version published, the way the BCR merges
// it: its directory and the module's metadata.json, as the registry serves
// them.
func bazelPublish(env *feedEnv, added []publication) error {
	repo := bazelRepo(env)
	for _, p := range added {
		dir := "modules/" + p.Pkg.Name
		files := map[string][]byte{}
		for _, name := range []string{"metadata.json", p.Pkg.Version + "/MODULE.bazel", p.Pkg.Version + "/source.json"} {
			body, err := env.fetch("/" + dir + "/" + name)
			if err != nil {
				return err
			}
			files[dir+"/"+name] = body
		}
		files[dir+"/"+p.Pkg.Version+"/presubmit.yml"] = []byte("matrix:\n  platform: [ubuntu2004]\n  bazel: [8.x]\n" +
			"tasks:\n  verify_targets:\n    name: Verify build targets\n    platform: ubuntu2004\n    bazel: 8.x\n" +
			"    build_targets:\n      - '@" + p.Pkg.Name + "//:defs.bzl'\n")
		if err := gitHaveCommit(env, repo, []publication{p}, fmt.Sprintf("Publish %s@%s", p.Pkg.Name, p.Pkg.Version), files); err != nil {
			return err
		}
	}
	return nil
}

func bazelVersionDir(p publication) string { return "/modules/" + p.Pkg.Name + "/" + p.Pkg.Version }

// bazelArchive is the source archive as the adapter names it.
func bazelArchive(p publication) string { return bazelVersionDir(p) + "/archive" }

// The Git-backed rows (this one, conan's and cargo's) check the restart in the
// Git protocol's own terms: the cursor is the commit whose trees the mirror
// holds, and a follower that continues from it fetches the new head naming
// that commit as one it has ("have"), where an enumeration asks for a snapshot
// of the head ("deepen 1", no have). The stub's request log shows a POST to
// git-upload-pack and nothing of its body, so the commands are recorded on
// their way to `git http-backend`.

// gitHaveLog records the protocol v2 fetch commands one repository of the
// stub receives.
type gitHaveLog struct {
	mu      sync.Mutex
	fetches [][]string // the argument lines of each fetch, in order
}

// newGitHaveLog installs the recorder of the repository newGitRepo(env,
// name) serves. Call it before newGitRepo: fallbacks are consulted in the
// order added, and the recorder passes every request on.
func newGitHaveLog(env *feedEnv, name string) *gitHaveLog {
	l := &gitHaveLog{}
	path := "/git/" + name + ".git/git-upload-pack"
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != path {
			return false
		}
		body, err := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil {
			return false
		}
		text := body
		if r.Header.Get("Content-Encoding") == "gzip" {
			if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
				text, _ = io.ReadAll(zr)
			}
		}
		if lines := gitHaveLines(text); len(lines) > 0 && lines[0] == "command=fetch" {
			l.mu.Lock()
			l.fetches = append(l.fetches, lines[1:])
			l.mu.Unlock()
		}
		return false
	})
	return l
}

// count is how many fetches were recorded.
func (l *gitHaveLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.fetches)
}

// since returns the fetches recorded after the first n.
func (l *gitHaveLog) since(n int) [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.fetches) {
		return nil
	}
	return append([][]string(nil), l.fetches[n:]...)
}

// gitHaveLines splits a pkt-line stream into its data lines, without their
// line feeds; flush, delimiter and response-end packets are dropped.
func gitHaveLines(b []byte) []string {
	var out []string
	for len(b) >= 4 {
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		if err != nil {
			return out
		}
		if n < 4 {
			b = b[4:]
			continue
		}
		if int(n) > len(b) {
			return out
		}
		out = append(out, strings.TrimSuffix(string(b[4:n]), "\n"))
		b = b[n:]
	}
	return out
}

// gitHaveCommit commits the files of the publications given and notes, for
// the late package, where the restarted mirror's fetches begin and which
// commits they must lead from and to.
func gitHaveCommit(env *feedEnv, repo *gitRepo, pubs []publication, message string, files map[string][]byte) error {
	held, _ := env.get("head").(string)
	commit, err := repo.commit(message, files)
	if err != nil {
		return err
	}
	late := false
	for _, p := range pubs {
		late = late || p.Variant == pkgLate
	}
	if late {
		env.set("resume", gitHaveMark{mark: env.get("fetches").(*gitHaveLog).count(), held: held, late: commit})
	}
	env.set("head", commit)
	return nil
}

// gitHaveMark is what a Git-backed row's Resumed check compares with.
type gitHaveMark struct {
	// mark is how many fetches the first proxy sent; held is the commit the
	// repository's head was at when it stopped (the cursor it stored), late
	// the commit of the package published while it was stopped.
	mark       int
	held, late string
}

// gitHaveResumed checks the restarted mirror's first fetch from the
// repository: it asks for the late package's commit and names the commit held
// before the restart as one it has, without asking for a snapshot.
func gitHaveResumed(env *feedEnv, name string) error {
	r, ok := env.get("resume").(gitHaveMark)
	if !ok {
		return fmt.Errorf("the late package was not committed to the %s repository", name)
	}
	fetches := env.get("fetches").(*gitHaveLog).since(r.mark)
	if len(fetches) == 0 {
		return fmt.Errorf("the restarted mirror fetched nothing from the %s repository", name)
	}
	first := fetches[0]
	has := map[string]bool{}
	for _, line := range first {
		if strings.HasPrefix(line, "deepen") {
			return fmt.Errorf("the restarted mirror's first fetch asked for a snapshot (%s), not for what followed commit %s", strings.Join(first, "; "), r.held)
		}
		has[line] = true
	}
	switch {
	case !has["have "+r.held]:
		return fmt.Errorf("the restarted mirror's first fetch does not continue from commit %s, the head it held (%s)", r.held, strings.Join(first, "; "))
	case !has["want "+r.late]:
		return fmt.Errorf("the restarted mirror's first fetch does not ask for commit %s, the late package's (%s)", r.late, strings.Join(first, "; "))
	}
	return nil
}
