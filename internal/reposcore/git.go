package reposcore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// gitEnv is appended to every git invocation: never prompt for credentials
// interactively (fail fast instead, so a misconfigured credential cannot hang a
// pull). It mirrors the safety posture of internal/git.
var gitEnv = []string{"GIT_TERMINAL_PROMPT=0"}

// gitRunner runs read-only git plumbing commands against a single local
// repository directory (a bare mirror, a partial blob:none clone, or an ordinary
// worktree — `git -C <dir>` autodetects which). It never mutates the repository
// and never contacts the network, so it is safe on an air-gapped host once the
// clone exists.
type gitRunner struct {
	gitBin string
	dir    string
}

// newGitRunner resolves the git binary and returns a runner bound to dir. It
// returns an error when git is not installed, so callers can degrade to an
// unresolved report rather than failing the pull.
func newGitRunner(gitBin, dir string) (*gitRunner, error) {
	if gitBin == "" {
		gitBin = "git"
	}
	resolved, err := exec.LookPath(gitBin)
	if err != nil {
		return nil, fmt.Errorf("reposcore: git binary %q not found: %w", gitBin, err)
	}
	if dir == "" {
		return nil, errors.New("reposcore: repository directory is required")
	}
	return &gitRunner{gitBin: resolved, dir: dir}, nil
}

// run executes a git subcommand against the bound directory, returning trimmed
// stdout. stderr is folded into the error so a diagnostic is never silently
// dropped, but never into the returned output (so it cannot corrupt a parsed
// stream).
func (g *gitRunner) run(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-C", g.dir}, args...)
	cmd := exec.CommandContext(ctx, g.gitBin, full...)
	cmd.Env = append(os.Environ(), gitEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

// lines runs a git subcommand and splits its output into non-empty lines.
func (g *gitRunner) lines(ctx context.Context, args ...string) ([]string, error) {
	out, err := g.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// headRef returns the symbolic name of the repository's default branch (the ref
// HEAD points at), used so file-tree lookups resolve against the right branch in
// a bare mirror.
func (g *gitRunner) headRef(ctx context.Context) (string, error) {
	// In a bare mirror HEAD is a symbolic ref to the default branch; resolving it
	// to a concrete commit confirms the repository has at least one commit.
	out, err := g.run(ctx, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}
