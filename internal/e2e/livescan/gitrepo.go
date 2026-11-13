//go:build integration || livellm

package livescan

import (
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// commitRepo is the repository of a git-commit sample: three commits on main.
type commitRepo struct {
	Sample *Sample
	// Bare is the bare repository the commit scanner watches.
	Bare string
	// Base, Benign and Malicious are the commit hashes: the repository before,
	// an ordinary change (the control), and the attacker's change on top.
	Base, Benign, Malicious string
}

// buildCommitRepo writes the sample's repository under dir. Dates are fixed,
// so the hashes are the same on every run.
func buildCommitRepo(dir string, s *Sample) (*commitRepo, error) {
	work := filepath.Join(dir, s.ID+"-work")
	// The repository is named as the real one is (owner/name.git), not by the
	// sample's id: the commit scan shows the model the repository's URL, and an
	// id such as "php-src-zerodium" would name the attack in the prompt.
	repo := &commitRepo{Sample: s, Bare: filepath.Join(dir, "repos", filepath.FromSlash(s.Commit.Repository)+".git")}
	if err := os.MkdirAll(filepath.Dir(repo.Bare), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	if _, err := gitRun(work, nil, "init", "--quiet", "--initial-branch=main"); err != nil {
		return nil, err
	}
	write := func(files map[string][]byte) error {
		for p, b := range files {
			full := filepath.Join(work, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(full, b, os.FileMode(fileMode(b))); err != nil {
				return err
			}
		}
		return nil
	}
	commit := func(date, author, message string) (string, error) {
		name, email := splitAuthor(author)
		env := []string{
			"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date,
			"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email,
			"GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + email,
		}
		if _, err := gitRun(work, env, "add", "-A"); err != nil {
			return "", err
		}
		if _, err := gitRun(work, env, "commit", "--quiet", "--allow-empty", "-m", message); err != nil {
			return "", err
		}
		return gitRun(work, nil, "rev-parse", "HEAD")
	}
	var err error
	if err = write(s.Shared); err != nil {
		return nil, err
	}
	if repo.Base, err = commit(s.Date+"T09:00:00Z", s.Commit.Author, s.Commit.BaseMessage); err != nil {
		return nil, err
	}
	if err = write(s.BenignOnly); err != nil {
		return nil, err
	}
	if repo.Benign, err = commit(s.Date+"T10:00:00Z", s.Commit.Author, s.Commit.BenignMessage); err != nil {
		return nil, err
	}
	if err = write(s.MaliciousOnly); err != nil {
		return nil, err
	}
	author := s.Commit.MaliciousAuthor
	if author == "" {
		author = s.Commit.Author
	}
	if repo.Malicious, err = commit(s.Date+"T11:00:00Z", author, s.Commit.MaliciousMessage); err != nil {
		return nil, err
	}
	if _, err := gitRun(dir, nil, "clone", "--quiet", "--bare", work, repo.Bare); err != nil {
		return nil, err
	}
	return repo, os.RemoveAll(work)
}

// splitAuthor splits "Name <email>"; an empty value gets a neutral identity.
func splitAuthor(s string) (name, email string) {
	if a, err := mail.ParseAddress(s); err == nil {
		return a.Name, a.Address
	}
	return "maintainer", "maintainer@example.invalid"
}

// gitEnv is the environment of every git command the suite runs: none of the
// developer's or the machine's configuration.
func gitEnv() []string {
	// Not the test process's environment: no git command of the suite needs a
	// credential, and a hook or helper a fixture managed to start must not find
	// one. (The corpus loader rejects .git components; this is the second wall.)
	return append(minimalEnv(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=livescan", "GIT_AUTHOR_EMAIL=livescan@example.invalid",
		"GIT_COMMITTER_NAME=livescan", "GIT_COMMITTER_EMAIL=livescan@example.invalid",
	)
}

func gitRun(dir string, extra []string, args ...string) (string, error) {
	// Hooks off: nothing a fixture contains may run during a commit.
	cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(), extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
