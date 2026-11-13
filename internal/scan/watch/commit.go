package watch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/git"
)

// This file is the write side of a repository's mirror, for the repository
// maintenance updater (Task 182): a commit of rewritten files is built on top
// of a branch's head — as objects in the mirror's object database, never
// through a checkout — and pushed to a maintenance branch of the remote with a
// lease, so that a branch somebody else moved in the meantime is never
// overwritten.
//
// Nothing here creates or moves a ref of the mirror. The commit is written as
// unreferenced objects and pushed by its ID straight to the repository's
// configured URL: not to the mirror's "origin", whose fetch refspecs would make
// git set the mirror's own refs/heads/<branch> after a successful push, and
// which may still point at an old URL until the next refresh. No hook of this
// side runs, no tag travels with the push, and credentials only ever reach git
// through the environment (authEnv), never its command line or a config file.

// FileChange is a file of a commit to build: its repository path and new
// content.
type FileChange struct {
	// Path is the file's path from the repository's root, slash-separated
	// ("services/api/go.sum").
	Path    string
	Content []byte
}

// Signature is an author or committer.
type Signature struct {
	Name, Email string
	// When is the time recorded, in its own zone. The zero time stands for the
	// moment the commit is built.
	When time.Time
}

// CommitSigner signs a commit's payload (the commit object without its gpgsig
// header) and returns the armored signature git stores in the "gpgsig" header.
// gitsign.SSHSigner is one.
type CommitSigner interface {
	SignCommit(payload []byte) ([]byte, error)
}

// CommitRequest describes a commit for BuildCommit.
type CommitRequest struct {
	// Base is the parent commit (a full object ID), which the mirror must hold.
	Base string
	// Files are the files to create or replace. Paths are relative to the
	// repository's root and slash-separated, without "." or ".." components,
	// without a ".git" component (in any spelling a checkout would treat as
	// one), and without control characters or backslashes. A file that exists
	// keeps its mode (an executable stays executable); a new one is 100644, and
	// the directories it needs are created. Replacing a directory, a symbolic
	// link or a submodule with a file — or going through one of them as if it
	// were a directory — is an error.
	Files []FileChange
	// Message is the commit message: valid UTF-8, not empty, without NUL
	// bytes. A missing final newline is added, as git commit does.
	Message string
	// Author and Committer are recorded as git records them: characters git's
	// own identity code trims from either end of a name or an address
	// (whitespace, and , : ; " ' \ < >) are trimmed; '<', '>' and control
	// characters inside one are refused.
	Author, Committer Signature
	// Signer signs the commit; nil leaves it unsigned.
	Signer CommitSigner
}

var (
	// ErrLeaseRejected is returned (wrapped) by PushBranch when the remote's
	// branch is no longer where the lease expected it: somebody else pushed
	// to it, created it, or deleted it.
	ErrLeaseRejected = errors.New("watch: the remote branch is not where the lease expected it")
	// ErrPushRejected is returned (wrapped) by PushBranch when the remote
	// refused the push for another reason: a protected branch, a hook that
	// declined, missing permissions to write the branch.
	ErrPushRejected = errors.New("watch: the remote rejected the push")
)

const (
	// maxCommitMessageBytes bounds a commit message.
	maxCommitMessageBytes = 1 << 20
	// maxRepoPathBytes bounds a file's path in a commit request.
	maxRepoPathBytes = 4096
	// maxRemoteOutput bounds what is kept of a command's standard output when
	// it talks to a remote (ls-remote, push): a few lines are expected.
	maxRemoteOutput = 1 << 20
	// maxLocalOutput bounds what is kept of a local command's standard output
	// (an object ID, a commit's header).
	maxLocalOutput = 1 << 20
	// maxStderr bounds what is kept of any command's standard error.
	maxStderr = 64 << 10
)

// localEnv is the environment of the commands that read and write the
// mirror's objects: objects are read as they are, not through replacements a
// refs/replace/ ref substitutes, and nothing is ever fetched on demand.
var localEnv = []string{"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1"}

// BuildCommit writes the blobs, trees and the commit object of req into
// repo's mirror — objects only: no ref is created or moved — and returns the
// commit's ID and its tree's. A request whose files leave the base tree
// unchanged returns the base's tree and still builds a commit; the caller
// compares the trees.
//
// The commit object is assembled here, byte for byte what git commit-tree
// writes for the same tree, parent, identities and message, and stored with
// git hash-object (which checks it the way fsck would). A signature is
// embedded the way git's own signing does, so no gpg or ssh-keygen runs.
func (g *GitSource) BuildCommit(ctx context.Context, repo RepoRef, req CommitRequest) (commit, tree string, err error) {
	if !hexObjectID.MatchString(req.Base) {
		return "", "", fmt.Errorf("watch: base %q is not a commit ID", req.Base)
	}
	root, err := planFiles(req.Files)
	if err != nil {
		return "", "", err
	}
	message, err := commitMessage(req.Message)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	author, err := identity("author", req.Author, now)
	if err != nil {
		return "", "", err
	}
	committer, err := identity("committer", req.Committer, now)
	if err != nil {
		return "", "", err
	}

	unlock := g.locks.lock(repo.Name)
	defer unlock()
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return "", "", errors.New("watch: the repository's mirror is not there yet")
	}
	rd, err := git.OpenObjectReader(dir, git.ObjectReaderOptions{GitBinary: g.gitBin})
	if err != nil {
		return "", "", fmt.Errorf("watch: reading the mirror of %s: %w", repo.Name, err)
	}
	defer rd.Close()

	baseCommit, baseTree, err := rd.ResolveCommit(ctx, req.Base)
	if err != nil {
		return "", "", fmt.Errorf("watch: base %s of %s: %w", req.Base, repo.Name, err)
	}
	if baseCommit != req.Base {
		return "", "", fmt.Errorf("watch: base %s of %s is not a commit", req.Base, repo.Name)
	}
	// Everything is checked against the base tree before anything is written.
	if err := resolvePlan(ctx, rd, root, baseTree, ""); err != nil {
		return "", "", fmt.Errorf("watch: %s: %w", repo.Name, err)
	}
	w := objectWriter{g: g, dir: dir, idLen: len(req.Base)}
	tree, err = w.writeTree(ctx, root)
	if err != nil {
		return "", "", fmt.Errorf("watch: building the tree for %s: %w", repo.Name, err)
	}

	text := []byte("tree " + tree + "\nparent " + req.Base + "\nauthor " + author + "\ncommitter " + committer + "\n\n" + message)
	if req.Signer != nil {
		sig, err := req.Signer.SignCommit(text)
		if err != nil {
			return "", "", fmt.Errorf("watch: signing the commit for %s: %w", repo.Name, err)
		}
		header := "gpgsig"
		if len(req.Base) == 64 {
			header = "gpgsig-sha256" // what a SHA-256 repository verifies
		}
		if text, err = withSignature(text, header, sig); err != nil {
			return "", "", fmt.Errorf("watch: signing the commit for %s: %w", repo.Name, err)
		}
	}
	commit, err = w.write(ctx, "commit", text)
	if err != nil {
		return "", "", fmt.Errorf("watch: writing the commit for %s: %w", repo.Name, err)
	}
	return commit, tree, nil
}

// CommitInfo returns a commit's tree and parents from repo's mirror, as the
// commit object records them (no replacement or graft applies). A commit the
// mirror does not hold is an error wrapping git.ErrObjectNotFound. Like the
// other readers (HasCommit, CommitTime) it does not wait for the repository's
// lock: objects can be read while a refresh runs.
func (g *GitSource) CommitInfo(ctx context.Context, repo RepoRef, commit string) (tree string, parents []string, err error) {
	if !hexObjectID.MatchString(commit) {
		return "", nil, fmt.Errorf("watch: %q is not a commit ID", commit)
	}
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return "", nil, errors.New("watch: the repository's mirror is not there yet")
	}
	// The type first, so that a large object that is not a commit is never
	// read.
	res, err := g.runGit(ctx, gitExec{dir: dir, timeout: g.opts.CommandTimeout, env: localEnv,
		stdin: []byte(commit + "\n"), args: []string{"cat-file", "--batch-check"}, maxStdout: 4 << 10})
	if err != nil {
		return "", nil, fmt.Errorf("watch: looking up %s: %w (%s)", commit, err, cleanText(res.stderr))
	}
	switch f := strings.Fields(string(res.stdout)); {
	case len(f) == 2 && f[0] == commit && f[1] == "missing":
		return "", nil, fmt.Errorf("%w: %s is not in the mirror of %s", git.ErrObjectNotFound, commit, repo.Name)
	case len(f) != 3 || f[0] != commit:
		return "", nil, fmt.Errorf("watch: unexpected answer looking up %s", commit)
	case f[1] != "commit":
		return "", nil, fmt.Errorf("%w: %s is a %s, not a commit", git.ErrObjectNotFound, commit, f[1])
	}
	res, err = g.runGit(ctx, gitExec{dir: dir, timeout: g.opts.CommandTimeout, env: localEnv,
		args: []string{"cat-file", "commit", commit}, maxStdout: maxLocalOutput})
	if err != nil {
		return "", nil, fmt.Errorf("watch: reading %s: %w (%s)", commit, err, cleanText(res.stderr))
	}
	return parseCommitHeader(res.stdout, res.truncated)
}

// parseCommitHeader reads a commit object's tree and parents as git does: the
// tree on the first line, the parents on the lines straight after it. Both
// come first, so an object cut short after them (truncated) still parses.
func parseCommitHeader(obj []byte, truncated bool) (string, []string, error) {
	lines := strings.Split(string(obj), "\n")
	if truncated {
		// The last line ends where the read did: it says nothing.
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return "", nil, errors.New("watch: malformed commit: no tree")
	}
	tree, ok := strings.CutPrefix(lines[0], "tree ")
	if !ok || !hexObjectID.MatchString(tree) {
		return "", nil, errors.New("watch: malformed commit: no tree")
	}
	var parents []string
	for _, l := range lines[1:] {
		p, ok := strings.CutPrefix(l, "parent ")
		if !ok {
			return tree, parents, nil
		}
		if !hexObjectID.MatchString(p) || len(p) != len(tree) {
			return "", nil, errors.New("watch: malformed commit: bad parent")
		}
		parents = append(parents, p)
	}
	if truncated {
		return "", nil, errors.New("watch: commit header too large")
	}
	return tree, parents, nil
}

// CommitObject returns a commit object of repo's mirror as git stores it
// (headers, a blank line, the message), at most 1 MiB of it.
func (g *GitSource) CommitObject(ctx context.Context, repo RepoRef, commit string) ([]byte, error) {
	if !hexObjectID.MatchString(commit) {
		return nil, fmt.Errorf("watch: %q is not a commit ID", commit)
	}
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return nil, errors.New("watch: the repository's mirror is not there yet")
	}
	if _, _, err := g.CommitInfo(ctx, repo, commit); err != nil {
		return nil, err // not there, or not a commit
	}
	res, err := g.runGit(ctx, gitExec{dir: dir, timeout: g.opts.CommandTimeout, env: localEnv,
		args: []string{"cat-file", "commit", commit}, maxStdout: 1 << 20})
	if err != nil {
		return nil, fmt.Errorf("watch: reading %s: %w (%s)", commit, err, cleanText(res.stderr))
	}
	if res.truncated {
		return nil, fmt.Errorf("watch: the commit %s is larger than 1 MiB", commit)
	}
	return res.stdout, nil
}

// RemoteBranch asks the remote (git ls-remote, with the repository's
// credentials) for refs/heads/<branch>: the commit it is at, or "" when the
// branch does not exist. It asks the repository's configured URL, from its
// mirror, which must exist (the first refresh creates it).
func (g *GitSource) RemoteBranch(ctx context.Context, repo RepoRef, branch string) (string, error) {
	if !validRefBranch(branch) {
		return "", fmt.Errorf("watch: %q is not a branch name", branch)
	}
	if err := git.ValidateCloneURL(repo.URL); err != nil {
		return "", fmt.Errorf("watch: %s: %w", repo.Name, err)
	}
	unlock := g.locks.lock(repo.Name)
	defer unlock()
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return "", errors.New("watch: the repository's mirror is not there yet")
	}
	return g.lsRemoteBranch(ctx, repo, dir, branch)
}

// lsRemoteBranch is RemoteBranch with the lock held. ls-remote matches a
// pattern against the end of every ref name (and protocol v2 servers send
// every ref the pattern prefixes), so the answer is filtered for the exact
// name.
func (g *GitSource) lsRemoteBranch(ctx context.Context, repo RepoRef, dir, branch string) (string, error) {
	ref := "refs/heads/" + branch
	res, err := g.runGit(ctx, gitExec{dir: dir, timeout: g.opts.FetchTimeout, env: authEnv(repo), maxStdout: maxRemoteOutput,
		args: g.safeArgs("ls-remote", "--refs", "--", repo.URL, ref)})
	if err != nil {
		return "", fmt.Errorf("watch: asking %s for %s: %w (%s)", repo.Name, ref, err, remoteText(repo, res.stderr))
	}
	for _, line := range strings.Split(string(res.stdout), "\n") {
		id, name, ok := strings.Cut(line, "\t")
		if !ok || name != ref {
			continue
		}
		if !hexObjectID.MatchString(id) {
			return "", fmt.Errorf("watch: %s answered %s with a malformed object ID", repo.Name, ref)
		}
		return id, nil
	}
	if res.truncated {
		return "", fmt.Errorf("watch: %s answered too much asking for %s", repo.Name, ref)
	}
	return "", nil
}

// PushBranch pushes commit, which the mirror must hold, to refs/heads/<branch>
// of the remote (the repository's URL) with
// --force-with-lease=refs/heads/<branch>:<expect>: the update happens only
// while the branch is at expect, or — expect "" — while it does not exist. It
// pushes atomically, with the repository's credentials, without running a hook
// and without sending a tag or any other ref, and leaves the mirror's own refs
// as they are (the branch arrives with the next refresh). A branch already at
// commit is success.
//
// A lease the remote no longer matches returns an error wrapping
// ErrLeaseRejected; any other rejection wraps ErrPushRejected. Other failures
// (the remote unreachable, credentials refused) wrap neither.
func (g *GitSource) PushBranch(ctx context.Context, repo RepoRef, branch, commit, expect string) error {
	if !validRefBranch(branch) {
		return fmt.Errorf("watch: %q is not a branch name", branch)
	}
	if !hexObjectID.MatchString(commit) {
		return fmt.Errorf("watch: %q is not a commit ID", commit)
	}
	if expect != "" && !hexObjectID.MatchString(expect) {
		return fmt.Errorf("watch: the lease %q is not a commit ID", expect)
	}
	if err := git.ValidateCloneURL(repo.URL); err != nil {
		return fmt.Errorf("watch: %s: %w", repo.Name, err)
	}
	unlock := g.locks.lock(repo.Name)
	defer unlock()
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return errors.New("watch: the repository's mirror is not there yet")
	}
	if !g.objectExists(ctx, dir, commit) {
		return fmt.Errorf("watch: commit %s is not in the mirror of %s", commit, repo.Name)
	}

	ref := "refs/heads/" + branch
	// --no-follow-tags, --recurse-submodules=no and --no-signed override what
	// a git configuration on this host might ask every push to do.
	res, err := g.runGit(ctx, gitExec{dir: dir, timeout: g.opts.FetchTimeout, env: authEnv(repo), maxStdout: maxRemoteOutput,
		args: g.safeArgs("push", "--porcelain", "--atomic", "--no-verify", "--no-follow-tags",
			"--recurse-submodules=no", "--no-signed", "--force-with-lease="+ref+":"+expect,
			"--", repo.URL, commit+":"+ref)})
	st, found := pushStatusOf(res.stdout, ref)
	switch {
	case found && st.accepted():
		return nil
	case found && st.flag == '!' && st.summary == "[rejected]" && (st.reason == "stale info" || st.reason == "remote ref updated since checkout"):
		// git compared the lease with what the remote advertised.
		return fmt.Errorf("%w: %s of %s is not at %s", ErrLeaseRejected, ref, repo.Name, leaseText(expect))
	case found && st.flag == '!' && st.summary == "[remote rejected]":
		// The remote refused the update itself. That is also how a branch
		// moved between the advertisement and the update shows (the remote's
		// compare-and-swap failed), so the branch is looked up again: a
		// branch that is no longer at expect is a lease that failed.
		why := remoteText(repo, st.reason+"\n"+res.stderr)
		now, lerr := g.lsRemoteBranch(ctx, repo, dir, branch)
		if lerr == nil && now != expect {
			return fmt.Errorf("%w: %s of %s is at %s now, not at %s (%s)", ErrLeaseRejected, ref, repo.Name, leaseText(now), leaseText(expect), why)
		}
		return fmt.Errorf("%w: %s of %s: %s", ErrPushRejected, ref, repo.Name, why)
	case found && st.flag == '!' && st.summary == "[rejected]":
		return fmt.Errorf("%w: %s of %s: %s", ErrPushRejected, ref, repo.Name, remoteText(repo, st.reason))
	case err != nil:
		return fmt.Errorf("watch: pushing %s to %s of %s: %w (%s)", commit, ref, repo.Name, err, remoteText(repo, res.stderr))
	default:
		return fmt.Errorf("watch: pushing %s to %s of %s: git reported no update of the branch", commit, ref, repo.Name)
	}
}

// DeleteBranch deletes refs/heads/<branch> of the remote with a lease: the
// branch must still be at expect. A lease the remote no longer matches wraps
// ErrLeaseRejected; a branch that is already gone is not an error.
func (g *GitSource) DeleteBranch(ctx context.Context, repo RepoRef, branch, expect string) error {
	if !validRefBranch(branch) {
		return fmt.Errorf("watch: %q is not a branch name", branch)
	}
	if !hexObjectID.MatchString(expect) {
		return fmt.Errorf("watch: the lease %q is not a commit ID", expect)
	}
	if err := git.ValidateCloneURL(repo.URL); err != nil {
		return fmt.Errorf("watch: %s: %w", repo.Name, err)
	}
	unlock := g.locks.lock(repo.Name)
	defer unlock()
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return errors.New("watch: the repository's mirror is not there yet")
	}
	ref := "refs/heads/" + branch
	res, err := g.runGit(ctx, gitExec{dir: dir, timeout: g.opts.FetchTimeout, env: authEnv(repo), maxStdout: maxRemoteOutput,
		args: g.safeArgs("push", "--porcelain", "--atomic", "--no-verify", "--no-follow-tags",
			"--recurse-submodules=no", "--no-signed", "--force-with-lease="+ref+":"+expect,
			"--", repo.URL, ":"+ref)})
	st, found := pushStatusOf(res.stdout, ref)
	switch {
	case found && st.flag == '-':
		return nil // deleted
	case found && st.flag == '!' && st.summary == "[rejected]" && (st.reason == "stale info" || st.reason == "remote ref updated since checkout"):
		if now, lerr := g.lsRemoteBranch(ctx, repo, dir, branch); lerr == nil && now == "" {
			return nil // already gone: what the deletion was for
		}
		return fmt.Errorf("%w: %s of %s is not at %s", ErrLeaseRejected, ref, repo.Name, leaseText(expect))
	case found && st.flag == '!' && st.summary == "[remote rejected]":
		why := remoteText(repo, st.reason+"\n"+res.stderr)
		now, lerr := g.lsRemoteBranch(ctx, repo, dir, branch)
		if lerr == nil && now == "" {
			return nil // gone meanwhile
		}
		if lerr == nil && now != expect {
			return fmt.Errorf("%w: %s of %s is at %s now, not at %s (%s)", ErrLeaseRejected, ref, repo.Name, leaseText(now), leaseText(expect), why)
		}
		return fmt.Errorf("%w: %s of %s: %s", ErrPushRejected, ref, repo.Name, why)
	case found && st.flag == '!':
		return fmt.Errorf("%w: %s of %s: %s", ErrPushRejected, ref, repo.Name, remoteText(repo, st.reason))
	case err != nil:
		return fmt.Errorf("watch: deleting %s of %s: %w (%s)", ref, repo.Name, err, remoteText(repo, res.stderr))
	}
	// No status line for the ref: git had nothing to delete.
	now, lerr := g.lsRemoteBranch(ctx, repo, dir, branch)
	if lerr == nil && now == "" {
		return nil
	}
	return fmt.Errorf("watch: deleting %s of %s: git reported no update of the branch", ref, repo.Name)
}

// pushStatus is git push --porcelain's line for one ref:
// "<flag>\t<from>:<to>\t<summary> (<reason>)".
type pushStatus struct {
	flag    byte
	summary string
	reason  string
}

// accepted reports a ref the remote now has at the pushed commit: updated
// (' ' fast-forward, '+' forced), created ('*') or already there ('=').
func (s pushStatus) accepted() bool {
	return s.flag == ' ' || s.flag == '+' || s.flag == '*' || s.flag == '='
}

// pushStatusOf finds ref's status line in git push --porcelain's output. Each
// line is one git printed; a reason the remote gave cannot span lines.
func pushStatusOf(out []byte, ref string) (pushStatus, bool) {
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 3 || line[1] != '\t' {
			continue
		}
		refs, summary, ok := strings.Cut(line[2:], "\t")
		if !ok {
			continue
		}
		if i := strings.LastIndexByte(refs, ':'); i < 0 || refs[i+1:] != ref {
			continue
		}
		st := pushStatus{flag: line[0], summary: summary}
		if s, r, ok := strings.Cut(summary, " ("); ok && strings.HasSuffix(r, ")") {
			st.summary, st.reason = s, strings.TrimSuffix(r, ")")
		}
		return st, true
	}
	return pushStatus{}, false
}

func leaseText(id string) string {
	if id == "" {
		return "nothing (absent)"
	}
	return id
}

// validRefBranch is validBranchName with the rest of git's rules for a ref
// name (git check-ref-format) that its character set leaves open: no empty
// component, no component starting with '.' or ending with ".lock", no '.' at
// the end. Such a name could never be pushed.
func validRefBranch(b string) bool {
	if !validBranchName(b) || strings.HasSuffix(b, ".") {
		return false
	}
	for _, c := range strings.Split(b, "/") {
		if c == "" || strings.HasPrefix(c, ".") || strings.HasSuffix(c, ".lock") {
			return false
		}
	}
	return true
}

// --- the request ---

// dirPlan is a directory of the new tree that the request changes.
type dirPlan struct {
	// base is the directory's tree in the base commit; "" for a new one.
	base string
	// entries are the base tree's entries by name (empty for a new
	// directory); writeTree replaces the changed ones.
	entries map[string]git.TreeEntry
	files   map[string]*filePlan
	dirs    map[string]*dirPlan
}

// filePlan is a file of the request.
type filePlan struct {
	path    string
	content []byte
	// mode is the file's mode in the new tree: the base's, or 100644 for a
	// new file. baseID is its blob in the base tree ("" for a new file).
	mode   uint32
	baseID string
}

func newDirPlan() *dirPlan {
	return &dirPlan{entries: map[string]git.TreeEntry{}, files: map[string]*filePlan{}, dirs: map[string]*dirPlan{}}
}

// planFiles validates the request's paths and arranges the files by
// directory. A path given twice, or used both as a file and as a directory,
// is an error.
func planFiles(files []FileChange) (*dirPlan, error) {
	root := newDirPlan()
	for _, f := range files {
		parts, err := splitRepoPath(f.Path)
		if err != nil {
			return nil, err
		}
		d := root
		for i, name := range parts[:len(parts)-1] {
			if _, ok := d.files[name]; ok {
				return nil, fmt.Errorf("watch: %s is both a file and a directory in the request", strings.Join(parts[:i+1], "/"))
			}
			sub := d.dirs[name]
			if sub == nil {
				sub = newDirPlan()
				d.dirs[name] = sub
			}
			d = sub
		}
		name := parts[len(parts)-1]
		if _, ok := d.files[name]; ok {
			return nil, fmt.Errorf("watch: %s is in the request twice", f.Path)
		}
		if _, ok := d.dirs[name]; ok {
			return nil, fmt.Errorf("watch: %s is both a file and a directory in the request", f.Path)
		}
		d.files[name] = &filePlan{path: f.Path, content: f.Content}
	}
	return root, nil
}

// splitRepoPath validates a repository path and splits it into its
// components.
func splitRepoPath(p string) ([]string, error) {
	switch {
	case p == "":
		return nil, errors.New("watch: empty file path")
	case len(p) > maxRepoPathBytes:
		return nil, fmt.Errorf("watch: file path of %d bytes is too long", len(p))
	case !utf8.ValidString(p):
		return nil, fmt.Errorf("watch: file path %q is not valid UTF-8", p)
	case strings.HasPrefix(p, "/"):
		return nil, fmt.Errorf("watch: file path %q is absolute", p)
	}
	for _, r := range p {
		if r == '\\' || unicode.IsControl(r) {
			return nil, fmt.Errorf("watch: file path %q contains a backslash or a control character", p)
		}
	}
	parts := strings.Split(p, "/")
	for _, c := range parts {
		switch {
		case c == "":
			return nil, fmt.Errorf("watch: file path %q has an empty component", p)
		case c == "." || c == "..":
			return nil, fmt.Errorf("watch: file path %q has a %q component", p, c)
		case isDotGit(c):
			return nil, fmt.Errorf("watch: file path %q goes into the repository's .git", p)
		}
	}
	return parts, nil
}

// isDotGit reports a path component a checkout would take for ".git": any
// case, with what NTFS ignores (trailing dots and spaces, an alternate data
// stream, the 8.3 short name "git~1") or HFS+ ignores (zero-width code
// points) — the names git's own verify_path refuses.
func isDotGit(c string) bool {
	c = strings.Map(func(r rune) rune {
		switch {
		case r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x206a && r <= 0x206f, r == 0xfeff:
			return -1
		}
		return r
	}, c)
	if i := strings.IndexByte(c, ':'); i >= 0 {
		c = c[:i]
	}
	c = strings.ToLower(strings.TrimRight(c, ". "))
	return c == ".git" || c == "git~1"
}

// resolvePlan reads the base tree of every directory the request changes and
// checks each change against it: a file may replace a file only, and a
// directory of the request must be a directory (or absent) in the base.
func resolvePlan(ctx context.Context, rd *git.ObjectReader, d *dirPlan, treeID, prefix string) error {
	d.base = treeID
	if treeID != "" {
		entries, err := rd.ReadTree(ctx, treeID)
		if err != nil {
			return fmt.Errorf("reading %q in the base commit: %w", strings.TrimSuffix(prefix, "/"), err)
		}
		for _, e := range entries {
			d.entries[e.Name] = e
		}
	}
	for _, name := range sortedKeys(d.files) {
		f := d.files[name]
		e, ok := d.entries[name]
		if !ok {
			f.mode = 0o100644
			continue
		}
		if e.Kind != git.EntryFile {
			return fmt.Errorf("%s is a %s in the base commit; it cannot be replaced by a file", f.path, kindText(e.Kind))
		}
		f.mode, f.baseID = e.Mode, e.ID
	}
	for _, name := range sortedKeys(d.dirs) {
		sub := d.dirs[name]
		subTree := ""
		if e, ok := d.entries[name]; ok {
			if e.Kind != git.EntryTree {
				return fmt.Errorf("%s%s is a %s in the base commit, not a directory", prefix, name, kindText(e.Kind))
			}
			subTree = e.ID
		}
		if err := resolvePlan(ctx, rd, sub, subTree, prefix+name+"/"); err != nil {
			return err
		}
	}
	return nil
}

func kindText(k git.EntryKind) string {
	switch k {
	case git.EntryFile:
		return "file"
	case git.EntrySymlink:
		return "symbolic link"
	case git.EntryTree:
		return "directory"
	case git.EntrySubmodule:
		return "submodule"
	}
	return k.String()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// objectWriter writes objects into one mirror.
type objectWriter struct {
	g   *GitSource
	dir string
	// idLen is the length of the repository's object IDs in hex.
	idLen int
}

// writeTree writes the blobs of d's files and, bottom-up, the trees of the
// directories that changed, and returns d's tree. A directory whose entries
// all stay as they were keeps its tree as it is, so a request that changes
// nothing gives the base tree back.
func (w objectWriter) writeTree(ctx context.Context, d *dirPlan) (string, error) {
	changed := d.base == ""
	for _, name := range sortedKeys(d.files) {
		f := d.files[name]
		id, err := w.write(ctx, "blob", f.content)
		if err != nil {
			return "", fmt.Errorf("%s: %w", f.path, err)
		}
		if id != f.baseID {
			d.entries[name] = git.TreeEntry{Name: name, Mode: f.mode, Kind: git.EntryFile, ID: id}
			changed = true
		}
	}
	for _, name := range sortedKeys(d.dirs) {
		sub := d.dirs[name]
		id, err := w.writeTree(ctx, sub)
		if err != nil {
			return "", err
		}
		if id != sub.base {
			d.entries[name] = git.TreeEntry{Name: name, Mode: 0o40000, Kind: git.EntryTree, ID: id}
			changed = true
		}
	}
	if !changed {
		return d.base, nil
	}
	// git mktree sorts the entries itself, and checks that every object it
	// is given exists with the type its mode says.
	var in bytes.Buffer
	for _, e := range d.entries {
		typ := "blob"
		switch e.Kind {
		case git.EntryTree:
			typ = "tree"
		case git.EntrySubmodule:
			typ = "commit"
		}
		fmt.Fprintf(&in, "%o %s %s\t%s\x00", e.Mode, typ, e.ID, e.Name)
	}
	return w.run(ctx, in.Bytes(), "mktree", "-z")
}

// write stores content as an object of the given type and returns its ID. A
// commit is checked the way fsck would check it before it is written.
func (w objectWriter) write(ctx context.Context, typ string, content []byte) (string, error) {
	return w.run(ctx, content, "hash-object", "-t", typ, "-w", "--no-filters", "--stdin")
}

// run runs a command that prints one object ID.
func (w objectWriter) run(ctx context.Context, stdin []byte, args ...string) (string, error) {
	if stdin == nil {
		stdin = []byte{}
	}
	res, err := w.g.runGit(ctx, gitExec{dir: w.dir, timeout: w.g.opts.CommandTimeout, env: localEnv,
		stdin: stdin, args: args, maxStdout: maxLocalOutput})
	if err != nil {
		return "", fmt.Errorf("git %s: %w (%s)", args[0], err, cleanText(res.stderr))
	}
	id := strings.TrimSpace(string(res.stdout))
	if !hexObjectID.MatchString(id) || len(id) != w.idLen {
		return "", fmt.Errorf("git %s printed %q, not an object ID", args[0], truncateText(id, 80))
	}
	return id, nil
}

// --- the commit object ---

// commitMessage checks a commit message and ends it with a newline.
func commitMessage(m string) (string, error) {
	switch {
	case strings.TrimSpace(m) == "":
		return "", errors.New("watch: the commit message is empty")
	case len(m) > maxCommitMessageBytes:
		return "", fmt.Errorf("watch: the commit message is %d bytes (at most %d)", len(m), maxCommitMessageBytes)
	case !utf8.ValidString(m):
		return "", errors.New("watch: the commit message is not valid UTF-8")
	case strings.IndexByte(m, 0) >= 0:
		return "", errors.New("watch: the commit message contains a NUL byte")
	}
	if !strings.HasSuffix(m, "\n") {
		m += "\n"
	}
	return m, nil
}

// identity formats a signature as the value of an author or committer header:
// "Name <email> <seconds> <±hhmm>".
func identity(role string, s Signature, now time.Time) (string, error) {
	name, err := identField(role+" name", s.Name)
	if err != nil {
		return "", err
	}
	email, err := identField(role+" email", s.Email)
	if err != nil {
		return "", err
	}
	when := s.When
	if when.IsZero() {
		when = now
	}
	secs := when.Unix()
	if secs < 0 {
		return "", fmt.Errorf("watch: the %s date %s is before 1970", role, when.Format(time.RFC3339))
	}
	_, offset := when.Zone()
	minutes := offset / 60
	sign := byte('+')
	if minutes < 0 {
		sign, minutes = '-', -minutes
	}
	if minutes >= 100*60 {
		return "", fmt.Errorf("watch: the %s date's zone offset %ds cannot be recorded", role, offset)
	}
	return fmt.Sprintf("%s <%s> %d %c%02d%02d", name, email, secs, sign, minutes/60, minutes%60), nil
}

// identField prepares a name or an e-mail address the way git's identity
// code does, so that git commit-tree given the same input writes the same
// commit: the characters git calls "crud" are trimmed from both ends. What git
// would silently delete inside the value instead ('<', '>', a line break) is
// refused, as is any other control character: none has a place in an
// identity, and a line break would end the header.
func identField(what, v string) (string, error) {
	if !utf8.ValidString(v) {
		return "", fmt.Errorf("watch: the %s is not valid UTF-8", what)
	}
	for _, r := range v {
		if r == '<' || r == '>' || unicode.IsControl(r) {
			return "", fmt.Errorf("watch: the %s %q contains '<', '>' or a control character", what, v)
		}
	}
	v = strings.TrimFunc(v, func(r rune) bool {
		return r <= ' ' || strings.ContainsRune(",:;<>\"\\'", r)
	})
	if v == "" {
		return "", fmt.Errorf("watch: the %s is empty", what)
	}
	return v, nil
}

// withSignature puts sig into a commit object's text the way git's
// sign_with_header does: as the last header, named header ("gpgsig"), its
// first line after the name and a space, every further line continued with a
// single leading space. The signature must end with a newline (one is added);
// a NUL or a control character other than the line breaks is refused, since it
// would not survive in a header.
func withSignature(text []byte, header string, sig []byte) ([]byte, error) {
	if len(bytes.TrimSpace(sig)) == 0 {
		return nil, errors.New("the signer returned no signature")
	}
	for _, c := range sig {
		if (c < 0x20 && c != '\n') || c == 0x7f {
			return nil, errors.New("the signature contains a control character")
		}
	}
	if sig[len(sig)-1] != '\n' {
		sig = append(append([]byte{}, sig...), '\n')
	}
	end := bytes.Index(text, []byte("\n\n"))
	if end < 0 {
		return nil, errors.New("the commit has no header")
	}
	var b bytes.Buffer
	b.Grow(len(text) + len(header) + len(sig) + len(sig)/40)
	b.Write(text[:end+1])
	b.WriteString(header)
	for _, line := range bytes.SplitAfter(sig, []byte("\n")) {
		if len(line) > 0 {
			b.WriteByte(' ')
			b.Write(line)
		}
	}
	b.Write(text[end+1:])
	return b.Bytes(), nil
}

// --- running git ---

// gitExec is one git invocation.
type gitExec struct {
	dir     string
	timeout time.Duration
	// env is added to the process's environment.
	env   []string
	stdin []byte
	args  []string
	// maxStdout bounds what is kept of the standard output.
	maxStdout int
}

// gitResult is what a git invocation printed.
type gitResult struct {
	stdout []byte
	// truncated reports standard output beyond maxStdout, which was dropped.
	truncated bool
	stderr    string
}

// runGit runs git as runEnv does — never prompting, restricted to the allowed
// transports, ended with every helper it started when ctx ends — with input,
// and with what it prints bounded: a remote decides how much of it there is.
// A non-zero exit is an error; the result is returned with it.
func (g *GitSource) runGit(ctx context.Context, c gitExec) (gitResult, error) {
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, g.gitBin, c.args...)
	cmd.Dir = c.dir
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if len(g.opts.AllowedProtocols) > 0 {
		env = append(env, "GIT_ALLOW_PROTOCOL="+strings.Join(g.opts.AllowedProtocols, ":"))
	}
	cmd.Env = append(env, c.env...)
	git.IsolateCommand(cmd)
	if c.stdin != nil {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}
	stdout := &limitedBuffer{max: c.maxStdout}
	stderr := &limitedBuffer{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	return gitResult{stdout: stdout.buf.Bytes(), truncated: stdout.truncated, stderr: stderr.buf.String()}, err
}

// limitedBuffer keeps the first max bytes written to it and drops the rest.
type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.max - b.buf.Len()
	switch {
	case room >= len(p):
		b.buf.Write(p)
	case room > 0:
		b.buf.Write(p[:room])
		b.truncated = true
	case len(p) > 0:
		b.truncated = true
	}
	return len(p), nil
}

// remoteText makes what git relayed from a remote fit for an error message:
// cleanText, after removing the repository's credentials in every form a
// server could echo back — the token, the Basic credential git sent, a URL's
// userinfo, a personal cache link.
func remoteText(repo RepoRef, s string) string {
	s = git.RedactURLSecrets(s)
	if len(repo.Token) >= 4 {
		s = strings.ReplaceAll(s, repo.Token, "***")
	}
	for _, kv := range authEnv(repo) {
		if v, ok := strings.CutPrefix(kv, "GIT_CONFIG_VALUE_0=Authorization: "); ok {
			if _, cred, ok := strings.Cut(v, " "); ok && len(cred) >= 4 {
				s = strings.ReplaceAll(s, cred, "***")
			}
		}
	}
	return cleanText(s)
}

// cleanText joins the lines of a command's output into one line for an
// error: control characters (terminal escapes among them) become spaces, the
// padding git puts after a "remote:" line and empty lines go, and the result
// is cut to a few hundred bytes.
func cleanText(s string) string {
	var parts []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, line))
		if line != "" && line != "remote:" {
			parts = append(parts, line)
		}
	}
	return truncateText(strings.Join(parts, " | "), 600)
}

// truncateText cuts s to at most n bytes at a character boundary.
func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
