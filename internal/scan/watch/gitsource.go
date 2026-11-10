package watch

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// GitSourceOptions configures the git-binary-backed CommitSource.
type GitSourceOptions struct {
	// Root is the directory under which per-repo bare mirrors are kept. Required.
	Root string
	// GitBinary is the git executable (default "git", resolved on PATH).
	GitBinary string
	// FetchTimeout bounds a single clone/fetch from upstream. Default 10m.
	FetchTimeout time.Duration
	// CommandTimeout bounds a single local git command (rev-list, show, …).
	// Default 2m.
	CommandTimeout time.Duration
	// MaxPatchBytes caps the unified-diff text retained per file; longer patches
	// are truncated (the commit is still scanned on the retained portion, and the
	// pipeline's own chunker bounds total tokens). Default 256 KiB.
	MaxPatchBytes int
	// MaxFilesPerCommit caps the number of per-file diffs built per commit.
	// Default 300.
	MaxFilesPerCommit int
	Logger            *slog.Logger
}

func (o GitSourceOptions) withDefaults() GitSourceOptions {
	if o.GitBinary == "" {
		o.GitBinary = "git"
	}
	if o.FetchTimeout <= 0 {
		o.FetchTimeout = 10 * time.Minute
	}
	if o.CommandTimeout <= 0 {
		o.CommandTimeout = 2 * time.Minute
	}
	if o.MaxPatchBytes <= 0 {
		o.MaxPatchBytes = 256 << 10
	}
	if o.MaxFilesPerCommit <= 0 {
		o.MaxFilesPerCommit = 300
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// GitSource is a CommitSource that maintains local bare mirrors via the git
// binary and enumerates new commits (and their diffs) with git log/show. It is
// safe for concurrent use; operations on one repo's mirror are serialized.
type GitSource struct {
	opts   GitSourceOptions
	gitBin string
	locks  keyedMutex
}

// NewGitSource validates opts, verifies the git binary exists, and returns a
// GitSource. It returns an error (so the caller can disable watching) when git
// is unavailable.
func NewGitSource(opts GitSourceOptions) (*GitSource, error) {
	opts = opts.withDefaults()
	if opts.Root == "" {
		return nil, errors.New("watch: git source root is required")
	}
	resolved, err := exec.LookPath(opts.GitBinary)
	if err != nil {
		return nil, fmt.Errorf("watch: git binary %q not found: %w", opts.GitBinary, err)
	}
	if err := os.MkdirAll(opts.Root, 0o750); err != nil {
		return nil, fmt.Errorf("watch: creating git source root %q: %w", opts.Root, err)
	}
	return &GitSource{opts: opts, gitBin: resolved, locks: newKeyedMutex()}, nil
}

// NewCommits implements CommitSource.
func (g *GitSource) NewCommits(ctx context.Context, repo RepoRef, known map[string]string, hint *UpdateHint, limit int) (*Batch, error) {
	unlock := g.locks.lock(repo.Name)
	defer unlock()

	dir := g.mirrorDir(repo)
	if err := g.ensureMirror(ctx, repo, dir); err != nil {
		return nil, err
	}

	// A sentinel "baseline" request (known has the "__skip__" key) only records
	// the current tips without enumerating any commits.
	baselineOnly := false
	if _, ok := known["__skip__"]; ok {
		baselineOnly = true
		known = nil
	}

	refs, err := g.trackedRefs(ctx, repo, dir, hint)
	if err != nil {
		return nil, err
	}

	batch := &Batch{Tips: cloneMap(known)}
	if batch.Tips == nil {
		batch.Tips = map[string]string{}
	}
	if baselineOnly {
		// Record the current head of every tracked ref as the baseline tip.
		for _, ref := range refs {
			after, perr := g.revParse(ctx, dir, ref.name)
			if perr != nil || after == "" {
				continue
			}
			batch.Tips[ref.name] = after
		}
		delete(batch.Tips, "__skip__")
		return batch, nil
	}

	if limit <= 0 {
		limit = 500
	}
	remaining := limit
	seen := make(map[string]struct{})

	for _, ref := range refs {
		after := ref.after
		if after == "" {
			p, perr := g.revParse(ctx, dir, ref.name)
			if perr != nil || p == "" {
				continue
			}
			after = p
		}
		// The lower bound is the cursor tip when known (so missed pushes are still
		// caught up), falling back to the webhook's reported "before" SHA.
		old := known[ref.name]
		if old == "" && ref.before != "" {
			old = ref.before
		}

		// Request one more than the limit so a fully-consumed range is
		// distinguishable from a truncated one (len(shas) > remaining).
		shas, rerr := g.revList(ctx, dir, old, after, remaining+1)
		if rerr != nil {
			return nil, rerr
		}

		fullyCovered := true
		lastCovered := ""
		for _, sha := range shas {
			if _, dup := seen[sha]; dup {
				lastCovered = sha
				continue
			}
			if remaining <= 0 {
				fullyCovered = false
				batch.Truncated = true
				break
			}
			c, cerr := g.buildCommit(ctx, dir, repo, sha)
			if cerr != nil {
				return nil, cerr
			}
			batch.Commits = append(batch.Commits, c)
			seen[sha] = struct{}{}
			remaining--
			lastCovered = sha
		}

		switch {
		case fullyCovered:
			batch.Tips[ref.name] = after
		case lastCovered != "":
			batch.Tips[ref.name] = lastCovered
		}
	}
	delete(batch.Tips, "__skip__")
	return batch, nil
}

// trackedRef is one ref to enumerate, optionally carrying the before/after SHAs
// a webhook hint reported.
type trackedRef struct {
	name   string // fully-qualified, e.g. refs/heads/main
	before string
	after  string
}

// trackedRefs resolves the set of refs to enumerate for a repo. A webhook hint
// takes precedence (scan exactly the pushed refs, filtered to the configured
// branches when any are set). Otherwise the configured branches are used, or the
// repo's default branch when none are configured.
func (g *GitSource) trackedRefs(ctx context.Context, repo RepoRef, dir string, hint *UpdateHint) ([]trackedRef, error) {
	allowed := branchFilter(repo.Branches)

	if hint != nil {
		var out []trackedRef
		for _, u := range hint.Refs {
			name := normalizeRefName(u.Ref)
			if !strings.HasPrefix(name, "refs/heads/") {
				continue // only branch pushes are scanned
			}
			if allowed != nil {
				if _, ok := allowed[strings.TrimPrefix(name, "refs/heads/")]; !ok {
					continue
				}
			}
			tr := trackedRef{name: name, after: u.After}
			if !isZeroSHA(u.Before) {
				tr.before = u.Before
			}
			out = append(out, tr)
		}
		return out, nil
	}

	if len(repo.Branches) > 0 {
		out := make([]trackedRef, 0, len(repo.Branches))
		for _, b := range repo.Branches {
			out = append(out, trackedRef{name: "refs/heads/" + strings.TrimPrefix(strings.TrimSpace(b), "refs/heads/")})
		}
		return out, nil
	}

	// No branches configured: track the mirror's default branch.
	def, err := g.defaultBranch(ctx, dir)
	if err != nil {
		return nil, err
	}
	return []trackedRef{{name: def}}, nil
}

func branchFilter(branches []string) map[string]struct{} {
	if len(branches) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(branches))
	for _, b := range branches {
		m[strings.TrimPrefix(strings.TrimSpace(b), "refs/heads/")] = struct{}{}
	}
	return m
}

func normalizeRefName(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "refs/") {
		return ref
	}
	return "refs/heads/" + ref
}

// defaultBranch returns the mirror's default branch ref (HEAD's symbolic
// target), falling back to refs/heads/main then refs/heads/master.
func (g *GitSource) defaultBranch(ctx context.Context, dir string) (string, error) {
	out, err := g.run(ctx, dir, g.opts.CommandTimeout, "symbolic-ref", "HEAD")
	if err == nil {
		if ref := strings.TrimSpace(out); ref != "" {
			return ref, nil
		}
	}
	for _, cand := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, perr := g.revParse(ctx, dir, cand); perr == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("watch: cannot determine default branch for mirror %q", dir)
}

// revParse returns the commit SHA a ref resolves to, or an error if absent.
func (g *GitSource) revParse(ctx context.Context, dir, ref string) (string, error) {
	out, err := g.run(ctx, dir, g.opts.CommandTimeout, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// objectExists reports whether sha names a commit in the mirror.
func (g *GitSource) objectExists(ctx context.Context, dir, sha string) bool {
	if sha == "" {
		return false
	}
	_, err := g.run(ctx, dir, g.opts.CommandTimeout, "cat-file", "-e", sha+"^{commit}")
	return err == nil
}

// revList returns the SHAs reachable from after but not from old (when old is a
// known commit), oldest-first, capped at limit. With no valid old it returns the
// whole reachable history (capped).
//
// Note: git applies --reverse *after* --max-count, so "--reverse --max-count=N"
// would yield the newest N reversed — the wrong end of history for forward
// incremental walking. We therefore request the full reversed list and slice the
// oldest `limit` in code. git streams the reversed output oldest-first, so the
// slice is the genuine history prefix.
func (g *GitSource) revList(ctx context.Context, dir, old, after string, limit int) ([]string, error) {
	args := []string{"rev-list", "--reverse", "--topo-order"}
	if old != "" && g.objectExists(ctx, dir, old) {
		args = append(args, old+".."+after)
	} else {
		args = append(args, after)
	}
	out, err := g.run(ctx, dir, g.opts.CommandTimeout, args...)
	if err != nil {
		return nil, fmt.Errorf("watch: rev-list %s: %w", after, err)
	}
	var shas []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			shas = append(shas, line)
			if limit > 0 && len(shas) >= limit {
				break
			}
		}
	}
	return shas, nil
}

// metaFormat is the git show --format template: fields separated by US (0x1f),
// with the raw body last (it may contain newlines).
const metaFormat = "%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%B"

// buildCommit assembles a *commit.Commit (metadata + per-file diff) for sha.
func (g *GitSource) buildCommit(ctx context.Context, dir string, repo RepoRef, sha string) (*commit.Commit, error) {
	meta, err := g.run(ctx, dir, g.opts.CommandTimeout, "show", "-s", "--format="+metaFormat, sha)
	if err != nil {
		return nil, fmt.Errorf("watch: reading commit %s metadata: %w", sha, err)
	}
	c, err := parseCommitMeta(meta)
	if err != nil {
		return nil, fmt.Errorf("watch: parsing commit %s metadata: %w", sha, err)
	}
	c.RepositoryURL = repo.URL

	patch, err := g.run(ctx, dir, g.opts.CommandTimeout,
		"show", "--format=", "--no-color", "--no-renames", "--unified=3", sha)
	if err != nil {
		return nil, fmt.Errorf("watch: reading commit %s diff: %w", sha, err)
	}
	c.Files = parsePatch(patch, g.opts.MaxFilesPerCommit, g.opts.MaxPatchBytes)
	return c, nil
}

// parseCommitMeta parses the metaFormat output into a Commit (without diff).
func parseCommitMeta(s string) (*commit.Commit, error) {
	parts := strings.SplitN(s, "\x1f", 9)
	if len(parts) < 9 {
		return nil, fmt.Errorf("unexpected field count %d", len(parts))
	}
	c := &commit.Commit{
		SHA:            strings.TrimSpace(parts[0]),
		AuthorName:     parts[2],
		AuthorEmail:    parts[3],
		CommitterName:  parts[5],
		CommitterEmail: parts[6],
		Message:        strings.TrimRight(parts[8], "\n"),
	}
	if c.SHA == "" {
		return nil, errors.New("empty SHA")
	}
	for _, p := range strings.Fields(parts[1]) {
		c.Parents = append(c.Parents, p)
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[4])); err == nil {
		c.AuthorDate = t
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[7])); err == nil {
		c.CommitDate = t
	}
	return c, nil
}

// --- mirror management ---

func (g *GitSource) mirrorDir(repo RepoRef) string {
	return filepath.Join(g.opts.Root, sanitizePathComponent(repo.Name)+".git")
}

func (g *GitSource) ensureMirror(ctx context.Context, repo RepoRef, dir string) error {
	fetchCtx, cancel := context.WithTimeout(ctx, g.opts.FetchTimeout)
	defer cancel()

	if isGitMirror(dir) {
		args := append(g.authArgs(repo), "remote", "update", "--prune")
		if out, err := g.run(fetchCtx, dir, g.opts.FetchTimeout, args...); err != nil {
			// A failed refresh of an existing mirror should not abort the cycle: scan
			// against the (possibly slightly stale) mirror and log.
			g.opts.Logger.Warn("commit-watch mirror refresh failed; using cached mirror",
				"repo", repo.Name, "error", err, "output", strings.TrimSpace(out))
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return fmt.Errorf("watch: creating mirror parent dir: %w", err)
	}
	args := append(g.authArgs(repo), "clone", "--mirror", "--quiet", repo.URL, dir)
	if out, err := g.run(fetchCtx, "", g.opts.FetchTimeout, args...); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("watch: cloning %s: %w (%s)", repo.Name, err, strings.TrimSpace(out))
	}
	return nil
}

// authArgs injects HTTPS credentials for this invocation without persisting them
// to the mirror's config (git -c http.extraHeader).
func (g *GitSource) authArgs(repo RepoRef) []string {
	if repo.Token == "" && repo.Username == "" {
		return nil
	}
	user := repo.Username
	pass := repo.Token
	if repo.Token != "" && repo.Username == "" {
		user = "x-access-token"
	}
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	return []string{"-c", "http.extraHeader=Authorization: " + header}
}

// run executes a git subcommand, returning combined stdout (stderr captured
// separately and surfaced in errors).
func (g *GitSource) run(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, g.gitBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func isGitMirror(dir string) bool {
	if fi, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil && !fi.IsDir() {
		return true
	}
	if fi, err := os.Stat(filepath.Join(dir, "objects")); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// sanitizePathComponent reduces a repo name to a filesystem-safe component.
func sanitizePathComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	out = strings.TrimLeft(out, ".")
	if out == "" {
		out = "repo"
	}
	return out
}
