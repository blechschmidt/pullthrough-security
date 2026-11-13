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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/git"
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
	// Refspecs, when set, makes each mirror a bare repository that fetches
	// exactly these refspecs (pruning within them) instead of a "clone
	// --mirror", which owns every ref under refs/. Refs outside the refspecs'
	// destinations — the repository tracker's refs/pullthrough/keep/* (Task
	// 180), which keep released commits reachable — then survive every
	// refresh. Example: "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*".
	Refspecs []string
	// AllowedProtocols, when set, restricts the transports git may use
	// (GIT_ALLOW_PROTOCOL), e.g. "https", "ssh". Empty leaves git's defaults.
	AllowedProtocols []string
	Logger           *slog.Logger
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
	err := g.syncMirror(ctx, repo, dir)
	var stale staleMirrorError
	if errors.As(err, &stale) {
		// A failed refresh of an existing mirror should not abort the cycle: scan
		// against the (possibly slightly stale) mirror and log.
		g.opts.Logger.Warn("commit-watch mirror refresh failed; using cached mirror",
			"repo", repo.Name, "error", stale.err)
		return nil
	}
	return err
}

// staleMirrorError reports that an existing mirror could not be refreshed: it
// is still there, as of its last successful refresh.
type staleMirrorError struct{ err error }

func (e staleMirrorError) Error() string { return "refreshing mirror: " + e.err.Error() }
func (e staleMirrorError) Unwrap() error { return e.err }

// syncMirror creates the mirror at dir or refreshes it from the upstream. A
// failed refresh of an existing mirror is a staleMirrorError.
func (g *GitSource) syncMirror(ctx context.Context, repo RepoRef, dir string) error {
	fetchCtx, cancel := context.WithTimeout(ctx, g.opts.FetchTimeout)
	defer cancel()

	if isGitMirror(dir) {
		if err := g.ensureRemoteURL(fetchCtx, repo, dir); err != nil {
			return staleMirrorError{err: err}
		}
		if out, err := g.runAuth(fetchCtx, repo, dir, g.opts.FetchTimeout, g.safeArgs("remote", "update", "--prune")...); err != nil {
			return staleMirrorError{err: fmt.Errorf("%w (%s)", err, git.RedactURLSecrets(strings.TrimSpace(out)))}
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return fmt.Errorf("watch: creating mirror parent dir: %w", err)
	}
	if len(g.opts.Refspecs) > 0 {
		if err := g.initRefspecMirror(fetchCtx, repo, dir); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
		return nil
	}
	// "--" ends the options: a URL is never read as one.
	args := g.safeArgs("clone", "--mirror", "--quiet", "--", repo.URL, dir)
	if out, err := g.runAuth(fetchCtx, repo, "", g.opts.FetchTimeout, args...); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("watch: cloning %s: %w (%s)", repo.Name, err, git.RedactURLSecrets(strings.TrimSpace(out)))
	}
	return nil
}

// ensureRemoteURL points an existing mirror at the repository's URL as it is
// configured now: a repository whose URL changed must be fetched from the new
// one, not go on being fetched from where it was first cloned.
func (g *GitSource) ensureRemoteURL(ctx context.Context, repo RepoRef, dir string) error {
	if out, err := g.run(ctx, dir, g.opts.CommandTimeout, "config", "--get", "remote.origin.url"); err == nil && strings.TrimSpace(out) == repo.URL {
		return nil
	}
	if out, err := g.run(ctx, dir, g.opts.CommandTimeout, "config", "remote.origin.url", repo.URL); err != nil {
		return fmt.Errorf("pointing the mirror of %s at its URL: %w (%s)", repo.Name, err, git.RedactURLSecrets(strings.TrimSpace(out)))
	}
	g.opts.Logger.Info("mirror now fetches from the repository's configured URL", "repo", repo.Name, "url", git.RedactURLSecrets(repo.URL))
	return nil
}

// initRefspecMirror creates a bare repository at dir that fetches exactly the
// configured refspecs from repo.URL, and fetches them.
func (g *GitSource) initRefspecMirror(ctx context.Context, repo RepoRef, dir string) error {
	steps := [][]string{
		{"init", "--bare", "--quiet", dir},
		{"-C", dir, "config", "remote.origin.url", repo.URL},
	}
	for i, spec := range g.opts.Refspecs {
		op := "--add"
		if i == 0 {
			op = "--replace-all"
		}
		steps = append(steps, []string{"-C", dir, "config", op, "remote.origin.fetch", spec})
	}
	for _, args := range steps {
		if out, err := g.run(ctx, "", g.opts.CommandTimeout, args...); err != nil {
			return fmt.Errorf("watch: preparing mirror of %s: %w (%s)", repo.Name, err, git.RedactURLSecrets(strings.TrimSpace(out)))
		}
	}
	if out, err := g.runAuth(ctx, repo, dir, g.opts.FetchTimeout, g.safeArgs("fetch", "--quiet", "--prune", "origin")...); err != nil {
		return fmt.Errorf("watch: fetching %s: %w (%s)", repo.Name, err, git.RedactURLSecrets(strings.TrimSpace(out)))
	}
	return nil
}

// safeArgs prefixes args with the settings every network-facing invocation
// carries: transports that run programs ("ext::") are refused, and no hook of
// the repository runs.
func (g *GitSource) safeArgs(args ...string) []string {
	return append([]string{"-c", "protocol.ext.allow=never", "-c", "core.hooksPath=/dev/null"}, args...)
}

// authEnv carries HTTPS credentials to one git invocation through the
// environment (GIT_CONFIG_COUNT, git >= 2.31) rather than the command line, so
// they never appear in the process list, and are never written to the mirror's
// config.
func authEnv(repo RepoRef) []string {
	if repo.Token == "" && repo.Username == "" {
		return nil
	}
	user := repo.Username
	pass := repo.Token
	if repo.Token != "" && repo.Username == "" {
		user = "x-access-token"
	}
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: " + header,
	}
}

// run executes a git subcommand, returning combined stdout (stderr captured
// separately and surfaced in errors).
func (g *GitSource) run(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	return g.runEnv(ctx, nil, dir, timeout, args...)
}

// runAuth is run with the repository's credentials in the environment.
func (g *GitSource) runAuth(ctx context.Context, repo RepoRef, dir string, timeout time.Duration, args ...string) (string, error) {
	return g.runEnv(ctx, authEnv(repo), dir, timeout, args...)
}

func (g *GitSource) runEnv(ctx context.Context, extra []string, dir string, timeout time.Duration, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, g.gitBin, args...)
	cmd.Dir = dir
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if len(g.opts.AllowedProtocols) > 0 {
		env = append(env, "GIT_ALLOW_PROTOCOL="+strings.Join(g.opts.AllowedProtocols, ":"))
	}
	cmd.Env = append(env, extra...)
	// A cancelled context ends git together with the helpers it started.
	git.IsolateCommand(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, git.RedactURLSecrets(strings.TrimSpace(stderr.String())))
	}
	return stdout.String(), nil
}

// MirrorDir returns the directory of repo's local mirror.
func (g *GitSource) MirrorDir(repo RepoRef) string { return g.mirrorDir(repo) }

// RefTip is a ref's state in a snapshot.
type RefTip struct {
	// Object is the object the ref points at: the commit for a lightweight tag
	// or a branch, the tag object for an annotated tag.
	Object string `json:"object"`
	// Commit is the commit the ref resolves to (an annotated tag peeled).
	Commit string `json:"commit"`
	// Annotated reports an annotated tag (Object is a tag object).
	Annotated bool `json:"annotated,omitempty"`
}

// ErrMirrorStale is returned (wrapped) by RefSnapshot when the mirror could not
// be refreshed from the upstream. The snapshot it returns with it is the
// mirror's state as of its last refresh.
var ErrMirrorStale = errors.New("watch: mirror could not be refreshed")

// RefSnapshot refreshes repo's mirror from its upstream and returns every ref
// under the given prefixes (e.g. "refs/tags/") with the commit it resolves to.
// A ref that does not resolve to a commit (a tag of a tree or blob) is left
// out. When the refresh fails the snapshot of the existing mirror is returned
// together with an error wrapping ErrMirrorStale; when there is no mirror yet,
// only the error.
func (g *GitSource) RefSnapshot(ctx context.Context, repo RepoRef, prefixes []string) (map[string]RefTip, error) {
	unlock := g.locks.lock(repo.Name)
	defer unlock()

	dir := g.mirrorDir(repo)
	syncErr := g.syncMirror(ctx, repo, dir)
	var stale staleMirrorError
	if syncErr != nil && !errors.As(syncErr, &stale) {
		return nil, syncErr
	}
	refs, err := g.listRefs(ctx, dir, prefixes)
	if err != nil {
		return nil, err
	}
	if syncErr != nil {
		return refs, fmt.Errorf("%w: %v", ErrMirrorStale, stale.err)
	}
	return refs, nil
}

// refFormat lists a ref's name, object, object type, and — for a tag — the
// object it points at and that object's type, separated by US (0x1f).
const refFormat = "%(refname)%1f%(objectname)%1f%(objecttype)%1f%(*objectname)%1f%(*objecttype)"

var hexObjectID = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func (g *GitSource) listRefs(ctx context.Context, dir string, prefixes []string) (map[string]RefTip, error) {
	args := []string{"for-each-ref", "--format=" + refFormat}
	for _, p := range prefixes {
		args = append(args, strings.TrimSpace(p))
	}
	out, err := g.run(ctx, dir, g.opts.CommandTimeout, args...)
	if err != nil {
		return nil, fmt.Errorf("watch: listing refs: %w", err)
	}
	refs := map[string]RefTip{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) != 5 || !hexObjectID.MatchString(f[1]) {
			continue
		}
		tip := RefTip{Object: f[1]}
		switch {
		case f[2] == "commit":
			tip.Commit = f[1]
		case f[2] == "tag" && f[4] == "commit" && hexObjectID.MatchString(f[3]):
			tip.Commit, tip.Annotated = f[3], true
		case f[2] == "tag":
			// A tag of a tag: peel it all the way. Git answers 1 when it
			// peels to a tree or a blob, which names no commit; any other
			// failure (a timeout) must fail the snapshot rather than leave
			// the tag out of it, where it would read as deleted.
			c, perr := g.revParse(ctx, dir, f[0])
			var exit *exec.ExitError
			switch {
			case perr != nil && errors.As(perr, &exit) && exit.ExitCode() == 1 && ctx.Err() == nil:
				continue
			case perr != nil:
				return nil, fmt.Errorf("watch: peeling %s: %w", f[0], perr)
			case !hexObjectID.MatchString(c):
				return nil, fmt.Errorf("watch: peeling %s gave %q", f[0], c)
			}
			tip.Commit, tip.Annotated = c, true
		default:
			continue // a ref to a tree or blob names no commit
		}
		refs[f[0]] = tip
	}
	return refs, nil
}

// keepRefPrefix is the namespace of the refs that keep released commits
// reachable in a refspec mirror (see GitSourceOptions.Refspecs).
const keepRefPrefix = "refs/pullthrough/keep/"

// KeepCommit makes commit reachable from a ref of its own in repo's mirror, so
// that it survives the tag that named it being moved or deleted upstream and
// the mirror being refreshed and garbage-collected. It needs a refspec mirror:
// a "clone --mirror" prunes every ref the upstream does not have.
func (g *GitSource) KeepCommit(ctx context.Context, repo RepoRef, commit string) error {
	if len(g.opts.Refspecs) == 0 {
		return errors.New("watch: keeping commits needs a refspec mirror (GitSourceOptions.Refspecs)")
	}
	if !hexObjectID.MatchString(commit) {
		return fmt.Errorf("watch: %q is not a commit ID", commit)
	}
	unlock := g.locks.lock(repo.Name)
	defer unlock()
	dir := g.mirrorDir(repo)
	if out, err := g.run(ctx, dir, g.opts.CommandTimeout, "update-ref", keepRefPrefix+commit, commit); err != nil {
		return fmt.Errorf("watch: keeping %s: %w (%s)", commit, err, strings.TrimSpace(out))
	}
	return nil
}

// HasCommit reports whether repo's mirror holds commit.
func (g *GitSource) HasCommit(ctx context.Context, repo RepoRef, commit string) bool {
	if !hexObjectID.MatchString(commit) {
		return false
	}
	return g.objectExists(ctx, g.mirrorDir(repo), commit)
}

// CommitTime returns the committer date of commit in repo's mirror.
func (g *GitSource) CommitTime(ctx context.Context, repo RepoRef, commit string) (time.Time, error) {
	if !hexObjectID.MatchString(commit) {
		return time.Time{}, fmt.Errorf("watch: %q is not a commit ID", commit)
	}
	out, err := g.run(ctx, g.mirrorDir(repo), g.opts.CommandTimeout, "show", "-s", "--format=%ct", commit)
	if err != nil {
		return time.Time{}, err
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("watch: reading the date of %s: %w", commit, err)
	}
	return time.Unix(sec, 0).UTC(), nil
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

// branchName is the shape of a branch name the mirror is asked about: nothing
// a command line could read as an option or a revision expression.
var branchName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$`)

func validBranchName(b string) bool {
	return branchName.MatchString(b) && !strings.Contains(b, "..") && !strings.HasSuffix(b, ".lock") && !strings.HasSuffix(b, "/")
}

// DefaultHead returns the branch whose head is followed and the commit that
// head is at in repo's mirror (as of its last refresh). branch, when set, is
// that branch. Otherwise the remote is asked for its default branch (its HEAD,
// `git ls-remote --symref`), which is remembered as the mirror's HEAD; when the
// remote cannot be asked, the remembered one is used, then main, then master.
func (g *GitSource) DefaultHead(ctx context.Context, repo RepoRef, branch string) (string, string, error) {
	unlock := g.locks.lock(repo.Name)
	defer unlock()
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return "", "", errors.New("watch: the repository's mirror is not there yet")
	}
	if branch == "" {
		out, err := g.runAuth(ctx, repo, dir, g.opts.FetchTimeout, g.safeArgs("ls-remote", "--symref", "origin", "HEAD")...)
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ref: refs/heads/")
				if !ok {
					continue
				}
				if b, ok := strings.CutSuffix(rest, "\tHEAD"); ok && validBranchName(b) {
					branch = b
					break
				}
			}
			if branch != "" {
				if out, err := g.run(ctx, dir, g.opts.CommandTimeout, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
					g.opts.Logger.Warn("remembering the remote's default branch failed", "repo", repo.Name, "error", err, "output", strings.TrimSpace(out))
				}
			}
		}
		if branch == "" {
			// The remote did not say: the branch the mirror remembers, if it
			// exists, then main, then master.
			if ref, derr := g.defaultBranch(ctx, dir); derr == nil {
				if _, perr := g.revParse(ctx, dir, ref); perr == nil {
					branch = strings.TrimPrefix(ref, "refs/heads/")
				}
			}
		}
		if branch == "" {
			return "", "", errors.New("watch: the repository's default branch could not be determined")
		}
	}
	if !validBranchName(branch) {
		return "", "", fmt.Errorf("watch: %q is not a branch name", branch)
	}
	commit, err := g.revParse(ctx, dir, "refs/heads/"+branch)
	if err != nil || !hexObjectID.MatchString(commit) {
		return branch, "", fmt.Errorf("watch: branch %s is not in the mirror", branch)
	}
	return branch, commit, nil
}

// hexPrefix is an abbreviated (or full) object ID.
var hexPrefix = regexp.MustCompile(`^[0-9a-f]{4,64}$`)

// ResolveRevision returns the commit a revision names in repo's mirror: a tag,
// then a branch, then a commit ID or an unambiguous prefix of one. Anything
// else — and anything shaped like an option or a revision expression — is
// refused.
func (g *GitSource) ResolveRevision(ctx context.Context, repo RepoRef, rev string) (string, error) {
	if !validBranchName(rev) {
		return "", fmt.Errorf("watch: %q is not a tag, branch or commit", rev)
	}
	dir := g.mirrorDir(repo)
	if !isGitMirror(dir) {
		return "", errors.New("watch: the repository's mirror is not there yet")
	}
	for _, ref := range []string{"refs/tags/" + rev, "refs/heads/" + rev} {
		if c, err := g.revParse(ctx, dir, ref); err == nil && hexObjectID.MatchString(c) {
			return c, nil
		}
	}
	if lower := strings.ToLower(rev); hexPrefix.MatchString(lower) {
		if c, err := g.revParse(ctx, dir, lower); err == nil && hexObjectID.MatchString(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("watch: unknown revision %q", rev)
}
