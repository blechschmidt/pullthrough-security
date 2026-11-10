package reposcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Locator resolves a source-repository URL to a local git directory the analyzer
// can read offline. It is the seam that keeps the Service air-gap friendly: an
// implementation may consult only already-present mirrors (pure offline) or fetch
// on demand (online), and tests supply a trivial in-memory implementation that
// maps URLs to fixture directories.
type Locator interface {
	// Locate returns a local git directory for repoURL. resolved=false means no
	// local copy is available (and on-demand fetching is disabled or failed), in
	// which case the Service records an unresolved report and the repository
	// contributes nothing to risk. online reports whether reaching the directory
	// required a network fetch (for the report's Online flag and metrics).
	Locate(ctx context.Context, repoURL string) (dir string, resolved bool, online bool, err error)
}

// normalizeRepoURL canonicalizes a repository URL into a stable key for caching
// and on-disk layout: lower-cased host, scheme dropped, a leading "git+" / user
// info / trailing ".git" / trailing slash stripped. It is best-effort — an
// unparseable value is returned trimmed and lower-cased — and never returns an
// error so a malformed hint cannot break a pull.
func normalizeRepoURL(repoURL string) string {
	s := strings.TrimSpace(repoURL)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "git+")
	// Normalize scp-like SSH syntax (git@host:owner/repo) to a path form.
	if !strings.Contains(s, "://") {
		if at := strings.Index(s, "@"); at >= 0 {
			if colon := strings.Index(s[at:], ":"); colon >= 0 {
				s = s[at+1:at+colon] + "/" + s[at+colon+1:]
			}
		}
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = strings.ToLower(u.Host) + u.Path
	}
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return strings.TrimSuffix(s, "/")
}

// MirrorLocator is the default Locator. It keeps blob-filtered bare clones under a
// cache root, keyed by the normalized repository URL, and reuses them across
// requests and restarts. On-demand cloning happens only when AllowFetch is set,
// so an air-gapped deployment (AllowFetch=false) serves exclusively from clones
// that already exist on disk and never reaches the network.
type MirrorLocator struct {
	root       string
	gitBin     string
	allowFetch bool
	depth      int
	timeout    time.Duration
	logger     *slog.Logger

	locks keyedMutex
}

// MirrorLocatorOptions configures a MirrorLocator.
type MirrorLocatorOptions struct {
	// Root is the directory under which clones are stored. Required.
	Root string
	// GitBinary is the git executable (default "git").
	GitBinary string
	// AllowFetch enables on-demand cloning of not-yet-mirrored repositories. Leave
	// false for a strict air-gapped deployment.
	AllowFetch bool
	// Depth bounds the clone history (shallow). Zero uses a built-in default; a
	// negative value clones full history.
	Depth int
	// FetchTimeout bounds a single clone. Zero uses a built-in default.
	FetchTimeout time.Duration
	Logger       *slog.Logger
}

const (
	defaultCloneDepth   = 256
	defaultFetchTimeout = 60 * time.Second
)

// NewMirrorLocator validates opts and returns a MirrorLocator. It verifies the
// git binary is present so a misconfiguration surfaces at startup rather than on
// the first pull.
func NewMirrorLocator(opts MirrorLocatorOptions) (*MirrorLocator, error) {
	if strings.TrimSpace(opts.Root) == "" {
		return nil, errors.New("reposcore: mirror locator root is required")
	}
	gitBin := opts.GitBinary
	if gitBin == "" {
		gitBin = "git"
	}
	resolved, err := exec.LookPath(gitBin)
	if err != nil {
		return nil, fmt.Errorf("reposcore: git binary %q not found: %w", gitBin, err)
	}
	if err := os.MkdirAll(opts.Root, 0o750); err != nil {
		return nil, fmt.Errorf("reposcore: creating mirror root %q: %w", opts.Root, err)
	}
	depth := opts.Depth
	if depth == 0 {
		depth = defaultCloneDepth
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &MirrorLocator{
		root:       opts.Root,
		gitBin:     resolved,
		allowFetch: opts.AllowFetch,
		depth:      depth,
		timeout:    orDuration(opts.FetchTimeout, defaultFetchTimeout),
		logger:     logger,
		locks:      newKeyedMutex(),
	}, nil
}

// Locate returns the local clone directory for repoURL, cloning it on demand when
// AllowFetch is set and it is not already present.
func (m *MirrorLocator) Locate(ctx context.Context, repoURL string) (string, bool, bool, error) {
	norm := normalizeRepoURL(repoURL)
	if norm == "" {
		return "", false, false, errors.New("empty repository URL")
	}
	dir := filepath.Join(m.root, mirrorSubdir(norm))

	unlock := m.locks.lock(dir)
	defer unlock()

	if isGitDir(dir) {
		return dir, true, false, nil
	}
	if !m.allowFetch {
		// Air-gapped: no pre-existing clone and fetching disabled — unresolved.
		return "", false, false, nil
	}

	cloneURL := cloneURLFor(repoURL)
	if cloneURL == "" {
		return "", false, false, fmt.Errorf("unsupported repository URL %q", repoURL)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	if err := m.clone(fetchCtx, cloneURL, dir); err != nil {
		_ = os.RemoveAll(dir) // clean up a partial clone for the next attempt
		return "", false, true, err
	}
	return dir, true, true, nil
}

// clone performs a blob-filtered bare clone so commit/tree metadata (everything
// the analyzer needs) is fetched while file blobs are not, keeping the clone
// small and fast. A shallow depth bounds the history to the recent window.
func (m *MirrorLocator) clone(ctx context.Context, cloneURL, dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return fmt.Errorf("creating clone parent dir: %w", err)
	}
	args := []string{"clone", "--bare", "--quiet", "--filter=blob:none", "--no-tags"}
	if m.depth > 0 {
		args = append(args, fmt.Sprintf("--depth=%d", m.depth))
	}
	args = append(args, cloneURL, dir)
	cmd := exec.CommandContext(ctx, m.gitBin, args...)
	cmd.Env = append(os.Environ(), gitEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cloning repository: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	// Fetch tags separately (shallow, bounded) so the signed-tag signal has data
	// without bloating the initial clone; a failure here is non-fatal.
	_ = exec.CommandContext(ctx, m.gitBin, "-C", dir, "fetch", "--quiet", "--tags", "--depth=1").Run()
	return nil
}

// cloneURLFor returns an https/ssh clone URL for a repository hint, or "" if it
// is not a network-cloneable URL (e.g. a bare "owner/repo" with no host).
func cloneURLFor(repoURL string) string {
	s := strings.TrimSpace(repoURL)
	s = strings.TrimPrefix(s, "git+")
	if strings.Contains(s, "://") || strings.Contains(s, "@") {
		return s
	}
	// host/owner/repo with no scheme → assume https.
	if strings.Contains(s, "/") && strings.Contains(s, ".") {
		return "https://" + s
	}
	return ""
}

// mirrorSubdir derives a filesystem-safe, collision-resistant subdirectory for a
// normalized repo URL: a readable prefix plus a content hash suffix.
func mirrorSubdir(norm string) string {
	sum := sha256.Sum256([]byte(norm))
	hash := hex.EncodeToString(sum[:])[:16]
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, norm)
	if len(safe) > 48 {
		safe = safe[:48]
	}
	return safe + "-" + hash + ".git"
}

// isGitDir reports whether dir looks like a (bare) git repository.
func isGitDir(dir string) bool {
	if fi, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil && !fi.IsDir() {
		return true
	}
	if fi, err := os.Stat(filepath.Join(dir, "objects")); err == nil && fi.IsDir() {
		return true
	}
	return false
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// keyedMutex provides per-key locking with reference counting so concurrent
// requests for the same repository serialize on its clone but different
// repositories proceed in parallel.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() keyedMutex { return keyedMutex{locks: make(map[string]*refLock)} }

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	rl, ok := k.locks[key]
	if !ok {
		rl = &refLock{}
		k.locks[key] = rl
	}
	rl.refs++
	k.mu.Unlock()

	rl.mu.Lock()
	return func() {
		rl.mu.Unlock()
		k.mu.Lock()
		rl.refs--
		if rl.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
