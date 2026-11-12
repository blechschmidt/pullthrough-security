package git

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// upstreamProtocol is the wire protocol the proxy requests when fetching from
// upstream; v2 is more efficient for large ref namespaces.
const upstreamProtocol = "version=2"

// baseGitEnv is appended to every git invocation: never prompt for credentials
// interactively (fail fast instead, so a misconfigured credential cannot hang
// the request).
var baseGitEnv = []string{"GIT_TERMINAL_PROMPT=0"}

// MirrorOptions configures the mirror manager.
type MirrorOptions struct {
	// Root is the directory under which bare mirrors are stored. Required.
	Root string
	// GitBinary is the git executable (default "git", resolved on PATH).
	GitBinary string
	// RefreshInterval bounds how often a mirror is refreshed from upstream. Within
	// the window, the existing mirror is served without contacting upstream.
	// Defaults to 1 minute when zero.
	RefreshInterval time.Duration
	// FetchTimeout bounds a single clone/fetch from upstream. Defaults to 10m.
	FetchTimeout time.Duration
	Logger       *slog.Logger
}

// Mirror maintains local bare mirrors of upstream repositories and serves git
// pack negotiation from them via the git binary. It is safe for concurrent use;
// operations on the same mirror are serialized.
type Mirror struct {
	root            string
	gitBin          string
	refreshInterval time.Duration
	fetchTimeout    time.Duration
	logger          *slog.Logger

	locks   keyedMutex
	mu      sync.Mutex
	lastRun map[string]time.Time
}

// NewMirror validates opts, verifies the git binary is available, and returns a
// Mirror. It returns an error (so the caller can fall back to pass-through mode)
// when git is not installed.
func NewMirror(opts MirrorOptions) (*Mirror, error) {
	if opts.Root == "" {
		return nil, errors.New("git: mirror root is required")
	}
	gitBin := opts.GitBinary
	if gitBin == "" {
		gitBin = "git"
	}
	resolved, err := exec.LookPath(gitBin)
	if err != nil {
		return nil, fmt.Errorf("git: git binary %q not found (mirror mode unavailable): %w", gitBin, err)
	}
	if err := os.MkdirAll(opts.Root, 0o750); err != nil {
		return nil, fmt.Errorf("git: creating mirror root %q: %w", opts.Root, err)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Mirror{
		root:            opts.Root,
		gitBin:          resolved,
		refreshInterval: orDur(opts.RefreshInterval, time.Minute),
		fetchTimeout:    orDur(opts.FetchTimeout, 10*time.Minute),
		logger:          logger,
		locks:           newKeyedMutex(),
		lastRun:         make(map[string]time.Time),
	}, nil
}

// mirrorDir returns the on-disk bare-mirror directory for an upstream repo.
func (m *Mirror) mirrorDir(up *Upstream, repoPath string) string {
	// repoPath is already sanitized (no traversal), so it is safe to join.
	name := repoPath
	if !hasGitSuffix(name) {
		name += ".git"
	}
	return filepath.Join(m.root, up.Name, filepath.FromSlash(name))
}

// Ensure makes the mirror for (up, repoPath) present and reasonably fresh,
// returning the bare-mirror directory. Concurrent calls for the same mirror are
// serialized; only one refresh runs per refresh interval.
func (m *Mirror) Ensure(ctx context.Context, up *Upstream, repoPath string) (string, error) {
	dir := m.mirrorDir(up, repoPath)

	unlock := m.locks.lock(dir)
	defer unlock()

	exists := isGitDir(dir)
	if exists && !m.stale(dir) {
		return dir, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, m.fetchTimeout)
	defer cancel()

	var err error
	if exists {
		err = m.fetch(fetchCtx, up, dir, repoPath)
		if err != nil {
			// A failed refresh of an existing mirror should not break clones: serve
			// the (possibly slightly stale) mirror and log the failure.
			m.logger.Warn("git mirror refresh failed; serving cached mirror",
				"upstream", up.Name, "repo", repoPath, "error", err)
			return dir, nil
		}
	} else {
		if err = m.clone(fetchCtx, up, dir, repoPath); err != nil {
			// Clean up a partial clone so the next attempt starts fresh.
			_ = os.RemoveAll(dir)
			return "", err
		}
	}

	m.markRefreshed(dir)
	return dir, nil
}

// OpenObjects makes the mirror of (up, repoPath) present and fresh, as Ensure
// does, and opens an ObjectReader over it: read access to the mirrored
// repository's commits, trees and files, without a checkout. The lock-file
// scanner (internal/lockfiles) reads mirrored repositories through it. The
// caller closes the reader.
func (m *Mirror) OpenObjects(ctx context.Context, up *Upstream, repoPath string, opts ObjectReaderOptions) (*ObjectReader, error) {
	clean, err := sanitizeRepoPath(repoPath)
	if err != nil {
		return nil, err
	}
	dir, err := m.Ensure(ctx, up, clean)
	if err != nil {
		return nil, err
	}
	if opts.GitBinary == "" {
		opts.GitBinary = m.gitBin
	}
	return OpenObjectReader(dir, opts)
}

func (m *Mirror) clone(ctx context.Context, up *Upstream, dir, repoPath string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return fmt.Errorf("git: creating mirror parent dir: %w", err)
	}
	cloneURL := up.upstreamCloneURL(repoPath)
	args := append(m.authArgs(up), "clone", "--mirror", "--quiet", cloneURL, dir)
	m.logger.Info("git mirror clone", "upstream", up.Name, "repo", repoPath, "url", up.redactedCloneURL(repoPath))
	if out, err := m.runGit(ctx, "", up, args...); err != nil {
		return fmt.Errorf("git: cloning %s: %w (%s)", up.redactedCloneURL(repoPath), err, out)
	}
	return nil
}

func (m *Mirror) fetch(ctx context.Context, up *Upstream, dir, repoPath string) error {
	args := append(m.authArgs(up), "remote", "update", "--prune")
	m.logger.Debug("git mirror refresh", "upstream", up.Name, "repo", repoPath)
	if out, err := m.runGit(ctx, dir, up, args...); err != nil {
		return fmt.Errorf("git: refreshing mirror: %w (%s)", err, out)
	}
	return nil
}

// AdvertiseRefs runs "git upload-pack --advertise-refs" against the mirror and
// returns the raw advertisement (without the smart-HTTP service preamble),
// capturing stdout separately so diagnostics on stderr never corrupt the
// protocol stream. protocol, when non-empty (e.g. "version=2"), is passed as
// GIT_PROTOCOL so the advertisement matches what the client negotiated.
func (m *Mirror) AdvertiseRefs(ctx context.Context, dir, protocol string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, m.gitBin, "upload-pack", "--stateless-rpc", "--advertise-refs", dir)
	cmd.Env = m.serveEnv(protocol)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git: advertising refs: %w (%s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// UploadPackStateless pipes a smart-HTTP git-upload-pack request body through
// "git upload-pack --stateless-rpc", streaming the result to w.
func (m *Mirror) UploadPackStateless(ctx context.Context, dir string, body io.Reader, w io.Writer, protocol string) error {
	return m.runGitStreaming(ctx, m.serveEnv(protocol), body, w, nil, "upload-pack", "--stateless-rpc", dir)
}

// UploadPackStateful connects a bidirectional client stream (e.g. an SSH
// channel) to "git upload-pack" using the stateful (non-RPC) protocol used over
// SSH and the git:// transport.
func (m *Mirror) UploadPackStateful(ctx context.Context, dir string, in io.Reader, out, errOut io.Writer, protocol string) error {
	return m.runGitStreaming(ctx, m.serveEnv(protocol), in, out, errOut, "upload-pack", dir)
}

// authArgs returns the per-invocation git -c flags that inject upstream HTTPS
// credentials without persisting them to the mirror's config.
func (m *Mirror) authArgs(up *Upstream) []string {
	if up.Transport != TransportHTTPS {
		return nil
	}
	var header string
	switch {
	case up.creds.Token != "":
		header = basicAuthHeader("x-access-token", up.creds.Token)
	case up.creds.Username != "" || up.creds.Password != "":
		header = basicAuthHeader(up.creds.Username, up.creds.Password)
	default:
		return nil
	}
	// http.extraHeader applies to all hosts for this invocation; combined with a
	// credential-less remote URL it authenticates without writing the secret to
	// .git/config.
	return []string{"-c", "http.extraHeader=Authorization: " + header}
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// sshEnv builds the GIT_SSH_COMMAND for SSH-transport upstreams (mirror mode).
func (m *Mirror) sshEnv(up *Upstream) []string {
	if up.Transport != TransportSSH {
		return nil
	}
	cmd := "ssh -o BatchMode=yes"
	if up.sshKeyFile != "" {
		cmd += " -i " + shellQuote(up.sshKeyFile) + " -o IdentitiesOnly=yes"
	}
	switch {
	case up.sshIgnoreHostKey:
		cmd += " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
	case up.sshKnownHosts != "":
		cmd += " -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + shellQuote(up.sshKnownHosts)
	default:
		cmd += " -o StrictHostKeyChecking=accept-new"
	}
	return []string{"GIT_SSH_COMMAND=" + cmd}
}

// runGit runs a git subcommand (a clone/fetch from upstream), capturing combined
// output. dir, when non-empty, is the working directory (the bare mirror). It
// requests protocol v2 from upstream and injects the upstream's SSH key when
// applicable.
func (m *Mirror) runGit(ctx context.Context, dir string, up *Upstream, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, m.gitBin, args...)
	cmd.Dir = dir
	cmd.Env = m.fetchEnv(up)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runGitStreaming runs git wiring stdin/stdout (and optionally stderr) to the
// provided streams, with the supplied environment.
func (m *Mirror) runGitStreaming(ctx context.Context, env []string, in io.Reader, out, errOut io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, m.gitBin, args...)
	cmd.Env = env
	cmd.Stdin = in
	cmd.Stdout = out
	if errOut != nil {
		cmd.Stderr = errOut
	} else {
		cmd.Stderr = io.Discard
	}
	return cmd.Run()
}

// fetchEnv builds the environment for an upstream clone/fetch: protocol v2 plus
// the upstream's SSH command when the upstream is reached over SSH.
func (m *Mirror) fetchEnv(up *Upstream) []string {
	env := append(os.Environ(), baseGitEnv...)
	env = append(env, "GIT_PROTOCOL="+upstreamProtocol)
	if up != nil {
		env = append(env, m.sshEnv(up)...)
	}
	return env
}

// serveEnv builds the environment for serving a local client: it forwards the
// client-negotiated protocol (e.g. "version=2") to upload-pack so the
// advertisement and responses match what the client expects.
func (m *Mirror) serveEnv(protocol string) []string {
	env := append(os.Environ(), baseGitEnv...)
	if protocol != "" {
		env = append(env, "GIT_PROTOCOL="+protocol)
	}
	return env
}

func (m *Mirror) stale(dir string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	last, ok := m.lastRun[dir]
	if !ok {
		// Fall back to the mirror's FETCH_HEAD/packed-refs mtime across restarts.
		if fi, err := os.Stat(filepath.Join(dir, "FETCH_HEAD")); err == nil {
			last = fi.ModTime()
		} else if fi, err := os.Stat(dir); err == nil {
			last = fi.ModTime()
		} else {
			return true
		}
	}
	return clock().Sub(last) >= m.refreshInterval
}

func (m *Mirror) markRefreshed(dir string) {
	m.mu.Lock()
	m.lastRun[dir] = clock()
	m.mu.Unlock()
}

// clock is overridable in tests.
var clock = time.Now

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func hasGitSuffix(p string) bool {
	return len(p) >= 4 && p[len(p)-4:] == ".git"
}

// isGitDir reports whether dir looks like a bare git repository.
func isGitDir(dir string) bool {
	if fi, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil && !fi.IsDir() {
		return true
	}
	if fi, err := os.Stat(filepath.Join(dir, "objects")); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// shellQuote single-quotes a string for safe inclusion in GIT_SSH_COMMAND.
func shellQuote(s string) string {
	return "'" + bytesReplace(s, "'", `'\''`) + "'"
}

func bytesReplace(s, old, new string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(old), []byte(new)))
}

// keyedMutex provides per-key locking with reference counting so unused keys are
// reclaimed.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() keyedMutex {
	return keyedMutex{locks: make(map[string]*refLock)}
}

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
