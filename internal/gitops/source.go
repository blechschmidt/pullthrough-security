package gitops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Fetched is the desired-state document a Source returns: the raw bundle bytes, an
// optional detached signature, and the revision identifier of the source of truth
// (a Git commit SHA, an OCI digest, or a content digest for a bare local file).
type Fetched struct {
	// Revision identifies the source-of-truth revision the bundle was read at. For
	// Git this is the resolved commit SHA; for a local file with no embedded
	// revision it falls back to the bundle content digest.
	Revision string
	// Bundle is the raw desired-state document bytes.
	Bundle []byte
	// Signature is the raw detached signature bytes (nil when none was found).
	Signature []byte
	// Origin describes where the bundle came from (for status/audit display).
	Origin string
}

// Source fetches the desired-state bundle from a designated source of truth. It is
// the seam that makes the reconciler air-gap friendly: the local-path source reads
// a pre-fetched bundle from disk (no network), while the Git source pulls from a
// remote repository.
type Source interface {
	// Fetch retrieves the current desired-state bundle. It must be safe to call
	// repeatedly; the reconciler invokes it once per interval.
	Fetch(ctx context.Context) (Fetched, error)
	// Describe returns a short human-readable description of the source (for status).
	Describe() string
}

// LocalSource reads the desired-state bundle from a local filesystem path. This is
// the air-gapped / pre-fetched-bundle source: an out-of-band process (a sidecar, a
// CI job, the air-gap mirror import) writes the signed bundle to a path the proxy
// reads. A detached signature is read from "<path>.sig" when present. It also backs
// the OCI-artifact workflow: pull the artifact to a local path out-of-band, then
// point the proxy at it.
type LocalSource struct {
	// Path is the bundle file to read.
	Path string
	// SignaturePath optionally overrides the detached-signature location (defaults
	// to Path + ".sig").
	SignaturePath string
}

// NewLocalSource constructs a LocalSource for the given bundle file.
func NewLocalSource(path string) *LocalSource {
	return &LocalSource{Path: path}
}

// Fetch reads the bundle (and any sibling signature) from disk.
func (s *LocalSource) Fetch(_ context.Context) (Fetched, error) {
	if strings.TrimSpace(s.Path) == "" {
		return Fetched{}, fmt.Errorf("gitops: local source path is empty")
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		return Fetched{}, fmt.Errorf("gitops: reading bundle %q: %w", s.Path, err)
	}
	sig := s.readSignature()
	rev := embeddedRevision(raw)
	if rev == "" {
		rev = "sha256:" + Digest(raw)
	}
	return Fetched{Revision: rev, Bundle: raw, Signature: sig, Origin: "file:" + s.Path}, nil
}

// Describe returns a description of the local source.
func (s *LocalSource) Describe() string { return "local:" + s.Path }

func (s *LocalSource) readSignature() []byte {
	sigPath := strings.TrimSpace(s.SignaturePath)
	if sigPath == "" {
		sigPath = s.Path + ".sig"
	}
	data, err := os.ReadFile(sigPath)
	if err != nil {
		return nil
	}
	return data
}

// GitSource clones/fetches a Git repository and reads the bundle file at a ref. It
// shells out to the `git` binary (so it works with any auth the host git is
// configured for: SSH agent, credential helper, https tokens), maintaining a single
// working clone under WorkDir that it fast-forwards on each Fetch.
type GitSource struct {
	// URL is the repository to clone (https or ssh).
	URL string
	// Ref is the branch/tag/commit to read (defaults to the remote HEAD).
	Ref string
	// BundlePath is the path to the bundle file within the repository.
	BundlePath string
	// WorkDir is the local directory the repo is cloned into and kept in sync.
	WorkDir string
	// SignaturePath optionally overrides the in-repo detached-signature path
	// (defaults to BundlePath + ".sig").
	SignaturePath string
	// gitBin is the git executable (overridable in tests); defaults to "git".
	gitBin string
}

// NewGitSource constructs a GitSource. WorkDir must be a writable directory the
// proxy owns.
func NewGitSource(url, ref, bundlePath, workDir string) *GitSource {
	return &GitSource{URL: url, Ref: ref, BundlePath: bundlePath, WorkDir: workDir, gitBin: "git"}
}

// Describe returns a description of the Git source.
func (s *GitSource) Describe() string {
	ref := s.Ref
	if ref == "" {
		ref = "HEAD"
	}
	return fmt.Sprintf("git:%s@%s:%s", s.URL, ref, s.BundlePath)
}

// Fetch ensures the working clone is present and up to date, then reads the bundle
// file and resolves the checked-out commit SHA as the revision.
func (s *GitSource) Fetch(ctx context.Context) (Fetched, error) {
	if strings.TrimSpace(s.URL) == "" {
		return Fetched{}, fmt.Errorf("gitops: git source url is empty")
	}
	if strings.TrimSpace(s.WorkDir) == "" {
		return Fetched{}, fmt.Errorf("gitops: git source workDir is empty")
	}
	git := s.gitBin
	if git == "" {
		git = "git"
	}
	if _, err := exec.LookPath(git); err != nil {
		return Fetched{}, fmt.Errorf("gitops: git binary not found on PATH (required for git source; use a local-path source in air-gapped deployments): %w", err)
	}

	if err := s.sync(ctx, git); err != nil {
		return Fetched{}, err
	}

	rev, err := s.run(ctx, git, s.WorkDir, "rev-parse", "HEAD")
	if err != nil {
		return Fetched{}, fmt.Errorf("gitops: resolving commit: %w", err)
	}
	rev = strings.TrimSpace(rev)

	bundleFile := filepath.Join(s.WorkDir, filepath.FromSlash(s.BundlePath))
	raw, err := os.ReadFile(bundleFile)
	if err != nil {
		return Fetched{}, fmt.Errorf("gitops: reading bundle %q from clone: %w", s.BundlePath, err)
	}
	sigRel := strings.TrimSpace(s.SignaturePath)
	if sigRel == "" {
		sigRel = s.BundlePath + ".sig"
	}
	var sig []byte
	if data, serr := os.ReadFile(filepath.Join(s.WorkDir, filepath.FromSlash(sigRel))); serr == nil {
		sig = data
	}
	return Fetched{Revision: rev, Bundle: raw, Signature: sig, Origin: s.Describe()}, nil
}

// sync clones the repo on first use, then fetches and hard-resets to the target ref
// so the working tree exactly reflects the source of truth.
func (s *GitSource) sync(ctx context.Context, git string) error {
	gitDir := filepath.Join(s.WorkDir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if err := os.MkdirAll(filepath.Dir(s.WorkDir), 0o755); err != nil {
			return fmt.Errorf("gitops: preparing workDir: %w", err)
		}
		if _, err := s.run(ctx, git, "", "clone", "--quiet", s.URL, s.WorkDir); err != nil {
			return fmt.Errorf("gitops: cloning %q: %w", s.URL, err)
		}
	}
	ref := strings.TrimSpace(s.Ref)
	if ref == "" {
		ref = "HEAD"
	}
	if _, err := s.run(ctx, git, s.WorkDir, "fetch", "--quiet", "origin"); err != nil {
		return fmt.Errorf("gitops: fetching origin: %w", err)
	}
	// Prefer the remote-tracking ref so a moving branch fast-forwards; fall back to
	// the literal ref (a tag or commit SHA).
	target := "origin/" + ref
	if _, err := s.run(ctx, git, s.WorkDir, "rev-parse", "--verify", "--quiet", target); err != nil {
		target = ref
	}
	if _, err := s.run(ctx, git, s.WorkDir, "reset", "--hard", "--quiet", target); err != nil {
		return fmt.Errorf("gitops: checking out %q: %w", ref, err)
	}
	return nil
}

func (s *GitSource) run(ctx context.Context, git, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, git, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// embeddedRevision extracts a bundle-declared revision without a full parse, so a
// local source can prefer the author's stated revision over a content digest. It
// returns "" when no parseable revision is present.
func embeddedRevision(raw []byte) string {
	b, err := ParseBundle(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(b.Revision)
}
