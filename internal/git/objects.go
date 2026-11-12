package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file is read access to a repository's object database: what a commit's
// tree holds, and the bytes of a file in it, without a working-tree checkout.
// The lock-file scanner (internal/lockfiles) walks a commit through it; it
// works on the bare mirrors this package maintains (Mirror) as well as on any
// local repository, bare or not.
//
// Objects are read through one long-running `git cat-file --batch-command`
// process per reader, the same git binary the mirrors already depend on: one
// process start for a whole walk, not one per object. Every read asks for the
// object's size first ("info") and fetches the content ("contents") only when
// it fits the caller's limit, so an oversized object is never read into
// memory.
//
// What the reader hands out comes from a repository nobody vouched for. Tree
// objects are parsed here (parseTree), strictly: an entry with a name a
// checkout could not produce ("", ".", "..", anything with "/" or NUL), an
// unknown mode or a short hash fails the whole tree, rather than reaching a
// caller as a path.

// Object types.
const (
	ObjectBlob   = "blob"
	ObjectTree   = "tree"
	ObjectCommit = "commit"
	ObjectTag    = "tag"
)

var (
	// ErrObjectNotFound is returned for a name that does not resolve to an
	// object in the repository (or to an object of the expected type).
	ErrObjectNotFound = errors.New("git: object not found")
	// ErrObjectTooLarge is returned when an object exceeds the caller's limit.
	// The content has not been read.
	ErrObjectTooLarge = errors.New("git: object exceeds the size limit")
	// ErrReaderClosed is returned by a reader that was closed, or whose git
	// process ended (after a cancelled read, for one).
	ErrReaderClosed = errors.New("git: object reader is closed")
	// ErrMalformedObject is returned for an object git could read but this
	// package will not interpret: a tree with an entry no checkout could
	// produce, an unknown mode, a truncated hash.
	ErrMalformedObject = errors.New("git: malformed object")
)

// ObjectInfo is an object's identity as the repository reports it.
type ObjectInfo struct {
	// ID is the full object ID in hex (40 characters for SHA-1, 64 for SHA-256).
	ID   string
	Type string
	Size int64
}

// EntryKind classifies a tree entry by its mode.
type EntryKind int

const (
	// EntryFile is a regular file (mode 100644, or 100755 when executable).
	EntryFile EntryKind = iota
	// EntrySymlink is a symbolic link (mode 120000); its blob holds the target.
	EntrySymlink
	// EntryTree is a directory (mode 40000).
	EntryTree
	// EntrySubmodule is a gitlink (mode 160000): a commit of another repository.
	EntrySubmodule
)

func (k EntryKind) String() string {
	switch k {
	case EntryFile:
		return "file"
	case EntrySymlink:
		return "symlink"
	case EntryTree:
		return "tree"
	case EntrySubmodule:
		return "submodule"
	}
	return "unknown"
}

// TreeEntry is one entry of a tree object.
type TreeEntry struct {
	Name string
	// Mode is the entry's mode as stored (e.g. 0o100644).
	Mode uint32
	Kind EntryKind
	// ID is the object the entry points at, in hex.
	ID string
}

// ObjectReaderOptions configures an ObjectReader.
type ObjectReaderOptions struct {
	// GitBinary is the git executable (default "git", resolved on PATH).
	GitBinary string
	// MaxTreeBytes bounds the size of a tree object ReadTree loads. Default
	// 16 MiB — a directory of some 300 000 entries.
	MaxTreeBytes int64
	// AllowLazyFetch lets git fetch an object a partial clone left out from
	// the repository's promisor remote — what any git command in a partial
	// clone does. Off, such an object cannot be read, and git ends the reader
	// when asked for it. Leave it off for repositories this process cloned
	// itself (CloneForScan unsets the promisor remote anyway) and for mirrors,
	// which are complete.
	AllowLazyFetch bool
}

// DefaultMaxTreeBytes is ObjectReaderOptions.MaxTreeBytes's default.
const DefaultMaxTreeBytes = 16 << 20

// ObjectReader reads objects from one local repository. It is safe for
// concurrent use; requests are served one at a time. Close it when done: it
// owns a git process.
type ObjectReader struct {
	maxTree int64

	mu     sync.Mutex
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr *boundedBuffer
	done   chan struct{} // closed when the process has exited
	err    error         // sticky: why the reader stopped working
	hexLen int           // 40 or 64 once known, 0 before
}

// OpenObjectReader starts reading the repository at dir: a bare repository, a
// ".git" directory or a working tree (whose objects, not files, are read).
func OpenObjectReader(dir string, opts ObjectReaderOptions) (*ObjectReader, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("git: repository directory is required")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("git: opening repository: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("git: opening repository: %s is not a directory", dir)
	}
	gitBin := opts.GitBinary
	if gitBin == "" {
		gitBin = "git"
	}
	resolved, err := exec.LookPath(gitBin)
	if err != nil {
		return nil, fmt.Errorf("git: git binary %q not found: %w", gitBin, err)
	}
	maxTree := opts.MaxTreeBytes
	if maxTree <= 0 {
		maxTree = DefaultMaxTreeBytes
	}

	// The process outlives any one request, so it is not bound to a request's
	// context: a cancelled request kills it explicitly (see roundTrip).
	cmd := exec.Command(resolved, "-C", dir, "cat-file", "--batch-command")
	cmd.Env = objectReaderEnv(opts.AllowLazyFetch)
	ownProcessGroup(cmd)
	cmd.WaitDelay = processWaitDelay
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("git: starting object reader: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: starting object reader: %w", err)
	}
	stderr := &boundedBuffer{max: 4 << 10}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git: starting object reader: %w", err)
	}
	r := &ObjectReader{
		maxTree: maxTree,
		cmd:     cmd,
		in:      stdin,
		out:     bufio.NewReaderSize(stdout, 64<<10),
		stderr:  stderr,
		done:    make(chan struct{}),
	}
	go func() {
		_ = cmd.Wait()
		close(r.done)
	}()
	return r, nil
}

// objectReaderEnv is the environment of the cat-file process: never prompt,
// unless allowed never fetch a missing object from a promisor remote (a scan
// reads what the repository holds), and read the objects themselves, not
// replacements a refs/replace/ ref substitutes.
func objectReaderEnv(lazyFetch bool) []string {
	env := append(os.Environ(), baseGitEnv...)
	env = append(env, "GIT_NO_REPLACE_OBJECTS=1")
	if !lazyFetch {
		env = append(env, "GIT_NO_LAZY_FETCH=1")
	}
	return env
}

// Close ends the git process.
func (r *ObjectReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = ErrReaderClosed
	}
	_ = r.in.Close()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		_ = killProcessGroup(r.cmd)
		<-r.done
	}
	return nil
}

// processWaitDelay bounds how long waiting for a killed git process may take
// when something it started still holds its pipes.
const processWaitDelay = 5 * time.Second

// HexLen returns the length of an object ID in hex: 40 in a SHA-1
// repository, 64 in a SHA-256 one, or 0 before the first object was read.
func (r *ObjectReader) HexLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hexLen
}

// Info looks an object up by name — an ID, a ref, or any revision expression
// git accepts ("HEAD", "v1.2^{commit}", "<commit>:<path>") — and returns its
// ID, type and size.
func (r *ObjectReader) Info(ctx context.Context, name string) (ObjectInfo, error) {
	if err := validObjectName(name); err != nil {
		return ObjectInfo{}, err
	}
	var info ObjectInfo
	err := r.roundTrip(ctx, func() error {
		var err error
		info, err = r.request("info", name)
		return err
	})
	return info, err
}

// ResolveCommit resolves rev to a commit and returns the commit's ID and the
// ID of its root tree.
func (r *ObjectReader) ResolveCommit(ctx context.Context, rev string) (commitID, treeID string, err error) {
	if strings.TrimSpace(rev) == "" {
		rev = "HEAD"
	}
	commit, err := r.Info(ctx, rev+"^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("git: resolving %q: %w", rev, err)
	}
	tree, err := r.Info(ctx, commit.ID+"^{tree}")
	if err != nil {
		return "", "", fmt.Errorf("git: reading the tree of %s: %w", commit.ID, err)
	}
	if tree.Type != ObjectTree {
		return "", "", fmt.Errorf("git: the tree of %s is a %s", commit.ID, tree.Type)
	}
	return commit.ID, tree.ID, nil
}

// ReadTree reads a tree object's entries, in the order the tree stores them.
func (r *ObjectReader) ReadTree(ctx context.Context, id string) ([]TreeEntry, error) {
	if !isHexID(id) {
		return nil, fmt.Errorf("git: %q is not an object ID", id)
	}
	var entries []TreeEntry
	err := r.roundTrip(ctx, func() error {
		data, err := r.readObject(id, ObjectTree, r.maxTree)
		if err != nil {
			return err
		}
		entries, err = parseTree(data, r.hexLen/2)
		return err
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// ReadBlob reads a blob, refusing (with ErrObjectTooLarge, without reading it)
// one larger than max bytes.
func (r *ObjectReader) ReadBlob(ctx context.Context, id string, max int64) ([]byte, error) {
	if !isHexID(id) {
		return nil, fmt.Errorf("git: %q is not an object ID", id)
	}
	var data []byte
	err := r.roundTrip(ctx, func() error {
		var err error
		data, err = r.readObject(id, ObjectBlob, max)
		return err
	})
	return data, err
}

// roundTrip runs one exchange with the git process under the lock, killing the
// process if ctx ends first — a read blocked on the pipe cannot be interrupted
// any other way. A reader whose process was killed stays unusable.
func (r *ObjectReader) roundTrip(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	stop := context.AfterFunc(ctx, func() { _ = killProcessGroup(r.cmd) })
	err := fn()
	if !stop() {
		// The context ended during the exchange and the process is gone.
		r.err = fmt.Errorf("%w: %v", ErrReaderClosed, ctx.Err())
		return ctx.Err()
	}
	if err != nil && isFatal(err) {
		r.err = err
	}
	return err
}

// fatalError marks an error after which the protocol stream is out of step.
type fatalError struct{ err error }

func (e fatalError) Error() string { return e.err.Error() }
func (e fatalError) Unwrap() error { return e.err }

func isFatal(err error) bool {
	var f fatalError
	return errors.As(err, &f)
}

// request sends one command and reads its header line. It must be called with
// r.mu held.
func (r *ObjectReader) request(cmd, name string) (ObjectInfo, error) {
	if _, err := io.WriteString(r.in, cmd+" "+name+"\n"); err != nil {
		return ObjectInfo{}, r.processError(err)
	}
	line, err := r.out.ReadString('\n')
	if err != nil {
		return ObjectInfo{}, r.processError(err)
	}
	line = strings.TrimSuffix(line, "\n")
	if rest, ok := strings.CutSuffix(line, " missing"); ok && rest == name {
		return ObjectInfo{}, fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	if rest, ok := strings.CutSuffix(line, " ambiguous"); ok && rest == name {
		return ObjectInfo{}, fmt.Errorf("%w: %s is ambiguous", ErrObjectNotFound, name)
	}
	info, ok := parseInfoLine(line)
	if !ok {
		return ObjectInfo{}, fatalError{fmt.Errorf("git: unexpected cat-file reply %q", truncate(line, 120))}
	}
	if r.hexLen == 0 {
		r.hexLen = len(info.ID)
	} else if len(info.ID) != r.hexLen {
		return ObjectInfo{}, fatalError{fmt.Errorf("git: cat-file reported an object ID of %d hex digits after %d", len(info.ID), r.hexLen)}
	}
	return info, nil
}

// readObject reads an object of the given type whose size is at most max. It
// must be called with r.mu held.
func (r *ObjectReader) readObject(id, wantType string, max int64) ([]byte, error) {
	info, err := r.request("info", id)
	if err != nil {
		return nil, err
	}
	if info.Type != wantType {
		return nil, fmt.Errorf("%w: %s is a %s, not a %s", ErrObjectNotFound, id, info.Type, wantType)
	}
	if max >= 0 && info.Size > max {
		return nil, fmt.Errorf("%w: %s is %d bytes (limit %d)", ErrObjectTooLarge, id, info.Size, max)
	}
	got, err := r.request("contents", id)
	if err != nil {
		return nil, err
	}
	if got.ID != info.ID || got.Size != info.Size || got.Type != info.Type {
		return nil, fatalError{fmt.Errorf("git: cat-file answered for %s with a different object", id)}
	}
	buf := make([]byte, got.Size+1) // the content and its trailing newline
	if _, err := io.ReadFull(r.out, buf); err != nil {
		return nil, r.processError(err)
	}
	if buf[len(buf)-1] != '\n' {
		return nil, fatalError{errors.New("git: cat-file reply is not terminated")}
	}
	return buf[:len(buf)-1], nil
}

// processError describes a failed exchange: usually the git process ended, and
// what it said on stderr is the reason.
func (r *ObjectReader) processError(err error) error {
	// A broken pipe or an EOF means git is exiting; what it says on stderr is
	// complete once the process has been waited for.
	select {
	case <-r.done:
	case <-time.After(2 * time.Second):
	}
	msg := strings.TrimSpace(r.stderr.String())
	if strings.Contains(msg, "batch-command") && strings.Contains(msg, "unknown") {
		msg = "this git does not support cat-file --batch-command (git 2.36 or newer is required)"
	}
	if msg != "" {
		return fatalError{fmt.Errorf("git: object reader: %s", RedactURLSecrets(truncate(msg, 300)))}
	}
	return fatalError{fmt.Errorf("git: object reader: %w", err)}
}

// parseInfoLine parses "<id> <type> <size>".
func parseInfoLine(line string) (ObjectInfo, bool) {
	f := strings.Split(line, " ")
	if len(f) != 3 || !isHexID(f[0]) {
		return ObjectInfo{}, false
	}
	switch f[1] {
	case ObjectBlob, ObjectTree, ObjectCommit, ObjectTag:
	default:
		return ObjectInfo{}, false
	}
	size, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil || size < 0 {
		return ObjectInfo{}, false
	}
	return ObjectInfo{ID: f[0], Type: f[1], Size: size}, true
}

// isHexID reports whether s is a full object ID in lower-case hex.
func isHexID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validObjectName rejects a name the batch protocol cannot carry (a line
// break would start a second command) or that is not a revision at all.
func validObjectName(name string) error {
	if name == "" {
		return errors.New("git: empty object name")
	}
	if len(name) > 4096 {
		return errors.New("git: object name too long")
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || c == 0x7f {
			return errors.New("git: object name contains a control character")
		}
	}
	return nil
}

// parseTree parses the content of a tree object: entries of
// "<octal mode> <name>\x00<raw hash>". hashLen is the raw hash length (20 or
// 32); 0 means "work it out" — only possible for a tree of one entry, so
// callers pass the repository's length.
func parseTree(data []byte, hashLen int) ([]TreeEntry, error) {
	if hashLen != 20 && hashLen != 32 {
		return nil, fmt.Errorf("%w: unsupported object ID length %d", ErrMalformedObject, hashLen)
	}
	var entries []TreeEntry
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp <= 0 || sp > 6 {
			return nil, fmt.Errorf("%w: tree entry mode", ErrMalformedObject)
		}
		mode, err := parseMode(data[:sp])
		if err != nil {
			return nil, err
		}
		data = data[sp+1:]
		nul := bytes.IndexByte(data, 0)
		if nul < 0 {
			return nil, fmt.Errorf("%w: tree entry name is not terminated", ErrMalformedObject)
		}
		name := string(data[:nul])
		if err := validEntryName(name); err != nil {
			return nil, err
		}
		data = data[nul+1:]
		if len(data) < hashLen {
			return nil, fmt.Errorf("%w: tree entry hash is truncated", ErrMalformedObject)
		}
		id := fmt.Sprintf("%x", data[:hashLen])
		data = data[hashLen:]

		var kind EntryKind
		switch mode & 0o170000 {
		case 0o100000:
			kind = EntryFile
		case 0o120000:
			kind = EntrySymlink
		case 0o040000:
			kind = EntryTree
		case 0o160000:
			kind = EntrySubmodule
		default:
			return nil, fmt.Errorf("%w: tree entry has unknown mode %o", ErrMalformedObject, mode)
		}
		entries = append(entries, TreeEntry{Name: name, Mode: mode, Kind: kind, ID: id})
	}
	return entries, nil
}

// parseMode parses a tree entry's octal mode.
func parseMode(b []byte) (uint32, error) {
	var mode uint32
	for _, c := range b {
		if c < '0' || c > '7' {
			return 0, fmt.Errorf("%w: tree entry mode", ErrMalformedObject)
		}
		mode = mode<<3 | uint32(c-'0')
	}
	return mode, nil
}

// validEntryName accepts the names git itself would write: non-empty, not "."
// or "..", no "/" and no NUL (the parser already split on NUL).
func validEntryName(name string) error {
	switch {
	case name == "", name == ".", name == "..":
		return fmt.Errorf("%w: tree entry has an invalid name %q", ErrMalformedObject, name)
	case strings.ContainsRune(name, '/'):
		return fmt.Errorf("%w: tree entry name contains '/'", ErrMalformedObject)
	case len(name) > 4096:
		return fmt.Errorf("%w: tree entry name too long", ErrMalformedObject)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// boundedBuffer keeps the first max bytes written to it.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// urlUserinfo matches the userinfo part of a URL ("scheme://user:secret@").
var urlUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]*@`)

// linkTokenRun matches a personal cache link token (internal/userlinks) and
// anything spelled like the start of one.
var linkTokenRun = regexp.MustCompile(`ptl1[a-z0-9]*`)

// RedactURLSecrets removes credentials from text that may quote a URL — git's
// error messages do: the userinfo of a URL, and personal cache link tokens
// ("…/u/ptl1…/v1/…").
func RedactURLSecrets(s string) string {
	s = urlUserinfo.ReplaceAllString(s, "${1}***@")
	return linkTokenRun.ReplaceAllString(s, "<link>")
}

// Repository is where a local path sits in a Git repository.
type Repository struct {
	// GitDir is the repository's object database directory (".git", or the
	// bare repository itself), absolute.
	GitDir string
	// Prefix is the path's directory relative to the top of the working tree
	// ("services/api"), slash-separated; "" at the top or in a bare repository.
	Prefix string
}

// LocateRepository finds the repository a local path belongs to. It reads
// nothing of the working tree.
func LocateRepository(ctx context.Context, dir, gitBinary string) (Repository, error) {
	if gitBinary == "" {
		gitBinary = "git"
	}
	resolved, err := exec.LookPath(gitBinary)
	if err != nil {
		return Repository{}, fmt.Errorf("git: git binary %q not found: %w", gitBinary, err)
	}
	cmd := exec.CommandContext(ctx, resolved, "-C", dir, "rev-parse", "--absolute-git-dir", "--show-prefix")
	cmd.Env = append(os.Environ(), baseGitEnv...)
	isolateProcess(cmd)
	cmd.WaitDelay = processWaitDelay
	var stderr boundedBuffer
	stderr.max = 4 << 10
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return Repository{}, fmt.Errorf("git: %s is not in a git repository: %s", dir, RedactURLSecrets(truncate(msg, 300)))
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	repo := Repository{GitDir: strings.TrimSpace(lines[0])}
	if len(lines) > 1 {
		repo.Prefix = strings.Trim(strings.TrimSpace(lines[1]), "/")
	}
	if repo.GitDir == "" {
		return Repository{}, fmt.Errorf("git: %s is not in a git repository", dir)
	}
	return repo, nil
}

// ScanCloneOptions configures CloneForScan.
type ScanCloneOptions struct {
	// URL is the repository to fetch: https://, http://, ssh://, git://,
	// file:// or scp-like "user@host:path".
	URL string
	// Dir is the directory to create the bare repository in. It must not exist
	// or be empty.
	Dir string
	// Rev is the branch, tag or commit to fetch; empty fetches the remote's
	// default branch (HEAD).
	Rev string
	// MaxBlobBytes leaves out every blob larger than this (a partial clone with
	// a blob:limit filter), so a file too large to scan is never downloaded.
	// Zero leaves nothing out.
	MaxBlobBytes int64
	// GitBinary is the git executable (default "git").
	GitBinary string
}

// CloneForScan fetches one revision of a remote repository into a new bare
// repository for reading through an ObjectReader, as cheaply as the server
// allows: one commit deep, without the blobs larger than MaxBlobBytes. It
// returns the ID of the fetched commit.
//
// A server that will not hand out a commit by ID (or an abbreviated ID) is
// asked for every branch and tag instead, and the revision is resolved
// locally. The repository is left without its promisor remote, so a reader
// finds a left-out blob missing instead of fetching it.
func CloneForScan(ctx context.Context, opts ScanCloneOptions) (string, error) {
	url := strings.TrimSpace(opts.URL)
	if err := validCloneURL(url); err != nil {
		return "", err
	}
	rev := strings.TrimSpace(opts.Rev)
	if rev != "" {
		if err := validObjectName(rev); err != nil {
			return "", fmt.Errorf("git: revision: %w", err)
		}
		if strings.HasPrefix(rev, "-") || strings.ContainsAny(rev, " \t") {
			return "", errors.New("git: a revision must not start with '-' or contain spaces")
		}
	}
	gitBin := opts.GitBinary
	if gitBin == "" {
		gitBin = "git"
	}
	resolved, err := exec.LookPath(gitBin)
	if err != nil {
		return "", fmt.Errorf("git: git binary %q not found: %w", gitBin, err)
	}
	if entries, err := os.ReadDir(opts.Dir); err == nil && len(entries) > 0 {
		return "", fmt.Errorf("git: clone directory %s is not empty", opts.Dir)
	}

	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, resolved, args...)
		// A server that stops sending ends the fetch after a minute, and a
		// cancelled context kills git with every helper it started.
		cmd.Env = append(append(os.Environ(), baseGitEnv...),
			"GIT_HTTP_LOW_SPEED_LIMIT=1000", "GIT_HTTP_LOW_SPEED_TIME=60")
		isolateProcess(cmd)
		cmd.WaitDelay = processWaitDelay
		var out boundedBuffer
		out.max = 8 << 10
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return RedactURLSecrets(strings.TrimSpace(out.String())), err
	}
	// Transports that run programs ("ext::") are never wanted here.
	safe := []string{"-c", "protocol.ext.allow=never", "-c", "core.hooksPath=/dev/null"}

	if out, err := run("init", "--bare", "--quiet", opts.Dir); err != nil {
		return "", fmt.Errorf("git: init: %w (%s)", err, out)
	}
	if out, err := run("-C", opts.Dir, "remote", "add", "origin", url); err != nil {
		return "", fmt.Errorf("git: remote add: %w (%s)", err, out)
	}
	fetch := append(append([]string{}, safe...), "-C", opts.Dir, "fetch", "--quiet", "--no-tags")
	if opts.MaxBlobBytes > 0 {
		fetch = append(fetch, fmt.Sprintf("--filter=blob:limit=%d", opts.MaxBlobBytes))
	}
	want := rev
	if want == "" {
		want = "HEAD"
	}
	shallow := append(append([]string{}, fetch...), "--depth=1", "origin", want)
	out, err := run(shallow...)
	target := "FETCH_HEAD"
	if err != nil {
		if rev == "" {
			return "", fmt.Errorf("git: fetching %s: %w (%s)", RedactURLSecrets(url), err, out)
		}
		// The server would not serve the revision by name: fetch every branch
		// and tag and resolve it here.
		full := append(append([]string{}, fetch...), "origin",
			"+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*")
		if out2, err2 := run(full...); err2 != nil {
			return "", fmt.Errorf("git: fetching %s: %w (%s)", RedactURLSecrets(url), err2, out2)
		}
		target = rev
	}
	// A left-out blob must read as missing, not be fetched on demand: while
	// origin is a promisor remote, git either fetches the blob (whatever its
	// size) or, with lazy fetching off, dies instead of answering "missing".
	for _, key := range []string{"remote.origin.promisor", "remote.origin.partialclonefilter", "extensions.partialClone"} {
		_, _ = run("-C", opts.Dir, "config", "--unset-all", key)
	}

	commit, err := run("-C", opts.Dir, "rev-parse", "--verify", "--quiet", "--end-of-options", target+"^{commit}")
	if err != nil || !isHexID(commit) {
		if target != rev {
			return "", fmt.Errorf("git: the fetched revision is not a commit")
		}
		// An unqualified branch name lives under refs/remotes/origin/ now.
		commit, err = run("-C", opts.Dir, "rev-parse", "--verify", "--quiet", "--end-of-options", "refs/remotes/origin/"+rev+"^{commit}")
		if err != nil || !isHexID(commit) {
			return "", fmt.Errorf("git: revision %q not found in %s", rev, RedactURLSecrets(url))
		}
	}
	return commit, nil
}

// validCloneURL accepts the URL forms CloneForScan fetches from, and nothing
// that git would read as an option or a program to run.
func validCloneURL(url string) error {
	switch {
	case url == "":
		return errors.New("git: repository URL is required")
	case strings.HasPrefix(url, "-"):
		return errors.New("git: repository URL must not start with '-'")
	case strings.ContainsAny(url, "\x00\n\r"):
		return errors.New("git: repository URL contains a control character")
	}
	lower := strings.ToLower(url)
	for _, scheme := range []string{"https://", "http://", "ssh://", "git://", "file://"} {
		if strings.HasPrefix(lower, scheme) {
			return nil
		}
	}
	if strings.Contains(url, "::") {
		return errors.New("git: remote-helper URLs (\"<transport>::<address>\") are not accepted")
	}
	if scpLike(url) {
		return nil
	}
	return fmt.Errorf("git: unsupported repository URL %q (want https://, ssh://, git://, file:// or user@host:path)", RedactURLSecrets(url))
}
