package lockfiles

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/git"
)

// Objects is the object access a scan reads a tree through.
// *git.ObjectReader implements it.
type Objects interface {
	ResolveCommit(ctx context.Context, rev string) (commitID, treeID string, err error)
	Info(ctx context.Context, name string) (git.ObjectInfo, error)
	ReadTree(ctx context.Context, id string) ([]git.TreeEntry, error)
	ReadBlob(ctx context.Context, id string, max int64) ([]byte, error)
}

var _ Objects = (*git.ObjectReader)(nil)

// Default limits of a scan.
const (
	DefaultMaxDepth       = 24
	DefaultMaxFileBytes   = 32 << 20
	DefaultMaxFiles       = 2000
	DefaultMaxTotalBytes  = 512 << 20
	DefaultMaxTreeEntries = 2_000_000
)

// DefaultSkip are the globs a scan skips unless told otherwise: directories of
// vendored code — whose lock files pin another project's dependencies, and
// which a package manager rewrites at will — and of test fixtures, whose lock
// files describe no build at all.
var DefaultSkip = []string{
	// Vendored and installed dependencies.
	"node_modules", "bower_components", "jspm_packages", ".pnpm-store", ".yarn",
	"vendor", "third_party", "third-party", "thirdparty",
	".venv", "venv", "site-packages", "__pypackages__", ".tox", ".nox",
	".bundle", "Pods", "Carthage", ".terraform", "target",
	// Test fixtures.
	"testdata", "test-data", "fixtures", "__fixtures__", "test-fixtures",
	"**/test/data", "**/tests/data",
}

// Options configures a scan.
type Options struct {
	// Registry holds the parsers; nil is DefaultRegistry().
	Registry *Registry
	// Proxy maps URLs that point at the proxy back to its upstreams; nil
	// knows no deployment (personal links and intercepted URLs are still
	// recognised).
	Proxy *Proxy
	// Root is the directory of the tree to scan, slash-separated; "" is the
	// whole tree. Reported paths stay relative to the repository root.
	Root string
	// Skip are the globs of paths not to scan; nil is DefaultSkip, an empty
	// slice skips nothing. A glob without "/" matches a directory or file
	// name at any depth ("node_modules"); one with "/" matches the path from
	// the repository root, "**" matching any number of directories
	// ("**/test/data", "docs/examples/*").
	Skip []string
	// MaxDepth is how many directories deep the walk descends below Root.
	MaxDepth int
	// MaxFileBytes is the largest lock file read; a larger one is reported as
	// skipped without being read.
	MaxFileBytes int64
	// MaxFiles, MaxTotalBytes and MaxTreeEntries end the walk early: after so
	// many lock files, so many bytes of them, or so many tree entries seen.
	MaxFiles       int
	MaxTotalBytes  int64
	MaxTreeEntries int
}

func (o Options) withDefaults() Options {
	if o.Registry == nil {
		o.Registry = DefaultRegistry()
	}
	if o.Skip == nil {
		o.Skip = DefaultSkip
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = DefaultMaxFiles
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if o.MaxTreeEntries <= 0 {
		o.MaxTreeEntries = DefaultMaxTreeEntries
	}
	return o
}

// Report is the outcome of a scan.
type Report struct {
	// Commit is the commit scanned; Root the directory of it, if not all.
	Commit string `json:"commit"`
	Root   string `json:"root,omitempty"`
	// Files are the lock files found, by path.
	Files []*File `json:"files"`
	// Skipped are paths the walk found and did not read: lock files over the
	// size limit or missing from the clone, symbolic links named like lock
	// files, and directories it did not enter.
	Skipped []Skipped `json:"skipped,omitempty"`
	// Submodules are the gitlinks in the tree: other repositories pinned at a
	// commit.
	Submodules []Submodule `json:"submodules,omitempty"`
	// Truncated says why the walk ended before seeing the whole tree, when it
	// did.
	Truncated string `json:"truncated,omitempty"`
	// Stats count what the walk did.
	Stats Stats `json:"stats"`
}

// Skipped is a path the walk found and did not read.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Submodule is a gitlink in the tree.
type Submodule struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

// Stats count what a walk did.
type Stats struct {
	Trees       int   `json:"trees"`
	Entries     int   `json:"entries"`
	LockFiles   int   `json:"lockFiles"`
	BytesRead   int64 `json:"bytesRead"`
	SkippedDirs int   `json:"skippedDirs"`
}

// Dependencies returns every dependency of every file, in path order.
func (r *Report) Dependencies() []Dependency {
	var out []Dependency
	for _, f := range r.Files {
		out = append(out, f.Dependencies...)
	}
	return out
}

// maxSkippedReported bounds Report.Skipped; Stats.SkippedDirs keeps counting.
const maxSkippedReported = 500

// Scan walks the tree of rev (a commit, branch, tag, or any revision the
// repository resolves) and parses every lock file in it.
func Scan(ctx context.Context, objs Objects, rev string, opts Options) (*Report, error) {
	opts = opts.withDefaults()
	skip, err := compileGlobs(opts.Skip)
	if err != nil {
		return nil, err
	}
	root := strings.Trim(path.Clean("/"+strings.TrimSpace(opts.Root)), "/")
	commit, tree, err := objs.ResolveCommit(ctx, rev)
	if err != nil {
		return nil, err
	}
	rep := &Report{Commit: commit, Root: root}
	if root != "" {
		info, err := objs.Info(ctx, commit+":"+root)
		if err != nil {
			return nil, fmt.Errorf("lockfiles: %s is not in commit %s: %w", root, commit, err)
		}
		if info.Type != git.ObjectTree {
			return nil, fmt.Errorf("lockfiles: %s is not a directory in commit %s", root, commit)
		}
		tree = info.ID
	}

	w := &walker{ctx: ctx, objs: objs, opts: opts, skip: skip, rep: rep}
	if err := w.walk(root, tree); err != nil {
		return nil, err
	}
	sort.Slice(w.found, func(i, j int) bool { return w.found[i].Path < w.found[j].Path })
	finish(w.found, opts.Proxy)
	rep.Files = w.found
	if rep.Files == nil {
		rep.Files = []*File{}
	}
	return rep, nil
}

type walker struct {
	ctx   context.Context
	objs  Objects
	opts  Options
	skip  []glob
	rep   *Report
	found []*File
}

// dirFrame is a directory waiting to be read.
type dirFrame struct {
	path  string
	tree  string
	depth int
}

// errStop ends the walk at a limit; the report says which.
var errStop = errors.New("lockfiles: walk limit reached")

func (w *walker) walk(root, tree string) error {
	stack := []dirFrame{{path: root, tree: tree}}
	for len(stack) > 0 {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := w.objs.ReadTree(w.ctx, dir.tree)
		if err != nil {
			if errors.Is(err, git.ErrObjectNotFound) || errors.Is(err, git.ErrObjectTooLarge) || errors.Is(err, git.ErrMalformedObject) {
				w.skipped(dir.path, "directory not readable: "+err.Error())
				continue
			}
			return err
		}
		w.rep.Stats.Trees++
		var subdirs []dirFrame
		for _, e := range entries {
			w.rep.Stats.Entries++
			if w.rep.Stats.Entries > w.opts.MaxTreeEntries {
				w.rep.Truncated = fmt.Sprintf("the tree has more than %d entries", w.opts.MaxTreeEntries)
				return nil
			}
			p := e.Name
			if dir.path != "" {
				p = dir.path + "/" + e.Name
			}
			switch e.Kind {
			case git.EntryTree:
				if matchAny(w.skip, p, e.Name) {
					w.rep.Stats.SkippedDirs++
					w.skipped(p+"/", "matches a skip glob")
					continue
				}
				if dir.depth+1 > w.opts.MaxDepth {
					w.rep.Stats.SkippedDirs++
					w.skipped(p+"/", fmt.Sprintf("deeper than %d directories", w.opts.MaxDepth))
					continue
				}
				subdirs = append(subdirs, dirFrame{path: p, tree: e.ID, depth: dir.depth + 1})
			case git.EntrySubmodule:
				w.rep.Submodules = append(w.rep.Submodules, Submodule{Path: p, Commit: e.ID})
			case git.EntrySymlink:
				if w.opts.Registry.Detect(p) != nil && !matchAny(w.skip, p, e.Name) {
					w.skipped(p, "a symbolic link; the walk does not follow links")
				}
			case git.EntryFile:
				if err := w.file(p, e); err != nil {
					if errors.Is(err, errStop) {
						return nil
					}
					return err
				}
			}
		}
		// Depth-first, in tree order: push in reverse.
		for i := len(subdirs) - 1; i >= 0; i-- {
			stack = append(stack, subdirs[i])
		}
	}
	return nil
}

// file reads and parses one tree entry, if a parser detects it.
func (w *walker) file(p string, e git.TreeEntry) error {
	parser := w.opts.Registry.Detect(p)
	if parser == nil || matchAny(w.skip, p, e.Name) {
		return nil
	}
	if len(w.found) >= w.opts.MaxFiles {
		w.rep.Truncated = fmt.Sprintf("more than %d lock files", w.opts.MaxFiles)
		return errStop
	}
	info, err := w.objs.Info(w.ctx, e.ID)
	if err != nil {
		if errors.Is(err, git.ErrObjectNotFound) {
			w.skipped(p, "the file's content is not in the repository (left out of a partial clone)")
			return nil
		}
		return err
	}
	if info.Size > w.opts.MaxFileBytes {
		w.skipped(p, fmt.Sprintf("%d bytes, more than the %d-byte limit", info.Size, w.opts.MaxFileBytes))
		return nil
	}
	if w.rep.Stats.BytesRead+info.Size > w.opts.MaxTotalBytes {
		w.rep.Truncated = fmt.Sprintf("the lock files hold more than %d bytes", w.opts.MaxTotalBytes)
		return errStop
	}
	data, err := w.objs.ReadBlob(w.ctx, e.ID, w.opts.MaxFileBytes)
	if err != nil {
		if errors.Is(err, git.ErrObjectNotFound) || errors.Is(err, git.ErrObjectTooLarge) {
			w.skipped(p, "not readable: "+err.Error())
			return nil
		}
		return err
	}
	w.rep.Stats.BytesRead += int64(len(data))
	w.rep.Stats.LockFiles++
	w.found = append(w.found, parseOne(parser, p, data))
	return nil
}

func (w *walker) skipped(p, reason string) {
	if len(w.rep.Skipped) < maxSkippedReported {
		w.rep.Skipped = append(w.rep.Skipped, Skipped{Path: p, Reason: reason})
	}
}
