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
	commit, rootTree, err := objs.ResolveCommit(ctx, rev)
	if err != nil {
		return nil, err
	}
	tree := rootTree
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
	if err := w.pinSubmodules(rootTree, root); err != nil {
		return nil, err
	}
	sort.Slice(w.found, func(i, j int) bool { return w.found[i].Path < w.found[j].Path })
	finish(w.found, opts.Proxy)
	rep.Files = dropEmpty(w.found)
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

// pinSubmodules turns the submodules of the root .gitmodules under root into
// dependencies, each pinned by the gitlink at its path. The walk finds the
// root .gitmodules when it walks the whole tree; for a directory of the tree
// it is read here, and reported only if it declares a submodule there (or
// cannot be read). Gitlinks are looked up in the tree whatever the skip globs
// say: a submodule in third_party/ is a dependency of this repository even
// though the lock files inside such a directory are not. Gitlinks no
// declaration names are reported as skipped.
func (w *walker) pinSubmodules(rootTree, root string) error {
	var gm *File
	for _, f := range w.found {
		if f.Path == gitmodulesPath && f.parser != nil && f.parser.Type() == "git" {
			gm = f
		}
	}
	if gm == nil && root != "" && !w.limitReached() {
		var err error
		if gm, err = w.readRootGitmodules(rootTree); err != nil {
			return err
		}
		if gm != nil && (gm.Error != "" || declaresUnder(gm, root)) {
			w.found = append(w.found, gm)
		}
	}
	links := w.rep.Submodules
	switch {
	case gm != nil && gm.Error != "":
		for _, l := range links {
			w.skipped(l.Path, "a submodule whose .gitmodules cannot be read: the repository it pins is unknown")
		}
		return nil
	case gm != nil:
		var paths []string
		for _, d := range gm.submodules {
			if underRoot(d.path, root) {
				paths = append(paths, d.path)
			}
		}
		pinned, complete, err := w.gitlinksAt(rootTree, paths)
		if err != nil {
			return err
		}
		if !complete {
			gm.addWarning(fmt.Sprintf("the submodule paths lead through more than %d tree entries; the submodules not reached are not pinned", w.opts.MaxTreeEntries))
		}
		lookup := func(p string) (string, error) { return pinned[p], nil }
		if links, err = joinSubmodules(gm, lookup, root, links); err != nil {
			return err
		}
	}
	for _, l := range links {
		w.skipped(l.Path, "a submodule .gitmodules does not declare: the repository it pins is unknown")
	}
	return nil
}

// declaresUnder reports whether a .gitmodules file declares a submodule
// inside root.
func declaresUnder(f *File, root string) bool {
	for _, d := range f.submodules {
		if underRoot(d.path, root) {
			return true
		}
	}
	return false
}

// limitReached reports whether the walk stopped at a limit.
func (w *walker) limitReached() bool { return w.rep.Truncated != "" }

// readRootGitmodules reads and parses the .gitmodules at the root of the tree,
// when a parser of the registry detects it and no skip glob matches it. It
// returns nil when there is none.
func (w *walker) readRootGitmodules(rootTree string) (*File, error) {
	parser := w.opts.Registry.Detect(gitmodulesPath)
	if parser == nil || matchAny(w.skip, gitmodulesPath, gitmodulesPath) {
		return nil, nil
	}
	entries, err := w.objs.ReadTree(w.ctx, rootTree)
	if err != nil {
		if errors.Is(err, git.ErrObjectNotFound) || errors.Is(err, git.ErrObjectTooLarge) || errors.Is(err, git.ErrMalformedObject) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.Name != gitmodulesPath || e.Kind != git.EntryFile {
			continue
		}
		info, err := w.objs.Info(w.ctx, e.ID)
		if err != nil {
			if errors.Is(err, git.ErrObjectNotFound) {
				w.skipped(gitmodulesPath, "the file's content is not in the repository (left out of a partial clone)")
				return nil, nil
			}
			return nil, err
		}
		if info.Size > w.opts.MaxFileBytes {
			w.skipped(gitmodulesPath, fmt.Sprintf("%d bytes, more than the %d-byte limit", info.Size, w.opts.MaxFileBytes))
			return nil, nil
		}
		data, err := w.objs.ReadBlob(w.ctx, e.ID, w.opts.MaxFileBytes)
		if err != nil {
			if errors.Is(err, git.ErrObjectNotFound) || errors.Is(err, git.ErrObjectTooLarge) {
				w.skipped(gitmodulesPath, "not readable: "+err.Error())
				return nil, nil
			}
			return nil, err
		}
		w.rep.Stats.BytesRead += int64(len(data))
		return parseOne(parser, gitmodulesPath, data), nil
	}
	return nil, nil
}

// pathNode is a directory or entry on the way to declared submodule paths.
type pathNode struct {
	path     string
	tree     string // the tree object of a directory, once found
	children map[string]*pathNode
	leaf     bool // a declared path ends here
}

// gitlinksAt finds the gitlinks at the declared paths: the commit each pins,
// keyed by path ("" or absent when the tree has no gitlink there). The paths
// come from .gitmodules and are never handed to git: the lookup descends from
// the root tree one level at a time, reading each tree object once per level
// whatever number of paths lead through it, scanning its entries once for
// every name wanted from it, and keeping nothing of it afterwards. The
// entries read count against MaxTreeEntries; complete is false when the
// budget ran out first. Paths deeper than MaxDepth are not followed.
func (w *walker) gitlinksAt(rootTree string, paths []string) (pinned map[string]string, complete bool, err error) {
	pinned = map[string]string{}
	root := &pathNode{tree: rootTree, children: map[string]*pathNode{}}
	for _, p := range paths {
		parts := strings.Split(p, "/")
		if len(parts) > w.opts.MaxDepth+1 {
			continue
		}
		n := root
		for _, name := range parts {
			child := n.children[name]
			if child == nil {
				child = &pathNode{children: map[string]*pathNode{}}
				if n.path == "" {
					child.path = name
				} else {
					child.path = n.path + "/" + name
				}
				n.children[name] = child
			}
			n = child
		}
		n.leaf = true
	}
	budget := w.opts.MaxTreeEntries
	level := []*pathNode{root}
	for len(level) > 0 {
		if err := w.ctx.Err(); err != nil {
			return nil, false, err
		}
		byTree := map[string][]*pathNode{}
		var trees []string
		for _, n := range level {
			if _, ok := byTree[n.tree]; !ok {
				trees = append(trees, n.tree)
			}
			byTree[n.tree] = append(byTree[n.tree], n)
		}
		var next []*pathNode
		for _, id := range trees {
			nodes := byTree[id]
			entries, err := w.objs.ReadTree(w.ctx, id)
			if err != nil {
				if errors.Is(err, git.ErrObjectNotFound) || errors.Is(err, git.ErrObjectTooLarge) || errors.Is(err, git.ErrMalformedObject) {
					continue
				}
				return nil, false, err
			}
			w.rep.Stats.Trees++
			budget -= len(entries)
			if budget < 0 {
				return pinned, false, nil
			}
			wanted := map[string]bool{}
			for _, n := range nodes {
				for name := range n.children {
					wanted[name] = true
				}
			}
			found := make(map[string]git.TreeEntry, len(wanted))
			for _, e := range entries {
				if wanted[e.Name] {
					found[e.Name] = e
				}
			}
			for _, n := range nodes {
				for name, child := range n.children {
					e, ok := found[name]
					if !ok {
						continue
					}
					switch {
					case child.leaf && e.Kind == git.EntrySubmodule:
						pinned[child.path] = e.ID
					case len(child.children) > 0 && e.Kind == git.EntryTree:
						child.tree = e.ID
						next = append(next, child)
					}
				}
			}
		}
		level = next
	}
	return pinned, true, nil
}

// GitDependencies returns every dependency fetched from a Git repository:
// the submodules .gitmodules declares and the Git dependencies of every other
// lock file, in path order.
func (r *Report) GitDependencies() []Dependency {
	var out []Dependency
	for _, f := range r.Files {
		for _, d := range f.Dependencies {
			if d.Source == SourceGit {
				out = append(out, d)
			}
		}
	}
	return out
}
