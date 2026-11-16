package fullmirror

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// A Git-backed registry's feed is the difference between the trees of two
// head commits. The follower keeps the trees of the commit its cursor names
// (a "tree store" in Env.Dir, only the part of the repository the registry
// lives in), fetches the new head's trees — only those the stored commit
// lacks — and walks both, pruning every subtree whose id did not change. The
// difference does not depend on the history between the commits: the
// crates.io index squashes its history weekly, a force-push rewrites it, and
// the diff of the two trees is still exactly what changed.

// gitChange is how a file differs between two trees.
type gitChange int

const (
	gitAdded gitChange = iota + 1
	gitModified
	gitDeleted
)

// errGitTreeMissing reports a tree neither the fetch nor the store holds.
var errGitTreeMissing = errors.New("a tree is missing")

// gitLookup finds a tree by id.
type gitLookup func(gitOID) ([]byte, bool)

// gitArea says which directories of the repository the registry lives in:
// it is asked for every directory (by its path, "" for the root) before the
// walk descends into it.
type gitArea func(dir string) bool

// readTree loads and parses a tree.
func readTree(look gitLookup, id gitOID) ([]gitTreeEntry, error) {
	data, ok := look(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errGitTreeMissing, id)
	}
	return parseGitTree(data)
}

func joinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// walkGitTree calls fn for every file (blob or submodule) of the tree within
// the area, in path order.
func walkGitTree(look gitLookup, area gitArea, root gitOID, dir string, fn func(path string) error) error {
	entries, err := readTree(look, root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := joinPath(dir, e.name)
		if e.isTree() {
			if area(p) {
				if err := walkGitTree(look, area, e.id, p, fn); err != nil {
					return err
				}
			}
			continue
		}
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

// diffGitTrees calls fn for every file that differs between two trees within
// the area. Subtrees with the same id are not read.
func diffGitTrees(look gitLookup, area gitArea, oldRoot, newRoot gitOID, dir string, fn func(path string, c gitChange) error) error {
	if oldRoot == newRoot {
		return nil
	}
	oldEntries, err := readTree(look, oldRoot)
	if err != nil {
		return err
	}
	newEntries, err := readTree(look, newRoot)
	if err != nil {
		return err
	}
	oldBy := make(map[string]gitTreeEntry, len(oldEntries))
	for _, e := range oldEntries {
		oldBy[e.name] = e
	}
	newBy := make(map[string]gitTreeEntry, len(newEntries))
	for _, e := range newEntries {
		newBy[e.name] = e
	}
	all := make([]string, 0, len(oldBy)+len(newBy))
	for n := range oldBy {
		all = append(all, n)
	}
	for n := range newBy {
		if _, ok := oldBy[n]; !ok {
			all = append(all, n)
		}
	}
	sort.Strings(all)
	each := func(look gitLookup, id gitOID, p string, c gitChange) error {
		if !area(p) {
			return nil
		}
		return walkGitTree(look, area, id, p, func(path string) error { return fn(path, c) })
	}
	for _, n := range all {
		o, inOld := oldBy[n]
		nw, inNew := newBy[n]
		p := joinPath(dir, n)
		switch {
		case inOld && inNew && o.id == nw.id && o.isTree() == nw.isTree():
			continue
		case inOld && inNew && o.isTree() && nw.isTree():
			if area(p) {
				if err := diffGitTrees(look, area, o.id, nw.id, p, fn); err != nil {
					return err
				}
			}
		case inOld && inNew && !o.isTree() && !nw.isTree():
			if err := fn(p, gitModified); err != nil {
				return err
			}
		default:
			if inOld {
				if o.isTree() {
					if err := each(look, o.id, p, gitDeleted); err != nil {
						return err
					}
				} else if err := fn(p, gitDeleted); err != nil {
					return err
				}
			}
			if inNew {
				if nw.isTree() {
					if err := each(look, nw.id, p, gitAdded); err != nil {
						return err
					}
				} else if err := fn(p, gitAdded); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// gitTreeStore is the trees of one commit, within the registry's area.
type gitTreeStore struct {
	commit    gitOID
	root      gitOID
	committed time.Time
	trees     map[gitOID][]byte
}

func (s *gitTreeStore) lookup(id gitOID) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	d, ok := s.trees[id]
	return d, ok
}

// collectGitTrees gathers every tree reachable from root within the area.
func collectGitTrees(look gitLookup, area gitArea, root gitOID) (map[gitOID][]byte, error) {
	out := map[gitOID][]byte{}
	var visit func(id gitOID, dir string) error
	visit = func(id gitOID, dir string) error {
		if _, seen := out[id]; seen {
			return nil
		}
		data, ok := look(id)
		if !ok {
			return fmt.Errorf("%w: %s", errGitTreeMissing, id)
		}
		entries, err := parseGitTree(data)
		if err != nil {
			return err
		}
		out[id] = data
		for _, e := range entries {
			if p := joinPath(dir, e.name); e.isTree() && area(p) {
				if err := visit(e.id, p); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return out, visit(root, "")
}

// Tree store files: "<prefix><commit>.gz", a magic line, the commit, its root
// and commit time, then (id, length, data) per tree.
const gitStoreMagic = "pullthrough-git-trees-1\n"

// maxGitStore bounds a tree store read back.
const maxGitStore = 2 << 30

func gitStoreName(prefix string, commit gitOID) string { return prefix + commit.String() + ".gz" }

// saveGitTreeStore writes a store.
func saveGitTreeStore(fs files, prefix string, st *gitTreeStore) error {
	ids := make([]gitOID, 0, len(st.trees))
	for id := range st.trees {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
	return fs.write(gitStoreName(prefix, st.commit), func(w io.Writer) error {
		zw := gzip.NewWriter(w)
		bw := bufio.NewWriter(zw)
		bw.WriteString(gitStoreMagic)
		bw.Write(st.commit[:])
		bw.Write(st.root[:])
		var n [binary.MaxVarintLen64]byte
		bw.Write(n[:binary.PutVarint(n[:], st.committed.Unix())])
		bw.Write(n[:binary.PutUvarint(n[:], uint64(len(ids)))])
		for _, id := range ids {
			bw.Write(id[:])
			bw.Write(n[:binary.PutUvarint(n[:], uint64(len(st.trees[id])))])
			bw.Write(st.trees[id])
		}
		if err := bw.Flush(); err != nil {
			return err
		}
		return zw.Close()
	})
}

// loadGitTreeStore reads the store of a commit. A missing store is
// os.ErrNotExist; a damaged one — a tree whose content does not hash to its
// id, a root it does not hold — is an error.
func loadGitTreeStore(fs files, prefix string, commit gitOID) (*gitTreeStore, error) {
	if fs.dir == "" {
		return nil, errValidationOnly
	}
	fh, err := os.Open(fs.path(gitStoreName(prefix, commit)))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(io.LimitReader(zr, maxGitStore))
	magic := make([]byte, len(gitStoreMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != gitStoreMagic {
		return nil, errors.New("not a tree store")
	}
	st := &gitTreeStore{}
	if _, err := io.ReadFull(br, st.commit[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(br, st.root[:]); err != nil {
		return nil, err
	}
	if st.commit != commit {
		return nil, fmt.Errorf("the tree store of %s holds %s", commit, st.commit)
	}
	secs, err := binary.ReadVarint(br)
	if err != nil {
		return nil, err
	}
	if secs > 0 {
		st.committed = time.Unix(secs, 0).UTC()
	}
	n, err := binary.ReadUvarint(br)
	if err != nil || n > maxPackObjects {
		return nil, fmt.Errorf("a tree store of %d trees", n)
	}
	st.trees = make(map[gitOID][]byte, n)
	for i := uint64(0); i < n; i++ {
		var id gitOID
		if _, err := io.ReadFull(br, id[:]); err != nil {
			return nil, err
		}
		size, err := binary.ReadUvarint(br)
		if err != nil || size > maxGitObject {
			return nil, fmt.Errorf("a tree of %d bytes", size)
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, err
		}
		if hashObject(gitTree, data) != id {
			return nil, fmt.Errorf("the stored tree %s does not match its id", id)
		}
		st.trees[id] = data
	}
	if _, ok := st.trees[st.root]; !ok {
		return nil, errors.New("the tree store does not hold its root")
	}
	return st, nil
}

// gitIndexSpec is what distinguishes one Git-backed registry from another.
type gitIndexSpec struct {
	// typ is the upstream type.
	typ string
	// area is the part of the repository the registry lives in.
	area gitArea
	// coordinate maps a changed file to the change the engine works on; ok
	// false for a file that names no package (a README, CI configuration).
	coordinate func(path string, c gitChange) (Coordinate, bool)
}

// gitIndex follows a Git-backed registry.
type gitIndex struct {
	k      kit
	spec   gitIndexSpec
	remote *gitRemote
	branch string
	files  files
	// page is how many changes one batch carries at most.
	page int
}

// gitIndexFormat is the format of the Git feeds' cursors.
const gitIndexFormat = 1

// gitCursor is a Git-backed feed's position: the commit whose trees are
// stored, and while a difference (or the listing of Bootstrap) spans several
// batches, where the next batch starts in it.
type gitCursor struct {
	Format string `json:"format"`
	Commit string `json:"commit"`
	// To is the commit the difference leads to, Skip how many of its
	// changes earlier batches carried. Listing marks Bootstrap's listing of
	// Commit's files.
	To      string `json:"to,omitempty"`
	Skip    int    `json:"skip,omitempty"`
	Listing bool   `json:"listing,omitempty"`
}

func (c *gitCursor) cursorFormat() string { return c.Format }

const gitStorePrefix = "trees-"

// gitDefaultPage is how many changes one batch of a Git feed carries.
const gitDefaultPage = 50_000

// newGitIndex builds the Git machinery of an adapter: repo is the repository
// URL ("url" option or the public registry's), branch the "branch" option.
func newGitIndex(k kit, spec gitIndexSpec, repo *url.URL, branch string) (*gitIndex, error) {
	if branch != "" && (strings.ContainsAny(branch, " \t~^:?*[\\") || strings.Contains(branch, "..") || strings.HasPrefix(branch, "-")) {
		return nil, fmt.Errorf("option branch %q is not a branch name", branch)
	}
	return &gitIndex{k: k, spec: spec, remote: newGitRemote(k, repo), branch: branch, files: files{dir: k.env.Dir}, page: gitDefaultPage}, nil
}

func (g *gitIndex) format() string { return cursorFormat(g.spec.typ+"-git", gitIndexFormat) }

func (g *gitIndex) cursor(c gitCursor) string {
	c.Format = g.format()
	return encodeCursor(&c)
}

// fetchStore fetches the trees of commit and builds its store; base, when
// set, is the store of the commit the follower holds, whose trees need not be
// sent again.
func (g *gitIndex) fetchStore(ctx context.Context, commit gitOID, base *gitTreeStore) (*gitTreeStore, error) {
	have := ""
	if base != nil {
		have = base.commit.String()
	}
	for attempt := 0; attempt < 2; attempt++ {
		objs, err := g.remote.fetchTrees(ctx, commit.String(), have)
		if errors.Is(err, errGitIncrementalTooLarge) {
			have = ""
			continue
		}
		if err != nil {
			return nil, err
		}
		obj, ok := objs.get(commit)
		if (!ok || obj.typ != gitCommit) && have != "" {
			// The server holds the head reachable from the stored commit
			// (the branch moved back): it sent nothing. Ask for all of it.
			have = ""
			continue
		}
		if !ok || obj.typ != gitCommit {
			return nil, Permanent(fmt.Errorf("the fetch of %s did not return the commit", commit))
		}
		ci, err := parseGitCommit(obj.data)
		if err != nil {
			return nil, Permanent(fmt.Errorf("commit %s: %w", commit, err))
		}
		look := func(id gitOID) ([]byte, bool) {
			if o, ok := objs.get(id); ok && o.typ == gitTree {
				return o.data, true
			}
			return base.lookup(id)
		}
		trees, err := collectGitTrees(look, g.spec.area, ci.tree)
		if errors.Is(err, errGitTreeMissing) && have != "" {
			// A tree the server took us to have (it is somewhere in the
			// stored commit's history) but the store does not hold: ask
			// for every tree.
			have = ""
			continue
		}
		if err != nil {
			return nil, Permanent(fmt.Errorf("the trees of %s: %w", commit, err))
		}
		return &gitTreeStore{commit: commit, root: ci.tree, committed: ci.committed, trees: trees}, nil
	}
	return nil, Permanent(fmt.Errorf("the trees of %s: %w", commit, errGitTreeMissing))
}

// head reads the commit the followed branch points at.
func (g *gitIndex) head(ctx context.Context) (gitOID, error) {
	s, err := g.remote.head(ctx, g.branch)
	if err != nil {
		return gitOID{}, err
	}
	return parseOID(s)
}

// load reads the store a cursor names; a missing or damaged one invalidates
// the cursor.
func (g *gitIndex) load(commit string) (*gitTreeStore, error) {
	id, err := parseOID(commit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCursorInvalid, err)
	}
	st, err := loadGitTreeStore(g.files, gitStorePrefix, id)
	if err != nil {
		return nil, fmt.Errorf("%w: the trees of %s are not stored (%v)", ErrCursorInvalid, commit, err)
	}
	return st, nil
}

// collect maps changed files to coordinates, each change once, in path order.
func (g *gitIndex) collect(visit func(fn func(path string, c gitChange) error) error) ([]Coordinate, error) {
	var out []Coordinate
	seen := map[Coordinate]bool{}
	err := visit(func(p string, c gitChange) error {
		co, ok := g.spec.coordinate(p, c)
		if !ok || !cleanName(co.Name) || len(co.Version) > 1024 {
			return nil
		}
		if !seen[co] {
			seen[co] = true
			out = append(out, co)
		}
		return nil
	})
	return out, err
}

// bootstrap lists every package of the head commit's trees.
func (g *gitIndex) bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var st *gitTreeStore
	var c gitCursor
	if cursor == "" {
		head, err := g.head(ctx)
		if err != nil {
			return Batch{}, err
		}
		if st, err = g.fetchStore(ctx, head, nil); err != nil {
			return Batch{}, err
		}
		if err := saveGitTreeStore(g.files, gitStorePrefix, st); err != nil {
			return Batch{}, fmt.Errorf("storing the trees of %s: %w", head, err)
		}
		g.files.prune(gitStorePrefix, gitStoreName(gitStorePrefix, head))
		c = gitCursor{Commit: head.String(), Listing: true}
	} else {
		if err := decodeCursor(cursor, g.format(), &c); err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the cursor does not continue a listing", ErrCursorInvalid)
		}
		var err error
		if st, err = g.load(c.Commit); err != nil {
			return Batch{}, err
		}
	}
	all, err := g.collect(func(fn func(string, gitChange) error) error {
		return walkGitTree(st.lookup, g.spec.area, st.root, "", func(p string) error { return fn(p, gitAdded) })
	})
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("listing the trees of %s: %w", c.Commit, err))
	}
	items, next, more := pageItems(all, c.Skip, g.page)
	b := Batch{Items: items, More: more, Head: c.Commit, HeadTime: st.committed, CursorTime: st.committed}
	if more {
		b.Next = g.cursor(gitCursor{Commit: c.Commit, Listing: true, Skip: next})
	} else {
		b.Next = g.cursor(gitCursor{Commit: c.Commit})
	}
	return b, nil
}

// changes diffs the stored commit's trees against the head's.
func (g *gitIndex) changes(ctx context.Context, cursor string) (Batch, error) {
	var c gitCursor
	if err := decodeCursor(cursor, g.format(), &c); err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the cursor continues a listing", ErrCursorInvalid)
	}
	from, err := g.load(c.Commit)
	if err != nil {
		return Batch{}, err
	}
	var to *gitTreeStore
	if c.To != "" {
		// The rest of a difference that spans several batches.
		if to, err = g.load(c.To); err != nil {
			return Batch{}, err
		}
	} else {
		head, err := g.head(ctx)
		if err != nil {
			return Batch{}, err
		}
		if head == from.commit {
			return Batch{Next: cursor, Head: c.Commit, HeadTime: from.committed, CursorTime: from.committed, LagKnown: true}, nil
		}
		if to, err = g.fetchStore(ctx, head, from); err != nil {
			return Batch{}, err
		}
		if err := saveGitTreeStore(g.files, gitStorePrefix, to); err != nil {
			return Batch{}, fmt.Errorf("storing the trees of %s: %w", head, err)
		}
	}
	// Keep the stored commit's trees (the engine may ask again from the same
	// cursor after a restart) and the new head's.
	g.files.prune(gitStorePrefix, gitStoreName(gitStorePrefix, from.commit), gitStoreName(gitStorePrefix, to.commit))
	look := func(id gitOID) ([]byte, bool) {
		if d, ok := to.lookup(id); ok {
			return d, true
		}
		return from.lookup(id)
	}
	all, err := g.collect(func(fn func(string, gitChange) error) error {
		return diffGitTrees(look, g.spec.area, from.root, to.root, "", fn)
	})
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("diffing %s and %s: %w", from.commit, to.commit, err))
	}
	items, next, more := pageItems(all, c.Skip, g.page)
	b := Batch{Items: items, More: more, Head: to.commit.String(), HeadTime: to.committed, CursorTime: to.committed}
	if more {
		b.Next = g.cursor(gitCursor{Commit: c.Commit, To: to.commit.String(), Skip: next})
		b.CursorTime = from.committed
	} else {
		b.Next = g.cursor(gitCursor{Commit: to.commit.String()})
		b.LagKnown = true
	}
	return b, nil
}
