package repos

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// Reading files of a commit for the maintenance updater (Task 182): the lock
// files' manifests and siblings, and the project a sandboxed package manager
// is given. Paths come from the repository, so every walk is bounded, and only
// regular files are read — never a symbolic link, whose target could name a
// file outside the tree on whatever checks it out.

// maxTreeFileBytes bounds one file read; maxTreeWalkEntries the entries one
// walk looks at.
const (
	maxTreeFileBytes   = 64 << 20
	maxTreeWalkEntries = 500_000
)

// ErrTooLarge is returned by ReadTreeFiles when the files hold more than the
// bytes asked for.
var ErrTooLarge = errors.New("repos: the files are larger than allowed")

// ReadTreeFiles returns the contents of the named files at commit, at most
// maxTotal bytes of them together (an error wrapping ErrTooLarge beyond). A
// path that is not a regular file there (absent, a directory, a symbolic link)
// is absent from the result.
func ReadTreeFiles(ctx context.Context, objs lockfiles.Objects, commit string, paths []string, maxTotal int64) (map[string][]byte, error) {
	remaining := maxTotal
	_, root, err := objs.ResolveCommit(ctx, commit)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	trees := map[string][]git.TreeEntry{}
	readTree := func(id string) ([]git.TreeEntry, error) {
		if t, ok := trees[id]; ok {
			return t, nil
		}
		t, err := objs.ReadTree(ctx, id)
		if err == nil {
			trees[id] = t
		}
		return t, err
	}
	for _, p := range paths {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		clean := path.Clean(strings.TrimPrefix(p, "/"))
		if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
			continue
		}
		parts := strings.Split(clean, "/")
		tree := root
		var entry *git.TreeEntry
		for i, part := range parts {
			entries, err := readTree(tree)
			if err != nil {
				return nil, err
			}
			entry = nil
			for j := range entries {
				if entries[j].Name == part {
					entry = &entries[j]
					break
				}
			}
			if entry == nil {
				break
			}
			if i < len(parts)-1 {
				if entry.Kind != git.EntryTree {
					entry = nil
					break
				}
				tree = entry.ID
			}
		}
		if entry == nil || entry.Kind != git.EntryFile {
			continue
		}
		limit := min(int64(maxTreeFileBytes), remaining)
		data, err := objs.ReadBlob(ctx, entry.ID, limit)
		if errors.Is(err, git.ErrObjectTooLarge) {
			return nil, fmt.Errorf("%w: %s and the files read before it exceed %d bytes", ErrTooLarge, clean, maxTotal)
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", clean, err)
		}
		remaining -= int64(len(data))
		out[p] = data
	}
	return out, nil
}

// ListTreeFiles returns the paths of the regular files at commit below dir
// ("" the whole tree) that match, in path order, at most max of them (one more
// than max reports that there are more). Directories lockfiles.DefaultSkip
// names (vendored and installed dependencies, fixtures) are not entered.
func ListTreeFiles(ctx context.Context, objs lockfiles.Objects, commit, dir string, match func(string) bool, max int) ([]string, error) {
	_, root, err := objs.ResolveCommit(ctx, commit)
	if err != nil {
		return nil, err
	}
	start := root
	if dir != "" && dir != "." {
		for _, part := range strings.Split(path.Clean(dir), "/") {
			entries, err := objs.ReadTree(ctx, start)
			if err != nil {
				return nil, err
			}
			next := ""
			for _, e := range entries {
				if e.Name == part && e.Kind == git.EntryTree {
					next = e.ID
				}
			}
			if next == "" {
				return nil, nil
			}
			start = next
		}
	} else {
		dir = ""
	}
	skip := map[string]bool{".git": true}
	for _, s := range lockfiles.DefaultSkip {
		if !strings.Contains(s, "/") {
			skip[strings.ToLower(s)] = true
		}
	}
	var out []string
	seen := 0
	type frame struct{ tree, prefix string }
	stack := []frame{{start, dir}}
	for len(stack) > 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := objs.ReadTree(ctx, f.tree)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			seen++
			if seen > maxTreeWalkEntries {
				return nil, fmt.Errorf("the tree has more than %d entries", maxTreeWalkEntries)
			}
			p := e.Name
			if f.prefix != "" {
				p = f.prefix + "/" + e.Name
			}
			switch e.Kind {
			case git.EntryTree:
				if !skip[strings.ToLower(e.Name)] {
					stack = append(stack, frame{e.ID, p})
				}
			case git.EntryFile:
				if match == nil || match(p) {
					out = append(out, p)
					if len(out) > max {
						sort.Strings(out)
						return out, nil
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
