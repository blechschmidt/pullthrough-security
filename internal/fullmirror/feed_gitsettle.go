package fullmirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

// The Git-backed feeds of the Bazel Central Registry, conan-center-index and
// homebrew-core (Task 190) follow repositories that are not what clients
// download from but what the registry is built from, and the registry
// serves a commit's files some time after the commit is pushed:
// bcr.bazel.build is uploaded about half a minute after a push, ConanCenter
// promotes a merged recipe's packages "within a few minutes" and serves its
// revision pointers from a CDN, formulae.brew.sh is regenerated from
// homebrew-core and cached for ten minutes. A change processed the moment it
// is pushed reads the registry before it has caught up: a version it does
// not list yet (the engine records it as gone and does not come back to it),
// the previous recipe revision or formula version (the new one would only be
// mirrored with the package's next change).
//
// So these feeds report a commit once it has settled. Changes diffs the
// stored commit's trees against the newest commit of the followed branch's
// first-parent history that was committed at least the settle period ago —
// not against the head — and catches up with the head as its commits age.
// While nothing newer than the stored commit has settled, a poll returns no
// change and keeps its cursor. A history that does not lead back to the
// stored commit (squashed, force-pushed) has no order to settle by: the head
// is diffed, as gitIndex.changes does. Bootstrap lists the head.
//
// The helper is shared by the three feeds (feed_bazel.go, feed_conan.go,
// feed_homebrew.go), which each set their own default period and take the
// feed option "settle".

// gitSettleMax bounds the settle period an operator may configure.
const gitSettleMax = 7 * 24 * time.Hour

// gitSettleOption reads the feed option "settle": a Go duration ("30m",
// "2h"); "0" reports every commit at once.
func gitSettleOption(o options, def time.Duration) (time.Duration, error) {
	v := o["settle"]
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || d > gitSettleMax {
		return 0, fmt.Errorf("option settle %q is not a duration between 0 and %s", v, gitSettleMax)
	}
	return d, nil
}

// gitSettleChanges is gitIndex.changes with commits reported once they are
// settle old at now.
func gitSettleChanges(ctx context.Context, g *gitIndex, cursor string, settle time.Duration, now time.Time) (Batch, error) {
	if settle <= 0 {
		return g.changes(ctx, cursor)
	}
	var c gitCursor
	if err := decodeCursor(cursor, g.format(), &c); err != nil {
		return Batch{}, err
	}
	if c.Listing || c.To != "" {
		// changes refuses a listing cursor, and pages through a difference
		// whose end was chosen by an earlier call.
		return g.changes(ctx, cursor)
	}
	from, err := g.load(c.Commit)
	if err != nil {
		return Batch{}, err
	}
	head, err := g.head(ctx)
	if err != nil {
		return Batch{}, err
	}
	if head == from.commit {
		return Batch{Next: cursor, Head: c.Commit, HeadTime: from.committed, CursorTime: from.committed, LagKnown: true}, nil
	}
	var to *gitTreeStore
	var headTime time.Time
	objs, err := g.remote.fetchTrees(ctx, head.String(), from.commit.String())
	switch {
	case errors.Is(err, errGitIncrementalTooLarge):
		// The history was rewritten: diff the head's snapshot.
		if to, err = g.fetchStore(ctx, head, nil); err != nil {
			return Batch{}, err
		}
	case err != nil:
		return Batch{}, err
	default:
		target, ht, settled := gitSettlePick(objs, head, from.commit, now.Add(-settle))
		headTime = ht
		if !settled {
			return Batch{Next: cursor, Head: head.String(), HeadTime: headTime, CursorTime: from.committed}, nil
		}
		if to, err = gitSettleStore(ctx, g, objs, target, from); err != nil {
			return Batch{}, err
		}
	}
	if err := saveGitTreeStore(g.files, gitStorePrefix, to); err != nil {
		return Batch{}, fmt.Errorf("storing the trees of %s: %w", to.commit, err)
	}
	// The difference to the chosen commit, paged as changes pages one.
	b, err := g.changes(ctx, g.cursor(gitCursor{Commit: c.Commit, To: to.commit.String()}))
	if err != nil {
		return Batch{}, err
	}
	if to.commit != head {
		// The head is ahead of what has settled: show it, without a count.
		b.Head, b.HeadTime, b.Lag, b.LagKnown = head.String(), headTime, 0, false
	}
	return b, nil
}

// gitSettlePick chooses the commit a difference from the stored commit leads
// to: walking the head's first-parent history from the stored commit
// forwards, the last commit before the first one committed after cutoff (a
// commit that states no time counts as settled). The time is the committer
// time — when the commit was made, which can be before it reached the branch
// (a merge queue's commits are made when they are queued), so the settle
// period is a lower bound on how long the registry has had. settled is false while none has. A
// first-parent history that does not reach the stored commit within the
// fetched commits — or holds a commit that does not read — has no order to
// settle by, and the head is taken (whose own commit is read, and judged, as
// gitIndex.changes would). headTime is the head's commit time, when the fetch
// holds the head.
func gitSettlePick(objs *gitObjects, head, from gitOID, cutoff time.Time) (target gitOID, headTime time.Time, settled bool) {
	var chain []gitOID
	var times []time.Time
	cur := head
	for cur != from {
		obj, ok := objs.get(cur)
		if !ok || obj.typ != gitCommit || len(chain) > len(objs.objs) {
			return head, headTime, true
		}
		committed, parents, err := gitSettleCommit(obj.data)
		if err != nil {
			return head, headTime, true
		}
		if len(chain) == 0 {
			headTime = committed
		}
		chain = append(chain, cur)
		times = append(times, committed)
		if len(parents) == 0 {
			return head, headTime, true
		}
		cur = parents[0]
	}
	// Oldest first, up to the first commit that has not settled: commit
	// times need not grow along the chain (a merge queue stamps a commit
	// when it queues it), and a newer commit beneath an unsettled one has
	// not settled either.
	settledAt := -1
	for i := len(chain) - 1; i >= 0; i-- {
		if t := times[i]; !t.IsZero() && t.After(cutoff) {
			break
		}
		settledAt = i
	}
	if settledAt < 0 {
		return gitOID{}, headTime, false
	}
	return chain[settledAt], headTime, true
}

// gitSettleCommit reads a commit's committer time and its parents, in order.
func gitSettleCommit(data []byte) (time.Time, []gitOID, error) {
	ci, err := parseGitCommit(data)
	if err != nil {
		return time.Time{}, nil, err
	}
	var parents []gitOID
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		if len(line) == 0 {
			break // the end of the headers
		}
		if rest, ok := bytes.CutPrefix(line, []byte("parent ")); ok {
			id, err := parseOID(string(rest))
			if err != nil {
				return time.Time{}, nil, fmt.Errorf("a parent: %w", err)
			}
			parents = append(parents, id)
		}
	}
	return ci.committed, parents, nil
}

// gitSettleStore builds the tree store of target from an incremental fetch
// and the stored commit's trees; a tree neither holds (one the stored
// commit's history has, outside its store) has target's trees fetched on
// their own.
func gitSettleStore(ctx context.Context, g *gitIndex, objs *gitObjects, target gitOID, from *gitTreeStore) (*gitTreeStore, error) {
	obj, ok := objs.get(target)
	if !ok || obj.typ != gitCommit {
		return g.fetchStore(ctx, target, nil)
	}
	ci, err := parseGitCommit(obj.data)
	if err != nil {
		return nil, Permanent(fmt.Errorf("commit %s: %w", target, err))
	}
	look := func(id gitOID) ([]byte, bool) {
		if o, ok := objs.get(id); ok && o.typ == gitTree {
			return o.data, true
		}
		return from.lookup(id)
	}
	trees, err := collectGitTrees(look, g.spec.area, ci.tree)
	if errors.Is(err, errGitTreeMissing) {
		return g.fetchStore(ctx, target, nil)
	}
	if err != nil {
		return nil, Permanent(fmt.Errorf("the trees of %s: %w", target, err))
	}
	return &gitTreeStore{commit: target, root: ci.tree, committed: ci.committed, trees: trees}, nil
}
