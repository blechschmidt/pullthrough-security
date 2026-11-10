package homebrew

import (
	"container/list"
	"sync"
	"time"
)

// bottleIndex is the bounded in-memory record of what the backend has learned
// about bottle blobs: for a (repository, digest) pair, the formula name and
// version the admission gates should see. It is filled as image indexes pass
// through (manifest.go) and, when a blob is requested with no index entry, from
// the formula JSON API (coordinate.go).
//
// It is a plain LRU: a lookup or an update moves an entry to the front, and an
// insert beyond the capacity evicts the least recently used entry. Nothing is
// lost for good by an eviction (or a restart, or a request landing on a
// different replica) — the next request for that bottle simply falls back to the
// formula API, and the mapping is immutable, so the answer is the same.

// defaultBottleIndexSize bounds the index. One manifest contributes an entry
// per platform (around six), so this holds the bottles of a few thousand
// recently used formula versions in a few MiB.
const defaultBottleIndexSize = 16384

// bottleKey identifies a bottle blob as a client requests it. The repository is
// part of the key so that what one repository's manifest says can never apply
// to a blob requested under another.
type bottleKey struct {
	repo   string // OCI repository, e.g. "homebrew/core/hello"
	digest string // lowercase hex SHA-256 of the bottle tarball
}

// bottleFact is what is known about one bottle blob.
type bottleFact struct {
	// name is the formula name established from upstream metadata, or "" when
	// none was (the name is then derived from the repository path).
	name string
	// version is the formula version, or "" when it is not known.
	version string
	// source records where version came from (a versionSource* constant).
	source string
	// expires, when non-zero, is when the fact stops being trusted. Only a fact
	// without a version expires: it records that a formula-API lookup just came
	// back empty-handed, so the lookup is not repeated on every request.
	expires time.Time
}

// known reports whether the fact carries a version.
func (f bottleFact) known() bool { return f.version != "" }

type bottleItem struct {
	key  bottleKey
	fact bottleFact
}

type bottleIndex struct {
	mu    sync.Mutex
	max   int
	now   func() time.Time
	order *list.List // front = most recently used
	items map[bottleKey]*list.Element
}

func newBottleIndex(max int, now func() time.Time) *bottleIndex {
	if max <= 0 {
		max = defaultBottleIndexSize
	}
	if now == nil {
		now = time.Now
	}
	return &bottleIndex{
		max:   max,
		now:   now,
		order: list.New(),
		items: make(map[bottleKey]*list.Element),
	}
}

// get returns the live fact for k, marking it most recently used. An expired
// fact is dropped and reported as absent.
func (x *bottleIndex) get(k bottleKey) (bottleFact, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.getLocked(k)
}

func (x *bottleIndex) getLocked(k bottleKey) (bottleFact, bool) {
	el, ok := x.items[k]
	if !ok {
		return bottleFact{}, false
	}
	item := el.Value.(*bottleItem)
	if !item.fact.expires.IsZero() && !x.now().Before(item.fact.expires) {
		x.order.Remove(el)
		delete(x.items, k)
		return bottleFact{}, false
	}
	x.order.MoveToFront(el)
	return item.fact, true
}

// put records f for k unconditionally, evicting the least recently used entry
// when the index is full.
func (x *bottleIndex) put(k bottleKey, f bottleFact) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.putLocked(k, f)
}

func (x *bottleIndex) putLocked(k bottleKey, f bottleFact) {
	if el, ok := x.items[k]; ok {
		el.Value.(*bottleItem).fact = f
		x.order.MoveToFront(el)
		return
	}
	x.items[k] = x.order.PushFront(&bottleItem{key: k, fact: f})
	for x.order.Len() > x.max {
		oldest := x.order.Back()
		x.order.Remove(oldest)
		delete(x.items, oldest.Value.(*bottleItem).key)
	}
}

// putIfUnknown records f for k unless a version is already known for it, and
// returns the fact now in force. It lets a slow formula-API lookup complete
// without clobbering what a manifest taught the index in the meantime.
func (x *bottleIndex) putIfUnknown(k bottleKey, f bottleFact) bottleFact {
	x.mu.Lock()
	defer x.mu.Unlock()
	if cur, ok := x.getLocked(k); ok && cur.known() {
		return cur
	}
	x.putLocked(k, f)
	return f
}

// len reports the number of entries held (including not-yet-collected expired
// ones).
func (x *bottleIndex) len() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.order.Len()
}
