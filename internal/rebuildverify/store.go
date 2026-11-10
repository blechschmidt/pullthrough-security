package rebuildverify

import (
	"container/list"
	"sync"
)

// resultStore is a bounded LRU cache of terminal verification results keyed by
// (coordinate, digest). It ensures a given artifact is rebuilt at most once
// (until evicted) regardless of how many times it is pulled.
type resultStore struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[string]*list.Element
}

type storeEntry struct {
	key string
	res Result
}

func newResultStore(max int) *resultStore {
	if max <= 0 {
		max = defaultCacheSize
	}
	return &resultStore{
		max: max,
		ll:  list.New(),
		m:   make(map[string]*list.Element, max),
	}
}

// get returns the cached result for key, marking it most-recently-used.
func (s *resultStore) get(key string) (Result, bool) {
	if s == nil {
		return Result{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.m[key]; ok {
		s.ll.MoveToFront(el)
		return el.Value.(*storeEntry).res, true
	}
	return Result{}, false
}

// put stores a result, evicting the least-recently-used entry when full. A
// pending (non-terminal) result is not cached, so a deferred rebuild is retried
// on the next pull.
func (s *resultStore) put(key string, res Result) {
	if s == nil || !res.Done {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.m[key]; ok {
		el.Value.(*storeEntry).res = res
		s.ll.MoveToFront(el)
		return
	}
	el := s.ll.PushFront(&storeEntry{key: key, res: res})
	s.m[key] = el
	for s.ll.Len() > s.max {
		oldest := s.ll.Back()
		if oldest == nil {
			break
		}
		s.ll.Remove(oldest)
		delete(s.m, oldest.Value.(*storeEntry).key)
	}
}

// len returns the number of cached results.
func (s *resultStore) len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}

// recentRing is a bounded ring of the most recent terminal results for the admin
// surface, newest-first.
type recentRing struct {
	mu  sync.Mutex
	max int
	buf []Result
}

func newRecentRing(max int) *recentRing {
	if max <= 0 {
		max = defaultRecentSize
	}
	return &recentRing{max: max}
}

func (r *recentRing) add(res Result) {
	if r == nil || !res.Done {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, res)
	if len(r.buf) > r.max {
		// Drop the oldest entries, keeping the ring bounded.
		r.buf = r.buf[len(r.buf)-r.max:]
	}
}

// snapshot returns up to limit recent results, newest first (0 = all retained).
func (r *recentRing) snapshot(limit int) []Result {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.buf)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, r.buf[len(r.buf)-1-i])
	}
	return out
}
