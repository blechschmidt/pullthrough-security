package cache

import "sync"

// singleflight coalesces concurrent calls that share a key so an expensive
// operation (such as an upstream fetch) runs at most once at a time per key. It
// is a small, dependency-free analogue of golang.org/x/sync/singleflight scoped
// to the cache's needs.
type singleflight struct {
	mu    sync.Mutex
	calls map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val *Stat
	err error
}

func newSingleflight() *singleflight {
	return &singleflight{calls: make(map[string]*sfCall)}
}

// keys returns the set of keys with a call currently in flight. The cache GC
// subsystem (Task 39) consults it so an artifact that is mid-fetch is never
// evicted out from under the in-progress load.
func (s *singleflight) keys() map[string]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]struct{}, len(s.calls))
	for k := range s.calls {
		out[k] = struct{}{}
	}
	return out
}

// Do executes fn for key, ensuring that only one execution is in flight for a
// given key at a time. Duplicate callers wait for the in-flight call to complete
// and receive its result. The returned shared flag reports whether the result
// was delivered to more than one caller (true for every waiter, and for the
// leader when at least one waiter joined).
func (s *singleflight) Do(key string, fn func() (*Stat, error)) (*Stat, error, bool) {
	s.mu.Lock()
	if c, ok := s.calls[key]; ok {
		s.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}
	c := new(sfCall)
	c.wg.Add(1)
	s.calls[key] = c
	s.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	s.mu.Lock()
	// Only delete if it is still our call; a later identical key starts fresh.
	if s.calls[key] == c {
		delete(s.calls, key)
	}
	s.mu.Unlock()

	return c.val, c.err, false
}
