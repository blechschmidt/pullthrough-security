package coord

import (
	"context"
	"strconv"
	"sync"
)

// memBackend is an in-process compare-and-swap store. It is the single-node
// default coordination backend: with one process pointed at it, that process
// always wins the lease and is permanently the leader, which is exactly the
// behavior an operator wants when running a single replica.
//
// It is also the substrate for deterministic multi-node tests: several
// coordinator instances (each with a distinct node ID) sharing one memBackend
// model a cluster contending over the same lease objects, with none of the
// timing nondeterminism of a real network store.
type memBackend struct {
	mu sync.Mutex
	m  map[string]memEntry
}

type memEntry struct {
	rec record
	gen uint64
}

func newMemoryBackend() *memBackend {
	return &memBackend{m: make(map[string]memEntry)}
}

func (b *memBackend) load(_ context.Context, name string) (record, string, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[name]
	if !ok {
		return record{}, "", false, nil
	}
	return e.rec, strconv.FormatUint(e.gen, 10), true, nil
}

func (b *memBackend) create(_ context.Context, name string, rec record) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[name]; ok {
		return "", ErrConflict
	}
	b.m[name] = memEntry{rec: rec, gen: 1}
	return "1", nil
}

func (b *memBackend) update(_ context.Context, name, expectedVersion string, rec record) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[name]
	if !ok || strconv.FormatUint(e.gen, 10) != expectedVersion {
		return "", ErrConflict
	}
	ng := e.gen + 1
	b.m[name] = memEntry{rec: rec, gen: ng}
	return strconv.FormatUint(ng, 10), nil
}

func (b *memBackend) remove(_ context.Context, name, expectedVersion string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[name]
	if !ok {
		return nil
	}
	if strconv.FormatUint(e.gen, 10) != expectedVersion {
		return ErrConflict
	}
	delete(b.m, name)
	return nil
}

func (b *memBackend) close() error { return nil }
