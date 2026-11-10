package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrSealed is returned (wrapped) by a SealedCache when a request misses the
// cache. In sealed mode the proxy never reaches upstream, so a miss is terminal
// rather than a trigger to fetch.
var ErrSealed = fmt.Errorf("cache: sealed (offline) mode; upstream fetch refused: %w", ErrNotFound)

// SealedCache wraps a Cache to enforce "offline/sealed" mode: it serves reads
// from the underlying cache but never invokes a loader, so a cache miss is
// answered locally and no upstream request is ever made. It is the cache-layer
// half of sealed mode; the gateway additionally refuses live (non-cacheable)
// upstream fetches at the backend layer.
//
// All other operations delegate to the wrapped cache, and the wrapper forwards
// the optional administrative/metrics surfaces (Entries, Metrics) so the admin
// API and Prometheus bridge keep working over a sealed cache.
type SealedCache struct {
	inner Cache
}

var _ Cache = (*SealedCache)(nil)

// NewSealedCache wraps inner so that GetOrLoad never reaches upstream.
func NewSealedCache(inner Cache) *SealedCache {
	return &SealedCache{inner: inner}
}

// Get implements Cache by delegating to the wrapped cache.
func (s *SealedCache) Get(ctx context.Context, key string) (*Entry, error) {
	return s.inner.Get(ctx, key)
}

// Put implements Cache by delegating to the wrapped cache. Writes are permitted
// so that bundle imports and administrative operations can still populate a
// sealed instance; only upstream-driven loads are blocked.
func (s *SealedCache) Put(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*Stat, error) {
	return s.inner.Put(ctx, key, r, metadata)
}

// GetOrLoad implements Cache. In sealed mode the loader is never called: the
// entry is served from the cache when present and reported as a sealed miss
// otherwise. This is the single seam through which the live proxy would fetch a
// cacheable artifact upstream, so blocking it here guarantees no phone-home for
// cached content.
func (s *SealedCache) GetOrLoad(ctx context.Context, key string, _ Loader) (*Entry, error) {
	entry, err := s.inner.Get(ctx, key)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrSealed
		}
		return nil, err
	}
	return entry, nil
}

// Stat implements Cache by delegating to the wrapped cache.
func (s *SealedCache) Stat(ctx context.Context, key string) (*Stat, error) {
	return s.inner.Stat(ctx, key)
}

// Delete implements Cache by delegating to the wrapped cache.
func (s *SealedCache) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}

// Close implements Cache by delegating to the wrapped cache.
func (s *SealedCache) Close() error {
	return s.inner.Close()
}

// Entries forwards the administrative cache listing when the wrapped cache
// supports it, so the admin API can inspect a sealed cache. It returns an empty
// listing when the underlying cache does not expose entries.
func (s *SealedCache) Entries(ctx context.Context) ([]Stat, error) {
	if insp, ok := s.inner.(interface {
		Entries(context.Context) ([]Stat, error)
	}); ok {
		return insp.Entries(ctx)
	}
	return nil, nil
}

// GCEntries forwards the wrapped cache's GC-facing listing when available, so
// the cache lifecycle manager (Task 39) can plan eviction over a sealed cache.
func (s *SealedCache) GCEntries(ctx context.Context) ([]GCEntry, error) {
	if insp, ok := s.inner.(interface {
		GCEntries(context.Context) ([]GCEntry, error)
	}); ok {
		return insp.GCEntries(ctx)
	}
	return nil, nil
}

// InFlightKeys forwards the wrapped cache's in-flight set when available.
func (s *SealedCache) InFlightKeys() map[string]struct{} {
	if insp, ok := s.inner.(interface{ InFlightKeys() map[string]struct{} }); ok {
		return insp.InFlightKeys()
	}
	return nil
}

// OpenRaw forwards the wrapped cache's metrics-free raw read when available, so
// the background integrity scan (Task 107) can re-verify a sealed cache.
func (s *SealedCache) OpenRaw(ctx context.Context, key string) (io.ReadCloser, Stat, error) {
	if insp, ok := s.inner.(interface {
		OpenRaw(context.Context, string) (io.ReadCloser, Stat, error)
	}); ok {
		return insp.OpenRaw(ctx, key)
	}
	return nil, Stat{}, ErrNotFound
}

// Metrics forwards the wrapped cache's activity counters when available, so the
// metrics bridge keeps reporting over a sealed cache.
func (s *SealedCache) Metrics() MetricsSnapshot {
	if src, ok := s.inner.(interface{ Metrics() MetricsSnapshot }); ok {
		return src.Metrics()
	}
	return MetricsSnapshot{}
}

// CompactionStats forwards the wrapped cache's storage-efficiency statistics
// (Task 125) so they remain visible through a sealed cache.
func (s *SealedCache) CompactionStats() CompactionStats {
	if src, ok := s.inner.(CompactionStatSource); ok {
		return src.CompactionStats()
	}
	return CompactionStats{Enabled: false, Codec: "none"}
}

// isNotFound reports whether err is (or wraps) ErrNotFound.
func isNotFound(err error) bool {
	return err != nil && errors.Is(err, ErrNotFound)
}
