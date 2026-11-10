package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"
)

// MemoryCache is a minimal in-memory Cache implementation. It exists so the
// proxy can be wired and exercised end to end before the durable
// content-addressable store (Task 2) lands. It is not intended for production
// use and keeps all content resident in memory.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]memoryEntry
	now     func() time.Time
	sf      *singleflight
}

type memoryEntry struct {
	data     []byte
	digest   string // "sha256:hex" of data, the fixity baseline (Task 107)
	modTime  time.Time
	metadata map[string]string
}

// NewMemoryCache returns an empty in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		entries: make(map[string]memoryEntry),
		now:     time.Now,
		sf:      newSingleflight(),
	}
}

var _ Cache = (*MemoryCache)(nil)

func (c *MemoryCache) Get(ctx context.Context, key string) (*Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, ErrNotFound
	}
	return &Entry{
		Stat: c.statLocked(key, e),
		// A *bytes.Reader is an io.ReadSeeker; wrap it in a seek-preserving
		// no-op closer (rather than io.NopCloser, which hides Seek) so the serve
		// path can satisfy HTTP range requests without spooling to disk.
		Content: readSeekNopCloser{bytes.NewReader(e.data)},
	}, nil
}

// readSeekNopCloser adapts an io.ReadSeeker into an io.ReadSeekCloser whose Close
// is a no-op. Unlike io.NopCloser it preserves the Seek method, so range serving
// can use the content directly.
type readSeekNopCloser struct{ io.ReadSeeker }

func (readSeekNopCloser) Close() error { return nil }

func (c *MemoryCache) Put(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*Stat, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	meta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		meta[k] = v
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	sum := sha256.Sum256(data)
	e := memoryEntry{data: data, digest: "sha256:" + hex.EncodeToString(sum[:]), modTime: c.now(), metadata: meta}
	c.entries[key] = e
	stat := c.statLocked(key, e)
	return &stat, nil
}

// GetOrLoad implements Cache. It coalesces concurrent misses for the same key so
// loader runs at most once; each caller then receives its own content stream.
func (c *MemoryCache) GetOrLoad(ctx context.Context, key string, loader Loader) (*Entry, error) {
	if entry, err := c.Get(ctx, key); err == nil {
		return entry, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	_, err, _ := c.sf.Do(key, func() (*Stat, error) {
		// Another flight may have populated the key between our miss and our
		// acquiring leadership; re-check before invoking the loader.
		if stat, serr := c.Stat(ctx, key); serr == nil {
			return stat, nil
		} else if !errors.Is(serr, ErrNotFound) {
			return nil, serr
		}
		r, metadata, lerr := loader(ctx)
		if lerr != nil {
			return nil, lerr
		}
		if rc, ok := r.(io.Closer); ok {
			defer rc.Close()
		}
		return c.Put(ctx, key, r, metadata)
	})
	if err != nil {
		return nil, err
	}
	return c.Get(ctx, key)
}

func (c *MemoryCache) Stat(ctx context.Context, key string) (*Stat, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, ErrNotFound
	}
	stat := c.statLocked(key, e)
	return &stat, nil
}

func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[key]; !ok {
		return ErrNotFound
	}
	delete(c.entries, key)
	return nil
}

// Close is a no-op for the in-memory cache.
func (c *MemoryCache) Close() error { return nil }

// Entries returns a Stat for every resident entry, for administrative
// inspection. The order is unspecified.
func (c *MemoryCache) Entries(ctx context.Context) ([]Stat, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats := make([]Stat, 0, len(c.entries))
	for key, e := range c.entries {
		stats = append(stats, c.statLocked(key, e))
	}
	return stats, nil
}

// statLocked builds a Stat from an entry. Callers must hold at least a read
// lock. A defensive copy of the metadata map is returned.
func (c *MemoryCache) statLocked(key string, e memoryEntry) Stat {
	meta := make(map[string]string, len(e.metadata)+1)
	for k, v := range e.metadata {
		meta[k] = v
	}
	if e.digest != "" {
		meta[MetaDigest] = e.digest
	}
	return Stat{
		Key:      key,
		Size:     int64(len(e.data)),
		ModTime:  e.modTime,
		Metadata: meta,
	}
}
