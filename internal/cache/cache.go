// Package cache defines the content-addressable caching contract used by the
// pull-through proxy. The concrete content-addressable storage implementation
// is built in a later task (see Task 2); this package establishes the stable
// interface and shared value types that backends and the proxy layer depend on.
package cache

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned by Cache implementations when a requested key is not
// present. Callers should compare with errors.Is.
var ErrNotFound = errors.New("cache: entry not found")

// Stat describes the metadata of a stored cache entry without exposing its
// content stream.
type Stat struct {
	// Key is the content address of the entry (e.g. "sha256:abcd...").
	Key string
	// Size is the length of the stored content in bytes.
	Size int64
	// ModTime is when the entry was last written.
	ModTime time.Time
	// Metadata carries opaque key/value pairs persisted alongside the content,
	// such as the upstream URL, media type, or original filename.
	Metadata map[string]string
}

// Entry bundles a content stream with its metadata. The caller owns Content and
// must Close it when done.
type Entry struct {
	Stat    Stat
	Content io.ReadCloser
}

// Cache is the content-addressable storage abstraction. Implementations must be
// safe for concurrent use by multiple goroutines.
//
// Keys are expected to be content addresses, but the interface does not enforce
// a particular scheme so that implementations can also key on logical
// coordinates when content digests are not yet known.
type Cache interface {
	// Get returns the entry for key. It returns ErrNotFound if the key is
	// absent. The caller must Close the returned Entry.Content.
	Get(ctx context.Context, key string) (*Entry, error)

	// Put stores content under key, persisting the supplied metadata. It reads
	// r until EOF and returns the resulting Stat. Implementations should write
	// atomically so that concurrent readers never observe a partial entry.
	Put(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*Stat, error)

	// GetOrLoad returns the cached entry for key, fetching it via loader on a
	// miss. Concurrent calls for the same key are coalesced (single-flight) so
	// loader runs at most once, preventing duplicate upstream fetches (the
	// "thundering herd"). Each caller receives its own independent content
	// stream. This is the primary entry point the proxy uses to populate the
	// cache transparently on a miss.
	GetOrLoad(ctx context.Context, key string, loader Loader) (*Entry, error)

	// Stat returns metadata for key without opening the content stream. It
	// returns ErrNotFound if the key is absent.
	Stat(ctx context.Context, key string) (*Stat, error)

	// Delete removes key. Deleting a missing key returns ErrNotFound.
	Delete(ctx context.Context, key string) error

	// Close releases any resources held by the cache.
	Close() error
}
