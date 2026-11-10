package cache

import (
	"context"
	"io"
	"time"
)

// Well-known metadata keys. The Cache interface exchanges metadata as an opaque
// string map, but the caching subsystem promotes a small set of keys to
// structured, first-class fields on the persisted Record so they can be indexed,
// reported, and reasoned about. Any other keys are preserved verbatim in
// Record.Extra and round-trip unchanged.
const (
	// MetaOrigin is the original upstream URL or package coordinate the content
	// was pulled from (e.g. "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz").
	MetaOrigin = "origin"
	// MetaContentType is the MIME type of the stored content.
	MetaContentType = "content-type"
	// MetaETag is the upstream entity tag, used for conditional revalidation.
	MetaETag = "etag"
	// MetaPin marks an entry as protected from garbage collection when set to a
	// truthy value ("1", "true", "yes"). The cache lifecycle/GC subsystem
	// (Task 39) never evicts a pinned entry unless explicitly allowed. It is the
	// generic, metadata-driven pin: gates that establish evidence (e.g. a
	// signed-and-attested artifact, or one quarantined for investigation) can set
	// it so retention survives restarts and replicas without the GC needing to
	// reach back into those subsystems.
	MetaPin = "pin"
	// MetaTenant records the owning tenant of an entry, so the GC can apply a
	// per-tenant TTL. When absent, the GC falls back to a namespaced key prefix.
	MetaTenant = "tenant"
	// MetaDigest is the content digest of the stored blob, formatted
	// "algo:hexdigest" (e.g. "sha256:ab12..."). Unlike MetaETag (an upstream
	// validator) it is computed by the Store over the exact bytes it persisted, so
	// it is the authoritative fixity baseline for read-time integrity verification
	// and the background integrity scan (Task 107). It is promoted to the
	// structured Record.Digest field; callers do not set it — the Store overwrites
	// any supplied value with the digest it computed on write.
	MetaDigest = "digest"
)

// Record is the durable metadata index entry for a single cached blob. It is
// persisted alongside the content by a Store and is the source of truth for the
// cache's in-memory index after a restart.
type Record struct {
	// Key is the cache key (a content address such as "sha256:..." or a logical
	// coordinate).
	Key string `json:"key"`
	// Size is the content length in bytes. Set by the Store on write.
	Size int64 `json:"size"`
	// Digest is the content digest of the stored blob ("algo:hexdigest"), computed
	// by the Store over the exact bytes it persisted. It is the fixity baseline
	// verified on serve and by the background integrity scan (Task 107). Empty for
	// entries written before digest recording was introduced; such entries are
	// skipped by verification rather than treated as corrupt.
	Digest string `json:"digest,omitempty"`
	// Origin is the upstream URL or coordinate the content came from.
	Origin string `json:"origin,omitempty"`
	// ContentType is the MIME type of the content.
	ContentType string `json:"contentType,omitempty"`
	// ETag is the upstream entity tag for conditional revalidation.
	ETag string `json:"etag,omitempty"`
	// CreatedAt is when the entry was first written.
	CreatedAt time.Time `json:"createdAt"`
	// ModTime is when the content was last (re)written.
	ModTime time.Time `json:"modTime"`
	// AccessedAt is when the entry was last read; it drives LRU eviction.
	AccessedAt time.Time `json:"accessedAt"`
	// Extra carries any additional, caller-supplied metadata keys that are not
	// promoted to structured fields.
	Extra map[string]string `json:"extra,omitempty"`
}

// recordFromMetadata builds a Record from a cache key, a caller metadata map,
// and a timestamp used for the create/modify/access fields. Well-known keys are
// promoted to structured fields; the remainder is preserved in Extra.
func recordFromMetadata(key string, metadata map[string]string, now time.Time) Record {
	rec := Record{
		Key:        key,
		CreatedAt:  now,
		ModTime:    now,
		AccessedAt: now,
	}
	for k, v := range metadata {
		switch k {
		case MetaOrigin:
			rec.Origin = v
		case MetaContentType:
			rec.ContentType = v
		case MetaETag:
			rec.ETag = v
		case MetaDigest:
			rec.Digest = v
		default:
			if rec.Extra == nil {
				rec.Extra = make(map[string]string)
			}
			rec.Extra[k] = v
		}
	}
	return rec
}

// toStat projects a Record onto the public Stat value, re-materializing the
// promoted fields into the metadata map so callers see a complete, opaque view.
func (r Record) toStat() Stat {
	meta := make(map[string]string, len(r.Extra)+4)
	for k, v := range r.Extra {
		meta[k] = v
	}
	if r.Origin != "" {
		meta[MetaOrigin] = r.Origin
	}
	if r.ContentType != "" {
		meta[MetaContentType] = r.ContentType
	}
	if r.ETag != "" {
		meta[MetaETag] = r.ETag
	}
	if r.Digest != "" {
		meta[MetaDigest] = r.Digest
	}
	return Stat{
		Key:      r.Key,
		Size:     r.Size,
		ModTime:  r.ModTime,
		Metadata: meta,
	}
}

// Store is the pluggable byte-and-metadata persistence layer behind the cache.
// It is deliberately storage-agnostic: the local filesystem implementation lives
// in this package today, and an S3/object-storage implementation can be added
// later without touching the eviction, indexing, single-flight, or metrics logic
// in FilesystemCache.
//
// Implementations must be safe for concurrent use. Writes must be atomic so that
// a concurrent reader never observes a partially written blob: either the prior
// content/Record or the new one, never a torn mix.
type Store interface {
	// Put writes content from r under rec.Key, persisting rec as the metadata
	// index entry. The Store computes and sets the byte size; all other Record
	// fields are supplied by the caller. It returns the stored Record.
	Put(ctx context.Context, rec Record, r io.Reader) (Record, error)

	// Get opens the content stream for key and returns it together with the
	// persisted Record. It returns ErrNotFound if the key is absent. The caller
	// must Close the returned reader.
	Get(ctx context.Context, key string) (io.ReadCloser, Record, error)

	// Stat returns the persisted Record for key without opening content. It
	// returns ErrNotFound if the key is absent.
	Stat(ctx context.Context, key string) (Record, error)

	// SetAccessed updates the persisted last-access timestamp for key. It is a
	// best-effort durability hook for LRU ordering across restarts; callers may
	// ignore its error. It returns ErrNotFound if the key is absent.
	SetAccessed(ctx context.Context, key string, t time.Time) error

	// Delete removes key and its metadata. It returns ErrNotFound if the key is
	// absent.
	Delete(ctx context.Context, key string) error

	// List enumerates every persisted Record. It is used to warm the in-memory
	// index when a cache is opened over an existing store.
	List(ctx context.Context) ([]Record, error)

	// Close releases any resources held by the store.
	Close() error
}
