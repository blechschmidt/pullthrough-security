package cache

import (
	"context"
	"errors"
	"fmt"
)

// Release pinning (Task 180).
//
// A pinned cache object is one a release depends on: the repository tracker
// recorded it in a release manifest, so that the release can be rebuilt from
// this cache for as long as the manifest exists. The pin set lives with the
// manifests (internal/repos), not in the objects' own metadata: an object can be
// pinned by any number of releases, and rewriting a record's metadata would have
// to pass through every Store layer (compaction, encryption, tiering) and their
// private record fields.
//
// What a pin means for this package:
//
//   - LRU eviction (MaxSizeBytes) and TTL expiry never remove a pinned object;
//     a cache whose pinned objects alone exceed its size bound stays over it.
//   - Delete refuses a pinned key with ErrPinned. Every path that removes an
//     object for a reason other than its bytes being wrong — garbage collection,
//     a gate quarantining an artifact it refuses to serve, an administrator's
//     purge — goes through Delete and is refused. A gate's refusal does not
//     depend on the bytes being gone: the gates run on every request, cache
//     hits included.
//   - The one exception is the integrity layer: bytes that no longer match their
//     digest are worthless to the release, so it removes them under
//     WithPinOverride and the pin's owner fetches the object again.
//
// Tiered storage moves objects between tiers and never deletes one without
// having copied it first, so a pinned object may be demoted to the cold tier
// but is never dropped; it needs no knowledge of pins.

// ErrPinned is returned (wrapped) by Delete for a key a release has pinned.
var ErrPinned = errors.New("cache: object is pinned by a release manifest")

// PinChecker reports whether a cache key is pinned. Implementations must be
// fast and safe for concurrent use: the cache consults them while holding its
// own index lock, so they must not call back into the cache.
type PinChecker interface {
	IsPinned(key string) bool
}

// PinCheckerFunc adapts a function to the PinChecker interface.
type PinCheckerFunc func(key string) bool

// IsPinned implements PinChecker.
func (f PinCheckerFunc) IsPinned(key string) bool { return f(key) }

type pinOverrideKey struct{}

// WithPinOverride marks ctx as allowed to delete pinned keys. reason is
// recorded for diagnostics. Only the integrity layer uses it, for bytes that no
// longer match their recorded digest.
func WithPinOverride(ctx context.Context, reason string) context.Context {
	if reason == "" {
		reason = "override"
	}
	return context.WithValue(ctx, pinOverrideKey{}, reason)
}

// pinOverride reports whether ctx carries a pin override.
func pinOverride(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(pinOverrideKey{}).(string)
	return v != ""
}

// pinnedError builds the error Delete returns for a pinned key.
func pinnedError(key string) error {
	return fmt.Errorf("%w: %q is retained (releases depend on it)", ErrPinned, key)
}

// pinSetter is implemented by the caches that enforce pins themselves.
type pinSetter interface {
	SetPinChecker(p PinChecker)
}

// SetPinChecker installs p on the cache that enforces pins inside c — the
// FilesystemCache or MemoryCache beneath the IntegrityCache and SealedCache
// wrappers. It reports whether one was found.
func SetPinChecker(c Cache, p PinChecker) bool {
	for c != nil {
		if s, ok := c.(pinSetter); ok {
			s.SetPinChecker(p)
			return true
		}
		u, ok := c.(interface{ unwrapCache() Cache })
		if !ok {
			return false
		}
		c = u.unwrapCache()
	}
	return false
}

func (c *IntegrityCache) unwrapCache() Cache { return c.inner }
func (s *SealedCache) unwrapCache() Cache    { return s.inner }
