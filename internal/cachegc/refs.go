package cachegc

import (
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// ReferenceSource reports whether a cached entry is still referenced by some
// out-of-band evidence (a provenance link, an audit record, an active
// investigation/quarantine) and must therefore be retained even under eviction
// pressure. Multiple sources compose; an entry is retained if any source claims
// it. Implementations must be safe for concurrent use.
type ReferenceSource interface {
	// Name identifies the source in retention reports and logs.
	Name() string
	// Referenced reports whether e must be retained, with a short reason suitable
	// for a retention report (the reason is only consulted when the bool is true).
	Referenced(e cache.GCEntry) (bool, string)
}

// isTruthy reports whether a metadata flag value means "on".
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "pinned":
		return true
	default:
		return false
	}
}

// MetadataPinSource retains any entry whose metadata carries a truthy pin marker.
// It is the generic, restart- and replica-safe pin: a gate that establishes
// evidence (signed-and-attested artifact, quarantine-for-investigation) sets the
// marker on the cached entry's metadata and the GC honors it without coupling to
// that gate. The default marker is cache.MetaPin ("pin"); additional keys may be
// supplied.
type MetadataPinSource struct {
	keys []string
}

// NewMetadataPinSource builds a pin source honoring cache.MetaPin plus any extra
// metadata keys (each treated as a truthy flag).
func NewMetadataPinSource(extraKeys ...string) *MetadataPinSource {
	keys := append([]string{cache.MetaPin}, extraKeys...)
	return &MetadataPinSource{keys: keys}
}

// Name implements ReferenceSource.
func (s *MetadataPinSource) Name() string { return "pin" }

// Referenced implements ReferenceSource.
func (s *MetadataPinSource) Referenced(e cache.GCEntry) (bool, string) {
	for _, k := range s.keys {
		if isTruthy(e.Metadata[k]) {
			return true, "pinned (" + k + ")"
		}
	}
	return false, ""
}

// KeySetSource retains entries that belong to a dynamically-computed set of
// protected identifiers — the seam used to wire concrete evidence holders (e.g.
// the set of quarantined content digests, or artifacts that are nodes in the
// provenance graph). The set is recomputed on each call so it always reflects the
// live state of the owning subsystem.
//
// An entry matches when its key, or any of its metadata values, is present in the
// set. This tolerates both digest-keyed and coordinate-keyed caches without the
// GC needing to understand either subsystem's key scheme.
type KeySetSource struct {
	name string
	set  func() map[string]struct{}
}

// NewKeySetSource builds a KeySetSource named name whose protected set is
// produced by fn on demand. A nil fn yields an empty (never-matching) set.
func NewKeySetSource(name string, fn func() map[string]struct{}) *KeySetSource {
	return &KeySetSource{name: name, set: fn}
}

// Name implements ReferenceSource.
func (s *KeySetSource) Name() string { return s.name }

// Referenced implements ReferenceSource.
func (s *KeySetSource) Referenced(e cache.GCEntry) (bool, string) {
	if s.set == nil {
		return false, ""
	}
	set := s.set()
	if len(set) == 0 {
		return false, ""
	}
	if _, ok := set[e.Key]; ok {
		return true, "referenced: " + s.name
	}
	for _, v := range e.Metadata {
		if v == "" {
			continue
		}
		if _, ok := set[v]; ok {
			return true, "referenced: " + s.name
		}
	}
	return false, ""
}

// RefTracker is a manual, counted reference holder: callers Retain a key while
// they hold evidence that depends on its cached bytes (an in-progress provenance
// build, an export bundling the artifact) and Release it when done. An entry with
// a positive count is never evicted. It is a ReferenceSource so it plugs straight
// into the engine. Safe for concurrent use.
type RefTracker struct {
	mu     sync.Mutex
	counts map[string]int
}

// NewRefTracker constructs an empty RefTracker.
func NewRefTracker() *RefTracker {
	return &RefTracker{counts: make(map[string]int)}
}

// Retain increments the reference count for key, protecting it from eviction.
func (t *RefTracker) Retain(key string) {
	t.mu.Lock()
	t.counts[key]++
	t.mu.Unlock()
}

// Release decrements the reference count for key, removing the hold at zero. It
// never drives the count below zero.
func (t *RefTracker) Release(key string) {
	t.mu.Lock()
	if n := t.counts[key]; n > 1 {
		t.counts[key] = n - 1
	} else {
		delete(t.counts, key)
	}
	t.mu.Unlock()
}

// Count returns the current reference count for key.
func (t *RefTracker) Count(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counts[key]
}

// Name implements ReferenceSource.
func (t *RefTracker) Name() string { return "ref-hold" }

// Referenced implements ReferenceSource.
func (t *RefTracker) Referenced(e cache.GCEntry) (bool, string) {
	t.mu.Lock()
	n := t.counts[e.Key]
	t.mu.Unlock()
	if n > 0 {
		return true, "referenced: active hold"
	}
	return false, ""
}
