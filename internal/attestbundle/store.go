package attestbundle

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// Store is a bounded, thread-safe retention layer for the most recent signed
// attestation Bundle per artifact. The pull path records into it after admitting
// and serving an artifact so the admin/CLI export and the OCI referrers endpoint
// can later serve the proxy's attestation without re-deriving it. Like the
// findings store it is in-memory and best-effort: the audit log (which carries
// each bundle's digest) is the authoritative, tamper-evident record.
//
// Entries are keyed by (tenant, coordinate); a re-pull replaces the prior bundle.
// A secondary index maps a subject content digest to the keys that carry it, so
// the referrers endpoint (which is digest-addressed, OCI-style) is O(1) without
// scanning. The store is bounded with oldest-eviction.
type Store struct {
	mu      sync.RWMutex
	max     int
	now     func() time.Time
	entries map[string]*storeEntry // key -> bundle
	byDig   map[string]map[string]struct{}
}

type storeEntry struct {
	bundle   *Bundle
	recorded time.Time
}

// StoreOptions configures a Store.
type StoreOptions struct {
	// MaxEntries bounds retained bundles (oldest-evicted). <=0 uses a default.
	MaxEntries int
	// Now overrides the clock (tests). Nil uses time.Now.
	Now func() time.Time
}

const defaultMaxEntries = 2048

// NewStore constructs a retention store.
func NewStore(opts StoreOptions) *Store {
	max := opts.MaxEntries
	if max <= 0 {
		max = defaultMaxEntries
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Store{
		max:     max,
		now:     now,
		entries: make(map[string]*storeEntry, 64),
		byDig:   make(map[string]map[string]struct{}, 64),
	}
}

func storeKey(tenant, coordinate string) string {
	return strings.ToLower(tenant) + "\x00" + coordinate
}

// Record upserts a bundle keyed by (tenant, coordinate), maintaining the digest
// index and evicting the oldest entry when over capacity. A bundle with no
// coordinate is dropped (it could never be looked up by the admin/CLI surface).
func (s *Store) Record(b *Bundle) {
	if s == nil || b == nil || b.Coordinate == "" {
		return
	}
	key := storeKey(b.Tenant, b.Coordinate)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Drop the old digest index entry for this key, if the coordinate previously
	// carried a different subject digest.
	if old, ok := s.entries[key]; ok {
		s.unindexLocked(key, old.bundle.SubjectDigest)
	}
	s.entries[key] = &storeEntry{bundle: b, recorded: s.now()}
	s.indexLocked(key, b.SubjectDigest)
	s.evictLocked()
}

func (s *Store) indexLocked(key, digest string) {
	if digest == "" {
		return
	}
	set := s.byDig[digest]
	if set == nil {
		set = make(map[string]struct{}, 1)
		s.byDig[digest] = set
	}
	set[key] = struct{}{}
}

func (s *Store) unindexLocked(key, digest string) {
	if digest == "" {
		return
	}
	if set := s.byDig[digest]; set != nil {
		delete(set, key)
		if len(set) == 0 {
			delete(s.byDig, digest)
		}
	}
}

func (s *Store) evictLocked() {
	if len(s.entries) <= s.max {
		return
	}
	type kv struct {
		key string
		t   time.Time
	}
	all := make([]kv, 0, len(s.entries))
	for k, e := range s.entries {
		all = append(all, kv{k, e.recorded})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for i := 0; i < len(all)-s.max; i++ {
		k := all[i].key
		if e := s.entries[k]; e != nil {
			s.unindexLocked(k, e.bundle.SubjectDigest)
		}
		delete(s.entries, k)
	}
}

// AttachRekor republishes bundle b carrying the transparency-log pointer p, but
// only when the entry currently stored for b's (tenant, coordinate) is still the
// same bundle (by envelope digest). This makes the asynchronous submit path
// safe against a concurrent re-pull: if a newer bundle replaced b meanwhile, the
// stale pointer is dropped rather than clobbering the newer entry. It returns
// whether the pointer was attached.
func (s *Store) AttachRekor(b *Bundle, p *rekor.Pointer) bool {
	if s == nil || b == nil || b.Coordinate == "" {
		return false
	}
	key := storeKey(b.Tenant, b.Coordinate)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.entries[key]
	if !ok || cur.bundle == nil || cur.bundle.Digest != b.Digest {
		return false
	}
	// Replace in place, preserving the recorded time and digest index (the subject
	// digest is unchanged, so no reindex is needed).
	cur.bundle = b.withRekor(p)
	return true
}

// Get returns the retained bundle for an artifact. pkg may be an exact coordinate
// ("lodash@4.17.21"), a bare name (latest recorded version), or empty. The tenant
// is matched case-insensitively; an empty tenant matches any tenant's bundle.
func (s *Store) Get(tenant, pkg string) (*Bundle, bool) {
	if s == nil {
		return nil, false
	}
	pkg = strings.TrimSpace(pkg)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if e, ok := s.entries[storeKey(tenant, pkg)]; ok {
		return e.bundle, true
	}
	var best *storeEntry
	for _, e := range s.entries {
		if tenant != "" && !strings.EqualFold(e.bundle.Tenant, tenant) {
			continue
		}
		if !coordinateMatches(e.bundle, pkg) {
			continue
		}
		if best == nil || e.recorded.After(best.recorded) {
			best = e
		}
	}
	if best == nil {
		return nil, false
	}
	return best.bundle, true
}

func coordinateMatches(b *Bundle, pkg string) bool {
	if pkg == "" {
		return true
	}
	if strings.EqualFold(b.Coordinate, pkg) {
		return true
	}
	// Bare-name match against the name component of a "name@version" coordinate.
	name := b.Coordinate
	if i := strings.LastIndex(b.Coordinate, "@"); i > 0 {
		name = b.Coordinate[:i]
	}
	return strings.EqualFold(name, pkg)
}

// ByDigest returns every retained bundle whose subject content digest equals
// digest, most-recently-recorded first. It backs the OCI referrers endpoint.
func (s *Store) ByDigest(digest string) []*Bundle {
	if s == nil || digest == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := s.byDig[digest]
	if len(set) == 0 {
		return nil
	}
	out := make([]*storeEntry, 0, len(set))
	for key := range set {
		if e := s.entries[key]; e != nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].recorded.After(out[j].recorded) })
	bundles := make([]*Bundle, len(out))
	for i := range out {
		bundles[i] = out[i].bundle
	}
	return bundles
}

// Documents returns all retained bundles, optionally filtered by tenant and a
// case-insensitive coordinate substring, most-recently-recorded first.
func (s *Store) Documents(tenant, q string) []*Bundle {
	if s == nil {
		return nil
	}
	q = strings.ToLower(strings.TrimSpace(q))
	s.mu.RLock()
	defer s.mu.RUnlock()
	type rec struct {
		b *Bundle
		t time.Time
	}
	recs := make([]rec, 0, len(s.entries))
	for _, e := range s.entries {
		if tenant != "" && !strings.EqualFold(e.bundle.Tenant, tenant) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.bundle.Coordinate), q) {
			continue
		}
		recs = append(recs, rec{e.bundle, e.recorded})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].t.After(recs[j].t) })
	out := make([]*Bundle, len(recs))
	for i := range recs {
		out[i] = recs[i].b
	}
	return out
}

// Len reports the number of retained bundles.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
