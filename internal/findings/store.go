package findings

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is a bounded, thread-safe retention layer for the most recent findings
// Document per artifact. The pull path records into it after every admission run
// so a CI pipeline can later retrieve an artifact's findings (as SARIF) without
// re-running the gates. It is intentionally in-memory and best-effort: it is a
// decoration/observability surface, not a system of record (the audit log and
// the per-gate stores are authoritative).
//
// Entries are keyed by (tenant, coordinate); a new pull of the same artifact
// replaces the prior document. The store is bounded by a max entry count with
// oldest-eviction so it cannot grow without limit on a busy proxy.
type Store struct {
	mu      sync.RWMutex
	max     int
	now     func() time.Time
	entries map[string]*entry
}

type entry struct {
	doc      Document
	recorded time.Time
}

// StoreOptions configures a Store.
type StoreOptions struct {
	// MaxEntries bounds retained documents (oldest-evicted). <=0 uses a default.
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
	return &Store{max: max, now: now, entries: make(map[string]*entry, 64)}
}

// key composes the retention key from tenant and coordinate. A blank coordinate
// falls back to the artifact name so an unversioned subject is still addressable.
func storeKey(tenant, coordinate string) string {
	return strings.ToLower(tenant) + "\x00" + coordinate
}

// Record upserts a document, stamping its GeneratedAt when unset and evicting the
// oldest entry if the store is over capacity. A document with no addressable
// coordinate (no name) is dropped, since it could never be looked up.
func (s *Store) Record(doc Document) {
	if s == nil {
		return
	}
	coord := doc.Artifact.Coordinate
	if coord == "" {
		coord = doc.Artifact.Name
	}
	if coord == "" {
		return
	}
	now := s.now()
	if doc.GeneratedAt.IsZero() {
		doc.GeneratedAt = now
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[storeKey(doc.Tenant, coord)] = &entry{doc: doc, recorded: now}
	s.evictLocked()
}

// evictLocked drops the oldest entries until the store is within capacity.
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
		delete(s.entries, all[i].key)
	}
}

// Get returns the retained document for an artifact. The pkg argument may be an
// exact coordinate ("lodash@4.17.21"), a bare name ("lodash", returning the
// most-recently-recorded version), or empty. It returns ok=false when nothing
// matches. The tenant is matched case-insensitively; an empty tenant matches the
// untenanted (or any) document for the package — see resolve semantics below.
func (s *Store) Get(tenant, pkg string) (Document, bool) {
	if s == nil {
		return Document{}, false
	}
	pkg = strings.TrimSpace(pkg)
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact (tenant, coordinate) hit.
	if e, ok := s.entries[storeKey(tenant, pkg)]; ok {
		return e.doc, true
	}
	// Otherwise scan for the best match: same tenant (or any when tenant blank),
	// matching the package by exact coordinate or by name, preferring the most
	// recently recorded.
	var best *entry
	for _, e := range s.entries {
		if tenant != "" && !strings.EqualFold(e.doc.Tenant, tenant) {
			continue
		}
		if !packageMatches(e.doc.Artifact, pkg) {
			continue
		}
		if best == nil || e.recorded.After(best.recorded) {
			best = e
		}
	}
	if best == nil {
		return Document{}, false
	}
	return best.doc, true
}

// packageMatches reports whether the artifact is addressed by pkg, which may be a
// coordinate, a bare name, or empty (matches anything).
func packageMatches(a Artifact, pkg string) bool {
	if pkg == "" {
		return true
	}
	if strings.EqualFold(a.Coordinate, pkg) || strings.EqualFold(a.Name, pkg) {
		return true
	}
	// Allow "name@version" to match an artifact whose coordinate is exactly that,
	// or a bare name match against the name component of a coordinate query.
	if i := strings.LastIndex(pkg, "@"); i > 0 {
		return strings.EqualFold(a.Name, pkg[:i]) && strings.EqualFold(a.Version, pkg[i+1:])
	}
	return false
}

// Documents returns all retained documents, optionally filtered by tenant and a
// case-insensitive package-name substring, most-recently-recorded first. It is
// the batch source for the admin list view and the batch SARIF export.
func (s *Store) Documents(tenant, q string) []Document {
	if s == nil {
		return nil
	}
	q = strings.ToLower(strings.TrimSpace(q))
	s.mu.RLock()
	defer s.mu.RUnlock()
	type rec struct {
		doc Document
		t   time.Time
	}
	recs := make([]rec, 0, len(s.entries))
	for _, e := range s.entries {
		if tenant != "" && !strings.EqualFold(e.doc.Tenant, tenant) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.doc.Artifact.Name), q) &&
			!strings.Contains(strings.ToLower(e.doc.Artifact.Coordinate), q) {
			continue
		}
		recs = append(recs, rec{e.doc, e.recorded})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].t.After(recs[j].t) })
	out := make([]Document, len(recs))
	for i := range recs {
		out[i] = recs[i].doc
	}
	return out
}

// Len reports the number of retained documents.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
