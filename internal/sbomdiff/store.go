package sbomdiff

import (
	"sort"
	"strings"
	"sync"
)

// historyKey identifies a coordinate's history bucket. Tenant is part of the key
// so one tenant's resolved dependency footprint is never compared against
// another's (per-tenant policy and mirrors can resolve the same coordinate
// differently).
type historyKey struct {
	tenant     string
	ecosystem  string
	coordinate string
}

func keyFor(tenant, ecosystem, coordinate string) historyKey {
	return historyKey{
		tenant:     strings.TrimSpace(tenant),
		ecosystem:  strings.ToLower(strings.TrimSpace(ecosystem)),
		coordinate: strings.TrimSpace(coordinate),
	}
}

// Store is a bounded, in-memory, per-coordinate history of resolved SBOM
// snapshots, enabling version-to-version diffs without persisting full SBOMs to
// disk. Each coordinate retains the most recent maxVersions snapshots; the store
// as a whole retains at most maxCoordinates buckets (the least-recently-updated
// bucket is evicted when the limit is exceeded). It is safe for concurrent use.
type Store struct {
	mu             sync.Mutex
	maxVersions    int
	maxCoordinates int
	buckets        map[historyKey]*bucket
	// order tracks bucket insertion/update recency for coordinate-level eviction.
	order []historyKey
}

type bucket struct {
	// snapshots are kept newest-last, deduplicated by version (a re-pull of the
	// same version replaces the prior snapshot in place).
	snapshots []Snapshot
}

// NewStore constructs a history store. maxVersions <= 0 defaults to 16;
// maxCoordinates <= 0 defaults to 4096.
func NewStore(maxVersions, maxCoordinates int) *Store {
	if maxVersions <= 0 {
		maxVersions = 16
	}
	if maxCoordinates <= 0 {
		maxCoordinates = 4096
	}
	return &Store{
		maxVersions:    maxVersions,
		maxCoordinates: maxCoordinates,
		buckets:        make(map[historyKey]*bucket),
	}
}

// Record inserts a snapshot into its coordinate's history, returning the most
// recent prior snapshot of a DIFFERENT version (the natural diff baseline) and
// whether one existed. A re-pull of an already-recorded version updates that
// version's snapshot in place and does not return it as a prior.
func (s *Store) Record(snap Snapshot) (Snapshot, bool) {
	snap.normalize()
	key := keyFor(snap.Tenant, snap.Ecosystem, snap.Coordinate)

	s.mu.Lock()
	defer s.mu.Unlock()

	b := s.buckets[key]
	if b == nil {
		b = &bucket{}
		s.buckets[key] = b
		s.order = append(s.order, key)
		s.evictCoordinatesLocked()
	} else {
		s.touchLocked(key)
	}

	// The diff baseline is the newest snapshot of a different version, captured
	// before we mutate the bucket.
	var prior Snapshot
	havePrior := false
	for i := len(b.snapshots) - 1; i >= 0; i-- {
		if !strings.EqualFold(b.snapshots[i].Version, snap.Version) {
			prior = b.snapshots[i]
			havePrior = true
			break
		}
	}

	// Replace an existing same-version snapshot in place, else append.
	replaced := false
	for i := range b.snapshots {
		if strings.EqualFold(b.snapshots[i].Version, snap.Version) {
			b.snapshots[i] = snap
			replaced = true
			break
		}
	}
	if !replaced {
		b.snapshots = append(b.snapshots, snap)
		if len(b.snapshots) > s.maxVersions {
			// Drop the oldest snapshot.
			b.snapshots = b.snapshots[len(b.snapshots)-s.maxVersions:]
		}
	}

	return prior, havePrior
}

// Snapshot returns the recorded snapshot for an exact version of a coordinate.
func (s *Store) Snapshot(tenant, ecosystem, coordinate, version string) (Snapshot, bool) {
	key := keyFor(tenant, ecosystem, coordinate)
	version = strings.TrimSpace(version)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[key]
	if b == nil {
		return Snapshot{}, false
	}
	for i := len(b.snapshots) - 1; i >= 0; i-- {
		if strings.EqualFold(b.snapshots[i].Version, version) {
			return b.snapshots[i], true
		}
	}
	return Snapshot{}, false
}

// History returns the retained snapshots for a coordinate, oldest first. The
// returned slice is a copy and safe for the caller to retain.
func (s *Store) History(tenant, ecosystem, coordinate string) []Snapshot {
	key := keyFor(tenant, ecosystem, coordinate)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[key]
	if b == nil {
		return nil
	}
	out := make([]Snapshot, len(b.snapshots))
	copy(out, b.snapshots)
	return out
}

// Latest returns the two most recent snapshots of distinct versions for a
// coordinate (previous, current), enabling a "what changed in the newest
// version" diff. ok is false when fewer than two distinct versions are held.
func (s *Store) Latest(tenant, ecosystem, coordinate string) (prev, cur Snapshot, ok bool) {
	hist := s.History(tenant, ecosystem, coordinate)
	if len(hist) < 2 {
		return Snapshot{}, Snapshot{}, false
	}
	cur = hist[len(hist)-1]
	for i := len(hist) - 2; i >= 0; i-- {
		if !strings.EqualFold(hist[i].Version, cur.Version) {
			return hist[i], cur, true
		}
	}
	return Snapshot{}, Snapshot{}, false
}

// CoordinateRef summarizes a tracked coordinate for the admin listing.
type CoordinateRef struct {
	Tenant     string   `json:"tenant,omitempty"`
	Ecosystem  string   `json:"ecosystem"`
	Coordinate string   `json:"coordinate"`
	Versions   []string `json:"versions"`
}

// Coordinates returns the tracked coordinates and their retained versions,
// sorted for a stable admin listing. A non-empty limit bounds the result.
func (s *Store) Coordinates(limit int) []CoordinateRef {
	s.mu.Lock()
	refs := make([]CoordinateRef, 0, len(s.buckets))
	for key, b := range s.buckets {
		versions := make([]string, 0, len(b.snapshots))
		for _, snap := range b.snapshots {
			versions = append(versions, snap.Version)
		}
		refs = append(refs, CoordinateRef{
			Tenant:     key.tenant,
			Ecosystem:  key.ecosystem,
			Coordinate: key.coordinate,
			Versions:   versions,
		})
	}
	s.mu.Unlock()

	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Ecosystem != refs[j].Ecosystem {
			return refs[i].Ecosystem < refs[j].Ecosystem
		}
		if refs[i].Coordinate != refs[j].Coordinate {
			return refs[i].Coordinate < refs[j].Coordinate
		}
		return refs[i].Tenant < refs[j].Tenant
	})
	if limit > 0 && len(refs) > limit {
		refs = refs[:limit]
	}
	return refs
}

// Len reports the number of tracked coordinate buckets.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets)
}

// touchLocked moves key to the most-recent position in the recency order.
func (s *Store) touchLocked(key historyKey) {
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	s.order = append(s.order, key)
}

// evictCoordinatesLocked drops the least-recently-updated coordinate buckets
// until the store is within its coordinate limit.
func (s *Store) evictCoordinatesLocked() {
	for len(s.order) > s.maxCoordinates {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.buckets, oldest)
	}
}
