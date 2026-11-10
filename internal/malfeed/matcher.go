package malfeed

import (
	"sort"
	"strings"
)

// Matcher is an immutable, indexed view over a set of known-malicious Entries.
// It is built once (from a feed fetch, a bundle import, or static config) and
// then queried concurrently; the live Service swaps a whole Matcher atomically
// on refresh, so a Matcher itself never mutates and needs no locking.
type Matcher struct {
	// index maps "ecosystem\x00normalizedName" to the entries for that package.
	// A package usually has a single entry, but multiple feed sources (or several
	// disjoint affected ranges) can contribute more than one.
	index map[string][]*Entry
	// entries is the flat, de-duplicated list in stable order, for listing and
	// re-export.
	entries []*Entry
	// byEcosystem counts entries per canonical ecosystem, for metrics and status.
	byEcosystem map[string]int
}

// Match is the result of querying the matcher for a coordinate. Matched reports
// whether the coordinate is known malicious; when true, Entry points at the
// record that fired (the most specific / first in stable order).
type Match struct {
	Matched bool
	Entry   *Entry
}

// indexKey builds the composite lookup key for a normalized coordinate.
func indexKey(eco, normName string) string {
	return eco + "\x00" + normName
}

// NewMatcher builds a Matcher from entries, normalizing and de-duplicating them.
// Entries with no usable package name are dropped. The input slice is not
// retained (each entry is copied into the index), so the caller may reuse it.
func NewMatcher(entries []Entry) *Matcher {
	m := &Matcher{
		index:       make(map[string][]*Entry),
		byEcosystem: make(map[string]int),
	}
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		e := entries[i] // copy
		e.Aliases = dedupeStrings(e.Aliases)
		e.Categories = dedupeStrings(e.Categories)
		e.finalize()
		if e.norm == "" || e.Ecosystem == "" {
			continue
		}
		// De-duplicate on (ecosystem, name, id) so the same advisory ingested from
		// two sources collapses to one entry.
		dk := e.Ecosystem + "\x00" + e.norm + "\x00" + e.ID
		if _, ok := seen[dk]; ok {
			continue
		}
		seen[dk] = struct{}{}

		stored := &e
		key := indexKey(e.Ecosystem, e.norm)
		m.index[key] = append(m.index[key], stored)
		m.entries = append(m.entries, stored)
		m.byEcosystem[e.Ecosystem]++
	}
	// Stable order: by ecosystem, then normalized name, then id.
	sort.SliceStable(m.entries, func(i, j int) bool {
		a, b := m.entries[i], m.entries[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.norm != b.norm {
			return a.norm < b.norm
		}
		return a.ID < b.ID
	})
	return m
}

// Match looks up a coordinate. It returns Matched=false (and a nil Entry) when
// the coordinate is not known malicious — the overwhelmingly common case, so the
// lookup is a single map access plus a short version scan.
func (m *Matcher) Match(c Coordinate) Match {
	if m == nil {
		return Match{}
	}
	eco := CanonicalEcosystem(c.Ecosystem)
	norm := normalizeName(eco, c.Name)
	if norm == "" {
		return Match{}
	}
	cands := m.index[indexKey(eco, norm)]
	if len(cands) == 0 {
		return Match{}
	}
	nv := normalizeVersion(c.Version)
	for _, e := range cands {
		if e.matchesVersion(nv) {
			return Match{Matched: true, Entry: e}
		}
	}
	return Match{}
}

// Len reports the total number of loaded entries.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.entries)
}

// CountsByEcosystem returns a copy of the per-ecosystem entry counts.
func (m *Matcher) CountsByEcosystem() map[string]int {
	out := make(map[string]int)
	if m == nil {
		return out
	}
	for k, v := range m.byEcosystem {
		out[k] = v
	}
	return out
}

// Entries returns the loaded entries in stable order. The returned slice is a
// fresh copy of value entries, so callers may not observe the internal pointers.
func (m *Matcher) Entries() []Entry {
	if m == nil {
		return nil
	}
	out := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, *e)
	}
	return out
}

// Search returns up to limit entries (0 = no limit) matching the query across
// ecosystem, name, id, alias, summary, and category, in stable order. An empty
// query matches everything (useful for paging the full list). The optional
// ecosystem filter, when non-empty, restricts to that canonical ecosystem.
func (m *Matcher) Search(query, ecosystem string, limit int) []Entry {
	if m == nil {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	ecoFilter := ""
	if strings.TrimSpace(ecosystem) != "" {
		ecoFilter = CanonicalEcosystem(ecosystem)
	}
	out := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		if ecoFilter != "" && e.Ecosystem != ecoFilter {
			continue
		}
		if q != "" && !e.matchesQuery(q) {
			continue
		}
		out = append(out, *e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// matchesQuery reports whether the entry contains q (already lowercased) in any
// searchable field.
func (e *Entry) matchesQuery(q string) bool {
	if strings.Contains(strings.ToLower(e.ID), q) ||
		strings.Contains(strings.ToLower(e.Name), q) ||
		strings.Contains(e.norm, q) ||
		strings.Contains(strings.ToLower(e.Summary), q) ||
		strings.Contains(e.Ecosystem, q) {
		return true
	}
	for _, a := range e.Aliases {
		if strings.Contains(strings.ToLower(a), q) {
			return true
		}
	}
	for _, c := range e.Categories {
		if strings.Contains(strings.ToLower(c), q) {
			return true
		}
	}
	return false
}
