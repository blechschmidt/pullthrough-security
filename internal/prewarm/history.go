package prewarm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// PullEvent is one observed client pull, reported by the gateway's pull-observer
// tap. It is the raw "historical pull telemetry" the predictor analyses. Only
// genuine client pulls are reported — the subsystem's own synthetic pre-warm
// fetches are tagged and excluded upstream, so pre-warming can never bootstrap a
// prediction off its own activity.
type PullEvent struct {
	Backend   string
	Ecosystem string
	Name      string
	Version   string
	// Path is the full client request path, e.g.
	// "/v1/pip/files/.../foo-1.2.3.tar.gz". It is replayed verbatim, with the
	// version substituted, to pre-warm a predicted release.
	Path string
	// Tenant is the team the pull was billed to (empty when unscoped). It is
	// retained so a pre-warm can be issued under the same tenant namespace when
	// per-tenant cache namespacing is enabled, ensuring the warmed key matches the
	// one a later client read will hit.
	Tenant   string
	CacheHit bool
	Size     int64
	At       time.Time
}

// VersionStat is the observed pull activity for one concrete version.
type VersionStat struct {
	Version  string    `json:"version"`
	Path     string    `json:"path"`
	Pulls    int       `json:"pulls"`
	LastPull time.Time `json:"lastPull"`
}

// CoordStats is the aggregated pull history for one (backend, name) coordinate
// across every version observed.
type CoordStats struct {
	Backend   string        `json:"backend"`
	Ecosystem string        `json:"ecosystem"`
	Name      string        `json:"name"`
	Tenant    string        `json:"tenant,omitempty"`
	Pulls     int           `json:"pulls"`
	FirstSeen time.Time     `json:"firstSeen"`
	LastPull  time.Time     `json:"lastPull"`
	Versions  []VersionStat `json:"versions"`
}

// maxVersionsPerCoord bounds the distinct versions tracked per coordinate so a
// coordinate pulled across thousands of versions cannot grow memory without
// bound. The highest versions are what the predictor needs.
const maxVersionsPerCoord = 128

type versionRecord struct {
	path     string
	pulls    int
	lastPull time.Time
}

type coordRecord struct {
	backend    string
	ecosystem  string
	name       string
	lastTenant string
	pulls      int
	firstSeen  time.Time
	lastPull   time.Time
	versions   map[string]*versionRecord
}

// History is a bounded, concurrency-safe record of observed pulls, optionally
// persisted to disk so learned patterns survive a restart. It is the predictor's
// sole input.
type History struct {
	mu       sync.Mutex
	records  map[string]*coordRecord // key: backend+"\x00"+name
	maxCoord int
	now      func() time.Time
}

// NewHistory constructs a History bounding the number of distinct coordinates
// tracked to maxCoord (<=0 defaults to 4096). now may be nil (defaults to
// time.Now).
func NewHistory(maxCoord int, now func() time.Time) *History {
	if maxCoord <= 0 {
		maxCoord = 4096
	}
	if now == nil {
		now = time.Now
	}
	return &History{
		records:  make(map[string]*coordRecord),
		maxCoord: maxCoord,
		now:      now,
	}
}

func coordKey(backend, name string) string { return backend + "\x00" + name }

// Observe folds one pull into the history. Events missing a backend or name are
// ignored (nothing actionable can be predicted from them).
func (h *History) Observe(ev PullEvent) {
	if h == nil || ev.Backend == "" || ev.Name == "" {
		return
	}
	at := ev.At
	if at.IsZero() {
		at = h.now()
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	key := coordKey(ev.Backend, ev.Name)
	rec := h.records[key]
	isNew := rec == nil
	if isNew {
		rec = &coordRecord{
			backend:   ev.Backend,
			ecosystem: ev.Ecosystem,
			name:      ev.Name,
			firstSeen: at,
			versions:  make(map[string]*versionRecord),
		}
		h.records[key] = rec
	}
	rec.pulls++
	if ev.Ecosystem != "" {
		rec.ecosystem = ev.Ecosystem
	}
	if ev.Tenant != "" {
		rec.lastTenant = ev.Tenant
	}
	if at.After(rec.lastPull) {
		rec.lastPull = at
	}

	if ev.Version != "" {
		vr := rec.versions[ev.Version]
		if vr == nil {
			// Bound the per-coordinate version set, dropping the least-recently
			// pulled version to make room.
			if len(rec.versions) >= maxVersionsPerCoord {
				h.dropOldestVersionLocked(rec)
			}
			vr = &versionRecord{}
			rec.versions[ev.Version] = vr
		}
		vr.pulls++
		if ev.Path != "" {
			vr.path = ev.Path
		}
		if at.After(vr.lastPull) {
			vr.lastPull = at
		}
	}

	// Evict only after the new record's lastPull is set, so the eviction scan
	// does not mistake the just-inserted record for the least-recently-pulled one.
	if isNew {
		h.evictLocked()
	}
}

// evictLocked drops the least-recently-pulled coordinate when the map exceeds
// its bound. Called with h.mu held, right after inserting a new record.
func (h *History) evictLocked() {
	if len(h.records) <= h.maxCoord {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, r := range h.records {
		if first || r.lastPull.Before(oldest) {
			oldestKey, oldest, first = k, r.lastPull, false
		}
	}
	if oldestKey != "" {
		delete(h.records, oldestKey)
	}
}

func (h *History) dropOldestVersionLocked(rec *coordRecord) {
	var oldestV string
	var oldest time.Time
	first := true
	for v, r := range rec.versions {
		if first || r.lastPull.Before(oldest) {
			oldestV, oldest, first = v, r.lastPull, false
		}
	}
	if oldestV != "" {
		delete(rec.versions, oldestV)
	}
}

// Snapshot returns a deterministically ordered copy of the recorded history.
func (h *History) Snapshot() []CoordStats {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshotLocked()
}

func (h *History) snapshotLocked() []CoordStats {
	out := make([]CoordStats, 0, len(h.records))
	for _, rec := range h.records {
		cs := CoordStats{
			Backend:   rec.backend,
			Ecosystem: rec.ecosystem,
			Name:      rec.name,
			Tenant:    rec.lastTenant,
			Pulls:     rec.pulls,
			FirstSeen: rec.firstSeen,
			LastPull:  rec.lastPull,
			Versions:  make([]VersionStat, 0, len(rec.versions)),
		}
		for v, vr := range rec.versions {
			cs.Versions = append(cs.Versions, VersionStat{
				Version:  v,
				Path:     vr.path,
				Pulls:    vr.pulls,
				LastPull: vr.lastPull,
			})
		}
		sort.Slice(cs.Versions, func(i, j int) bool {
			return cs.Versions[i].Version < cs.Versions[j].Version
		})
		out = append(out, cs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Backend != out[j].Backend {
			return out[i].Backend < out[j].Backend
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Len reports the number of distinct coordinates currently tracked.
func (h *History) Len() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

// persistState is the on-disk history schema (atomic temp-file + rename).
type persistState struct {
	Version int          `json:"version"`
	SavedAt string       `json:"savedAt"`
	Coords  []CoordStats `json:"coords"`
}

// Save writes the history to path atomically. A blank path is a no-op.
func (h *History) Save(path string) error {
	if h == nil || path == "" {
		return nil
	}
	snap := h.Snapshot()
	st := persistState{Version: 1, SavedAt: h.now().UTC().Format(time.RFC3339), Coords: snap}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("prewarm: marshaling history: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("prewarm: creating history dir: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("prewarm: writing history: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("prewarm: replacing history: %w", err)
	}
	return nil
}

// Load replaces the in-memory history with the contents of path. A missing file
// is not an error (a fresh deployment simply starts with no history). A blank
// path is a no-op.
func (h *History) Load(path string) error {
	if h == nil || path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("prewarm: reading history: %w", err)
	}
	var st persistState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("prewarm: parsing history: %w", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = make(map[string]*coordRecord, len(st.Coords))
	for _, cs := range st.Coords {
		if cs.Backend == "" || cs.Name == "" {
			continue
		}
		rec := &coordRecord{
			backend:    cs.Backend,
			ecosystem:  cs.Ecosystem,
			name:       cs.Name,
			lastTenant: cs.Tenant,
			pulls:      cs.Pulls,
			firstSeen:  cs.FirstSeen,
			lastPull:   cs.LastPull,
			versions:   make(map[string]*versionRecord, len(cs.Versions)),
		}
		for _, vs := range cs.Versions {
			if vs.Version == "" {
				continue
			}
			rec.versions[vs.Version] = &versionRecord{path: vs.Path, pulls: vs.Pulls, lastPull: vs.LastPull}
		}
		h.records[coordKey(cs.Backend, cs.Name)] = rec
	}
	return nil
}
