package cache

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// This file implements the tiered cache storage layer (Task 154): a Store
// decorator that composes two underlying Stores — a fast "hot" backend
// (typically the local filesystem) and a slower/cheaper "cold" backend
// (typically the S3-compatible object store from Task 20) — keeping frequently
// and recently used artifacts hot while demoting cold artifacts to the cheap
// tier on a leader-gated background sweep, and transparently promoting a cold
// artifact back to hot on a read hit.
//
// Each artifact lives in exactly one tier at a time (hot XOR cold), so tiering
// never doubles the stored footprint: a promotion copies cold->hot then deletes
// the cold copy; a demotion copies hot->cold then deletes the hot copy. An
// in-process access tracker (last-access recency + a process-local access
// count, aligned with the GC/eviction policy engine's LRU/LFU signals from
// Task 39) drives the demotion victim selection.
//
// Composition: the layer sits INNERMOST in the Store stack, wrapping the
// durable byte stores and sitting beneath the at-rest encryption (Task 141) and
// compaction/dedup (Task 125) decorators. It therefore only ever moves opaque,
// already-transformed bytes between tiers and preserves every Record field
// verbatim across a tier move (origin/content-type/ETag/timestamps and the
// reserved pte.*/ptc.* sidecars), so the digest-over-plaintext invariant is
// upheld by the layers above it. A tier move re-Puts the identical bytes, so the
// destination store recomputes the same content digest it had in the source
// tier; the fixity baseline (Task 107) is unchanged.

// ErrTieringDisabled is returned by the controller helpers when no tiering layer
// is present in the cache stack.
var ErrTieringDisabled = errors.New("cache: tiered storage is not enabled")

// errDemoteAborted is an internal sentinel: a demotion candidate was accessed,
// promoted, overwritten, or deleted between the sweep snapshot and the move, so
// the demotion was safely abandoned (it is counted as "skipped", not an error).
var errDemoteAborted = errors.New("cache: tier demotion aborted (entry changed)")

// tier identifies which backend holds an artifact.
type tier uint8

const (
	tierHot tier = iota
	tierCold
)

func (t tier) String() string {
	if t == tierCold {
		return "cold"
	}
	return "hot"
}

// tierKeyStripes is the number of striped key locks used to serialize the
// mutating moves (Put / promote / demote) of a single key against each other
// without serializing unrelated keys or the (lock-free) read path.
const tierKeyStripes = 256

// TieredOptions configures a tiered Store decorator.
type TieredOptions struct {
	// Hot is the fast backend that newly written and recently/frequently used
	// artifacts live on. Required.
	Hot Store
	// Cold is the slower/cheaper backend that idle artifacts are demoted to.
	// Required, and must be a distinct store from Hot.
	Cold Store

	// PromoteOnRead copies a cold artifact back to the hot tier when it is read,
	// so a resurgent artifact migrates back to fast storage automatically.
	PromoteOnRead bool
	// DemoteAfterIdle is the idle window after which a hot artifact becomes a
	// demotion candidate: if it has not been read for at least this long it is
	// demoted on the next sweep. Zero disables idle-based demotion.
	DemoteAfterIdle time.Duration
	// HotMaxBytes is a soft cap on the hot tier's total bytes. When the hot tier
	// exceeds it, the sweep demotes least-recently-used hot artifacts until the
	// tier is back under the cap. Zero means the hot tier is unbounded (only
	// idle-based demotion applies).
	HotMaxBytes int64
	// MinAccessesToStayHot is a frequency floor: a hot artifact that has been read
	// at least this many times is protected from idle-based demotion (capacity
	// pressure can still demote it). Zero disables the frequency override.
	MinAccessesToStayHot int64
	// SweepInterval is the cadence of the background demotion sweep. Zero disables
	// the background sweep entirely (demotion then runs only when SweepTiers is
	// called explicitly).
	SweepInterval time.Duration

	// Logger receives sweep/transition diagnostics. Defaults to a discard logger.
	Logger *slog.Logger
	// now overrides the clock for deterministic tests. Defaults to time.Now.
	now func() time.Time
}

// TieredStats is an immutable snapshot of the tiering layer's configuration and
// cumulative counters, exported both to Prometheus and to the admin/ptctl
// status report.
type TieredStats struct {
	Enabled              bool   `json:"enabled"`
	PromoteOnRead        bool   `json:"promoteOnRead"`
	DemoteAfterIdle      string `json:"demoteAfterIdle,omitempty"`
	HotMaxBytes          int64  `json:"hotMaxBytes"`
	MinAccessesToStayHot int64  `json:"minAccessesToStayHot"`
	SweepInterval        string `json:"sweepInterval,omitempty"`

	// Promotions / Demotions count artifacts migrated between tiers over the
	// process lifetime; the *Failures counters count moves that errored.
	Promotions      int64 `json:"promotions"`
	Demotions       int64 `json:"demotions"`
	PromoteFailures int64 `json:"promoteFailures"`
	DemoteFailures  int64 `json:"demoteFailures"`

	// HotHits / ColdHits count reads served from an artifact residing on each
	// tier at lookup time; HotTierHitRatio is HotHits/(HotHits+ColdHits).
	HotHits         int64   `json:"hotHits"`
	ColdHits        int64   `json:"coldHits"`
	HotTierHitRatio float64 `json:"hotTierHitRatio"`

	// Sweeps counts completed demotion sweeps; LastSweep is the most recent.
	Sweeps    int64     `json:"sweeps"`
	LastSweep time.Time `json:"lastSweep,omitempty"`

	// Live per-tier gauges.
	HotObjects  int64 `json:"hotObjects"`
	ColdObjects int64 `json:"coldObjects"`
	HotBytes    int64 `json:"hotBytes"`
	ColdBytes   int64 `json:"coldBytes"`
}

// TierSweepReport summarizes one demotion sweep.
type TierSweepReport struct {
	StartedAt        time.Time `json:"startedAt"`
	Duration         string    `json:"duration"`
	HotObjectsBefore int       `json:"hotObjectsBefore"`
	Candidates       int       `json:"candidates"`
	Demoted          int       `json:"demoted"`
	Skipped          int       `json:"skipped"`
	Errors           int       `json:"errors"`
	// SampleErrors holds a bounded sample of human-readable error descriptions
	// (each naming only a cache key and reason, never content).
	SampleErrors []string `json:"sampleErrors,omitempty"`
}

// TieredStatSource is implemented by a cache (directly or via the decorator
// unwrap chain) that can report tiering statistics.
type TieredStatSource interface {
	TieredStats() TieredStats
}

// tierEntry is the in-memory tracker record for a single artifact: which tier
// holds it, its physical size, and the recency/frequency signals that drive
// demotion.
type tierEntry struct {
	tier       tier
	size       int64
	lastAccess time.Time
	accesses   int64
}

// TieredStore decorates two inner Stores with transparent hot/cold tiering.
type TieredStore struct {
	hot  Store
	cold Store

	promoteOnRead bool
	demoteAfter   time.Duration
	hotMaxBytes   int64
	minAccesses   int64
	sweepInterval time.Duration
	logger        *slog.Logger
	clock         func() time.Time

	// mu guards the tracker map and the derived per-tier gauges.
	mu          sync.Mutex
	entries     map[string]*tierEntry
	hotObjects  int64
	coldObjects int64
	hotBytes    int64
	coldBytes   int64

	// keyLocks serialize mutating moves of the same key (striped by key hash).
	keyLocks [tierKeyStripes]sync.Mutex

	// leaderMu guards the leader gate predicate.
	leaderMu sync.Mutex
	leaderFn func() bool

	// lifecycle
	started sync.Once
	closed  sync.Once
	done    chan struct{}

	// Cumulative counters (atomic, lock-free).
	promotions      atomic.Int64
	demotions       atomic.Int64
	promoteFailures atomic.Int64
	demoteFailures  atomic.Int64
	hotHits         atomic.Int64
	coldHits        atomic.Int64
	sweeps          atomic.Int64
	lastSweepUnix   atomic.Int64
}

var _ Store = (*TieredStore)(nil)
var _ TieredStatSource = (*TieredStore)(nil)

// NewTieredStore composes hot and cold into a tiered Store. It rebuilds the
// in-memory tier index by listing both backends: entries found in the hot store
// are tracked hot, those found only in the cold store are tracked cold. An
// artifact found in both tiers (e.g. after a crash mid-move) is resolved to hot
// and its redundant cold copy is removed, so the one-tier-per-artifact invariant
// is restored at startup.
func NewTieredStore(opts TieredOptions) (*TieredStore, error) {
	if opts.Hot == nil {
		return nil, errors.New("cache: tiered storage requires a hot store")
	}
	if opts.Cold == nil {
		return nil, errors.New("cache: tiered storage requires a cold store")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	clock := opts.now
	if clock == nil {
		clock = time.Now
	}
	t := &TieredStore{
		hot:           opts.Hot,
		cold:          opts.Cold,
		promoteOnRead: opts.PromoteOnRead,
		demoteAfter:   opts.DemoteAfterIdle,
		hotMaxBytes:   opts.HotMaxBytes,
		minAccesses:   opts.MinAccessesToStayHot,
		sweepInterval: opts.SweepInterval,
		logger:        logger,
		clock:         clock,
		entries:       make(map[string]*tierEntry),
		done:          make(chan struct{}),
	}
	if err := t.rebuildIndex(context.Background()); err != nil {
		return nil, fmt.Errorf("cache: rebuilding tier index: %w", err)
	}
	return t, nil
}

// rebuildIndex reconstructs the tier tracker from the durable stores at startup.
func (t *TieredStore) rebuildIndex(ctx context.Context) error {
	hotRecs, err := t.hot.List(ctx)
	if err != nil {
		return fmt.Errorf("listing hot tier: %w", err)
	}
	coldRecs, err := t.cold.List(ctx)
	if err != nil {
		return fmt.Errorf("listing cold tier: %w", err)
	}
	now := t.clock()
	t.mu.Lock()
	for _, rec := range hotRecs {
		t.setLocked(rec.Key, tierHot, rec.Size, accessTime(rec, now), 0)
	}
	var redundant []string
	for _, rec := range coldRecs {
		if e := t.entries[rec.Key]; e != nil {
			// Present in both tiers: hot wins; the cold copy is redundant.
			redundant = append(redundant, rec.Key)
			continue
		}
		t.setLocked(rec.Key, tierCold, rec.Size, accessTime(rec, now), 0)
	}
	t.mu.Unlock()
	for _, key := range redundant {
		if err := t.cold.Delete(ctx, key); err != nil && !errors.Is(err, ErrNotFound) {
			t.logger.Warn("cache: tiering: removing redundant cold copy at startup failed", "key", key, "error", err)
		}
	}
	return nil
}

// accessTime picks the best available recency signal for a record.
func accessTime(rec Record, fallback time.Time) time.Time {
	switch {
	case !rec.AccessedAt.IsZero():
		return rec.AccessedAt
	case !rec.ModTime.IsZero():
		return rec.ModTime
	default:
		return fallback
	}
}

// --- Store implementation ---------------------------------------------------

// Put writes new content to the hot tier (a freshly written artifact is hot by
// definition) and supersedes any cold copy of the same key.
func (t *TieredStore) Put(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	if rec.Key == "" {
		return Record{}, errors.New("cache: Put requires a non-empty key")
	}
	unlock := t.lockKey(rec.Key)
	defer unlock()

	stored, err := t.hot.Put(ctx, rec, r)
	if err != nil {
		return Record{}, err
	}

	t.mu.Lock()
	prev := t.entries[rec.Key]
	supersededCold := prev != nil && prev.tier == tierCold
	t.setLocked(rec.Key, tierHot, stored.Size, t.clock(), 0)
	t.mu.Unlock()

	if supersededCold {
		if err := t.cold.Delete(ctx, rec.Key); err != nil && !errors.Is(err, ErrNotFound) {
			// The hot copy is authoritative and the tracker points at it; a stale
			// cold copy is harmless (it will be overwritten on the next demotion).
			t.logger.Warn("cache: tiering: removing superseded cold copy failed", "key", rec.Key, "error", err)
		}
	}
	return stored, nil
}

// Get serves an artifact from the tier that holds it, promoting a cold artifact
// to hot first when PromoteOnRead is enabled.
func (t *TieredStore) Get(ctx context.Context, key string) (io.ReadCloser, Record, error) {
	t.mu.Lock()
	e := t.entries[key]
	var loc tier
	if e != nil {
		loc = e.tier
	}
	t.mu.Unlock()

	if e == nil {
		return t.getUntracked(ctx, key)
	}
	if loc == tierHot {
		t.hotHits.Add(1)
		rc, rec, err := t.serve(ctx, key, tierHot)
		if err == nil {
			t.recordAccess(key)
		}
		return rc, rec, err
	}

	// Cold tier hit.
	t.coldHits.Add(1)
	if t.promoteOnRead {
		if err := t.promote(ctx, key); err != nil {
			t.promoteFailures.Add(1)
			t.logger.Warn("cache: tiering: promote-on-read failed", "key", key, "error", err)
		}
	}
	rc, rec, err := t.serve(ctx, key, t.currentTier(key))
	if err == nil {
		t.recordAccess(key)
	}
	return rc, rec, err
}

// getUntracked handles a key absent from the tracker: it probes hot then cold,
// healing the tracker on a hit. This keeps reads correct even if a prior process
// wrote directly to a backing store, or a tracker entry was lost.
func (t *TieredStore) getUntracked(ctx context.Context, key string) (io.ReadCloser, Record, error) {
	rc, rec, err := t.hot.Get(ctx, key)
	if err == nil {
		t.healEntry(key, tierHot, rec.Size)
		t.hotHits.Add(1)
		return rc, rec, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, Record{}, err
	}
	rc, rec, err = t.cold.Get(ctx, key)
	if err == nil {
		t.healEntry(key, tierCold, rec.Size)
		t.coldHits.Add(1)
		return rc, rec, nil
	}
	return nil, Record{}, err
}

// serve opens a read from the primary tier, falling back to the other tier on a
// not-found result. The fallback covers the brief window during a concurrent
// tier move where the tracker and a backing store momentarily disagree (the
// bytes always exist in exactly one of the two tiers throughout a move).
func (t *TieredStore) serve(ctx context.Context, key string, primary tier) (io.ReadCloser, Record, error) {
	first, second := t.hot, t.cold
	if primary == tierCold {
		first, second = t.cold, t.hot
	}
	rc, rec, err := first.Get(ctx, key)
	if err == nil {
		return rc, rec, nil
	}
	if errors.Is(err, ErrNotFound) {
		if rc2, rec2, err2 := second.Get(ctx, key); err2 == nil {
			return rc2, rec2, nil
		}
	}
	return nil, Record{}, err
}

// Stat returns the Record from the tier that holds the key. It does not promote
// or record an access (it is a metadata probe, not a content read).
func (t *TieredStore) Stat(ctx context.Context, key string) (Record, error) {
	loc, tracked := t.lookupTier(key)
	if !tracked {
		rec, err := t.hot.Stat(ctx, key)
		if err == nil {
			return rec, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return Record{}, err
		}
		return t.cold.Stat(ctx, key)
	}
	first, second := t.hot, t.cold
	if loc == tierCold {
		first, second = t.cold, t.hot
	}
	rec, err := first.Stat(ctx, key)
	if err == nil {
		return rec, nil
	}
	if errors.Is(err, ErrNotFound) {
		if rec2, err2 := second.Stat(ctx, key); err2 == nil {
			return rec2, nil
		}
	}
	return Record{}, err
}

// SetAccessed records recency against the tier that holds the key and refreshes
// the in-memory tracker so the demotion sweep sees the fresh access.
func (t *TieredStore) SetAccessed(ctx context.Context, key string, tm time.Time) error {
	t.mu.Lock()
	e := t.entries[key]
	var loc tier
	tracked := e != nil
	if tracked {
		loc = e.tier
		if tm.After(e.lastAccess) {
			e.lastAccess = tm
		}
	}
	t.mu.Unlock()

	if !tracked {
		if err := t.hot.SetAccessed(ctx, key, tm); err == nil || !errors.Is(err, ErrNotFound) {
			return err
		}
		return t.cold.SetAccessed(ctx, key, tm)
	}
	if loc == tierHot {
		return t.hot.SetAccessed(ctx, key, tm)
	}
	return t.cold.SetAccessed(ctx, key, tm)
}

// Delete removes the key from both tiers and the tracker.
func (t *TieredStore) Delete(ctx context.Context, key string) error {
	unlock := t.lockKey(key)
	defer unlock()

	t.mu.Lock()
	t.removeLocked(key)
	t.mu.Unlock()

	hotErr := t.hot.Delete(ctx, key)
	if hotErr != nil && !errors.Is(hotErr, ErrNotFound) {
		return hotErr
	}
	coldErr := t.cold.Delete(ctx, key)
	if coldErr != nil && !errors.Is(coldErr, ErrNotFound) {
		return coldErr
	}
	if errors.Is(hotErr, ErrNotFound) && errors.Is(coldErr, ErrNotFound) {
		return ErrNotFound
	}
	return nil
}

// List returns the union of both tiers, deduplicated by key (preferring the hot
// record if a key somehow appears in both).
func (t *TieredStore) List(ctx context.Context) ([]Record, error) {
	hotRecs, err := t.hot.List(ctx)
	if err != nil {
		return nil, err
	}
	coldRecs, err := t.cold.List(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(hotRecs))
	out := make([]Record, 0, len(hotRecs)+len(coldRecs))
	for _, rec := range hotRecs {
		seen[rec.Key] = struct{}{}
		out = append(out, rec)
	}
	for _, rec := range coldRecs {
		if _, dup := seen[rec.Key]; dup {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// Close stops the background sweep and closes both backing stores.
func (t *TieredStore) Close() error {
	t.closed.Do(func() { close(t.done) })
	hotErr := t.hot.Close()
	coldErr := t.cold.Close()
	if hotErr != nil {
		return hotErr
	}
	return coldErr
}

// --- tier moves -------------------------------------------------------------

// promote copies a cold artifact to the hot tier and removes the cold copy. It
// is idempotent and a no-op when the key is not (or no longer) cold.
func (t *TieredStore) promote(ctx context.Context, key string) error {
	unlock := t.lockKey(key)
	defer unlock()

	t.mu.Lock()
	e := t.entries[key]
	stillCold := e != nil && e.tier == tierCold
	t.mu.Unlock()
	if !stillCold {
		return nil
	}

	if err := t.copyEntry(ctx, t.cold, t.hot, key); err != nil {
		return err
	}

	t.mu.Lock()
	t.moveTierLocked(key, tierHot)
	t.mu.Unlock()

	if err := t.cold.Delete(ctx, key); err != nil && !errors.Is(err, ErrNotFound) {
		// The hot copy is authoritative and the tracker points at it; a stray cold
		// copy is harmless.
		t.logger.Warn("cache: tiering: removing promoted cold copy failed", "key", key, "error", err)
	}
	t.promotions.Add(1)
	return nil
}

// demote copies a hot artifact to the cold tier and removes the hot copy. The
// key lock excludes a concurrent Put/promote; the re-check under mu abandons the
// move if the artifact was accessed (recency advanced past the sweep snapshot),
// deleted, or already moved since the sweep selected it.
func (t *TieredStore) demote(ctx context.Context, key string, snapLast time.Time) error {
	unlock := t.lockKey(key)
	defer unlock()

	t.mu.Lock()
	e := t.entries[key]
	eligible := e != nil && e.tier == tierHot && !e.lastAccess.After(snapLast)
	t.mu.Unlock()
	if !eligible {
		return errDemoteAborted
	}

	if err := t.copyEntry(ctx, t.hot, t.cold, key); err != nil {
		return err
	}

	t.mu.Lock()
	cur := t.entries[key]
	if cur == nil || cur.tier != tierHot || cur.lastAccess.After(snapLast) {
		t.mu.Unlock()
		// The artifact changed under us after we copied it; drop the redundant cold
		// copy and leave the hot copy as the source of truth.
		if err := t.cold.Delete(ctx, key); err != nil && !errors.Is(err, ErrNotFound) {
			t.logger.Warn("cache: tiering: rolling back aborted demotion failed", "key", key, "error", err)
		}
		return errDemoteAborted
	}
	t.moveTierLocked(key, tierCold)
	t.mu.Unlock()

	if err := t.hot.Delete(ctx, key); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("cache: tiering: removing demoted hot copy of %q: %w", key, err)
	}
	t.demotions.Add(1)
	return nil
}

// copyEntry streams an artifact from src to dst, preserving every Record field
// (timestamps, origin, content-type, ETag, and the reserved encryption/
// compaction sidecars). The destination store recomputes Size and Digest over
// the identical bytes, so both tiers agree on the content digest.
func (t *TieredStore) copyEntry(ctx context.Context, src, dst Store, key string) error {
	rc, rec, err := src.Get(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	if _, err := dst.Put(ctx, rec, rc); err != nil {
		return err
	}
	return nil
}

// --- background sweep -------------------------------------------------------

// StartSweep launches the background demotion sweep. It is idempotent and a
// no-op when SweepInterval is zero (demotion then runs only via SweepTiers).
func (t *TieredStore) StartSweep(ctx context.Context) {
	if t == nil || t.sweepInterval <= 0 {
		return
	}
	t.started.Do(func() {
		go t.loop(ctx)
		t.logger.Info("cache tiering sweep started",
			"interval", t.sweepInterval, "demoteAfterIdle", t.demoteAfter, "hotMaxBytes", t.hotMaxBytes)
	})
}

func (t *TieredStore) loop(ctx context.Context) {
	ticker := time.NewTicker(t.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		case <-ticker.C:
			if !t.isLeader() {
				t.logger.Debug("cache tiering: skipping sweep; not coordination leader")
				continue
			}
			rep := t.sweepOnce(ctx)
			t.logger.Debug("cache tiering sweep complete",
				"candidates", rep.Candidates, "demoted", rep.Demoted, "skipped", rep.Skipped, "errors", rep.Errors)
		}
	}
}

// SweepTiers runs a demotion sweep inline and returns its report. It is the
// operator-triggered path (admin API / ptctl) and is not leader-gated: an
// operator asking for a sweep gets one.
func (t *TieredStore) SweepTiers(ctx context.Context) (TierSweepReport, error) {
	if t == nil {
		return TierSweepReport{}, ErrTieringDisabled
	}
	return t.sweepOnce(ctx), nil
}

// sweepOnce selects demotion victims from the hot tier and demotes them.
func (t *TieredStore) sweepOnce(ctx context.Context) TierSweepReport {
	start := t.clock()
	rep := TierSweepReport{StartedAt: start.UTC()}

	cands, hotBytes := t.snapshotHot()
	rep.HotObjectsBefore = len(cands)

	victims := t.selectVictims(cands, hotBytes, start)
	rep.Candidates = len(victims)

	for _, v := range victims {
		if ctx.Err() != nil {
			break
		}
		if err := t.demote(ctx, v.key, v.lastAccess); err != nil {
			if errors.Is(err, errDemoteAborted) {
				rep.Skipped++
				continue
			}
			rep.Errors++
			t.demoteFailures.Add(1)
			t.sampleErr(&rep, v.key, err)
			continue
		}
		rep.Demoted++
	}

	t.sweeps.Add(1)
	t.lastSweepUnix.Store(t.clock().Unix())
	rep.Duration = t.clock().Sub(start).String()
	return rep
}

// candidate is a sweep-time snapshot of a hot entry's demotion signals.
type candidate struct {
	key        string
	size       int64
	lastAccess time.Time
	accesses   int64
}

// snapshotHot copies the hot entries' demotion signals under the lock so victim
// selection and the (I/O-bearing) demotions run without holding it.
func (t *TieredStore) snapshotHot() ([]candidate, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cands := make([]candidate, 0, t.hotObjects)
	for k, e := range t.entries {
		if e.tier != tierHot {
			continue
		}
		cands = append(cands, candidate{key: k, size: e.size, lastAccess: e.lastAccess, accesses: e.accesses})
	}
	return cands, t.hotBytes
}

// selectVictims picks the hot artifacts to demote: every artifact idle past
// DemoteAfterIdle (unless protected by the frequency floor), plus — when the hot
// tier is over HotMaxBytes — the least-recently-used remaining artifacts until
// the tier is projected back under the cap.
func (t *TieredStore) selectVictims(cands []candidate, hotBytes int64, now time.Time) []candidate {
	var victims []candidate
	chosen := make(map[string]struct{})

	if t.demoteAfter > 0 {
		for _, c := range cands {
			if now.Sub(c.lastAccess) < t.demoteAfter {
				continue
			}
			if t.minAccesses > 0 && c.accesses >= t.minAccesses {
				continue
			}
			victims = append(victims, c)
			chosen[c.key] = struct{}{}
		}
	}

	if t.hotMaxBytes > 0 && hotBytes > t.hotMaxBytes {
		projected := hotBytes
		for _, c := range victims {
			projected -= c.size
		}
		if projected > t.hotMaxBytes {
			remaining := make([]candidate, 0, len(cands)-len(chosen))
			for _, c := range cands {
				if _, done := chosen[c.key]; done {
					continue
				}
				remaining = append(remaining, c)
			}
			// Least-recently-used first (tie-break on key for determinism).
			sort.Slice(remaining, func(i, j int) bool {
				if remaining[i].lastAccess.Equal(remaining[j].lastAccess) {
					return remaining[i].key < remaining[j].key
				}
				return remaining[i].lastAccess.Before(remaining[j].lastAccess)
			})
			for _, c := range remaining {
				if projected <= t.hotMaxBytes {
					break
				}
				victims = append(victims, c)
				projected -= c.size
			}
		}
	}
	return victims
}

func (t *TieredStore) sampleErr(rep *TierSweepReport, key string, err error) {
	const maxSamples = 16
	if len(rep.SampleErrors) >= maxSamples {
		return
	}
	rep.SampleErrors = append(rep.SampleErrors, fmt.Sprintf("%s: %s", key, err.Error()))
}

// --- leader gate ------------------------------------------------------------

// SetTierLeaderGate installs the predicate that gates the background sweep to
// the coordination leader in an HA deployment. A nil predicate (or gate) means
// "always leader" (single-node). It must be called before StartSweep.
func (t *TieredStore) SetTierLeaderGate(fn func() bool) {
	if t == nil {
		return
	}
	t.leaderMu.Lock()
	t.leaderFn = fn
	t.leaderMu.Unlock()
}

func (t *TieredStore) isLeader() bool {
	t.leaderMu.Lock()
	fn := t.leaderFn
	t.leaderMu.Unlock()
	return fn == nil || fn()
}

// --- stats ------------------------------------------------------------------

// TieredStats returns a snapshot of the tiering layer's configuration and
// cumulative counters.
func (t *TieredStore) TieredStats() TieredStats {
	st := TieredStats{
		Enabled:              true,
		PromoteOnRead:        t.promoteOnRead,
		HotMaxBytes:          t.hotMaxBytes,
		MinAccessesToStayHot: t.minAccesses,
		Promotions:           t.promotions.Load(),
		Demotions:            t.demotions.Load(),
		PromoteFailures:      t.promoteFailures.Load(),
		DemoteFailures:       t.demoteFailures.Load(),
		HotHits:              t.hotHits.Load(),
		ColdHits:             t.coldHits.Load(),
		Sweeps:               t.sweeps.Load(),
	}
	if t.demoteAfter > 0 {
		st.DemoteAfterIdle = t.demoteAfter.String()
	}
	if t.sweepInterval > 0 {
		st.SweepInterval = t.sweepInterval.String()
	}
	if total := st.HotHits + st.ColdHits; total > 0 {
		st.HotTierHitRatio = float64(st.HotHits) / float64(total)
	}
	if u := t.lastSweepUnix.Load(); u > 0 {
		st.LastSweep = time.Unix(u, 0).UTC()
	}
	t.mu.Lock()
	st.HotObjects = t.hotObjects
	st.ColdObjects = t.coldObjects
	st.HotBytes = t.hotBytes
	st.ColdBytes = t.coldBytes
	t.mu.Unlock()
	return st
}

// --- tracker helpers (callers hold t.mu) ------------------------------------

// setLocked inserts or replaces a tracker entry and keeps the per-tier gauges
// consistent (removing any prior entry's contribution first).
func (t *TieredStore) setLocked(key string, tr tier, size int64, lastAccess time.Time, accesses int64) {
	if old := t.entries[key]; old != nil {
		t.adjustLocked(old.tier, -1, -old.size)
	}
	t.entries[key] = &tierEntry{tier: tr, size: size, lastAccess: lastAccess, accesses: accesses}
	t.adjustLocked(tr, +1, +size)
}

func (t *TieredStore) removeLocked(key string) {
	if old := t.entries[key]; old != nil {
		t.adjustLocked(old.tier, -1, -old.size)
		delete(t.entries, key)
	}
}

func (t *TieredStore) moveTierLocked(key string, to tier) {
	e := t.entries[key]
	if e == nil || e.tier == to {
		return
	}
	t.adjustLocked(e.tier, -1, -e.size)
	e.tier = to
	t.adjustLocked(to, +1, +e.size)
}

func (t *TieredStore) adjustLocked(tr tier, dObjects, dBytes int64) {
	if tr == tierHot {
		t.hotObjects += dObjects
		t.hotBytes += dBytes
	} else {
		t.coldObjects += dObjects
		t.coldBytes += dBytes
	}
}

// --- tracker helpers (acquire t.mu) -----------------------------------------

func (t *TieredStore) lookupTier(key string) (tier, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.entries[key]; e != nil {
		return e.tier, true
	}
	return tierHot, false
}

func (t *TieredStore) currentTier(key string) tier {
	loc, _ := t.lookupTier(key)
	return loc
}

// recordAccess bumps the recency and frequency signals for a read hit.
func (t *TieredStore) recordAccess(key string) {
	now := t.clock()
	t.mu.Lock()
	if e := t.entries[key]; e != nil {
		if now.After(e.lastAccess) {
			e.lastAccess = now
		}
		e.accesses++
	}
	t.mu.Unlock()
}

// healEntry records a tracker entry discovered by an untracked read, without
// clobbering a concurrently-created entry.
func (t *TieredStore) healEntry(key string, tr tier, size int64) {
	now := t.clock()
	t.mu.Lock()
	if _, ok := t.entries[key]; !ok {
		t.setLocked(key, tr, size, now, 1)
	}
	t.mu.Unlock()
}

// lockKey acquires the striped mutex guarding mutating moves of key and returns
// its unlock function.
func (t *TieredStore) lockKey(key string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	mu := &t.keyLocks[h.Sum32()%tierKeyStripes]
	mu.Lock()
	return mu.Unlock
}

// --- decorator unwrap chain -------------------------------------------------
//
// The tiered store sits innermost in the Store stack (beneath encryption and
// compaction). The admin API, the Prometheus bridge, and the sweep wiring reach
// it through a small unwrap chain: each wrapping cache/decorator implements the
// unexported tierUnwrapper so the outermost cache can be unwrapped down to the
// tiered store (or report its absence) with a single call.

type tierUnwrapper interface {
	findTiered() (*TieredStore, bool)
}

func (t *TieredStore) findTiered() (*TieredStore, bool) { return t, true }

func unwrapTiered(inner any) (*TieredStore, bool) {
	if u, ok := inner.(tierUnwrapper); ok {
		return u.findTiered()
	}
	return nil, false
}

// TieredStoreOf returns the tiered store composed inside a cache chain, if any.
// It is the seam the admin API, Prometheus bridge, and sweep wiring use to find
// the layer regardless of how many decorators sit above it.
func TieredStoreOf(c Cache) (*TieredStore, bool) {
	return unwrapTiered(c)
}

// findTiered forwarders: each wrapping Store decorator and Cache wrapper passes
// the unwrap down to its inner component so TieredStoreOf can reach the tiered
// store through the full IntegrityCache -> (SealedCache ->) FilesystemCache ->
// compactStore -> encryptStore -> TieredStore chain. The base durable stores
// (FilesystemStore, S3Store) do not implement tierUnwrapper, so the unwrap stops
// (reporting absence) when no tiering layer is configured.

func (s *compactStore) findTiered() (*TieredStore, bool)    { return unwrapTiered(s.inner) }
func (s *encryptStore) findTiered() (*TieredStore, bool)    { return unwrapTiered(s.inner) }
func (c *FilesystemCache) findTiered() (*TieredStore, bool) { return unwrapTiered(c.store) }
func (c *IntegrityCache) findTiered() (*TieredStore, bool)  { return unwrapTiered(c.inner) }
func (s *SealedCache) findTiered() (*TieredStore, bool)     { return unwrapTiered(s.inner) }
