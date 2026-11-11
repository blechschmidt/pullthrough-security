package downloadlog

import (
	"log/slog"
	"sync"
	"time"
)

// Defaults applied when a Config field is left zero.
const (
	// DefaultMaxEntries is how many entries the log holds before it drops the
	// oldest. An entry typically costs under a kilobyte of memory, and never
	// more than a few: every field is length-bounded.
	DefaultMaxEntries = 50_000
	// MaxMaxEntries is the largest accepted capacity. The log is held in memory
	// and scanned per query; beyond this an external log pipeline (the audit
	// log's SIEM forwarding) is the right tool.
	MaxMaxEntries = 5_000_000
	// DefaultRetention is how long an entry is kept.
	DefaultRetention = 30 * 24 * time.Hour
	// DefaultFlushInterval is how often new entries are appended to the on-disk
	// log, and how often expired entries are dropped.
	DefaultFlushInterval = time.Second
)

// Config configures a Log.
type Config struct {
	// Enabled turns the log on. A disabled log records nothing and reports
	// itself as disabled.
	Enabled bool
	// MaxEntries is the capacity of the log. Zero means DefaultMaxEntries.
	MaxEntries int
	// Retention is how long an entry is kept. Zero means DefaultRetention; a
	// negative value disables time-based expiry (the capacity still applies).
	Retention time.Duration
	// Path is the JSON Lines file the log is persisted to. Empty keeps the log
	// in memory only: it is then lost on restart.
	Path string
	// IncludeMetadata also records requests for metadata documents (indexes,
	// version lists, checksums), not only for packages.
	IncludeMetadata bool
	// FlushInterval is the period of the background flush. Zero means
	// DefaultFlushInterval.
	FlushInterval time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logger receives persistence problems. Nil means slog.Default().
	Logger *slog.Logger
}

// chunkSize is how many entries one chunk of the log holds.
const chunkSize = 512

// chunk is a fixed block of entries. A slot is written once, under the log's
// lock, and never modified afterwards; that is what lets a query read the
// entries it was handed without holding the lock.
type chunk struct {
	entries [chunkSize]Entry
}

// view is an immutable snapshot of the log's contents: count entries in
// ascending ID order, the first one at offset start of the first chunk.
//
// A view stays valid — and unchanged — after the lock it was taken under is
// released. The log only ever writes slots past the end of every existing view,
// and replaces its chunk list instead of editing it, so a query can scan a view
// for as long as it likes while downloads keep being recorded.
type view struct {
	chunks []*chunk
	start  int
	count  int
}

// at returns the i-th entry of the view, oldest first.
func (v view) at(i int) *Entry {
	pos := v.start + i
	return &v.chunks[pos/chunkSize].entries[pos%chunkSize]
}

// Log is the download log. Create one with New; a nil *Log is a valid disabled
// log. It is safe for concurrent use.
type Log struct {
	enabled         bool
	capacity        int
	retention       time.Duration // <= 0: no time-based expiry
	includeMetadata bool
	now             func() time.Time
	logger          *slog.Logger

	mu sync.Mutex
	// cur is the log's contents. Guarded by mu; see view for what may be done
	// with a copy of it after mu is released.
	cur    view
	nextID uint64
	// Cumulative counters since process start.
	recorded  uint64
	byOutcome map[Outcome]uint64
	evicted   uint64
	expired   uint64

	store   *fileStore // nil when the log is not persistent
	flushMu sync.Mutex // serializes Flush

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New builds a Log. With a Path it loads the entries a previous run persisted
// and starts the background flush; call Close to stop it and write what is
// pending. A disabled Config yields a non-nil Log that records nothing.
func New(cfg Config) (*Log, error) {
	l := &Log{
		enabled:         cfg.Enabled,
		capacity:        cfg.MaxEntries,
		retention:       cfg.Retention,
		includeMetadata: cfg.IncludeMetadata,
		now:             cfg.Now,
		logger:          cfg.Logger,
		nextID:          1,
		byOutcome:       map[Outcome]uint64{},
	}
	if l.capacity <= 0 {
		l.capacity = DefaultMaxEntries
	}
	if l.capacity > MaxMaxEntries {
		l.capacity = MaxMaxEntries
	}
	if l.retention == 0 {
		l.retention = DefaultRetention
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.logger == nil {
		l.logger = slog.Default()
	}
	if !l.enabled || cfg.Path == "" {
		return l, nil
	}

	if err := l.open(cfg.Path); err != nil {
		return nil, err
	}

	interval := cfg.FlushInterval
	if interval <= 0 {
		interval = DefaultFlushInterval
	}
	l.stop = make(chan struct{})
	l.done = make(chan struct{})
	go l.run(interval)
	return l, nil
}

// open attaches the on-disk log at path and loads what a previous run left in
// it. It runs before the log is shared, so it touches the log's contents
// without the lock.
func (l *Log) open(path string) error {
	now := l.now()
	store, err := openFileStore(path, now, l.logger)
	if err != nil {
		return err
	}
	// Entries go straight into the log as they are read; when the file holds
	// more than the log does, the oldest fall out again as newer ones arrive.
	file, err := store.load(l.cutoff(), now, l.push)
	if err != nil {
		_ = store.close()
		return err
	}
	l.evicted = 0 // what did not fit was not evicted by this run's traffic

	maxID := file.maxID
	if file.outOfOrder {
		// A file whose IDs do not increase was not written by one process in
		// sequence. IDs order the log and drive the "what is new" bookkeeping, so
		// renumber what was kept rather than build on a broken sequence.
		for i := 0; i < l.cur.count; i++ {
			l.cur.at(i).ID = uint64(i + 1)
		}
		maxID = uint64(l.cur.count)
	}
	// Continue the ID sequence where the previous run stopped.
	l.nextID = maxID + 1
	if err := store.start(l.cur, file, maxID); err != nil {
		_ = store.close()
		return err
	}
	l.store = store
	return nil
}

// Enabled reports whether the log records anything.
func (l *Log) Enabled() bool { return l != nil && l.enabled }

// Wants reports whether an entry of the given kind and outcome would be kept,
// so a caller can skip assembling one that would be dropped.
//
// Requests for metadata are left out unless Config.IncludeMetadata asks for
// them — with one exception: a refused request is always kept. A gate that
// judges a package by its coordinate refuses the first request that names it,
// and for several package managers that is a metadata request (the go command
// asks for a version's .info before its .zip). The client stops there, so the
// refused metadata request is the only trace of the attempt.
func (l *Log) Wants(kind Kind, outcome Outcome) bool {
	if !l.Enabled() {
		return false
	}
	return kind != KindMetadata || l.includeMetadata || outcome == OutcomeBlocked
}

// Record adds an entry to the log. The entry's ID is assigned here, and so is
// its Time when unset — under the log's lock, so that entries are in time order
// and the expired ones are always a prefix. Record only touches memory and
// never blocks on I/O.
func (l *Log) Record(e Entry) {
	if !l.Enabled() {
		return
	}
	e.sanitize()
	if !l.Wants(e.Kind, e.Outcome) {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	e.ID = l.nextID
	l.nextID++
	l.recorded++
	l.byOutcome[e.Outcome]++
	l.expireLocked()
	l.push(e)
}

// push appends e, evicting the oldest entry when the log is full. The caller
// holds l.mu (or is New, before the log is shared).
func (l *Log) push(e Entry) {
	if l.cur.count >= l.capacity {
		l.dropOldest(1)
		l.evicted++
	}
	pos := l.cur.start + l.cur.count
	if pos/chunkSize == len(l.cur.chunks) {
		// append may write the new pointer into spare room of the array an older
		// view shares, but only past that view's length — where it never looks.
		l.cur.chunks = append(l.cur.chunks, &chunk{})
	}
	l.cur.chunks[pos/chunkSize].entries[pos%chunkSize] = e
	l.cur.count++
}

// dropOldest removes the n oldest entries. Entries are not cleared — an older
// view may still be reading them — they are released when the chunk they live
// in has no live entry left and is dropped from the list. The list itself is
// replaced, never edited in place, for the same reason.
func (l *Log) dropOldest(n int) {
	if n >= l.cur.count {
		l.cur = view{}
		return
	}
	l.cur.start += n
	l.cur.count -= n
	if dead := l.cur.start / chunkSize; dead > 0 {
		l.cur.chunks = append([]*chunk(nil), l.cur.chunks[dead:]...)
		l.cur.start -= dead * chunkSize
	}
}

// cutoff is the time before which entries have expired, or the zero time when
// time-based expiry is off.
func (l *Log) cutoff() time.Time {
	if l.retention <= 0 {
		return time.Time{}
	}
	return l.now().Add(-l.retention)
}

// expireLocked drops entries older than the retention. Entries are in time
// order, so the expired ones form a prefix. The caller holds l.mu.
func (l *Log) expireLocked() {
	cutoff := l.cutoff()
	if cutoff.IsZero() || l.cur.count == 0 || !l.cur.at(0).Time.Before(cutoff) {
		return
	}
	// Binary search for the first entry that is still within the retention.
	lo, hi := 1, l.cur.count
	for lo < hi {
		mid := (lo + hi) / 2
		if l.cur.at(mid).Time.Before(cutoff) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	l.expired += uint64(lo)
	l.dropOldest(lo)
}

// snapshotView drops expired entries and returns the log's current contents as
// a view that can be read without holding the lock.
func (l *Log) snapshotView() view {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	return l.cur
}

// Stats is a snapshot of the log's state and cumulative counters.
type Stats struct {
	Enabled bool `json:"enabled"`
	// Capacity is the maximum number of entries; Retained how many are held now.
	Capacity int `json:"capacity"`
	Retained int `json:"retained"`
	// RetentionSeconds is how long an entry is kept; 0 means no time limit.
	RetentionSeconds int64 `json:"retentionSeconds"`
	// Persistent reports whether the log is written to disk.
	Persistent bool `json:"persistent"`
	// IncludeMetadata reports whether metadata requests are recorded too.
	IncludeMetadata bool `json:"includeMetadata"`
	// Oldest and Newest are the times of the first and last retained entry.
	Oldest *time.Time `json:"oldest,omitempty"`
	Newest *time.Time `json:"newest,omitempty"`

	// Recorded counts entries recorded since the process started, by outcome.
	Recorded  uint64             `json:"recorded"`
	ByOutcome map[Outcome]uint64 `json:"byOutcome"`
	// Evicted counts entries dropped because the log was full; Expired those
	// dropped because they outlived the retention.
	Evicted uint64 `json:"evicted"`
	Expired uint64 `json:"expired"`
	// Persisted counts entries written to disk; PersistErrors failed writes;
	// PersistLost entries that left the log before they could be written.
	Persisted     uint64 `json:"persisted"`
	PersistErrors uint64 `json:"persistErrors"`
	PersistLost   uint64 `json:"persistLost"`
}

// Stats returns a snapshot of the log's state.
func (l *Log) Stats() Stats {
	if l == nil {
		return Stats{ByOutcome: map[Outcome]uint64{}}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.enabled {
		l.expireLocked()
	}
	st := Stats{
		Enabled:         l.enabled,
		Capacity:        l.capacity,
		Retained:        l.cur.count,
		Persistent:      l.store != nil,
		IncludeMetadata: l.includeMetadata,
		Recorded:        l.recorded,
		ByOutcome:       make(map[Outcome]uint64, len(l.byOutcome)),
		Evicted:         l.evicted,
		Expired:         l.expired,
	}
	if l.retention > 0 {
		st.RetentionSeconds = int64(l.retention / time.Second)
	}
	for k, v := range l.byOutcome {
		st.ByOutcome[k] = v
	}
	if l.cur.count > 0 {
		oldest, newest := l.cur.at(0).Time, l.cur.at(l.cur.count-1).Time
		st.Oldest, st.Newest = &oldest, &newest
	}
	if l.store != nil {
		st.Persisted, st.PersistErrors, st.PersistLost = l.store.counters()
	}
	return st
}

// run is the background loop of a persistent log: it periodically drops expired
// entries and appends new ones to the file.
func (l *Log) run(interval time.Duration) {
	defer close(l.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			_ = l.Flush()
		}
	}
}

// Flush writes every entry not yet persisted to the on-disk log. It is called
// periodically in the background and by Close; tests call it to make the file
// current. It is a no-op for a log without a Path.
//
// After a failed write Flush pauses before it tries again — a second, then
// two, up to a minute — and returns the standing failure meanwhile.
func (l *Log) Flush() error {
	return l.flush(false)
}

// flush writes what is pending. force attempts the write even during the pause
// that follows a failure.
func (l *Log) flush(force bool) error {
	if l == nil || l.store == nil {
		return nil
	}
	// One flush at a time: two flushes working from the same "last persisted"
	// mark would write the same entries twice.
	l.flushMu.Lock()
	defer l.flushMu.Unlock()

	// The log's lock is held only to take the snapshot. The file is written
	// from that snapshot with the lock released — recording never waits for the
	// disk — and the store is handed everything it needs, so it never has to
	// come back to the log for more (see fileStore).
	l.mu.Lock()
	l.expireLocked()
	v := l.cur
	upTo := l.nextID - 1
	cutoff := l.cutoff()
	l.mu.Unlock()

	return l.store.sync(v, upTo, cutoff, l.now(), force)
}

// Close stops the background flush, writes what is pending and closes the
// on-disk log. The log must not be used for recording afterwards.
func (l *Log) Close() error {
	if l == nil || l.store == nil {
		return nil
	}
	var err error
	l.stopOnce.Do(func() {
		close(l.stop)
		<-l.done
		// The last chance to write: do not sit out a pause.
		err = l.flush(true)
		if cerr := l.store.close(); err == nil {
			err = cerr
		}
	})
	return err
}
