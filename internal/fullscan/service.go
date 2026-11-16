package fullscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults.
const (
	// DefaultConcurrency is how many of the full scan's scans run at a time.
	DefaultConcurrency = 2
	// MaxConcurrency bounds it.
	MaxConcurrency = 32
	// DefaultSweepInterval is the time between two backfill sweeps;
	// MinSweepInterval the shortest accepted.
	DefaultSweepInterval = 6 * time.Hour
	MinSweepInterval     = time.Minute
	// DefaultMaxItems bounds the inventory.
	DefaultMaxItems = 1_000_000
)

// States the full scan reports (Status.State).
const (
	StateStarting        = "starting"
	StateStandby         = "standby"
	StateLockdown        = "lockdown"
	StatePaused          = "paused"
	StateBudgetExhausted = "budget-exhausted"
	StateWaiting         = "waiting"
	StateScanning        = "scanning"
	StateIdle            = "idle"
	StateFailed          = "error"
	StateStopped         = "stopped"
)

// Options configure the full scan.
type Options struct {
	// Dir is the state directory.
	Dir string
	// Upstreams are the upstreams in scope: those whose fullMirror block
	// sets fullScan, and — with All — every upstream the gate scans.
	Upstreams []string
	// All reports that the global fullScan.enabled set the scope.
	All bool
	// Tenant is the full mirror's tenant (for the status: an artifact is
	// scanned as the tenant whose request filled its cache entry).
	Tenant string
	// Concurrency is how many of the full scan's scans run at a time.
	Concurrency int
	// DailyUSD and MonthlyUSD are the cost ceilings per UTC day and month (0:
	// none).
	DailyUSD   float64
	MonthlyUSD float64
	// SweepInterval is the time between two backfill sweeps.
	SweepInterval time.Duration
	// MaxItems bounds the inventory.
	MaxItems int
	Logger   *slog.Logger
	Audit    AuditLogger
	// OnBudgetExhausted, when set, is called once per window when a ceiling
	// is reached. It must not block.
	OnBudgetExhausted func(window string, spentUSD, ceilingUSD float64)
	// Now is the clock (tests).
	Now func() time.Time

	// Tuning; zero values take the defaults.
	// MaxAttempts is how often an artifact is tried before it is given up on
	// until the next sweep (5); RetryBase the first wait after a failed
	// attempt (30s, doubling, at most an hour).
	MaxAttempts int
	RetryBase   time.Duration
	// BusyWait is the wait while a client's scan waits for one of the gate's
	// slots (2s); GateBudgetWait the wait after the gate's own budget refused
	// a scan (15m).
	BusyWait       time.Duration
	GateBudgetWait time.Duration
	// ControlRefresh is how often control.json is re-read (5s);
	// PersistInterval how often the journal is synced and the state written
	// when they changed (1s); StandbyInterval how often a replica that does
	// not lead checks again (15s); InboxInterval how often the leader reads
	// the inbox (2s).
	ControlRefresh  time.Duration
	PersistInterval time.Duration
	StandbyInterval time.Duration
	InboxInterval   time.Duration
	// EvictedRetention is how long the record of an artifact the ladder
	// evicted is kept (30 days).
	EvictedRetention time.Duration
	// PublishInterval is how often the leader refreshes the figures it
	// publishes for the replicas that do not lead (10s): counting them walks
	// the inventory.
	PublishInterval time.Duration
	// TenantInterval is how often the leader recounts the figures per tenant
	// (15s): counting them walks the inventory once per tenant that pulled
	// each artifact, so a status read between two counts reuses the last.
	TenantInterval time.Duration
}

func (o Options) withDefaults() Options {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.Concurrency > MaxConcurrency {
		o.Concurrency = MaxConcurrency
	}
	if o.MaxItems <= 0 {
		o.MaxItems = DefaultMaxItems
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 5
	}
	def(&o.SweepInterval, DefaultSweepInterval)
	def(&o.RetryBase, 30*time.Second)
	def(&o.BusyWait, 2*time.Second)
	def(&o.GateBudgetWait, 15*time.Minute)
	def(&o.ControlRefresh, 5*time.Second)
	def(&o.PersistInterval, time.Second)
	def(&o.StandbyInterval, 15*time.Second)
	def(&o.InboxInterval, 2*time.Second)
	def(&o.EvictedRetention, 30*24*time.Hour)
	def(&o.PublishInterval, 10*time.Second)
	def(&o.TenantInterval, 15*time.Second)
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Note is something the server learned about a cached artifact in scope.
type Note struct {
	Source   Source
	Artifact Artifact
	// Reading is the gate's reading (nil for SourceSeen: only that the file
	// is cached).
	Reading *Reading
	// Attribution marks a note that says only who pulled the artifact: a
	// replica that does not lead forwards one per artifact and tenant, for
	// the per-tenant figures, when the pull needs nothing else of the leader.
	Attribution bool
}

// maxNotes bounds the notes waiting to be applied; one beyond it is dropped
// (the sweep finds its artifact later).
const maxNotes = 4096

// maxNotesPerStep bounds the notes one step applies.
const maxNotesPerStep = 4096

// maxJournalRecords is the journal length past which the inventory is
// compacted into a new snapshot (when the journal is also more than twice the
// inventory).
const maxJournalRecords = 200_000

// Service is the full scan.
type Service struct {
	opts  Options
	log   *slog.Logger
	now   func() time.Time
	store store
	scope map[string]bool
	names []string

	wake    chan struct{}
	notes   chan Note
	dropped atomic.Uint64

	persistMu sync.Mutex

	mu        sync.Mutex
	scanner   Scanner
	inventory Inventory
	leader    func() bool
	kill      func() (bool, string)
	started   bool
	stopped   bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	control   controlFile
	controlAt time.Time
	controlOK bool

	// The leader's state: valid while loaded.
	loaded          bool
	loadErr         string
	st              stateFile
	gen             uint64
	items           map[string]*Item
	q               *queue
	jr              *journal
	dirty           bool
	lastSave        time.Time
	running         int
	sweeping        bool
	nextSweep       time.Time
	gateBudgetUntil time.Time
	lastInbox       time.Time
	overflow        uint64
	activity        string
	detail          string

	// statusCache is the leader's last status; peeked the state a replica
	// that does not lead read from disk.
	statusCache *Status
	statusAt    time.Time
	peeked      *stateFile
	peekedAt    time.Time
	// published is the status last written for the other replicas.
	published   *Status
	publishedAt time.Time
	// tenantFigures are the figures per tenant as last counted.
	tenantFigures   map[string]Figures
	tenantFiguresAt time.Time
	// attributed are the artifacts and tenants a replica that does not lead
	// has forwarded attribution notes for (bounded; cleared when full).
	attributed map[string]struct{}

	// term numbers the leaderships of this replica; termCtx ends with one
	// (standby cancels it), and the scans started under it.
	term       uint64
	termCtx    context.Context
	termCancel context.CancelFunc
	// A compaction under way: the snapshot and journal it will name, the
	// journal state.json still names (oldJr), and whether the live journal
	// failed (jrFailed: the next write starts a new one).
	pendingSnap string
	pendingLog  string
	oldJr       *journal
	jrFailed    bool
	// fencedUntil holds this replica in standby after another one took over
	// the state, so two replicas that both think they lead do not take it
	// from each other in turn.
	fencedUntil time.Time
	fencedSeen  bool
}

// New builds the full scan. Nothing runs before Start; no state is read
// before the replica first leads.
func New(opts Options) (*Service, error) {
	opts = opts.withDefaults()
	if len(opts.Upstreams) == 0 {
		return nil, errors.New("fullscan: no upstream is in scope")
	}
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, errors.New("fullscan: a state directory is required")
	}
	if opts.DailyUSD < 0 || opts.MonthlyUSD < 0 {
		return nil, errors.New("fullscan: budget ceilings must not be negative")
	}
	if opts.DailyUSD == 0 && opts.MonthlyUSD == 0 {
		return nil, errors.New("fullscan: a cost budget is required (a daily or a monthly ceiling)")
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("fullscan: creating the state directory: %w", err)
	}
	s := &Service{
		opts:  opts,
		log:   opts.Logger,
		now:   opts.Now,
		store: store{dir: opts.Dir},
		scope: map[string]bool{},
		wake:  make(chan struct{}, 1),
		notes: make(chan Note, maxNotes),
	}
	for _, u := range opts.Upstreams {
		if u = strings.TrimSpace(u); u != "" && !s.scope[u] {
			s.scope[u] = true
			s.names = append(s.names, u)
		}
	}
	sort.Strings(s.names)
	return s, nil
}

// Enabled reports whether a full scan is configured. Safe on nil.
func (s *Service) Enabled() bool { return s != nil && len(s.scope) > 0 }

// InScope reports whether an upstream's cached artifacts are fully scanned.
// Safe on nil.
func (s *Service) InScope(upstream string) bool { return s.Enabled() && s.scope[upstream] }

func (s *Service) inScope(upstream string) bool { return s.scope[upstream] }

// Attach hands the full scan the gate (through the gateway) and the cache
// listing. Call it once the gateway exists, before Start. A nil inventory
// leaves the backfill to the full mirror and the clients' pulls.
func (s *Service) Attach(sc Scanner, inv Inventory) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.scanner, s.inventory = sc, inv
	s.mu.Unlock()
	s.kick()
}

// SetLeaderGate installs the HA leadership predicate (coord.Guard.IsLeader of
// the full-mirror lease). Nil leaves the full scan always leading.
func (s *Service) SetLeaderGate(isLeader func() bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.leader = isLeader
	s.mu.Unlock()
}

// SetKillSwitch installs the emergency lockdown predicate: while it reports an
// active lockdown the full scan starts no scan.
func (s *Service) SetKillSwitch(fn func() (bool, string)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.kill = fn
	s.mu.Unlock()
}

func (s *Service) isLeader() bool {
	s.mu.Lock()
	fn := s.leader
	s.mu.Unlock()
	return fn == nil || fn()
}

func (s *Service) killSwitch() (bool, string) {
	s.mu.Lock()
	fn := s.kill
	s.mu.Unlock()
	if fn == nil {
		return false, ""
	}
	return fn()
}

func (s *Service) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Start launches the full scan's loop.
func (s *Service) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	s.started, s.cancel = true, cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go s.run(ctx)
	s.log.Info("full scan started", "upstreams", strings.Join(s.names, ","), "stateDir", s.opts.Dir,
		"concurrency", s.opts.Concurrency, "dailyUSD", s.opts.DailyUSD, "monthlyUSD", s.opts.MonthlyUSD)
}

// Close stops the loop, waits for the scans in flight and the sweep, and
// writes the state. Safe on nil and more than once.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
	var err error
	if s.isLeader() {
		if perr := s.persist(true); perr != nil && !errors.Is(perr, errFenced) {
			err = perr
		}
	}
	s.mu.Lock()
	if s.termCancel != nil {
		s.termCancel()
	}
	if s.jr != nil {
		if cerr := s.jr.close(); cerr != nil && err == nil {
			err = cerr
		}
		s.jr = nil
	}
	if s.oldJr != nil {
		_ = s.oldJr.close()
		s.oldJr = nil
	}
	s.activity = StateStopped
	s.mu.Unlock()
	return err
}

// run is the loop.
func (s *Service) run(ctx context.Context) {
	defer s.wg.Done()
	for {
		wait := s.safeStep(ctx)
		if ctx.Err() != nil {
			return
		}
		if wait < 10*time.Millisecond {
			wait = 10 * time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// panicWait is the wait after the loop recovered from a panic.
const panicWait = time.Minute

func (s *Service) safeStep(ctx context.Context) (wait time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("full scan: the loop recovered from a panic", "panic", r, "stack", string(debug.Stack()))
			s.setActivity(StateFailed, fmt.Sprintf("internal error: %v", r))
			wait = panicWait
		}
	}()
	return s.step(ctx)
}

func (s *Service) setActivity(state, detail string) {
	s.mu.Lock()
	s.activity, s.detail = state, detail
	s.mu.Unlock()
}

// step does one round of work and returns how long to wait before the next.
func (s *Service) step(ctx context.Context) time.Duration {
	ctl := s.refreshControl(false)
	leader := s.isLeader()
	s.mu.Lock()
	fenced := s.now().Before(s.fencedUntil)
	if fenced && !leader {
		// The lease has moved on: the replica may lead again when it comes
		// back.
		s.fencedUntil, fenced = time.Time{}, false
	}
	s.mu.Unlock()
	if !leader || fenced {
		s.standby()
		s.forwardNotes()
		return s.opts.StandbyInterval
	}
	s.mu.Lock()
	attached := s.scanner != nil
	s.mu.Unlock()
	if !attached {
		// The scan signature comes from the gate: nothing is loaded before.
		s.setActivity(StateStarting, "waiting for the gateway")
		return 5 * time.Second
	}
	if err := s.ensureLoaded(ctx); err != nil {
		if errors.Is(err, errFenced) {
			s.fence()
			s.setActivity(StateStandby, "another replica took over the full scan")
			return s.opts.StandbyInterval
		}
		s.setActivity(StateFailed, "the state cannot be read: "+cleanMessage(err.Error()))
		return time.Minute
	}
	s.applyNotes()
	s.ingestInbox()
	s.applyRescans(ctx, ctl)
	s.maybeSweep(ctx)
	wait := s.work(ctx, ctl)
	// What this step changed is written before a wait longer than the
	// persist interval, rather than at the step after it: the state file
	// carries the figures the replicas that do not lead show
	// (Status.Published), and a paused or blocked loop sleeps half a minute.
	// (A paused leader that took in a follower's note within the persist
	// interval of its last write left it unpublished that long; Task 194.)
	s.mu.Lock()
	force := s.dirty && wait > s.opts.PersistInterval
	s.mu.Unlock()
	if err := s.persist(force); errors.Is(err, errFenced) {
		s.fence()
		s.standby()
		return s.opts.StandbyInterval
	}
	return wait
}

// fenceHold is how long a replica that found the state taken over stays in
// standby while its lease still says it leads.
const fenceHold = 5 * time.Minute

// fence holds the replica in standby: another one wrote the state since it
// last did. It leads again once its lease has said otherwise, or after
// fenceHold (a lease service that is off, a state restored under it).
func (s *Service) fence() {
	s.mu.Lock()
	s.fencedUntil = s.now().Add(fenceHold)
	s.mu.Unlock()
}

// work starts scans while nothing holds the queue, and returns the wait.
func (s *Service) work(ctx context.Context, ctl controlFile) time.Duration {
	now := s.now()
	if active, mode := s.killSwitch(); active {
		s.setActivity(StateLockdown, "emergency lockdown ("+firstNonEmpty(mode, "active")+"): no scan starts")
		return 30 * time.Second
	}
	if paused, detail := ctl.pausedDetail(); paused {
		s.setActivity(StatePaused, detail)
		return 30 * time.Second
	}
	s.mu.Lock()
	sc := s.scanner
	s.mu.Unlock()
	if wait, blocked := s.budgetBlocked(ctx, now); blocked {
		return wait
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gateBudgetUntil.After(now) {
		s.activity, s.detail = StateWaiting, "the gate's own cost budget (llmPackageScan.budget) is spent; trying again at "+s.gateBudgetUntil.UTC().Format(time.RFC3339)
		return s.gateBudgetUntil.Sub(now)
	}
	paused := func(upstream string) bool { return ctl.Upstreams[upstream].Paused }
	// A pause lifted elsewhere (another replica, a race with this step) puts
	// the upstream's parked items back.
	s.q.unparkUnless(paused, now)
	for s.running < s.opts.Concurrency {
		if running, waiting, slots := sc.Load(); waiting > 0 || (slots > 0 && running >= int64(slots)) {
			// A client's scan waits for a slot, or every slot is taken: the
			// scans clients start come first.
			s.activity, s.detail = StateWaiting, fmt.Sprintf("yielding to client scans (%d running, %d waiting, %d slots)", running, waiting, slots)
			return s.opts.BusyWait
		}
		it := s.q.pop(now, paused)
		if it == nil {
			break
		}
		it.busy = true
		s.running++
		s.wg.Add(1)
		go s.scanItem(s.termCtx, s.term, sc, it, it.artifact(), ScanOptions{Refresh: it.Refresh, Gates: it.Gates != GatesPassed})
	}
	ready, delayed, parked := s.q.sizes()
	queued := delayed
	for _, n := range ready {
		queued += n
	}
	switch {
	case s.running > 0:
		s.activity, s.detail = StateScanning, fmt.Sprintf("%d scan(s) running, %d queued", s.running, queued)
	case queued > 0 || parked > 0:
		s.activity, s.detail = StateIdle, fmt.Sprintf("%d queued (%d waiting out a retry), %d of paused upstreams", queued, delayed, parked)
	default:
		s.activity, s.detail = StateIdle, "every artifact in scope has a current reading"
	}
	if s.running >= s.opts.Concurrency {
		return time.Minute // a finishing scan wakes the loop
	}
	if due := s.q.nextDue(); !due.IsZero() {
		if d := due.Sub(now); d < 30*time.Second {
			return d
		}
	}
	return 30 * time.Second
}

// budgetBlocked reports a spent cost ceiling, announcing it once per window.
func (s *Service) budgetBlocked(ctx context.Context, now time.Time) (time.Duration, bool) {
	s.mu.Lock()
	exhausted, window := s.st.Ledger.exhausted(now, s.opts.DailyUSD, s.opts.MonthlyUSD)
	if !exhausted {
		s.mu.Unlock()
		return 0, false
	}
	spent, ceiling, key := s.st.Ledger.DaySpentUSD, s.opts.DailyUSD, s.st.Ledger.Day
	announced := &s.st.Ledger.AnnouncedDay
	if window == WindowMonth {
		spent, ceiling, key = s.st.Ledger.MonthSpentUSD, s.opts.MonthlyUSD, s.st.Ledger.Month
		announced = &s.st.Ledger.AnnouncedMonth
	}
	first := *announced != key
	if first {
		*announced = key
		s.dirty = true
	}
	reset := resetsAt(now, window)
	s.activity = StateBudgetExhausted
	s.detail = fmt.Sprintf("the %s cost ceiling is spent ($%.2f of $%.2f); the queue resumes at %s or once fullScan.budget is raised",
		map[string]string{WindowDay: "daily", WindowMonth: "monthly"}[window], spent, ceiling, reset.Format(time.RFC3339))
	s.mu.Unlock()
	if first {
		s.audit(ctx, "budget-exhausted", "", "", map[string]any{"window": window, "spentUsd": spent, "ceilingUsd": ceiling})
		s.log.Warn("full scan: the cost budget is spent; pausing the queue", "window", window, "spentUSD", spent, "ceilingUSD", ceiling, "resets", reset)
		if s.opts.OnBudgetExhausted != nil {
			s.opts.OnBudgetExhausted(window, spent, ceiling)
		}
	}
	wait := reset.Sub(now)
	if wait > 5*time.Minute {
		wait = 5 * time.Minute
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait, true
}

// scanItem runs one scan in a worker, under the leadership term it started
// in.
func (s *Service) scanItem(ctx context.Context, term uint64, sc Scanner, it *Item, art Artifact, opts ScanOptions) {
	defer s.wg.Done()
	defer s.kick()
	r, err := safeScan(ctx, sc, art, opts)
	s.complete(ctx, term, it, r, err)
}

func safeScan(ctx context.Context, sc Scanner, art Artifact, opts ScanOptions) (r Reading, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error: %v", p)
		}
	}()
	return sc.Scan(ctx, art, opts)
}

// complete applies a scan's outcome to its item.
func (s *Service) complete(ctx context.Context, term uint64, it *Item, r Reading, err error) {
	var changed *verdictChange
	defer func() {
		if changed != nil {
			s.audit(context.Background(), "verdict-changed", "", changed.upstream, map[string]any{
				"path": changed.path, "digest": changed.digest, "from": changed.from, "to": changed.to,
			})
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if term != s.term || !s.loaded {
		// A scan of an earlier leadership: its item and its slot belong to
		// that leadership, gone since. What it cost was spent all the same,
		// and the ledger is this replica's again if it leads.
		if s.loaded && r.Cost > 0 {
			s.st.Ledger.add(now, r.Cost)
			s.countersLocked(it.Upstream).SpentUSD += r.Cost
			s.dirty = true
		}
		return
	}
	s.running--
	it.busy = false
	again := it.again
	it.again = false
	c := s.countersLocked(it.Upstream)
	if r.Cost > 0 {
		s.st.Ledger.add(now, r.Cost)
		c.SpentUSD += r.Cost
		s.dirty = true
	}
	if s.items[it.Key] != it {
		return // the item was replaced
	}
	if again {
		// An operator asked for a re-scan while this scan ran: once it is
		// recorded, the item goes back for a fresh model call.
		defer func() {
			if s.items[it.Key] == it && !it.Evicted {
				it.Refresh = true
				s.enqueueLocked(it, it.Priority, s.now(), time.Time{})
				s.putLocked(it)
			}
		}()
	}
	if err != nil && ctx.Err() != nil {
		// The leadership ends, or the full scan stops: the item is still to
		// do.
		s.q.push(it, now)
		return
	}
	if it.Refresh && r.Kind == ReadingVerdict && it.Verdict != "" && it.Verdict != r.Disposition && it.State == StatePending {
		// An operator's re-scan changed the reading: say so, from what to what.
		changed = &verdictChange{upstream: it.Upstream, path: it.Path, digest: firstNonEmpty(r.Digest, it.Digest), from: it.Verdict, to: r.Disposition}
	}
	switch {
	case errors.Is(err, ErrGone):
		c.Gone++
		s.removeLocked(it)
	case errors.Is(err, ErrChanged):
		// The cache holds other bytes under the key now: judge those.
		it.Digest = ""
		s.retryLocked(it, now, it.Priority, false, "")
	case err != nil:
		c.Errors++
		s.retryLocked(it, now, it.Priority, true, cleanMessage(err.Error()))
	default:
		s.applyReadingLocked(it, r, now, -1)
	}
	s.dirty = true
}

// verdictChange is a re-scan that changed an artifact's reading.
type verdictChange struct {
	upstream, path, digest, from, to string
}

// applyReadingLocked records a reading on an item. src is the note's source,
// or -1 for the full scan's own scan.
func (s *Service) applyReadingLocked(it *Item, r Reading, now time.Time, src Source) {
	c := s.countersLocked(it.Upstream)
	own := src < 0
	it.learnCoordinate(r)
	if r.Digest != "" {
		it.Digest = r.Digest
	}
	if r.Size > 0 {
		it.Size = r.Size
	}
	if r.Gates != "" {
		if r.Gates == GatesRefused && it.Gates != GatesRefused {
			bump(&c.GateRefusals, firstNonEmpty(r.Gate, "unknown"), 1)
		}
		it.Gates, it.Gate = r.Gates, ""
		if r.Gates == GatesRefused {
			it.Gate = r.Gate
		}
	}
	settle := func(state string) {
		s.q.remove(it)
		it.State = state
		it.Attempts, it.LastError, it.Refresh, it.NotBefore = 0, "", false, time.Time{}
		it.Scanned = now.UTC()
	}
	switch r.Kind {
	case ReadingVerdict:
		settle(StateScanned)
		it.Verdict, it.Code, it.Signature = r.Disposition, "", r.Signature
		it.Action = ""
		if r.Refused {
			it.Action = r.Action
		}
		if own {
			if r.Fresh {
				c.Scans++
			} else {
				c.CachedVerdicts++
			}
			bump(&c.Verdicts, r.Disposition, 1)
		}
		if r.Refused {
			c.Refused++
		}
	case ReadingNotApplicable:
		settle(StateNotApplicable)
		it.Verdict, it.Code, it.Action, it.Signature = "", r.Code, "", s.signatureLocked()
	case ReadingUnscanned:
		if own {
			bump(&c.Unscanned, r.Code, 1)
		}
		if r.Content && !r.Retryable {
			settle(StateUnscannable)
			it.Verdict, it.Code, it.Signature = "", r.Code, s.signatureLocked()
			it.Action = ""
			if r.Refused {
				it.Action = r.Action
			}
			if r.Refused {
				c.Refused++
			}
			break
		}
		// No verdict, but one is worth trying for again.
		prio := it.Priority
		switch src {
		case SourceClient:
			prio = PriorityClient
		case SourceMirror:
			prio = PriorityMirror
		}
		if r.Code == "budget-exhausted" {
			// The gate's own budget: every scan would be refused for now.
			s.gateBudgetUntil = now.Add(s.opts.GateBudgetWait)
		}
		it.Code = r.Code
		if !own {
			// The gate could not judge a client's pull or the mirror's
			// fetch: queued at once, in the note's class. (The full scan
			// yields to the gate's waiting scans, so a busy gate is not
			// asked again before it has room.)
			s.enqueueLocked(it, prio, now, time.Time{})
			break
		}
		c.Retries++
		counted := !(r.Code == "scanner-busy" || r.Code == "budget-exhausted" || r.Code == "provider-unavailable")
		s.retryLocked(it, now, prio, counted, "")
	}
	if r.Evicted && !it.Evicted {
		// The ladder — this gate's or another's in a gate pass — removed the
		// object from the cache; the item stays as the record of why.
		s.q.remove(it)
		it.Evicted, it.EvictedAt = true, now.UTC()
		c.Evicted++
	}
	s.putLocked(it)
}

// retryLocked puts an item back into the queue after a failed attempt, or
// gives up on it once it has failed MaxAttempts times (the next sweep queues
// it again).
func (s *Service) retryLocked(it *Item, now time.Time, prio Priority, countAttempt bool, msg string) {
	if countAttempt {
		it.Attempts++
	}
	if msg != "" {
		it.LastError = msg
	}
	if it.Attempts >= s.opts.MaxAttempts {
		s.q.remove(it)
		it.State, it.NotBefore = StateError, time.Time{}
		s.putLocked(it)
		return
	}
	wait := s.opts.RetryBase
	for i := 1; i < it.Attempts && wait < time.Hour; i++ {
		wait *= 2
	}
	if wait > time.Hour {
		wait = time.Hour
	}
	s.enqueueLocked(it, prio, now, now.Add(wait))
}

// enqueueLocked queues an item (or moves it up to a higher class). A pending
// item keeps its place unless prio is higher than its class.
func (s *Service) enqueueLocked(it *Item, prio Priority, now, notBefore time.Time) {
	wasPending := it.State == StatePending
	if wasPending && prio >= it.Priority && notBefore.IsZero() && !it.busy {
		if it.hq < 0 && !it.parked {
			s.q.push(it, now) // lost its place (a restart): back in
		}
		return
	}
	if !wasPending || prio < it.Priority {
		it.Priority = prio
	}
	if !wasPending || it.Enqueued.IsZero() {
		it.Enqueued = now.UTC()
	}
	it.State = StatePending
	s.st.Seq++
	it.Seq = s.st.Seq
	it.NotBefore = notBefore
	if !it.busy {
		s.q.push(it, now)
	}
	s.putLocked(it)
}

func (s *Service) putLocked(it *Item) {
	if err := s.jr.put(it); err != nil {
		s.log.Warn("fullscan: journalling an item", "key", it.Key, "error", err)
		s.jrFailed = true
	}
	s.dirty = true
	s.statusCache = nil
}

func (s *Service) removeLocked(it *Item) {
	s.q.remove(it)
	delete(s.items, it.Key)
	if err := s.jr.del(it.Key); err != nil {
		s.log.Warn("fullscan: journalling a removal", "key", it.Key, "error", err)
		s.jrFailed = true
	}
	s.dirty = true
	s.statusCache = nil
}

func (s *Service) countersLocked(upstream string) *Counters {
	if s.st.Counters == nil {
		s.st.Counters = map[string]*Counters{}
	}
	c := s.st.Counters[upstream]
	if c == nil {
		c = &Counters{}
		s.st.Counters[upstream] = c
	}
	return c
}

func (s *Service) signatureLocked() string {
	if s.scanner == nil {
		return ""
	}
	return s.scanner.Signature()
}

// newItem tracks a cached artifact.
func (s *Service) newItem(a Artifact, now time.Time) *Item {
	it := &Item{
		Key: a.Key, Upstream: a.Upstream, Path: a.Path, Accept: a.Accept, Tenant: a.Tenant,
		Digest: a.Digest, Size: a.Size, Cached: a.Cached.UTC(), Priority: PriorityBackfill, hq: -1, hi: -1,
	}
	// The tenant is the one the fill metadata or the note names, the empty
	// (shared) one included: with cache namespacing it is the namespace that
	// holds the object, and a verdict is shown to the tenant that pulled.
	if it.Cached.IsZero() {
		it.Cached = now.UTC()
	}
	return it
}

// stale reports an item whose reading was made under another signature.
func stale(it *Item, sig string) bool {
	if sig == "" || it.Evicted {
		return false
	}
	switch it.State {
	case StateScanned, StateUnscannable, StateNotApplicable:
		return it.Signature != sig
	}
	return false
}

// standby drops what this replica held: whoever leads now writes the state.
func (s *Service) standby() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		if s.termCancel != nil {
			// The scans of this leadership end; their items are the new
			// leader's.
			s.termCancel()
		}
		if err := s.jr.close(); err != nil {
			s.log.Warn("fullscan: closing the journal", "error", err)
		}
		if s.oldJr != nil {
			_ = s.oldJr.close()
		}
		s.loaded, s.items, s.q, s.jr, s.oldJr = false, nil, nil, nil, nil
		s.pendingSnap, s.pendingLog, s.jrFailed = "", "", false
		s.statusCache, s.published = nil, nil
	}
	s.activity, s.detail = StateStandby, "another replica leads the full scan"
}

// ensureLoaded reads the state when this replica has just come to lead, and
// starts a new snapshot and journal under a new generation.
func (s *Service) ensureLoaded(ctx context.Context) error {
	s.mu.Lock()
	if s.loaded {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	now := s.now()
	st, err := s.store.loadState()
	reset := ""
	switch {
	case errors.Is(err, errNoFile):
		st = stateFile{}
	case err != nil:
		// The inventory can be rebuilt from the cache: set the unreadable
		// state aside and start over. The counters and the spend are lost.
		aside := s.store.statePath() + ".unreadable-" + now.UTC().Format("20060102T150405Z")
		if rerr := os.Rename(s.store.statePath(), aside); rerr != nil {
			return fmt.Errorf("%w (and it cannot be set aside: %v)", err, rerr)
		}
		reset = "the state could not be read (" + cleanMessage(err.Error()) + "); it was set aside as " + aside
		st = stateFile{}
	}
	expect := st.Generation
	items, skipped, ierr := s.store.loadInventory(st)
	if ierr != nil {
		reset = "the inventory could not be read (" + cleanMessage(ierr.Error()) + "); the sweep rebuilds it"
		items = map[string]*Item{}
	}
	// An upstream that left the scope (or the configuration) leaves with its
	// artifacts; the sweep adds them again if it comes back.
	dropped := 0
	for key, it := range items {
		if !s.inScope(it.Upstream) {
			delete(items, key)
			dropped++
		}
	}
	if dropped > 0 {
		s.log.Info("full scan: dropping the artifacts of upstreams outside the scope", "artifacts", dropped)
	}
	snap, jname := newInventoryNames(expect + 1)
	if err := s.store.writeSnapshot(snap, items); err != nil {
		return fmt.Errorf("fullscan: writing the inventory snapshot: %w", err)
	}
	jr, err := s.store.openJournal(jname)
	if err != nil {
		return fmt.Errorf("fullscan: opening the journal: %w", err)
	}
	next := st
	next.Snapshot, next.Journal = snap, jname
	gen, err := s.store.saveState(next, expect)
	if err != nil {
		_ = jr.close()
		return err
	}
	s.store.removeStale(snap, jname)
	q := newQueue()
	for _, it := range items {
		if it.State == StatePending {
			q.push(it, now)
		}
	}
	next.Generation = gen
	tctx, tcancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.term++
	s.termCtx, s.termCancel = tctx, tcancel
	s.st, s.gen, s.items, s.q, s.jr, s.loaded = next, gen, items, q, jr, true
	s.dirty, s.lastSave, s.statusCache = false, now, nil
	s.nextSweep = now
	s.running = 0
	loadedItems := len(items) // read under the lock: notes change the map once it is loaded
	s.mu.Unlock()
	if skipped > 0 {
		s.log.Warn("full scan: damaged inventory lines were skipped; the sweep restores their artifacts", "lines", skipped)
	}
	if reset != "" {
		s.log.Warn("full scan: starting the inventory over", "reason", reset)
		s.audit(ctx, "state-reset", "", "", map[string]any{"reason": reset})
	}
	s.recheckSignature(ctx)
	s.log.Info("full scan: leading", "items", loadedItems, "generation", gen)
	return nil
}

// recheckSignature puts every artifact whose reading was made under another
// scan signature back into the queue.
func (s *Service) recheckSignature(ctx context.Context) {
	s.mu.Lock()
	sig := s.signatureLocked()
	if sig == "" {
		s.mu.Unlock()
		return
	}
	prev := s.st.Signature
	now := s.now()
	var stales []*Item
	for _, it := range s.items {
		if stale(it, sig) {
			stales = append(stales, it)
		}
	}
	sort.Slice(stales, func(i, j int) bool { return olderFirst(stales[i], stales[j]) })
	counts := map[string]uint64{}
	for _, it := range stales {
		s.enqueueLocked(it, PriorityBackfill, now, time.Time{})
		bump(&s.countersLocked(it.Upstream).Rescans, "version", 1)
		counts[it.Upstream]++
	}
	s.st.Signature = sig
	s.dirty = true
	s.mu.Unlock()
	if len(stales) > 0 {
		s.audit(ctx, "rescan-version", "", "", map[string]any{"from": prev, "to": sig, "artifacts": len(stales)})
		s.log.Info("full scan: the scan signature changed; re-queueing artifacts", "from", prev, "to", sig, "artifacts", len(stales))
	}
}

func olderFirst(a, b *Item) bool {
	if !a.Cached.Equal(b.Cached) {
		return a.Cached.Before(b.Cached)
	}
	return a.Key < b.Key
}

// persist syncs the journal and writes the state when they changed (or when
// force), compacting the inventory once its journal is long or broken.
//
// A compaction switches the appends to a new journal at once, but state.json
// names the new snapshot and journal only once that snapshot is on disk: until
// then (a failed write is retried at the next persist, from a fresh copy) it
// names the old pair, which describes the inventory as of the switch. Replaying
// the new journal over a snapshot taken after the switch is sound: its records
// are puts and deletes, applied in order.
func (s *Service) persist(force bool) error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.Lock()
	if !s.loaded {
		s.mu.Unlock()
		return nil
	}
	now := s.now()
	if err := s.jr.flush(); err != nil {
		s.log.Warn("fullscan: syncing the journal; starting a new one", "error", err)
		s.jrFailed = true
	}
	due := force || s.jrFailed || s.pendingSnap != "" ||
		(s.dirty && now.Sub(s.lastSave) >= s.opts.PersistInterval) || now.Sub(s.lastSave) >= 10*time.Second
	if !due {
		s.mu.Unlock()
		return nil
	}
	if s.jrFailed || (s.pendingSnap == "" && s.jr.records > maxJournalRecords && s.jr.records > 2*len(s.items)) {
		snap, jname := newInventoryNames(s.gen + 1)
		if jr, err := s.store.openJournal(jname); err != nil {
			s.log.Warn("fullscan: opening a new journal", "error", err)
		} else {
			if s.pendingSnap != "" || s.oldJr != nil {
				// A compaction is under way already: its journal is the one
				// that failed. The journal state.json names stays as it is.
				_ = s.jr.close()
			} else {
				s.oldJr = s.jr
			}
			s.jr = jr
			s.pendingSnap, s.pendingLog, s.jrFailed = snap, jname, false
		}
	}
	var snapCopy map[string]*Item
	pendingSnap, pendingLog := s.pendingSnap, s.pendingLog
	if pendingSnap != "" {
		snapCopy = make(map[string]*Item, len(s.items))
		for k, it := range s.items {
			cp := *it
			snapCopy[k] = &cp
		}
	}
	st := s.st
	st.Counters = make(map[string]*Counters, len(s.st.Counters))
	for k, c := range s.st.Counters {
		cp := c.clone()
		st.Counters[k] = &cp
	}
	st.Untracked = cloneInts(s.st.Untracked)
	// The figures for replicas that do not lead: counting them walks the
	// inventory, so they are refreshed every PublishInterval, not on every
	// write.
	if s.published == nil || force || now.Sub(s.publishedAt) >= s.opts.PublishInterval {
		pub := s.statusLocked(now)
		pub.State, pub.Detail = s.activity, s.detail
		pub.Upstreams = append([]UpstreamStatus(nil), pub.Upstreams...)
		s.published, s.publishedAt = &pub, now
	}
	st.Published = s.published
	expect := s.gen
	s.lastSave, s.dirty = now, false
	s.mu.Unlock()

	compacted := false
	if snapCopy != nil {
		if err := s.store.writeSnapshot(pendingSnap, snapCopy); err != nil {
			s.log.Warn("fullscan: writing the compacted snapshot; retrying at the next write", "error", err)
		} else {
			st.Snapshot, st.Journal, compacted = pendingSnap, pendingLog, true
		}
	}
	gen, err := s.store.saveState(st, expect)
	if errors.Is(err, errFenced) {
		s.log.Warn("full scan: another replica has taken over; standing by")
		return err
	}
	if err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		s.log.Warn("fullscan: writing the state", "error", err)
		return err
	}
	var old *journal
	s.mu.Lock()
	if s.gen == expect {
		s.gen = gen
		s.st.Generation = gen
	}
	if compacted && s.pendingSnap == pendingSnap {
		s.st.Snapshot, s.st.Journal = pendingSnap, pendingLog
		s.pendingSnap, s.pendingLog = "", ""
		old, s.oldJr = s.oldJr, nil
	}
	s.mu.Unlock()
	if compacted {
		_ = old.close()
		s.store.removeStale(pendingSnap, pendingLog)
	}
	return nil
}

func cloneInts(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// applyRescans acts on the operators' re-scan requests not handled yet.
func (s *Service) applyRescans(ctx context.Context, ctl controlFile) {
	s.mu.Lock()
	handled := s.st.RescanHandled
	var todo []RescanRequest
	for _, r := range ctl.Rescans {
		if r.Seq > handled {
			todo = append(todo, r)
		}
	}
	if len(todo) == 0 {
		s.mu.Unlock()
		return
	}
	now := s.now()
	type result struct {
		req   RescanRequest
		count int
	}
	var results []result
	for _, r := range todo {
		var matched []*Item
		for _, it := range s.items {
			if r.matches(it) {
				matched = append(matched, it)
			}
		}
		sort.Slice(matched, func(i, j int) bool { return olderFirst(matched[i], matched[j]) })
		prio := PriorityBackfill
		if r.Path != "" {
			prio = PriorityClient
		}
		for _, it := range matched {
			// A re-scan checks everything again: the gates too.
			it.Refresh, it.Attempts, it.LastError, it.Gates, it.Gate = true, 0, "", "", ""
			if it.busy {
				// Its scan is running: the re-scan follows it.
				it.again = true
				s.putLocked(it)
			} else if it.State == StatePending {
				// Already queued: it gets the fresh model call when its
				// turn comes, and moves up for a re-scan by path.
				if prio < it.Priority && !it.busy {
					s.enqueueLocked(it, prio, now, time.Time{})
				} else {
					s.putLocked(it)
				}
			} else {
				s.enqueueLocked(it, prio, now, time.Time{})
			}
			bump(&s.countersLocked(it.Upstream).Rescans, "operator", 1)
		}
		if r.Seq > s.st.RescanHandled {
			s.st.RescanHandled = r.Seq
		}
		results = append(results, result{req: r, count: len(matched)})
	}
	s.dirty = true
	s.mu.Unlock()
	for _, res := range results {
		s.audit(ctx, "rescan", res.req.By, firstNonEmpty(res.req.Upstream, "*"), map[string]any{
			"request": res.req.Seq, "filter": res.req.Filter, "path": res.req.Path, "artifacts": res.count,
		})
		s.log.Info("full scan: re-scan queued", "request", res.req.Seq, "upstream", firstNonEmpty(res.req.Upstream, "*"),
			"filter", res.req.Filter, "path", res.req.Path, "artifacts", res.count)
	}
}
