package fullmirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// Activities a follower reports (UpstreamStatus.State).
const (
	// StateStarting: the engine is not attached to the gateway yet.
	StateStarting = "starting"
	// StateStandby: another replica leads the full mirror.
	StateStandby = "standby"
	// StateLockdown: an emergency lockdown is engaged.
	StateLockdown = "lockdown"
	// StatePaused: an operator paused the mirror.
	StatePaused = "paused"
	// StateOffPeak: outside the off-peak window.
	StateOffPeak = "off-peak"
	// StateBudgetExhausted: the byte budget is spent.
	StateBudgetExhausted = "budget-exhausted"
	// StateBackingOff: waiting after failures, or for the upstream's
	// Retry-After.
	StateBackingOff = "backing-off"
	// StateBootstrapping: enumerating the registry for the first time.
	StateBootstrapping = "bootstrapping"
	// StateFollowing: following the registry's changes.
	StateFollowing = "following"
	// StateError: the state could not be read; a resync starts afresh.
	StateError = "error"
	// StateStopped: the engine was closed.
	StateStopped = "stopped"
)

// Reasons a batch stops before its end. The batch is resumed later.
var (
	errNotLeader   = errors.New("fullmirror: this replica does not lead the full mirror")
	errLockdown    = errors.New("fullmirror: an emergency lockdown is engaged")
	errPaused      = errors.New("fullmirror: paused by an operator")
	errResync      = errors.New("fullmirror: a resync was requested")
	errOffPeak     = errors.New("fullmirror: outside the off-peak window")
	errBudget      = errors.New("fullmirror: the byte budget is spent")
	errBackingOff  = errors.New("fullmirror: backing off")
	errRetryLater  = errors.New("fullmirror: the upstream keeps failing; retrying later")
	errVersionGone = errors.New("fullmirror: the registry does not list the version")
	// errBatchHalted is what a worker's checks report once another worker
	// has stopped the batch: the stop is not this worker's item's failure.
	errBatchHalted = errors.New("fullmirror: the batch stopped")
	// errHeld reports a refusal that would hold for every file of the
	// upstream (the mirror's roles do not grant it, the organization is
	// frozen to a snapshot): no verdict, the mirror waits.
	errHeld = errors.New("fullmirror: a gate refuses every file of this upstream for now")
)

// Waits after refusals that are not verdicts.
const (
	// holdWait is how long the mirror waits after a refusal that holds for
	// the whole upstream.
	holdWait = 5 * time.Minute
	// deferUnjudged is when a file a gate could not judge (its scanner
	// unavailable, fail-closed) is asked for again; minDeferral the
	// shortest deferral.
	deferUnjudged = 15 * time.Minute
	minDeferral   = time.Minute
	// maxDuePerStep bounds the deferred files retried in one step.
	maxDuePerStep = 256
)

// maxInlineBackoff is the longest wait a worker sleeps through; a longer one
// stops the batch and leaves the wait to the follower.
const maxInlineBackoff = time.Minute

// follower follows one upstream.
type follower struct {
	e        *Engine
	s        Settings
	tier     Tier
	upstream Upstream
	feed     Feed
	scheme   versions.Scheme
	wake     chan struct{}

	// persistMu serializes the writes of state.json.
	persistMu sync.Mutex

	mu sync.Mutex
	// st is the state as of the last load (valid when loaded).
	st      upstreamState
	loaded  bool
	loadErr error
	// items are the pending batch's items.
	items []Coordinate
	// control is the upstream's control file, read at controlAt.
	control   controlFile
	controlAt time.Time
	controlOK bool
	// activity and detail are what the follower is doing, for the status.
	activity string
	detail   string
	// nextPoll is when the feed is asked again; backoffUntil when the
	// upstream may be asked anything again.
	nextPoll     time.Time
	backoffUntil time.Time
	pollFailures int
	// inFlight counts files being fetched, reserved the budget they hold.
	inFlight int
	reserved int64
	// stuck counts the failed rounds of the pending batch's items; donePaths
	// the files of an unfinished item already dealt with in an earlier round
	// (the key "" records that its version-policy skips were counted).
	stuck     map[int]int
	donePaths map[int]map[string]bool
	// ahead is the pending batch's items done beyond its low-water mark.
	ahead map[int]bool
	// deferred are the files a gate said "not yet" to, by path; deferredGen
	// counts their changes, savedGen is the generation last written.
	deferred    map[string]*deferredItem
	deferredGen uint64
	savedGen    uint64
	// lastPersist is when the state was last written; dirty that it changed
	// since; gen the generation of state.json last read or written.
	lastPersist time.Time
	dirty       bool
	gen         uint64
	// peeked is the state read from disk for the status of a follower that
	// does not lead, at peekedAt, with its deferred queue's size and first
	// due time.
	peeked         *upstreamState
	peekedAt       time.Time
	peekedDeferred int
	peekedNextDue  time.Time
}

func (f *follower) kick() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// run is the follower's loop.
func (f *follower) run(ctx context.Context) {
	for {
		wait := f.safeStep(ctx)
		if ctx.Err() != nil {
			f.setActivity(StateStopped, "")
			return
		}
		if wait < 10*time.Millisecond {
			wait = 10 * time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			f.setActivity(StateStopped, "")
			return
		case <-f.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// panicWait is the wait after a follower recovered from a panic.
const panicWait = 5 * time.Minute

// safeStep runs step, turning a panic — a bug in an adapter reading a
// registry's documents — into an error of this upstream instead of the end of
// the proxy.
func (f *follower) safeStep(ctx context.Context) (wait time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("internal error: %v", r)
			f.e.log.Error("full mirroring: the follower recovered from a panic", "upstream", f.s.Upstream, "panic", r, "stack", string(debug.Stack()))
			f.recordError("", "", err)
			f.setActivity(StateError, cleanMessage(err.Error()))
			wait = panicWait
		}
	}()
	return f.step(ctx)
}

// step does one unit of work — a poll, or a batch — and returns how long to
// wait before the next.
func (f *follower) step(ctx context.Context) time.Duration {
	now := f.e.now()
	f.refreshControl(now, true)
	if !f.e.isLeader() {
		f.standby()
		return f.e.opts.StandbyInterval
	}
	if err := f.ensureLoaded(); err != nil {
		if f.resyncPending() {
			f.resync(ctx, now)
			return 0
		}
		f.setActivity(StateError, "the state cannot be read: "+cleanMessage(err.Error())+"; a resync starts afresh")
		return time.Minute
	}
	if f.resyncPending() {
		f.resync(ctx, now)
	}
	if wait, blocked := f.blocked(ctx, now); blocked {
		return wait
	}
	fetcher := f.e.currentFetcher()
	if fetcher == nil {
		f.setActivity(StateStarting, "waiting for the gateway")
		return 5 * time.Second
	}
	if err := f.processDeferred(ctx, fetcher); err != nil {
		if errors.Is(err, errNotLeader) {
			f.standby()
			return f.e.opts.StandbyInterval
		}
		return f.nextWait()
	}
	if f.hasBatch() {
		f.processBatch(ctx, fetcher)
		return f.nextWait()
	}
	f.mu.Lock()
	next := f.nextPoll
	f.mu.Unlock()
	if next.After(now) {
		f.setActivity(f.phaseActivity(), "next poll at "+next.UTC().Format(time.RFC3339))
		return f.nextWait()
	}
	f.poll(ctx, fetcher)
	return f.nextWait()
}

// nextWait is the wait after a poll or a batch: until the upstream may be
// asked again, the next poll, or the next deferred file is due.
func (f *follower) nextWait() time.Duration {
	now := f.e.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.backoffUntil.After(now) {
		return f.backoffUntil.Sub(now)
	}
	if f.st.Batch != nil {
		// A batch that stopped: the next step finds out why (a pause, the
		// window, the budget) and waits accordingly.
		return 100 * time.Millisecond
	}
	wait := time.Duration(0)
	if f.nextPoll.After(now) {
		wait = f.nextPoll.Sub(now)
	}
	if due := f.nextDueLocked(); !due.IsZero() && wait > 0 {
		if d := due.Sub(now); d < wait {
			wait = d
			if wait < time.Second {
				wait = time.Second
			}
		}
	}
	return wait
}

// nextDueLocked is when the earliest deferred file is due (zero: none).
func (f *follower) nextDueLocked() time.Time {
	var due time.Time
	for _, it := range f.deferred {
		if due.IsZero() || it.NotBefore.Before(due) {
			due = it.NotBefore
		}
	}
	return due
}

// blocked reports a reason the follower must not work now, and how long to
// wait before looking again.
func (f *follower) blocked(ctx context.Context, now time.Time) (time.Duration, bool) {
	if active, mode := f.e.killSwitch(); active {
		f.setActivity(StateLockdown, "emergency lockdown ("+firstNonEmpty(mode, "active")+")")
		return 30 * time.Second, true
	}
	if paused, detail := f.paused(); paused {
		f.setActivity(StatePaused, detail)
		return 30 * time.Second, true
	}
	if !f.s.Window.Contains(now) {
		open := f.s.Window.NextOpen(now)
		f.setActivity(StateOffPeak, "the window ("+f.s.Window.String()+") opens at "+open.UTC().Format(time.RFC3339))
		wait := open.Sub(now)
		if wait > 15*time.Minute {
			wait = 15 * time.Minute
		}
		if wait < time.Second {
			wait = time.Second
		}
		return wait, true
	}
	if f.budgetBlocked(ctx) {
		f.mu.Lock()
		used := f.st.BudgetUsed
		f.mu.Unlock()
		f.setActivity(StateBudgetExhausted, fmt.Sprintf("%d of %d bytes spent; raise fullMirror.byteBudget to continue", used, f.s.ByteBudget))
		return 5 * time.Minute, true
	}
	f.mu.Lock()
	until := f.backoffUntil
	f.mu.Unlock()
	if until.After(now) {
		f.setActivity(StateBackingOff, "until "+until.UTC().Format(time.RFC3339))
		return until.Sub(now), true
	}
	return 0, false
}

// paused reports whether an operator paused this upstream (or every one).
func (f *follower) paused() (bool, string) {
	g := f.e.globalControl(false)
	if g.Paused {
		return true, pauseDetail("all upstreams", g)
	}
	f.mu.Lock()
	c := f.control
	f.mu.Unlock()
	if c.Paused {
		return true, pauseDetail("this upstream", c)
	}
	return false, ""
}

func pauseDetail(what string, c controlFile) string {
	d := "paused (" + what + ")"
	if c.PausedBy != "" {
		d += " by " + c.PausedBy
	}
	if !c.PausedAt.IsZero() {
		d += " at " + c.PausedAt.UTC().Format(time.RFC3339)
	}
	if c.Reason != "" {
		d += ": " + c.Reason
	}
	return d
}

// refreshControl re-reads the upstream's control file (and the global one),
// at most every ControlRefresh unless force.
func (f *follower) refreshControl(now time.Time, force bool) {
	f.e.globalControl(force)
	f.mu.Lock()
	fresh := f.controlOK && now.Sub(f.controlAt) < f.e.opts.ControlRefresh
	f.mu.Unlock()
	if fresh && !force {
		return
	}
	c, err := f.e.store.loadControl(f.e.store.controlPath(f.s.Upstream))
	if err != nil {
		f.e.log.Warn("fullmirror: reading the control file", "upstream", f.s.Upstream, "error", err)
		return
	}
	f.mu.Lock()
	f.control, f.controlAt, f.controlOK = c, now, true
	f.mu.Unlock()
}

func (f *follower) resyncPending() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.control.ResyncSeq > f.st.ResyncHandled
}

// freshState is the state of an upstream never mirrored.
func (f *follower) freshState() upstreamState {
	return upstreamState{Format: stateFormat, Upstream: f.s.Upstream, Type: f.s.Type, Phase: phaseBootstrap}
}

// ensureLoaded reads the state when this replica has just come to lead.
func (f *follower) ensureLoaded() error {
	f.mu.Lock()
	if f.loaded {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()
	st, err := f.e.store.loadState(f.s.Upstream)
	switch {
	case errors.Is(err, errNoFile):
		st, err = f.freshState(), nil
	case err != nil:
		f.mu.Lock()
		f.loadErr = err
		f.mu.Unlock()
		return err
	}
	if st.Upstream != f.s.Upstream {
		err := fmt.Errorf("fullmirror: the state directory of %q holds the state of %q", f.s.Upstream, st.Upstream)
		f.mu.Lock()
		f.loadErr = err
		f.mu.Unlock()
		return err
	}
	typeChanged := st.Type != "" && st.Type != f.s.Type
	deferred := map[string]*deferredItem{}
	def, derr := f.e.store.loadDeferred(f.s.Upstream)
	switch {
	case derr == nil:
		for i := range def.Items {
			it := def.Items[i]
			if it.Path != "" {
				deferred[it.Path] = &it
			}
		}
	case !errors.Is(derr, errNoFile):
		// The queue is lost; its files come back with the next change of
		// their packages (or a resync).
		f.e.log.Warn("fullmirror: the deferred queue cannot be read; starting it empty", "upstream", f.s.Upstream, "error", derr)
	}
	f.mu.Lock()
	f.st, f.loaded, f.loadErr, f.gen = st, true, nil, st.Generation
	f.items, f.stuck, f.donePaths, f.ahead = nil, nil, nil, nil
	f.nextPoll, f.backoffUntil, f.pollFailures = time.Time{}, time.Time{}, 0
	f.deferred, f.deferredGen, f.savedGen = deferred, 0, 0
	f.mu.Unlock()
	if derr != nil && !errors.Is(derr, errNoFile) {
		f.recordError("", "", fmt.Errorf("the deferred queue could not be read and starts empty: %w", derr))
	}
	if typeChanged {
		// The cursor belongs to another registry's feed.
		f.e.log.Warn("fullmirror: the upstream's type changed; enumerating it again", "upstream", f.s.Upstream, "was", st.Type, "now", f.s.Type)
		f.mu.Lock()
		f.resetLocked()
		f.st.Type = f.s.Type
		f.mu.Unlock()
		f.e.audit(context.Background(), f, "type-changed", "", map[string]any{"was": st.Type})
		_ = f.e.store.removeBatch(f.s.Upstream)
		return f.persist(true)
	}
	return nil
}

// standby drops what this replica knew: whoever leads now writes the state,
// and this replica reads it afresh when it leads again.
func (f *follower) standby() {
	f.mu.Lock()
	f.loaded, f.items, f.stuck, f.donePaths, f.ahead = false, nil, nil, nil, nil
	f.deferred = nil
	f.mu.Unlock()
	f.setActivity(StateStandby, "another replica leads the full mirror")
}

// resetLocked forgets the cursor: the registry is enumerated again.
func (f *follower) resetLocked() {
	f.st.Phase, f.st.Cursor, f.st.Batch = phaseBootstrap, "", nil
	f.st.BootstrapStarted, f.st.BootstrapFinished = time.Time{}, time.Time{}
	f.st.Head, f.st.Lag, f.st.LagKnown = "", 0, false
	f.st.HeadTime, f.st.CursorTime = time.Time{}, time.Time{}
	f.items, f.stuck, f.donePaths, f.ahead = nil, nil, nil, nil
	f.nextPoll, f.backoffUntil, f.pollFailures = time.Time{}, time.Time{}, 0
}

// resync acts on an operator's resync request.
func (f *follower) resync(ctx context.Context, now time.Time) {
	f.mu.Lock()
	seq, by := f.control.ResyncSeq, f.control.ResyncBy
	if !f.loaded {
		// The state could not be read: start from a fresh one, which
		// replaces the unreadable file.
		f.st, f.loaded, f.loadErr = f.freshState(), true, nil
		f.gen = 0
		if cur, err := f.e.store.loadState(f.s.Upstream); err == nil {
			f.gen = cur.Generation
		}
		if f.deferred == nil {
			f.deferred = map[string]*deferredItem{}
		}
	}
	f.resetLocked()
	f.st.ResyncHandled = seq
	f.mu.Unlock()
	_ = f.e.store.removeBatch(f.s.Upstream)
	if err := f.persist(true); err != nil {
		f.e.log.Warn("fullmirror: writing the state", "upstream", f.s.Upstream, "error", err)
	}
	f.e.audit(ctx, f, "resync", by, map[string]any{"request": seq})
	f.e.log.Info("full mirroring: enumerating the registry again", "upstream", f.s.Upstream, "requestedBy", by)
}

// budgetBlocked reports whether the byte budget is spent. A budget raised
// above the one in force when it ran out lets the mirror continue.
func (f *follower) budgetBlocked(ctx context.Context) bool {
	f.mu.Lock()
	raised := f.st.BudgetExhaustedAt > 0 && f.s.ByteBudget > f.st.BudgetExhaustedAt
	if raised {
		f.st.BudgetExhaustedAt = 0
		f.dirty = true
	}
	blocked := f.st.BudgetUsed >= f.s.ByteBudget || f.st.BudgetExhaustedAt > 0
	f.mu.Unlock()
	if raised && !blocked {
		f.e.audit(ctx, f, "budget-raised", "", map[string]any{"budget": f.s.ByteBudget})
	}
	return blocked
}

// exhaustBudget records that the budget ran out.
func (f *follower) exhaustBudget(ctx context.Context) {
	f.mu.Lock()
	first := f.st.BudgetExhaustedAt == 0
	if first {
		f.st.BudgetExhaustedAt = f.s.ByteBudget
		f.dirty = true
	}
	used := f.st.BudgetUsed
	f.mu.Unlock()
	if first {
		f.e.audit(ctx, f, "budget-exhausted", "", map[string]any{"budget": f.s.ByteBudget, "used": used})
		f.e.log.Warn("full mirroring: the byte budget is spent", "upstream", f.s.Upstream, "budget", f.s.ByteBudget, "used", used)
	}
}

func (f *follower) hasBatch() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.Batch != nil
}

func (f *follower) phaseActivity() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Phase == phaseFollow {
		return StateFollowing
	}
	return StateBootstrapping
}

func (f *follower) setActivity(state, detail string) {
	f.mu.Lock()
	f.activity, f.detail = state, detail
	f.mu.Unlock()
}

// count updates the counters.
func (f *follower) count(edit func(*Counters)) {
	f.mu.Lock()
	edit(&f.st.Counters)
	f.dirty = true
	f.mu.Unlock()
}

// recordError keeps an error for the status.
func (f *follower) recordError(pkg, path string, err error) {
	rec := ErrorRecord{Time: f.e.now().UTC(), Package: pkg, Path: path, Message: cleanMessage(err.Error())}
	f.mu.Lock()
	f.st.RecentErrors = append(f.st.RecentErrors, rec)
	if n := len(f.st.RecentErrors); n > maxRecentErrors {
		f.st.RecentErrors = append([]ErrorRecord(nil), f.st.RecentErrors[n-maxRecentErrors:]...)
	}
	f.dirty = true
	f.mu.Unlock()
}

// setUpstreamBackoff has every request to the upstream wait until t.
func (f *follower) setUpstreamBackoff(t time.Time) {
	f.mu.Lock()
	if t.After(f.backoffUntil) {
		f.backoffUntil = t
	}
	f.mu.Unlock()
}

// persist writes the state (when force, or when it is due). A newer
// leadership's state stops this replica.
func (f *follower) persist(force bool) error {
	now := f.e.now()
	// One write at a time, and the generation expected read under the same
	// lock: two workers persisting at once must not fence each other.
	f.persistMu.Lock()
	defer f.persistMu.Unlock()
	f.mu.Lock()
	if !f.loaded || (!force && (!f.dirty || now.Sub(f.lastPersist) < f.e.opts.PersistInterval)) {
		f.mu.Unlock()
		return nil
	}
	f.st.Fence = f.e.fenceToken()
	st := f.st
	st.Counters = st.Counters.clone()
	st.RecentErrors = append([]ErrorRecord(nil), st.RecentErrors...)
	if st.Batch != nil {
		b := *st.Batch
		b.Ahead = sortedKeys(f.ahead)
		if f.ahead == nil {
			b.Ahead = append([]int(nil), st.Batch.Ahead...)
		}
		st.Batch = &b
	}
	var defSnap *deferredFile
	defGen := f.deferredGen
	if defGen != f.savedGen {
		defSnap = &deferredFile{Items: make([]deferredItem, 0, len(f.deferred))}
		for _, it := range f.deferred {
			defSnap.Items = append(defSnap.Items, *it)
		}
		sort.Slice(defSnap.Items, func(i, j int) bool {
			a, b := defSnap.Items[i], defSnap.Items[j]
			if !a.NotBefore.Equal(b.NotBefore) {
				return a.NotBefore.Before(b.NotBefore)
			}
			return a.Path < b.Path
		})
	}
	expect := f.gen
	f.lastPersist, f.dirty = now, false
	f.mu.Unlock()
	var err error
	if defSnap != nil {
		// The deferred queue first: an item the state counts as done has
		// its deferrals on disk. Not over a newer leader's.
		if cur, lerr := f.e.store.loadState(f.s.Upstream); lerr == nil && cur.Generation != expect {
			err = errFenced
		} else if err = f.e.store.saveDeferred(f.s.Upstream, *defSnap); err == nil {
			f.mu.Lock()
			if defGen > f.savedGen {
				f.savedGen = defGen
			}
			f.mu.Unlock()
		}
	}
	if err == nil {
		err = f.e.store.saveState(f.s.Upstream, st, expect)
	}
	if err == nil {
		f.mu.Lock()
		f.gen = expect + 1
		f.st.Generation = f.gen
		f.mu.Unlock()
	}
	if errors.Is(err, errFenced) {
		f.e.log.Warn("full mirroring: another replica has taken over; standing by", "upstream", f.s.Upstream)
		f.standby()
		return err
	}
	if err != nil {
		f.mu.Lock()
		f.dirty = true
		f.mu.Unlock()
		f.e.log.Warn("fullmirror: writing the state", "upstream", f.s.Upstream, "error", err)
	}
	return err
}

// sortedKeys returns a set's members in order (nil for an empty set).
func sortedKeys(m map[int]bool) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// flush writes the state on Close.
func (f *follower) flush() error {
	f.mu.Lock()
	loaded := f.loaded
	f.mu.Unlock()
	if !loaded || !f.e.isLeader() {
		return nil
	}
	return f.persist(true)
}

// poll asks the feed for what comes after the cursor and works through it.
func (f *follower) poll(ctx context.Context, fetcher Fetcher) {
	f.mu.Lock()
	phase, cursor := f.st.Phase, f.st.Cursor
	starting := phase == phaseBootstrap && cursor == "" && f.st.BootstrapStarted.IsZero()
	if starting {
		f.st.BootstrapStarted = f.e.now().UTC()
		f.dirty = true
	}
	f.mu.Unlock()
	if starting {
		f.e.audit(ctx, f, "bootstrap-started", "", nil)
		f.e.log.Info("full mirroring: enumerating the registry", "upstream", f.s.Upstream)
	}
	f.setActivity(f.phaseActivity(), "polling the feed")

	pctx, cancel := context.WithTimeout(ctx, f.e.opts.PollTimeout)
	var (
		b   Batch
		err error
	)
	if phase == phaseBootstrap {
		b, err = f.feed.Bootstrap(pctx, cursor)
	} else {
		b, err = f.feed.Changes(pctx, cursor)
	}
	cancel()
	if ctx.Err() != nil {
		return
	}
	now := f.e.now()
	f.mu.Lock()
	f.st.LastPoll = now.UTC()
	f.st.Counters.Polls++
	f.dirty = true
	f.mu.Unlock()
	if err == nil {
		err = validateBatch(b)
	}
	if err != nil {
		f.pollFailed(ctx, err, now)
		return
	}
	f.mu.Lock()
	f.pollFailures = 0
	if b.Head != "" {
		f.st.Head = b.Head
	}
	f.st.Lag, f.st.LagKnown = b.Lag, b.LagKnown
	if !b.HeadTime.IsZero() {
		f.st.HeadTime = b.HeadTime.UTC()
	}
	if !b.CursorTime.IsZero() {
		f.st.CursorTime = b.CursorTime.UTC()
	}
	f.mu.Unlock()

	prog := batchProgress{Phase: phase, From: cursor, Next: b.Next, More: b.More, Total: len(b.Items), Polled: now.UTC()}
	if len(b.Items) == 0 {
		f.commit(ctx, prog)
		return
	}
	f.mu.Lock()
	prog.Seq = f.st.BatchSeq + 1
	f.mu.Unlock()
	if err := f.e.store.saveBatch(f.s.Upstream, batchFile{Seq: prog.Seq, Items: b.Items}); err != nil {
		f.recordError("", "", fmt.Errorf("storing the batch: %w", err))
		f.setUpstreamBackoff(now.Add(f.e.opts.PollBackoff))
		return
	}
	f.mu.Lock()
	f.st.BatchSeq = prog.Seq
	f.st.Batch = &prog
	f.st.LastChange = now.UTC()
	f.items = b.Items
	f.stuck, f.donePaths = map[int]int{}, map[int]map[string]bool{}
	f.dirty = true
	f.mu.Unlock()
	if err := f.persist(true); err != nil {
		return
	}
	f.processBatch(ctx, fetcher)
}

// validateBatch refuses a batch the engine cannot store or resume from.
func validateBatch(b Batch) error {
	switch {
	case b.Next == "":
		return Permanent(errors.New("the feed returned no cursor to continue from"))
	case len(b.Next) > maxCursorBytes:
		return Permanent(fmt.Errorf("the feed's cursor is %d bytes long; at most %d are kept", len(b.Next), maxCursorBytes))
	case len(b.Items) > maxBatchItems:
		return Permanent(fmt.Errorf("the feed returned %d changes in one batch; at most %d are taken", len(b.Items), maxBatchItems))
	}
	for i, c := range b.Items {
		if c.Name == "" || len(c.Name) > 1024 || len(c.Version) > 1024 || strings.ContainsAny(c.Name+c.Version, "\x00\r\n") {
			return Permanent(fmt.Errorf("the feed's change %d names no valid package (%q)", i, cleanMessage(c.String())))
		}
	}
	return nil
}

// pollFailed handles a failed poll: a cursor the registry no longer knows
// starts the enumeration over; anything else is retried after a backoff.
func (f *follower) pollFailed(ctx context.Context, err error, now time.Time) {
	f.mu.Lock()
	f.st.Counters.PollErrors++
	f.dirty = true
	f.mu.Unlock()
	if errors.Is(err, ErrCursorInvalid) {
		f.mu.Lock()
		was := f.st.Cursor
		f.resetLocked()
		f.mu.Unlock()
		_ = f.e.store.removeBatch(f.s.Upstream)
		f.recordError("", "", err)
		_ = f.persist(true)
		f.e.audit(ctx, f, "cursor-reset", "", map[string]any{"cursor": was, "error": cleanMessage(err.Error())})
		f.e.log.Warn("full mirroring: the registry no longer knows the cursor; enumerating it again", "upstream", f.s.Upstream, "error", err)
		return
	}
	f.mu.Lock()
	f.pollFailures++
	n := f.pollFailures
	f.mu.Unlock()
	wait := backoff(f.e.opts.PollBackoff, time.Hour, n)
	if ra, ok := RetryAfterOf(err); ok && ra > wait {
		wait = ra
	}
	f.setUpstreamBackoff(now.Add(wait))
	f.recordError("", "", fmt.Errorf("polling the feed: %w", err))
	_ = f.persist(true)
	f.e.log.Warn("full mirroring: polling the feed failed", "upstream", f.s.Upstream, "failures", n, "retryIn", wait, "error", err)
}

// backoff is base doubled per failure after the first, at most max.
func backoff(base, max time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// commit stores the cursor after a batch has been dealt with.
func (f *follower) commit(ctx context.Context, prog batchProgress) {
	now := f.e.now()
	f.mu.Lock()
	f.st.Cursor = prog.Next
	finished := prog.Phase == phaseBootstrap && !prog.More
	if finished {
		f.st.Phase = phaseFollow
		f.st.BootstrapFinished = now.UTC()
	}
	if prog.Total > 0 {
		f.st.Counters.Batches++
	}
	f.st.Batch = nil
	f.st.LastCommit = now.UTC()
	f.items, f.stuck, f.donePaths, f.ahead = nil, nil, nil, nil
	if prog.More {
		f.nextPoll = now
	} else {
		f.nextPoll = now.Add(f.s.PollInterval)
	}
	f.dirty = true
	activity := StateBootstrapping
	if f.st.Phase == phaseFollow {
		activity = StateFollowing
	}
	f.activity, f.detail = activity, "next poll at "+f.nextPoll.UTC().Format(time.RFC3339)
	f.mu.Unlock()
	if err := f.persist(true); err != nil {
		return
	}
	_ = f.e.store.removeBatch(f.s.Upstream)
	if finished {
		f.e.audit(ctx, f, "bootstrap-finished", "", nil)
		f.e.log.Info("full mirroring: the registry has been enumerated; following its changes", "upstream", f.s.Upstream)
	}
}

// processBatch works through the pending batch from where it stopped.
func (f *follower) processBatch(ctx context.Context, fetcher Fetcher) {
	f.mu.Lock()
	prog := *f.st.Batch
	items := f.items
	f.mu.Unlock()
	if items == nil {
		b, err := f.e.store.loadBatch(f.s.Upstream)
		if err != nil || b.Seq != prog.Seq || len(b.Items) != prog.Total {
			// The batch's items are lost (or belong to another batch): ask
			// the feed again from the stored cursor. Files already fetched
			// are found in the cache.
			if err == nil {
				err = fmt.Errorf("batch.json holds batch %d with %d items, not batch %d with %d", b.Seq, len(b.Items), prog.Seq, prog.Total)
			}
			f.e.log.Warn("full mirroring: the pending batch cannot be read; polling again", "upstream", f.s.Upstream, "error", err)
			f.mu.Lock()
			f.st.Batch = nil
			f.dirty = true
			f.mu.Unlock()
			_ = f.persist(true)
			return
		}
		items = b.Items
		f.mu.Lock()
		f.items = items
		if f.stuck == nil {
			f.stuck, f.donePaths = map[int]int{}, map[int]map[string]bool{}
		}
		f.mu.Unlock()
	}
	f.setActivity(f.phaseActivity(), fmt.Sprintf("batch %d: %d of %d changes to do", prog.Seq, prog.queued(), prog.Total))

	// mu guards next and stop; the progress — done, the low-water mark lwm
	// and the items done beyond it (f.ahead, persisted with the batch so a
	// resumed batch does not do them again) — is guarded by f.mu.
	var (
		mu   sync.Mutex
		next int
		stop error
		lwm  = prog.Done
		done = make([]bool, len(items))
	)
	f.mu.Lock()
	f.ahead = map[int]bool{}
	for _, i := range prog.Ahead {
		if i >= prog.Done && i < len(items) {
			done[i], f.ahead[i] = true, true
		}
	}
	for lwm < len(items) && done[lwm] {
		delete(f.ahead, lwm)
		lwm++
	}
	rest := len(items) - lwm - len(f.ahead)
	f.mu.Unlock()
	next = lwm
	halt := func() error {
		mu.Lock()
		s := stop
		mu.Unlock()
		if s != nil {
			// Another worker stopped the batch: not this worker's failure.
			return errBatchHalted
		}
		return f.interrupted(ctx)
	}
	workers := f.s.Concurrency
	if rest < workers {
		workers = rest
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				f.mu.Lock()
				for next < len(items) && done[next] {
					next++
				}
				f.mu.Unlock()
				if stop != nil || next >= len(items) {
					mu.Unlock()
					return
				}
				idx := next
				next++
				mu.Unlock()
				if err := halt(); err != nil {
					mu.Lock()
					if stop == nil {
						stop = err
					}
					mu.Unlock()
					return
				}
				if err := f.safeProcessItem(ctx, fetcher, items[idx], idx, halt); err != nil {
					mu.Lock()
					if stop == nil {
						stop = err
					}
					mu.Unlock()
					return
				}
				f.mu.Lock()
				done[idx] = true
				if f.ahead != nil {
					f.ahead[idx] = true
				}
				for lwm < len(items) && done[lwm] {
					delete(f.ahead, lwm)
					lwm++
				}
				if f.st.Batch != nil && f.st.Batch.Seq == prog.Seq {
					f.st.Batch.Done = lwm
					f.dirty = true
				}
				toDo := len(items) - lwm - len(f.ahead)
				f.mu.Unlock()
				f.setActivity(f.phaseActivity(), fmt.Sprintf("batch %d: %d of %d changes to do", prog.Seq, toDo, prog.Total))
				if err := f.persist(false); errors.Is(err, errFenced) {
					mu.Lock()
					if stop == nil {
						stop = errNotLeader
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	f.mu.Lock()
	complete := lwm == len(items)
	f.mu.Unlock()
	if stop == nil && complete {
		f.commit(ctx, prog)
		return
	}
	if errors.Is(stop, errNotLeader) {
		f.standby()
		return
	}
	_ = f.persist(true)
	if stop != nil && ctx.Err() == nil {
		f.e.log.Debug("full mirroring: batch stopped", "upstream", f.s.Upstream, "batch", prog.Seq, "reason", stop)
	}
}

// interrupted reports why the batch must stop now, if it must.
func (f *follower) interrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !f.e.isLeader() {
		return errNotLeader
	}
	f.mu.Lock()
	loaded := f.loaded
	f.mu.Unlock()
	if !loaded {
		return errNotLeader
	}
	if active, _ := f.e.killSwitch(); active {
		return errLockdown
	}
	now := f.e.now()
	f.refreshControl(now, false)
	if paused, _ := f.paused(); paused {
		return errPaused
	}
	if f.resyncPending() {
		return errResync
	}
	if !f.s.Window.Contains(now) {
		return errOffPeak
	}
	if f.budgetBlocked(ctx) {
		return errBudget
	}
	f.mu.Lock()
	until := f.backoffUntil
	f.mu.Unlock()
	if until.Sub(now) > maxInlineBackoff {
		return errBackingOff
	}
	return nil
}

// isStop reports a reason that stops the batch (as opposed to a failure of
// the item). The engine's own end is judged by its context (stopping): a
// network timeout also wraps context.DeadlineExceeded, and is a failure.
func isStop(err error) bool {
	for _, s := range []error{errNotLeader, errLockdown, errPaused, errResync, errOffPeak, errBudget, errBackingOff, errBatchHalted, errHeld, errRetryLater} {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// stopping reports whether err stops the batch: the engine's context ended,
// or an engine stop.
func stopping(ctx context.Context, err error) bool {
	return ctx.Err() != nil || isStop(err)
}

// safeProcessItem runs processItem in a worker, turning a panic into a failed
// round of the item.
func (f *follower) safeProcessItem(ctx context.Context, fetcher Fetcher, c Coordinate, idx int, halt func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			f.e.log.Error("full mirroring: recovered from a panic", "upstream", f.s.Upstream, "package", c.String(), "panic", r, "stack", string(debug.Stack()))
			err = f.roundFailed(ctx, idx, c, "", fmt.Errorf("internal error: %v", r))
		}
	}()
	return f.processItem(ctx, fetcher, c, idx, halt)
}

// processItem deals with one change. A nil result means the item is done
// (mirrored, excluded, failed for good); an error stops the batch with the
// item still to do.
func (f *follower) processItem(ctx context.Context, fetcher Fetcher, c Coordinate, idx int, halt func() error) error {
	if c.Deleted {
		f.count(func(n *Counters) { n.Deleted++ })
		return nil
	}
	if !f.s.Wants(c.Name) {
		f.count(func(n *Counters) { n.Excluded++ })
		return nil
	}
	rels, err := f.listReleases(ctx, c, halt)
	if err != nil {
		switch {
		case stopping(ctx, err):
			return err
		case IsPermanent(err), errors.Is(err, errVersionGone):
			f.count(func(n *Counters) { n.PackageErrors++ })
			f.recordError(c.String(), "", err)
			return nil
		}
		return f.roundFailed(ctx, idx, c, "", err)
	}
	kept, dropped := selectReleases(rels, c.Version, f.s.Latest, f.scheme)
	// The files dealt with in an earlier round of this item are not dealt
	// with again (a refused file is not asked for twice), and its
	// version-policy skips are counted once.
	done := f.takeDonePaths(idx)
	if !done[""] {
		f.count(func(n *Counters) { n.skip(SkipVersionPolicy, uint64(dropped)) })
		done[""] = true
	}
	for _, r := range kept {
		for _, a := range r.Artifacts {
			if done[a.Path] {
				continue
			}
			if err := halt(); err != nil {
				f.keepDonePaths(idx, done)
				return err
			}
			if err := f.mirrorArtifact(ctx, fetcher, c, a, halt, 0); err != nil {
				if stopping(ctx, err) {
					f.keepDonePaths(idx, done)
					return err
				}
				if rerr := f.roundFailed(ctx, idx, c, a.Path, err); rerr != nil {
					f.keepDonePaths(idx, done)
					return rerr
				}
				// Given up on this file (counted as failed): the package's
				// other files go on.
			}
			done[a.Path] = true
		}
	}
	f.dropDonePaths(idx)
	f.count(func(n *Counters) { n.Packages++ })
	return nil
}

// takeDonePaths returns a copy of the files an item dealt with in earlier
// rounds.
func (f *follower) takeDonePaths(idx int) map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for p := range f.donePaths[idx] {
		out[p] = true
	}
	return out
}

// keepDonePaths remembers the files an unfinished item has dealt with.
func (f *follower) keepDonePaths(idx int, done map[string]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.donePaths == nil {
		f.donePaths = map[int]map[string]bool{}
	}
	f.donePaths[idx] = done
}

func (f *follower) dropDonePaths(idx int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.donePaths, idx)
}

// roundFailed stops the round after an item kept failing: the upstream is
// backed off and the item tried again later — unless it has failed
// MaxRounds rounds, when it is counted as failed and left behind.
func (f *follower) roundFailed(ctx context.Context, idx int, c Coordinate, path string, err error) error {
	f.mu.Lock()
	if f.stuck == nil {
		f.stuck, f.donePaths = map[int]int{}, map[int]map[string]bool{}
	}
	f.stuck[idx]++
	n := f.stuck[idx]
	f.mu.Unlock()
	if n >= f.e.opts.MaxRounds {
		f.count(func(cn *Counters) {
			if path == "" {
				cn.PackageErrors++
			} else {
				cn.Failed++
			}
		})
		f.recordError(c.String(), path, fmt.Errorf("given up after %d rounds: %w", n, err))
		f.e.log.Warn("full mirroring: giving up on a change", "upstream", f.s.Upstream, "package", c.String(), "path", path, "rounds", n, "error", err)
		return nil
	}
	wait := backoff(f.e.opts.RoundBackoff, 30*time.Minute, n)
	if ra, ok := RetryAfterOf(err); ok && ra > wait {
		wait = ra
	}
	f.setUpstreamBackoff(f.e.now().Add(wait))
	f.recordError(c.String(), path, fmt.Errorf("round %d failed, retrying in %s: %w", n, wait.Round(time.Second), err))
	return errRetryLater
}

// listReleases asks the feed for a package's versions, retrying transient
// failures.
func (f *follower) listReleases(ctx context.Context, c Coordinate, halt func() error) ([]Release, error) {
	var last error
	for attempt := 1; attempt <= f.e.opts.MaxAttempts; attempt++ {
		if err := f.waitBackoff(ctx, halt); err != nil {
			return nil, err
		}
		rels, err := f.feed.Releases(ctx, c.Name)
		if err == nil && c.Version != "" && !hasVersion(rels, c.Version) {
			err = fmt.Errorf("%w %s of %s (yet)", errVersionGone, c.Version, c.Name)
		}
		if err == nil {
			return rels, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isStop(err) {
			// The adapter passed an engine stop through; do not count it.
			return nil, err
		}
		if IsPermanent(err) {
			return nil, err
		}
		last = err
		if attempt == f.e.opts.MaxAttempts {
			break
		}
		f.count(func(n *Counters) { n.Retries++ })
		wait := backoff(f.e.opts.BaseBackoff, f.e.opts.MaxBackoff, attempt)
		if ra, ok := RetryAfterOf(err); ok {
			f.setUpstreamBackoff(f.e.now().Add(ra))
			wait = 0
		}
		if err := f.sleep(ctx, wait, halt); err != nil {
			return nil, err
		}
	}
	return nil, last
}

func hasVersion(rels []Release, v string) bool {
	for _, r := range rels {
		if r.Version == v {
			return true
		}
	}
	return false
}

// selectReleases applies the version policy to a change. It returns the
// releases to mirror and the number of files the policy leaves out.
func selectReleases(rels []Release, version string, latest int, scheme versions.Scheme) ([]Release, int) {
	var keep map[string]bool
	if latest > 0 {
		keep = latestVersions(rels, latest, scheme)
	}
	var kept []Release
	dropped := 0
	for _, r := range rels {
		if version != "" && r.Version != version {
			continue
		}
		if keep != nil && !keep[r.Version] {
			dropped += len(r.Artifacts)
			continue
		}
		kept = append(kept, r)
	}
	return kept, dropped
}

// latestVersions picks the n newest versions: by the ecosystem's version
// order when the proxy knows it, else in the order the feed listed them.
// Yanked versions never count; pre-releases count only for a package that
// has no other version.
func latestVersions(rels []Release, n int, scheme versions.Scheme) map[string]bool {
	type cand struct {
		r   Release
		v   versions.Version
		pre bool
		pos int
	}
	var all []cand
	for i, r := range rels {
		if r.Yanked {
			continue
		}
		c := cand{r: r, pos: i}
		if scheme != nil {
			if v, err := scheme.Parse(r.Version); err == nil {
				c.v, c.pre = v, v.Prerelease()
			}
		}
		all = append(all, c)
	}
	stable := all[:0:0]
	for _, c := range all {
		if !c.pre {
			stable = append(stable, c)
		}
	}
	if len(stable) == 0 {
		stable = all
	}
	if scheme != nil {
		sort.SliceStable(stable, func(i, j int) bool {
			a, b := stable[i], stable[j]
			switch {
			case a.v == nil && b.v == nil:
				return a.pos < b.pos
			case a.v == nil:
				return true
			case b.v == nil:
				return false
			}
			return scheme.Compare(a.v, b.v) < 0
		})
	}
	keep := map[string]bool{}
	for i := len(stable) - 1; i >= 0 && len(keep) < n; i-- {
		keep[stable[i].r.Version] = true
	}
	return keep
}

// waitBackoff waits out a short upstream backoff; a long one stops the batch.
func (f *follower) waitBackoff(ctx context.Context, halt func() error) error {
	for {
		f.mu.Lock()
		until := f.backoffUntil
		f.mu.Unlock()
		d := until.Sub(f.e.now())
		if d <= 0 {
			return nil
		}
		if d > maxInlineBackoff {
			return errBackingOff
		}
		if err := f.sleep(ctx, d, halt); err != nil {
			return err
		}
	}
}

// sleep waits d, checking halt every second.
func (f *follower) sleep(ctx context.Context, d time.Duration, halt func() error) error {
	for d > 0 {
		step := d
		if step > time.Second {
			step = time.Second
		}
		t := time.NewTimer(step)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		d -= step
		if err := halt(); err != nil {
			return err
		}
	}
	return nil
}

// fetch outcomes.
type outcome int

const (
	outFetched outcome = iota
	outCached
	outRefused
	outTooLarge
	outNotCacheable
	outRetryable
	outPermanent
)

// classify reads what the gated pipeline did with a fetch.
func classify(res FetchResult, err error) outcome {
	if err != nil {
		if IsPermanent(err) {
			return outPermanent
		}
		return outRetryable
	}
	switch {
	case res.Gate != "":
		return outRefused
	case res.Code == CodeTooLarge || res.Status == http.StatusRequestEntityTooLarge:
		return outTooLarge
	case res.Status >= 200 && res.Status < 300:
		switch {
		case !res.Admitted:
			return outNotCacheable
		case res.Cache == "MISS":
			return outFetched
		}
		return outCached
	case res.Status == http.StatusTooManyRequests, res.Status == http.StatusRequestTimeout, res.Status >= 500:
		return outRetryable
	}
	return outPermanent
}

// statusError describes a fetch that failed.
type statusError struct {
	res FetchResult
}

func (e statusError) Error() string {
	msg := fmt.Sprintf("the proxy answered %d", e.res.Status)
	if e.res.Reason != "" {
		msg += ": " + e.res.Reason
	}
	return msg
}

// refusal kinds.
type refusal int

const (
	// refusalVerdict: the gate judged the file; it is not asked for again.
	refusalVerdict refusal = iota
	// refusalLater: the gate said "not yet" — a Retry-After (a maturity
	// cooldown, a scan still running) or a fail-closed refusal of a gate that
	// could not judge the file: the file is deferred.
	refusalLater
	// refusalHold: the refusal holds for every file of the upstream (the
	// mirror's roles do not grant it; the organization is frozen to a
	// snapshot): no verdict, the mirror waits.
	refusalHold
	// refusalLockdown: an emergency lockdown engaged mid-batch.
	refusalLockdown
)

// classifyRefusal tells a verdict from a refusal that is not one.
func classifyRefusal(res FetchResult) refusal {
	switch res.Gate {
	case "lockdown":
		return refusalLockdown
	case "access-control", "snapshot", "snapshot-freeze":
		return refusalHold
	}
	if res.RetryAfter > 0 || res.Action == "fail-closed" {
		return refusalLater
	}
	return refusalVerdict
}

// mirrorArtifact fetches one file through the gated pipeline unless the cache
// holds it already. A nil result means the file is dealt with (fetched,
// refused, deferred, skipped, failed for good); an error stops the batch
// (stopping) or failed the round. deferrals is how often the file was
// deferred before (0 for a file of a batch).
func (f *follower) mirrorArtifact(ctx context.Context, fetcher Fetcher, c Coordinate, a Artifact, halt func() error, deferrals int) error {
	if !validArtifactPath(a.Path) {
		f.count(func(n *Counters) { n.Failed++ })
		f.recordError(c.String(), cleanMessage(a.Path), errors.New("the feed named an invalid path"))
		return nil
	}
	if max := f.s.MaxArtifactBytes; max > 0 && a.Size > max {
		f.count(func(n *Counters) { n.skip(SkipTooLarge, 1) })
		return nil
	}
	req := FetchRequest{Upstream: f.s.Upstream, Path: a.Path, Accept: a.Accept}
	lk, err := fetcher.Lookup(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.count(func(n *Counters) { n.Failed++ })
		f.recordError(c.String(), a.Path, fmt.Errorf("resolving the path: %w", err))
		return nil
	}
	switch {
	case !lk.Cacheable:
		f.count(func(n *Counters) { n.skip(SkipNotCacheable, 1) })
		return nil
	case lk.Cached:
		f.count(func(n *Counters) { n.skip(SkipCached, 1) })
		return nil
	case f.s.DryRun:
		f.count(func(n *Counters) { n.skip(SkipDryRun, 1) })
		return nil
	}
	for attempt := 1; ; attempt++ {
		if err := f.waitBackoff(ctx, halt); err != nil {
			return err
		}
		limit, fromBudget, contended, err := f.reserveFor(ctx, a.Size, halt)
		if err != nil {
			return err
		}
		req.MaxBytes = limit
		res, ferr := f.fetchOnce(ctx, fetcher, req)
		f.unreserve(a.Size)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch classify(res, ferr) {
		case outFetched:
			f.mu.Lock()
			f.st.Counters.Fetched++
			if res.Size > 0 {
				f.st.Counters.FetchedBytes += uint64(res.Size)
				f.st.BudgetUsed += res.Size
			}
			spent := f.st.BudgetUsed >= f.s.ByteBudget
			f.dirty = true
			f.mu.Unlock()
			if spent {
				f.exhaustBudget(ctx)
			}
			return nil
		case outCached:
			f.count(func(n *Counters) { n.skip(SkipCached, 1) })
			return nil
		case outRefused:
			switch classifyRefusal(res) {
			case refusalLockdown:
				// A lockdown engaged while the batch ran: no verdict on the
				// file. The batch stops and resumes once it is lifted.
				return errLockdown
			case refusalHold:
				return f.hold(c, a, res)
			case refusalLater:
				f.deferFile(c, a, res, deferrals)
				return nil
			}
			f.count(func(n *Counters) { n.refuse(res.Gate) })
			f.e.log.Info("full mirroring: an admission gate refused a file", "upstream", f.s.Upstream, "package", c.String(), "path", a.Path, "gate", res.Gate, "code", res.Code)
			return nil
		case outTooLarge:
			if !fromBudget {
				f.count(func(n *Counters) { n.skip(SkipTooLarge, 1) })
				return nil
			}
			if contended {
				// It may fit once the other fetches in flight are done.
				if err := f.waitReservations(ctx, halt); err != nil {
					return err
				}
				attempt--
				continue
			}
			f.exhaustBudget(ctx)
			return errBudget
		case outNotCacheable:
			f.count(func(n *Counters) { n.skip(SkipNotCacheable, 1) })
			return nil
		case outPermanent:
			if ferr == nil {
				ferr = statusError{res: res}
			}
			f.count(func(n *Counters) { n.Failed++ })
			f.recordError(c.String(), a.Path, ferr)
			return nil
		}
		// Retryable.
		err = ferr
		if err == nil {
			err = statusError{res: res}
		}
		wait := backoff(f.e.opts.BaseBackoff, f.e.opts.MaxBackoff, attempt)
		var thr errThrottled
		switch {
		case res.RetryAfter > 0:
			// The upstream (or the proxy) asked for a wait: every request to
			// the upstream honours it (waitBackoff, at the top of the loop).
			f.setUpstreamBackoff(f.e.now().Add(res.RetryAfter))
			err = RetryAfter(err, res.RetryAfter)
			wait = 0
		case errors.As(err, &thr) && thr.after > 0:
			// The pacing or the proxy's rate limiter: this request waits.
			err = RetryAfter(err, thr.after)
			wait = thr.after
		}
		if attempt >= f.e.opts.MaxAttempts {
			return fmt.Errorf("after %d attempts: %w", attempt, err)
		}
		f.count(func(n *Counters) { n.Retries++ })
		if err := f.sleep(ctx, wait, halt); err != nil {
			return err
		}
	}
}

// hold answers a refusal that would hold for every file of the upstream: the
// batch stops, the reason is recorded, and the upstream is left alone for a
// while — an operator has something to fix.
func (f *follower) hold(c Coordinate, a Artifact, res FetchResult) error {
	wait := holdWait
	if res.RetryAfter > wait {
		wait = res.RetryAfter
	}
	f.setUpstreamBackoff(f.e.now().Add(wait))
	reason := res.Reason
	if reason == "" {
		reason = "refused"
	}
	f.recordError(c.String(), a.Path, fmt.Errorf("the %s gate refuses the mirror's fetches (%s): %s; every file of this upstream would be refused, so the mirror waits %s", res.Gate, firstNonEmpty(res.Code, "no code"), reason, wait))
	f.e.log.Warn("full mirroring: held by a gate", "upstream", f.s.Upstream, "gate", res.Gate, "code", res.Code, "reason", res.Reason, "retryIn", wait)
	return errHeld
}

// deferFile queues a file a gate said "not yet" to, to be asked for again
// when the gate said it may pass (its Retry-After), or after deferUnjudged.
func (f *follower) deferFile(c Coordinate, a Artifact, res FetchResult, deferrals int) {
	now := f.e.now()
	if deferrals >= maxDeferrals {
		// The gate keeps saying "not yet": take it as its verdict.
		f.count(func(n *Counters) { n.refuse(res.Gate) })
		f.recordError(c.String(), a.Path, fmt.Errorf("still refused by the %s gate after %d deferrals; counted as refused", res.Gate, deferrals))
		return
	}
	delay := res.RetryAfter
	if delay <= 0 {
		delay = deferUnjudged
	}
	if delay < minDeferral {
		delay = minDeferral
	}
	item := &deferredItem{
		Package: c.Name, Version: c.Version, Path: a.Path, Accept: a.Accept, Size: a.Size,
		Gate: res.Gate, Code: res.Code, NotBefore: now.Add(delay).UTC(), Since: now.UTC(), Deferrals: deferrals + 1,
	}
	f.mu.Lock()
	if f.deferred == nil {
		f.deferred = map[string]*deferredItem{}
	}
	if old, ok := f.deferred[a.Path]; ok {
		item.Since = old.Since
	} else if len(f.deferred) >= maxDeferred {
		f.st.Counters.skip(SkipDeferralOverflow, 1)
		f.dirty = true
		f.mu.Unlock()
		f.recordError(c.String(), a.Path, fmt.Errorf("the %s gate said not yet, but the deferred queue holds %d files already", res.Gate, maxDeferred))
		return
	}
	f.deferred[a.Path] = item
	f.deferredGen++
	f.st.Counters.Deferred++
	f.dirty = true
	f.mu.Unlock()
	f.e.log.Debug("full mirroring: a file deferred", "upstream", f.s.Upstream, "package", c.String(), "path", a.Path, "gate", res.Gate, "until", item.NotBefore)
}

// processDeferred asks again for the deferred files that are due. An error
// stops the step: an engine stop, or an upstream that keeps failing (the
// files stay queued).
func (f *follower) processDeferred(ctx context.Context, fetcher Fetcher) error {
	now := f.e.now()
	f.mu.Lock()
	var due []*deferredItem
	for _, it := range f.deferred {
		if !it.NotBefore.After(now) {
			due = append(due, it)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].NotBefore.Equal(due[j].NotBefore) {
			return due[i].NotBefore.Before(due[j].NotBefore)
		}
		return due[i].Path < due[j].Path
	})
	if len(due) > maxDuePerStep {
		due = due[:maxDuePerStep]
	}
	f.mu.Unlock()
	if len(due) == 0 {
		return nil
	}
	f.setActivity(f.phaseActivity(), fmt.Sprintf("asking again for %d deferred file(s)", len(due)))
	halt := func() error { return f.interrupted(ctx) }
	for _, it := range due {
		if err := halt(); err != nil {
			return err
		}
		f.mu.Lock()
		cur, ok := f.deferred[it.Path]
		if ok && cur == it {
			delete(f.deferred, it.Path)
			f.deferredGen++
			f.dirty = true
		}
		f.mu.Unlock()
		if !ok || cur != it {
			continue
		}
		c := Coordinate{Name: it.Package, Version: it.Version}
		err := f.mirrorArtifact(ctx, fetcher, c, Artifact{Path: it.Path, Accept: it.Accept, Size: it.Size}, halt, it.Deferrals)
		if err == nil {
			continue
		}
		// Not dealt with: back into the queue, as it was.
		f.mu.Lock()
		if _, again := f.deferred[it.Path]; !again {
			if stopping(ctx, err) {
				f.deferred[it.Path] = it
			} else {
				retry := *it
				retry.NotBefore = f.e.now().Add(f.e.opts.RoundBackoff).UTC()
				f.deferred[it.Path] = &retry
			}
			f.deferredGen++
			f.dirty = true
		}
		f.mu.Unlock()
		if stopping(ctx, err) {
			return err
		}
		f.recordError(c.String(), it.Path, fmt.Errorf("asking again for a deferred file: %w", err))
		f.setUpstreamBackoff(f.e.now().Add(f.e.opts.RoundBackoff))
		return errRetryLater
	}
	_ = f.persist(false)
	return nil
}

// fetchOnce admits a fetch under the upstream's pacing and the proxy's rate
// limiter, then runs it.
func (f *follower) fetchOnce(ctx context.Context, fetcher Fetcher, req FetchRequest) (FetchResult, error) {
	if err := f.e.paceAdmit(ctx, f.s.Upstream); err != nil {
		return FetchResult{}, err
	}
	if lim := f.e.admitter(); lim != nil {
		res, dec := lim.Admit(ctx, f.e.opts.Tenant)
		defer res.Release()
		if !dec.Allowed {
			if err := ctx.Err(); err != nil {
				return FetchResult{}, err
			}
			after := dec.RetryAfter
			if after <= 0 {
				after = time.Second
			}
			return FetchResult{}, errThrottled{after: after}
		}
	}
	f.mu.Lock()
	f.inFlight++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	return fetcher.Fetch(ctx, req, io.Discard)
}

// reserve sets aside the budget a fetch may spend. A stated size must fit in
// what is left; a file of unknown size is cut off at what is left (or at
// maxArtifactBytes when that is smaller), and fromBudget reports that the
// cut-off is the budget's. contended reports that other fetches in flight
// hold a part of what is left: when ok is false because of them, the file may
// fit once they are done — the budget is not spent.
func (f *follower) reserve(size int64) (limit int64, fromBudget, contended, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	free := f.s.ByteBudget - f.st.BudgetUsed
	remaining := free - f.reserved
	contended = f.reserved > 0
	switch {
	case size > 0 && size > free, size <= 0 && free <= 0:
		return 0, false, false, false
	case size > 0 && size > remaining, size <= 0 && remaining <= 0:
		return 0, false, true, false
	}
	if size > 0 {
		f.reserved += size
	}
	limit = f.s.MaxArtifactBytes
	if limit == 0 || remaining < limit {
		limit, fromBudget = remaining, true
	}
	return limit, fromBudget, contended, true
}

// reserveFor reserves the budget for a fetch, waiting while other fetches in
// flight hold what it needs. A budget that is spent is marked so (errBudget).
func (f *follower) reserveFor(ctx context.Context, size int64, halt func() error) (int64, bool, bool, error) {
	for {
		limit, fromBudget, contended, ok := f.reserve(size)
		if ok {
			return limit, fromBudget, contended, nil
		}
		if !contended {
			f.exhaustBudget(ctx)
			return 0, false, false, errBudget
		}
		if err := f.sleep(ctx, 50*time.Millisecond, halt); err != nil {
			return 0, false, false, err
		}
	}
}

// waitReservations waits until no fetch in flight holds budget.
func (f *follower) waitReservations(ctx context.Context, halt func() error) error {
	for {
		f.mu.Lock()
		held := f.reserved
		f.mu.Unlock()
		if held <= 0 {
			return nil
		}
		if err := f.sleep(ctx, 50*time.Millisecond, halt); err != nil {
			return err
		}
	}
}

func (f *follower) unreserve(size int64) {
	if size <= 0 {
		return
	}
	f.mu.Lock()
	f.reserved -= size
	f.mu.Unlock()
}
