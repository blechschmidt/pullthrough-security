package fullscan

// Regression tests for defects an independent review of the full scan found
// (Task 192): each scenario failed on the first version of the package.

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// R1: a Resume received by a replica that does not lead never unparks the
// leader's parked items: they stay pending in no heap, and nothing (not even
// a sweep) puts them back.
func TestRegressResumeOnFollowerLeavesParkedItemsStuck(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put("npm:a", "npm", "/a/-/a-1.0.0.tgz", "", tarball("a", false), time.Now())
	fc.put("private:b", "private", "/b/-/b-1.0.0.tgz", "", tarball("b", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}

	leader, err := New(testOptions(dir, "npm", "private"))
	if err != nil {
		t.Fatal(err)
	}
	if err := leader.Pause(ctx, "private", "op", "embargo"); err != nil {
		t.Fatal(err)
	}
	leader.Attach(gs, fc)
	leader.Start(ctx)
	t.Cleanup(func() { _ = leader.Close() })
	waitFor(t, "npm scanned and private parked", func() bool {
		return upstreamStatus(t, leader, "npm").Scanned == 1 && leader.Status().Queue.Parked == 1
	})

	// The operator's Resume lands on the other replica (the admin API of any
	// replica writes control.json).
	follower, err := New(testOptions(dir, "npm", "private"))
	if err != nil {
		t.Fatal(err)
	}
	follower.SetLeaderGate(func() bool { return false })
	if err := follower.Resume(ctx, "private", "op"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the leader to see the resume", func() bool {
		for _, u := range leader.Status().Upstreams {
			if u.Upstream == "private" {
				return !u.Paused
			}
		}
		return false
	})
	// Even a sweep does not put the parked item back.
	if err := leader.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	p := upstreamStatus(t, leader, "private")
	t.Logf("private after resume on the follower: scanned=%d pending=%d paused=%v parked=%d calls=%d",
		p.Scanned, p.Pending, p.Paused, leader.Status().Queue.Parked, provider.Calls())
	if p.Scanned == 0 && p.Pending == 1 {
		t.Errorf("the resumed upstream's artifact is stuck parked (pending, in no heap) on the leader")
	}
}

// R1b: the same on one replica: a Resume that runs between the loop's
// refreshControl and its pop leaves the item parked for good.
func TestRegressResumeRacingAStepLeavesParkedItemsStuck(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put("private:b", "private", "/b/-/b-1.0.0.tgz", "", tarball("b", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	s, err := New(testOptions(dir, "private"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(ctx, "private", "op", ""); err != nil {
		t.Fatal(err)
	}
	s.Attach(gs, fc)
	if err := s.ensureLoaded(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	// One step, interleaved: the step read the control file (paused) ...
	ctl := s.refreshControl(true)
	// ... the operator resumes (nothing is parked yet, so nothing to unpark) ...
	if err := s.Resume(ctx, "private", "op"); err != nil {
		t.Fatal(err)
	}
	// ... and the step's work pops with the control it read: the item is parked.
	s.work(ctx, ctl)
	s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })
	time.Sleep(500 * time.Millisecond)
	p := upstreamStatus(t, s, "private")
	t.Logf("scanned=%d pending=%d parked=%d calls=%d", p.Scanned, p.Pending, s.Status().Queue.Parked, provider.Calls())
	if p.Scanned == 0 {
		t.Errorf("the artifact stays parked after the resume")
	}
}

// blockingInv lists the cache at once but returns the listing only when
// released (from the second call on): a large cache's listing takes a while.
type blockingInv struct {
	fc      *fakeCache
	calls   atomic.Int32
	listed  chan struct{}
	release chan struct{}
}

func (b *blockingInv) Entries(ctx context.Context) ([]cache.Stat, error) {
	list, err := b.fc.Entries(ctx)
	if b.calls.Add(1) >= 2 {
		close(b.listed)
		<-b.release
	}
	return list, err
}

// R2: the sweep drops every item a note added while the cache was being
// listed: a mirror-fetched artifact without a verdict leaves the queue and
// is counted as gone.
func TestRegressSweepDropsItemsNotedDuringTheListing(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	fc.put(objectKey("old"), "npm", objectPath("old"), "", tarball("old", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	inv := &blockingInv{fc: fc, listed: make(chan struct{}), release: make(chan struct{})}
	s := startService(t, testOptions(t.TempDir()), gs, inv)
	waitFor(t, "old scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 1 })
	waitFor(t, "first sweep done", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.sweeping
	})
	// Hold the queue so the new artifact stays queued.
	if err := s.Pause(ctx, "", "op", "hold"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Sweep(ctx); close(done) }()
	<-inv.listed
	// Meanwhile the full mirror fetches a new file; the gate is busy.
	fc.put(objectKey("new"), "npm", objectPath("new"), "", tarball("new", false), time.Now())
	s.Note(Note{Source: SourceMirror, Artifact: Artifact{Upstream: "npm", Path: objectPath("new"), Key: objectKey("new")},
		Reading: &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeBusy, Retryable: true}})
	waitFor(t, "the mirror's note to be queued", func() bool { return s.Status().Queue.Mirror == 1 })
	close(inv.release)
	<-done
	u := upstreamStatus(t, s, "npm")
	s.mu.Lock()
	_, tracked := s.items[objectKey("new")]
	s.mu.Unlock()
	t.Logf("after the sweep: tracked=%v queue=%+v pending=%d gone=%d", tracked, s.Status().Queue, u.Pending, u.Counters.Gone)
	if !tracked {
		t.Errorf("the sweep removed an artifact noted during its listing (counted gone=%d); it is cached and unscanned", u.Counters.Gone)
	}
}

// R3: a client's pull answered from the verdict cache cancels an operator's
// pending re-scan: the item settles without the fresh model call.
func TestRegressClientCachedVerdictCancelsOperatorRescan(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	fc.put(objectKey("p"), "npm", objectPath("p"), "", tarball("p", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	s := startService(t, testOptions(t.TempDir()), gs, fc)
	waitFor(t, "p scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 1 })
	if err := s.Pause(ctx, "", "op", "hold"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rescan(ctx, RescanRequest{Upstream: "npm", Path: objectPath("p"), By: "op"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the re-scan to be queued", func() bool { return s.Status().Queue.Client == 1 })
	// A client pulls p; the gate answers from its verdict cache.
	s.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("p"), Key: objectKey("p")},
		Reading: &Reading{Kind: ReadingVerdict, Disposition: "benign", Fresh: false, Signature: gs.Signature()}})
	waitFor(t, "the note", func() bool { return upstreamStatus(t, s, "npm").Counters.ClientPulls == 1 })
	if err := s.Resume(ctx, "", "op"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	t.Logf("model calls=%d queue=%+v", provider.Calls(), s.Status().Queue)
	if provider.Calls() == 1 {
		t.Errorf("the operator's re-scan never made its model call (a cached verdict from a client pull settled it)")
	}
}

// concScanner counts concurrent scans per key.
type concScanner struct {
	*gateScanner
	cur, max atomic.Int32
	mu       sync.Mutex
	perKey   map[string]int
	maxKey   int
}

func (c *concScanner) Scan(ctx context.Context, a Artifact, opts ScanOptions) (Reading, error) {
	n := c.cur.Add(1)
	for {
		m := c.max.Load()
		if n <= m || c.max.CompareAndSwap(m, n) {
			break
		}
	}
	c.mu.Lock()
	c.perKey[a.Key]++
	if c.perKey[a.Key] > c.maxKey {
		c.maxKey = c.perKey[a.Key]
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.perKey[a.Key]--
		c.mu.Unlock()
		c.cur.Add(-1)
	}()
	return c.gateScanner.Scan(ctx, a, opts)
}

// R4: losing and regaining the lead while a scan is in flight resets the
// running count to 0; the stale scan then drives it negative, the same item
// is scanned twice at once, and the concurrency limit is exceeded.
func TestRegressRelead(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	base := time.Now().Add(-time.Hour)
	for i, n := range []string{"a", "b", "c"} {
		fc.put(objectKey(n), "npm", objectPath(n), "", tarball(n, false), base.Add(time.Duration(i)*time.Minute))
	}
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc, gate: make(chan struct{})}
	cs := &concScanner{gateScanner: gs, perKey: map[string]int{}}
	var lead atomic.Bool
	lead.Store(true)
	s, err := New(testOptions(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s.SetLeaderGate(lead.Load)
	s.Attach(cs, fc)
	s.Start(ctx)
	t.Cleanup(func() { close(gs.gate); _ = s.Close() })
	waitFor(t, "a in flight", func() bool { return len(gs.started()) == 1 })
	lead.Store(false)
	s.kick()
	waitFor(t, "standby", func() bool { return !isLoaded(s) })
	lead.Store(true)
	s.kick()
	waitFor(t, "the second scan of a", func() bool { return len(gs.started()) == 2 })
	gs.gate <- struct{}{} // one of the two finishes
	waitFor(t, "a third scan", func() bool { return len(gs.started()) == 3 })
	t.Logf("in flight after one finished: started %v, max concurrent %d", gs.started(), cs.max.Load())
	// Release whatever is held until everything is scanned.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && upstreamStatus(t, s, "npm").Scanned < 3 {
		select {
		case gs.gate <- struct{}{}:
		case <-time.After(50 * time.Millisecond):
		}
	}
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	st := s.Status()
	t.Logf("scans started %v; max concurrent %d (limit 1); same key at once %d; running=%d inFlight=%d; spent total %.0f, model calls %d",
		gs.started(), cs.max.Load(), cs.maxKey, running, st.Queue.InFlight, st.Budget.TotalSpentUSD, provider.Calls())
	if running != 0 || cs.max.Load() > 1 || cs.maxKey > 1 {
		t.Errorf("running=%d (want 0), max concurrent=%d (limit 1), same item twice at once=%v", running, cs.max.Load(), cs.maxKey > 1)
	}
}

// R5: a failed write of the compacted snapshot leaves the state naming the
// old snapshot and journal, retries the write, and loses nothing at restart.
func TestRegressCompactionFailureLosesTheInventory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("a"), "npm", objectPath("a"), "", tarball("a", false), time.Now())
	fc.put(objectKey("b"), "npm", objectPath("b"), "", tarball("b", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	s, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	s.Attach(gs, fc)
	if err := s.ensureLoaded(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	// Two items tracked. The journal is long: compaction is due; the
	// snapshot write fails (here: an item that cannot be encoded stands in
	// for ENOSPC / EIO).
	s.mu.Lock()
	s.items["npm:zz-bad"] = &Item{Key: "npm:zz-bad", Upstream: "npm", Path: "/zz", State: StatePending,
		Cached: time.Date(10001, 1, 1, 0, 0, 0, 0, time.UTC), hq: -1, hi: -1}
	s.jr.records = maxJournalRecords + 1
	s.dirty = true
	s.mu.Unlock()
	// The snapshot cannot be written: the state still names the old pair,
	// which exists, and the compaction stays pending.
	if err := s.persist(true); err != nil {
		t.Fatal(err)
	}
	st, err := store_(dir).loadState()
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Stat(filepath.Join(dir, st.Snapshot)); serr != nil {
		t.Fatalf("after the failed compaction state.json names a snapshot that does not exist: %v", serr)
	}
	s.mu.Lock()
	pending := s.pendingSnap
	delete(s.items, "npm:zz-bad")
	s.mu.Unlock()
	if pending == "" || pending == st.Snapshot {
		t.Fatalf("the failed compaction is not pending (pending %q, state names %q)", pending, st.Snapshot)
	}
	// The next write completes it.
	if err := s.persist(true); err != nil {
		t.Fatal(err)
	}
	st, err = store_(dir).loadState()
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Stat(filepath.Join(dir, st.Snapshot)); serr != nil || st.Snapshot != pending {
		t.Fatalf("the retried compaction: state names %q (want %q), stat %v", st.Snapshot, pending, serr)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	rec := &recAudit{}
	s2.opts.Audit = rec
	s2.Attach(gs, nil)
	if err := s2.ensureLoaded(ctx); err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	n := len(s2.items)
	s2.mu.Unlock()
	t.Logf("after the restart: %d items (2 before), audit %v", n, rec.actions())
	if n != 2 {
		t.Errorf("the inventory was lost after a failed compaction (%d items)", n)
	}
	_ = s2.Close()
}

// R6: an unreadable control.json at start-up (nothing read before) does not
// keep an operator's pause: the scan runs.
func TestRegressUnreadableControlAtStartUnpauses(t *testing.T) {
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("a"), "npm", objectPath("a"), "", tarball("a", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	if err := os.WriteFile(filepath.Join(dir, "control.json"), []byte(`{"paused": true, "pausedBy": "op", "reason": "do not send private code to the provider"`), 0o640); err != nil {
		t.Fatal(err)
	}
	s := startService(t, testOptions(dir), gs, fc)
	time.Sleep(500 * time.Millisecond)
	t.Logf("model calls=%d state=%s", provider.Calls(), s.Status().State)
	if provider.Calls() > 0 {
		t.Errorf("the pause in an unreadable control.json was ignored at start-up (%d model calls)", provider.Calls())
	}
}

// R7: an item re-pushed while parked is parked twice: the status counts it
// twice.
func TestRegressParkedCountedTwice(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	fc.put("private:b", "private", "/b/-/b-1.0.0.tgz", "", tarball("b", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	s, err := New(testOptions(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(ctx, "private", "op", ""); err != nil {
		t.Fatal(err)
	}
	s.Attach(gs, fc)
	s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })
	waitFor(t, "parked", func() bool { return s.Status().Queue.Parked == 1 })
	s.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "private", Path: "/b/-/b-1.0.0.tgz", Key: "private:b"},
		Reading: &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeBusy, Retryable: true}})
	time.Sleep(300 * time.Millisecond)
	q := s.Status().Queue
	t.Logf("queue %+v (1 item)", q)
	if q.Parked != 1 {
		t.Errorf("one parked item counted %d times", q.Parked)
	}
}

// R8: an operator's re-scan of an artifact whose scan is running is not
// journalled (applyRescans sets Refresh/again in memory only); a restart
// before that scan is recorded loses the re-scan, though the request is
// marked handled.
func TestRegressRescanOfBusyItemLostOnRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("a"), "npm", objectPath("a"), "", tarball("a", false), time.Now())
	store := llmpkgscan.NewMemoryStore(0)
	p1 := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", store, p1, llmpkgscan.ActionBlock), cache: fc}
	// The bytes already have a verdict (a client pulled them earlier).
	if _, err := gs.Scan(ctx, Artifact{Upstream: "npm", Path: objectPath("a"), Key: objectKey("a")}, ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	gs.mu.Lock()
	gs.order, gs.gate = nil, make(chan struct{})
	gs.mu.Unlock()
	s1, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	s1.Attach(gs, fc)
	s1.Start(ctx)
	waitFor(t, "a's scan to be running", func() bool { return len(gs.started()) == 1 })
	if _, err := s1.Rescan(ctx, RescanRequest{Upstream: "npm", Filter: "all", By: "op"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the re-scan to be handled", func() bool {
		s1.mu.Lock()
		defer s1.mu.Unlock()
		return s1.st.RescanHandled == 1
	})
	if err := s1.Close(); err != nil { // e.g. an upgrade restarts the replica
		t.Fatal(err)
	}
	p2 := &pkgscantest.Provider{}
	gs2 := &gateScanner{svc: newGate(t, "mock-model", store, p2, llmpkgscan.ActionBlock), cache: fc}
	s2 := startService(t, testOptions(dir), gs2, fc)
	waitFor(t, "a scanned", func() bool { return upstreamStatus(t, s2, "npm").Scanned == 1 })
	time.Sleep(100 * time.Millisecond)
	t.Logf("model calls after the restart: %d; rescans counter %v", p2.Calls(), upstreamStatus(t, s2, "npm").Counters.Rescans)
	if p2.Calls() == 0 {
		t.Errorf("the operator's re-scan was lost across the restart (no fresh model call)")
	}
}

// R9: a replica whose write was fenced stays in standby while its lease
// predicate still says it leads: two replicas that both think they lead do
// not take the state from each other in turn.
func TestRegressFencedReplicaRetakesAtOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("a"), "npm", objectPath("a"), "", tarball("a", false), time.Now())
	var bufs [2]*lockedBuf
	mk := func(i int) *Service {
		bufs[i] = &lockedBuf{}
		o := testOptions(dir)
		o.Logger = slog.New(slog.NewTextHandler(bufs[i], nil))
		s, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		s.Attach(&gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}, fc)
		s.Start(ctx)
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	first := mk(0)
	waitFor(t, "first scanned", func() bool { return upstreamStatus(t, first, "npm").Scanned == 1 })
	second := mk(1)
	// Each replica's loop wakes now and then (a client note, a finished scan).
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		for _, s := range []*Service{first, second} {
			s.mu.Lock()
			s.dirty = true // something changed (a note, a finished scan)
			s.mu.Unlock()
			s.kick()
		}
	}
	firstN, secondN := strings.Count(bufs[0].String(), "full scan: leading"), strings.Count(bufs[1].String(), "full scan: leading")
	if firstN > 1 || secondN > 1 {
		t.Errorf("the replicas took the state from each other in turn: first led %d times, second %d times", firstN, secondN)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
