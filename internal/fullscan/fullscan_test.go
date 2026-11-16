package fullscan

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// The queue serves what clients pulled first, then what the mirror fetched,
// then the backfill (oldest cached first).
func TestQueueServesClientsThenMirrorThenBackfill(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	base := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	fc.put(objectKey("b-new"), "npm", objectPath("b-new"), "", tarball("b-new", false), base.Add(2*time.Hour))
	fc.put(objectKey("b-old"), "npm", objectPath("b-old"), "", tarball("b-old", false), base)
	fc.put(objectKey("b-mid"), "npm", objectPath("b-mid"), "", tarball("b-mid", false), base.Add(time.Hour))
	fc.put(objectKey("mirrored"), "npm", objectPath("mirrored"), "", tarball("mirrored", false), base.Add(3*time.Hour))
	fc.put(objectKey("pulled"), "npm", objectPath("pulled"), "team-a", tarball("pulled", false), base.Add(4*time.Hour))
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}

	s, err := New(testOptions(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	// Paused before it starts: the sweep fills the queue, nothing is scanned.
	if err := s.Pause(ctx, "", "op", "ordering test"); err != nil {
		t.Fatal(err)
	}
	s.Attach(gs, fc)
	s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })
	waitFor(t, "the backfill to be queued", func() bool { return s.Status().Queue.Backfill == 5 })

	busy := &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeBusy, Retryable: true}
	s.Note(Note{Source: SourceMirror, Artifact: Artifact{Upstream: "npm", Path: objectPath("mirrored"), Key: objectKey("mirrored")}, Reading: busy})
	s.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("pulled"), Key: objectKey("pulled"), Tenant: "team-a"}, Reading: busy})
	waitFor(t, "the notes to move their artifacts up", func() bool {
		q := s.Status().Queue
		return q.Client == 1 && q.Mirror == 1 && q.Backfill == 3
	})
	if n := provider.Calls(); n != 0 {
		t.Fatalf("%d scans ran while the full scan was paused", n)
	}
	if err := s.Resume(ctx, "", "op"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "every artifact to be scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 5 })
	want := []string{objectKey("pulled"), objectKey("mirrored"), objectKey("b-old"), objectKey("b-mid"), objectKey("b-new")}
	if got := gs.started(); !reflect.DeepEqual(got, want) {
		t.Fatalf("scan order\n got %v\nwant %v", got, want)
	}
	u := upstreamStatus(t, s, "npm")
	if u.Benign != 5 || u.Pending != 0 || u.Counters.Scans != 5 || u.Counters.ClientPulls != 1 || u.Counters.Mirrored != 1 {
		t.Fatalf("status %+v", u)
	}
	// The client's artifact was scanned as the tenant whose pull filled it.
	if v := gs.svc.ForCoordinate("team-a", "npm", "pulled", ""); len(v) != 1 {
		t.Fatalf("team-a sees %d verdicts on its own package, want 1", len(v))
	}
	if v := gs.svc.ForCoordinate("team-b", "npm", "pulled", ""); len(v) != 0 {
		t.Fatalf("team-b sees %d verdicts on team-a's package", len(v))
	}
}

// A spent daily ceiling pauses the queue until the day rolls over; the
// exhaustion is announced once.
func TestBudgetExhaustionPausesTheQueueUntilTheNextDay(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 16, 23, 0, 0, 0, time.UTC)}
	fc := newFakeCache()
	for i, name := range []string{"a", "b", "c", "d", "e"} {
		fc.put(objectKey(name), "npm", objectPath(name), "", tarball(name, false), clk.now().Add(time.Duration(i)*time.Minute))
	}
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	rec := &recAudit{}
	var announced []string
	opts := testOptions(t.TempDir())
	opts.DailyUSD, opts.MonthlyUSD, opts.Now, opts.Audit = 2.5, 100, clk.now, rec
	opts.OnBudgetExhausted = func(window string, spent, ceiling float64) { announced = append(announced, window) }
	s := startService(t, opts, gs, fc)

	waitFor(t, "the budget to run out", func() bool { return s.Status().State == StateBudgetExhausted })
	time.Sleep(50 * time.Millisecond)
	st := s.Status()
	u := upstreamStatus(t, s, "npm")
	// Soft by the scans in flight: the third scan started with $2 spent.
	if provider.Calls() != 3 || u.Scanned != 3 || u.Pending != 2 {
		t.Fatalf("%d model calls, status %+v", provider.Calls(), u.Figures)
	}
	if b := st.Budget; !b.Exhausted || !b.Daily.Exhausted || b.Daily.SpentUSD != 3 || b.Daily.CeilingUSD != 2.5 || b.Monthly.Exhausted {
		t.Fatalf("budget %+v", b)
	}
	if u.SpentUSD != 3 {
		t.Fatalf("upstream spend %v", u.SpentUSD)
	}
	if strings.Count(strings.Join(rec.actions(), ","), "budget-exhausted") != 1 || !reflect.DeepEqual(announced, []string{WindowDay}) {
		t.Fatalf("announcements: audit %v, callback %v", rec.actions(), announced)
	}

	// The next day the queue resumes, and its spend starts over.
	clk.add(2 * time.Hour)
	s.kick()
	waitFor(t, "the queue to resume", func() bool { return upstreamStatus(t, s, "npm").Scanned == 5 })
	b := s.Status().Budget
	if b.Exhausted || b.Daily.SpentUSD != 2 || b.Monthly.SpentUSD != 5 || b.TotalSpentUSD != 5 {
		t.Fatalf("budget after the day rolled over %+v", b)
	}
}

// What is queued — and in which class — and what was scanned survive a
// restart: the queue resumes where it stopped, and nothing is scanned twice.
func TestQueueAndVerdictsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	base := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	for i, name := range []string{"one", "two", "three", "four"} {
		fc.put(objectKey(name), "npm", objectPath(name), "", tarball(name, false), base.Add(time.Duration(i)*time.Hour))
	}
	store := llmpkgscan.NewMemoryStore(0)
	p1 := &pkgscantest.Provider{}
	gs1 := &gateScanner{svc: newGate(t, "mock-model", store, p1, llmpkgscan.ActionBlock), cache: fc, gate: make(chan struct{})}
	s1, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	s1.Attach(gs1, fc)
	s1.Start(ctx)
	gs1.gate <- struct{}{}
	gs1.gate <- struct{}{}
	waitFor(t, "two scans", func() bool { return upstreamStatus(t, s1, "npm").Scanned == 2 })
	// The third scan is running (held at the gate); a client asks for "four".
	s1.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("four"), Key: objectKey("four")},
		Reading: &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeTimeout, Retryable: true}})
	waitFor(t, "the client's note", func() bool { return s1.Status().Queue.Client == 1 })
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	p2 := &pkgscantest.Provider{}
	gs2 := &gateScanner{svc: newGate(t, "mock-model", store, p2, llmpkgscan.ActionBlock), cache: fc}
	s2, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Pause(ctx, "", "op", "look first"); err != nil {
		t.Fatal(err)
	}
	s2.Attach(gs2, fc)
	s2.Start(ctx)
	t.Cleanup(func() { _ = s2.Close() })
	waitFor(t, "the state to be read back", func() bool {
		q := s2.Status().Queue
		return q.Client == 1 && q.Backfill == 1
	})
	if err := s2.Resume(ctx, "", "op"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the rest to be scanned", func() bool { return upstreamStatus(t, s2, "npm").Scanned == 4 })
	if got, want := gs2.started(), []string{objectKey("four"), objectKey("three")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after the restart the scans were %v, want %v", got, want)
	}
	if p2.Calls() != 2 {
		t.Fatalf("%d model calls after the restart, want 2 (the two scanned before are not scanned again)", p2.Calls())
	}
	if c := upstreamStatus(t, s2, "npm").Counters; c.Scans != 4 || c.ClientPulls != 1 {
		t.Fatalf("counters across the restart %+v", c)
	}
}

// A new model makes every verdict stale: the artifacts go back into the queue
// and are scanned again; the same model again changes nothing.
func TestANewModelPutsEveryArtifactBackIntoTheQueue(t *testing.T) {
	dir := t.TempDir()
	fc := newFakeCache()
	for _, name := range []string{"x", "y", "z"} {
		fc.put(objectKey(name), "npm", objectPath(name), "", tarball(name, false), time.Now())
	}
	store := llmpkgscan.NewMemoryStore(0)
	run := func(model string) (*pkgscantest.Provider, *Service, *recAudit) {
		p := &pkgscantest.Provider{}
		gs := &gateScanner{svc: newGate(t, model, store, p, llmpkgscan.ActionBlock), cache: fc}
		rec := &recAudit{}
		opts := testOptions(dir)
		opts.Audit = rec
		s, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		s.Attach(gs, fc)
		s.Start(context.Background())
		waitFor(t, "every artifact to be current", func() bool {
			if !isLoaded(s) {
				return false
			}
			u := upstreamStatus(t, s, "npm")
			return u.Scanned == 3 && u.Pending == 0
		})
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return p, s, rec
	}
	p1, _, _ := run("model-a")
	if p1.Calls() != 3 {
		t.Fatalf("first run: %d model calls", p1.Calls())
	}
	p2, s2, rec2 := run("model-b")
	if p2.Calls() != 3 {
		t.Fatalf("after the model changed: %d model calls, want 3", p2.Calls())
	}
	u := upstreamStatus(t, s2, "npm")
	if u.Counters.Rescans["version"] != 3 {
		t.Fatalf("rescans %v", u.Counters.Rescans)
	}
	if !strings.Contains(strings.Join(rec2.actions(), ","), "rescan-version") {
		t.Fatalf("audit %v", rec2.actions())
	}
	for _, it := range s2.items {
		if want := (llmpkgscan.ScanSignature{Model: "model-b", PromptVersion: llmpkgscan.PromptVersion, SchemaVersion: llmpkgscan.VerdictSchemaVersion}).String(); it.Signature != want {
			t.Fatalf("item %s holds signature %q, want %q", it.Key, it.Signature, want)
		}
	}
	p3, _, _ := run("model-b")
	if p3.Calls() != 0 {
		t.Fatalf("the same model again: %d model calls", p3.Calls())
	}
}

// A malicious artifact found by the backfill follows the action ladder: under
// quarantine it is evicted, and the inventory keeps the record.
func TestAMaliciousBackfilledArtifactIsQuarantined(t *testing.T) {
	fc := newFakeCache()
	fc.put(objectKey("evil"), "npm", objectPath("evil"), "", tarball("evil", true), time.Now())
	fc.put(objectKey("good"), "npm", objectPath("good"), "", tarball("good", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionQuarantine), cache: fc}
	s := startService(t, testOptions(t.TempDir()), gs, fc)
	waitFor(t, "both scanned", func() bool { return upstreamStatus(t, s, "npm").Pending == 0 && len(gs.started()) == 2 })
	u := upstreamStatus(t, s, "npm")
	if u.Malicious != 1 || u.Quarantined != 1 || u.Cached != 1 || u.Benign != 1 || u.Counters.Evicted != 1 || u.Counters.Refused != 1 {
		t.Fatalf("status %+v counters %+v", u.Figures, u.Counters)
	}
	if fc.has(objectKey("evil")) || !fc.has(objectKey("good")) {
		t.Fatal("the malicious artifact is still cached, or the benign one is not")
	}
	// A later sweep does not drop the record, nor scan the evicted artifact.
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u := upstreamStatus(t, s, "npm"); u.Malicious != 1 || u.Quarantined != 1 || len(gs.started()) != 2 {
		t.Fatalf("after a sweep: %+v, scans %v", u.Figures, gs.started())
	}
}

// An operator's re-scan asks for a new model call even though the bytes have
// a verdict; a re-scan by path is queued ahead of the backfill.
func TestAnOperatorRescanCallsTheModelAgain(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	fc.put(objectKey("p"), "npm", objectPath("p"), "", tarball("p", false), time.Now())
	fc.put(objectKey("q"), "npm", objectPath("q"), "", tarball("q", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	rec := &recAudit{}
	opts := testOptions(t.TempDir())
	opts.Audit = rec
	s := startService(t, opts, gs, fc)
	waitFor(t, "both scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 2 })
	if _, err := s.Rescan(ctx, RescanRequest{Upstream: "npm", Filter: "nonsense"}); err == nil {
		t.Fatal("an unknown filter was accepted")
	}
	if _, err := s.Rescan(ctx, RescanRequest{Upstream: "elsewhere"}); err == nil {
		t.Fatal("an upstream outside the scope was accepted")
	}
	req, err := s.Rescan(ctx, RescanRequest{Upstream: "npm", Path: objectPath("q"), By: "op"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Seq != 1 || req.Filter != "all" {
		t.Fatalf("request %+v", req)
	}
	waitFor(t, "the re-scan", func() bool { return provider.Calls() == 3 })
	waitFor(t, "the re-scan to be recorded", func() bool { return upstreamStatus(t, s, "npm").Scanned == 2 })
	if got := gs.started(); got[len(got)-1] != objectKey("q") {
		t.Fatalf("scans %v", got)
	}
	if u := upstreamStatus(t, s, "npm"); u.Counters.Rescans["operator"] != 1 || u.Counters.Scans != 3 {
		t.Fatalf("counters %+v", u.Counters)
	}
	acts := strings.Join(rec.actions(), ",")
	if !strings.Contains(acts, "rescan-requested") || !strings.Contains(acts, "rescan") {
		t.Fatalf("audit %v", acts)
	}
}

// A paused upstream's artifacts wait (parked); the others go on.
func TestAPausedUpstreamWaitsAndTheOthersGoOn(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	fc.put("npm:a", "npm", "/a/-/a-1.0.0.tgz", "", tarball("a", false), time.Now())
	fc.put("private:b", "private", "/b/-/b-1.0.0.tgz", "", tarball("b", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	s, err := New(testOptions(t.TempDir(), "npm", "private"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(ctx, "private", "op", "embargo"); err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(ctx, "unknown", "op", ""); err == nil {
		t.Fatal("pausing an upstream outside the scope was accepted")
	}
	s.Attach(gs, fc)
	s.Start(ctx)
	t.Cleanup(func() { _ = s.Close() })
	waitFor(t, "npm to be scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 1 })
	time.Sleep(30 * time.Millisecond)
	p := upstreamStatus(t, s, "private")
	if p.Scanned != 0 || p.Pending != 1 || !p.Paused || p.PauseReason != "embargo" || s.Status().Queue.Parked != 1 {
		t.Fatalf("the paused upstream: %+v, queue %+v", p, s.Status().Queue)
	}
	if err := s.Resume(ctx, "private", "op"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "private to be scanned", func() bool { return upstreamStatus(t, s, "private").Scanned == 1 })
}

// The sweep drops what left the cache, counts what it cannot track, and
// queues again what was given up on.
func TestTheSweepFollowsTheCache(t *testing.T) {
	fc := newFakeCache()
	fc.put(objectKey("stay"), "npm", objectPath("stay"), "", tarball("stay", false), time.Now())
	fc.put(objectKey("leave"), "npm", objectPath("leave"), "", tarball("leave", false), time.Now())
	// Cached before fill metadata existed: attributable by its key only.
	fc.put(objectKey("legacy"), "", "", "", tarball("legacy", false), time.Now())
	fc.put("sha256:0123", "", "", "", []byte("a blob"), time.Now())
	// Another upstream, outside the scope: ignored.
	fc.put("pip:x", "pip", "/x.whl", "", tarball("x", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	s := startService(t, testOptions(t.TempDir()), gs, fc)
	waitFor(t, "the two to be scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 2 })
	st := s.Status()
	u := upstreamStatus(t, s, "npm")
	if u.Untracked != 1 || st.Untracked != 1 || u.Cached != 2 {
		t.Fatalf("untracked %d (global %d), cached %d", u.Untracked, st.Untracked, u.Cached)
	}
	fc.del(objectKey("leave"))
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u := upstreamStatus(t, s, "npm"); u.Cached != 1 || u.Counters.Gone != 1 {
		t.Fatalf("after the object left the cache: %+v %+v", u.Figures, u.Counters)
	}
	if !st.Sweep.Inventory || st.Sweep.LastFinished.IsZero() {
		t.Fatalf("sweep %+v", st.Sweep)
	}
}

// A replica that does not lead passes what a client pulled unjudged on to
// the leader through the inbox; the leader queues it ahead of the backfill.
func TestTheInboxCarriesClientPullsToTheLeader(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("pulled"), "npm", objectPath("pulled"), "", tarball("pulled", false), time.Now())
	follower, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	follower.SetLeaderGate(func() bool { return false })
	follower.Attach(&gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}, fc)
	follower.Start(ctx)
	t.Cleanup(func() { _ = follower.Close() })
	follower.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("pulled"), Key: objectKey("pulled")},
		Reading: &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeBusy, Retryable: true}})
	// A verdict a client got is not forwarded: the leader finds it for free.
	follower.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("other"), Key: objectKey("other")},
		Reading: &Reading{Kind: ReadingVerdict, Disposition: "benign"}})
	waitFor(t, "the inbox file", func() bool {
		entries, _ := os.ReadDir(filepath.Join(dir, "inbox"))
		return len(entries) == 1
	})
	if st := follower.Status(); st.State != StateStandby || st.Leader {
		t.Fatalf("the follower reports %s (leader %v)", st.State, st.Leader)
	}

	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	leader, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := leader.Pause(ctx, "", "op", ""); err != nil {
		t.Fatal(err)
	}
	leader.Attach(gs, fc)
	leader.Start(ctx)
	t.Cleanup(func() { _ = leader.Close() })
	waitFor(t, "the leader to queue the client's artifact", func() bool { return leader.Status().Queue.Client == 1 })
	entries, _ := os.ReadDir(filepath.Join(dir, "inbox"))
	if len(entries) != 0 {
		t.Fatalf("the inbox still holds %d file(s)", len(entries))
	}
	// The follower shows what the leader published.
	waitFor(t, "the follower to see the leader's figures", func() bool {
		follower.mu.Lock()
		follower.peeked = nil
		follower.mu.Unlock()
		return follower.Status().Queue.Client == 1
	})
}

// Two replicas that both think they lead (a lease service that glitched)
// share the state directory: each takeover moves the generation on, a replica
// that finds it moved stands by, and the pair settles with exactly one
// leading — not taking the state from each other in turn.
func TestAFormerLeaderStandsBy(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("a"), "npm", objectPath("a"), "", tarball("a", false), time.Now())
	mk := func() *Service {
		s, err := New(testOptions(dir))
		if err != nil {
			t.Fatal(err)
		}
		s.Attach(&gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}, fc)
		s.Start(ctx)
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	first := mk()
	waitFor(t, "the first replica to scan", func() bool { return upstreamStatus(t, first, "npm").Scanned == 1 })
	second := mk()
	// Both write now and then (a note, a finished scan).
	poke := func() {
		for _, s := range []*Service{first, second} {
			s.mu.Lock()
			s.dirty = true
			s.mu.Unlock()
			s.kick()
		}
	}
	// Settled: one replica holds the state, the other has tried (or found
	// it taken) and stands by.
	settled := func() bool {
		poke()
		switch {
		case isLoaded(first) && !isLoaded(second):
			return second.Status().State == StateStandby
		case isLoaded(second) && !isLoaded(first):
			return first.Status().State == StateStandby
		}
		return false
	}
	waitFor(t, "exactly one replica to lead", settled)
	time.Sleep(50 * time.Millisecond) // the standby's own attempt, if it was still to come
	waitFor(t, "exactly one replica to lead", settled)
	leader, standby := first, second
	if isLoaded(second) {
		leader, standby = second, first
	}
	for i := 0; i < 20; i++ {
		time.Sleep(10 * time.Millisecond)
		poke()
		if !isLoaded(leader) || isLoaded(standby) {
			t.Fatalf("the replicas took the state from each other (leader loaded %v, standby loaded %v)", isLoaded(leader), isLoaded(standby))
		}
	}
	if st := standby.Status(); st.State != StateStandby {
		t.Fatalf("the replica that does not lead reports %s", st.State)
	}
}

// The journal's torn last line (a crash in the middle of an append) is
// ignored; the state reads back.
func TestATornJournalLineIsIgnored(t *testing.T) {
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("a"), "npm", objectPath("a"), "", tarball("a", false), time.Now())
	store := llmpkgscan.NewMemoryStore(0)
	gs := &gateScanner{svc: newGate(t, "mock-model", store, &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}
	s, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	s.Attach(gs, fc)
	s.Start(context.Background())
	waitFor(t, "the scan", func() bool { return upstreamStatus(t, s, "npm").Scanned == 1 })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := (store_(dir)).loadState()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, st.Journal), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"k":"npm:torn","u":"npm","p":"/torn","st":"pend`)
	_ = f.Close()
	p := &pkgscantest.Provider{}
	s2 := startService(t, testOptions(dir), &gateScanner{svc: newGate(t, "mock-model", store, p, llmpkgscan.ActionBlock), cache: fc}, fc)
	waitFor(t, "the state to be read back", func() bool { return upstreamStatus(t, s2, "npm").Scanned == 1 })
	if p.Calls() != 0 {
		t.Fatalf("%d model calls after reading the state back", p.Calls())
	}
	if _, ok := s2.items["npm:torn"]; ok {
		t.Fatal("the torn line was read as an item")
	}
}

func store_(dir string) store { return store{dir: dir} }

func isLoaded(s *Service) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loaded
}

func TestOptionsAreValidated(t *testing.T) {
	if _, err := New(Options{Dir: t.TempDir(), Upstreams: []string{"npm"}}); err == nil {
		t.Fatal("a full scan without a budget was accepted")
	}
	if _, err := New(Options{Dir: t.TempDir(), DailyUSD: 1}); err == nil {
		t.Fatal("a full scan without an upstream was accepted")
	}
	if _, err := New(Options{Upstreams: []string{"npm"}, DailyUSD: 1}); err == nil {
		t.Fatal("a full scan without a state directory was accepted")
	}
	var nilSvc *Service
	if nilSvc.Enabled() || nilSvc.InScope("npm") || nilSvc.Status().Enabled {
		t.Fatal("a nil service reports itself enabled")
	}
	nilSvc.Note(Note{})
	if err := nilSvc.Close(); err != nil {
		t.Fatal(err)
	}
}
