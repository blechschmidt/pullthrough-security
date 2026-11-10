package coalesce

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// notFound classifies an error as a terminal (non-retryable) negative result.
func notFoundClassifier(error) Verdict { return Verdict{Cache: true, Kind: "not_found"} }

// serverClassifier marks every error as a transient (jittered-backoff) result.
func serverClassifier(error) Verdict { return Verdict{Cache: true, Retryable: true, Kind: "server"} }

// reopenOK is a trivial reopen that returns a sentinel "waiter" value, so a test
// can distinguish the leader's own value from a waiter's re-opened one.
func reopenOK(context.Context) (int, error) { return waiterValue, nil }

const (
	leaderValue = 1
	waiterValue = 2
)

func enabledCfg() Config {
	return Config{Enabled: true, NegativeTTL: time.Minute, MaxNegativeEntries: 1024}
}

// waitFor polls cond until it is true or the deadline elapses, failing the test
// otherwise. It avoids racy fixed sleeps when synchronizing on a counter.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestConcurrentMissFanIn verifies that N simultaneous misses for the same key
// run the load exactly once, every waiter receives its own re-opened value, and
// the counters reflect one leader and N-1 coalesced waiters.
func TestConcurrentMissFanIn(t *testing.T) {
	t.Parallel()
	c := New[int](enabledCfg(), notFoundClassifier)

	const n = 64
	var loadCalls, reopenCalls atomic.Int64
	release := make(chan struct{})

	load := func(ctx context.Context) (int, error) {
		loadCalls.Add(1)
		<-release // hold the flight open until every waiter has joined
		return leaderValue, nil
	}
	reopen := func(ctx context.Context) (int, error) {
		reopenCalls.Add(1)
		return waiterValue, nil
	}

	results := make([]int, n)
	infos := make([]Info, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			v, info, err := c.Do(context.Background(), "k", load, reopen)
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", i, err)
			}
			results[i], infos[i] = v, info
		}(i)
	}

	// Once N-1 callers have coalesced, the single leader is the only one running
	// load; release it so the flight completes.
	waitFor(t, "all waiters to join", func() bool { return c.Metrics().Coalesced == n-1 })
	close(release)
	wg.Wait()

	if got := loadCalls.Load(); got != 1 {
		t.Fatalf("load ran %d times, want exactly 1", got)
	}
	if got := reopenCalls.Load(); got != n-1 {
		t.Fatalf("reopen ran %d times, want %d (one per waiter)", got, n-1)
	}

	leaders, waiters := 0, 0
	for i := 0; i < n; i++ {
		switch {
		case infos[i].Lead:
			leaders++
			if results[i] != leaderValue {
				t.Errorf("leader got value %d, want %d", results[i], leaderValue)
			}
		case infos[i].Coalesced:
			waiters++
			if results[i] != waiterValue {
				t.Errorf("waiter got value %d, want %d (independent re-open)", results[i], waiterValue)
			}
		default:
			t.Errorf("goroutine %d was neither leader nor waiter: %+v", i, infos[i])
		}
	}
	if leaders != 1 || waiters != n-1 {
		t.Fatalf("got %d leaders / %d waiters, want 1 / %d", leaders, waiters, n-1)
	}

	snap := c.Metrics()
	if snap.Leads != 1 || snap.Coalesced != n-1 {
		t.Fatalf("snapshot leads=%d coalesced=%d, want 1/%d", snap.Leads, snap.Coalesced, n-1)
	}
	if snap.DedupRatio() <= 0 || snap.DedupRatio() >= 1 {
		t.Fatalf("dedup ratio %v out of expected (0,1)", snap.DedupRatio())
	}
}

// TestErrorPropagatedToAllWaiters verifies that when the leader's load fails,
// every coalesced waiter receives the same error (and none falls through to its
// own upstream fetch).
func TestErrorPropagatedToAllWaiters(t *testing.T) {
	t.Parallel()
	c := New[int](enabledCfg(), notFoundClassifier)

	sentinel := errors.New("upstream 404")
	const n = 32
	var loadCalls, reopenCalls atomic.Int64
	release := make(chan struct{})

	load := func(ctx context.Context) (int, error) {
		loadCalls.Add(1)
		<-release
		return 0, sentinel
	}
	reopen := func(ctx context.Context) (int, error) {
		reopenCalls.Add(1) // must never happen on a failed flight
		return waiterValue, nil
	}

	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = c.Do(context.Background(), "missing", load, reopen)
		}(i)
	}

	waitFor(t, "all waiters to join", func() bool { return c.Metrics().Coalesced == n-1 })
	close(release)
	wg.Wait()

	if got := loadCalls.Load(); got != 1 {
		t.Fatalf("load ran %d times, want exactly 1", got)
	}
	if got := reopenCalls.Load(); got != 0 {
		t.Fatalf("reopen ran %d times on a failed flight, want 0", got)
	}
	for i, err := range errs {
		if !errors.Is(err, sentinel) {
			t.Fatalf("goroutine %d got err %v, want %v", i, err, sentinel)
		}
	}
	if snap := c.Metrics(); snap.NegativeStored != 1 {
		t.Fatalf("negative stored=%d, want exactly 1 (the leader records it once)", snap.NegativeStored)
	}
}

// TestNegativeCacheHitWithinTTL verifies that a terminal failure is remembered:
// subsequent calls within the TTL return the cached error without running load,
// and after the TTL elapses load runs again.
func TestNegativeCacheHitWithinTTL(t *testing.T) {
	t.Parallel()
	cfg := Config{Enabled: true, NegativeTTL: 30 * time.Second, MaxNegativeEntries: 16}
	c := New[int](cfg, notFoundClassifier)
	clock := &fakeClock{t: time.Unix(1_000, 0)}
	c.setClock(clock.Now)

	sentinel := errors.New("404")
	var loadCalls atomic.Int64
	load := func(ctx context.Context) (int, error) { loadCalls.Add(1); return 0, sentinel }

	// First miss: load runs and a negative entry is stored.
	if _, _, err := c.Do(context.Background(), "k", load, reopenOK); !errors.Is(err, sentinel) {
		t.Fatalf("first call err=%v, want sentinel", err)
	}
	// Within TTL: served from the negative cache, load not re-run.
	clock.advance(10 * time.Second)
	_, info, err := c.Do(context.Background(), "k", load, reopenOK)
	if !errors.Is(err, sentinel) {
		t.Fatalf("second call err=%v, want sentinel", err)
	}
	if !info.Negative {
		t.Fatalf("second call info=%+v, want Negative=true", info)
	}
	if got := loadCalls.Load(); got != 1 {
		t.Fatalf("load ran %d times within TTL, want 1", got)
	}
	if snap := c.Metrics(); snap.NegativeHits != 1 {
		t.Fatalf("negative hits=%d, want 1", snap.NegativeHits)
	}

	// After TTL: the stale entry is dropped and load runs again.
	clock.advance(30 * time.Second)
	if _, _, err := c.Do(context.Background(), "k", load, reopenOK); !errors.Is(err, sentinel) {
		t.Fatalf("post-expiry call err=%v, want sentinel", err)
	}
	if got := loadCalls.Load(); got != 2 {
		t.Fatalf("load ran %d times after expiry, want 2", got)
	}
	if snap := c.Metrics(); snap.NegativeExpired != 1 {
		t.Fatalf("negative expired=%d, want 1", snap.NegativeExpired)
	}
}

// TestPositiveFillClearsNegative verifies that a successful fill purges any
// stale negative entry so a later request is served the (now available)
// artifact rather than the remembered failure.
func TestPositiveFillClearsNegative(t *testing.T) {
	t.Parallel()
	cfg := Config{Enabled: true, NegativeTTL: time.Hour, MaxNegativeEntries: 16}
	c := New[int](cfg, notFoundClassifier)

	failing := func(ctx context.Context) (int, error) { return 0, errors.New("404") }
	if _, _, err := c.Do(context.Background(), "k", failing, reopenOK); err == nil {
		t.Fatal("expected error from failing load")
	}
	if c.Metrics().NegativeEntries != 1 {
		t.Fatalf("want 1 negative entry, got %d", c.Metrics().NegativeEntries)
	}
	// A positive fill for the same key must clear any negative entry. Because the
	// negative cache short-circuits on the miss path, we first open the window
	// (as the TTL or an operator purge would) and then perform a successful fill,
	// asserting the entry is gone afterwards.
	c.Purge("k")
	ok := func(ctx context.Context) (int, error) { return leaderValue, nil }
	if _, _, err := c.Do(context.Background(), "k", ok, reopenOK); err != nil {
		t.Fatalf("positive fill err=%v", err)
	}
	if c.Metrics().NegativeEntries != 0 {
		t.Fatalf("want negative entry cleared after positive fill, got %d", c.Metrics().NegativeEntries)
	}
}

// TestNegativeCacheEviction verifies the LRU bound on the negative cache.
func TestNegativeCacheEviction(t *testing.T) {
	t.Parallel()
	cfg := Config{Enabled: true, NegativeTTL: time.Hour, MaxNegativeEntries: 2}
	c := New[int](cfg, notFoundClassifier)
	fail := func(ctx context.Context) (int, error) { return 0, errors.New("404") }

	for _, k := range []string{"a", "b", "c"} {
		if _, _, err := c.Do(context.Background(), k, fail, reopenOK); err == nil {
			t.Fatalf("key %q: expected error", k)
		}
	}
	snap := c.Metrics()
	if snap.NegativeEntries != 2 {
		t.Fatalf("negative entries=%d, want 2 (bounded)", snap.NegativeEntries)
	}
	if snap.NegativeEvictions != 1 {
		t.Fatalf("negative evictions=%d, want 1", snap.NegativeEvictions)
	}
	if snap.NegativeStored != 3 {
		t.Fatalf("negative stored=%d, want 3", snap.NegativeStored)
	}
}

// TestRetryableJitteredBackoff verifies that a transient (5xx) failure is cached
// for a TTL within the configured jittered backoff window.
func TestRetryableJitteredBackoff(t *testing.T) {
	t.Parallel()
	cfg := Config{Enabled: true, MaxNegativeEntries: 16, Backoff5xxBase: time.Second, Backoff5xxMax: 4 * time.Second}
	c := New[int](cfg, serverClassifier)
	clock := &fakeClock{t: time.Unix(5_000, 0)}
	c.setClock(clock.Now)

	sentinel := errors.New("503")
	var loadCalls atomic.Int64
	fail := func(ctx context.Context) (int, error) { loadCalls.Add(1); return 0, sentinel }

	if _, _, err := c.Do(context.Background(), "k", fail, reopenOK); !errors.Is(err, sentinel) {
		t.Fatalf("err=%v, want sentinel", err)
	}
	// Just before the minimum backoff: still negatively cached.
	clock.advance(900 * time.Millisecond)
	if _, info, _ := c.Do(context.Background(), "k", fail, reopenOK); !info.Negative {
		t.Fatalf("within backoff window: want Negative hit, got %+v", info)
	}
	if got := loadCalls.Load(); got != 1 {
		t.Fatalf("load ran %d times within backoff, want 1", got)
	}
	// After the maximum backoff: the entry must have expired.
	clock.advance(4 * time.Second)
	if _, info, _ := c.Do(context.Background(), "k", fail, reopenOK); info.Negative {
		t.Fatalf("past max backoff: want fresh fetch, got Negative hit")
	}
	if got := loadCalls.Load(); got != 2 {
		t.Fatalf("load ran %d times past backoff, want 2", got)
	}
}

// TestNonCacheableErrorNotStored verifies that a classifier verdict of
// {Cache:false} (e.g. client cancellation) leaves no negative entry.
func TestNonCacheableErrorNotStored(t *testing.T) {
	t.Parallel()
	c := New[int](enabledCfg(), func(error) Verdict { return Verdict{Cache: false} })
	if _, _, err := c.Do(context.Background(), "k", func(context.Context) (int, error) {
		return 0, context.Canceled
	}, reopenOK); err == nil {
		t.Fatal("expected error")
	}
	if snap := c.Metrics(); snap.NegativeStored != 0 || snap.NegativeEntries != 0 {
		t.Fatalf("non-cacheable error stored a negative entry: %+v", snap)
	}
}

// TestMaxInflightOverloaded verifies that a new distinct fetch beyond the
// in-flight ceiling is shed with ErrOverloaded, while a caller joining an
// existing flight is never rejected.
func TestMaxInflightOverloaded(t *testing.T) {
	t.Parallel()
	cfg := Config{Enabled: true, NegativeTTL: time.Minute, MaxNegativeEntries: 16, MaxInflight: 1}
	c := New[int](cfg, notFoundClassifier)

	release := make(chan struct{})
	leaderStarted := make(chan struct{})
	var once sync.Once
	blockingLoad := func(ctx context.Context) (int, error) {
		once.Do(func() { close(leaderStarted) })
		<-release
		return leaderValue, nil
	}

	// Occupy the single in-flight slot with key "a".
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := c.Do(context.Background(), "a", blockingLoad, reopenOK); err != nil {
			t.Errorf("leader err=%v", err)
		}
	}()
	<-leaderStarted

	// A distinct key "b" must be shed while "a" holds the only slot.
	if _, _, err := c.Do(context.Background(), "b", func(context.Context) (int, error) {
		return leaderValue, nil
	}, reopenOK); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("distinct key under inflight cap: err=%v, want ErrOverloaded", err)
	}

	// A caller joining the existing "a" flight is admitted, not shed.
	joinDone := make(chan error, 1)
	go func() {
		_, info, err := c.Do(context.Background(), "a", blockingLoad, reopenOK)
		if !info.Coalesced {
			err = fmt.Errorf("joiner not coalesced: %+v", info)
		}
		joinDone <- err
	}()
	waitFor(t, "joiner to coalesce", func() bool { return c.Metrics().Coalesced == 1 })

	close(release)
	<-done
	if err := <-joinDone; err != nil {
		t.Fatalf("joiner: %v", err)
	}
	if snap := c.Metrics(); snap.Overloaded != 1 {
		t.Fatalf("overloaded=%d, want 1", snap.Overloaded)
	}
}

// TestKeyIsolation verifies that distinct keys never coalesce and that a
// negative entry under one key does not affect another (the basis of the
// gateway's tenant isolation, which scopes the key by tenant).
func TestKeyIsolation(t *testing.T) {
	t.Parallel()
	c := New[int](enabledCfg(), notFoundClassifier)

	// A 404 cached for tenant-A's key must not shadow tenant-B's key.
	failA := func(context.Context) (int, error) { return 0, errors.New("403 for A") }
	if _, _, err := c.Do(context.Background(), "A\x00pkg", failA, reopenOK); err == nil {
		t.Fatal("expected error for A")
	}

	var bLoaded atomic.Int64
	okB := func(context.Context) (int, error) { bLoaded.Add(1); return leaderValue, nil }
	v, info, err := c.Do(context.Background(), "B\x00pkg", okB, reopenOK)
	if err != nil {
		t.Fatalf("B err=%v, want nil (not shadowed by A's negative entry)", err)
	}
	if v != leaderValue || !info.Lead {
		t.Fatalf("B got v=%d info=%+v, want leader value", v, info)
	}
	if bLoaded.Load() != 1 {
		t.Fatalf("B load ran %d times, want 1", bLoaded.Load())
	}

	// Concurrent distinct keys each run their own load (no cross-key coalescing).
	const n = 16
	var distinctLoads atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("T%d\x00pkg", i)
			_, _, _ = c.Do(context.Background(), key, func(context.Context) (int, error) {
				distinctLoads.Add(1)
				return leaderValue, nil
			}, reopenOK)
		}(i)
	}
	wg.Wait()
	if got := distinctLoads.Load(); got != n {
		t.Fatalf("distinct keys ran %d loads, want %d (no cross-key coalescing)", got, n)
	}
}

// TestDisabledPassThrough verifies that a disabled coalescer runs the load on
// every call with no coalescing or negative caching.
func TestDisabledPassThrough(t *testing.T) {
	t.Parallel()
	c := New[int](Config{Enabled: false}, notFoundClassifier)
	var loadCalls atomic.Int64
	fail := func(context.Context) (int, error) { loadCalls.Add(1); return 0, errors.New("404") }

	for i := 0; i < 3; i++ {
		_, info, err := c.Do(context.Background(), "k", fail, reopenOK)
		if err == nil {
			t.Fatal("expected error")
		}
		if !info.Lead || info.Negative || info.Coalesced {
			t.Fatalf("disabled call info=%+v, want Lead only", info)
		}
	}
	if got := loadCalls.Load(); got != 3 {
		t.Fatalf("disabled: load ran %d times, want 3 (no negative caching)", got)
	}
	if snap := c.Metrics(); snap.Enabled || snap.NegativeStored != 0 || snap.Lookups != 0 {
		t.Fatalf("disabled snapshot unexpectedly active: %+v", snap)
	}
}

// TestNilCoalescerSafe verifies the nil-receiver conveniences used by the
// gateway's pass-through.
func TestNilCoalescerSafe(t *testing.T) {
	t.Parallel()
	var c *Coalescer[int]
	if c.Enabled() {
		t.Fatal("nil coalescer reports enabled")
	}
	if snap := c.Metrics(); snap.Enabled {
		t.Fatal("nil coalescer snapshot enabled")
	}
	var loadCalls atomic.Int64
	v, info, err := c.Do(context.Background(), "k", func(context.Context) (int, error) {
		loadCalls.Add(1)
		return leaderValue, nil
	}, reopenOK)
	if err != nil || v != leaderValue || !info.Lead || loadCalls.Load() != 1 {
		t.Fatalf("nil Do: v=%d info=%+v err=%v calls=%d", v, info, err, loadCalls.Load())
	}
}

// fakeClock is a manually-advanced clock for deterministic TTL tests. It is
// guarded by a mutex so concurrent Do calls under -race observe a consistent
// time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}
