package fullmirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
)

// fakeFeed is a scripted registry feed.
type fakeFeed struct {
	mu        sync.Mutex
	bootstrap map[string]Batch
	changes   map[string]Batch
	pollErr   map[string]error
	releases  map[string][]Release
	relErr    map[string]error
	relHook   func(name string)
	calls     []string
}

func newFakeFeed() *fakeFeed {
	return &fakeFeed{
		bootstrap: map[string]Batch{}, changes: map[string]Batch{}, pollErr: map[string]error{},
		releases: map[string][]Release{}, relErr: map[string]error{},
	}
}

func (f *fakeFeed) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeFeed) Bootstrap(_ context.Context, cursor string) (Batch, error) {
	f.record("bootstrap:" + cursor)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pollErr["bootstrap:"+cursor]; err != nil {
		return Batch{}, err
	}
	b, ok := f.bootstrap[cursor]
	if !ok {
		return Batch{}, fmt.Errorf("fake feed: no bootstrap page for %q", cursor)
	}
	return b, nil
}

func (f *fakeFeed) Changes(_ context.Context, cursor string) (Batch, error) {
	f.record("changes:" + cursor)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pollErr["changes:"+cursor]; err != nil {
		return Batch{}, err
	}
	b, ok := f.changes[cursor]
	if !ok {
		return Batch{Next: cursor}, nil // nothing new
	}
	return b, nil
}

func (f *fakeFeed) Releases(_ context.Context, name string) ([]Release, error) {
	f.record("releases:" + name)
	f.mu.Lock()
	hook := f.relHook
	err := f.relErr[name]
	rels, ok := f.releases[name]
	f.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Permanent(fmt.Errorf("no package %q", name))
	}
	return rels, nil
}

func (f *fakeFeed) callsWithPrefix(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// release is a version with one tarball of the given size (0: unstated).
func release(name, version string, size int64) Release {
	return Release{Version: version, Artifacts: []Artifact{{Path: "/" + name + "/-/" + name + "-" + version + ".tgz", Size: size}}}
}

func tarball(name, version string) string { return "/" + name + "/-/" + name + "-" + version + ".tgz" }

// fakeFetcher is the gated serve pipeline: a cache, and scripted answers.
type fakeFetcher struct {
	mu           sync.Mutex
	cached       map[string]bool
	sizes        map[string]int64
	gate         map[string]string
	statuses     map[string][]FetchResult
	notCacheable map[string]bool
	fetches      map[string]int
	maxBytes     map[string]int64
	times        map[string][]time.Time
	onFetch      func(path string, n int) error
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		cached: map[string]bool{}, sizes: map[string]int64{}, gate: map[string]string{},
		statuses: map[string][]FetchResult{}, notCacheable: map[string]bool{},
		fetches: map[string]int{}, maxBytes: map[string]int64{}, times: map[string][]time.Time{},
	}
}

func (f *fakeFetcher) Lookup(_ context.Context, req FetchRequest) (LookupResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return LookupResult{Cacheable: !f.notCacheable[req.Path], Cached: f.cached[req.Path]}, nil
}

func (f *fakeFetcher) Fetch(ctx context.Context, req FetchRequest, body io.Writer) (FetchResult, error) {
	f.mu.Lock()
	f.fetches[req.Path]++
	n := f.fetches[req.Path]
	f.maxBytes[req.Path] = req.MaxBytes
	f.times[req.Path] = append(f.times[req.Path], time.Now())
	hook := f.onFetch
	f.mu.Unlock()
	if hook != nil {
		if err := hook(req.Path, n); err != nil {
			return FetchResult{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return FetchResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if q := f.statuses[req.Path]; len(q) > 0 {
		f.statuses[req.Path] = q[1:]
		return q[0], nil
	}
	if g := f.gate[req.Path]; g != "" {
		return FetchResult{Status: http.StatusForbidden, Cache: "MISS", Gate: g, Code: "blocked", Reason: "refused by " + g}, nil
	}
	size, ok := f.sizes[req.Path]
	if !ok {
		size = 100
	}
	if req.MaxBytes > 0 && size > req.MaxBytes {
		return FetchResult{Status: http.StatusRequestEntityTooLarge, Code: CodeTooLarge}, nil
	}
	if f.notCacheable[req.Path] {
		return FetchResult{Status: http.StatusOK, Cache: "BYPASS"}, nil
	}
	cache := "MISS"
	if f.cached[req.Path] {
		cache = "HIT"
	}
	f.cached[req.Path] = true
	_, _ = body.Write([]byte("x"))
	return FetchResult{Status: http.StatusOK, Cache: cache, Admitted: true, Size: size}, nil
}

func (f *fakeFetcher) fetchCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches[path]
}

func (f *fakeFetcher) totalFetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.fetches {
		n += v
	}
	return n
}

// fakeAudit records audit events.
type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *fakeAudit) Log(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	a.events = append(a.events, ev)
	a.mu.Unlock()
	return nil
}

func (a *fakeAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, ev := range a.events {
		if ev.Type == audit.EventFullMirror {
			out = append(out, fmt.Sprint(ev.Detail["action"]))
		}
	}
	return out
}

func (a *fakeAudit) has(action string) bool {
	for _, x := range a.actions() {
		if x == action {
			return true
		}
	}
	return false
}

// testSettings are fast settings for one upstream.
func testSettings(name string) Settings {
	return Settings{Upstream: name, Type: "npm", ByteBudget: 1 << 40, Concurrency: 1, RequestsPerSecond: 1e6, PollInterval: time.Hour}
}

type harness struct {
	t       *testing.T
	dir     string
	feed    *fakeFeed
	fetcher *fakeFetcher
	audit   *fakeAudit
	e       *Engine
}

func newHarness(t *testing.T, dir string, feed *fakeFeed, fetcher *fakeFetcher, s Settings, edit func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, dir: dir, feed: feed, fetcher: fetcher, audit: &fakeAudit{}}
	opts := Options{
		Dir:         dir,
		Upstreams:   []Upstream{{Settings: s, Feed: feed}},
		Audit:       h.audit,
		Logger:      discardLogger(),
		MaxAttempts: 3, BaseBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond,
		MaxRounds: 3, RoundBackoff: time.Millisecond, PollBackoff: time.Millisecond,
		ControlRefresh: time.Millisecond, PersistInterval: time.Millisecond, StandbyInterval: time.Millisecond,
	}
	if edit != nil {
		edit(&opts)
	}
	e, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.Attach(fetcher)
	h.e = e
	t.Cleanup(func() { _ = e.Close() })
	return h
}

func (h *harness) follower() *follower { return h.e.followers[0] }

// steps runs the follower's steps until it has nothing to do right away (or n
// steps).
func (h *harness) steps(ctx context.Context, n int) {
	h.t.Helper()
	f := h.follower()
	for i := 0; i < n; i++ {
		wait := f.safeStep(ctx)
		if ctx.Err() != nil || wait > time.Second {
			return
		}
		time.Sleep(wait)
	}
}

func (h *harness) status() UpstreamStatus {
	h.t.Helper()
	return h.e.Status().Upstreams[0]
}

func (h *harness) diskState() upstreamState {
	h.t.Helper()
	st, err := h.e.store.loadState(h.follower().s.Upstream)
	if err != nil {
		h.t.Fatalf("reading state.json: %v", err)
	}
	return st
}

// twoPageRegistry is a registry of four packages enumerated in two bootstrap
// pages, then one change.
func twoPageRegistry() *fakeFeed {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a"}, {Name: "b"}}, Next: "page:2", More: true}
	feed.bootstrap["page:2"] = Batch{Items: []Coordinate{{Name: "c"}, {Name: "d"}}, Next: "seq:10", Head: "seq:12", Lag: 2, LagKnown: true}
	feed.changes["seq:10"] = Batch{Items: []Coordinate{{Name: "a", Version: "2.0.0"}}, Next: "seq:12", Head: "seq:12", Lag: 0, LagKnown: true}
	for _, n := range []string{"a", "b", "c", "d"} {
		feed.releases[n] = []Release{release(n, "1.0.0", 0)}
	}
	feed.releases["a"] = append(feed.releases["a"], release("a", "2.0.0", 0))
	return feed
}

func TestBootstrapThenFollowFetchesEverythingOnceThroughTheGateway(t *testing.T) {
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	ctx := context.Background()

	h.steps(ctx, 10)
	st := h.diskState()
	if st.Phase != phaseFollow || st.Cursor != "seq:10" {
		t.Fatalf("after the bootstrap: phase %q cursor %q, want follow seq:10", st.Phase, st.Cursor)
	}
	if st.BootstrapFinished.IsZero() || st.BootstrapStarted.IsZero() {
		t.Errorf("bootstrap times not recorded: %+v", st)
	}
	for _, p := range []string{tarball("a", "1.0.0"), tarball("a", "2.0.0"), tarball("b", "1.0.0"), tarball("c", "1.0.0"), tarball("d", "1.0.0")} {
		if n := fetcher.fetchCount(p); n != 1 {
			t.Errorf("%s fetched %d times, want 1", p, n)
		}
	}
	if got := h.audit.actions(); !contains(got, "bootstrap-started") || !contains(got, "bootstrap-finished") {
		t.Errorf("audit actions %v lack the bootstrap's start and end", got)
	}

	// The change feed: a@2.0.0 is already in the cache.
	h.follower().mu.Lock()
	h.follower().nextPoll = time.Time{}
	h.follower().mu.Unlock()
	h.steps(ctx, 3)
	st = h.diskState()
	if st.Cursor != "seq:12" || st.Phase != phaseFollow {
		t.Fatalf("after the change: cursor %q phase %q", st.Cursor, st.Phase)
	}
	if n := fetcher.fetchCount(tarball("a", "2.0.0")); n != 1 {
		t.Errorf("a@2.0.0 fetched %d times; the cache already held it", n)
	}
	c := st.Counters
	if c.Fetched != 5 || c.Skipped[SkipCached] != 1 || c.Packages != 5 || c.Batches != 3 || c.Failed != 0 || c.Refused != 0 {
		t.Errorf("counters %+v", c)
	}
	us := h.status()
	if us.State != StateFollowing || us.Lag == nil || *us.Lag != 0 || us.FeedHead != "seq:12" {
		t.Errorf("status: state %q lag %v head %q", us.State, us.Lag, us.FeedHead)
	}
}

func TestCursorResumesAfterRestartWithoutRefetching(t *testing.T) {
	dir := t.TempDir()
	feed := newFakeFeed()
	var items []Coordinate
	for i := 0; i < 6; i++ {
		n := fmt.Sprintf("p%d", i)
		items = append(items, Coordinate{Name: n})
		feed.releases[n] = []Release{release(n, "1.0.0", 0)}
	}
	feed.bootstrap[""] = Batch{Items: items, Next: "seq:100"}
	fetcher := newFakeFetcher()

	// The first run stops at the fourth file: the process goes away.
	ctx, cancel := context.WithCancel(context.Background())
	fetcher.onFetch = func(path string, _ int) error {
		if path == tarball("p3", "1.0.0") {
			cancel()
			return context.Canceled
		}
		return nil
	}
	h1 := newHarness(t, dir, feed, fetcher, testSettings("npm"), nil)
	h1.follower().safeStep(ctx)
	if err := h1.e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st := h1.diskState()
	if st.Batch == nil || st.Batch.Done != 3 || st.Cursor != "" {
		t.Fatalf("after the interrupted run: batch %+v cursor %q, want 3 of 6 done and no cursor yet", st.Batch, st.Cursor)
	}
	if got := h1.status().Queued; got != 3 {
		t.Errorf("queued = %d, want 3", got)
	}

	// A new engine on the same state resumes the batch without asking the
	// feed again, and stores the cursor once the batch is done.
	fetcher.onFetch = nil
	feed2 := newFakeFeed()
	feed2.releases = feed.releases
	feed2.bootstrap[""] = Batch{Next: "must-not-be-asked"}
	h2 := newHarness(t, dir, feed2, fetcher, testSettings("npm"), nil)
	h2.follower().safeStep(context.Background())
	if calls := feed2.callsWithPrefix("bootstrap"); len(calls) != 0 {
		t.Errorf("the resumed engine polled the feed (%v) before finishing the stored batch", calls)
	}
	st = h2.diskState()
	if st.Batch != nil || st.Cursor != "seq:100" || st.Phase != phaseFollow {
		t.Fatalf("after the resumed run: batch %+v cursor %q phase %q", st.Batch, st.Cursor, st.Phase)
	}
	for i := 0; i < 6; i++ {
		p := tarball(fmt.Sprintf("p%d", i), "1.0.0")
		want := 1
		if i == 3 {
			want = 2 // the fetch interrupted by the restart, then the real one
		}
		if n := fetcher.fetchCount(p); n != want {
			t.Errorf("%s fetched %d times, want %d", p, n, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "upstreams", "npm", "batch.json")); !os.IsNotExist(err) {
		t.Errorf("batch.json left behind after the batch was committed: %v", err)
	}
}

func TestByteBudgetExhaustionStopsAndResumesWhenRaised(t *testing.T) {
	dir := t.TempDir()
	feed := newFakeFeed()
	var items []Coordinate
	for i := 0; i < 4; i++ {
		n := fmt.Sprintf("p%d", i)
		items = append(items, Coordinate{Name: n})
		feed.releases[n] = []Release{release(n, "1.0.0", 100)}
	}
	feed.bootstrap[""] = Batch{Items: items, Next: "seq:4"}
	fetcher := newFakeFetcher()
	s := testSettings("npm")
	s.ByteBudget = 250
	h := newHarness(t, dir, feed, fetcher, s, nil)
	ctx := context.Background()
	h.steps(ctx, 5)

	if n := fetcher.totalFetches(); n != 2 {
		t.Fatalf("%d files fetched with a budget for two", n)
	}
	us := h.status()
	if us.State != StateBudgetExhausted || !us.Budget.Exhausted || us.Budget.Used != 200 {
		t.Errorf("status: state %q budget %+v", us.State, us.Budget)
	}
	if us.Queued != 2 || us.Cursor != "" {
		t.Errorf("queued %d cursor %q: the unfetched changes must stay queued", us.Queued, us.Cursor)
	}
	if !h.audit.has("budget-exhausted") {
		t.Errorf("no budget-exhausted audit event: %v", h.audit.actions())
	}
	if c := us.Counters; c.Failed != 0 || c.Refused != 0 || c.SkippedTotal() != 0 {
		t.Errorf("budget exhaustion counted as a failure or skip: %+v", c)
	}
	// Still exhausted on later steps: nothing more is fetched.
	h.steps(ctx, 3)
	if n := fetcher.totalFetches(); n != 2 {
		t.Fatalf("fetched past the budget: %d", n)
	}
	_ = h.e.Close()

	// A larger budget lets the mirror finish the batch.
	s.ByteBudget = 1000
	h2 := newHarness(t, dir, feed, fetcher, s, nil)
	h2.steps(ctx, 5)
	st := h2.diskState()
	if st.Cursor != "seq:4" || st.Batch != nil || st.BudgetUsed != 400 || st.BudgetExhaustedAt != 0 {
		t.Errorf("after raising the budget: cursor %q batch %+v used %d exhaustedAt %d", st.Cursor, st.Batch, st.BudgetUsed, st.BudgetExhaustedAt)
	}
	if n := fetcher.totalFetches(); n != 4 {
		t.Errorf("%d fetches in total, want 4", n)
	}
}

func TestBudgetCutsOffAFileOfUnknownSize(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "small"}, {Name: "big"}}, Next: "seq:1"}
	feed.releases["small"] = []Release{release("small", "1.0.0", 0)}
	feed.releases["big"] = []Release{release("big", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.sizes[tarball("big", "1.0.0")] = 500
	s := testSettings("npm")
	s.ByteBudget = 300
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	h.steps(context.Background(), 5)
	if got := fetcher.maxBytes[tarball("big", "1.0.0")]; got != 200 {
		t.Errorf("the unknown-size fetch was limited to %d bytes, want the 200 left of the budget", got)
	}
	us := h.status()
	if us.State != StateBudgetExhausted || us.Counters.Fetched != 1 || us.Queued != 1 {
		t.Errorf("state %q fetched %d queued %d", us.State, us.Counters.Fetched, us.Queued)
	}
}

func TestMaxArtifactBytesSkipsLargeFiles(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "stated"}, {Name: "unstated"}, {Name: "ok"}}, Next: "seq:1"}
	feed.releases["stated"] = []Release{release("stated", "1.0.0", 5000)}
	feed.releases["unstated"] = []Release{release("unstated", "1.0.0", 0)}
	feed.releases["ok"] = []Release{release("ok", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.sizes[tarball("unstated", "1.0.0")] = 5000
	s := testSettings("npm")
	s.MaxArtifactBytes = 1000
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	h.steps(context.Background(), 5)
	if n := fetcher.fetchCount(tarball("stated", "1.0.0")); n != 0 {
		t.Errorf("a file stated larger than maxArtifactBytes was fetched")
	}
	if got := fetcher.maxBytes[tarball("unstated", "1.0.0")]; got != 1000 {
		t.Errorf("unknown-size fetch limit %d, want maxArtifactBytes 1000", got)
	}
	st := h.diskState()
	if st.Counters.Skipped[SkipTooLarge] != 2 || st.Counters.Fetched != 1 || st.Cursor != "seq:1" {
		t.Errorf("counters %+v cursor %q", st.Counters, st.Cursor)
	}
}

func TestGateRefusalsAreCountedAsRefusedNotFailed(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "evil"}, {Name: "good"}, {Name: "gone"}, {Name: "late"}}, Next: "seq:1"}
	for _, n := range []string{"evil", "good", "gone", "late"} {
		feed.releases[n] = []Release{release(n, "1.0.0", 0)}
	}
	fetcher := newFakeFetcher()
	fetcher.gate[tarball("evil", "1.0.0")] = "malfeed"
	fetcher.gate[tarball("late", "1.0.0")] = "llmpkgscan"
	fetcher.statuses[tarball("gone", "1.0.0")] = []FetchResult{{Status: http.StatusNotFound, Reason: "upstream returned status 404"}}
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	h.steps(context.Background(), 5)

	st := h.diskState()
	c := st.Counters
	if c.Refused != 2 || c.RefusedBy["malfeed"] != 1 || c.RefusedBy["llmpkgscan"] != 1 {
		t.Errorf("refusals %d by gate %v, want malfeed and llmpkgscan once each", c.Refused, c.RefusedBy)
	}
	if c.Failed != 1 {
		t.Errorf("failed = %d, want 1 (the 404 only; a refusal is not a failure)", c.Failed)
	}
	if c.Fetched != 1 || c.Retries != 0 {
		t.Errorf("fetched %d retries %d", c.Fetched, c.Retries)
	}
	if n := fetcher.fetchCount(tarball("evil", "1.0.0")); n != 1 {
		t.Errorf("a refused file was asked for %d times; a verdict is final", n)
	}
	if st.Cursor != "seq:1" || st.Batch != nil {
		t.Errorf("a refusal held the batch: cursor %q batch %+v", st.Cursor, st.Batch)
	}
}

func TestStandbyReplicaPollsAndFetchesNothing(t *testing.T) {
	dir := t.TempDir()
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	var leader atomic.Bool
	h := newHarness(t, dir, feed, fetcher, testSettings("npm"), nil)
	h.e.SetLeaderGate(leader.Load, func() uint64 { return 7 })
	ctx := context.Background()

	wait := h.follower().safeStep(ctx)
	if wait != h.e.opts.StandbyInterval {
		t.Errorf("standby wait %s", wait)
	}
	if len(feed.callsWithPrefix("")) != 0 || fetcher.totalFetches() != 0 {
		t.Fatalf("a replica that does not lead polled (%v) or fetched (%d)", feed.calls, fetcher.totalFetches())
	}
	if _, err := os.Stat(filepath.Join(dir, "upstreams", "npm", "state.json")); !os.IsNotExist(err) {
		t.Errorf("a replica that does not lead wrote the state: %v", err)
	}
	st := h.e.Status()
	if st.Leader || st.Upstreams[0].State != StateStandby {
		t.Errorf("status: leader %v state %q", st.Leader, st.Upstreams[0].State)
	}

	// Leadership arrives: the follower works, and stamps the lease's fence.
	leader.Store(true)
	h.steps(ctx, 10)
	if fetcher.totalFetches() == 0 {
		t.Fatal("the new leader fetched nothing")
	}
	if got := h.diskState().Fence; got != 7 {
		t.Errorf("state.json fence %d, want the lease's 7", got)
	}

	// Leadership is lost in the middle of a batch: the batch stops.
	h.follower().mu.Lock()
	h.follower().nextPoll = time.Time{}
	h.follower().mu.Unlock()
	feed.mu.Lock()
	feed.changes["seq:10"] = Batch{Items: []Coordinate{{Name: "b", Version: "1.0.0"}, {Name: "c", Version: "1.0.0"}}, Next: "seq:12"}
	feed.mu.Unlock()
	feed.relHook = func(string) { leader.Store(false) }
	before := fetcher.totalFetches()
	h.follower().safeStep(ctx)
	if fetcher.totalFetches() != before {
		t.Errorf("fetched after losing leadership")
	}
	if h.e.Status().Upstreams[0].State != StateStandby {
		t.Errorf("state %q after losing leadership", h.e.Status().Upstreams[0].State)
	}
}

func TestANewerLeadershipFencesTheOldLeaderOut(t *testing.T) {
	dir := t.TempDir()
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	h := newHarness(t, dir, feed, fetcher, testSettings("npm"), nil)
	h.e.SetLeaderGate(func() bool { return true }, func() uint64 { return 3 })
	h.follower().safeStep(context.Background())
	// Another replica takes over and writes the state.
	st := h.diskState()
	st.Fence = 1 // its lease store restarted: a lower token
	st.Cursor = "theirs"
	if err := h.e.store.saveState("npm", st, st.Generation); err != nil {
		t.Fatal(err)
	}
	if err := h.follower().persist(true); !errors.Is(err, errFenced) {
		t.Fatalf("persist after another replica wrote = %v, want errFenced", err)
	}
	if got := h.diskState().Cursor; got != "theirs" {
		t.Errorf("the old leader overwrote the new leader's state (cursor %q)", got)
	}
	if h.e.Status().Upstreams[0].State != StateStandby {
		t.Errorf("the fenced follower did not stand by")
	}
	// Leading again, it reads the newer state and goes on from there —
	// whatever its lease token: fencing tokens restart with the lease store.
	h.e.SetLeaderGate(func() bool { return true }, func() uint64 { return 1 })
	h.follower().safeStep(context.Background())
	if err := h.follower().persist(true); err != nil {
		t.Fatalf("persist after reloading: %v", err)
	}
	if got := h.diskState(); got.Cursor == "" || got.Fence != 1 {
		t.Errorf("after reloading: %+v", got)
	}
}

func TestRetryAfterIsHonouredForTheUpstream(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a"}}, Next: "seq:1"}
	feed.releases["a"] = []Release{release("a", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	p := tarball("a", "1.0.0")
	fetcher.statuses[p] = []FetchResult{{Status: http.StatusTooManyRequests, RetryAfter: 150 * time.Millisecond}}
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	h.steps(context.Background(), 5)
	times := fetcher.times[p]
	if len(times) != 2 {
		t.Fatalf("%d attempts, want 2", len(times))
	}
	if gap := times[1].Sub(times[0]); gap < 150*time.Millisecond {
		t.Errorf("retried after %s, before the upstream's Retry-After of 150ms", gap)
	}
	st := h.diskState()
	if st.Counters.Retries != 1 || st.Counters.Fetched != 1 || st.Counters.Failed != 0 {
		t.Errorf("counters %+v", st.Counters)
	}
}

func TestTransientFailuresBackOffThenGiveUp(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "flaky"}, {Name: "fine"}}, Next: "seq:1"}
	feed.releases["flaky"] = []Release{release("flaky", "1.0.0", 0)}
	feed.releases["fine"] = []Release{release("fine", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	var always []FetchResult
	for i := 0; i < 50; i++ {
		always = append(always, FetchResult{Status: http.StatusBadGateway, Reason: "upstream fetch failed"})
	}
	fetcher.statuses[tarball("flaky", "1.0.0")] = always
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	ctx := context.Background()

	// The first round stops at the failing file, leaving the batch queued.
	h.follower().safeStep(ctx)
	us := h.status()
	if us.Queued != 2 || us.Counters.Failed != 0 || len(us.RecentErrors) == 0 {
		t.Fatalf("after one round: queued %d failed %d errors %v", us.Queued, us.Counters.Failed, us.RecentErrors)
	}
	if n := fetcher.fetchCount(tarball("flaky", "1.0.0")); n != h.e.opts.MaxAttempts {
		t.Errorf("%d attempts in the first round, want %d", n, h.e.opts.MaxAttempts)
	}
	// After MaxRounds the file is counted as failed and the batch completes.
	h.steps(ctx, 20)
	st := h.diskState()
	if st.Counters.Failed != 1 || st.Counters.Fetched != 1 || st.Cursor != "seq:1" {
		t.Errorf("counters %+v cursor %q", st.Counters, st.Cursor)
	}
	if n := fetcher.fetchCount(tarball("flaky", "1.0.0")); n != h.e.opts.MaxAttempts*h.e.opts.MaxRounds {
		t.Errorf("%d attempts in total, want %d", n, h.e.opts.MaxAttempts*h.e.opts.MaxRounds)
	}
}

func TestPollFailuresBackOffAndRetryAfterOfTheFeed(t *testing.T) {
	feed := newFakeFeed()
	feed.pollErr["bootstrap:"] = RetryAfter(errors.New("429 from the registry"), 3*time.Hour)
	h := newHarness(t, t.TempDir(), feed, newFakeFetcher(), testSettings("npm"), nil)
	wait := h.follower().safeStep(context.Background())
	if wait < 2*time.Hour {
		t.Errorf("waited %s after the feed asked for 3h", wait)
	}
	us := h.status()
	if us.Counters.PollErrors != 1 || us.BackoffUntil.IsZero() || len(us.RecentErrors) != 1 {
		t.Errorf("status %+v", us)
	}
	if got := h.follower().safeStep(context.Background()); got < time.Hour || len(feed.callsWithPrefix("bootstrap")) != 1 {
		t.Errorf("polled again during the backoff (wait %s, calls %v)", got, feed.calls)
	}
}

func TestInvalidCursorStartsTheEnumerationOver(t *testing.T) {
	dir := t.TempDir()
	feed := twoPageRegistry()
	h := newHarness(t, dir, feed, newFakeFetcher(), testSettings("npm"), nil)
	ctx := context.Background()
	h.steps(ctx, 10)
	feed.mu.Lock()
	feed.pollErr["changes:seq:10"] = fmt.Errorf("sequence reset: %w", ErrCursorInvalid)
	feed.mu.Unlock()
	h.follower().mu.Lock()
	h.follower().nextPoll = time.Time{}
	h.follower().mu.Unlock()
	h.follower().safeStep(ctx)
	st := h.diskState()
	if st.Phase != phaseBootstrap || st.Cursor != "" {
		t.Fatalf("phase %q cursor %q after an invalid cursor", st.Phase, st.Cursor)
	}
	if !h.audit.has("cursor-reset") {
		t.Errorf("no cursor-reset audit event: %v", h.audit.actions())
	}
	before := len(feed.callsWithPrefix("bootstrap:"))
	h.follower().safeStep(ctx)
	if got := feed.callsWithPrefix("bootstrap:"); len(got) != before+1 || got[len(got)-1] != "bootstrap:" {
		t.Errorf("the enumeration did not start over: %v", got)
	}
}

func TestPauseResumeAndResync(t *testing.T) {
	dir := t.TempDir()
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	h := newHarness(t, dir, feed, fetcher, testSettings("npm"), nil)
	ctx := context.Background()

	if err := h.e.Pause(ctx, "npm", "alice", "maintenance window"); err != nil {
		t.Fatal(err)
	}
	h.follower().safeStep(ctx)
	us := h.status()
	if us.State != StatePaused || !us.Paused || us.PausedBy != "alice" || us.PauseReason != "maintenance window" {
		t.Fatalf("paused status %+v", us)
	}
	if len(feed.calls) != 0 {
		t.Fatalf("a paused mirror polled: %v", feed.calls)
	}
	// The pause is durable: a new engine on the same state stays paused.
	h2 := newHarness(t, dir, feed, fetcher, testSettings("npm"), nil)
	h2.follower().safeStep(ctx)
	if h2.status().State != StatePaused || len(feed.calls) != 0 {
		t.Fatalf("the pause did not survive a restart: %q %v", h2.status().State, feed.calls)
	}
	if err := h2.e.Resume(ctx, "npm", "bob"); err != nil {
		t.Fatal(err)
	}
	h2.steps(ctx, 10)
	if st := h2.diskState(); st.Phase != phaseFollow {
		t.Fatalf("not following after resume: %+v", st)
	}

	// A global pause holds every upstream; resuming all lifts it.
	if err := h2.e.Pause(ctx, "", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if st := h2.e.Status(); !st.Paused {
		t.Errorf("global pause not reported")
	}
	h2.follower().safeStep(ctx)
	if h2.status().State != StatePaused {
		t.Errorf("state %q under a global pause", h2.status().State)
	}
	if err := h2.e.Resume(ctx, "", "alice"); err != nil {
		t.Fatal(err)
	}

	// Resync forgets the cursor; the cache spares the refetch.
	fetchesBefore := fetcher.totalFetches()
	if err := h2.e.Resync(ctx, "npm", "carol"); err != nil {
		t.Fatal(err)
	}
	if !h2.status().ResyncPending {
		t.Errorf("resync not pending")
	}
	h2.follower().safeStep(ctx)
	st := h2.diskState()
	if st.ResyncHandled != 1 {
		t.Errorf("resync not handled: %+v", st)
	}
	h2.steps(ctx, 10)
	st = h2.diskState()
	if st.Phase != phaseFollow || st.Cursor != "seq:10" {
		t.Errorf("after the resync's enumeration: %q %q", st.Phase, st.Cursor)
	}
	if fetcher.totalFetches() != fetchesBefore {
		t.Errorf("the resync refetched files the cache holds")
	}
	for _, a := range []string{"paused", "resumed", "resync-requested", "resync"} {
		if !h2.audit.has(a) && !h.audit.has(a) {
			t.Errorf("no %q audit event", a)
		}
	}
	if err := h2.e.Pause(ctx, "nope", "x", ""); !errors.Is(err, ErrUnknownUpstream) {
		t.Errorf("pausing an unknown upstream: %v", err)
	}
	if err := h2.e.Resync(ctx, "", "x"); err == nil {
		t.Errorf("a resync of every upstream at once was accepted")
	}
}

func TestLockdownAndWindowHoldTheMirror(t *testing.T) {
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	s := testSettings("npm")
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	var clock atomic.Value
	clock.Store(now)
	var err error
	s.Window, err = ParseWindow("22:00", "06:00", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, t.TempDir(), feed, fetcher, s, func(o *Options) { o.Now = func() time.Time { return clock.Load().(time.Time) } })
	ctx := context.Background()

	wait := h.follower().safeStep(ctx)
	if us := h.status(); us.State != StateOffPeak || len(feed.calls) != 0 {
		t.Fatalf("outside the window: state %q calls %v", us.State, feed.calls)
	}
	if wait > 15*time.Minute {
		t.Errorf("waits %s outside the window", wait)
	}
	clock.Store(time.Date(2026, 11, 16, 23, 0, 0, 0, time.UTC))
	var locked atomic.Bool
	locked.Store(true)
	h.e.SetKillSwitch(func() (bool, string) { return locked.Load(), "freeze" })
	h.follower().safeStep(ctx)
	if st := h.e.Status(); st.Upstreams[0].State != StateLockdown || st.Lockdown != "freeze" || len(feed.calls) != 0 {
		t.Fatalf("under a lockdown: %+v calls %v", st, feed.calls)
	}
	locked.Store(false)
	h.steps(ctx, 10)
	if fetcher.totalFetches() == 0 {
		t.Errorf("nothing fetched inside the window once the lockdown was lifted")
	}
}

func TestALockdownRefusalMidBatchIsNoVerdict(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a"}}, Next: "seq:1"}
	feed.releases["a"] = []Release{release("a", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.statuses[tarball("a", "1.0.0")] = []FetchResult{{Status: http.StatusServiceUnavailable, Gate: "lockdown", Code: "lockdown_freeze"}}
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	h.follower().safeStep(context.Background())
	us := h.status()
	if us.Counters.Refused != 0 || us.Queued != 1 {
		t.Errorf("a lockdown refusal was counted as a verdict: %+v queued %d", us.Counters, us.Queued)
	}
}

func TestDryRunFetchesNothingButMovesTheCursor(t *testing.T) {
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	fetcher.cached[tarball("b", "1.0.0")] = true
	s := testSettings("npm")
	s.DryRun = true
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	h.steps(context.Background(), 10)
	if n := fetcher.totalFetches(); n != 0 {
		t.Fatalf("dry run fetched %d files", n)
	}
	st := h.diskState()
	if st.Phase != phaseFollow || st.Counters.Skipped[SkipDryRun] != 4 || st.Counters.Skipped[SkipCached] != 1 || st.BudgetUsed != 0 {
		t.Errorf("dry run: phase %q counters %+v used %d", st.Phase, st.Counters, st.BudgetUsed)
	}
}

func TestNamePatternsAndVersionPolicy(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "@acme/core"}, {Name: "lodash-evil"}, {Name: "lodash"}, {Name: "@acme/old", Deleted: true}}, Next: "seq:1"}
	feed.releases["@acme/core"] = []Release{
		release("core", "1.0.0", 0), release("core", "1.10.0", 0), release("core", "1.2.0", 0),
		release("core", "2.0.0-beta.1", 0), {Version: "1.9.0", Yanked: true, Artifacts: []Artifact{{Path: "/yanked"}}},
	}
	feed.releases["lodash"] = []Release{release("lodash", "4.17.21", 0)}
	fetcher := newFakeFetcher()
	s := testSettings("npm")
	var err error
	if s.Include, err = CompilePatterns([]string{"@acme/.*", "lodash"}); err != nil {
		t.Fatal(err)
	}
	if s.Exclude, err = CompilePatterns([]string{"@acme/internal-.*"}); err != nil {
		t.Fatal(err)
	}
	s.Latest = 2
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	h.steps(context.Background(), 5)

	// latest 2 by semver: 1.10.0 and 1.2.0 — not the yanked 1.9.0, not the
	// pre-release, not 1.0.0.
	for p, want := range map[string]int{
		tarball("core", "1.10.0"): 1, tarball("core", "1.2.0"): 1, tarball("core", "1.0.0"): 0,
		tarball("core", "2.0.0-beta.1"): 0, "/yanked": 0, tarball("lodash", "4.17.21"): 1,
	} {
		if n := fetcher.fetchCount(p); n != want {
			t.Errorf("%s fetched %d times, want %d", p, n, want)
		}
	}
	c := h.diskState().Counters
	if c.Excluded != 1 || c.Deleted != 1 || c.Skipped[SkipVersionPolicy] != 3 || c.Packages != 2 {
		t.Errorf("counters %+v", c)
	}
	if feed.callsWithPrefix("releases:lodash-evil") != nil {
		t.Errorf("an excluded package's versions were listed")
	}
}

func TestSelectReleasesForAVersionChange(t *testing.T) {
	rels := []Release{release("p", "1.0.0", 0), release("p", "2.0.0", 0), release("p", "3.0.0", 0)}
	kept, dropped := selectReleases(rels, "1.0.0", 0, nil)
	if len(kept) != 1 || kept[0].Version != "1.0.0" || dropped != 0 {
		t.Errorf("all versions, one changed: %v %d", kept, dropped)
	}
	kept, dropped = selectReleases(rels, "1.0.0", 2, nil)
	if len(kept) != 0 || dropped != 1 {
		t.Errorf("latest 2, an old version changed: %v %d", kept, dropped)
	}
	kept, _ = selectReleases(rels, "3.0.0", 2, nil)
	if len(kept) != 1 {
		t.Errorf("latest 2, the newest version changed: %v", kept)
	}
}

func TestUnknownVersionAndUnknownPackageArePackageErrors(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a", Version: "9.9.9"}, {Name: "missing"}, {Name: "b"}}, Next: "seq:1"}
	feed.releases["a"] = []Release{release("a", "1.0.0", 0)}
	feed.releases["b"] = []Release{release("b", "1.0.0", 0)}
	h := newHarness(t, t.TempDir(), feed, newFakeFetcher(), testSettings("npm"), nil)
	h.steps(context.Background(), 5)
	st := h.diskState()
	if st.Counters.PackageErrors != 2 || st.Counters.Packages != 1 || st.Cursor != "seq:1" {
		t.Errorf("counters %+v cursor %q", st.Counters, st.Cursor)
	}
}

func TestAPanickingAdapterDoesNotTakeTheProxyDown(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "boom"}}, Next: "seq:1"}
	feed.relHook = func(string) { panic("adapter bug") }
	h := newHarness(t, t.TempDir(), feed, newFakeFetcher(), testSettings("npm"), nil)
	h.steps(context.Background(), 10)
	st := h.diskState()
	if st.Counters.PackageErrors != 1 || st.Cursor != "seq:1" {
		t.Errorf("after a panicking adapter: %+v cursor %q", st.Counters, st.Cursor)
	}
}

func TestInvalidBatchesAreRefused(t *testing.T) {
	for name, b := range map[string]Batch{
		"no cursor":    {Items: []Coordinate{{Name: "a"}}},
		"no name":      {Items: []Coordinate{{Name: ""}}, Next: "x"},
		"control char": {Items: []Coordinate{{Name: "a\nb"}}, Next: "x"},
		"huge cursor":  {Next: strings.Repeat("x", maxCursorBytes+1)},
	} {
		if err := validateBatch(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStateFilesSurviveAndCorruptStateWaitsForAResync(t *testing.T) {
	dir := t.TempDir()
	feed := twoPageRegistry()
	h := newHarness(t, dir, feed, newFakeFetcher(), testSettings("npm"), nil)
	if err := os.MkdirAll(filepath.Join(dir, "upstreams", "npm"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "upstreams", "npm", "state.json"), []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	h.follower().safeStep(context.Background())
	if us := h.status(); us.State != StateError || len(feed.calls) != 0 {
		t.Fatalf("corrupt state: %q %v", us.State, feed.calls)
	}
	if err := h.e.Resync(context.Background(), "npm", "ops"); err != nil {
		t.Fatal(err)
	}
	h.steps(context.Background(), 10)
	if st := h.diskState(); st.Phase != phaseFollow {
		t.Errorf("the resync did not start afresh: %+v", st)
	}
}

func TestUpstreamNamesBecomeSafeDirectoryNames(t *testing.T) {
	for name, want := range map[string]string{"npm": "npm", "npm-internal_2.x": "npm-internal_2.x"} {
		if got := upstreamDirName(name); got != want {
			t.Errorf("%q → %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"..", ".", "a/b", "../x", "_x", "x y", strings.Repeat("a", 200)} {
		got := upstreamDirName(name)
		if !strings.HasPrefix(got, "_") || strings.ContainsAny(got, "/. ") || len(got) != 33 {
			t.Errorf("%q → %q", name, got)
		}
	}
}

func TestStatusAndMetrics(t *testing.T) {
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	fetcher.gate[tarball("c", "1.0.0")] = "malfeed"
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), func(o *Options) { o.Tenant = "mirror" })
	h.steps(context.Background(), 10)
	st := h.e.Status()
	if !st.Enabled || !st.Attached || !st.Leader || st.Tenant != "mirror" || st.Subject != Subject {
		t.Errorf("status %+v", st)
	}
	if st.Totals.Fetched != 4 || st.Totals.Refused != 1 || st.Totals.Upstreams != 1 || st.Totals.FetchedBytes != 400 {
		t.Errorf("totals %+v", st.Totals)
	}
	reg := metrics.New()
	BindMetrics(reg, h.e)
	var b strings.Builder
	if err := reg.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`pullthrough_fullmirror_artifacts_total{upstream="npm",outcome="fetched"} 4`,
		`pullthrough_fullmirror_artifacts_total{upstream="npm",outcome="refused"} 1`,
		`pullthrough_fullmirror_refused_total{upstream="npm",gate="malfeed"} 1`,
		`pullthrough_fullmirror_fetched_bytes_total{upstream="npm"} 400`,
		`pullthrough_fullmirror_state{upstream="npm",state="following"} 1`,
		`pullthrough_fullmirror_leader 1`,
		`pullthrough_fullmirror_lag{upstream="npm"} 2`,
		`pullthrough_fullmirror_budget_used_bytes{upstream="npm"} 400`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	for _, name := range MetricNames {
		if !strings.Contains(out, "# TYPE "+name+" ") {
			t.Errorf("metric %s not registered", name)
		}
	}
	var nilEngine *Engine
	if s := nilEngine.Status(); s.Enabled || s.Upstreams == nil {
		t.Errorf("nil engine status %+v", s)
	}
}

func TestTheProxysRateLimiterAdmitsEveryFetch(t *testing.T) {
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), func(o *Options) { o.Tenant = "mirror" })
	lim := &countingAdmitter{}
	h.e.SetLimiter(lim)
	h.steps(context.Background(), 10)
	if lim.calls.Load() != int64(fetcher.totalFetches()) || lim.tenant.Load() != "mirror" {
		t.Errorf("limiter admitted %d fetches (as %v), %d were made", lim.calls.Load(), lim.tenant.Load(), fetcher.totalFetches())
	}
	// A refusal is a wait, not a failure.
	lim.refuseNext.Store(2)
	h.follower().mu.Lock()
	h.follower().nextPoll = time.Time{}
	h.follower().mu.Unlock()
	feed.mu.Lock()
	feed.changes["seq:10"] = Batch{Items: []Coordinate{{Name: "e"}}, Next: "seq:11"}
	feed.releases["e"] = []Release{release("e", "1.0.0", 0)}
	feed.mu.Unlock()
	h.steps(context.Background(), 5)
	st := h.diskState()
	if st.Counters.Failed != 0 || fetcher.fetchCount(tarball("e", "1.0.0")) != 1 || st.Cursor != "seq:11" {
		t.Errorf("throttled fetch: %+v cursor %q", st.Counters, st.Cursor)
	}
}

type countingAdmitter struct {
	calls      atomic.Int64
	tenant     atomic.Value
	refuseNext atomic.Int64
}

func (a *countingAdmitter) Admit(_ context.Context, tenant string) (ratelimit.Reservation, ratelimit.Decision) {
	a.tenant.Store(tenant)
	if a.refuseNext.Load() > 0 {
		a.refuseNext.Add(-1)
		return ratelimit.Reservation{}, ratelimit.Decision{Allowed: false, Type: ratelimit.LimitRPS, RetryAfter: 2 * time.Millisecond}
	}
	a.calls.Add(1)
	return ratelimit.Reservation{}, ratelimit.Decision{Allowed: true}
}

func TestRequestsArePacedPerUpstream(t *testing.T) {
	feed := newFakeFeed()
	var items []Coordinate
	for i := 0; i < 5; i++ {
		n := fmt.Sprintf("p%d", i)
		items = append(items, Coordinate{Name: n})
		feed.releases[n] = []Release{release(n, "1.0.0", 0)}
	}
	feed.bootstrap[""] = Batch{Items: items, Next: "seq:1"}
	fetcher := newFakeFetcher()
	s := testSettings("npm")
	s.RequestsPerSecond = 20
	s.Concurrency = 4
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	start := time.Now()
	h.steps(context.Background(), 5)
	// Five fetches at 20/s with a burst of 20 tokens would be instant; the
	// bucket starts full, so pace with a burst of one second's worth: check
	// only that the pacing let everything through and that the limiter is
	// keyed by the upstream.
	if fetcher.totalFetches() != 5 {
		t.Fatalf("%d fetches", fetcher.totalFetches())
	}
	if p, ok := h.e.pace.Policy("npm"); !ok || p.RPS != 20 {
		t.Errorf("pace policy %+v %v", p, ok)
	}
	_ = start
}

func TestAdaptersGetAPacedClientAndAReadThroughTheGateway(t *testing.T) {
	var built Env
	swapAdapter(t, "cargo", func(env Env) (Feed, error) {
		built = env
		return newFakeFeed(), nil
	})
	if err := Followable("cargo"); err != nil {
		t.Fatalf("Followable after Register: %v", err)
	}
	srv := &countingTransport{}
	dir := t.TempDir()
	s := testSettings("crates")
	s.Type = "cargo"
	e, err := New(Options{Dir: dir, Logger: discardLogger(), Upstreams: []Upstream{{
		Settings: s, URL: "https://index.crates.io", UserAgent: "pullthrough-test",
		HTTP: &http.Client{Transport: srv}, Config: map[string]string{"downloadUrl": "https://static.crates.io"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if built.Upstream != "crates" || built.Type != "cargo" || built.URL != "https://index.crates.io" || built.UserAgent != "pullthrough-test" || built.Settings["downloadUrl"] == "" {
		t.Errorf("env %+v", built)
	}
	if built.Dir != filepath.Join(dir, "upstreams", "crates", "feed") {
		t.Errorf("adapter dir %q", built.Dir)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://index.crates.io/config.json", nil)
	if _, err := built.HTTP.Do(req); err != nil {
		t.Fatal(err)
	}
	if srv.n.Load() != 1 {
		t.Errorf("the adapter's client did not use the upstream's transport")
	}
	if _, err := built.Read(context.Background(), "/config.json", "", io.Discard); err == nil {
		t.Errorf("Read before Attach succeeded")
	}
	fetcher := newFakeFetcher()
	e.Attach(fetcher)
	if _, err := built.Read(context.Background(), "/config.json", "", io.Discard); err != nil || fetcher.fetchCount("/config.json") != 1 {
		t.Errorf("Read through the gateway: %v", err)
	}
}

// swapAdapter replaces the adapter registered for a type for the rest of the
// test (registering a second one panics).
func swapAdapter(t *testing.T, typ string, f Factory) {
	t.Helper()
	t.Cleanup(ReplaceAdapter(typ, f))
}

type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Request: r, Header: http.Header{}}, nil
}

// withoutAdapter removes the adapter registered for typ (if any) for the rest
// of the test.
func withoutAdapter(t *testing.T, typ string) {
	t.Helper()
	adaptersMu.Lock()
	old, had := adapters[typ]
	delete(adapters, typ)
	adaptersMu.Unlock()
	t.Cleanup(func() {
		adaptersMu.Lock()
		defer adaptersMu.Unlock()
		if had {
			adapters[typ] = old
		}
	})
}

func TestFollowableExplainsWhy(t *testing.T) {
	withoutAdapter(t, "cran")
	withoutAdapter(t, "apt")
	for typ, want := range map[string]string{
		"docker":    "Docker Hub cannot be followed: its tier is (d), no practical enumeration (see docs/full-mirroring.md#docker)",
		"terraform": "cannot be followed: no feed adapter",
		"cran":      "no feed adapter follows CRAN (R) yet (tier (b)",
		"deb":       "tier (b)",
		"nothing":   "knows no upstream type",
	} {
		err := Followable(typ)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Followable(%q) = %v, want it to say %q", typ, err, want)
		}
	}
}

// Full mirroring is refused, pointing at the page that says why, for every
// type with nothing to follow: the tier-(d) registries and those the catalog
// marks not applicable.
func TestFollowableRefusesTypesWithoutAFeed(t *testing.T) {
	for _, typ := range []string{"docker", "terraform", "swift", "nix", "generic", "git"} {
		err := Followable(typ)
		if err == nil || !strings.Contains(err.Error(), "cannot be followed") || !strings.Contains(err.Error(), "docs/full-mirroring.md#"+typ) {
			t.Errorf("Followable(%q) = %v, want a refusal pointing at docs/full-mirroring.md#%s", typ, err, typ)
		}
		e, _ := Lookup(typ)
		if e.Tier != TierNone && e.Status.State != StateNotApplicable {
			t.Errorf("%s is refused but neither tier (d) nor %q in the catalog", typ, StateNotApplicable)
		}
	}
	// And only those: every other type of the catalog has an adapter.
	refused := map[string]bool{"docker": true, "terraform": true, "swift": true, "nix": true, "generic": true, "git": true}
	for _, e := range Catalog() {
		if err := Followable(e.Type); (err != nil) != refused[e.Type] {
			t.Errorf("Followable(%q) = %v", e.Type, err)
		}
	}
}

func TestEveryAdapterMatchesTheCatalogStatus(t *testing.T) {
	// A type the catalog says is (partly) implemented must have an adapter,
	// and an adapter's type must say so in the catalog: the generated page's
	// status column is what operators read.
	registered := map[string]bool{}
	for _, t := range Adapters() {
		registered[t] = true
	}
	for _, e := range Catalog() {
		impl := e.Tier != TierNone && (e.Status.State == StateImplemented || e.Status.State == StatePartial)
		if impl != registered[e.Type] {
			t.Errorf("%s: catalog status %q (tier %s) but adapter registered: %v", e.Type, e.Status.State, e.Tier, registered[e.Type])
		}
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	withoutAdapter(t, "cran")
	feed := newFakeFeed()
	for name, opts := range map[string]Options{
		"no dir":     {Upstreams: []Upstream{{Settings: testSettings("a"), Feed: feed}}},
		"no budget":  {Dir: t.TempDir(), Upstreams: []Upstream{{Settings: Settings{Upstream: "a", Type: "npm"}, Feed: feed}}},
		"duplicate":  {Dir: t.TempDir(), Upstreams: []Upstream{{Settings: testSettings("a"), Feed: feed}, {Settings: testSettings("a"), Feed: feed}}},
		"no adapter": {Dir: t.TempDir(), Upstreams: []Upstream{{Settings: Settings{Upstream: "a", Type: "cran", ByteBudget: 1}}}},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStartAndCloseRunTheLoop(t *testing.T) {
	feed := twoPageRegistry()
	fetcher := newFakeFetcher()
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	h.e.Start(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for h.e.Status().Upstreams[0].Phase != phaseFollow && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	if h.diskState().Phase != phaseFollow {
		t.Fatalf("the running engine did not finish the enumeration")
	}
	if st := h.e.Status(); st.Running || st.Upstreams[0].State != StateStopped {
		t.Errorf("after Close: running %v state %q", st.Running, st.Upstreams[0].State)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Items finished out of order — while an earlier item was stuck — are kept
// with the batch's progress: a resumed batch does not do them again.
func TestItemsDoneAheadAreNotRedone(t *testing.T) {
	dir := t.TempDir()
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}, Next: "seq:4"}
	for _, n := range []string{"a", "b", "c", "d"} {
		feed.releases[n] = []Release{release(n, "1.0.0", 0)}
	}
	fetcher := newFakeFetcher()
	released := make(chan struct{})
	var bad []FetchResult
	for i := 0; i < 10; i++ {
		bad = append(bad, FetchResult{Status: http.StatusBadGateway})
	}
	fetcher.statuses[tarball("a", "1.0.0")] = bad
	fetcher.onFetch = func(path string, n int) error {
		switch path {
		case tarball("a", "1.0.0"):
			if n == 1 {
				<-released // a's first attempt waits until b, c and d are done
			}
		case tarball("d", "1.0.0"):
			close(released)
		}
		return nil
	}
	s := testSettings("npm")
	s.Concurrency = 2
	h := newHarness(t, dir, feed, fetcher, s, func(o *Options) { o.MaxRounds = 5 })
	h.follower().safeStep(context.Background())
	st := h.diskState()
	if st.Batch == nil || st.Batch.Done != 0 || fmt.Sprint(st.Batch.Ahead) != "[1 2 3]" {
		t.Fatalf("after the stuck round: %+v", st.Batch)
	}
	if q := h.status().Queued; q != 1 {
		t.Errorf("queued %d, want 1", q)
	}
	_ = h.e.Close()

	fetcher.mu.Lock()
	fetcher.statuses[tarball("a", "1.0.0")] = nil
	fetcher.onFetch = nil
	fetcher.mu.Unlock()
	feed2 := newFakeFeed()
	feed2.releases = feed.releases
	h2 := newHarness(t, dir, feed2, fetcher, s, nil)
	h2.steps(context.Background(), 5)
	if calls := feed2.callsWithPrefix("releases:"); fmt.Sprint(calls) != "[releases:a]" {
		t.Errorf("the resumed batch listed %v; only a was left to do", calls)
	}
	if st := h2.diskState(); st.Cursor != "seq:4" || st.Batch != nil {
		t.Errorf("after the resumed batch: %+v", st)
	}
}

// --- regressions found by the independent review -----------------------------

func alwaysFailing(status int) []FetchResult {
	var out []FetchResult
	for i := 0; i < 100; i++ {
		out = append(out, FetchResult{Status: status})
	}
	return out
}

// Giving up on one file (after MaxRounds) leaves the package's other files to
// be mirrored, and counts the file as failed.
func TestGivingUpOnAFileKeepsThePackagesOtherFiles(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "pkg"}}, Next: "seq:1"}
	feed.releases["pkg"] = []Release{release("pkg", "1.0.0", 0), release("pkg", "2.0.0", 0), release("pkg", "3.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.statuses[tarball("pkg", "1.0.0")] = alwaysFailing(http.StatusBadGateway)
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	h.steps(context.Background(), 40)
	st := h.diskState()
	if st.Cursor != "seq:1" {
		t.Fatalf("the batch did not complete: %+v", st.Batch)
	}
	if fetcher.fetchCount(tarball("pkg", "2.0.0")) != 1 || fetcher.fetchCount(tarball("pkg", "3.0.0")) != 1 {
		t.Errorf("the package's other files were dropped: 2.0.0=%d 3.0.0=%d", fetcher.fetchCount(tarball("pkg", "2.0.0")), fetcher.fetchCount(tarball("pkg", "3.0.0")))
	}
	if c := st.Counters; c.Failed != 1 || c.Fetched != 2 || c.Packages != 1 {
		t.Errorf("counters %+v", c)
	}
}

// One worker's failed round stops the batch; the other workers' items are not
// charged a failed round for it.
func TestAFailedRoundIsNotChargedToOtherWorkers(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "bad"}, {Name: "good"}}, Next: "seq:1"}
	feed.releases["bad"] = []Release{release("bad", "1.0.0", 0)}
	feed.releases["good"] = []Release{release("good", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.statuses[tarball("bad", "1.0.0")] = alwaysFailing(http.StatusBadGateway)
	fetcher.statuses[tarball("good", "1.0.0")] = []FetchResult{{Status: http.StatusServiceUnavailable}}
	badDone := make(chan struct{})
	fetcher.onFetch = func(path string, n int) error {
		switch {
		case path == tarball("bad", "1.0.0") && n == 3:
			close(badDone)
		case path == tarball("good", "1.0.0") && n == 1:
			<-badDone
			time.Sleep(50 * time.Millisecond) // bad's round has failed by now
		}
		return nil
	}
	s := testSettings("npm")
	s.Concurrency = 2
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	h.follower().safeStep(context.Background())
	f := h.follower()
	f.mu.Lock()
	stuck := fmt.Sprint(f.stuck)
	errs := fmt.Sprint(f.st.RecentErrors)
	f.mu.Unlock()
	if strings.Contains(errs, "good") || stuck != "map[0:1]" {
		t.Errorf("the healthy item was charged a failed round: stuck=%s errors=%s", stuck, errs)
	}
}

// A network timeout (which wraps context.DeadlineExceeded) is a failure of
// the item, not the engine's end: it fails a round, is recorded, and is given
// up after MaxRounds instead of stalling the feed.
func TestANetworkTimeoutIsAFailureNotAStop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 20 * time.Millisecond}}
	_, terr := c.Get(srv.URL)
	if terr == nil || !errors.Is(terr, context.DeadlineExceeded) {
		t.Fatalf("expected a transport timeout wrapping DeadlineExceeded, got %v", terr)
	}
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "slow"}, {Name: "fine"}}, Next: "seq:1"}
	feed.releases["fine"] = []Release{release("fine", "1.0.0", 0)}
	feed.relErr["slow"] = fmt.Errorf("listing slow: %w", terr)
	h := newHarness(t, t.TempDir(), feed, newFakeFetcher(), testSettings("npm"), nil)
	h.steps(context.Background(), 40)
	st := h.diskState()
	if st.Cursor != "seq:1" || st.Counters.PackageErrors != 1 || len(st.RecentErrors) == 0 {
		t.Errorf("after a timing-out package: cursor %q counters %+v errors %d", st.Cursor, st.Counters, len(st.RecentErrors))
	}
	if calls := len(feed.callsWithPrefix("releases:slow")); calls != h.e.opts.MaxAttempts*h.e.opts.MaxRounds {
		t.Errorf("%d version-list requests, want %d", calls, h.e.opts.MaxAttempts*h.e.opts.MaxRounds)
	}
}

// The files an item dealt with in a round that then failed are not dealt with
// again: a refused file is asked for once and counted once.
func TestFilesOfAFailedRoundAreNotRedone(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "pkg"}}, Next: "seq:1"}
	feed.releases["pkg"] = []Release{release("pkg", "1.0.0", 0), release("pkg", "2.0.0", 0), release("pkg", "3.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.gate[tarball("pkg", "1.0.0")] = "malfeed"
	fetcher.statuses[tarball("pkg", "3.0.0")] = []FetchResult{{Status: http.StatusBadGateway}, {Status: http.StatusBadGateway}, {Status: http.StatusBadGateway}}
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	h.steps(context.Background(), 20)
	st := h.diskState()
	if st.Cursor != "seq:1" {
		t.Fatalf("not committed: %+v", st.Batch)
	}
	if n := fetcher.fetchCount(tarball("pkg", "1.0.0")); n != 1 || st.Counters.Refused != 1 {
		t.Errorf("the refused file was fetched %d times, Refused=%d", n, st.Counters.Refused)
	}
	if n := fetcher.fetchCount(tarball("pkg", "2.0.0")); n != 1 || st.Counters.Skipped[SkipCached] != 0 {
		t.Errorf("the fetched file was asked for %d times, cached skips %d", n, st.Counters.Skipped[SkipCached])
	}
	if st.Counters.Fetched != 2 || st.Counters.Packages != 1 {
		t.Errorf("counters %+v", st.Counters)
	}
}

// Budget held by a fetch in flight is not spent budget: a file that fits once
// the other fetch is done waits for it instead of declaring the budget spent.
func TestReservationsInFlightDoNotSpendTheBudget(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a"}, {Name: "b"}}, Next: "seq:1"}
	feed.releases["a"] = []Release{release("a", "1.0.0", 600)}
	feed.releases["b"] = []Release{release("b", "1.0.0", 600)}
	fetcher := newFakeFetcher()
	fetcher.gate[tarball("a", "1.0.0")] = "malfeed"
	fetcher.sizes[tarball("b", "1.0.0")] = 600
	s := testSettings("npm")
	s.Concurrency = 2
	s.ByteBudget = 1000
	// a must hold its reservation when b asks for its share: b's version
	// list is answered only once a's fetch — after its reservation — has
	// begun. (Left to the scheduler, b could go first, and then a correctly
	// finds no room: the budget is spent with b's 600 bytes.)
	aFetching := make(chan struct{})
	var once sync.Once
	fetcher.onFetch = func(path string, n int) error {
		if path == tarball("a", "1.0.0") {
			once.Do(func() { close(aFetching) })
			time.Sleep(200 * time.Millisecond) // b asks for its share meanwhile
		}
		return nil
	}
	feed.relHook = func(name string) {
		if name == "b" {
			select {
			case <-aFetching:
			case <-time.After(10 * time.Second):
				t.Errorf("a's fetch did not begin")
			}
		}
	}
	h := newHarness(t, t.TempDir(), feed, fetcher, s, nil)
	h.steps(context.Background(), 5)
	us := h.status()
	if us.Budget.Exhausted || h.audit.has("budget-exhausted") {
		t.Errorf("budget marked spent with %d of %d bytes used", us.Budget.Used, us.Budget.Limit)
	}
	if fetcher.fetchCount(tarball("b", "1.0.0")) != 1 || us.Budget.Used != 600 || us.Cursor != "seq:1" {
		t.Errorf("b fetched %d times, used %d, cursor %q", fetcher.fetchCount(tarball("b", "1.0.0")), us.Budget.Used, us.Cursor)
	}
}

// --- refusals that are not verdicts -------------------------------------------

// A gate's "not yet" (a maturity cooldown's Retry-After, a fail-closed refusal
// of a scanner that could not judge the file) defers the file: the batch goes
// on, the file waits in the deferred queue — across a restart — and is asked
// for again when it is due.
func TestNotYetRefusalsAreDeferred(t *testing.T) {
	dir := t.TempDir()
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "fresh"}, {Name: "unjudged"}, {Name: "ok"}}, Next: "seq:1"}
	for _, n := range []string{"fresh", "unjudged", "ok"} {
		feed.releases[n] = []Release{release(n, "1.0.0", 0)}
	}
	fetcher := newFakeFetcher()
	fetcher.statuses[tarball("fresh", "1.0.0")] = []FetchResult{{Status: http.StatusForbidden, Gate: "maturity", Code: "cooldown", RetryAfter: 3 * time.Hour}}
	fetcher.statuses[tarball("unjudged", "1.0.0")] = []FetchResult{{Status: http.StatusForbidden, Gate: "avscan", Code: "engine-unavailable", Action: "fail-closed"}}
	var mu sync.Mutex
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	h := newHarness(t, dir, feed, fetcher, testSettings("npm"), func(o *Options) { o.Now = clock })
	h.steps(context.Background(), 10)
	st := h.diskState()
	if st.Cursor != "seq:1" || st.Counters.Refused != 0 || st.Counters.Deferred != 2 || st.Counters.Fetched != 1 {
		t.Fatalf("after the batch: cursor %q counters %+v", st.Cursor, st.Counters)
	}
	us := h.status()
	if us.Deferred != 2 || !us.NextDeferred.Equal(now.Add(deferUnjudged)) {
		t.Errorf("deferred %d, next %s", us.Deferred, us.NextDeferred)
	}
	_ = h.e.Close()

	// The queue survives a restart; the unjudged file is due first.
	h2 := newHarness(t, dir, feed, fetcher, testSettings("npm"), func(o *Options) { o.Now = clock })
	advance(deferUnjudged + time.Minute)
	h2.follower().safeStep(context.Background())
	if n := fetcher.fetchCount(tarball("unjudged", "1.0.0")); n != 2 {
		t.Errorf("the unjudged file was asked for %d times, want 2", n)
	}
	if n := fetcher.fetchCount(tarball("fresh", "1.0.0")); n != 1 {
		t.Errorf("the file in its cooldown was asked for again before it was due (%d)", n)
	}
	if us := h2.status(); us.Deferred != 1 || us.Counters.Fetched != 2 {
		t.Errorf("after the first is due: deferred %d counters %+v", us.Deferred, us.Counters)
	}
	advance(3 * time.Hour)
	h2.follower().safeStep(context.Background())
	if us := h2.status(); us.Deferred != 0 || us.Counters.Fetched != 3 || us.Counters.Refused != 0 {
		t.Errorf("after the cooldown: deferred %d counters %+v", us.Deferred, us.Counters)
	}
}

// A gate that keeps saying "not yet" is taken at its word in the end.
func TestEndlessDeferralsBecomeAVerdict(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "never"}}, Next: "seq:1"}
	feed.releases["never"] = []Release{release("never", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	var later []FetchResult
	for i := 0; i < maxDeferrals+5; i++ {
		later = append(later, FetchResult{Status: http.StatusForbidden, Gate: "llmpkgscan", Code: "provider-timeout", RetryAfter: 30 * time.Second})
	}
	fetcher.statuses[tarball("never", "1.0.0")] = later
	var mu sync.Mutex
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), func(o *Options) { o.Now = clock })
	h.steps(context.Background(), 5)
	for i := 0; i < maxDeferrals+2; i++ {
		mu.Lock()
		now = now.Add(2 * time.Minute)
		mu.Unlock()
		h.follower().safeStep(context.Background())
	}
	us := h.status()
	if us.Deferred != 0 || us.Counters.Refused != 1 || us.Counters.RefusedBy["llmpkgscan"] != 1 || us.Counters.Deferred != maxDeferrals {
		t.Errorf("deferred %d counters %+v", us.Deferred, us.Counters)
	}
}

// A refusal that would hold for every file of the upstream — the mirror's
// roles do not grant it — is no verdict: the batch stops, the reason is
// recorded, and the upstream is left alone until an operator fixes it.
func TestAccessControlRefusalHoldsTheUpstream(t *testing.T) {
	feed := newFakeFeed()
	feed.bootstrap[""] = Batch{Items: []Coordinate{{Name: "a"}, {Name: "b"}}, Next: "seq:1"}
	feed.releases["a"] = []Release{release("a", "1.0.0", 0)}
	feed.releases["b"] = []Release{release("b", "1.0.0", 0)}
	fetcher := newFakeFetcher()
	fetcher.statuses[tarball("a", "1.0.0")] = []FetchResult{{Status: http.StatusForbidden, Gate: "access-control", Code: "forbidden", Reason: "no role grants upstream npm"}}
	h := newHarness(t, t.TempDir(), feed, fetcher, testSettings("npm"), nil)
	wait := h.follower().safeStep(context.Background())
	us := h.status()
	if us.Counters.Refused != 0 || us.Queued != 2 || us.BackoffUntil.IsZero() || wait < time.Minute {
		t.Fatalf("held: counters %+v queued %d backoff %s wait %s", us.Counters, us.Queued, us.BackoffUntil, wait)
	}
	if len(us.RecentErrors) != 1 || !strings.Contains(us.RecentErrors[0].Message, "no role grants upstream npm") {
		t.Errorf("errors %+v", us.RecentErrors)
	}
	if fetcher.fetchCount(tarball("b", "1.0.0")) != 0 {
		t.Error("the mirror went on fetching while held")
	}
}

func TestClassifyRefusal(t *testing.T) {
	for _, tc := range []struct {
		res  FetchResult
		want refusal
	}{
		{FetchResult{Gate: "malfeed"}, refusalVerdict},
		{FetchResult{Gate: "vulnscan", Action: "block"}, refusalVerdict},
		{FetchResult{Gate: "maturity", RetryAfter: time.Hour}, refusalLater},
		{FetchResult{Gate: "avscan", Action: "fail-closed"}, refusalLater},
		{FetchResult{Gate: "access-control"}, refusalHold},
		{FetchResult{Gate: "snapshot"}, refusalHold},
		{FetchResult{Gate: "lockdown"}, refusalLockdown},
	} {
		if got := classifyRefusal(tc.res); got != tc.want {
			t.Errorf("classifyRefusal(%+v) = %d, want %d", tc.res, got, tc.want)
		}
	}
}
