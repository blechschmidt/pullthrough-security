package userlinks

// Faults of the registry found in review (Task 177): what a failed read, a
// listing taken while another replica cleans up, clocks that disagree, a spent
// lookup budget and concurrent requests must not do to the guarantees in
// docs/user-links.md ("Several replicas").

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// splitListStore answers one listing in two halves, taken before and after a
// hook: what a paged S3 listing, or DirStore's listing of one folder after the
// other, sees when another replica deletes objects meanwhile.
type splitListStore struct {
	Store
	mu      sync.Mutex
	between func()
}

func (s *splitListStore) List(ctx context.Context) ([]Object, error) {
	first, err := s.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	hook := s.between
	s.between = nil
	s.mu.Unlock()
	if hook == nil {
		return first, nil
	}
	hook()
	second, err := s.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, o := range first {
		if o.Name < "revoked/" { // block/ and link/: listed before the hook
			out = append(out, o)
		}
	}
	for _, o := range second {
		if o.Name >= "revoked/" { // revoked/ and usage/: after it
			out = append(out, o)
		}
	}
	return out, nil
}

// flakyReads fails the next n reads of objects whose name starts with a
// prefix, as a store does that is briefly overloaded.
type flakyReads struct {
	Store
	mu   sync.Mutex
	fail map[string]int
}

func (f *flakyReads) Get(ctx context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	for prefix, n := range f.fail {
		if n > 0 && strings.HasPrefix(name, prefix) {
			f.fail[prefix] = n - 1
			f.mu.Unlock()
			return nil, errors.New("503 SlowDown")
		}
	}
	f.mu.Unlock()
	return f.Store.Get(ctx, name)
}

func (f *flakyReads) set(fail map[string]int) {
	f.mu.Lock()
	f.fail = fail
	f.mu.Unlock()
}

// The cleaning replica deletes a link and, later, its revocation. Another
// replica that lists the store meanwhile — the link before the deletion, the
// revocations after it — must not lose the revocation of a link it still has.
func TestRevocationIsKeptWhileItsLinkIsListed(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	leader := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "leader" })
	tok, info := mustIssue(t, leader, alice, "laptop") // works for 90 days
	if _, err := leader.Revoke(ctx, info.ID, "alice", "stolen laptop"); err != nil {
		t.Fatal(err)
	}
	split := &splitListStore{Store: inner}
	replica := newTestRegistry(t, split, c, func(cfg *RegistryConfig) { cfg.Node = "replica" })
	replica.SetLeaderGate(func() bool { return false })
	if _, err := replica.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("before: %v", err)
	}

	// Thirty days on, the leader cleans up — twice, so that the revocation
	// would go as well — while the replica is half-way through a listing.
	c.Advance(retainEnded + time.Minute)
	split.mu.Lock()
	split.between = func() {
		_ = leader.Sync(ctx)
		_ = leader.Sync(ctx)
	}
	split.mu.Unlock()
	_ = replica.Sync(ctx)
	if _, err := inner.Get(ctx, linkObject(hashToken(tok))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the leader did not delete the link: %v", err)
	}
	if _, err := replica.Resolve(ctx, tok); err == nil {
		t.Fatal("a revoked link works on a replica that listed the store while the leader cleaned up")
	}
	_ = replica.Sync(ctx)
	if _, err := replica.Resolve(ctx, tok); err == nil {
		t.Fatal("a revoked link works after the next refresh")
	}
}

// The revocation of a deleted link is removed one clean-up after the link: a
// replica that reads a link record always finds its revocation as well.
func TestCleanUpRemovesARevocationAfterItsLink(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := NewMemoryStore()
	r := newTestRegistry(t, store, c, nil)
	tok, info := mustIssue(t, r, alice, "laptop")
	if _, err := r.Revoke(ctx, info.ID, "alice", ""); err != nil {
		t.Fatal(err)
	}
	c.Advance(retainEnded + time.Minute)
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, linkObject(hashToken(tok))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the link was not deleted: %v", err)
	}
	if _, err := store.Get(ctx, revokedObject(info.ID)); err != nil {
		t.Fatalf("the revocation went with its link, in the same pass: %v", err)
	}
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, revokedObject(info.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the revocation of a deleted link is still there one clean-up later: %v", err)
	}
}

// A block record that cannot be read once must not pin a made-up watermark: a
// link the user created after the real one works again once the record can be
// read, and no clean-up deletes it.
func TestUnreadableBlockRecordDoesNotPinAWatermark(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a" })
	a.SetLeaderGate(func() bool { return false })
	if _, _, err := a.RevokeUser(ctx, bob.Subject, "ops", "reset"); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Minute)
	tok, info := mustIssue(t, a, bob, "after the reset")
	if _, err := a.Resolve(ctx, tok); err != nil {
		t.Fatalf("the link created after the reset: %v", err)
	}

	c.Advance(10 * time.Minute)
	flaky := &flakyReads{Store: inner, fail: map[string]int{"block/": 1}}
	replica := newTestRegistry(t, flaky, c, func(cfg *RegistryConfig) { cfg.Node = "c" })
	// Not knowing the block, the replica refuses everything of bob's for now.
	if _, err := replica.Resolve(ctx, tok); err == nil {
		t.Fatal("a link was let through while its user's block record could not be read")
	}
	if err := replica.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Resolve(ctx, tok); err != nil {
		t.Fatalf("the link still refused once the block record could be read: %v", err)
	}

	// Thirty days later the replica cleans up: the link has sixty days to go.
	c.Advance(retainEnded + time.Hour)
	if err := replica.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Get(ctx, linkObject(hashToken(tok))); err != nil {
		t.Fatalf("clean-up deleted the valid link %s: %v", info.ID, err)
	}
	if _, err := a.Resolve(ctx, tok); err != nil {
		t.Fatalf("on the replica that created it: %v", err)
	}
}

// A block known from an earlier reading keeps meaning what it meant when its
// record cannot be read again: no fallback replaces it.
func TestKnownBlockSurvivesAnUnreadableRecord(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a" })
	flaky := &flakyReads{Store: inner}
	b := newTestRegistry(t, flaky, c, func(cfg *RegistryConfig) { cfg.Node = "b" })
	if _, _, err := a.RevokeUser(ctx, bob.Subject, "ops", "first"); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Minute)
	tok, _ := mustIssue(t, a, bob, "after the first reset")
	c.Advance(time.Minute)
	// The record changes (a second reset) and cannot be read at first.
	if _, _, err := a.RevokeUser(ctx, bob.Subject, "ops", "second"); err != nil {
		t.Fatal(err)
	}
	flaky.set(map[string]int{"block/": 1})
	_ = b.Sync(ctx)
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("a link the second reset ended: %v", err)
	}
}

// Clean-up after a refresh that could not read a link record must not decide
// that the link is gone and delete its revocation.
func TestCleanUpWaitsForACompleteRefresh(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a" })
	a.SetLeaderGate(func() bool { return false })
	tok, info := mustIssue(t, a, alice, "laptop")
	if _, err := a.Revoke(ctx, info.ID, "ops", "stolen"); err != nil {
		t.Fatal(err)
	}
	c.Advance(retainEnded + time.Minute)
	flaky := &flakyReads{Store: inner, fail: map[string]int{"link/": 1}}
	cleaner := newTestRegistry(t, flaky, c, func(cfg *RegistryConfig) { cfg.Node = "c" })
	if _, err := inner.Get(ctx, revokedObject(info.ID)); err != nil {
		t.Fatalf("a refresh that could not read the link deleted its revocation: %v", err)
	}
	_ = cleaner.Sync(ctx)
	_ = a.Sync(ctx)
	for name, r := range map[string]*Registry{"the cleaning replica": cleaner, "the other replica": a} {
		if _, err := r.Resolve(ctx, tok); err == nil {
			t.Errorf("%s: a revoked link works again", name)
		}
	}
}

// Everything issued to a user before a revocation ends with it — also a link
// created by a replica whose clock is ahead, or before the clock was set back.
func TestRevokeUserCoversLinksDatedLater(t *testing.T) {
	ctx := context.Background()
	slow, fast := newClock(), newClock()
	fast.Advance(5 * time.Second)
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, fast, func(cfg *RegistryConfig) { cfg.Node = "a" })
	b := newTestRegistry(t, inner, slow, func(cfg *RegistryConfig) { cfg.Node = "b" })
	tok, _ := mustIssue(t, a, bob, "laptop")
	slow.Advance(time.Second)
	fast.Advance(time.Second)
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	n, _, err := b.RevokeUser(ctx, bob.Subject, "ops", "left the company")
	if err != nil || n != 1 {
		t.Fatalf("RevokeUser = %d, %v", n, err)
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*Registry{"the revoking replica": b, "the replica with the fast clock": a} {
		if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
			t.Errorf("%s: the link of a revoked user resolves: %v", name, err)
		}
	}

	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, nil)
	tok2, _ := mustIssue(t, r, bob, "desktop")
	c.Advance(-2 * time.Second)
	if _, _, err := r.RevokeUser(ctx, bob.Subject, "ops", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, tok2); reasonOf(t, err) != ReasonRevoked {
		t.Errorf("after the clock was set back: %v", err)
	}
}

// An operator who types a user's address with other capitals means the user
// the registry knows.
func TestRevokeUserMatchesTheKnownSpelling(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, nil)
	tok, _ := mustIssue(t, r, alice, "laptop")
	c.Advance(time.Second)
	n, _, err := r.RevokeUser(ctx, "Alice@Example.COM", "ops", "")
	if err != nil || n != 1 {
		t.Fatalf("RevokeUser = %d, %v", n, err)
	}
	if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("the link resolves: %v", err)
	}
	if r.SessionValid(alice.Subject, c.Now().Add(-time.Minute)) {
		t.Fatal("the user's session survived")
	}
}

// A watermark of this replica's that the store lost to a concurrent, earlier
// write is written back by the next refresh.
func TestStoredWatermarkDoesNotMoveBack(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := NewMemoryStore()
	r := newTestRegistry(t, store, c, nil)
	if _, _, err := r.RevokeUser(ctx, bob.Subject, "ops", "later"); err != nil {
		t.Fatal(err)
	}
	later := c.Now()
	// Another replica's revocation, a moment earlier, lands in the store last.
	earlier, _ := json.Marshal(Block{Subject: bob.Subject, NotBefore: later.Add(-time.Second), By: "ops"})
	if err := store.Put(ctx, blockObject(bob.Subject), earlier); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(ctx, blockObject(bob.Subject))
	if err != nil {
		t.Fatal(err)
	}
	var stored Block
	if err := json.Unmarshal(data, &stored); err != nil || stored.NotBefore.Before(later) {
		t.Fatalf("the store keeps the earlier watermark %v (want %v): %v", stored.NotBefore, later, err)
	}
}

// With the lookup budget spent — by anyone, with tokens that merely look
// right — a valid link this replica has not seen yet is "unavailable" (ask
// again), never "unknown", which a package manager takes as final.
func TestSpentLookupBudgetAnswersUnavailable(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a" })
	b := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "b" })
	for i := 0; i < missBurst+1; i++ {
		junk, _ := NewToken()
		_, _ = b.Resolve(ctx, junk)
	}
	tok, _ := mustIssue(t, a, alice, "new")
	if _, err := b.Resolve(ctx, tok); reasonOf(t, err) != ReasonUnavailable {
		t.Fatalf("a valid link, with the budget spent: %v (want unavailable)", err)
	}
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok); err != nil {
		t.Fatalf("after the next refresh: %v", err)
	}

	// The links of a first refresh that could read none of them: each works,
	// or is "unavailable" — none is "unknown".
	seed := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "seed"; cfg.MaxLinksPerUser = -1 })
	var tokens []string
	for i := 0; i < 150; i++ {
		tk, _ := mustIssue(t, seed, Identity{Subject: fmt.Sprintf("u%d@example.com", i)}, "x")
		tokens = append(tokens, tk)
	}
	flaky := &flakyReads{Store: inner, fail: map[string]int{"link/": 1 << 30}}
	fresh := newTestRegistry(t, flaky, c, func(cfg *RegistryConfig) { cfg.Node = "fresh" })
	flaky.set(nil)
	for _, tk := range tokens {
		if _, err := fresh.Resolve(ctx, tk); err != nil && reasonOf(t, err) != ReasonUnavailable {
			t.Fatalf("a valid link after a partial first refresh: %v", err)
		}
	}
}

// The lookup of a token this replica does not know reads a damaged block
// record as a refresh does: everything issued to the user so far is revoked.
func TestLookupHonoursADamagedBlock(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a" })
	b := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "b" })
	tok, _ := mustIssue(t, a, bob, "x")
	c.Advance(time.Second)
	if err := inner.Put(ctx, blockObject(bob.Subject), []byte(`{"subject":"bob@example.com","notBefore":"garbage"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("by lookup: %v", err)
	}
	_ = b.Sync(ctx)
	if _, err := b.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("after a refresh: %v", err)
	}
}

// slowPuts delays every write, widening the window between counting a user's
// links and writing a new one.
type slowPuts struct{ Store }

func (s slowPuts) Put(ctx context.Context, name string, data []byte) error {
	time.Sleep(20 * time.Millisecond)
	return s.Store.Put(ctx, name, data)
}

// Concurrent requests do not get a user past maxLinksPerUser.
func TestMaxLinksPerUserHoldsUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t, slowPuts{NewMemoryStore()}, newClock(), func(cfg *RegistryConfig) { cfg.MaxLinksPerUser = 2 })
	var issued atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := r.Issue(ctx, alice, IssueOptions{}); err == nil {
				issued.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := issued.Load(); n != 2 {
		t.Fatalf("%d links issued with maxLinksPerUser=2", n)
	}
}

// Every entry point at once, on two replicas sharing a store, with clean-up
// and usage records in play — for the race detector.
func TestRegistryUnderConcurrentUse(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a"; cfg.MaxLinksPerUser = -1; cfg.LinkTTL = time.Hour })
	b := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "b"; cfg.MaxLinksPerUser = -1; cfg.LinkTTL = time.Hour })
	var tokens sync.Map
	var wg sync.WaitGroup
	deadline := time.Now().Add(time.Second)
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := a
			if g%2 == 1 {
				r = b
			}
			for i := 0; time.Now().Before(deadline); i++ {
				switch (i + g) % 11 {
				case 0:
					if tk, info, err := r.Issue(ctx, Identity{Subject: fmt.Sprintf("u%d", i%4)}, IssueOptions{}); err == nil {
						tokens.Store(tk, info.ID)
					}
				case 1:
					tokens.Range(func(k, _ any) bool { _, _ = r.Resolve(ctx, k.(string)); return i%3 != 0 })
				case 2:
					tokens.Range(func(_, v any) bool { _, _ = r.Revoke(ctx, v.(string), "x", ""); return false })
				case 3:
					_, _, _ = r.RevokeUser(ctx, fmt.Sprintf("u%d", i%4), "ops", "")
				case 4:
					_ = r.Sync(ctx)
				case 5:
					tokens.Range(func(_, v any) bool { r.Touch(v.(string), "10.0.0.1", "ua"); return i%2 == 0 })
				case 6:
					r.flushUsage(ctx)
				case 7:
					_ = r.List(Filter{State: StateActive})
					_ = r.Stats()
				case 8:
					junk, _ := NewToken()
					_, _ = r.Resolve(ctx, junk)
				case 9:
					_ = r.SessionValid("u1", c.Now())
				case 10:
					if g == 0 && i%50 == 0 {
						c.Advance(retainEnded / 3)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	a.Close()
	b.Close()
}

// A sign-in session ended by "revoke everything of this user" on one replica
// cannot create a link on another that has not refreshed since: the link would
// be dated after the revocation, and work.
func TestEndedSessionCannotCreateALinkElsewhere(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	a := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "a" })
	b := newTestRegistry(t, inner, c, func(cfg *RegistryConfig) { cfg.Node = "b" })
	signedIn := c.Now()
	c.Advance(time.Minute)
	if _, _, err := a.RevokeUser(ctx, bob.Subject, "ops", "left the company"); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Second)
	if !b.SessionValid(bob.Subject, signedIn) {
		t.Fatal("precondition: replica B already knows of the revocation")
	}
	if _, _, err := b.Issue(ctx, bob, IssueOptions{SessionIssuedAt: signedIn}); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("Issue with an ended session = %v, want ErrSessionEnded", err)
	}
	if b.SessionValid(bob.Subject, signedIn) {
		t.Fatal("replica B did not remember the revocation it read")
	}
	// A session that began after the revocation is fine.
	if _, _, err := b.Issue(ctx, bob, IssueOptions{SessionIssuedAt: c.Now()}); err != nil {
		t.Fatalf("Issue with a new session: %v", err)
	}
}
