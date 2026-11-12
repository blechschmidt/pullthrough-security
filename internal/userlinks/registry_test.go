package userlinks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a clock the test sets.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// spyStore wraps a Store: it counts operations, can be told to fail, and can
// run a hook in the middle of one.
type spyStore struct {
	Store
	mu       sync.Mutex
	gets     map[string]int
	puts     map[string]int
	deletes  map[string]int
	lists    int
	failList error
	failGet  error
	failPut  error
	// afterList runs after a listing has been taken, before it is returned.
	afterList func()
}

func newSpyStore(inner Store) *spyStore {
	return &spyStore{Store: inner, gets: map[string]int{}, puts: map[string]int{}, deletes: map[string]int{}}
}

func (s *spyStore) List(ctx context.Context) ([]Object, error) {
	s.mu.Lock()
	s.lists++
	fail, hook := s.failList, s.afterList
	s.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	objs, err := s.Store.List(ctx)
	if hook != nil {
		hook()
	}
	return objs, err
}

func (s *spyStore) Get(ctx context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	s.gets[name]++
	fail := s.failGet
	s.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	return s.Store.Get(ctx, name)
}

func (s *spyStore) Put(ctx context.Context, name string, data []byte) error {
	s.mu.Lock()
	s.puts[name]++
	fail := s.failPut
	s.mu.Unlock()
	if fail != nil {
		return fail
	}
	return s.Store.Put(ctx, name, data)
}

func (s *spyStore) Delete(ctx context.Context, name string) error {
	s.mu.Lock()
	s.deletes[name]++
	s.mu.Unlock()
	return s.Store.Delete(ctx, name)
}

func (s *spyStore) getCount(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for name, c := range s.gets {
		if strings.HasPrefix(name, prefix) {
			n += c
		}
	}
	return n
}

func (s *spyStore) set(fn func(*spyStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

func newTestRegistry(t *testing.T, store Store, c *clock, mutate func(*RegistryConfig)) *Registry {
	t.Helper()
	cfg := RegistryConfig{Store: store, Now: c.Now, Node: "node-a", SessionTTL: time.Hour}
	if mutate != nil {
		mutate(&cfg)
	}
	r, err := NewRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var alice = Identity{Subject: "alice@example.com", Name: "Alice", Email: "alice@example.com", Team: "platform", Roles: []string{"dev"}}
var bob = Identity{Subject: "bob@example.com", Name: "Bob", Email: "bob@example.com", Team: "payments"}

func mustIssue(t *testing.T, r *Registry, id Identity, label string) (string, Info) {
	t.Helper()
	tok, info, err := r.Issue(context.Background(), id, IssueOptions{Label: label, From: "10.0.0.5"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok, info
}

func reasonOf(t *testing.T, err error) Reason {
	t.Helper()
	var re *ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("error %v (%T) is not a *ResolveError", err, err)
	}
	return re.Reason
}

func TestIssueAndResolve(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := NewMemoryStore()
	r := newTestRegistry(t, store, c, nil)

	tok, info := mustIssue(t, r, alice, "  laptop‮ ")
	if !WellFormed(tok) {
		t.Fatalf("Issue returned %q, which is not a token", tok)
	}
	if info.State != StateActive || info.Subject != alice.Subject || info.Label != "laptop" || info.CreatedFrom != "10.0.0.5" {
		t.Fatalf("issued link = %+v", info)
	}
	if info.ExpiresAt == nil || !info.ExpiresAt.Equal(c.Now().Add(DefaultLinkTTL)) {
		t.Fatalf("expiry = %v, want the default lifetime from now", info.ExpiresAt)
	}

	link, err := r.Resolve(ctx, tok)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.ID != info.ID || link.Subject != alice.Subject || link.Team != "platform" || len(link.Roles) != 1 || link.Roles[0] != "dev" {
		t.Fatalf("resolved link = %+v", link)
	}
	// What Resolve hands out is a copy; changing it does not change the registry.
	link.Roles[0] = "admin"
	link.Subject = "mallory"
	again, _ := r.Resolve(ctx, tok)
	if again.Roles[0] != "dev" || again.Subject != alice.Subject {
		t.Fatalf("a caller changed the registry's record through the link it was given: %+v", again)
	}

	// The store holds the link under the hash of its token — and nowhere the
	// token itself.
	objs, _ := store.List(ctx)
	if len(objs) != 1 || objs[0].Name != linkObject(hashToken(tok)) {
		t.Fatalf("stored objects = %v", objs)
	}
	data, _ := store.Get(ctx, objs[0].Name)
	if strings.Contains(string(data), tok) || strings.Contains(string(data), tok[len(TokenPrefix):len(TokenPrefix)+12]) {
		t.Fatalf("the stored record contains token material: %s", data)
	}
	if !strings.Contains(string(data), `"tokenHash":"`+hashToken(tok)+`"`) {
		t.Fatalf("the stored record does not carry the token hash: %s", data)
	}

	for name, bad := range map[string]string{"empty": "", "not a token": "hunter2", "truncated": tok[:len(tok)-2]} {
		if _, err := r.Resolve(ctx, bad); reasonOf(t, err) != ReasonMalformed {
			t.Errorf("%s: reason = %v, want malformed", name, reasonOf(t, err))
		}
	}
	other, _ := NewToken()
	if _, err := r.Resolve(ctx, other); reasonOf(t, err) != ReasonUnknown {
		t.Errorf("a token nobody issued: reason = %v, want unknown", reasonOf(t, err))
	}
}

func TestLinkLifetime(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.LinkTTL = 48 * time.Hour })

	tok, info := mustIssue(t, r, alice, "ci")
	if !info.ExpiresAt.Equal(c.Now().Add(48 * time.Hour)) {
		t.Fatalf("expiry = %v, want 48h from now", info.ExpiresAt)
	}
	// A shorter lifetime may be asked for; a longer one is cut to the limit.
	short, shortInfo, _ := r.Issue(ctx, alice, IssueOptions{TTL: time.Hour})
	_, longInfo, _ := r.Issue(ctx, alice, IssueOptions{TTL: 1000 * time.Hour})
	if !shortInfo.ExpiresAt.Equal(c.Now().Add(time.Hour)) || !longInfo.ExpiresAt.Equal(c.Now().Add(48*time.Hour)) {
		t.Fatalf("expiries = %v / %v", shortInfo.ExpiresAt, longInfo.ExpiresAt)
	}

	c.Advance(time.Hour - time.Second)
	if _, err := r.Resolve(ctx, short); err != nil {
		t.Fatalf("a second before its expiry the link is refused: %v", err)
	}
	c.Advance(time.Second)
	_, err := r.Resolve(ctx, short)
	var re *ResolveError
	if !errors.As(err, &re) || re.Reason != ReasonExpired {
		t.Fatalf("at its expiry: %v, want expired", err)
	}
	// An expired link is still a known one: the refusal can say whose it was.
	if re.Link == nil || re.Link.Subject != alice.Subject || re.Link.ID != shortInfo.ID {
		t.Fatalf("the refusal of an expired link does not name it: %+v", re.Link)
	}
	if got, _ := r.Get(shortInfo.ID); got.State != StateExpired {
		t.Fatalf("state = %v, want expired", got.State)
	}
	if _, err := r.Resolve(ctx, tok); err != nil {
		t.Fatalf("the longer-lived link stopped working too: %v", err)
	}

	// Links that do not expire.
	forever := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.LinkTTL = -1 })
	ftok, finfo := mustIssue(t, forever, alice, "")
	if finfo.ExpiresAt != nil {
		t.Fatalf("a link without expiry has one: %v", finfo.ExpiresAt)
	}
	c.Advance(20 * 365 * 24 * time.Hour)
	if _, err := forever.Resolve(ctx, ftok); err != nil {
		t.Fatalf("a link without expiry expired: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, nil)
	tok, info := mustIssue(t, r, alice, "laptop")
	keep, _ := mustIssue(t, r, alice, "desktop")

	c.Advance(time.Minute)
	revoked, err := r.Revoke(ctx, info.ID, "alice@example.com", "lost the laptop\x07")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != StateRevoked || revoked.RevokedBy != "alice@example.com" || revoked.RevokeReason != "lost the laptop" ||
		revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(c.Now()) {
		t.Fatalf("revoked link = %+v", revoked)
	}
	_, err = r.Resolve(ctx, tok)
	var re *ResolveError
	if !errors.As(err, &re) || re.Reason != ReasonRevoked || re.Link == nil || re.Link.ID != info.ID {
		t.Fatalf("a revoked link resolves: %v", err)
	}
	if _, err := r.Resolve(ctx, keep); err != nil {
		t.Fatalf("revoking one link took another with it: %v", err)
	}

	// Revoking again changes nothing — not the time, not who did it.
	c.Advance(time.Hour)
	again, err := r.Revoke(ctx, info.ID, "someone-else", "again")
	if err != nil || !again.RevokedAt.Equal(*revoked.RevokedAt) || again.RevokedBy != "alice@example.com" {
		t.Fatalf("a second revocation changed the record: %+v, %v", again, err)
	}
	if st := r.Stats(); st.RevokedTotal != 1 || st.Revoked != 1 || st.Active != 1 {
		t.Fatalf("stats = %+v", st)
	}

	for _, bad := range []string{"", "nope", strings.Repeat("0", 16), "../../etc/passwd"} {
		if _, err := r.Revoke(ctx, bad, "x", ""); !errors.Is(err, ErrNoSuchLink) {
			t.Errorf("Revoke(%q) = %v, want ErrNoSuchLink", bad, err)
		}
	}
	// A link that is revoked stays revoked after it would have expired too.
	c.Advance(DefaultLinkTTL)
	if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("an expired, revoked link is reported as %v, want revoked", reasonOf(t, err))
	}
}

func TestRevokeUser(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, nil)
	a1, _ := mustIssue(t, r, alice, "laptop")
	a2, _ := mustIssue(t, r, alice, "ci")
	b1, _ := mustIssue(t, r, bob, "laptop")
	sessionStart := c.Now()

	c.Advance(time.Minute)
	n, notBefore, err := r.RevokeUser(ctx, alice.Subject, "ops@example.com", "left the company")
	if err != nil || n != 2 || !notBefore.Equal(c.Now()) {
		t.Fatalf("RevokeUser = %d, %v, %v; want 2 links, now", n, notBefore, err)
	}
	for _, tok := range []string{a1, a2} {
		if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
			t.Fatalf("a link of the revoked user resolves: %v", err)
		}
	}
	if _, err := r.Resolve(ctx, b1); err != nil {
		t.Fatalf("another user's link was affected: %v", err)
	}
	for _, info := range r.List(Filter{Subject: alice.Subject}) {
		if info.State != StateRevoked || info.RevokedBy != "ops@example.com" || info.RevokeReason != "left the company" {
			t.Fatalf("link after RevokeUser = %+v", info)
		}
	}

	// Sessions that began before the revocation ended with it; one that begins
	// afterwards is good, and so is a link created afterwards.
	if r.SessionValid(alice.Subject, sessionStart) || r.SessionValid(alice.Subject, c.Now()) {
		t.Fatal("a session from before the revocation is still valid")
	}
	if !r.SessionValid(bob.Subject, sessionStart) {
		t.Fatal("another user's session was ended")
	}
	c.Advance(time.Second)
	if !r.SessionValid(alice.Subject, c.Now()) {
		t.Fatal("a session started after the revocation is not valid: the revocation is a watermark, not a ban")
	}
	a3, _ := mustIssue(t, r, alice, "new laptop")
	if _, err := r.Resolve(ctx, a3); err != nil {
		t.Fatalf("a link created after the revocation does not work: %v", err)
	}

	// The watermark never moves backwards.
	_, first, _ := r.RevokeUser(ctx, bob.Subject, "ops", "")
	c.Advance(-10 * time.Minute) // a replica whose clock is behind
	_, second, err := r.RevokeUser(ctx, bob.Subject, "ops", "")
	if err != nil || second.Before(first) {
		t.Fatalf("a later revocation moved the watermark back from %v to %v (%v)", first, second, err)
	}
	if _, _, err := r.RevokeUser(ctx, "  ", "ops", ""); !errors.Is(err, ErrBadSubject) {
		t.Fatalf("RevokeUser of nobody = %v", err)
	}
}

func TestMaxLinksPerUser(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.MaxLinksPerUser = 2; cfg.LinkTTL = time.Hour })
	_, first := mustIssue(t, r, alice, "1")
	mustIssue(t, r, alice, "2")
	if _, _, err := r.Issue(ctx, alice, IssueOptions{}); !errors.Is(err, ErrTooManyLinks) {
		t.Fatalf("a third link: %v, want ErrTooManyLinks", err)
	}
	// The bound is per user, and counts working links only.
	mustIssue(t, r, bob, "1")
	if _, err := r.Revoke(ctx, first.ID, "alice", ""); err != nil {
		t.Fatal(err)
	}
	mustIssue(t, r, alice, "3")
	c.Advance(2 * time.Hour) // everything has expired
	mustIssue(t, r, alice, "4")

	unbounded := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.MaxLinksPerUser = -1 })
	for i := 0; i < DefaultMaxLinksPerUser+5; i++ {
		mustIssue(t, unbounded, alice, fmt.Sprint(i))
	}
}

func TestIdentityIsValidated(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t, NewMemoryStore(), newClock(), nil)
	for name, id := range map[string]Identity{
		"no subject":           {},
		"blank subject":        {Subject: "   "},
		"control character":    {Subject: "alice\nadmin"},
		"right-to-left mark":   {Subject: "alice‮ecila"},
		"zero-width space":     {Subject: "ali​ce"},
		"invalid UTF-8":        {Subject: "alice\xff"},
		"an enormous subject":  {Subject: strings.Repeat("a", maxSubjectLen+1)},
		"NUL in the middle":    {Subject: "alice\x00"},
		"a line separator":     {Subject: "alice bob"},
		"a soft hyphen format": {Subject: "ali­ce"},
	} {
		if _, _, err := r.Issue(ctx, id, IssueOptions{}); !errors.Is(err, ErrBadSubject) {
			t.Errorf("%s: Issue = %v, want ErrBadSubject", name, err)
		}
	}
	// Everything else is repaired rather than refused: it is for display.
	roles := []string{"dev", "dev", " ", "ops\x00"}
	for i := 0; i < 200; i++ {
		roles = append(roles, fmt.Sprintf("role-%03d", i))
	}
	_, info, err := r.Issue(ctx, Identity{
		Subject: " carol@example.com ", Name: "Carol‮\x07 Example", Team: strings.Repeat("t", 500), Roles: roles,
	}, IssueOptions{Label: strings.Repeat("l", 500), From: "10.0.0.1\r\nX-Injected: 1"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Subject != "carol@example.com" || info.Name != "Carol Example" || len(info.Team) != maxTeamLen ||
		len(info.Label) != maxLabelLen || len(info.Roles) != maxRoles || info.CreatedFrom != "10.0.0.1X-Injected: 1" {
		t.Fatalf("normalized link = %+v", info)
	}
	seen := map[string]bool{}
	for _, role := range info.Roles {
		if seen[role] || strings.TrimSpace(role) == "" || strings.ContainsRune(role, 0) {
			t.Fatalf("roles are not deduplicated and cleaned: %q", info.Roles)
		}
		seen[role] = true
	}
}

// Two replicas, one store. This is the deployment the registry's layout exists
// for: a link created on one replica works on the other at once, and what one
// replica says about a link reaches the other with its next refresh.
func TestTwoReplicasShareAStore(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	shared := NewMemoryStore()
	spyB := newSpyStore(shared)
	a := newTestRegistry(t, shared, c, func(cfg *RegistryConfig) { cfg.Node = "replica-a" })
	b := newTestRegistry(t, spyB, c, func(cfg *RegistryConfig) { cfg.Node = "replica-b" })

	// Created on A, used on B before B has refreshed: B looks it up, once.
	tok, info := mustIssue(t, a, alice, "laptop")
	link, err := b.Resolve(ctx, tok)
	if err != nil || link.ID != info.ID || link.Subject != alice.Subject {
		t.Fatalf("a link created on replica A does not resolve on replica B: %+v, %v", link, err)
	}
	lookups := spyB.getCount("link/")
	if lookups != 1 {
		t.Fatalf("replica B read the link from the store %d times, want once", lookups)
	}
	for i := 0; i < 50; i++ {
		if _, err := b.Resolve(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if spyB.getCount("link/") != lookups {
		t.Fatal("a link replica B already knows sends it back to the store")
	}

	// Revoked on A: immediate on A, and on B with its next refresh.
	if _, err := a.Revoke(ctx, info.ID, "alice", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatal("the revocation is not immediate on the replica that performed it")
	}
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("the revocation did not reach replica B with its refresh: %v", err)
	}
	if got, _ := b.Get(info.ID); got.RevokedBy != "alice" || got.RevokeReason != "test" {
		t.Fatalf("replica B does not know who revoked the link: %+v", got)
	}

	// A link created on A and revoked on A, before B has heard of either: B
	// must not take the link as good because it has not seen the revocation.
	tok2, info2 := mustIssue(t, a, alice, "second")
	if _, err := a.Revoke(ctx, info2.ID, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok2); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("replica B honoured a link that was revoked before B first saw it: %v", err)
	}

	// The same for "revoke everything of this user": a link B has never seen is
	// covered when B first meets it, and links B knows are covered by a refresh.
	tok3, _ := mustIssue(t, a, bob, "one")
	if _, err := b.Resolve(ctx, tok3); err != nil {
		t.Fatal(err)
	}
	tok4, _ := mustIssue(t, a, bob, "two")
	c.Advance(time.Second)
	if _, _, err := a.RevokeUser(ctx, bob.Subject, "ops", "offboarding"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok4); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("replica B honoured a link of a user whose links were all revoked: %v", err)
	}
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(ctx, tok3); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("the user-wide revocation did not reach a link replica B already knew: %v", err)
	}
	if b.SessionValid(bob.Subject, c.Now().Add(-time.Minute)) {
		t.Fatal("replica B still accepts the user's old sessions")
	}

	// Usage seen by A shows on B.
	tok5, info5 := mustIssue(t, a, alice, "used on a")
	_ = tok5
	c.Advance(time.Minute)
	a.Touch(info5.ID, "10.1.2.3", "cargo/1.84.0")
	a.Close() // writes replica A's usage object
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := b.Get(info5.ID)
	if !ok || got.LastUsedAt == nil || !got.LastUsedAt.Equal(c.Now()) || got.LastAddr != "10.1.2.3" || got.LastAgent != "cargo/1.84.0" {
		t.Fatalf("replica B does not show the use replica A saw: %+v", got)
	}
	// The most recent use wins, whichever replica saw it.
	c.Advance(time.Minute)
	b.Touch(info5.ID, "10.9.9.9", "go")
	if got, _ := b.Get(info5.ID); got.LastAddr != "10.9.9.9" {
		t.Fatalf("a later use on replica B did not replace the earlier one from A: %+v", got)
	}
}

// A token nobody knows must not cost the store a request each time it is tried.
func TestUnknownTokensAreBudgeted(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	spy := newSpyStore(NewMemoryStore())
	r := newTestRegistry(t, spy, c, nil)

	junk, _ := NewToken()
	for i := 0; i < 100; i++ {
		if _, err := r.Resolve(ctx, junk); reasonOf(t, err) != ReasonUnknown {
			t.Fatal(err)
		}
	}
	if n := spy.getCount("link/"); n != 1 {
		t.Fatalf("the same unknown token was looked up %d times, want once", n)
	}

	// Many different unknown tokens: the lookups stop at the budget. Beyond it
	// the store is not asked, and the answer is "ask again" — not "unknown":
	// the token may be a link created on another replica a moment ago.
	for i := 0; i < 10*missBurst; i++ {
		tok, _ := NewToken()
		want := ReasonUnknown
		if i >= missBurst-1 { // the token above took one lookup of the burst
			want = ReasonUnavailable
		}
		if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != want {
			t.Fatalf("unknown token %d: %v, want %s", i, err, want)
		}
	}
	if n := spy.getCount("link/"); n > missBurst+1 {
		t.Fatalf("%d store lookups for unknown tokens, want at most the burst of %d", n, missBurst)
	}
	// The budget refills with time, and a link created elsewhere is then found.
	c.Advance(10 * time.Second)
	other := newTestRegistry(t, spy.Store, c, func(cfg *RegistryConfig) { cfg.Node = "other" })
	tok, _ := mustIssue(t, other, alice, "elsewhere")
	if _, err := r.Resolve(ctx, tok); err != nil {
		t.Fatalf("after the budget refilled, a link created on another replica is not found: %v", err)
	}
	// An unknown token is remembered only for a while: a link created later
	// under that very token hash (as after a replica's delayed write) is found.
	c.Advance(2 * DefaultSyncInterval)
	before := spy.getCount("link/")
	if _, err := r.Resolve(ctx, junk); reasonOf(t, err) != ReasonUnknown {
		t.Fatal(err)
	}
	if spy.getCount("link/") != before+1 {
		t.Fatal("an unknown token is never asked about again")
	}
}

// When the store cannot be read, the registry says so: a link it cannot verify
// is "unavailable", not "unknown" — the user's link is fine, and the client
// should retry rather than be told to get a new one.
func TestStoreUnavailable(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	seed := newTestRegistry(t, inner, c, nil)
	tok, info := mustIssue(t, seed, alice, "laptop")

	down := errors.New("the store is down")
	spy := newSpyStore(inner)
	spy.set(func(s *spyStore) { s.failList, s.failGet, s.failPut = down, down, down })
	r := newTestRegistry(t, spy, c, nil) // starts although the store is down

	if st := r.Stats(); st.Synced || st.LastSyncError == "" {
		t.Fatalf("stats of a registry that never loaded = %+v", st)
	}
	if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonUnavailable {
		t.Fatalf("with the store down, a valid link is reported as %v, want unavailable", reasonOf(t, err))
	}
	junk, _ := NewToken()
	if _, err := r.Resolve(ctx, junk); reasonOf(t, err) != ReasonUnavailable {
		t.Fatalf("with the store down, an unknown link is reported as %v, want unavailable", reasonOf(t, err))
	}
	if _, _, err := r.Issue(ctx, alice, IssueOptions{}); err == nil {
		t.Fatal("a link was issued although it could not be stored")
	}
	if _, err := r.Revoke(ctx, info.ID, "x", ""); err == nil {
		t.Fatal("Revoke succeeded although nothing could be read or written")
	}
	if _, _, err := r.RevokeUser(ctx, alice.Subject, "x", ""); err == nil {
		t.Fatal("RevokeUser succeeded although it could not be stored")
	}

	// The store comes back: the next refresh loads the registry.
	spy.set(func(s *spyStore) { s.failList, s.failGet, s.failPut = nil, nil, nil })
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, tok); err != nil {
		t.Fatalf("after the store came back: %v", err)
	}

	// The store goes away again. What is known stays known and enforced —
	// links keep working, revoked ones stay revoked — and an unknown token is
	// "unavailable" again, because it cannot be told from a new link.
	revokedTok, revokedInfo := mustIssue(t, r, alice, "to revoke")
	if _, err := r.Revoke(ctx, revokedInfo.ID, "alice", ""); err != nil {
		t.Fatal(err)
	}
	spy.set(func(s *spyStore) { s.failList, s.failGet, s.failPut = down, down, down })
	if err := r.Sync(ctx); err == nil {
		t.Fatal("Sync reported success with the store down")
	}
	if _, err := r.Resolve(ctx, tok); err != nil {
		t.Fatalf("a known link stopped working when the store went away: %v", err)
	}
	if _, err := r.Resolve(ctx, revokedTok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("a revoked link is reported as %v while the store is away", reasonOf(t, err))
	}
	c.Advance(time.Minute)
	junk2, _ := NewToken()
	if _, err := r.Resolve(ctx, junk2); reasonOf(t, err) != ReasonUnavailable {
		t.Fatalf("an unknown link while the store is away: %v, want unavailable", reasonOf(t, err))
	}
	if st := r.Stats(); !st.Synced || st.SyncErrors == 0 || st.StoreErrors == 0 || st.LastSyncError == "" {
		t.Fatalf("stats = %+v", st)
	}
}

// What is in the store is the truth, including when it changes behind the
// registry's back: a record deleted there is gone, a damaged one is skipped —
// and a damaged "no" still means no.
func TestStoreIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := NewMemoryStore()
	r := newTestRegistry(t, store, c, nil)
	tok, info := mustIssue(t, r, alice, "laptop")
	tok2, info2 := mustIssue(t, r, alice, "desktop")
	tok3, info3 := mustIssue(t, r, bob, "laptop")

	// A link object removed from the store (by an operator, by another
	// replica's clean-up) no longer resolves after the next refresh.
	if err := store.Delete(ctx, linkObject(hashToken(tok))); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	c.Advance(2 * DefaultSyncInterval)
	if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonUnknown {
		t.Fatalf("a link deleted from the store still resolves: %v", err)
	}
	if _, ok := r.Get(info.ID); ok {
		t.Fatal("a link deleted from the store is still listed")
	}

	// A revocation whose content is unreadable is still a revocation.
	if err := store.Put(ctx, revokedObject(info2.ID), []byte("{{{ not json")); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, tok2); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("a revocation with unreadable content was ignored: %v", err)
	}

	// A block that cannot be read blocks everything issued to its user so far —
	// and nothing issued afterwards, and nobody else.
	c.Advance(time.Minute)
	if err := store.Put(ctx, blockObject(bob.Subject), []byte(`{"subject":"someone else","notBefore":"2026-01-01T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, tok3); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("a block that cannot be read was ignored: %v", err)
	}
	c.Advance(time.Minute)
	tok4, _ := mustIssue(t, r, bob, "after")
	if _, err := r.Resolve(ctx, tok4); err != nil {
		t.Fatalf("a link created after the unreadable block is refused: %v", err)
	}
	_ = info3

	// Damaged and foreign link records are skipped, counted, and do not stop
	// the others from loading.
	good, _ := mustIssue(t, r, alice, "good")
	hash1 := hashToken("ptl1" + strings.Repeat("a", 39))
	hash2 := hashToken("ptl1" + strings.Repeat("b", 39))
	record := func(hash string, mutate func(*Link)) []byte {
		l := Link{ID: linkIDFromHash(hash), TokenHash: hash, Identity: alice, CreatedAt: c.Now()}
		if mutate != nil {
			mutate(&l)
		}
		data, _ := json.Marshal(l)
		return data
	}
	for name, data := range map[string][]byte{
		linkObject(strings.Repeat("1", 64)): []byte("not json"),
		linkObject(strings.Repeat("2", 64)): record(hash1, nil), // stored under another hash than its own
		linkObject(hash1):                   record(hash1, func(l *Link) { l.ID = strings.Repeat("0", 16) }),
		linkObject(hash2):                   record(hash2, func(l *Link) { l.Subject = "" }),
		linkObject("short"):                 record(hash1, nil),
		"unknownkind/abc":                   []byte("{}"),
	} {
		if err := store.Put(ctx, name, data); err != nil {
			t.Fatal(err)
		}
	}
	fresh := newTestRegistry(t, store, c, nil)
	if _, err := fresh.Resolve(ctx, good); err != nil {
		t.Fatalf("a damaged record kept a good one from loading: %v", err)
	}
	st := fresh.Stats()
	// The five damaged link records, and the block that cannot be read.
	if st.Skipped != 6 {
		t.Fatalf("%d records were skipped, want 6", st.Skipped)
	}
	if n := len(fresh.List(Filter{})); n != 4 {
		t.Fatalf("the registry lists %d links, want the 4 real ones: %+v", n, fresh.List(Filter{}))
	}
	// A damaged record is reported once, not on every refresh.
	_ = fresh.Sync(ctx)
	_ = fresh.Sync(ctx)
	if got := fresh.Stats().Skipped; got != st.Skipped {
		t.Fatalf("the damaged records were counted again on a refresh: %d → %d", st.Skipped, got)
	}
}

// A link created while a refresh is in flight — after the refresh listed the
// store, before it applied the listing — must not be dropped as "deleted".
func TestLinkCreatedDuringRefreshSurvives(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	spy := newSpyStore(NewMemoryStore())
	r := newTestRegistry(t, spy, c, nil)
	mustIssue(t, r, alice, "before")

	var tok string
	var info Info
	spy.set(func(s *spyStore) {
		s.afterList = func() {
			spy.set(func(s *spyStore) { s.afterList = nil })
			tok, info = mustIssue(t, r, alice, "during")
			if _, err := r.Revoke(ctx, info.ID, "alice", ""); err != nil {
				t.Errorf("Revoke during a refresh: %v", err)
			}
			if _, _, err := r.RevokeUser(ctx, bob.Subject, "ops", ""); err != nil {
				t.Errorf("RevokeUser during a refresh: %v", err)
			}
		}
	})
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("the hook did not run")
	}
	if _, ok := r.Get(info.ID); !ok {
		t.Fatal("a link created during a refresh was dropped by it")
	}
	if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("a revocation made during a refresh was dropped by it: %v", err)
	}
	if r.SessionValid(bob.Subject, c.Now()) {
		t.Fatal("a user-wide revocation made during a refresh was dropped by it")
	}
	// And they are still there after the next, undisturbed refresh.
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, tok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("after the next refresh: %v", err)
	}
}

func TestCleanUp(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := NewMemoryStore()
	r := newTestRegistry(t, store, c, func(cfg *RegistryConfig) { cfg.LinkTTL = 24 * time.Hour })

	expiring, expInfo := mustIssue(t, r, alice, "expires")
	_, revInfo := mustIssue(t, r, alice, "revoked")
	if _, err := r.Revoke(ctx, revInfo.ID, "alice", ""); err != nil {
		t.Fatal(err)
	}
	_, bobInfo := mustIssue(t, r, bob, "blocked")
	c.Advance(time.Second)
	if _, _, err := r.RevokeUser(ctx, bob.Subject, "ops", ""); err != nil {
		t.Fatal(err)
	}
	// A revocation whose link is already gone.
	if err := store.Put(ctx, revokedObject(strings.Repeat("9", 16)), []byte(`{"id":"9999999999999999","revokedAt":"2026-03-01T12:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}

	// Within the retention nothing is deleted: "what was this link" still has
	// an answer.
	c.Advance(retainEnded - time.Hour)
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(r.List(Filter{})); got != 3 {
		t.Fatalf("%d links are listed before the retention is over, want 3", got)
	}
	if st := r.Stats(); st.Deleted != 0 {
		t.Fatalf("%d records were deleted early", st.Deleted)
	}

	// The retention of what was revoked is over; the link that merely expired —
	// a day after it was created — still has a day of it left.
	c.Advance(2 * time.Hour)
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{revInfo.ID, bobInfo.ID} {
		if _, ok := r.Get(id); ok {
			t.Errorf("revoked link %s is still listed after its retention", id)
		}
	}
	if got, ok := r.Get(expInfo.ID); !ok || got.State != StateExpired {
		t.Fatalf("the expired link was deleted before its retention was over: %+v, %v", got, ok)
	}
	if _, err := store.Get(ctx, revokedObject(strings.Repeat("9", 16))); !errors.Is(err, ErrNotFound) {
		t.Errorf("a revocation without a link was not cleaned up: %v", err)
	}

	c.Advance(24 * time.Hour)
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get(expInfo.ID); ok {
		t.Error("the expired link is still listed after its retention")
	}
	// The block went too: no link it covers is left, and the sessions it ended
	// are long over.
	objs, _ := store.List(ctx)
	if len(objs) != 0 {
		t.Fatalf("the store still holds %v", objs)
	}
	// A cleaned-up link is simply unknown: it does not come back.
	if _, err := r.Resolve(ctx, expiring); reasonOf(t, err) != ReasonUnknown {
		t.Fatalf("a cleaned-up link: %v", err)
	}

	// A link without expiry is never deleted for being old, and the block that
	// covers it stays as long as the link does.
	forever := newTestRegistry(t, store, c, func(cfg *RegistryConfig) { cfg.LinkTTL = -1 })
	ftok, _ := mustIssue(t, forever, alice, "forever")
	c.Advance(time.Second)
	if _, _, err := forever.RevokeUser(ctx, alice.Subject, "ops", ""); err != nil {
		t.Fatal(err)
	}
	c.Advance(retainEnded - time.Hour)
	if err := forever.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := forever.Resolve(ctx, ftok); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("a blocked link without expiry: %v, want revoked", err)
	}
	c.Advance(10 * 365 * 24 * time.Hour)
	if err := forever.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// By now the link's record has been deleted (it ended more than the
	// retention ago) — together with the block. The token must stay dead.
	if _, err := forever.Resolve(ctx, ftok); err == nil {
		t.Fatal("a revoked link came back to life after clean-up")
	}

	// Clean-up can be reserved for the lease holder.
	gated := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.LinkTTL = time.Hour })
	leader := false
	gated.SetLeaderGate(func() bool { return leader })
	_, gInfo := mustIssue(t, gated, alice, "x")
	c.Advance(time.Hour + retainEnded + time.Hour)
	_ = gated.Sync(ctx)
	if _, ok := gated.Get(gInfo.ID); !ok {
		t.Fatal("a replica that is not the leader cleaned up")
	}
	leader = true
	_ = gated.Sync(ctx)
	if _, ok := gated.Get(gInfo.ID); ok {
		t.Fatal("the leader did not clean up")
	}
}

func TestUsageSurvivesRestartAndStaleNodesAreFolded(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := NewMemoryStore()
	a := newTestRegistry(t, store, c, func(cfg *RegistryConfig) { cfg.Node = "Replica A/1" })
	_, info := mustIssue(t, a, alice, "laptop")
	a.Touch(info.ID, "10.0.0.7\n", strings.Repeat("u", 500))
	a.Close()

	if _, err := store.Get(ctx, "usage/replica-a-1"); err != nil {
		t.Fatalf("the usage object is not named after the node: %v", err)
	}
	// The same node, restarted: it remembers.
	a2 := newTestRegistry(t, store, c, func(cfg *RegistryConfig) { cfg.Node = "Replica A/1" })
	got, _ := a2.Get(info.ID)
	if got.LastUsedAt == nil || got.LastAddr != "10.0.0.7" || len(got.LastAgent) != maxAgentLen {
		t.Fatalf("usage after a restart = %+v", got)
	}

	// A node that has not written for a long time is taken to be gone: another
	// replica folds what it saw into its own usage and removes the object.
	b := newTestRegistry(t, store, c, func(cfg *RegistryConfig) { cfg.Node = "replica-b" })
	c.Advance(staleUsageAge + time.Hour)
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "usage/replica-a-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the stale usage object is still there: %v", err)
	}
	if got, _ := b.Get(info.ID); got.LastAddr != "10.0.0.7" {
		t.Fatalf("folding a stale usage object lost what it knew: %+v", got)
	}
	b.Close()
	if data, err := store.Get(ctx, "usage/replica-b"); err != nil || !strings.Contains(string(data), info.ID) {
		t.Fatalf("the folded usage was not written to the surviving replica's object: %s, %v", data, err)
	}
	// Usage read from the store is bounded and filtered like everything else.
	if err := store.Put(ctx, "usage/evil", []byte(`{"node":"evil","updatedAt":"2026-03-01T12:00:00Z","links":{"../x":{"lastUsedAt":"2030-01-01T00:00:00Z","lastAddr":"x"},"`+info.ID+`":{"lastUsedAt":"2031-01-01T00:00:00Z","lastAddr":"`+strings.Repeat("9", 500)+`"}}}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Get(info.ID); len(got.LastAddr) > maxAddrLen {
		t.Fatalf("an oversized address from a usage object was taken as is: %d bytes", len(got.LastAddr))
	}
}

// Two replicas that were given the same name — two processes on one host, a
// node name copied from one configuration into the next — write the same usage
// object. Neither may erase what the other has seen, and once both have seen
// everything they must stop writing.
func TestReplicasOfTheSameNameMergeTheirUsage(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store := newSpyStore(NewMemoryStore())
	sameName := func(cfg *RegistryConfig) { cfg.Node = "proxy" }
	a := newTestRegistry(t, store, c, sameName)
	_, first := mustIssue(t, a, alice, "laptop")
	_, second := mustIssue(t, a, bob, "laptop")
	b := newTestRegistry(t, store, c, sameName)

	a.Touch(first.ID, "10.0.0.1", "npm/10")
	a.flushUsage(ctx)
	c.Advance(time.Second)
	// B has not looked at the object since A wrote it, and writes over it.
	b.Touch(second.ID, "10.0.0.2", "pip/24")
	b.flushUsage(ctx)
	if data, _ := store.Get(ctx, "usage/proxy"); strings.Contains(string(data), first.ID) {
		t.Fatal("the test's premise is gone: B was meant to write over what A had written")
	}

	// Each refresh reads the object when it changed. A finds its own observation
	// missing and writes both; B learns A's.
	for round := 0; round < 3; round++ {
		for _, r := range []*Registry{a, b} {
			if err := r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			r.flushUsage(ctx)
		}
	}
	for name, r := range map[string]*Registry{"A": a, "B": b} {
		one, _ := r.Get(first.ID)
		two, _ := r.Get(second.ID)
		if one.LastUsedAt == nil || one.LastAddr != "10.0.0.1" || two.LastUsedAt == nil || two.LastAddr != "10.0.0.2" {
			t.Fatalf("replica %s knows %+v and %+v", name, one, two)
		}
	}
	data, err := store.Get(ctx, "usage/proxy")
	if err != nil || !strings.Contains(string(data), first.ID) || !strings.Contains(string(data), second.ID) {
		t.Fatalf("the shared usage object holds %s (%v), want both links", data, err)
	}

	// Settled: with nothing new, nobody writes and nobody reads the object again.
	store.set(func(s *spyStore) { s.puts, s.gets = map[string]int{}, map[string]int{} })
	for round := 0; round < 3; round++ {
		for _, r := range []*Registry{a, b} {
			if err := r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			r.flushUsage(ctx)
		}
	}
	store.mu.Lock()
	puts, gets := store.puts["usage/proxy"], store.gets["usage/proxy"]
	store.mu.Unlock()
	if puts != 0 || gets != 0 {
		t.Fatalf("with nothing new, the replicas wrote the usage object %d times and read it %d times", puts, gets)
	}

	// A later use by either replica reaches the other.
	c.Advance(time.Minute)
	b.Touch(first.ID, "10.0.0.9", "cargo")
	b.flushUsage(ctx)
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Get(first.ID); got.LastAddr != "10.0.0.9" {
		t.Fatalf("replica A did not learn of the later use: %+v", got)
	}
}

// failingGets fails reads of one object.
type failingGets struct {
	Store
	mu   sync.Mutex
	name string
	err  error
}

func (f *failingGets) Get(ctx context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	fail := f.err != nil && name == f.name
	err := f.err
	f.mu.Unlock()
	if fail {
		return nil, err
	}
	return f.Store.Get(ctx, name)
}

// A replica that has not been able to read what it recorded before it was
// restarted must not write over it.
func TestUsageIsNotWrittenOverBeforeItWasRead(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	inner := NewMemoryStore()
	first := newTestRegistry(t, inner, c, nil)
	_, old := mustIssue(t, first, alice, "old laptop")
	_, recent := mustIssue(t, first, alice, "new laptop")
	first.Touch(old.ID, "10.0.0.1", "npm/10")
	first.Close()

	// The replica restarts while its usage object cannot be read.
	store := &failingGets{Store: inner, name: "usage/node-a", err: errors.New("i/o error")}
	restarted := newTestRegistry(t, store, c, nil)
	c.Advance(time.Second)
	restarted.Touch(recent.ID, "10.0.0.2", "pip/24")
	restarted.flushUsage(ctx)
	if data, _ := inner.Get(ctx, "usage/node-a"); !strings.Contains(string(data), old.ID) || strings.Contains(string(data), recent.ID) {
		t.Fatalf("the replica wrote over a usage object it had not read: %s", data)
	}

	// Readable again: the next refresh merges, the next flush writes both.
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	if err := restarted.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	restarted.flushUsage(ctx)
	data, _ := inner.Get(ctx, "usage/node-a")
	if !strings.Contains(string(data), old.ID) || !strings.Contains(string(data), recent.ID) {
		t.Fatalf("after the object became readable it holds %s, want both links", data)
	}
	if got, _ := restarted.Get(old.ID); got.LastAddr != "10.0.0.1" {
		t.Fatalf("what the replica had seen before the restart is lost: %+v", got)
	}
}

func TestListFilters(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.LinkTTL = time.Hour })
	_, a1 := mustIssue(t, r, alice, "laptop")
	c.Advance(time.Minute)
	_, a2 := mustIssue(t, r, alice, "ci")
	c.Advance(time.Minute)
	_, b1 := mustIssue(t, r, bob, "Laptop")
	if _, err := r.Revoke(ctx, a2.ID, "alice", ""); err != nil {
		t.Fatal(err)
	}

	all := r.List(Filter{})
	if len(all) != 3 || all[0].ID != b1.ID || all[2].ID != a1.ID {
		t.Fatalf("List is not newest first: %+v", all)
	}
	if got := r.List(Filter{Subject: alice.Subject}); len(got) != 2 {
		t.Fatalf("by subject: %d links", len(got))
	}
	// An e-mail address names its user whatever the capitals — as at sign-in;
	// any other subject (an identity provider's "sub") is compared exactly.
	if got := r.List(Filter{Subject: "ALICE@Example.com"}); len(got) != 2 {
		t.Fatalf("an e-mail address with other capitals: %d links", len(got))
	}
	bots := newTestRegistry(t, NewMemoryStore(), newClock(), nil)
	mustIssue(t, bots, Identity{Subject: "CI-Bot"}, "nightly")
	if got := bots.List(Filter{Subject: "ci-bot"}); len(got) != 0 {
		t.Fatal("the subject filter is not exact for a subject that is not an e-mail address")
	}
	if got := bots.List(Filter{Subject: "CI-Bot"}); len(got) != 1 {
		t.Fatalf("by the exact subject: %d links", len(got))
	}
	if got := r.List(Filter{State: StateRevoked}); len(got) != 1 || got[0].ID != a2.ID {
		t.Fatalf("by state: %+v", got)
	}
	if got := r.List(Filter{Search: "LAPTOP"}); len(got) != 2 {
		t.Fatalf("search by label: %d links", len(got))
	}
	if got := r.List(Filter{Search: "payments"}); len(got) != 1 || got[0].ID != b1.ID {
		t.Fatalf("search by team: %+v", got)
	}
	if got := r.List(Filter{Search: a1.ID[:8]}); len(got) != 1 || got[0].ID != a1.ID {
		t.Fatalf("search by id: %+v", got)
	}
	c.Advance(2 * time.Hour)
	if got := r.List(Filter{State: StateExpired}); len(got) != 2 {
		t.Fatalf("expired: %d links, want 2 (the revoked one stays revoked)", len(got))
	}
	// No listing ever carries a token hash.
	data, _ := json.Marshal(r.List(Filter{}))
	if strings.Contains(string(data), "tokenHash") {
		t.Fatalf("the listing exposes token hashes: %s", data)
	}
	st := r.Stats()
	if st.Active != 0 || st.Expired != 2 || st.Revoked != 1 || st.Users != 0 || st.Issued != 3 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	r := newTestRegistry(t, NewMemoryStore(), c, func(cfg *RegistryConfig) { cfg.MaxLinksPerUser = -1 })
	tok, info := mustIssue(t, r, alice, "shared")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				switch j % 5 {
				case 0:
					if _, err := r.Resolve(ctx, tok); err != nil {
						t.Errorf("Resolve: %v", err)
						return
					}
				case 1:
					r.Touch(info.ID, "10.0.0.1", "agent")
				case 2:
					_ = r.List(Filter{Subject: alice.Subject})
				case 3:
					_ = r.Sync(ctx)
				case 4:
					if i == 0 {
						t2, i2, err := r.Issue(ctx, bob, IssueOptions{})
						if err == nil {
							_, _ = r.Resolve(ctx, t2)
							_, _ = r.Revoke(ctx, i2.ID, "bob", "")
						}
					}
					_ = r.Stats()
				}
			}
		}(i)
	}
	wg.Wait()
	r.Close()
}
