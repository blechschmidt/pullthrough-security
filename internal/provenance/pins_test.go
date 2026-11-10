package provenance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	commitC = "cccccccccccccccccccccccccccccccccccccccc"
)

func mustPins(t *testing.T, pins ...Pin) *PinSet {
	t.Helper()
	set, err := NewPinSet(pins)
	if err != nil {
		t.Fatalf("NewPinSet: %v", err)
	}
	return set
}

func TestNewPinSet_Validation(t *testing.T) {
	cases := []struct {
		name    string
		pins    []Pin
		wantErr string
	}{
		{"missing name", []Pin{{Ecosystem: "npm", Commit: commitA}}, "name is required"},
		{"blank name", []Pin{{Ecosystem: "npm", Name: "   ", Commit: commitA}}, "name is required"},
		{"name pattern", []Pin{{Ecosystem: "npm", Name: "@acme/*", Commit: commitA}}, "not a pattern"},
		{"missing commit", []Pin{{Ecosystem: "npm", Name: "left-pad"}}, "full 40- or 64-character"},
		{"abbreviated commit", []Pin{{Ecosystem: "npm", Name: "left-pad", Commit: "abc1234"}}, "full 40- or 64-character"},
		{"non-hex commit", []Pin{{Ecosystem: "npm", Name: "left-pad", Commit: strings.Repeat("z", 40)}}, "full 40- or 64-character"},
		{"duplicate", []Pin{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Commit: commitA},
			{Ecosystem: "NPM", Name: "Left-Pad", Version: "1.0.0", Commit: commitB},
		}, "duplicates pin #1"},
		{"duplicate wildcard spellings", []Pin{
			{Ecosystem: "*", Name: "left-pad", Version: "", Commit: commitA},
			{Ecosystem: "", Name: "left-pad", Version: "*", Commit: commitB},
		}, "duplicates pin #1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPinSet(tc.pins)
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}

	// SHA-256 object-format commits and upper-case hex are accepted and normalized.
	set := mustPins(t,
		Pin{Ecosystem: "npm", Name: "a", Commit: strings.Repeat("A", 40)},
		Pin{Ecosystem: "npm", Name: "b", Commit: strings.Repeat("0", 64)},
	)
	if p, ok := set.Match(Artifact{Ecosystem: "npm", Name: "a", Version: "1"}); !ok || p.Commit != commitA {
		t.Errorf("upper-case commit not normalized: %+v ok=%v", p, ok)
	}
	if set.Len() != 2 {
		t.Errorf("Len = %d, want 2", set.Len())
	}
}

func TestPinSet_NilAndEmptyAreSafe(t *testing.T) {
	var nilSet *PinSet
	if nilSet.Len() != 0 {
		t.Error("nil PinSet Len must be 0")
	}
	if _, ok := nilSet.Match(Artifact{Ecosystem: "npm", Name: "x", Version: "1"}); ok {
		t.Error("nil PinSet must match nothing")
	}
	if _, ok := nilSet.Link(Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, time.Now()); ok {
		t.Error("nil PinSet must link nothing")
	}
	empty := mustPins(t)
	if _, ok := empty.Match(Artifact{Ecosystem: "npm", Name: "x", Version: "1"}); ok {
		t.Error("empty PinSet must match nothing")
	}
}

func TestPinSet_MatchSpecificity(t *testing.T) {
	set := mustPins(t,
		// Declared least-specific first to prove ordering is by specificity, not
		// by declaration order.
		Pin{Name: "widget", Commit: commitA},                                     // any ecosystem, any version
		Pin{Ecosystem: "npm", Name: "widget", Commit: commitB},                   // npm, any version
		Pin{Ecosystem: "npm", Name: "widget", Version: "2.0.0", Commit: commitC}, // npm, exact version
		Pin{Ecosystem: "docker", Name: "library/alpine", Version: "3.19", Repository: "https://github.com/alpinelinux/docker-alpine", Commit: commitA},
	)

	cases := []struct {
		art    Artifact
		want   string // expected commit, "" = no match
		reason string
	}{
		{Artifact{Ecosystem: "npm", Name: "widget", Version: "2.0.0"}, commitC, "exact version beats the ecosystem-wide pin"},
		{Artifact{Ecosystem: "npm", Name: "widget", Version: "1.0.0"}, commitB, "ecosystem pin covers other versions"},
		{Artifact{Ecosystem: "pip", Name: "widget", Version: "2.0.0"}, commitA, "wildcard-ecosystem pin covers other ecosystems"},
		{Artifact{Ecosystem: "NPM", Name: "Widget", Version: "2.0.0"}, commitC, "ecosystem and name match case-insensitively"},
		{Artifact{Ecosystem: "npm", Name: "widget", Version: "2.0.0-rc1"}, commitB, "a version is matched exactly, never by prefix"},
		{Artifact{Ecosystem: "docker", Name: "library/alpine", Version: "3.19"}, commitA, "names with separators match"},
		{Artifact{Ecosystem: "docker", Name: "library/alpine", Version: "3.20"}, "", "an exact-version pin does not cover other versions"},
		{Artifact{Ecosystem: "npm", Name: "widgets", Version: "2.0.0"}, "", "names are matched exactly, never by prefix"},
		{Artifact{Ecosystem: "npm", Name: "", Version: "2.0.0"}, "", "an artifact without a name matches nothing"},
	}
	for _, tc := range cases {
		p, ok := set.Match(tc.art)
		got := ""
		if ok {
			got = p.Commit
		}
		if got != tc.want {
			t.Errorf("Match(%+v) = %q, want %q: %s", tc.art, got, tc.want, tc.reason)
		}
	}
}

func TestPinSet_LinkShape(t *testing.T) {
	set := mustPins(t, Pin{Ecosystem: "npm", Name: "widget", Repository: " https://git.example.com/acme/widget ", Commit: commitA})
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	art := Artifact{Ecosystem: "npm", Name: "widget", Version: "1.2.3", Digest: "sha256:ab"}

	link, ok := set.Link(art, now)
	if !ok {
		t.Fatal("expected a link")
	}
	if link.Artifact != art {
		t.Errorf("link.Artifact = %+v, want the requested artifact %+v", link.Artifact, art)
	}
	if link.CommitSHA != commitA || link.RepositoryURL != "https://git.example.com/acme/widget" {
		t.Errorf("link = %+v", link)
	}
	if link.ResolverName != PinResolverName {
		t.Errorf("ResolverName = %q, want %q", link.ResolverName, PinResolverName)
	}
	// A pin is an assertion, not evidence: it must never look attested.
	if link.Confidence != ConfidenceClaimed || link.SignatureVerified || link.ChainTrusted {
		t.Errorf("a pinned link must be claimed and unverified, got confidence=%q sig=%v chain=%v",
			link.Confidence, link.SignatureVerified, link.ChainTrusted)
	}
	if !link.ResolvedAt.Equal(now) {
		t.Errorf("ResolvedAt = %v, want %v", link.ResolvedAt, now)
	}
}

// staticVerdicts is a VerdictLookup over a fixed map.
type staticVerdicts map[string]*CommitVerdict

func (v staticVerdicts) VerdictFor(_ context.Context, sha string) (*CommitVerdict, bool) {
	cv, ok := v[sha]
	return cv, ok
}

func TestService_PinIsAuthoritative(t *testing.T) {
	// A resolver that would associate the package with a DIFFERENT commit, at the
	// strongest confidence. The operator's pin must still win, and the resolver
	// must not even be consulted for a pinned coordinate.
	attested := &fixedResolver{name: "att", link: &Link{RepositoryURL: "https://github.com/o/other", CommitSHA: commitB, Confidence: ConfidenceAttested}}
	store := NewMemoryLinkStore()
	svc := NewService(ServiceOptions{
		Resolvers: []Resolver{attested},
		Pins:      mustPins(t, Pin{Ecosystem: "npm", Name: "widget", Repository: "https://git.example.com/acme/widget", Commit: commitA}),
		Store:     store,
		Verdicts:  staticVerdicts{commitA: {SHA: commitA, RiskScore: 96, Malicious: true}},
	})
	ctx := context.Background()
	art := Artifact{Ecosystem: "npm", Name: "widget", Version: "1.0.0"}

	enriched, err := svc.ResolveEnriched(ctx, art)
	if err != nil {
		t.Fatalf("ResolveEnriched: %v", err)
	}
	if enriched.Link.CommitSHA != commitA || enriched.Link.ResolverName != PinResolverName {
		t.Fatalf("link = %+v, want the pinned commit from %q", enriched.Link, PinResolverName)
	}
	if attested.calls != 0 {
		t.Errorf("resolver chain consulted %d time(s) for a pinned coordinate", attested.calls)
	}
	// The pinned commit's scan verdict is what gates the package.
	if enriched.Verdict == nil || !enriched.Verdict.Malicious {
		t.Fatalf("verdict = %+v, want the malicious verdict of the pinned commit", enriched.Verdict)
	}

	// The association is visible in the admin listing.
	links, err := svc.Links(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].CommitSHA != commitA {
		t.Fatalf("Links = %+v, want the pinned link", links)
	}
	if svc.PinCount() != 1 {
		t.Errorf("PinCount = %d, want 1", svc.PinCount())
	}

	// An unpinned coordinate still goes through the resolver chain.
	other, err := svc.Resolve(ctx, Artifact{Ecosystem: "npm", Name: "gadget", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Resolve(unpinned): %v", err)
	}
	if other.CommitSHA != commitB || other.ResolverName == PinResolverName {
		t.Errorf("unpinned link = %+v, want the resolver's link", other)
	}
}

func TestService_PinOverridesPreviouslyStoredLink(t *testing.T) {
	// The package was resolved (and persisted) before the operator pinned it.
	res := &fixedResolver{name: "meta", link: &Link{RepositoryURL: "https://github.com/o/r", CommitSHA: commitB, Confidence: ConfidenceClaimed}}
	store := NewMemoryLinkStore()
	ctx := context.Background()
	art := Artifact{Ecosystem: "npm", Name: "widget", Version: "1.0.0"}

	before := NewService(ServiceOptions{Resolvers: []Resolver{res}, Store: store})
	if l, err := before.Resolve(ctx, art); err != nil || l.CommitSHA != commitB {
		t.Fatalf("pre-pin resolve = %+v, %v", l, err)
	}

	// Restart with a pin: it must not be shadowed by the persisted link.
	after := NewService(ServiceOptions{
		Resolvers: []Resolver{res},
		Pins:      mustPins(t, Pin{Ecosystem: "npm", Name: "widget", Commit: commitA}),
		Store:     store,
	})
	l, err := after.Resolve(ctx, art)
	if err != nil {
		t.Fatal(err)
	}
	if l.CommitSHA != commitA {
		t.Fatalf("commit = %q, want the pinned %q (a stored link must not shadow a pin)", l.CommitSHA, commitA)
	}
}

func TestService_RemovedPinStopsAnswering(t *testing.T) {
	store := NewMemoryLinkStore()
	ctx := context.Background()
	art := Artifact{Ecosystem: "npm", Name: "widget", Version: "1.0.0"}

	pinned := NewService(ServiceOptions{
		Pins:  mustPins(t, Pin{Ecosystem: "npm", Name: "widget", Commit: commitA}),
		Store: store,
	})
	if _, err := pinned.Resolve(ctx, art); err != nil {
		t.Fatal(err)
	}

	// Restart WITHOUT the pin and with no resolver that knows the package: the
	// persisted pinned link must not keep asserting the association.
	unpinned := NewService(ServiceOptions{Store: store})
	if _, err := unpinned.Resolve(ctx, art); !errors.Is(err, ErrNoProvenance) {
		t.Fatalf("Resolve after pin removal: err = %v, want ErrNoProvenance", err)
	}
	if links, _ := unpinned.Links(ctx); len(links) != 0 {
		t.Fatalf("Links after pin removal = %+v, want none (stale pinned link must be hidden)", links)
	}

	// Restart with the pin moved to another commit: the old one is replaced.
	moved := NewService(ServiceOptions{
		Pins:  mustPins(t, Pin{Ecosystem: "npm", Name: "widget", Commit: commitC}),
		Store: store,
	})
	if l, err := moved.Resolve(ctx, art); err != nil || l.CommitSHA != commitC {
		t.Fatalf("Resolve after pin change = %+v, %v; want commit %q", l, err, commitC)
	}
	if links, _ := moved.Links(ctx); len(links) != 1 || links[0].CommitSHA != commitC {
		t.Fatalf("Links after pin change = %+v, want only the new commit", links)
	}

	// With the pin gone, a resolver's link replaces the stale pinned one.
	res := &fixedResolver{name: "meta", link: &Link{RepositoryURL: "https://github.com/o/r", CommitSHA: commitB, Confidence: ConfidenceClaimed}}
	chained := NewService(ServiceOptions{Resolvers: []Resolver{res}, Store: store})
	if l, err := chained.Resolve(ctx, art); err != nil || l.CommitSHA != commitB || l.ResolverName == PinResolverName {
		t.Fatalf("Resolve via chain after pin removal = %+v, %v", l, err)
	}
}

// countingStore counts Put calls so a test can prove a hot pinned coordinate is
// not rewritten on every pull.
type countingStore struct {
	*MemoryLinkStore
	puts int
}

func (c *countingStore) Put(ctx context.Context, l *Link) error {
	c.puts++
	return c.MemoryLinkStore.Put(ctx, l)
}

func TestService_PinnedLinkPersistedOnce(t *testing.T) {
	store := &countingStore{MemoryLinkStore: NewMemoryLinkStore()}
	svc := NewService(ServiceOptions{
		Pins:  mustPins(t, Pin{Ecosystem: "npm", Name: "widget", Commit: commitA}),
		Store: store,
	})
	art := Artifact{Ecosystem: "npm", Name: "widget", Version: "1.0.0"}
	for i := 0; i < 5; i++ {
		if _, err := svc.Resolve(context.Background(), art); err != nil {
			t.Fatal(err)
		}
	}
	if store.puts != 1 {
		t.Errorf("store written %d times for 5 pulls of one pinned coordinate, want 1", store.puts)
	}
}

func TestService_PinWorksWithoutStore(t *testing.T) {
	svc := NewService(ServiceOptions{Pins: mustPins(t, Pin{Name: "widget", Commit: commitA})})
	l, err := svc.Resolve(context.Background(), Artifact{Ecosystem: "cargo", Name: "widget", Version: "0.1.0"})
	if err != nil || l.CommitSHA != commitA {
		t.Fatalf("Resolve = %+v, %v", l, err)
	}
}
