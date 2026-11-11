package continuity

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// stubResolver returns a fixed identity per coordinate name, driven by the test.
type stubResolver struct {
	byName map[string]Identity
	found  map[string]bool
	calls  int
}

func (r *stubResolver) Publishers(_ context.Context, c Coordinate) (Identity, bool, error) {
	r.calls++
	id, ok := r.byName[c.Name]
	if !ok {
		return Identity{}, false, nil
	}
	if r.found != nil {
		if f, set := r.found[c.Name]; set {
			return id, f, nil
		}
	}
	return id, true, nil
}

func newService(t *testing.T, cfg Config) (*Service, func() time.Time, func(time.Duration)) {
	t.Helper()
	clock := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	cfg.Now = func() time.Time { return clock }
	advance := func(d time.Duration) { clock = clock.Add(d) }
	cfg.Now = func() time.Time { return clock }
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, cfg.Now, advance
}

func TestFirstUseEstablishesTrustThenSilent(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{
		"left-pad": {Maintainers: []string{"alice"}},
	}}
	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour})

	d := svc.Check(context.Background(), "team-a", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}, Identity{})
	if !d.FirstUse || d.Drift {
		t.Fatalf("expected first-use, got %+v", d)
	}
	if d.TrustedCount != 1 {
		t.Fatalf("expected 1 trusted principal, got %d", d.TrustedCount)
	}
	// Same maintainer next pull: no drift.
	d = svc.Check(context.Background(), "team-a", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.1"}, Identity{})
	if d.Drift || d.FirstUse {
		t.Fatalf("expected silent admit, got %+v", d)
	}
}

func TestMaintainerDriftBlocksWithinCooldown(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{
		"event-stream": {Maintainers: []string{"dominictarr"}},
	}}
	block := DispositionBlock
	svc, _, advance := newService(t, Config{
		Resolver:           res,
		Cooldown:           24 * time.Hour,
		DefaultDisposition: block,
	})
	ctx := context.Background()

	// TOFU establishes dominictarr.
	svc.Check(ctx, "team-a", Coordinate{Ecosystem: "npm", Name: "event-stream", Version: "3.3.5"}, Identity{})

	// New maintainer "right9ctrl" takes over — drift.
	res.byName["event-stream"] = Identity{Maintainers: []string{"right9ctrl"}}
	d := svc.Check(ctx, "team-a", Coordinate{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}, Identity{})
	if !d.Drift {
		t.Fatalf("expected drift, got %+v", d)
	}
	if !d.Block() {
		t.Fatalf("expected block disposition to block, got %+v", d)
	}
	if len(d.Added) != 1 || d.Added[0] != "maintainer:right9ctrl" {
		t.Fatalf("unexpected added principals: %v", d.Added)
	}
	if d.Remaining <= 0 {
		t.Fatalf("expected positive cooldown remaining, got %s", d.Remaining)
	}

	// Still within cooldown: still drift.
	advance(12 * time.Hour)
	d = svc.Check(ctx, "team-a", Coordinate{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}, Identity{})
	if !d.Drift {
		t.Fatalf("expected continued drift within cooldown, got %+v", d)
	}

	// Past cooldown: the new maintainer ages into the trusted set; no more drift.
	advance(13 * time.Hour)
	d = svc.Check(ctx, "team-a", Coordinate{Ecosystem: "npm", Name: "event-stream", Version: "3.3.7"}, Identity{})
	if d.Drift {
		t.Fatalf("expected trust after cooldown, got %+v", d)
	}
}

func TestZeroCooldownSignalsOnceThenTrusts(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{
		"coa": {Maintainers: []string{"veged"}},
	}}
	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: 0, DefaultDisposition: DispositionWarn})
	ctx := context.Background()
	svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "coa", Version: "2.0.2"}, Identity{})

	res.byName["coa"] = Identity{Maintainers: []string{"attacker"}}
	d := svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "coa", Version: "2.0.3"}, Identity{})
	if !d.Drift {
		t.Fatalf("expected drift once, got %+v", d)
	}
	if d.Remaining != 0 {
		t.Fatalf("expected zero remaining with no cooldown, got %s", d.Remaining)
	}
	// Second pull of the same new maintainer: trusted, silent.
	d = svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "coa", Version: "2.0.3"}, Identity{})
	if d.Drift {
		t.Fatalf("expected silent admit after immediate trust, got %+v", d)
	}
}

func TestUnknownPublisherFailsOpen(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{}}
	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour, DefaultDisposition: DispositionBlock})
	d := svc.Check(context.Background(), "", Coordinate{Ecosystem: "npm", Name: "ghost", Version: "1.0.0"}, Identity{})
	if !d.Unknown || d.Block() {
		t.Fatalf("expected unknown fail-open, got %+v", d)
	}
}

func TestAllowlistBypass(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{
		"@acme/widget": {Maintainers: []string{"alice"}},
	}}
	svc, _, _ := newService(t, Config{
		Resolver:           res,
		Cooldown:           time.Hour,
		DefaultDisposition: DispositionBlock,
		Allowlist:          []string{"npm:@acme/"},
	})
	ctx := context.Background()
	svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "@acme/widget", Version: "1.0.0"}, Identity{})
	res.byName["@acme/widget"] = Identity{Maintainers: []string{"mallory"}}
	d := svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "@acme/widget", Version: "1.0.1"}, Identity{})
	if !d.Allowlisted || d.Drift {
		t.Fatalf("expected allowlist bypass, got %+v", d)
	}
}

func TestNamespaceDriftDetected(t *testing.T) {
	// No registry maintainers; the namespace alone is the principal. A change of
	// namespace owner (dependency confusion) is drift.
	res := &stubResolver{byName: map[string]Identity{}}
	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour, DefaultDisposition: DispositionBlock})
	ctx := context.Background()
	// First use establishes namespace ns:@acme via the merged extra identity.
	d := svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "@acme/x", Version: "1"}, Identity{Namespace: "@acme"})
	if !d.FirstUse {
		t.Fatalf("expected first use, got %+v", d)
	}
	d = svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "@acme/x", Version: "2"}, Identity{Namespace: "@evil"})
	if !d.Drift {
		t.Fatalf("expected namespace drift, got %+v", d)
	}
}

func TestKeyIdentityFolding(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{
		"sig": {Maintainers: []string{"alice"}},
	}}
	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour, DefaultDisposition: DispositionWarn})
	ctx := context.Background()
	key := KeyPrincipalFromIdentity("https://github.com/acme/.github/workflows/release.yml@refs/tags/v1", "https://token.actions.githubusercontent.com")
	svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "sig", Version: "1"}, Identity{Keys: []string{key}})
	// Same maintainers but a rotated signing key: drift.
	key2 := KeyPrincipalFromIdentity("https://github.com/attacker/.github/workflows/release.yml@refs/tags/v1", "https://token.actions.githubusercontent.com")
	d := svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "sig", Version: "2"}, Identity{Keys: []string{key2}})
	if !d.Drift {
		t.Fatalf("expected key-rotation drift, got %+v", d)
	}
}

func TestPerTenantDisposition(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{"p": {Maintainers: []string{"a"}}}}
	observe := DispositionObserve
	svc, _, _ := newService(t, Config{
		Resolver:           res,
		Cooldown:           time.Hour,
		DefaultDisposition: DispositionBlock,
		Tenants: map[string]TenantConfig{
			"lax": {Disposition: &observe},
		},
	})
	ctx := context.Background()
	for _, tenant := range []string{"strict", "lax"} {
		svc.Check(ctx, tenant, Coordinate{Ecosystem: "npm", Name: "p", Version: "1"}, Identity{})
	}
	res.byName["p"] = Identity{Maintainers: []string{"b"}}
	strict := svc.Check(ctx, "strict", Coordinate{Ecosystem: "npm", Name: "p", Version: "2"}, Identity{})
	if !strict.Block() {
		t.Fatalf("strict tenant should block, got %+v", strict)
	}
	lax := svc.Check(ctx, "lax", Coordinate{Ecosystem: "npm", Name: "p", Version: "2"}, Identity{})
	if lax.Block() || !lax.Drift {
		t.Fatalf("lax tenant should observe (drift, no block), got %+v", lax)
	}
}

func TestDurablePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "continuity.json")
	res := &stubResolver{byName: map[string]Identity{"d": {Maintainers: []string{"alice"}}}}

	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour, StorePath: path})
	svc.Check(context.Background(), "", Coordinate{Ecosystem: "npm", Name: "d", Version: "1"}, Identity{})

	// Re-open from disk: the established trust must survive, so a new maintainer
	// drifts rather than re-establishing TOFU.
	res2 := &stubResolver{byName: map[string]Identity{"d": {Maintainers: []string{"mallory"}}}}
	svc2, _, _ := newService(t, Config{Resolver: res2, Cooldown: time.Hour, StorePath: path, DefaultDisposition: DispositionBlock})
	d := svc2.Check(context.Background(), "", Coordinate{Ecosystem: "npm", Name: "d", Version: "2"}, Identity{})
	if d.FirstUse {
		t.Fatalf("expected loaded trust, got first-use: %+v", d)
	}
	if !d.Drift {
		t.Fatalf("expected drift against persisted trust, got %+v", d)
	}
}

func TestResolverCachingBoundsCalls(t *testing.T) {
	res := &stubResolver{byName: map[string]Identity{"c": {Maintainers: []string{"alice"}}}}
	svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour, CacheTTL: time.Hour})
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		svc.Check(ctx, "", Coordinate{Ecosystem: "npm", Name: "c", Version: "1"}, Identity{})
	}
	if res.calls != 1 {
		t.Fatalf("expected resolver cached to 1 call, got %d", res.calls)
	}
}

func TestNpmMaintainerParse(t *testing.T) {
	data := []byte(`{"maintainers":[{"name":"alice","email":"a@x"},{"name":"bob"}]}`)
	id := parseNpmMaintainers(data)
	if len(id.Maintainers) != 2 || id.Maintainers[0] != "alice" || id.Maintainers[1] != "bob" {
		t.Fatalf("unexpected maintainers: %v", id.Maintainers)
	}
}

func TestNamespaceForDerivation(t *testing.T) {
	cases := []struct{ eco, name, want string }{
		{"npm", "@acme/widget", "@acme"},
		{"npm", "left-pad", ""},
		{"maven", "com.acme:lib", "com.acme"},
		{"go", "github.com/acme/tool", "github.com/acme"},
		{"composer", "acme/pkg", "acme"},
	}
	for _, c := range cases {
		if got := namespaceFor(c.eco, c.name); got != c.want {
			t.Errorf("namespaceFor(%q,%q)=%q want %q", c.eco, c.name, got, c.want)
		}
	}
}

// Check is called from every request's goroutine, and the first thing it does
// is count the request for its ecosystem — before it takes the roster lock.
// That counter lives in a map; unguarded, two first requests for an ecosystem
// write it at once, and the Go runtime kills the process for that ("fatal
// error: concurrent map writes"). It took the real-client Go suite down in CI:
// a module download starts with requests in parallel.
//
// Run under -race this fails on the first unsynchronized access; without it,
// the unguarded code dies in the runtime within a few rounds.
func TestCheckIsSafeForConcurrentRequests(t *testing.T) {
	res := resolverFunc(func(_ context.Context, c Coordinate) (Identity, bool, error) {
		if c.Name == "known" {
			return Identity{Maintainers: []string{"alice"}}, true, nil
		}
		return Identity{}, false, nil
	})
	const ecosystems, perEcosystem = 24, 12
	for round := 0; round < 20; round++ {
		// A fresh service each round: the fatal write is the first one for a key.
		svc, _, _ := newService(t, Config{Resolver: res, Cooldown: time.Hour, DefaultDisposition: DispositionBlock})
		start := make(chan struct{})
		var wg sync.WaitGroup
		for e := 0; e < ecosystems; e++ {
			eco := fmt.Sprintf("eco%02d", e)
			for i := 0; i < perEcosystem; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					// Every path through Check that counts: no name (returns after
					// the first count), an unknown publisher, first use and repeat.
					switch i % 4 {
					case 0:
						svc.Check(context.Background(), "t", Coordinate{Ecosystem: eco}, Identity{})
					case 1:
						svc.Check(context.Background(), "t", Coordinate{Ecosystem: eco, Name: "nobody-knows", Version: "1"}, Identity{})
					default:
						svc.Check(context.Background(), "t", Coordinate{Ecosystem: eco, Name: "known", Version: fmt.Sprint(i)}, Identity{})
					}
					_ = svc.Metrics() // a metrics scrape reads the same counters
				}(i)
			}
		}
		close(start)
		wg.Wait()

		snap := svc.Metrics()
		if want := uint64(ecosystems * perEcosystem); snap.Checks != want {
			t.Fatalf("round %d: %d checks counted, want %d", round, snap.Checks, want)
		}
		if len(snap.ChecksByEco) != ecosystems {
			t.Fatalf("round %d: %d ecosystems counted, want %d", round, len(snap.ChecksByEco), ecosystems)
		}
		for eco, n := range snap.ChecksByEco {
			if n != perEcosystem {
				t.Fatalf("round %d: %s counted %d checks, want %d — a lost update", round, eco, n, perEcosystem)
			}
		}
	}
}

// resolverFunc is a stateless PublisherResolver, safe to call from any number
// of goroutines (stubResolver counts its calls without a lock).
type resolverFunc func(context.Context, Coordinate) (Identity, bool, error)

func (f resolverFunc) Publishers(ctx context.Context, c Coordinate) (Identity, bool, error) {
	return f(ctx, c)
}
