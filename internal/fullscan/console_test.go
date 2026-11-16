package fullscan

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// What the console's Mirroring view and the tenant portal read (Task 193):
// the most recent malicious verdicts per upstream, filed under the coordinate
// the dossier is asked about, the tenants known to have pulled each artifact,
// and the figures per tenant — and what a tenant-scoped reader is left with.
func TestStatusNamesRecentMaliciousVerdictsPerTenant(t *testing.T) {
	fc := newFakeCache()
	base := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	for i, o := range []struct {
		name, tenant string
		malicious    bool
	}{
		{"evil-a", "team-a", true},
		{"good-a", "team-a", false},
		{"evil-b", "team-b", true},
		{"good-b", "team-b", false},
		{"evil-shared", "", true},
	} {
		fc.put(objectKey(o.name), "npm", objectPath(o.name), o.tenant, tarball(o.name, o.malicious), base.Add(time.Duration(i)*time.Minute))
	}
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	dir := t.TempDir()
	s := startService(t, testOptions(dir), gs, fc)
	digest := pkgscantest.Digest(tarball("evil-a", true))
	waitFor(t, "every artifact to be scanned", func() bool {
		u := upstreamStatus(t, s, "npm")
		return u.Scanned == 2 && u.Quarantined == 3 && u.Pending == 0
	})

	// team-b pulls team-a's malicious package too: the reading on record.
	sig := s.Status().Signature
	s.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("evil-a"), Key: objectKey("evil-a"), Tenant: "team-b"},
		Reading: &Reading{Kind: ReadingVerdict, Disposition: "malicious", Signature: sig, Digest: digest, Refused: true, Action: "block", Evicted: true}})
	waitFor(t, "team-b to be noted", func() bool { return s.Status().Tenants["team-b"].Malicious == 2 })

	st := s.Status()
	u := st.Upstreams[0]
	var got []string
	for _, f := range u.RecentMalicious {
		got = append(got, fmt.Sprintf("%s %s %s@%s %v %s", f.Path, f.Ecosystem, f.Name, f.Version, f.Tenants, f.Action))
		if f.Scanned.IsZero() || f.Digest == "" || !f.Quarantined {
			t.Errorf("verdict %+v", f)
		}
	}
	// Newest first: the backfill scanned the oldest cached first.
	want := []string{
		objectPath("evil-shared") + " npm evil-shared@1.0.0 [] block",
		objectPath("evil-b") + " npm evil-b@1.0.0 [team-b] block",
		objectPath("evil-a") + " npm evil-a@1.0.0 [team-a team-b] block",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recent malicious verdicts\n got %q\nwant %q", got, want)
	}
	// The ladder removed the malicious ones from the cache (block evicts).
	if a, b := st.Tenants["team-a"], st.Tenants["team-b"]; a.Cached != 1 || a.Quarantined != 1 || a.Malicious != 1 || a.Benign != 1 ||
		b.Cached != 1 || b.Quarantined != 2 || b.Malicious != 2 || b.Benign != 1 || len(st.Tenants) != 2 {
		t.Fatalf("tenant figures %+v", st.Tenants)
	}

	// A tenant-scoped reader: its own figures, the verdicts on what it
	// pulled, without who else pulled them.
	rb := st.RedactedFor("team-b")
	if len(rb.Tenants) != 1 || rb.Tenants["team-b"].Malicious != 2 {
		t.Fatalf("team-b's figures %+v", rb.Tenants)
	}
	var own []string
	for _, f := range rb.Upstreams[0].RecentMalicious {
		own = append(own, f.Name)
		if f.Tenants != nil {
			t.Errorf("a tenant is told who else pulled %s: %v", f.Name, f.Tenants)
		}
	}
	if !reflect.DeepEqual(own, []string{"evil-b", "evil-a"}) {
		t.Fatalf("team-b is shown %v", own)
	}
	if rc := st.RedactedFor("team-c"); len(rc.Tenants) != 0 || len(rc.Upstreams[0].RecentMalicious) != 0 {
		t.Fatalf("a tenant that pulled nothing is shown %+v / %+v", rc.Tenants, rc.Upstreams[0].RecentMalicious)
	}
	if r := st.Redacted(); len(r.Tenants) != 0 || len(r.Upstreams[0].RecentMalicious) != 0 {
		t.Fatalf("the redacted status names artifacts: %+v", r.Upstreams[0].RecentMalicious)
	}
	// The unredacted status is untouched by redacting a copy.
	if len(s.Status().Upstreams[0].RecentMalicious[2].Tenants) != 2 {
		t.Fatal("redacting changed the status it was made from")
	}

	// The coordinates and the tenants survive a restart.
	_ = s.Close()
	s2 := startService(t, testOptions(dir), gs, fc)
	waitFor(t, "the inventory to load", func() bool { return len(upstreamStatus(t, s2, "npm").RecentMalicious) == 3 })
	if got := upstreamStatus(t, s2, "npm").RecentMalicious[2]; got.Name != "evil-a" || !reflect.DeepEqual(got.Tenants, []string{"team-a", "team-b"}) {
		t.Fatalf("after a restart: %+v", got)
	}
}

// A reading recorded before the full scan noted coordinates learns its
// coordinate from the next pull that names it, without a new reading.
func TestARepeatedReadingTeachesTheCoordinate(t *testing.T) {
	fc := newFakeCache()
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}
	s := startService(t, testOptions(t.TempDir()), gs, fc)
	waitFor(t, "the inventory to load", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.loaded
	})
	sig := s.Status().Signature
	now := time.Now()
	s.mu.Lock()
	it := s.newItem(Artifact{Upstream: "npm", Path: objectPath("old"), Key: objectKey("old"), Digest: "sha256:aa"}, now)
	it.State, it.Verdict, it.Signature, it.Scanned = StateScanned, "malicious", sig, now.Add(-time.Hour)
	s.items[it.Key] = it
	s.putLocked(it)
	s.applyNoteLocked(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("old"), Key: objectKey("old"), Tenant: "team-a"},
		Reading: &Reading{Kind: ReadingVerdict, Disposition: "malicious", Signature: sig, Digest: "sha256:aa", Ecosystem: "npm", Name: "old", Version: "1.0.0"}})
	got := *s.items[objectKey("old")]
	s.mu.Unlock()
	if got.Name != "old" || got.Version != "1.0.0" || got.Ecosystem != "npm" || !got.Scanned.Equal(now.Add(-time.Hour)) {
		t.Fatalf("item %+v", got)
	}
	if !reflect.DeepEqual(got.Tenants, []string{"team-a"}) {
		t.Fatalf("tenants %v", got.Tenants)
	}
}

func TestKeepRecentKeepsTheNewestInOrder(t *testing.T) {
	base := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	var list []Flagged
	for _, i := range []int{3, 14, 0, 7, 9, 1, 12, 5, 11, 2, 13, 6, 8, 4, 10} {
		list = keepRecent(list, Flagged{Path: fmt.Sprintf("/p%02d", i), Scanned: base.Add(time.Duration(i) * time.Minute)}, MaxRecentMalicious)
	}
	// Two at the same moment are ordered by path.
	list = keepRecent(list, Flagged{Path: "/p13b", Scanned: base.Add(13 * time.Minute)}, MaxRecentMalicious)
	var got []string
	for _, f := range list {
		got = append(got, f.Path)
	}
	want := []string{"/p14", "/p13", "/p13b", "/p12", "/p11", "/p10", "/p09", "/p08", "/p07", "/p06"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAddTenantIsBoundedAndCopiesOnWrite(t *testing.T) {
	it := &Item{Tenant: "first"}
	if it.addTenant("first") || it.addTenant("") {
		t.Fatal("the first tenant or no tenant was added")
	}
	for i := 0; i < maxItemTenants+5; i++ {
		it.addTenant(fmt.Sprintf("t%d", i))
	}
	beyond := fmt.Sprintf("t%d", maxItemTenants+2)
	if len(it.Tenants) != maxItemTenants || !it.pulledBy("first") || !it.pulledBy("t0") || it.pulledBy(beyond) || it.pulledBy("") {
		t.Fatalf("tenants %v", it.Tenants)
	}
	snapshot := *it
	it.Tenants = it.Tenants[:2]
	it.addTenant("late")
	if snapshot.Tenants[2] != "t2" {
		t.Fatal("adding a tenant wrote into a copy's slice")
	}
}

// The sweep finds that another tenant's pull filled the cache entry (it was
// refilled): that tenant is who the scan runs as now, and the one it replaces
// stays among those who pulled the bytes — counted once each.
func TestSetFillTenantKeepsThePreviousPuller(t *testing.T) {
	it := &Item{Tenant: "acme", Tenants: []string{"globex"}}
	it.setFillTenant("globex")
	if it.Tenant != "globex" || !reflect.DeepEqual(it.Tenants, []string{"acme"}) {
		t.Fatalf("after a refill by globex: %q %v", it.Tenant, it.Tenants)
	}
	var seen []string
	it.pullersOf(func(t string) { seen = append(seen, t) })
	if !reflect.DeepEqual(seen, []string{"globex", "acme"}) {
		t.Fatalf("pullers %v", seen)
	}
	it.setFillTenant("")
	if it.Tenant != "" || !reflect.DeepEqual(it.Tenants, []string{"acme", "globex"}) {
		t.Fatalf("after a refill by no tenant: %q %v", it.Tenant, it.Tenants)
	}
}

// Other bytes under the same key: who pulled the old ones did not pull these.
func TestNewBytesForgetWhoPulledTheOldOnes(t *testing.T) {
	fc := newFakeCache()
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}
	s := startService(t, testOptions(t.TempDir()), gs, fc)
	waitFor(t, "the inventory to load", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.loaded
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	a := Artifact{Upstream: "npm", Path: objectPath("tag"), Key: objectKey("tag"), Digest: "sha256:old", Tenant: "acme"}
	it := s.newItem(a, time.Now())
	it.State, it.Verdict = StateScanned, "benign"
	it.addTenant("globex")
	s.items[it.Key] = it
	s.putLocked(it)
	b := a
	b.Digest, b.Tenant = "sha256:new", "initech"
	s.applyNoteLocked(Note{Source: SourceClient, Artifact: b, Reading: &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeBusy, Retryable: true}})
	got := s.items[a.Key]
	if got.Tenant != "initech" || len(got.Tenants) != 0 || got.Digest != "sha256:new" {
		t.Fatalf("after new bytes: tenant %q, others %v, digest %s", got.Tenant, got.Tenants, got.Digest)
	}
}

// A replica that does not lead forwards, once per artifact and tenant, who
// pulled an artifact whose pull needed nothing else of the leader; the leader
// counts it for that tenant.
func TestPullsOnAnotherReplicaAreAttributed(t *testing.T) {
	fc := newFakeCache()
	fc.put(objectKey("shared"), "npm", objectPath("shared"), "acme", tarball("shared", false), time.Now())
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}
	dir := t.TempDir()
	leader := startService(t, testOptions(dir), gs, fc)
	waitFor(t, "the artifact to be scanned", func() bool { return upstreamStatus(t, leader, "npm").Scanned == 1 })

	follower, err := New(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	sig := leader.Status().Signature
	digest := pkgscantest.Digest(tarball("shared", false))
	verdict := Reading{Kind: ReadingVerdict, Disposition: "benign", Signature: sig, Digest: digest}
	for i := 0; i < 3; i++ { // the same tenant pulling again forwards nothing more
		r := verdict
		follower.notes <- Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("shared"), Key: objectKey("shared"), Tenant: "globex"}, Reading: &r}
	}
	follower.forwardNotes()
	follower.mu.Lock()
	forwarded := len(follower.attributed)
	follower.mu.Unlock()
	if forwarded != 1 {
		t.Fatalf("%d attributions forwarded for one tenant's pulls", forwarded)
	}
	// The leader reads its inbox when its loop next runs (an idle one within
	// half a minute); here it is woken.
	leader.kick()
	waitFor(t, "globex to be counted", func() bool {
		f := leader.Status().Tenants["globex"]
		return f.Cached == 1 && f.Benign == 1
	})
}

// A coordinate longer than an item keeps is clipped once, on a rune
// boundary, and a pull naming it again changes nothing.
func TestALongCoordinateIsClippedOnce(t *testing.T) {
	long := strings.Repeat("é", 300) // 600 bytes
	it := &Item{}
	if !it.learnCoordinate(Reading{Ecosystem: "npm", Name: long, Version: "1"}) {
		t.Fatal("the first reading taught nothing")
	}
	if len(it.Name) > 512 || !utf8.ValidString(it.Name) {
		t.Fatalf("clipped to %d bytes, valid UTF-8: %v", len(it.Name), utf8.ValidString(it.Name))
	}
	if it.learnCoordinate(Reading{Ecosystem: "npm", Name: long, Version: "1"}) {
		t.Fatal("the same long coordinate counted as news again")
	}
}

// The figures per tenant are recounted every TenantInterval, not on every
// status read.
func TestTenantFiguresAreRecountedOnTheirInterval(t *testing.T) {
	fc := newFakeCache()
	fc.put(objectKey("one"), "npm", objectPath("one"), "acme", tarball("one", false), time.Now())
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}
	clk := &clock{t: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}
	opts := testOptions(t.TempDir())
	opts.Now, opts.TenantInterval = clk.now, time.Minute
	s := startService(t, opts, gs, fc)
	waitFor(t, "the artifact to be scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 1 })
	// A status computed while the inventory loaded counted no tenant yet;
	// past the interval the figures are counted again.
	clk.add(2 * time.Minute)
	upstreamStatus(t, s, "npm")
	if got := s.Status().Tenants["acme"].Cached; got != 1 {
		t.Fatalf("acme's figures %d", got)
	}
	s.mu.Lock()
	it := s.newItem(Artifact{Upstream: "npm", Path: objectPath("two"), Key: objectKey("two"), Tenant: "acme"}, clk.now())
	it.State, it.Verdict = StateScanned, "benign"
	s.items[it.Key] = it
	s.putLocked(it)
	s.mu.Unlock()
	if got := s.Status().Tenants["acme"].Cached; got != 1 {
		t.Fatalf("recounted within the interval: %d", got)
	}
	if got := upstreamStatus(t, s, "npm").Cached; got != 2 {
		t.Fatalf("the upstream's figures are not recounted on every read: %d", got)
	}
	clk.add(2 * time.Minute)
	upstreamStatus(t, s, "npm")
	if got := s.Status().Tenants["acme"].Cached; got != 2 {
		t.Fatalf("not recounted after the interval: %d", got)
	}
}

// The sweep finds the cache entry refilled by another tenant that pulled the
// same bytes: that tenant is counted once, and the tenant whose pull filled
// the entry first still counts the artifact.
func TestASweepThatFindsARefillKeepsBothTenants(t *testing.T) {
	fc := newFakeCache()
	fc.put(objectKey("foo"), "npm", objectPath("foo"), "acme", tarball("foo", false), time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC))
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}
	opts := testOptions(t.TempDir())
	opts.SweepInterval = time.Hour
	s := startService(t, opts, gs, fc)
	waitFor(t, "foo to be scanned", func() bool { return upstreamStatus(t, s, "npm").Scanned == 1 })

	sig := s.Status().Signature
	digest := pkgscantest.Digest(tarball("foo", false))
	s.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("foo"), Key: objectKey("foo"), Tenant: "globex"},
		Reading: &Reading{Kind: ReadingVerdict, Disposition: "benign", Signature: sig, Digest: digest}})
	waitFor(t, "globex to be noted", func() bool { return s.Status().Tenants["globex"].Cached == 1 })

	// The entry is filled again, by globex, with the same bytes.
	o, _ := fc.get(objectKey("foo"))
	fc.mu.Lock()
	o.meta[cache.MetaFillTenant] = "globex"
	fc.mu.Unlock()
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	upstreamStatus(t, s, "npm") // the status is computed afresh
	tenants := s.Status().Tenants
	if tenants["globex"].Cached != 1 || tenants["acme"].Cached != 1 {
		t.Fatalf("after the refill: %+v", tenants)
	}
	s.mu.Lock()
	it := *s.items[objectKey("foo")]
	s.mu.Unlock()
	if it.Tenant != "globex" || !reflect.DeepEqual(it.Tenants, []string{"acme"}) {
		t.Fatalf("item tenant %q, others %v", it.Tenant, it.Tenants)
	}
}
