package llmpkgscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

func testVerdict(seed string, at time.Time) *Verdict {
	hexDigest, _ := NormalizeDigest(pkgscantest.Digest([]byte(seed)))
	return &Verdict{
		Key:        CacheKey(hexDigest, "model-x", PromptVersion),
		Digest:     "sha256:" + hexDigest,
		Verdict:    VerdictMalicious,
		Confidence: 0.9,
		Reasons:    []string{"reason for " + seed},
		Evidence:   []Evidence{{Path: "a.js", Line: 2, Excerpt: "x", Verified: true}},
		Model:      "model-x",
		ScannedAt:  at,
	}
}

func TestNormalizeDigest(t *testing.T) {
	hexd := strings.Repeat("ab", 32)
	for in, want := range map[string]string{
		"sha256:" + hexd:                  hexd,
		hexd:                              hexd,
		"SHA256:" + strings.ToUpper(hexd): hexd,
		"  sha256:" + hexd + "  ":         hexd,
	} {
		if got, ok := NormalizeDigest(in); !ok || got != want {
			t.Errorf("NormalizeDigest(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{
		"", "sha256:", "sha256:abc", hexd[:63], hexd + "0", "sha512:" + hexd, "md5:" + hexd[:32],
		"npm/left-pad/-/left-pad-1.3.0.tgz", strings.Repeat("zz", 32), "sha256:" + hexd + "/../x",
	} {
		if got, ok := NormalizeDigest(in); ok {
			t.Errorf("NormalizeDigest(%q) accepted as %q", in, got)
		}
	}
}

func TestCacheKeyFoldsModelAndPromptVersion(t *testing.T) {
	d := strings.Repeat("cd", 32)
	base := CacheKey(d, "claude-opus-4-8", 1)
	if !keyPattern.MatchString(base) || !strings.HasPrefix(base, d+"-") {
		t.Fatalf("key %q is not <digest>-<signature>", base)
	}
	if CacheKey(d, "claude-opus-4-8", 1) != base {
		t.Error("the key must be deterministic")
	}
	for name, other := range map[string]string{
		"model":          CacheKey(d, "gpt-4o", 1),
		"prompt version": CacheKey(d, "claude-opus-4-8", 2),
		"digest":         CacheKey(strings.Repeat("ef", 32), "claude-opus-4-8", 1),
	} {
		if other == base {
			t.Errorf("changing the %s did not change the key", name)
		}
	}
	if CacheKey(d, " claude-opus-4-8 ", 1) != base {
		t.Error("surrounding whitespace in the model must not change the key")
	}
}

func storeContract(t *testing.T, s VerdictStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	old, fresh := testVerdict("old", now.Add(-48*time.Hour)), testVerdict("fresh", now)

	if _, err := s.Get(ctx, old.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on an empty store: %v, want ErrNotFound", err)
	}
	for _, v := range []*Verdict{old, fresh} {
		if err := s.Put(ctx, v); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	got, err := s.Get(ctx, fresh.Key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Verdict != VerdictMalicious || got.Reasons[0] != "reason for fresh" || !got.Evidence[0].Verified || !got.ScannedAt.Equal(now) {
		t.Errorf("round trip lost data: %+v", got)
	}
	// A caller cannot corrupt the stored verdict through the returned value.
	got.Verdict = VerdictBenign
	got.Reasons[0] = "tampered"
	again, _ := s.Get(ctx, fresh.Key)
	if again.Verdict != VerdictMalicious || again.Reasons[0] != "reason for fresh" {
		t.Errorf("the stored verdict was mutated through a returned copy: %+v", again)
	}

	all, err := s.List(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("List = %d verdicts, %v", len(all), err)
	}
	n, err := s.Prune(ctx, now.Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("Prune removed %d, %v; want 1", n, err)
	}
	if _, err := s.Get(ctx, old.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("the pruned verdict is still there: %v", err)
	}
	if _, err := s.Get(ctx, fresh.Key); err != nil {
		t.Errorf("the fresh verdict was pruned: %v", err)
	}

	// A key that is not <sha256>-<signature> is refused — it would otherwise
	// become a file name.
	for _, bad := range []string{"", "../../etc/passwd", "abc", fresh.Key + "/x", strings.Repeat("a", 64), fresh.Key + ".json"} {
		if err := s.Put(ctx, &Verdict{Key: bad, Verdict: VerdictBenign}); err == nil {
			t.Errorf("Put accepted the key %q", bad)
		}
	}
	if err := s.Put(ctx, nil); err == nil {
		t.Error("Put accepted a nil verdict")
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestMemoryStore(t *testing.T) { storeContract(t, NewMemoryStore(0)) }

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(filepath.Join(dir, "verdicts"))
	if err != nil {
		t.Fatal(err)
	}
	storeContract(t, s)
	if _, err := NewFileStore(" "); err == nil {
		t.Error("an empty directory must be rejected")
	}
}

func TestFileStoreIsOwnerOnlyAndIgnoresForeignFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "verdicts")
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v := testVerdict("perm", time.Now())
	if err := s.Put(ctx, v); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("store directory mode = %o, want 0700", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Join(dir, v.Key+".json")); info.Mode().Perm() != 0o600 {
		t.Errorf("verdict file mode = %o, want 0600", info.Mode().Perm())
	}
	// No temp files are left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("store holds %d files, want exactly the verdict", len(entries))
	}

	// A verdict file that answers for another digest is not returned for this
	// one, whatever it is named: the name is the lookup key.
	other := testVerdict("other", time.Now())
	forged := verdictJSONFor(v, VerdictBenign)
	if err := os.WriteFile(filepath.Join(dir, other.Key+".json"), []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, other.Key); err == nil {
		t.Errorf("a verdict filed under the wrong key was returned: %+v", got)
	}

	// Junk in the directory is skipped by List and Prune, never fatal.
	for name, content := range map[string]string{
		"notes.txt":      "hello",
		"not-a-key.json": "{}",
		strings.Repeat("a", 64) + "-" + strings.Repeat("b", 16) + ".json": "{ not json",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List(ctx)
	if err != nil || len(all) != 1 || all[0].Key != v.Key {
		t.Errorf("List = %d verdicts (err %v), want only the valid one", len(all), err)
	}
	if _, err := s.Prune(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Errorf("Prune over junk: %v", err)
	}
}

// verdictJSONFor renders a minimal verdict file for v with the given verdict.
func verdictJSONFor(v *Verdict, verdict string) string {
	return fmt.Sprintf(`{"key":%q,"digest":%q,"verdict":%q,"confidence":0.9,"scannedAt":%q}`,
		v.Key, v.Digest, verdict, v.ScannedAt.UTC().Format(time.RFC3339))
}

func TestMemoryStoreIsBounded(t *testing.T) {
	s := NewMemoryStore(20)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	var keys []string
	for i := 0; i < 50; i++ {
		v := testVerdict(fmt.Sprintf("v%d", i), base.Add(time.Duration(i)*time.Minute))
		keys = append(keys, v.Key)
		if err := s.Put(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.List(ctx)
	if len(all) > 20 {
		t.Fatalf("store holds %d verdicts, over its bound of 20", len(all))
	}
	// The newest survive; the oldest were evicted.
	if _, err := s.Get(ctx, keys[49]); err != nil {
		t.Error("the newest verdict was evicted")
	}
	if _, err := s.Get(ctx, keys[0]); !errors.Is(err, ErrNotFound) {
		t.Error("the oldest verdict should have been evicted")
	}
	// Replacing an existing key does not evict anything.
	before := len(all)
	if err := s.Put(ctx, testVerdict("v49", base.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.List(ctx); len(after) != before {
		t.Errorf("replacing a verdict changed the count: %d -> %d", before, len(after))
	}
}

func TestForCoordinateAndVerdictsListing(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := &pkgscantest.Provider{}
	svc := newService(t, p, func(c *Config) { c.Now = func() time.Time { return now } })

	a := pkgscantest.NpmTarball("demo", "1.0.0", nil, map[string]string{"index.js": "// one\n"})
	b := pkgscantest.NpmTarball("demo", "2.0.0", nil, map[string]string{"index.js": "// two " + pkgscantest.MaliciousMarker + "\n"})
	assess(t, svc, request(a, "demo", "1.0.0", nil))
	now = now.Add(time.Minute)
	assess(t, svc, request(b, "demo", "2.0.0", nil))

	if vs := svc.ForCoordinate("", "npm", "demo", "2.0.0"); len(vs) != 1 || vs[0].Verdict != VerdictMalicious {
		t.Errorf("ForCoordinate(demo@2.0.0) = %+v", vs)
	}
	// No version: every version seen, newest first.
	vs := svc.ForCoordinate("", "npm", "demo", "")
	if len(vs) != 2 || vs[0].Version != "2.0.0" || vs[1].Version != "1.0.0" {
		t.Errorf("ForCoordinate(demo) = %+v", vs)
	}
	// Ecosystem aliases match; other ecosystems and names do not.
	if len(svc.ForCoordinate("", "nodejs", "demo", "1.0.0")) != 1 {
		t.Error("an ecosystem alias should match")
	}
	if len(svc.ForCoordinate("", "pip", "demo", "1.0.0")) != 0 || len(svc.ForCoordinate("", "npm", "other", "")) != 0 || len(svc.ForCoordinate("", "npm", "", "")) != 0 {
		t.Error("ForCoordinate matched a different coordinate")
	}

	all := svc.Verdicts("", 0)
	if len(all) != 2 || all[0].Version != "2.0.0" {
		t.Errorf("Verdicts(0) = %+v", all)
	}
	if one := svc.Verdicts("", 1); len(one) != 1 || one[0].Version != "2.0.0" {
		t.Errorf("Verdicts(1) = %+v", one)
	}
}

// A verdict quotes the package it describes. A tenant-scoped reader is shown a
// verdict only for bytes that tenant has itself pulled.
func TestVerdictsAreScopedToTheTenantsThatPulledTheBytes(t *testing.T) {
	p := &pkgscantest.Provider{}
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, p, func(c *Config) { c.Store = store })

	private := pkgscantest.NpmTarball("@acme/secret", "1.0.0", nil, map[string]string{
		"index.js": "const key = 'acme-internal'; // " + pkgscantest.MaliciousMarker + "\n",
	})
	shared := pkgscantest.NpmTarball("left-pad", "1.3.0", nil, map[string]string{"index.js": "module.exports = 1;\n"})
	anonymous := pkgscantest.NpmTarball("public", "1.0.0", nil, map[string]string{"index.js": "module.exports = 2;\n"})

	asTenant := func(artifact []byte, name, version, tenant string) {
		t.Helper()
		req := request(artifact, name, version, nil)
		req.Tenant = tenant
		assess(t, svc, req)
	}
	asTenant(private, "@acme/secret", "1.0.0", "team-a")
	asTenant(shared, "left-pad", "1.3.0", "team-a")
	asTenant(shared, "left-pad", "1.3.0", "team-b") // a cache hit still admits the tenant
	asTenant(anonymous, "public", "1.0.0", "")

	count := func(tenant, name string) int { return len(svc.ForCoordinate(tenant, "npm", name, "")) }
	for _, tc := range []struct {
		tenant, name string
		want         int
	}{
		{"team-a", "@acme/secret", 1},
		{"team-b", "@acme/secret", 0}, // knows the coordinate, never pulled the bytes
		{"team-c", "@acme/secret", 0},
		{"", "@acme/secret", 1}, // organization-wide reader
		{"team-a", "left-pad", 1},
		{"team-b", "left-pad", 1},
		{"team-c", "left-pad", 0},
		{"team-c", "public", 1}, // served to an unidentified client: not confidential
	} {
		if got := count(tc.tenant, tc.name); got != tc.want {
			t.Errorf("ForCoordinate(tenant=%q, %s) = %d verdicts, want %d", tc.tenant, tc.name, got, tc.want)
		}
	}

	names := func(tenant string) string {
		var out []string
		for _, v := range svc.Verdicts(tenant, 0) {
			out = append(out, v.Name)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := names(""); got != "@acme/secret,left-pad,public" {
		t.Errorf("unscoped listing = %s", got)
	}
	if got := names("team-b"); got != "left-pad,public" {
		t.Errorf("team-b listing = %s", got)
	}
	if got := names("team-c"); got != "public" {
		t.Errorf("team-c listing = %s", got)
	}

	// A tenant-scoped reader is not told who triggered the scan or what it cost.
	scoped := svc.ForCoordinate("team-b", "npm", "left-pad", "")[0]
	if scoped.Tenant != "" || scoped.CostUSD != 0 || scoped.InputTokens != 0 {
		t.Errorf("scoped verdict leaks the scanning tenant or its spend: %+v", scoped)
	}
	full := svc.ForCoordinate("", "npm", "left-pad", "")[0]
	if full.Tenant != "team-a" || full.InputTokens == 0 {
		t.Errorf("unscoped verdict = tenant %q tokens %d", full.Tenant, full.InputTokens)
	}
	// Scoping returns copies: the stored verdict is not altered by redaction.
	if again := svc.ForCoordinate("", "npm", "left-pad", "")[0]; again.Tenant != "team-a" {
		t.Error("redacting a scoped copy altered the stored verdict")
	}

	// After a restart only the scanning tenant is known to have had the bytes;
	// the others are re-admitted when they pull again.
	_ = svc.Close()
	svc2 := newService(t, p, func(c *Config) { c.Store = store })
	if n := len(svc2.ForCoordinate("team-a", "npm", "left-pad", "")); n != 1 {
		t.Errorf("after restart the scanning tenant sees %d verdicts, want 1", n)
	}
	if n := len(svc2.ForCoordinate("team-b", "npm", "left-pad", "")); n != 0 {
		t.Errorf("after restart team-b sees %d verdicts before pulling again, want 0", n)
	}
	req := request(shared, "left-pad", "1.3.0", nil)
	req.Tenant = "team-b"
	if rep := assess(t, svc2, req); !rep.Cached {
		t.Error("the stored verdict should have been reused")
	}
	if n := len(svc2.ForCoordinate("team-b", "npm", "left-pad", "")); n != 1 {
		t.Errorf("team-b sees %d verdicts after pulling again, want 1", n)
	}
}

func TestStandingAppliesTheCurrentConfiguration(t *testing.T) {
	mal := &Verdict{Verdict: VerdictMalicious, Confidence: 0.9}
	weak := &Verdict{Verdict: VerdictMalicious, Confidence: 0.4}
	sus := &Verdict{Verdict: VerdictSuspicious, Confidence: 0.8}
	ok := &Verdict{Verdict: VerdictBenign, Confidence: 0.9}
	injected := &Verdict{Verdict: VerdictBenign, Confidence: 0.9, Injection: []InjectionHit{{Rule: "ignore-instructions", Strong: true}}}

	for _, tc := range []struct {
		action  Action
		v       *Verdict
		disp    Disposition
		refused bool
	}{
		{ActionBlock, mal, DispositionMalicious, true},
		{ActionQuarantine, mal, DispositionMalicious, true},
		{ActionAnnotate, mal, DispositionMalicious, false},
		{ActionBlock, weak, DispositionSuspicious, false},
		{ActionBlock, sus, DispositionSuspicious, false},
		{ActionQuarantine, sus, DispositionSuspicious, true},
		{ActionQuarantine, injected, DispositionSuspicious, true},
		{ActionQuarantine, ok, DispositionBenign, false},
	} {
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Action = tc.action })
		before := svc.Metrics()
		st := svc.Standing(tc.v)
		if st.Disposition != tc.disp || st.Refused != tc.refused || st.Action != tc.action || st.Reason == "" {
			t.Errorf("%s / %s %.1f: standing = %+v, want %s refused=%v", tc.action, tc.v.Verdict, tc.v.Confidence, st, tc.disp, tc.refused)
		}
		// It agrees with the gate itself...
		rep := svc.report(Artifact{}, tc.v)
		if d := svc.Gate(rep); d.Served() == tc.refused {
			t.Errorf("%s / %s: Standing and Gate disagree (%+v vs %+v)", tc.action, tc.v.Verdict, st, d)
		}
		// ...and, unlike the gate, counts nothing.
		after := svc.Metrics()
		if tc.refused && after.Blocked+after.Quarantined != before.Blocked+before.Quarantined+1 {
			t.Errorf("gate did not count the refusal")
		}
	}

	var nilSvc *Service
	if st := nilSvc.Standing(mal); st.Refused || st.Disposition != DispositionMalicious {
		t.Errorf("nil service standing = %+v", st)
	}
	if st := newService(t, &pkgscantest.Provider{}, nil).Standing(nil); st.Disposition != DispositionUnscanned || st.Refused {
		t.Errorf("standing of no verdict = %+v", st)
	}
}
