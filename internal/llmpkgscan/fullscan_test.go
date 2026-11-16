package llmpkgscan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// What the full scan (Task 192) needs of the gate: a re-scan that calls the
// model although the bytes have a verdict, the cost of each scan, the verdict
// schema version in the verdict cache, the scan signature, and the gate's load.

// A refreshing request calls the model again and replaces the stored verdict;
// an ordinary one is answered from the verdict cache.
func TestRefreshScansAgainAndReplacesTheVerdict(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p.BundleOnly(), nil)
	art := benignPackage()
	first := assess(t, svc, request(art, "left-pad", "1.3.0", nil))
	if !first.Scanned() || first.Cached || p.Calls() != 1 {
		t.Fatalf("first scan: %+v, %d calls", first, p.Calls())
	}
	if again := assess(t, svc, request(art, "left-pad", "1.3.0", nil)); !again.Cached || p.Calls() != 1 || again.SpentUSD != 0 {
		t.Fatalf("a second pull: cached %v, spent %v, %d calls", again.Cached, again.SpentUSD, p.Calls())
	}
	p.Judge = func(string) string { return pkgscantest.MaliciousVerdict("package/index.js", 1, "module.exports") }
	req := request(art, "left-pad", "1.3.0", nil)
	req.Refresh = true
	fresh := assess(t, svc, req)
	if fresh.Cached || p.Calls() != 2 || fresh.Disposition != DispositionMalicious {
		t.Fatalf("refresh: cached %v, disposition %s, %d calls", fresh.Cached, fresh.Disposition, p.Calls())
	}
	if after := assess(t, svc, request(art, "left-pad", "1.3.0", nil)); !after.Cached || after.Disposition != DispositionMalicious {
		t.Fatalf("the refreshed verdict did not replace the stored one: %+v", after)
	}
}

// A report says what its scan cost; a verdict from the cache cost nothing.
func TestReportsCarryTheirScansCost(t *testing.T) {
	p := &pkgscantest.Provider{Usage: commit.Usage{InputTokens: 1000, OutputTokens: 100}}
	svc := newService(t, p.BundleOnly(), func(c *Config) {
		c.Pricing = commit.DefaultPricing().WithOverrides(map[string]commit.ModelPrice{"mock-model": {InputPerMTok: 1000, OutputPerMTok: 10000}})
	})
	rep := assess(t, svc, request(benignPackage(), "left-pad", "1.3.0", nil))
	if want := 1000.0/1e6*1000 + 100.0/1e6*10000; rep.SpentUSD != want || rep.Verdict.CostUSD != want {
		t.Fatalf("spent %v (verdict %v), want %v", rep.SpentUSD, rep.Verdict.CostUSD, want)
	}
	// A scan that fails after the model was called still reports its cost.
	p.Judge = func(string) string { return "not a verdict" }
	failed := assess(t, svc, request(maliciousPackage(), "evil-pad", "1.0.0", nil))
	if failed.Unscanned == nil || failed.SpentUSD <= 0 {
		t.Fatalf("a failed scan: %+v spent %v", failed.Unscanned, failed.SpentUSD)
	}
}

// A verdict written under another verdict schema is not served: the bytes are
// scanned again and the new verdict replaces it under the same key.
func TestAVerdictOfAnotherSchemaIsScannedAgain(t *testing.T) {
	p := &pkgscantest.Provider{}
	store := NewMemoryStore(0)
	svc := newService(t, p.BundleOnly(), func(c *Config) { c.Store = store })
	art := benignPackage()
	rep := assess(t, svc, request(art, "left-pad", "1.3.0", nil))
	if rep.Verdict.SchemaVersion != VerdictSchemaVersion {
		t.Fatalf("a new verdict carries schema version %d", rep.Verdict.SchemaVersion)
	}
	// A record from before the field existed reads as version 1.
	old := rep.Verdict.clone()
	old.SchemaVersion = 0
	if err := store.Put(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if again := assess(t, svc, request(art, "left-pad", "1.3.0", nil)); !again.Cached || p.Calls() != 1 {
		t.Fatalf("a record without a schema version was not served as version 1 (%d calls)", p.Calls())
	}
	newer := rep.Verdict.clone()
	newer.SchemaVersion = VerdictSchemaVersion + 1
	if err := store.Put(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	again := assess(t, svc, request(art, "left-pad", "1.3.0", nil))
	if again.Cached || p.Calls() != 2 || again.Verdict.SchemaVersion != VerdictSchemaVersion || again.Verdict.Key != rep.Verdict.Key {
		t.Fatalf("a verdict of another schema was served: cached %v, %d calls", again.Cached, p.Calls())
	}
	if v, err := store.Get(context.Background(), rep.Verdict.Key); err != nil || v.SchemaVersion != VerdictSchemaVersion {
		t.Fatalf("the stored verdict was not replaced: %+v %v", v, err)
	}
}

func TestSignatureAndLoad(t *testing.T) {
	svc := newService(t, (&pkgscantest.Provider{}).BundleOnly(), func(c *Config) { c.MaxConcurrent = 3 })
	sig := svc.Signature()
	if sig.Model != "mock-model" || sig.PromptVersion != PromptVersion || sig.SchemaVersion != VerdictSchemaVersion {
		t.Fatalf("signature %+v", sig)
	}
	if got, want := sig.String(), "mock-model|p"+itoa(PromptVersion)+"|s"+itoa(VerdictSchemaVersion); got != want {
		t.Fatalf("signature string %q, want %q", got, want)
	}
	rep := assess(t, svc, request(benignPackage(), "left-pad", "1.3.0", nil))
	if SignatureOf(rep.Verdict) != sig {
		t.Fatalf("the verdict's signature %+v is not the gate's %+v", SignatureOf(rep.Verdict), sig)
	}
	if running, waiting, slots := svc.Load(); running != 0 || waiting != 0 || slots != 3 {
		t.Fatalf("load %d/%d/%d", running, waiting, slots)
	}
	var nilSvc *Service
	if nilSvc.Signature() != (ScanSignature{}) || (ScanSignature{}).String() != "" {
		t.Fatal("a nil service has a signature")
	}
	if r, w, s := nilSvc.Load(); r != 0 || w != 0 || s != 0 {
		t.Fatal("a nil service has a load")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// A stored malicious verdict of another verdict schema is not served as the
// answer, but while no new verdict can be had (the provider down, the budget
// spent) it still refuses the bytes; a bundle's current verdict replaces it.
func TestAStaleRefusingVerdictKeepsRefusingUntilReplaced(t *testing.T) {
	p := &pkgscantest.Provider{}
	store := NewMemoryStore(0)
	svc := newService(t, p.BundleOnly(), func(c *Config) { c.Store = store })
	art := maliciousPackage()
	rep := assess(t, svc, request(art, "evil-pad", "1.0.0", nil))
	if rep.Disposition != DispositionMalicious || svc.Decide(rep).Served() {
		t.Fatalf("first scan: %+v", rep)
	}
	current := rep.Verdict.clone()
	stale := rep.Verdict.clone()
	stale.SchemaVersion = VerdictSchemaVersion + 1
	if err := store.Put(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	p.Err = errors.New("provider down")
	again := assess(t, svc, request(art, "evil-pad", "1.0.0", nil))
	if again.Disposition != DispositionMalicious || svc.Decide(again).Served() {
		t.Fatalf("with a stale-schema malicious record and the provider down: %s (served %v)", again.Disposition, svc.Decide(again).Served())
	}
	raw, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportVerdict(context.Background(), store, current.Digest, raw); err != nil {
		t.Fatalf("a bundle's current verdict over the stale record: %v", err)
	}
	if v, err := store.Get(context.Background(), current.Key); err != nil || v.schema() != VerdictSchemaVersion {
		t.Fatalf("the stale record was not replaced: %+v %v", v, err)
	}
}

// A scan paid from the caller's own budget neither consults nor charges the
// gate's ceilings.
func TestOwnBudgetScansLeaveTheGateBudgetAlone(t *testing.T) {
	p := &pkgscantest.Provider{Usage: commit.Usage{InputTokens: 2_000_000}}
	svc := newService(t, p.BundleOnly(), func(c *Config) {
		c.Budget = BudgetConfig{Enabled: true, GlobalCeilingUSD: 1, TenantCeilingUSD: 1}
	})
	req := request(benignPackage(), "left-pad", "1.3.0", nil)
	req.OwnBudget = true
	if rep := assess(t, svc, req); !rep.Scanned() || rep.SpentUSD <= 1 {
		t.Fatalf("an own-budget scan: %+v spent %v", rep.Unscanned, rep.SpentUSD)
	}
	if b := svc.BudgetStatus(); b.GlobalSpentUSD != 0 || b.GlobalExhausted {
		t.Fatalf("the gate's budget was charged: %+v", b)
	}
	// A client's scan still has the whole budget.
	if rep := assess(t, svc, request(maliciousPackage(), "evil-pad", "1.0.0", nil)); !rep.Scanned() {
		t.Fatalf("a client's scan after the own-budget one: %+v", rep.Unscanned)
	}
}
