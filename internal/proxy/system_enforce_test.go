package proxy

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// What the full scan (Task 192) needs of the gateway: the action ladder
// applied to a reading of a cached object nobody asked for, the request that
// filled each cache entry, a gate pass over a cached object, and the readings
// of clients' pulls.

type siemDocs struct {
	mu   sync.Mutex
	docs []findings.Document
}

func (s *siemDocs) ForwardFindings(_ context.Context, doc findings.Document) {
	s.mu.Lock()
	s.docs = append(s.docs, doc)
	s.mu.Unlock()
}

func (s *siemDocs) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.docs)
}

type observations struct {
	mu  sync.Mutex
	obs []LLMScanObservation
}

func (o *observations) ObserveLLMScan(_ context.Context, obs LLMScanObservation) {
	o.mu.Lock()
	o.obs = append(o.obs, obs)
	o.mu.Unlock()
}

func (o *observations) all() []LLMScanObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]LLMScanObservation(nil), o.obs...)
}

const evilBackendPath = "/evil-pad/-/evil-pad-1.0.0.tgz"

// cacheTheEvilTarball fills the cache with the malicious tarball the way the
// full mirror does under the full scan: the gate's refusal deferred.
func cacheTheEvilTarball(t *testing.T, fx *llmGateFixture) SystemFetchResult {
	t.Helper()
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: evilBackendPath, Tenant: "team-a", DeferLLMRefusal: true, DeferredTo: "full-scan",
	}, nil)
	if err != nil || !res.Admitted || res.LLMScan == nil || !res.LLMScan.Deferred {
		t.Fatalf("deferred fetch: %+v %v", res, err)
	}
	if res.LLMScan.CacheKey != res.CacheKey || res.LLMScan.Digest != res.Digest || res.LLMScan.Size != res.Size {
		t.Fatalf("the reading does not name the object: %+v vs %+v", res.LLMScan, res)
	}
	return res
}

// Under quarantine a refused reading evicts the object, is audited with its
// source, alerted, and its findings go to the store and the SIEM.
func TestEnforceLLMScanQuarantinesARefusedObject(t *testing.T) {
	siem := &siemDocs{}
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{},
		func(c *llmpkgscan.Config) { c.Action = llmpkgscan.ActionQuarantine },
		func(d *Dependencies) { d.SIEM = siem })
	res := cacheTheEvilTarball(t, fx)

	// The cache entry records the request that filled it.
	st, err := fx.cache.Stat(context.Background(), res.CacheKey)
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Metadata; m[cache.MetaFillUpstream] != "npm" || m[cache.MetaFillPath] != evilBackendPath || m[cache.MetaFillTenant] != "team-a" {
		t.Fatalf("fill metadata %v", m)
	}
	audited := len(fx.auditReasons())
	if !strings.Contains(strings.Join(fx.auditReasons(), " "), "llmpkgscan:deferred:malicious") {
		t.Fatalf("audit %v", fx.auditReasons())
	}

	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", Subject: "system:full-scan", CacheKey: res.CacheKey, Digest: res.Digest})
	if err != nil || !sl.Report.Cached || sl.Decision.Served() {
		t.Fatalf("system scan: %+v %v", sl, err)
	}
	enf, err := fx.g.EnforceLLMScan(context.Background(), SystemEnforceRequest{
		Backend: "npm", Path: evilBackendPath, Tenant: "team-a", Subject: "system:full-scan", Scan: sl, RecordFindings: true, Source: "full-scan",
	})
	if err != nil || !enf.Refused || !enf.Evicted || enf.Action != string(llmpkgscan.ActionQuarantine) || enf.Findings == 0 {
		t.Fatalf("enforce: %+v %v", enf, err)
	}
	if fx.cached(t) {
		t.Fatal("the refused object is still cached")
	}
	var found bool
	for _, rec := range fx.audit.Records()[audited:] {
		ev := rec.Event
		if ev.Reason == "llmpkgscan:malicious" && ev.Detail["source"] == "full-scan" && ev.Detail["evicted"] == true && ev.Subject == "system:full-scan" && ev.Resource == "/v1/npm"+evilBackendPath {
			found = true
		}
	}
	if !found {
		t.Fatalf("no full-scan quarantine audit record: %v", fx.auditReasons())
	}
	if evs := fx.notify.snapshot(); len(evs) != 1 || evs[0].Type != notify.EventLLMPackageScan || evs[0].Severity != notify.SeverityCritical || evs[0].Subject != "system:full-scan" {
		t.Fatalf("alerts %+v", evs)
	}
	if siem.count() == 0 {
		t.Fatal("no SIEM document")
	}
	// A scan of the object now finds it gone.
	if _, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", CacheKey: res.CacheKey}); err == nil || !strings.Contains(err.Error(), "not in the cache") {
		t.Fatalf("a scan of the evicted object: %v", err)
	}
}

// A release pin keeps the bytes of a refused object; a stale digest is
// reported as such; a clean reading records nothing.
func TestEnforceLLMScanKeepsPinnedBytesAndIgnoresCleanOnes(t *testing.T) {
	pins := &pinSet{keys: map[string]bool{}}
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.Pins = pins })
	res := cacheTheEvilTarball(t, fx)
	pins.pin(res.CacheKey)
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", CacheKey: res.CacheKey})
	if err != nil {
		t.Fatal(err)
	}
	enf, err := fx.g.EnforceLLMScan(context.Background(), SystemEnforceRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", Scan: sl, Source: "full-scan"})
	if err != nil || !enf.Refused || enf.Evicted || !enf.KeptPinned {
		t.Fatalf("enforce on pinned bytes: %+v %v", enf, err)
	}
	if !fx.cached(t) {
		t.Fatal("pinned bytes were evicted")
	}
	if _, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", CacheKey: res.CacheKey, Digest: "sha256:" + strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("a stale digest: %v", err)
	}

	clean := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{}, nil, nil)
	cres, err := clean.g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "npm", Path: strings.TrimPrefix(llmBenignPath, "/v1/npm"), Tenant: "team-a", DeferLLMRefusal: true}, nil)
	if err != nil || !cres.Admitted {
		t.Fatalf("clean fetch: %+v %v", cres, err)
	}
	audited := len(clean.auditReasons())
	csl, err := clean.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: strings.TrimPrefix(llmBenignPath, "/v1/npm"), Tenant: "team-a", CacheKey: cres.CacheKey})
	if err != nil {
		t.Fatal(err)
	}
	cenf, err := clean.g.EnforceLLMScan(context.Background(), SystemEnforceRequest{Backend: "npm", Path: "/left-pad/-/left-pad-1.3.0.tgz", Tenant: "team-a", Scan: csl, RecordFindings: true})
	if err != nil || cenf.Refused || cenf.Evicted || cenf.Findings != 0 || len(clean.auditReasons()) != audited || len(clean.notify.snapshot()) != 0 {
		t.Fatalf("a clean reading: %+v %v, audit %v", cenf, err, clean.auditReasons()[audited:])
	}
	// Nothing to enforce without a reading.
	if res, err := clean.g.EnforceLLMScan(context.Background(), SystemEnforceRequest{}); err != nil || res.Refused {
		t.Fatalf("an empty request: %+v %v", res, err)
	}
}

// A re-scan asks the model again though the bytes have a verdict.
func TestSystemScanRefreshCallsTheModelAgain(t *testing.T) {
	p := &pkgscantest.Provider{}
	fx := newLLMGateFixture(t, llmEvilTarball(), p, nil, nil)
	res := cacheTheEvilTarball(t, fx)
	calls := p.Calls()
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", CacheKey: res.CacheKey})
	if err != nil || !sl.Report.Cached || p.Calls() != calls {
		t.Fatalf("an ordinary scan: %+v %v (%d calls)", sl, err, p.Calls()-calls)
	}
	sl, err = fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: evilBackendPath, Tenant: "team-a", CacheKey: res.CacheKey, Refresh: true})
	if err != nil || sl.Report.Cached || p.Calls() != calls+1 || sl.Report.SpentUSD <= 0 {
		t.Fatalf("a re-scan: cached %v, %d new calls, spent %v (%v)", sl.Report.Cached, p.Calls()-calls, sl.Report.SpentUSD, err)
	}
}

// A gate pass puts a cached object through every gate without fetching or
// serving it, and is not a download; a miss fetches nothing and is not
// remembered; a gate's refusal is reported as the gate's.
func TestCacheOnlyGatePass(t *testing.T) {
	dl, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fx := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.DownloadLog = dl })
	path := strings.TrimPrefix(llmBenignPath, "/v1/npm")
	req := SystemFetchRequest{Backend: "npm", Path: path, Tenant: "team-a", Subject: "system:full-scan", CacheOnly: true, NoReview: true}

	// Not cached yet: nothing is fetched.
	hits := atomic.LoadInt32(fx.hits)
	res, err := fx.g.SystemFetch(context.Background(), req, nil)
	if err != nil || res.Status != http.StatusNotFound || res.Admitted || atomic.LoadInt32(fx.hits) != hits {
		t.Fatalf("a gate pass over a miss: %+v %v (%d upstream hits)", res, err, atomic.LoadInt32(fx.hits)-hits)
	}
	// A client's pull right after is not answered from a negative cache.
	if rr := fx.pull(llmBenignPath); rr.Code != http.StatusOK {
		t.Fatalf("a client's pull after the miss: %d", rr.Code)
	}
	logged := func() int {
		r, err := dl.Query(downloadlog.Query{Limit: -1})
		if err != nil {
			t.Fatal(err)
		}
		return len(r.Entries)
	}
	before := logged()

	var body bytes.Buffer
	hits = atomic.LoadInt32(fx.hits)
	res, err = fx.g.SystemFetch(context.Background(), req, &body)
	if err != nil || res.Status != http.StatusNoContent || !res.Admitted || body.Len() != 0 || atomic.LoadInt32(fx.hits) != hits {
		t.Fatalf("a gate pass: %+v %v (%d bytes, %d upstream hits)", res, err, body.Len(), atomic.LoadInt32(fx.hits)-hits)
	}
	if logged() != before {
		t.Fatal("the gate pass is in the download log")
	}

	// The malware feed lists the package now (a proxy restarted with a newer
	// feed, over the same cache): the gate pass is refused by it.
	deps := fx.g.deps
	deps.Malfeed = malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{ID: "MAL-1", Ecosystem: "npm", Name: "left-pad", AllVersions: true, Source: "test"}},
		InitialLoaded:  true,
	})
	g2, err := New(deps, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	res, err = g2.SystemFetch(context.Background(), req, nil)
	if err != nil || res.Admitted || res.Gate != "malfeed" {
		t.Fatalf("a gate pass over a listed package: %+v %v", res, err)
	}
}

// A client's pull of a cached artifact is reported to the observer with the
// gate's reading; a system fetch is not.
func TestClientPullsAreObserved(t *testing.T) {
	obs := &observations{}
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.LLMScanObserver = obs })
	cacheTheEvilTarball(t, fx)
	if n := len(obs.all()); n != 0 {
		t.Fatalf("a system fetch was observed (%d)", n)
	}
	if rr := fx.pull(llmEvilPath); rr.Code != http.StatusForbidden {
		t.Fatalf("client pull: %d", rr.Code)
	}
	got := obs.all()
	if len(got) != 1 {
		t.Fatalf("%d observations", len(got))
	}
	o := got[0]
	if o.Backend != "npm" || o.Path != evilBackendPath || o.CacheKey == "" || o.Digest == "" || !o.Evicted ||
		o.Scan == nil || !o.Scan.Applicable || o.Scan.Report.Disposition != llmpkgscan.DispositionMalicious || o.Scan.Decision.Served() {
		t.Fatalf("observation %+v (scan %+v)", o, o.Scan)
	}
}
