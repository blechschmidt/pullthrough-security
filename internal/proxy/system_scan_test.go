package proxy

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// pinSet is a cache.PinChecker over a fixed set of keys.
type pinSet struct {
	mu   sync.Mutex
	keys map[string]bool
}

func (p *pinSet) IsPinned(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keys[key]
}

func (p *pinSet) pin(key string) {
	p.mu.Lock()
	p.keys[key] = true
	p.mu.Unlock()
}

// The release pinner and the dependency scanner (Task 181) defer the LLM
// gate's refusal: the object is admitted and served to them, with the gate's
// reading; a client's own pull of it is refused as always.
func TestSystemFetchDefersTheLLMRefusal(t *testing.T) {
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, nil)
	path := strings.TrimPrefix(llmEvilPath, "/v1/npm")
	var body bytes.Buffer
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "npm", Path: path, Tenant: "team-a", DeferLLMRefusal: true}, &body)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK || res.Gate != "" || res.CacheKey == "" || body.Len() == 0 {
		t.Fatalf("deferred fetch: %+v (%d bytes)", res, body.Len())
	}
	sl := res.LLMScan
	if sl == nil || !sl.Applicable || !sl.Deferred || sl.Report == nil || sl.Report.Disposition != llmpkgscan.DispositionMalicious || sl.Decision.Served() {
		t.Fatalf("the gate's reading: %+v", sl)
	}
	if !fx.cached(t) {
		t.Fatal("a deferred refusal evicted the object")
	}
	if got := strings.Join(fx.auditReasons(), " "); !strings.Contains(got, "llmpkgscan:deferred:malicious") {
		t.Fatalf("audit: %s", got)
	}
	if n := len(fx.notify.events); n != 0 {
		t.Fatalf("a deferred refusal notified (%d): the repository scan announces it", n)
	}
	// The request's findings document still says what the gate read.
	if doc, ok := fx.findings.Get("team-a", "evil-pad@1.0.0"); !ok || len(doc.Findings) == 0 || doc.Findings[0].RuleID != "llmpkgscan/malicious-package" {
		t.Fatalf("findings of the deferred fetch: %v %+v", ok, doc.Findings)
	}

	// Without deferral a system fetch is refused, and reports the reading.
	res2, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "npm", Path: path, Tenant: "team-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != http.StatusForbidden || res2.Gate != "llmpkgscan" || res2.LLMScan == nil || res2.LLMScan.Deferred || !res2.LLMScan.Report.Cached {
		t.Fatalf("refused fetch: %+v %+v", res2, res2.LLMScan)
	}

	// A client is refused.
	if rr := fx.pull(llmEvilPath); rr.Code != http.StatusForbidden {
		t.Fatalf("client pull: %d", rr.Code)
	}
}

// A refusal of bytes a release pins does not delete them: they are kept, for
// forensics, and the refusal stands.
func TestRefusedPinnedBytesAreKept(t *testing.T) {
	pins := &pinSet{keys: map[string]bool{}}
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.Pins = pins })
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "npm", Path: strings.TrimPrefix(llmEvilPath, "/v1/npm"), DeferLLMRefusal: true}, nil)
	if err != nil || res.CacheKey == "" {
		t.Fatalf("fetch: %v %+v", err, res)
	}
	pins.pin(res.CacheKey)
	rr := fx.pull(llmEvilPath)
	if rr.Code != http.StatusForbidden || rr.Header().Get("X-Policy-Code") != llmpkgscan.PolicyCodeMalicious {
		t.Fatalf("client pull of pinned malicious bytes: %d %s", rr.Code, rr.Header().Get("X-Policy-Code"))
	}
	if _, err := fx.cache.Stat(context.Background(), res.CacheKey); err != nil {
		t.Fatalf("pinned bytes were evicted: %v", err)
	}
	kept := false
	for _, rec := range fx.audit.Records() {
		if rec.Event.Type == audit.EventPolicy && rec.Event.Reason == "llmpkgscan:malicious" {
			kept = rec.Event.Detail["keptPinned"] == true && rec.Event.Detail["evicted"] == false
		}
	}
	if !kept {
		t.Fatal("the refusal's audit record does not say the pinned bytes were kept")
	}
}

// SystemScan reads a cached object's verdict without serving it: from the
// verdict cache when there is one, by a scan (under the gate's limits) when
// not. Nothing is evicted.
func TestSystemScan(t *testing.T) {
	p := &pkgscantest.Provider{}
	fx := newLLMGateFixture(t, llmBenignTarball(), p, nil, nil)
	ctx := context.Background()
	benign := strings.TrimPrefix(llmBenignPath, "/v1/npm")

	// Cached by a fetch that ran no scan yet (the payload changes after).
	res, err := fx.g.SystemFetch(ctx, SystemFetchRequest{Backend: "npm", Path: benign, Tenant: "team-a", DeferLLMRefusal: true}, nil)
	if err != nil || res.CacheKey == "" || res.LLMScan == nil || res.LLMScan.Report.Disposition != llmpkgscan.DispositionBenign {
		t.Fatalf("fetch: %v %+v", err, res)
	}
	calls := p.Calls()
	sl, err := fx.g.SystemScan(ctx, SystemScanRequest{Backend: "npm", Path: benign, Tenant: "team-a", CacheKey: res.CacheKey, Digest: res.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if !sl.Applicable || sl.Report == nil || !sl.Report.Cached || sl.Report.Disposition != llmpkgscan.DispositionBenign || !sl.Decision.Served() {
		t.Fatalf("reading: %+v", sl)
	}
	if p.Calls() != calls {
		t.Fatal("a verdict on record was scanned again")
	}

	// A malicious object: refused under block, not evicted.
	fx.payload.Store(llmEvilTarball())
	evil := strings.TrimPrefix(llmEvilPath, "/v1/npm")
	resEvil, err := fx.g.SystemFetch(ctx, SystemFetchRequest{Backend: "npm", Path: evil, Tenant: "team-a", DeferLLMRefusal: true}, nil)
	if err != nil || resEvil.CacheKey == "" {
		t.Fatalf("fetch evil: %v %+v", err, resEvil)
	}
	sl, err = fx.g.SystemScan(ctx, SystemScanRequest{Backend: "npm", Path: evil, Tenant: "team-a", CacheKey: resEvil.CacheKey})
	if err != nil {
		t.Fatal(err)
	}
	if sl.Report.Disposition != llmpkgscan.DispositionMalicious || sl.Decision.Served() || sl.ReviewCoordinate == "" {
		t.Fatalf("evil reading: %+v", sl)
	}
	if _, err := fx.cache.Stat(ctx, resEvil.CacheKey); err != nil {
		t.Fatalf("a system scan evicted: %v", err)
	}

	// What SystemScan refuses to read.
	if _, err := fx.g.SystemScan(ctx, SystemScanRequest{Backend: "npm", Path: evil, CacheKey: "elsewhere/" + resEvil.CacheKey}); err == nil {
		t.Fatal("a path that resolves to another key was scanned")
	}
	if _, err := fx.g.SystemScan(ctx, SystemScanRequest{Backend: "npm", Path: evil, CacheKey: resEvil.CacheKey, Digest: "sha256:" + strings.Repeat("0", 64)}); err == nil {
		t.Fatal("bytes other than the recorded digest were scanned")
	}
	if _, err := fx.g.SystemScan(ctx, SystemScanRequest{Backend: "npm", Path: "/nope/-/nope-1.0.0.tgz"}); err == nil {
		t.Fatal("an object not in the cache was scanned")
	}
	for _, bad := range []string{"/a/../b", "relative", "/x?y=1"} {
		if _, err := fx.g.SystemScan(ctx, SystemScanRequest{Backend: "npm", Path: bad}); err == nil {
			t.Fatalf("path %q accepted", bad)
		}
	}
}

// Out of the gate's scope, a system scan reads nothing.
func TestSystemScanOutOfScope(t *testing.T) {
	fx := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{}, func(c *llmpkgscan.Config) {
		c.ExcludeUpstreams = []string{"npm"}
	}, nil)
	sl, err := fx.g.SystemScan(context.Background(), SystemScanRequest{Backend: "npm", Path: strings.TrimPrefix(llmBenignPath, "/v1/npm")})
	if err != nil {
		t.Fatal(err)
	}
	if sl.Applicable || sl.NotApplicable != LLMOutOfScope || !strings.Contains(sl.NotApplicableReason, "excludeUpstreams") {
		t.Fatalf("reading: %+v", sl)
	}
}
