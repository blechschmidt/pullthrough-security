package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
)

// fakeCacheGC is a stub CacheGCInspector for the admin handler tests.
type fakeCacheGC struct {
	snap      cachegc.Snapshot
	last      cachegc.Report
	hasLast   bool
	lastDry   bool
	runReport cachegc.Report
}

func (f *fakeCacheGC) Snapshot() cachegc.Snapshot         { return f.snap }
func (f *fakeCacheGC) LastReport() (cachegc.Report, bool) { return f.last, f.hasLast }
func (f *fakeCacheGC) Run(_ context.Context, dryRun bool) (cachegc.Report, error) {
	f.lastDry = dryRun
	rep := f.runReport
	rep.DryRun = dryRun
	return rep, nil
}

func TestCacheGCStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp cacheGCStatusResponse
	if code := getJSON(t, srv, "/admin/api/cachegc", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected enabled=false when GC absent")
	}
}

func TestCacheGCStatusEnabled(t *testing.T) {
	gc := &fakeCacheGC{
		snap: cachegc.Snapshot{
			Enabled: true, Policy: "lru", EvictedTotal: 7, BytesReclaimedTotal: 4096,
			CapacityBytes: 1000, HighWatermarkBytes: 900, UsedBytes: 850, UtilizationPct: 85,
		},
		hasLast: true,
		last:    cachegc.Report{EvictedCount: 2, BytesReclaimed: 500},
	}
	srv := newTestServer(t, Options{CacheGC: gc})
	var resp cacheGCStatusResponse
	if code := getJSON(t, srv, "/admin/api/cachegc", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.Snapshot.EvictedTotal != 7 {
		t.Fatalf("unexpected status: %+v", resp)
	}
	if resp.LastReport == nil || resp.LastReport.EvictedCount != 2 {
		t.Fatalf("expected last report with 2 evictions, got %+v", resp.LastReport)
	}
}

func TestCacheGCRunDefaultsToDryRun(t *testing.T) {
	gc := &fakeCacheGC{runReport: cachegc.Report{EvictedCount: 3, BytesReclaimed: 750}}
	srv := newTestServer(t, Options{CacheGC: gc})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cachegc/run", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	if !gc.lastDry {
		t.Error("run without dryRun param must default to a dry-run")
	}
	var resp cacheGCRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Report.DryRun || resp.Report.EvictedCount != 3 {
		t.Fatalf("unexpected report: %+v", resp.Report)
	}
}

func TestCacheGCRunRealWhenRequested(t *testing.T) {
	gc := &fakeCacheGC{runReport: cachegc.Report{EvictedCount: 1}}
	srv := newTestServer(t, Options{CacheGC: gc})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cachegc/run?dryRun=false", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if gc.lastDry {
		t.Error("dryRun=false must perform a real run")
	}
}

func TestCacheGCRunBadParam(t *testing.T) {
	gc := &fakeCacheGC{}
	srv := newTestServer(t, Options{CacheGC: gc})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cachegc/run?dryRun=maybe", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid dryRun, got %d", rec.Code)
	}
}

func TestCacheGCRunDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cachegc/run", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when GC absent, got %d", rec.Code)
	}
}
