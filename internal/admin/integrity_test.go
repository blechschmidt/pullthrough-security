package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// fakeIntegrity is a stub IntegrityInspector for the admin handler tests.
type fakeIntegrity struct {
	metrics cache.IntegrityMetricsSnapshot
	last    cache.IntegrityReport
	hasLast bool
	scan    cache.IntegrityReport
	scanErr error
	scanned bool
}

func (f *fakeIntegrity) IntegrityMetrics() cache.IntegrityMetricsSnapshot { return f.metrics }
func (f *fakeIntegrity) LastScan() (cache.IntegrityReport, bool)          { return f.last, f.hasLast }
func (f *fakeIntegrity) ScanIntegrity(context.Context) (cache.IntegrityReport, error) {
	f.scanned = true
	return f.scan, f.scanErr
}

func TestIntegrityStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp integrityStatusResponse
	if code := getJSON(t, srv, "/admin/api/integrity", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected enabled=false when integrity absent")
	}
}

func TestIntegrityStatusEnabled(t *testing.T) {
	fi := &fakeIntegrity{
		metrics: cache.IntegrityMetricsSnapshot{Verifications: 42, Failures: 1},
		hasLast: true,
		last:    cache.IntegrityReport{Scanned: 10, Verified: 9, Corrupted: 1, CorruptKeys: []string{"bad"}},
	}
	srv := newTestServer(t, Options{Integrity: fi, CacheIntegrityVerifyOnServe: true})
	var resp integrityStatusResponse
	if code := getJSON(t, srv, "/admin/api/integrity", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || !resp.VerifyOnServe {
		t.Fatalf("unexpected status: %+v", resp)
	}
	if resp.Metrics.Verifications != 42 || resp.Metrics.Failures != 1 {
		t.Fatalf("unexpected metrics: %+v", resp.Metrics)
	}
	if resp.LastScan == nil || resp.LastScan.Corrupted != 1 {
		t.Fatalf("expected last scan with 1 corruption, got %+v", resp.LastScan)
	}
}

func TestIntegrityScanTriggers(t *testing.T) {
	fi := &fakeIntegrity{scan: cache.IntegrityReport{Scanned: 5, Verified: 4, Corrupted: 1, CorruptKeys: []string{"k"}}}
	srv := newTestServer(t, Options{Integrity: fi})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/integrity/scan", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	if !fi.scanned {
		t.Error("scan was not triggered")
	}
	var resp integrityScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Report.Scanned != 5 || resp.Report.Corrupted != 1 {
		t.Fatalf("unexpected report: %+v", resp.Report)
	}
}

func TestIntegrityScanDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/integrity/scan", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when integrity absent, got %d", rec.Code)
	}
}

func TestIntegrityScanError(t *testing.T) {
	fi := &fakeIntegrity{scanErr: errors.New("boom")}
	srv := newTestServer(t, Options{Integrity: fi})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/integrity/scan", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on scan error, got %d", rec.Code)
	}
}

// fakeCompaction is a stub CompactionInspector for the admin handler test.
type fakeCompaction struct{ stats cache.CompactionStats }

func (f fakeCompaction) CompactionStats() cache.CompactionStats { return f.stats }

func TestCacheCompactionDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp cache.CompactionStats
	if code := getJSON(t, srv, "/admin/api/cache/compaction", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Errorf("expected enabled=false when compaction absent")
	}
}

func TestCacheCompactionEnabled(t *testing.T) {
	fc := fakeCompaction{stats: cache.CompactionStats{
		Enabled: true, Codec: "zstd", Level: 3, DedupEnabled: true,
		LogicalBytes: 1000, PhysicalBytes: 250, SavedBytes: 750,
		CompressionRatio: 4.0, DedupSavingsBytes: 400, UniqueChunks: 7,
	}}
	srv := newTestServer(t, Options{Compaction: fc})
	var resp cache.CompactionStats
	if code := getJSON(t, srv, "/admin/api/cache/compaction", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.Codec != "zstd" || resp.CompressionRatio != 4.0 {
		t.Fatalf("unexpected stats: %+v", resp)
	}
	if resp.DedupSavingsBytes != 400 || resp.UniqueChunks != 7 {
		t.Fatalf("dedup stats not surfaced: %+v", resp)
	}
}
