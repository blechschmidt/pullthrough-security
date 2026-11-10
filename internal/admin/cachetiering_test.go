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

// fakeTiering is a stub TieringInspector for the admin handler tests.
type fakeTiering struct {
	stats    cache.TieredStats
	report   cache.TierSweepReport
	sweepErr error
	swept    bool
}

func (f *fakeTiering) TieredStats() cache.TieredStats { return f.stats }
func (f *fakeTiering) SweepTiers(context.Context) (cache.TierSweepReport, error) {
	f.swept = true
	return f.report, f.sweepErr
}

func TestCacheTieringDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp cache.TieredStats
	if code := getJSON(t, srv, "/admin/api/cache/tiering", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Errorf("expected enabled=false when tiering absent")
	}
}

func TestCacheTieringEnabled(t *testing.T) {
	ft := &fakeTiering{stats: cache.TieredStats{
		Enabled: true, PromoteOnRead: true, HotObjects: 3, ColdObjects: 5,
		HotBytes: 300, ColdBytes: 500, Promotions: 2, Demotions: 4,
		HotHits: 7, ColdHits: 3, HotTierHitRatio: 0.7,
	}}
	srv := newTestServer(t, Options{Tiering: ft})
	var resp cache.TieredStats
	if code := getJSON(t, srv, "/admin/api/cache/tiering", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.HotObjects != 3 || resp.ColdObjects != 5 || resp.HotTierHitRatio != 0.7 {
		t.Fatalf("unexpected stats: %+v", resp)
	}
}

func TestCacheTieringSweepTriggers(t *testing.T) {
	ft := &fakeTiering{report: cache.TierSweepReport{HotObjectsBefore: 10, Candidates: 3, Demoted: 2, Skipped: 1}}
	srv := newTestServer(t, Options{Tiering: ft})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cache/tiering/sweep", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	if !ft.swept {
		t.Error("sweep was not triggered")
	}
	var resp cache.TierSweepReport
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Demoted != 2 || resp.Candidates != 3 {
		t.Fatalf("unexpected report: %+v", resp)
	}
}

func TestCacheTieringSweepDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cache/tiering/sweep", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when tiering absent, got %d", rec.Code)
	}
}

func TestCacheTieringSweepError(t *testing.T) {
	ft := &fakeTiering{sweepErr: errors.New("boom")}
	srv := newTestServer(t, Options{Tiering: ft})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/cache/tiering/sweep", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on sweep error, got %d", rec.Code)
	}
}
