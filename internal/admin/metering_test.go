package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/metering"
)

func newTestMeter() *metering.Meter {
	m := metering.New(metering.Config{Enabled: true})
	m.RecordRequest("acme", "npm-proxy", "npm")
	m.RecordTraffic("acme", 2048, true)
	m.RecordTraffic("acme", 1024, false)
	m.RecordScan("acme", "vulnscan")
	return m
}

func TestMeteringEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var out map[string]any
	if code := getJSON(t, srv, "/admin/api/metering", "", &out); code != http.StatusNotFound {
		t.Fatalf("expected 404 when metering absent, got %d", code)
	}
}

func TestMeteringStatusEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{Metering: newTestMeter()})
	var snap metering.Snapshot
	if code := getJSON(t, srv, "/admin/api/metering", "", &snap); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !snap.Enabled || len(snap.Tenants) != 1 || snap.Tenants[0].Tenant != "acme" {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if snap.Grand.BytesServed() != 3072 {
		t.Errorf("grand served = %d, want 3072", snap.Grand.BytesServed())
	}
}

func TestMeteringUsageJSON(t *testing.T) {
	srv := newTestServer(t, Options{Metering: newTestMeter()})
	var rep metering.UsageReport
	if code := getJSON(t, srv, "/admin/api/metering/usage?granularity=total", "", &rep); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(rep.Totals) != 1 || rep.Totals[0].Tenant != "acme" {
		t.Fatalf("unexpected totals: %+v", rep.Totals)
	}
}

func TestMeteringUsageCSV(t *testing.T) {
	srv := newTestServer(t, Options{Metering: newTestMeter()})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/metering/usage?format=csv&granularity=total", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "tenant,period_start") {
		t.Errorf("CSV body missing header: %s", rec.Body.String())
	}
}

func TestMeteringUsageBadTime(t *testing.T) {
	srv := newTestServer(t, Options{Metering: newTestMeter()})
	var out map[string]any
	if code := getJSON(t, srv, "/admin/api/metering/usage?start=not-a-time", "", &out); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad start time, got %d", code)
	}
}
