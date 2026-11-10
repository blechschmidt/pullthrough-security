package admin

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// TestNotifyStatusDisabled reports enabled=false when no notifier is wired.
func TestNotifyStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp notifyStatusResponse
	if code := getJSON(t, srv, "/admin/api/notify", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected enabled=false without a notifier")
	}
}

// TestNotifyStatusAndTest exercises the status and test endpoints against a real
// Notifier whose webhook sink points at an httptest server.
func TestNotifyStatusAndTest(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	n, err := notify.Build(notify.Config{
		Sinks: []notify.SinkConfig{{Name: "hook", Kind: "webhook", URL: upstream.URL}},
	}, nil)
	if err != nil {
		t.Fatalf("notify.Build: %v", err)
	}
	defer n.Close()

	srv := newTestServer(t, Options{Notify: n})

	// Status lists the configured sink.
	var status notifyStatusResponse
	if code := getJSON(t, srv, "/admin/api/notify", "", &status); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !status.Enabled || len(status.Sinks) != 1 || status.Sinks[0].Name != "hook" {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Test endpoint delivers synchronously and reports success.
	req := httptest.NewRequest(http.MethodPost, "/admin/api/notify/test", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test endpoint code = %d, body %s", rec.Code, rec.Body.String())
	}
	if hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1", hits.Load())
	}

	// An unknown sink name is a 404.
	req = httptest.NewRequest(http.MethodPost, "/admin/api/notify/test?sink=nope", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown sink test code = %d, want 404", rec.Code)
	}
}
