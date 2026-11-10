package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scrape renders the collector's registry via its HTTP handler and returns the
// body, asserting a 200 and the Prometheus content type.
func scrape(t *testing.T, c *Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics handler status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type = %q, want text/plain...", ct)
	}
	return rec.Body.String()
}

func TestCollectorRecordsProxyMetrics(t *testing.T) {
	c := NewCollector()
	c.IncRequest("npm", "GET", "200")
	c.IncRequest("npm", "GET", "200")
	c.IncRequest("pip", "GET", "404")
	c.ObserveUpstreamLatency("npm", 0.2, true)
	c.ObserveUpstreamLatency("npm", 1.5, false) // an upstream error
	c.AddBytesServed("npm", 4096)
	c.AddBytesServed("npm", 0) // ignored
	c.IncPolicyDecision("npm", "block")
	c.IncPolicyDecision("", "allow") // empty ecosystem normalizes to "unknown"

	out := scrape(t, c)
	for _, want := range []string{
		`pullthrough_requests_total{backend="npm",method="GET",code="200"} 2`,
		`pullthrough_requests_total{backend="pip",method="GET",code="404"} 1`,
		`pullthrough_upstream_request_duration_seconds_count{backend="npm"} 2`,
		`pullthrough_upstream_errors_total{backend="npm"} 1`,
		`pullthrough_served_bytes_total{backend="npm"} 4096`,
		`pullthrough_policy_decisions_total{ecosystem="npm",action="block"} 1`,
		`pullthrough_policy_decisions_total{ecosystem="unknown",action="allow"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape missing %q\n%s", want, out)
		}
	}
}

func TestCollectorBridges(t *testing.T) {
	c := NewCollector()
	hits := 7.0
	c.BindCounter("pullthrough_cache_hits_total", "cache hits", func() float64 { return hits })
	c.BindGauge("pullthrough_scan_queue_depth", "queue depth", func() float64 { return 3 })

	if out := scrape(t, c); !strings.Contains(out, "pullthrough_cache_hits_total 7") ||
		!strings.Contains(out, "pullthrough_scan_queue_depth 3") {
		t.Errorf("bridged metrics not rendered:\n%s", out)
	}

	// Bridges are read live at scrape time.
	hits = 9
	if out := scrape(t, c); !strings.Contains(out, "pullthrough_cache_hits_total 9") {
		t.Errorf("bridge not re-read on scrape:\n%s", scrape(t, c))
	}
}

func TestCollectorHandlerRejectsNonGet(t *testing.T) {
	c := NewCollector()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
}
