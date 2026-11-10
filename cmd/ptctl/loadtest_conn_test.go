package main

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/loadbench"
)

func TestParseConnCounters(t *testing.T) {
	const exposition = `# HELP pullthrough_upstream_conn_acquired_total Total connection acquisitions.
# TYPE pullthrough_upstream_conn_acquired_total counter
pullthrough_upstream_conn_acquired_total 1500
# TYPE pullthrough_upstream_conn_reused_total counter
pullthrough_upstream_conn_reused_total 1460
# TYPE pullthrough_upstream_conn_dials_total counter
pullthrough_upstream_conn_dials_total 40
# a labeled series that must be ignored (wrong field count)
pullthrough_upstream_tls_pin_violations_by_host_total{host="x",mode="enforce"} 3
pullthrough_requests_total{backend="npm",method="GET",code="200"} 99
`
	var m loadbench.ServerMetrics
	parseConnCounters(exposition, &m)

	if m.ConnAcquired != 1500 {
		t.Errorf("ConnAcquired = %d, want 1500", m.ConnAcquired)
	}
	if m.ConnReused != 1460 {
		t.Errorf("ConnReused = %d, want 1460", m.ConnReused)
	}
	if m.ConnDials != 40 {
		t.Errorf("ConnDials = %d, want 40", m.ConnDials)
	}
}

func TestParseConnCountersIgnoresMissing(t *testing.T) {
	var m loadbench.ServerMetrics
	parseConnCounters("# only comments\n\n", &m)
	if m.ConnAcquired != 0 || m.ConnReused != 0 || m.ConnDials != 0 {
		t.Errorf("expected zero counters for empty exposition, got %+v", m)
	}
}
