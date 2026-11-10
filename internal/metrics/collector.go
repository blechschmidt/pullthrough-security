package metrics

import (
	"net/http"
)

// ContentType is the media type of the Prometheus text exposition format the
// Collector emits. Prometheus servers key their parser off this value.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Collector is the proxy's central telemetry surface. It owns a Registry, the
// proxy-level instruments the gateway records into (request counts, upstream
// latency, bytes served, policy decisions), and the HTTP handler that renders
// the whole set in the Prometheus text format.
//
// Values owned by other subsystems — the cache's hit/miss counters, the scan
// queue depth — are not duplicated here; instead they are bridged at scrape time
// via Bind* methods so a single source of truth is read live on each scrape.
//
// A Collector is safe for concurrent use. Its recording methods satisfy the
// gateway's metrics recorder interface structurally, so the proxy package need
// not import this one.
type Collector struct {
	reg *Registry

	requests     *CounterVec   // by backend, method, code
	upstreamTime *HistogramVec // by backend
	upstreamErr  *CounterVec   // by backend
	bytesServed  *CounterVec   // by backend
	policy       *CounterVec   // by ecosystem, action
}

// NewCollector constructs a Collector with the proxy-level instruments
// registered. The metric names follow the project's "pullthrough_" prefix
// convention so they namespace cleanly alongside other exporters.
func NewCollector() *Collector {
	r := New()
	c := &Collector{reg: r}
	c.requests = r.NewCounterVec(
		"pullthrough_requests_total",
		"Total backend requests served, partitioned by backend, HTTP method, and response status code.",
		[]string{"backend", "method", "code"})
	c.upstreamTime = r.NewHistogramVec(
		"pullthrough_upstream_request_duration_seconds",
		"Latency of upstream fetches (cache misses and pass-through) in seconds, by backend.",
		[]string{"backend"}, DefaultBuckets)
	c.upstreamErr = r.NewCounterVec(
		"pullthrough_upstream_errors_total",
		"Total upstream fetches that failed, by backend.",
		[]string{"backend"})
	c.bytesServed = r.NewCounterVec(
		"pullthrough_served_bytes_total",
		"Total response body bytes served to clients, by backend.",
		[]string{"backend"})
	c.policy = r.NewCounterVec(
		"pullthrough_policy_decisions_total",
		"Total admission-policy decisions, by ecosystem and action (allow|warn|block).",
		[]string{"ecosystem", "action"})
	return c
}

// Registry exposes the underlying registry so callers can register additional
// metrics (for example, subsystem-owned scrape-time callbacks).
func (c *Collector) Registry() *Registry { return c.reg }

// Handler returns an http.Handler that renders the registry in the Prometheus
// text exposition format. It answers GET and HEAD only.
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		if r.Method == http.MethodHead {
			return
		}
		_ = c.reg.WritePrometheus(w)
	})
}

// --- gateway recorder surface ----------------------------------------------

// IncRequest records one served backend request.
func (c *Collector) IncRequest(backend, method, code string) {
	c.requests.With(backend, method, code).Inc()
}

// ObserveUpstreamLatency records the duration of an upstream fetch and, when ok
// is false, increments the per-backend upstream error counter.
func (c *Collector) ObserveUpstreamLatency(backend string, seconds float64, ok bool) {
	c.upstreamTime.With(backend).Observe(seconds)
	if !ok {
		c.upstreamErr.With(backend).Inc()
	}
}

// AddBytesServed records response body bytes written to a client.
func (c *Collector) AddBytesServed(backend string, n int64) {
	if n > 0 {
		c.bytesServed.With(backend).Add(float64(n))
	}
}

// IncPolicyDecision records one admission-policy decision.
func (c *Collector) IncPolicyDecision(ecosystem, action string) {
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	c.policy.With(ecosystem, action).Inc()
}

// --- subsystem bridges ------------------------------------------------------

// BindGauge registers a gauge whose value is read from fn at scrape time. Use it
// to surface a value owned by another subsystem (e.g. the scan queue depth)
// without duplicating its state here.
func (c *Collector) BindGauge(name, help string, fn func() float64) {
	c.reg.RegisterFunc(name, help, "gauge", fn)
}

// BindCounter registers a monotonic counter whose value is read from fn at
// scrape time (e.g. the cache's cumulative hit/miss counters).
func (c *Collector) BindCounter(name, help string, fn func() float64) {
	c.reg.RegisterFunc(name, help, "counter", fn)
}

// BindCounterVec registers a labeled monotonic counter whose series are produced
// by fn at scrape time. Use it to surface a subsystem's per-key counters (e.g.
// notification deliveries partitioned by sink) as a single labeled metric.
func (c *Collector) BindCounterVec(name, help string, labelNames []string, fn func() []LabeledValue) {
	c.reg.RegisterFuncVec(name, help, "counter", labelNames, fn)
}

// BindGaugeVec registers a labeled gauge whose series are produced by fn at
// scrape time. Use it to surface a subsystem's per-key gauges (e.g. the active
// lockdown mode partitioned by mode) as a single labeled metric.
func (c *Collector) BindGaugeVec(name, help string, labelNames []string, fn func() []LabeledValue) {
	c.reg.RegisterFuncVec(name, help, "gauge", labelNames, fn)
}
