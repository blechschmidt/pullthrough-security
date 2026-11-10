// Package metrics provides a small, dependency-free metrics registry that emits
// the Prometheus text exposition format (version 0.0.4). It supports the metric
// types the proxy needs — counters, gauges, and histograms, each optionally
// partitioned by labels — plus scrape-time callback metrics for values that are
// owned by another subsystem (e.g. the cache's internal counters or the scan
// queue depth).
//
// The implementation is intentionally self-contained so the proxy can expose
// Prometheus-compatible telemetry without pulling in a third-party client
// library. All exported types are safe for concurrent use.
package metrics

import (
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds a set of collectors and renders them in the Prometheus text
// exposition format. The zero value is not usable; construct one with New.
type Registry struct {
	mu    sync.Mutex
	cols  []collector
	names map[string]struct{}
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{names: make(map[string]struct{})}
}

// collector is the internal interface every registered metric implements.
type collector interface {
	// meta returns the metric's base name, help text, and Prometheus type.
	meta() (name, help, typ string)
	// collect returns the current series for the metric.
	collect() []series
}

// series is one rendered time series: a name suffix (for histograms), an
// ordered label set, and a value.
type series struct {
	suffix string
	labels []label
	value  float64
}

type label struct{ name, value string }

// register adds c to the registry, rejecting duplicate metric names so a
// programming error surfaces immediately rather than producing malformed
// output.
func (r *Registry) register(c collector) {
	name, _, _ := c.meta()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.names[name]; dup {
		panic("metrics: duplicate metric registered: " + name)
	}
	r.names[name] = struct{}{}
	r.cols = append(r.cols, c)
}

// NewCounter registers and returns a label-less counter.
func (r *Registry) NewCounter(name, help string) *Counter {
	return r.NewCounterVec(name, help, nil).With()
}

// NewGauge registers and returns a label-less gauge.
func (r *Registry) NewGauge(name, help string) *Gauge {
	return r.NewGaugeVec(name, help, nil).With()
}

// NewCounterVec registers and returns a counter partitioned by labelNames.
func (r *Registry) NewCounterVec(name, help string, labelNames []string) *CounterVec {
	v := &CounterVec{base: newVecBase(name, help, "counter", labelNames)}
	r.register(v)
	return v
}

// NewGaugeVec registers and returns a gauge partitioned by labelNames.
func (r *Registry) NewGaugeVec(name, help string, labelNames []string) *GaugeVec {
	v := &GaugeVec{base: newVecBase(name, help, "gauge", labelNames)}
	r.register(v)
	return v
}

// NewHistogramVec registers and returns a histogram partitioned by labelNames.
// buckets are the upper bounds (an implicit +Inf bucket is always added); when
// empty, DefaultBuckets is used.
func (r *Registry) NewHistogramVec(name, help string, labelNames []string, buckets []float64) *HistogramVec {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	v := &HistogramVec{base: newVecBase(name, help, "histogram", labelNames), buckets: sortedBuckets(buckets)}
	r.register(v)
	return v
}

// NewHistogram registers and returns a label-less histogram.
func (r *Registry) NewHistogram(name, help string, buckets []float64) *Histogram {
	return r.NewHistogramVec(name, help, nil, buckets).With()
}

// RegisterFunc registers a metric whose value is read from fn at scrape time.
// typ must be "counter" or "gauge". This is the bridge for values owned by
// another subsystem (for example, the cache's internal hit/miss counters).
func (r *Registry) RegisterFunc(name, help, typ string, fn func() float64) {
	r.register(&funcCollector{name: name, help: help, typ: typ, fn: fn})
}

// LabeledValue is one labeled sample produced by a func-vec collector at scrape
// time: Labels holds the label values in labelNames order, paired with Value.
type LabeledValue struct {
	Labels []string
	Value  float64
}

// RegisterFuncVec registers a labeled metric whose series are produced by fn at
// scrape time. It is the labeled counterpart to RegisterFunc, used to bridge a
// subsystem's per-key counters (e.g. notification deliveries by sink) without
// duplicating their state. typ must be "counter" or "gauge". A produced sample
// whose label count does not match labelNames is skipped.
func (r *Registry) RegisterFuncVec(name, help, typ string, labelNames []string, fn func() []LabeledValue) {
	r.register(&funcVecCollector{name: name, help: help, typ: typ, labelNames: labelNames, fn: fn})
}

// WritePrometheus renders every registered metric to w in the Prometheus text
// exposition format. Output is deterministic: metrics appear in registration
// order and series within a metric are sorted by their labels.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.Lock()
	cols := make([]collector, len(r.cols))
	copy(cols, r.cols)
	r.mu.Unlock()

	bw := &errWriter{w: w}
	for _, c := range cols {
		name, help, typ := c.meta()
		if help != "" {
			bw.writeString("# HELP " + name + " " + escapeHelp(help) + "\n")
		}
		bw.writeString("# TYPE " + name + " " + typ + "\n")

		ss := c.collect()
		sort.Slice(ss, func(i, j int) bool { return lessSeries(ss[i], ss[j]) })
		for _, s := range ss {
			bw.writeString(name + s.suffix)
			writeLabels(bw, s.labels)
			bw.writeString(" " + formatFloat(s.value) + "\n")
		}
	}
	return bw.err
}

// DefaultBuckets are latency buckets in seconds suitable for upstream request
// timing, spanning 5ms to 30s.
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// --- atomic float helpers ---------------------------------------------------

func addFloat(bits *atomic.Uint64, delta float64) {
	for {
		old := bits.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if bits.CompareAndSwap(old, next) {
			return
		}
	}
}

func setFloat(bits *atomic.Uint64, v float64) { bits.Store(math.Float64bits(v)) }
func loadFloat(bits *atomic.Uint64) float64   { return math.Float64frombits(bits.Load()) }

// --- Counter ----------------------------------------------------------------

// Counter is a monotonically increasing value.
type Counter struct{ bits atomic.Uint64 }

// Inc adds one.
func (c *Counter) Inc() { addFloat(&c.bits, 1) }

// Add increases the counter by v, which must be non-negative.
func (c *Counter) Add(v float64) {
	if v < 0 {
		return
	}
	addFloat(&c.bits, v)
}

// Value returns the current value.
func (c *Counter) Value() float64 { return loadFloat(&c.bits) }

// --- Gauge ------------------------------------------------------------------

// Gauge is a value that can go up or down.
type Gauge struct{ bits atomic.Uint64 }

// Set replaces the gauge value.
func (g *Gauge) Set(v float64) { setFloat(&g.bits, v) }

// Add adds v (which may be negative).
func (g *Gauge) Add(v float64) { addFloat(&g.bits, v) }

// Inc adds one.
func (g *Gauge) Inc() { addFloat(&g.bits, 1) }

// Dec subtracts one.
func (g *Gauge) Dec() { addFloat(&g.bits, -1) }

// Value returns the current value.
func (g *Gauge) Value() float64 { return loadFloat(&g.bits) }

// --- Histogram --------------------------------------------------------------

// Histogram aggregates observations into cumulative buckets, tracking the
// count and sum so quantiles and averages can be computed by the scraper.
type Histogram struct {
	buckets []float64       // upper bounds, ascending (no +Inf)
	counts  []atomic.Uint64 // per-bucket (non-cumulative) counts
	sum     atomic.Uint64   // float bits
	count   atomic.Uint64
}

func newHistogram(buckets []float64) *Histogram {
	return &Histogram{buckets: buckets, counts: make([]atomic.Uint64, len(buckets))}
}

// Observe records a single value.
func (h *Histogram) Observe(v float64) {
	// Find the first bucket whose upper bound is >= v.
	i := sort.SearchFloat64s(h.buckets, v)
	if i < len(h.counts) {
		h.counts[i].Add(1)
	}
	h.count.Add(1)
	addFloat(&h.sum, v)
}

// --- vec plumbing -----------------------------------------------------------

// vecBase holds the metadata and child map shared by every *Vec type.
type vecBase struct {
	name, help, typ string
	labelNames      []string

	mu       sync.Mutex
	children map[string]*child
}

type child struct {
	labels []label
	// exactly one of the following is set, per metric type
	counter *Counter
	gauge   *Gauge
	hist    *Histogram
}

func newVecBase(name, help, typ string, labelNames []string) *vecBase {
	return &vecBase{name: name, help: help, typ: typ, labelNames: labelNames, children: make(map[string]*child)}
}

func (b *vecBase) meta() (string, string, string) { return b.name, b.help, b.typ }

// keyFor validates the label cardinality and returns a stable map key.
func (b *vecBase) keyFor(values []string) (string, []label) {
	if len(values) != len(b.labelNames) {
		panic("metrics: wrong number of label values for " + b.name)
	}
	labels := make([]label, len(values))
	for i, v := range values {
		labels[i] = label{name: b.labelNames[i], value: v}
	}
	return strings.Join(values, "\x00"), labels
}

// CounterVec is a counter partitioned by labels.
type CounterVec struct{ base *vecBase }

func (v *CounterVec) meta() (string, string, string) { return v.base.meta() }

// With returns the Counter for the given label values, creating it on first use.
func (v *CounterVec) With(values ...string) *Counter {
	key, labels := v.base.keyFor(values)
	v.base.mu.Lock()
	defer v.base.mu.Unlock()
	c := v.base.children[key]
	if c == nil {
		c = &child{labels: labels, counter: &Counter{}}
		v.base.children[key] = c
	}
	return c.counter
}

func (v *CounterVec) collect() []series {
	v.base.mu.Lock()
	defer v.base.mu.Unlock()
	out := make([]series, 0, len(v.base.children))
	for _, c := range v.base.children {
		out = append(out, series{labels: c.labels, value: c.counter.Value()})
	}
	return out
}

// GaugeVec is a gauge partitioned by labels.
type GaugeVec struct{ base *vecBase }

func (v *GaugeVec) meta() (string, string, string) { return v.base.meta() }

// With returns the Gauge for the given label values, creating it on first use.
func (v *GaugeVec) With(values ...string) *Gauge {
	key, labels := v.base.keyFor(values)
	v.base.mu.Lock()
	defer v.base.mu.Unlock()
	c := v.base.children[key]
	if c == nil {
		c = &child{labels: labels, gauge: &Gauge{}}
		v.base.children[key] = c
	}
	return c.gauge
}

func (v *GaugeVec) collect() []series {
	v.base.mu.Lock()
	defer v.base.mu.Unlock()
	out := make([]series, 0, len(v.base.children))
	for _, c := range v.base.children {
		out = append(out, series{labels: c.labels, value: c.gauge.Value()})
	}
	return out
}

// HistogramVec is a histogram partitioned by labels.
type HistogramVec struct {
	base    *vecBase
	buckets []float64
}

func (v *HistogramVec) meta() (string, string, string) { return v.base.meta() }

// With returns the Histogram for the given label values, creating it on first use.
func (v *HistogramVec) With(values ...string) *Histogram {
	key, labels := v.base.keyFor(values)
	v.base.mu.Lock()
	defer v.base.mu.Unlock()
	c := v.base.children[key]
	if c == nil {
		c = &child{labels: labels, hist: newHistogram(v.buckets)}
		v.base.children[key] = c
	}
	return c.hist
}

func (v *HistogramVec) collect() []series {
	v.base.mu.Lock()
	defer v.base.mu.Unlock()
	out := make([]series, 0, len(v.base.children)*(len(v.buckets)+3))
	for _, c := range v.base.children {
		h := c.hist
		var cumulative uint64
		for i, bound := range h.buckets {
			cumulative += h.counts[i].Load()
			leLabels := append(cloneLabels(c.labels), label{name: "le", value: formatFloat(bound)})
			out = append(out, series{suffix: "_bucket", labels: leLabels, value: float64(cumulative)})
		}
		total := h.count.Load()
		infLabels := append(cloneLabels(c.labels), label{name: "le", value: "+Inf"})
		out = append(out, series{suffix: "_bucket", labels: infLabels, value: float64(total)})
		out = append(out, series{suffix: "_sum", labels: c.labels, value: loadFloat(&h.sum)})
		out = append(out, series{suffix: "_count", labels: c.labels, value: float64(total)})
	}
	return out
}

// --- func collector ---------------------------------------------------------

type funcCollector struct {
	name, help, typ string
	fn              func() float64
}

func (f *funcCollector) meta() (string, string, string) { return f.name, f.help, f.typ }
func (f *funcCollector) collect() []series              { return []series{{value: f.fn()}} }

// funcVecCollector renders a labeled metric from a scrape-time function.
type funcVecCollector struct {
	name, help, typ string
	labelNames      []string
	fn              func() []LabeledValue
}

func (f *funcVecCollector) meta() (string, string, string) { return f.name, f.help, f.typ }

func (f *funcVecCollector) collect() []series {
	vals := f.fn()
	out := make([]series, 0, len(vals))
	for _, v := range vals {
		if len(v.Labels) != len(f.labelNames) {
			continue
		}
		labels := make([]label, len(f.labelNames))
		for i, name := range f.labelNames {
			labels[i] = label{name: name, value: v.Labels[i]}
		}
		out = append(out, series{labels: labels, value: v.Value})
	}
	return out
}

// --- rendering helpers ------------------------------------------------------

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) writeString(s string) {
	if e.err != nil {
		return
	}
	_, e.err = io.WriteString(e.w, s)
}

func writeLabels(w *errWriter, labels []label) {
	if len(labels) == 0 {
		return
	}
	w.writeString("{")
	for i, l := range labels {
		if i > 0 {
			w.writeString(",")
		}
		w.writeString(l.name + `="` + escapeLabelValue(l.value) + `"`)
	}
	w.writeString("}")
}

func lessSeries(a, b series) bool {
	if a.suffix != b.suffix {
		return a.suffix < b.suffix
	}
	for i := 0; i < len(a.labels) && i < len(b.labels); i++ {
		if a.labels[i].value != b.labels[i].value {
			return a.labels[i].value < b.labels[i].value
		}
	}
	return len(a.labels) < len(b.labels)
}

func cloneLabels(in []label) []label {
	out := make([]label, len(in))
	copy(out, in)
	return out
}

func sortedBuckets(b []float64) []float64 {
	out := make([]float64, len(b))
	copy(out, b)
	sort.Float64s(out)
	return out
}

func formatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
