// Package tracing provides a self-contained, dependency-free OpenTelemetry
// distributed-tracing layer for the proxy. It implements just enough of the
// OpenTelemetry data model and OTLP wire protocol to give operators a full
// latency breakdown of a pull — ingress, auth, rate limiting, cache lookup,
// upstream fetch, every admission gate, cache write, and response — without
// pulling the full OpenTelemetry-Go SDK (and its large transitive dependency
// tree) into this codebase.
//
// The design mirrors the rest of the proxy's optional subsystems: a nil
// *Provider (or nil *Tracer / nil *Span) is a valid no-op, so tracing can be
// disabled — the default when no OTLP endpoint is configured — without nil
// checks at call sites. Spans are exported asynchronously by a bounded batch
// processor to a vendored-thin OTLP/HTTP exporter (see exporter.go), so the
// request path never blocks on the collector.
//
// What is implemented:
//   - W3C Trace Context (traceparent/tracestate) propagation in and out of the
//     HTTP request lifecycle and across background workers (see propagation.go).
//   - Parent-based, ratio-controlled sampling (see sampler.go).
//   - A bounded, batched span exporter speaking OTLP/HTTP with the protobuf-JSON
//     encoding that the OpenTelemetry Collector accepts at /v1/traces.
//
// What is deliberately omitted (relative to the full SDK): metrics/logs
// signals, the gRPC OTLP transport, baggage, and span links. These are not
// needed for the pull-pipeline latency story and would substantially enlarge
// the implementation.
package tracing

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// TraceID is a 16-byte W3C trace identifier.
type TraceID [16]byte

// SpanID is an 8-byte W3C span identifier.
type SpanID [8]byte

// IsValid reports whether the id is non-zero (a zero id is the "invalid"
// sentinel in the W3C model).
func (t TraceID) IsValid() bool { return t != TraceID{} }

// IsValid reports whether the id is non-zero.
func (s SpanID) IsValid() bool { return s != SpanID{} }

// SpanKind classifies a span's role, matching the OTLP enum values.
type SpanKind int

const (
	SpanKindUnspecified SpanKind = 0
	SpanKindInternal    SpanKind = 1
	SpanKindServer      SpanKind = 2
	SpanKindClient      SpanKind = 3
	SpanKindProducer    SpanKind = 4
	SpanKindConsumer    SpanKind = 5
)

// StatusCode mirrors the OTLP span status codes.
type StatusCode int

const (
	StatusUnset StatusCode = 0
	StatusOK    StatusCode = 1
	StatusError StatusCode = 2
)

// SpanStatus is a span's terminal status.
type SpanStatus struct {
	Code    StatusCode
	Message string
}

// SpanContext is the immutable, propagatable identity of a span.
type SpanContext struct {
	TraceID    TraceID
	SpanID     SpanID
	TraceFlags byte   // bit 0 = sampled
	TraceState string // opaque W3C tracestate, propagated verbatim
	Remote     bool   // true when extracted from an inbound carrier
}

// IsValid reports whether both ids are non-zero.
func (sc SpanContext) IsValid() bool { return sc.TraceID.IsValid() && sc.SpanID.IsValid() }

// IsSampled reports whether the sampled flag is set.
func (sc SpanContext) IsSampled() bool { return sc.TraceFlags&FlagSampled != 0 }

// FlagSampled is the W3C trace-flags "sampled" bit.
const FlagSampled byte = 0x01

// Event is a timestamped annotation within a span.
type Event struct {
	Name       string
	Time       time.Time
	Attributes []Attr
}

// SpanData is the immutable record a finished span hands to the exporter.
type SpanData struct {
	Name        string
	SpanContext SpanContext
	Parent      SpanID
	Kind        SpanKind
	StartTime   time.Time
	EndTime     time.Time
	Attributes  []Attr
	Status      SpanStatus
	Events      []Event
}

// SpanExporter is the sink finished, sampled spans are flushed to. The OTLP
// exporter implements it; tests substitute a recording exporter.
type SpanExporter interface {
	// ExportSpans delivers a batch of finished spans. It must not retain the
	// slice after returning.
	ExportSpans(ctx context.Context, spans []SpanData) error
	// Shutdown flushes and releases the exporter's resources.
	Shutdown(ctx context.Context) error
}

// Provider owns the sampler, the id generator, the batch processor, and the
// exporter. It is the root from which Tracers are obtained. A nil *Provider is
// a valid no-op, so disabled tracing needs no nil checks at call sites.
type Provider struct {
	sampler  Sampler
	exporter SpanExporter
	clock    func() time.Time
	idReader io.Reader

	mu            sync.Mutex
	queue         []SpanData
	maxQueue      int
	batchSize     int
	flushInterval time.Duration
	flushTrigger  chan struct{}
	stop          chan struct{}
	stopped       bool
	wg            sync.WaitGroup

	serviceName string

	// Counters, read by the admin/metrics surfaces.
	cStarted   atomic.Uint64
	cEnded     atomic.Uint64
	cSampled   atomic.Uint64
	cExported  atomic.Uint64
	cDropped   atomic.Uint64
	cBatches   atomic.Uint64
	cExportErr atomic.Uint64
}

// ProviderOptions configures a Provider built around a given exporter. It is the
// lower-level constructor used by NewProvider (which builds the OTLP exporter
// from config) and directly by tests (which inject a recording exporter).
type ProviderOptions struct {
	Exporter      SpanExporter
	Sampler       Sampler
	ServiceName   string
	MaxQueueSize  int
	MaxBatchSize  int
	FlushInterval time.Duration
	// Clock and IDReader are test seams; both default to the production sources.
	Clock    func() time.Time
	IDReader io.Reader
}

// Default batch-processor bounds, chosen to bound memory and collector load
// while keeping per-request latency unaffected (export is fully asynchronous).
const (
	defaultMaxQueueSize  = 2048
	defaultMaxBatchSize  = 512
	defaultFlushInterval = 5 * time.Second
)

// NewProviderWithExporter builds a Provider around an explicit exporter and
// starts its background batch processor. The caller owns shutdown via Shutdown.
func NewProviderWithExporter(opts ProviderOptions) *Provider {
	if opts.Exporter == nil {
		return nil
	}
	if opts.Sampler == nil {
		opts.Sampler = AlwaysSample()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.IDReader == nil {
		opts.IDReader = rand.Reader
	}
	if opts.MaxQueueSize <= 0 {
		opts.MaxQueueSize = defaultMaxQueueSize
	}
	if opts.MaxBatchSize <= 0 {
		opts.MaxBatchSize = defaultMaxBatchSize
	}
	if opts.MaxBatchSize > opts.MaxQueueSize {
		opts.MaxBatchSize = opts.MaxQueueSize
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultFlushInterval
	}
	p := &Provider{
		sampler:       opts.Sampler,
		exporter:      opts.Exporter,
		clock:         opts.Clock,
		idReader:      opts.IDReader,
		maxQueue:      opts.MaxQueueSize,
		batchSize:     opts.MaxBatchSize,
		flushInterval: opts.FlushInterval,
		flushTrigger:  make(chan struct{}, 1),
		stop:          make(chan struct{}),
		serviceName:   opts.ServiceName,
	}
	p.wg.Add(1)
	go p.run()
	return p
}

// Tracer returns a named Tracer. A nil Provider yields a nil Tracer, which is a
// valid no-op.
func (p *Provider) Tracer(name string) *Tracer {
	if p == nil {
		return nil
	}
	return &Tracer{provider: p, name: name}
}

// ServiceName returns the configured service.name resource attribute.
func (p *Provider) ServiceName() string {
	if p == nil {
		return ""
	}
	return p.serviceName
}

// run is the batch-processor loop: it exports on a timer and when explicitly
// triggered (queue reached the batch size), and drains on shutdown.
func (p *Provider) run() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			p.exportBatch(context.Background())
			return
		case <-ticker.C:
			p.exportBatch(context.Background())
		case <-p.flushTrigger:
			p.exportBatch(context.Background())
		}
	}
}

// enqueue appends a finished, sampled span to the bounded queue, dropping the
// span (and counting it) when the queue is full so a slow/unreachable collector
// can never apply backpressure to the request path.
func (p *Provider) enqueue(sd SpanData) {
	p.mu.Lock()
	if len(p.queue) >= p.maxQueue {
		p.mu.Unlock()
		p.cDropped.Add(1)
		return
	}
	p.queue = append(p.queue, sd)
	full := len(p.queue) >= p.batchSize
	p.mu.Unlock()
	if full {
		select {
		case p.flushTrigger <- struct{}{}:
		default:
		}
	}
}

// exportBatch removes up to batchSize spans and hands them to the exporter.
func (p *Provider) exportBatch(ctx context.Context) {
	p.mu.Lock()
	if len(p.queue) == 0 {
		p.mu.Unlock()
		return
	}
	n := len(p.queue)
	if n > p.batchSize {
		n = p.batchSize
	}
	batch := make([]SpanData, n)
	copy(batch, p.queue[:n])
	p.queue = append(p.queue[:0], p.queue[n:]...)
	remaining := len(p.queue)
	p.mu.Unlock()

	p.cBatches.Add(1)
	if err := p.exporter.ExportSpans(ctx, batch); err != nil {
		p.cExportErr.Add(1)
	} else {
		p.cExported.Add(uint64(len(batch)))
	}
	// If a single flush left more than a batch queued, schedule another so the
	// backlog drains promptly rather than waiting for the next tick.
	if remaining > 0 {
		select {
		case p.flushTrigger <- struct{}{}:
		default:
		}
	}
}

// Shutdown stops the batch processor, drains any queued spans, and shuts down
// the exporter. It is idempotent and safe on a nil Provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return nil
	}
	p.stopped = true
	close(p.stop)
	p.mu.Unlock()

	// Wait for the loop to drain (bounded by ctx), then shut down the exporter.
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return p.exporter.Shutdown(ctx)
}

// Metrics is a point-in-time snapshot of the tracer's counters.
type Metrics struct {
	SpansStarted  uint64 `json:"spansStarted"`
	SpansEnded    uint64 `json:"spansEnded"`
	SpansSampled  uint64 `json:"spansSampled"`
	SpansExported uint64 `json:"spansExported"`
	SpansDropped  uint64 `json:"spansDropped"`
	ExportBatches uint64 `json:"exportBatches"`
	ExportErrors  uint64 `json:"exportErrors"`
	QueueDepth    int    `json:"queueDepth"`
}

// Metrics returns the current counter snapshot. Safe on a nil Provider.
func (p *Provider) Metrics() Metrics {
	if p == nil {
		return Metrics{}
	}
	p.mu.Lock()
	depth := len(p.queue)
	p.mu.Unlock()
	return Metrics{
		SpansStarted:  p.cStarted.Load(),
		SpansEnded:    p.cEnded.Load(),
		SpansSampled:  p.cSampled.Load(),
		SpansExported: p.cExported.Load(),
		SpansDropped:  p.cDropped.Load(),
		ExportBatches: p.cBatches.Load(),
		ExportErrors:  p.cExportErr.Load(),
		QueueDepth:    depth,
	}
}

// newTraceID and newSpanID draw random identifiers from the provider's reader,
// retrying the (astronomically unlikely) all-zero result so generated ids are
// always valid.
func (p *Provider) newTraceID() TraceID {
	var id TraceID
	for {
		_, _ = io.ReadFull(p.idReader, id[:])
		if id.IsValid() {
			return id
		}
	}
}

func (p *Provider) newSpanID() SpanID {
	var id SpanID
	for {
		_, _ = io.ReadFull(p.idReader, id[:])
		if id.IsValid() {
			return id
		}
	}
}
