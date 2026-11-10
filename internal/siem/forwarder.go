package siem

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// Default tuning values, applied by New when an option is left zero.
const (
	defaultQueueSize    = 1024
	defaultBatchSize    = 100
	defaultBatchTimeout = 5 * time.Second
	defaultMaxRetries   = 3
	defaultBaseDelay    = 500 * time.Millisecond
	defaultMaxDelay     = 30 * time.Second
	defaultTimeout      = 10 * time.Second
)

// sinkCounters holds lock-free per-sink delivery telemetry.
type sinkCounters struct {
	delivered atomic.Uint64 // events delivered successfully
	failed    atomic.Uint64 // events dropped after exhausting retries
	retries   atomic.Uint64 // batch delivery retry attempts
	batches   atomic.Uint64 // batches attempted
}

// boundSink pairs a Sink with its counters.
type boundSink struct {
	sink     Sink
	counters *sinkCounters
}

// SinkMetrics is a snapshot of one sink's counters.
type SinkMetrics struct {
	Delivered uint64 `json:"delivered"`
	Failed    uint64 `json:"failed"`
	Retries   uint64 `json:"retries"`
	Batches   uint64 `json:"batches"`
}

// Snapshot is a point-in-time view of the forwarder's telemetry, consumed by the
// Prometheus bridge and the admin/status surfaces.
type Snapshot struct {
	PerSink    map[string]SinkMetrics `json:"perSink"`
	QueueDepth int                    `json:"queueDepth"`
	SpillDepth int                    `json:"spillDepth"`
	Enqueued   uint64                 `json:"enqueued"`
	Dropped    uint64                 `json:"dropped"`
	Spilled    uint64                 `json:"spilled"`
	// OCSF aggregates the OCSF-encoder telemetry across all "ocsf" sinks.
	OCSF OCSFMetrics `json:"ocsf"`
}

// OCSFMetrics aggregates the OCSF output-encoder telemetry across every "ocsf"
// sink: the count of objects encoded per OCSF class and the total encode
// failures. It is empty when no OCSF sink is configured.
type OCSFMetrics struct {
	ByClass      map[string]uint64 `json:"byClass"`
	EncodeErrors uint64            `json:"encodeErrors"`
}

// ocsfStatsProvider is implemented by sinks that encode OCSF output and expose
// per-class encode telemetry.
type ocsfStatsProvider interface {
	OCSFStats() OCSFStats
}

// Options configures a Forwarder.
type Options struct {
	Logger          *slog.Logger
	Sinks           []Sink
	MinSeverity     Severity
	ForwardAudit    bool
	ForwardFindings bool
	QueueSize       int
	BatchSize       int
	BatchTimeout    time.Duration
	MaxRetries      int
	RetryBaseDelay  time.Duration
	RetryMaxDelay   time.Duration
	Timeout         time.Duration
	// Spill, when non-nil, is a bounded file-backed overflow queue absorbing
	// bursts that exceed the in-memory QueueSize.
	Spill *spillQueue
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Forwarder streams normalized SIEM events to one or more sinks. It owns a
// bounded in-memory queue (with optional disk spill) drained by a single
// dispatcher goroutine that batches events and delivers each batch to every sink
// with retry and exponential backoff. Enqueueing never blocks: when both the
// in-memory queue and the spill are full the event is dropped and counted, so a
// slow or unreachable SIEM can never stall the pull path.
//
// A nil *Forwarder is a valid no-op, so SIEM forwarding can be disabled without
// nil checks at call sites.
type Forwarder struct {
	logger          *slog.Logger
	sinks           []*boundSink
	byName          map[string]*boundSink
	minSev          Severity
	forwardAudit    bool
	forwardFindings bool

	batchSize    int
	batchTimeout time.Duration
	maxRetries   int
	baseDelay    time.Duration
	maxDelay     time.Duration
	timeout      time.Duration

	mu       sync.Mutex
	queue    []Event
	queueCap int
	spill    *spillQueue
	signal   chan struct{}

	enqueued atomic.Uint64
	dropped  atomic.Uint64
	spilled  atomic.Uint64

	now       func() time.Time
	wg        sync.WaitGroup
	stop      chan struct{}
	closed    atomic.Bool
	startOnce sync.Once
	closeOnce sync.Once
}

// New constructs and starts a Forwarder. It returns a non-nil forwarder even
// with no sinks (a headless no-op that still accounts enqueue/drop metrics).
func New(opts Options) *Forwarder {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	f := &Forwarder{
		logger:          logger,
		byName:          make(map[string]*boundSink),
		minSev:          NormalizeSeverity(string(opts.MinSeverity)),
		forwardAudit:    opts.ForwardAudit,
		forwardFindings: opts.ForwardFindings,
		batchSize:       orInt(opts.BatchSize, defaultBatchSize),
		batchTimeout:    orDuration(opts.BatchTimeout, defaultBatchTimeout),
		maxRetries:      opts.MaxRetries,
		baseDelay:       orDuration(opts.RetryBaseDelay, defaultBaseDelay),
		maxDelay:        orDuration(opts.RetryMaxDelay, defaultMaxDelay),
		timeout:         orDuration(opts.Timeout, defaultTimeout),
		queueCap:        orInt(opts.QueueSize, defaultQueueSize),
		spill:           opts.Spill,
		signal:          make(chan struct{}, 1),
		stop:            make(chan struct{}),
		now:             opts.Now,
	}
	if f.now == nil {
		f.now = time.Now
	}
	if opts.MaxRetries == 0 {
		f.maxRetries = defaultMaxRetries
	}
	for _, s := range opts.Sinks {
		bs := &boundSink{sink: s, counters: &sinkCounters{}}
		f.sinks = append(f.sinks, bs)
		f.byName[s.Name()] = bs
	}
	f.start()
	return f
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// start launches the single dispatcher goroutine (idempotent).
func (f *Forwarder) start() {
	f.startOnce.Do(func() {
		f.wg.Add(1)
		go f.run()
	})
}

// Sinks returns the number of configured sinks.
func (f *Forwarder) Sinks() int {
	if f == nil {
		return 0
	}
	return len(f.sinks)
}

// ForwardAudit enqueues a tamper-evident audit record for forwarding. The record
// is read-only here; the hash chain is computed and committed before this is
// ever called (see WrapAuditSink), so forwarding cannot affect log integrity.
func (f *Forwarder) ForwardAudit(rec audit.Record) {
	if f == nil || f.closed.Load() || !f.forwardAudit {
		return
	}
	f.enqueue(EventFromAuditRecord(rec))
}

// ForwardFindings enqueues one event per finding in the document. It is
// best-effort and never blocks; the context is accepted for interface symmetry
// with the proxy and is not used to bound the (non-blocking) enqueue.
func (f *Forwarder) ForwardFindings(_ context.Context, doc findings.Document) {
	if f == nil || f.closed.Load() || !f.forwardFindings {
		return
	}
	for _, fd := range doc.Findings {
		f.enqueue(EventFromFinding(doc, fd))
	}
}

// Emit enqueues an already-built event (used by tests and any future direct
// producer). It applies the same severity floor as the typed forwarders.
func (f *Forwarder) Emit(ev Event) {
	if f == nil || f.closed.Load() {
		return
	}
	f.enqueue(ev)
}

// enqueue applies the severity floor and places the event on the in-memory
// queue, overflowing to the disk spill and finally dropping (all counted) rather
// than ever blocking the caller.
func (f *Forwarder) enqueue(ev Event) {
	if ev.Severity == "" {
		ev.Severity = SeverityInfo
	}
	if !ev.Severity.AtLeast(f.minSev) {
		return
	}
	f.enqueued.Add(1)

	f.mu.Lock()
	if len(f.queue) < f.queueCap {
		f.queue = append(f.queue, ev)
		f.mu.Unlock()
		f.wake()
		return
	}
	spill := f.spill
	f.mu.Unlock()

	if spill != nil {
		if err := spill.push(ev); err != nil {
			f.dropped.Add(1)
			if err != errSpillFull {
				f.logger.Warn("siem: spill write failed, dropping event", "error", err)
			}
			return
		}
		f.spilled.Add(1)
		f.wake()
		return
	}
	f.dropped.Add(1)
}

// wake signals the dispatcher that work is available (non-blocking; the buffered
// channel coalesces a burst into a single wake-up).
func (f *Forwarder) wake() {
	select {
	case f.signal <- struct{}{}:
	default:
	}
}

// run is the dispatcher loop: on each wake-up (a new event, the periodic flush
// timer, or shutdown) it drains all currently-available events in batch-sized
// chunks and delivers each chunk to every sink.
func (f *Forwarder) run() {
	defer f.wg.Done()
	ticker := time.NewTicker(f.batchTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-f.stop:
			f.flushAll()
			return
		case <-f.signal:
		case <-ticker.C:
		}
		for {
			batch := f.drain(f.batchSize)
			if len(batch) == 0 {
				break
			}
			f.deliver(batch)
		}
	}
}

// flushAll drains and delivers everything remaining at shutdown so queued and
// spilled events are not silently lost.
func (f *Forwarder) flushAll() {
	for {
		batch := f.drain(f.batchSize)
		if len(batch) == 0 {
			return
		}
		f.deliver(batch)
	}
}

// drain removes up to max events from the front of the queue, topping up from
// the spill when the in-memory queue is exhausted.
func (f *Forwarder) drain(max int) []Event {
	f.mu.Lock()
	n := len(f.queue)
	if n > max {
		n = max
	}
	var batch []Event
	if n > 0 {
		batch = make([]Event, n)
		copy(batch, f.queue[:n])
		rest := copy(f.queue, f.queue[n:])
		f.queue = f.queue[:rest]
	}
	spill := f.spill
	f.mu.Unlock()

	if spill != nil && len(batch) < max {
		more, err := spill.pop(max - len(batch))
		if err != nil {
			f.logger.Warn("siem: spill read failed", "error", err)
		}
		batch = append(batch, more...)
	}
	return batch
}

// deliver sends one batch to every configured sink.
func (f *Forwarder) deliver(batch []Event) {
	for _, bs := range f.sinks {
		f.deliverToSink(bs, batch)
	}
}

// deliverToSink delivers a batch to a single sink with retry and exponential
// backoff, updating the sink's counters.
func (f *Forwarder) deliverToSink(bs *boundSink, batch []Event) {
	bs.counters.batches.Add(1)
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
		err := bs.sink.DeliverBatch(ctx, batch)
		cancel()
		if err == nil {
			bs.counters.delivered.Add(uint64(len(batch)))
			return
		}
		if attempt >= f.maxRetries || !isRetryable(err) {
			bs.counters.failed.Add(uint64(len(batch)))
			f.logger.Warn("siem: batch delivery failed",
				"sink", bs.sink.Name(), "events", len(batch),
				"attempts", attempt+1, "error", err)
			return
		}
		bs.counters.retries.Add(1)
		if !f.backoff(attempt) {
			bs.counters.failed.Add(uint64(len(batch)))
			return
		}
	}
}

// backoff sleeps for an exponentially growing, capped delay, returning false if
// interrupted by shutdown.
func (f *Forwarder) backoff(attempt int) bool {
	delay := f.baseDelay << attempt
	if delay <= 0 || delay > f.maxDelay {
		delay = f.maxDelay
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-f.stop:
		return false
	}
}

// Metrics returns a point-in-time snapshot of the forwarder's telemetry.
func (f *Forwarder) Metrics() Snapshot {
	if f == nil {
		return Snapshot{PerSink: map[string]SinkMetrics{}, OCSF: OCSFMetrics{ByClass: map[string]uint64{}}}
	}
	perSink := make(map[string]SinkMetrics, len(f.sinks))
	ocsf := OCSFMetrics{ByClass: map[string]uint64{}}
	for _, bs := range f.sinks {
		perSink[bs.sink.Name()] = SinkMetrics{
			Delivered: bs.counters.delivered.Load(),
			Failed:    bs.counters.failed.Load(),
			Retries:   bs.counters.retries.Load(),
			Batches:   bs.counters.batches.Load(),
		}
		if p, ok := bs.sink.(ocsfStatsProvider); ok {
			st := p.OCSFStats()
			for class, n := range st.ByClass {
				ocsf.ByClass[class] += n
			}
			ocsf.EncodeErrors += st.EncodeErrors
		}
	}
	f.mu.Lock()
	qd := len(f.queue)
	f.mu.Unlock()
	sd := 0
	if f.spill != nil {
		sd = f.spill.len()
	}
	return Snapshot{
		PerSink:    perSink,
		QueueDepth: qd,
		SpillDepth: sd,
		Enqueued:   f.enqueued.Load(),
		Dropped:    f.dropped.Load(),
		Spilled:    f.spilled.Load(),
		OCSF:       ocsf,
	}
}

// Close stops accepting new events, flushes the dispatcher, and releases the
// sinks and spill file. It is safe to call multiple times.
func (f *Forwarder) Close() error {
	if f == nil {
		return nil
	}
	var err error
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		close(f.stop)
		f.wg.Wait()
		for _, bs := range f.sinks {
			if cerr := bs.sink.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if f.spill != nil {
			if cerr := f.spill.close(); cerr != nil && err == nil {
				err = cerr
			}
		}
	})
	return err
}
