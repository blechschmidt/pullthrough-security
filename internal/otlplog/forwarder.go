package otlplog

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning values, applied by newForwarder when an option is left zero.
// They mirror the siem forwarder's defaults so operators have one mental model
// for every resilient forwarding path in the proxy.
const (
	defaultQueueSize    = 2048
	defaultBatchSize    = 512
	defaultBatchTimeout = 5 * time.Second
	defaultMaxRetries   = 3
	defaultBaseDelay    = 500 * time.Millisecond
	defaultMaxDelay     = 30 * time.Second
	defaultTimeout      = 10 * time.Second
)

// retryable is implemented by an export error that knows whether redelivery can
// succeed (a transient 429/5xx or network failure) versus a permanent one.
type retryable interface {
	Retryable() bool
}

// isRetryable reports whether a failed export should be retried. A nil error is
// never retried; an error implementing retryable defers to it; any other error
// (including a transport-level failure, which is transient) is retried, matching
// the conservative "retry unknown transport failures" posture of the collector.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var r retryable
	if errors.As(err, &r) {
		return r.Retryable()
	}
	// Transport-level errors (connection refused, timeout) carry no Retryable
	// classification but are transient, so retry them.
	return true
}

// Metrics is a point-in-time snapshot of the forwarder's telemetry, consumed by
// the Prometheus bridge and admin/status surfaces.
type Metrics struct {
	QueueDepth int    `json:"queueDepth"`
	SpillDepth int    `json:"spillDepth"`
	Enqueued   uint64 `json:"enqueued"`
	Delivered  uint64 `json:"delivered"`
	Dropped    uint64 `json:"dropped"`
	Spilled    uint64 `json:"spilled"`
	Failed     uint64 `json:"failed"`
	Retries    uint64 `json:"retries"`
	Batches    uint64 `json:"batches"`
}

// forwarderOptions configures a Forwarder.
type forwarderOptions struct {
	Logger       *slog.Logger
	Exporter     Exporter
	QueueSize    int
	BatchSize    int
	BatchTimeout time.Duration
	MaxRetries   int
	BaseDelay    time.Duration
	MaxDelay     time.Duration
	Timeout      time.Duration
	Spill        *spillQueue
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Forwarder streams structured log records to an OTLP exporter. It owns a
// bounded in-memory queue (with optional disk spill) drained by a single
// dispatcher goroutine that batches records and delivers each batch to the
// exporter with retry and exponential backoff. Enqueueing never blocks: when
// both the in-memory queue and the spill are full the record is dropped and
// counted, so a slow or unreachable collector can never stall the code that is
// logging.
//
// A nil *Forwarder is a valid no-op, so OTLP log export can be disabled without
// nil checks at call sites.
type Forwarder struct {
	logger   *slog.Logger
	exporter Exporter

	batchSize    int
	batchTimeout time.Duration
	maxRetries   int
	baseDelay    time.Duration
	maxDelay     time.Duration
	timeout      time.Duration

	mu       sync.Mutex
	queue    []LogRecord
	queueCap int
	spill    *spillQueue
	signal   chan struct{}

	enqueued  atomic.Uint64
	delivered atomic.Uint64
	dropped   atomic.Uint64
	spilled   atomic.Uint64
	failed    atomic.Uint64
	retries   atomic.Uint64
	batches   atomic.Uint64

	now       func() time.Time
	wg        sync.WaitGroup
	stop      chan struct{}
	closed    atomic.Bool
	startOnce sync.Once
	closeOnce sync.Once
}

// newForwarder constructs and starts a Forwarder around an explicit exporter.
func newForwarder(opts forwarderOptions) *Forwarder {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	f := &Forwarder{
		logger:       logger,
		exporter:     opts.Exporter,
		batchSize:    orInt(opts.BatchSize, defaultBatchSize),
		batchTimeout: orDuration(opts.BatchTimeout, defaultBatchTimeout),
		maxRetries:   opts.MaxRetries,
		baseDelay:    orDuration(opts.BaseDelay, defaultBaseDelay),
		maxDelay:     orDuration(opts.MaxDelay, defaultMaxDelay),
		timeout:      orDuration(opts.Timeout, defaultTimeout),
		queueCap:     orInt(opts.QueueSize, defaultQueueSize),
		spill:        opts.Spill,
		signal:       make(chan struct{}, 1),
		stop:         make(chan struct{}),
		now:          opts.Now,
	}
	if f.now == nil {
		f.now = time.Now
	}
	if opts.MaxRetries == 0 {
		f.maxRetries = defaultMaxRetries
	}
	if f.batchSize > f.queueCap {
		f.batchSize = f.queueCap
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

// Enqueue places a record on the in-memory queue, overflowing to the disk spill
// and finally dropping (all counted) rather than ever blocking the caller. It is
// a no-op on a nil or closed forwarder.
func (f *Forwarder) Enqueue(rec LogRecord) {
	if f == nil || f.closed.Load() {
		return
	}
	f.enqueued.Add(1)

	f.mu.Lock()
	if len(f.queue) < f.queueCap {
		f.queue = append(f.queue, rec)
		f.mu.Unlock()
		f.wake()
		return
	}
	spill := f.spill
	f.mu.Unlock()

	if spill != nil {
		if err := spill.push(rec); err != nil {
			f.dropped.Add(1)
			if !errors.Is(err, errSpillFull) {
				f.logger.Warn("otlplog: spill write failed, dropping log record", "error", err)
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

// run is the dispatcher loop: on each wake-up (a new record, the periodic flush
// timer, or shutdown) it drains all currently-available records in batch-sized
// chunks and delivers each chunk to the exporter.
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
// spilled records are not silently lost.
func (f *Forwarder) flushAll() {
	for {
		batch := f.drain(f.batchSize)
		if len(batch) == 0 {
			return
		}
		f.deliver(batch)
	}
}

// drain removes up to max records from the front of the queue, topping up from
// the spill when the in-memory queue is exhausted.
func (f *Forwarder) drain(max int) []LogRecord {
	f.mu.Lock()
	n := len(f.queue)
	if n > max {
		n = max
	}
	var batch []LogRecord
	if n > 0 {
		batch = make([]LogRecord, n)
		copy(batch, f.queue[:n])
		rest := copy(f.queue, f.queue[n:])
		f.queue = f.queue[:rest]
	}
	spill := f.spill
	f.mu.Unlock()

	if spill != nil && len(batch) < max {
		more, err := spill.pop(max - len(batch))
		if err != nil {
			f.logger.Warn("otlplog: spill read failed", "error", err)
		}
		batch = append(batch, more...)
	}
	return batch
}

// deliver sends one batch to the exporter with retry and exponential backoff.
func (f *Forwarder) deliver(batch []LogRecord) {
	f.batches.Add(1)
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
		err := f.exporter.Export(ctx, batch)
		cancel()
		if err == nil {
			f.delivered.Add(uint64(len(batch)))
			return
		}
		if attempt >= f.maxRetries || !isRetryable(err) {
			f.failed.Add(uint64(len(batch)))
			f.logger.Warn("otlplog: batch export failed",
				"records", len(batch), "attempts", attempt+1, "error", err)
			return
		}
		f.retries.Add(1)
		if !f.backoff(attempt) {
			f.failed.Add(uint64(len(batch)))
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

// Metrics returns a point-in-time snapshot of the forwarder's telemetry. Safe on
// a nil Forwarder (reports zero).
func (f *Forwarder) Metrics() Metrics {
	if f == nil {
		return Metrics{}
	}
	f.mu.Lock()
	qd := len(f.queue)
	f.mu.Unlock()
	sd := 0
	if f.spill != nil {
		sd = f.spill.len()
	}
	return Metrics{
		QueueDepth: qd,
		SpillDepth: sd,
		Enqueued:   f.enqueued.Load(),
		Delivered:  f.delivered.Load(),
		Dropped:    f.dropped.Load(),
		Spilled:    f.spilled.Load(),
		Failed:     f.failed.Load(),
		Retries:    f.retries.Load(),
		Batches:    f.batches.Load(),
	}
}

// Close stops accepting new records, flushes the dispatcher (draining the
// in-memory queue and the spill to completion), and releases the exporter and
// spill file. It is safe to call multiple times and on a nil Forwarder.
func (f *Forwarder) Close() error {
	if f == nil {
		return nil
	}
	var err error
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		close(f.stop)
		f.wg.Wait()
		if f.exporter != nil {
			if cerr := f.exporter.Shutdown(context.Background()); cerr != nil && err == nil {
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
