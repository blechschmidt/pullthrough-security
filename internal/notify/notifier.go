package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// route binds a set of sinks to the event types and minimum severity they should
// receive. An empty types set matches every routable event type.
type route struct {
	types  map[EventType]bool
	minSev Severity
	sinks  []*boundSink
}

// matches reports whether the route should deliver ev.
func (r route) matches(ev Event) bool {
	if len(r.types) > 0 && !r.types[ev.Type] {
		return false
	}
	return ev.Severity.AtLeast(r.minSev)
}

// boundSink pairs a Sink with its per-sink delivery counters so a metric lookup
// is lock-free and a sink reachable via multiple routes shares one counter set.
type boundSink struct {
	sink     Sink
	counters *sinkCounters
}

// sinkCounters holds the cumulative delivery telemetry for one sink.
type sinkCounters struct {
	sent    atomic.Uint64
	failed  atomic.Uint64
	dropped atomic.Uint64
	retries atomic.Uint64
}

// task is one queued delivery: a prepared event destined for a specific sink.
type task struct {
	bs *boundSink
	ev Event
}

// Notifier is the event bus and asynchronous dispatcher. Producers call Emit;
// the Notifier applies routing and severity filtering, redacts sensitive fields,
// and hands each matching delivery to a bounded worker pool that retries with
// exponential backoff. Delivery never blocks Emit: a full queue drops the
// notification (counted in metrics) rather than stalling the request path.
//
// A nil *Notifier is a valid no-op Emitter, so notification can be disabled
// without nil checks at the call sites that emit.
type Notifier struct {
	logger   *slog.Logger
	redactor *Redactor
	minSev   Severity

	routes []route
	// sinks is the registration-ordered, de-duplicated set of bound sinks, used
	// for the test endpoint, metrics enumeration, and the admin surface.
	sinks  []*boundSink
	byName map[string]*boundSink

	// taps are in-process observers invoked synchronously for every prepared
	// event, ahead of sink routing and the global severity floor. They let an
	// internal consumer (the SecOps dashboard) see the complete, redacted event
	// stream without participating in sink delivery. Guarded by tapMu so a tap
	// can be registered after construction (the admin layer wires it up once the
	// notifier exists).
	tapMu sync.RWMutex
	taps  []func(Event)

	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	timeout    time.Duration
	now        func() time.Time

	queue     chan task
	wg        sync.WaitGroup
	stop      chan struct{}
	closed    atomic.Bool
	startOnce sync.Once
	closeOnce sync.Once
}

// Options configures a Notifier built directly (Build constructs one from a
// declarative Config; this is the lower-level constructor used by tests and by
// Build itself).
type Options struct {
	Logger      *slog.Logger
	Redactor    *Redactor
	MinSeverity Severity
	Routes      []RouteSpec
	Workers     int
	QueueSize   int
	MaxRetries  int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Timeout     time.Duration
	// Now overrides the clock (tests); defaults to time.Now.
	Now func() time.Time
}

// RouteSpec declares that a set of sinks should receive the given event types at
// or above a minimum severity. It is the assembled (sink-resolved) form of a
// RouteConfig.
type RouteSpec struct {
	Sinks       []Sink
	EventTypes  []EventType
	MinSeverity Severity
}

// New constructs a Notifier from resolved options and starts its worker pool.
// The caller owns the lifecycle and must call Close to drain and stop it.
func New(opts Options) *Notifier {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 2
	}
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = 256
	}
	maxRetries := opts.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	baseDelay := opts.BaseDelay
	if baseDelay <= 0 {
		baseDelay = 500 * time.Millisecond
	}
	maxDelay := opts.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	n := &Notifier{
		logger:     logger,
		redactor:   opts.Redactor,
		minSev:     NormalizeSeverity(string(opts.MinSeverity)),
		byName:     make(map[string]*boundSink),
		maxRetries: maxRetries,
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
		timeout:    timeout,
		now:        now,
		queue:      make(chan task, queueSize),
		stop:       make(chan struct{}),
	}

	// Resolve routes, sharing one boundSink per distinct Sink instance so a sink
	// referenced by multiple routes keeps a single counter set and is delivered to
	// at most once per event.
	for _, rs := range opts.Routes {
		r := route{minSev: NormalizeSeverity(string(rs.MinSeverity))}
		if len(rs.EventTypes) > 0 {
			r.types = make(map[EventType]bool, len(rs.EventTypes))
			for _, t := range rs.EventTypes {
				r.types[t] = true
			}
		}
		for _, s := range rs.Sinks {
			r.sinks = append(r.sinks, n.bind(s))
		}
		n.routes = append(n.routes, r)
	}

	n.start(workers)
	return n
}

// Tap registers an in-process observer invoked synchronously for every event
// that enters Emit, after redaction and before sink routing/severity filtering,
// so an observer (such as the SecOps dashboard) sees the complete, scrubbed
// event stream regardless of sink configuration or the global severity floor.
// fn must not block the caller (delivery to real sinks stays asynchronous). A
// nil *Notifier or nil fn is ignored, so callers need no nil checks.
func (n *Notifier) Tap(fn func(Event)) {
	if n == nil || fn == nil {
		return
	}
	n.tapMu.Lock()
	n.taps = append(n.taps, fn)
	n.tapMu.Unlock()
}

// bind returns the shared boundSink for s, registering it on first sighting.
func (n *Notifier) bind(s Sink) *boundSink {
	if bs, ok := n.byName[s.Name()]; ok {
		return bs
	}
	bs := &boundSink{sink: s, counters: &sinkCounters{}}
	n.byName[s.Name()] = bs
	n.sinks = append(n.sinks, bs)
	return bs
}

// start launches the worker pool exactly once.
func (n *Notifier) start(workers int) {
	n.startOnce.Do(func() {
		for i := 0; i < workers; i++ {
			n.wg.Add(1)
			go n.worker()
		}
	})
}

// Emit routes ev to the configured sinks and enqueues a delivery per matching
// sink. It never blocks: a full queue drops the notification and records it.
// A nil *Notifier is a no-op. The provided context is not retained for delivery
// (which outlives the request); it is accepted for interface symmetry and future
// cancellation propagation.
func (n *Notifier) Emit(_ context.Context, ev Event) {
	if n == nil || n.closed.Load() {
		return
	}
	ev = n.prepare(ev)

	// In-process observers see every prepared event, regardless of the sink
	// severity floor or routing, so the SecOps dashboard reflects the complete
	// security-event stream. Taps must not block; they snapshot under a read lock
	// so a late Tap registration is race-free.
	n.tapMu.RLock()
	taps := n.taps
	n.tapMu.RUnlock()
	for _, tap := range taps {
		tap(ev)
	}

	// The global floor short-circuits before any per-route work.
	if !ev.Severity.AtLeast(n.minSev) {
		return
	}

	for _, bs := range n.match(ev) {
		n.enqueue(bs, ev)
	}
}

// prepare stamps the event time, normalizes severity, and redacts sensitive
// fields so every downstream sink sees a consistent, scrubbed event.
func (n *Notifier) prepare(ev Event) Event {
	if ev.Time.IsZero() {
		ev.Time = n.now().UTC()
	} else {
		ev.Time = ev.Time.UTC()
	}
	ev.Severity = NormalizeSeverity(string(ev.Severity))
	if n.redactor != nil {
		ev = n.redactor.Apply(ev)
	}
	return ev
}

// match returns the de-duplicated, registration-ordered set of sinks that should
// receive ev. De-duplication ensures a sink referenced by two matching routes is
// delivered to once.
func (n *Notifier) match(ev Event) []*boundSink {
	var matched []*boundSink
	seen := make(map[*boundSink]bool)
	for _, bs := range n.sinks { // preserve registration order
		for _, r := range n.routes {
			if !r.matches(ev) {
				continue
			}
			if routeHasSink(r, bs) && !seen[bs] {
				seen[bs] = true
				matched = append(matched, bs)
				break
			}
		}
	}
	return matched
}

func routeHasSink(r route, bs *boundSink) bool {
	for _, s := range r.sinks {
		if s == bs {
			return true
		}
	}
	return false
}

// enqueue offers a delivery to the worker pool without blocking. If the queue is
// full the notification is dropped and counted, so a slow or wedged endpoint can
// never apply backpressure to a client pull.
func (n *Notifier) enqueue(bs *boundSink, ev Event) {
	select {
	case n.queue <- task{bs: bs, ev: ev}:
	default:
		bs.counters.dropped.Add(1)
		n.logger.Warn("notify: delivery queue full, dropping notification",
			"sink", bs.sink.Name(), "type", string(ev.Type), "severity", string(ev.Severity))
	}
}

// worker pulls deliveries and processes them until stopped, draining any
// remaining queued deliveries on shutdown (best effort) so notifications already
// accepted are not silently lost.
func (n *Notifier) worker() {
	defer n.wg.Done()
	for {
		select {
		case t := <-n.queue:
			n.deliver(t)
		case <-n.stop:
			for {
				select {
				case t := <-n.queue:
					n.deliver(t)
				default:
					return
				}
			}
		}
	}
}

// deliver attempts a single delivery with bounded exponential-backoff retries.
// Each attempt uses a fresh, timeout-bounded context independent of any request
// context (delivery is asynchronous and outlives the request). Retries abort
// promptly on shutdown.
func (n *Notifier) deliver(t task) {
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
		err := t.bs.sink.Deliver(ctx, t.ev)
		cancel()
		if err == nil {
			t.bs.counters.sent.Add(1)
			return
		}
		if attempt >= n.maxRetries || !isRetryable(err) {
			t.bs.counters.failed.Add(1)
			n.logger.Warn("notify: delivery failed",
				"sink", t.bs.sink.Name(), "type", string(t.ev.Type),
				"attempts", attempt+1, "error", err)
			return
		}
		t.bs.counters.retries.Add(1)
		if !n.backoff(attempt) {
			// Shutdown interrupted the backoff; record the final failure.
			t.bs.counters.failed.Add(1)
			return
		}
	}
}

// backoff sleeps for the exponential delay of the given attempt (capped at
// maxDelay), returning false if shutdown interrupts the wait.
func (n *Notifier) backoff(attempt int) bool {
	delay := n.baseDelay << attempt
	if delay <= 0 || delay > n.maxDelay { // guard against overflow on large attempt
		delay = n.maxDelay
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-n.stop:
		return false
	}
}

// Close stops accepting new notifications, signals the workers to drain and
// exit, and waits for them. It is safe to call multiple times. After Close, Emit
// is a no-op.
func (n *Notifier) Close() error {
	if n == nil {
		return nil
	}
	n.closeOnce.Do(func() {
		n.closed.Store(true)
		close(n.stop)
		n.wg.Wait()
	})
	return nil
}

// --- test, introspection, and metrics ---------------------------------------

// SinkInfo is a read-only description of a configured sink for the admin surface.
type SinkInfo struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Sinks returns the configured sinks in registration order. A nil Notifier
// returns nil.
func (n *Notifier) Sinks() []SinkInfo {
	if n == nil {
		return nil
	}
	out := make([]SinkInfo, 0, len(n.sinks))
	for _, bs := range n.sinks {
		out = append(out, SinkInfo{Name: bs.sink.Name(), Kind: bs.sink.Kind()})
	}
	return out
}

// TestResult reports the outcome of a synchronous test delivery to one sink.
type TestResult struct {
	Sink  string `json:"sink"`
	Kind  string `json:"kind"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Test synchronously delivers a single TestEvent to the named sink, or to every
// configured sink when name is empty, and returns a per-sink result. Unlike
// Emit, Test bypasses routing and the async queue so the operator gets an
// immediate, authoritative answer about reachability. It performs no retries:
// the result reflects a single attempt. A nil Notifier or unknown sink name is
// an error.
func (n *Notifier) Test(ctx context.Context, name string) ([]TestResult, error) {
	if n == nil {
		return nil, fmt.Errorf("notify: notifications are not enabled")
	}
	var targets []*boundSink
	if name == "" {
		targets = n.sinks
	} else {
		bs, ok := n.byName[name]
		if !ok {
			return nil, fmt.Errorf("notify: no sink named %q", name)
		}
		targets = []*boundSink{bs}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("notify: no sinks configured")
	}

	ev := n.prepare(TestEvent())
	results := make([]TestResult, 0, len(targets))
	for _, bs := range targets {
		res := TestResult{Sink: bs.sink.Name(), Kind: bs.sink.Kind()}
		dctx, cancel := context.WithTimeout(ctx, n.timeout)
		err := bs.sink.Deliver(dctx, ev)
		cancel()
		if err != nil {
			res.OK = false
			res.Error = err.Error()
			bs.counters.failed.Add(1)
		} else {
			res.OK = true
			bs.counters.sent.Add(1)
		}
		results = append(results, res)
	}
	return results, nil
}

// SinkMetrics is the cumulative delivery telemetry for one sink.
type SinkMetrics struct {
	Sent    uint64 `json:"sent"`
	Failed  uint64 `json:"failed"`
	Dropped uint64 `json:"dropped"`
	Retries uint64 `json:"retries"`
}

// Snapshot is a point-in-time view of the Notifier's delivery telemetry, used by
// the Prometheus bridge and the admin surface.
type Snapshot struct {
	// PerSink maps a sink name to its cumulative counters.
	PerSink map[string]SinkMetrics `json:"perSink"`
	// QueueDepth is the number of deliveries currently waiting for a worker.
	QueueDepth int `json:"queueDepth"`
}

// Metrics returns a snapshot of cumulative delivery counters by sink and the
// current queue depth. A nil Notifier returns the zero snapshot.
func (n *Notifier) Metrics() Snapshot {
	snap := Snapshot{PerSink: map[string]SinkMetrics{}}
	if n == nil {
		return snap
	}
	for _, bs := range n.sinks {
		snap.PerSink[bs.sink.Name()] = SinkMetrics{
			Sent:    bs.counters.sent.Load(),
			Failed:  bs.counters.failed.Load(),
			Dropped: bs.counters.dropped.Load(),
			Retries: bs.counters.retries.Load(),
		}
	}
	snap.QueueDepth = len(n.queue)
	return snap
}

// SinkNames returns the configured sink names in sorted order (helper for
// documentation/validation callers that just need the identifiers).
func (n *Notifier) SinkNames() []string {
	if n == nil {
		return nil
	}
	names := make([]string, 0, len(n.byName))
	for name := range n.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
