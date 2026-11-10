// Package secops implements the unified Security Operations (SOC) read-model
// behind the admin dashboard's "Security Ops" tab (Task 60).
//
// Verdict and finding data is otherwise spread across many independent admin
// tabs (vulnscan, license, secretscan, malfeed, anomaly, riskscore, approvals,
// findings/SARIF, policyengine). Operators lack a single at-a-glance posture
// view. The Hub aggregates, in near-real-time, two complementary things:
//
//   - A rolling-window tally of notable admission decisions — blocks vs warns vs
//     admits, broken down by owning gate, by subject/tenant, and by severity —
//     derived from the live notification event stream (notify.Event). The Hub is
//     wired as an in-process notify tap, so it observes every security-relevant
//     event the proxy emits without re-deriving any verdict itself.
//   - A point-in-time posture summary assembled from the existing subsystem
//     read-models (approvals backlog, active anomalies, risk-band distribution,
//     findings store), read live through narrow provider interfaces so nothing is
//     duplicated and a disabled subsystem simply contributes nothing.
//
// It also brokers a live event feed (server-sent events) so the dashboard can
// stream notable verdicts as they happen, each with enough context to drill into
// the owning subsystem tab.
//
// The Hub holds no source of truth: the window tallies are a bounded, decaying
// projection of events it is told about, and the posture summary is read on
// demand from the owning subsystems. A nil/absent subsystem is always handled
// gracefully. All exported methods are safe for concurrent use.
package secops

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// Outcome is the coarse admission disposition a notable event represents. It is
// the top-line breakdown the SOC view leads with.
type Outcome string

const (
	// OutcomeBlock is a refused/quarantined/denied pull (or a confirmed block).
	OutcomeBlock Outcome = "block"
	// OutcomeWarn is a flagged-but-served pull, or a review/regression signal.
	OutcomeWarn Outcome = "warn"
	// OutcomeAdmit is an explicit allow override (a granted break-glass exception).
	OutcomeAdmit Outcome = "admit"
)

// Defaults for the rolling window and the notable-event feed ring.
const (
	defaultWindow    = time.Hour
	defaultBuckets   = 60
	defaultFeedSize  = 512
	maxDistinctKeys  = 200 // cap on distinct gate/subject/severity keys per bucket
	subscriberBuffer = 64
)

// Options configures a Hub.
type Options struct {
	// Window is the rolling window the top-line tallies cover (default 1h).
	Window time.Duration
	// Buckets is the number of time buckets the window is divided into for decay
	// (default 60). More buckets means finer expiry granularity.
	Buckets int
	// FeedSize bounds the retained notable-event ring used for the feed and the
	// stream replay (default 512).
	FeedSize int
	// Providers are the optional subsystem read-models the posture summary taps.
	// Any nil provider is skipped, so a disabled subsystem contributes nothing.
	Providers Providers
	// Now overrides the clock (tests); defaults to time.Now.
	Now func() time.Time
}

// Hub is the SecOps aggregation read-model and live-event broker.
type Hub struct {
	mu sync.Mutex

	window    time.Duration
	bucketDur time.Duration
	buckets   []bucket // ring of time buckets, indexed by epoch/bucketDur

	feed     []NotableEvent // ring of recent notable events (newest appended)
	feedHead int
	feedLen  int
	feedCap  int
	seq      uint64

	subs   map[int]chan NotableEvent
	nextID int

	providers Providers
	now       func() time.Time

	// telemetry
	eventsObserved atomic.Uint64
	summaryQueries atomic.Uint64
	streamOpened   atomic.Uint64
	streamClosed   atomic.Uint64
	streamDropped  atomic.Uint64
}

// bucket holds the tallies for one slice of the rolling window. The epoch field
// identifies which window slice it currently represents so a stale bucket is
// recognized and reset lazily on access rather than swept by a timer.
type bucket struct {
	epoch      int64
	total      int64
	byOutcome  [3]int64 // indexed by outcomeIndex
	byGate     map[string]int64
	bySubject  map[string]int64
	bySeverity map[string]int64
}

func outcomeIndex(o Outcome) int {
	switch o {
	case OutcomeBlock:
		return 0
	case OutcomeWarn:
		return 1
	default:
		return 2
	}
}

// NewHub constructs a Hub. It is always safe to construct (even with no
// providers and no event source); it then yields a valid, empty summary.
func NewHub(opts Options) *Hub {
	window := opts.Window
	if window <= 0 {
		window = defaultWindow
	}
	buckets := opts.Buckets
	if buckets <= 0 {
		buckets = defaultBuckets
	}
	feedCap := opts.FeedSize
	if feedCap <= 0 {
		feedCap = defaultFeedSize
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	h := &Hub{
		window:    window,
		bucketDur: window / time.Duration(buckets),
		buckets:   make([]bucket, buckets),
		feed:      make([]NotableEvent, feedCap),
		feedCap:   feedCap,
		subs:      make(map[int]chan NotableEvent),
		providers: opts.Providers,
		now:       now,
	}
	if h.bucketDur <= 0 {
		h.bucketDur = time.Minute
	}
	return h
}

// Observe folds a notification event into the rolling window, appends it to the
// notable-event feed, and fans it out to live subscribers. It is the function
// registered as a notify tap; it must not block. A nil Hub is a no-op.
func (h *Hub) Observe(ev notify.Event) {
	if h == nil {
		return
	}
	// The synthetic test event is operator-initiated noise, not a verdict.
	if ev.Type == notify.EventTest {
		return
	}
	ne := classify(ev)
	if ne.Time.IsZero() {
		ne.Time = h.now().UTC()
	}

	h.mu.Lock()
	h.eventsObserved.Add(1)
	h.seq++
	ne.Seq = h.seq
	h.record(ne)
	h.appendFeed(ne)
	// Snapshot subscriber channels under the lock, then send without blocking.
	targets := make([]chan NotableEvent, 0, len(h.subs))
	for _, ch := range h.subs {
		targets = append(targets, ch)
	}
	h.mu.Unlock()

	for _, ch := range targets {
		select {
		case ch <- ne:
		default:
			// A slow client must never apply backpressure to the request path
			// (Observe runs inline in notify.Emit). Drop and count instead.
			h.streamDropped.Add(1)
		}
	}
}

// record updates the rolling-window buckets for ne, lazily resetting the target
// bucket if it now represents an older window slice. Caller holds h.mu.
func (h *Hub) record(ne NotableEvent) {
	epoch := ne.Time.UnixNano() / int64(h.bucketDur)
	idx := int(epoch % int64(len(h.buckets)))
	if idx < 0 {
		idx += len(h.buckets)
	}
	b := &h.buckets[idx]
	if b.epoch != epoch || b.byGate == nil {
		*b = bucket{
			epoch:      epoch,
			byGate:     make(map[string]int64),
			bySubject:  make(map[string]int64),
			bySeverity: make(map[string]int64),
		}
	}
	b.total++
	b.byOutcome[outcomeIndex(ne.Outcome)]++
	bumpCapped(b.byGate, ne.Gate)
	if ne.Subject != "" {
		bumpCapped(b.bySubject, ne.Subject)
	}
	if ne.Severity != "" {
		bumpCapped(b.bySeverity, ne.Severity)
	}
}

// bumpCapped increments m[key], refusing to grow the map past maxDistinctKeys so
// a flood of unique subjects cannot grow memory without bound.
func bumpCapped(m map[string]int64, key string) {
	if _, ok := m[key]; !ok && len(m) >= maxDistinctKeys {
		m["…other"]++
		return
	}
	m[key]++
}

// appendFeed pushes ne onto the bounded feed ring. Caller holds h.mu.
func (h *Hub) appendFeed(ne NotableEvent) {
	h.feed[h.feedHead] = ne
	h.feedHead = (h.feedHead + 1) % h.feedCap
	if h.feedLen < h.feedCap {
		h.feedLen++
	}
}

// recentLocked returns up to limit feed entries, newest first. Caller holds h.mu.
func (h *Hub) recentLocked(limit int) []NotableEvent {
	if limit <= 0 || limit > h.feedLen {
		limit = h.feedLen
	}
	out := make([]NotableEvent, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (h.feedHead - 1 - i + h.feedCap) % h.feedCap
		out = append(out, h.feed[idx])
	}
	return out
}

// Subscribe registers a live-feed consumer. It returns a receive channel of
// notable events and a cancel function the caller must invoke to release the
// subscription (e.g. on stream disconnect). The channel is buffered; if the
// consumer falls behind, events are dropped rather than blocking producers.
func (h *Hub) Subscribe() (<-chan NotableEvent, func()) {
	ch := make(chan NotableEvent, subscriberBuffer)
	h.mu.Lock()
	id := h.nextID
	h.nextID++
	h.subs[id] = ch
	h.mu.Unlock()
	h.streamOpened.Add(1)

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, id)
			h.mu.Unlock()
			h.streamClosed.Add(1)
			close(ch)
		})
	}
	return ch, cancel
}

// Summary assembles the full SOC read-model: the rolling-window decision tallies,
// the current posture from the owning subsystems, and the most recent notable
// events. It is read on demand and never blocks the request path. Each call is
// counted for the dashboard-query metric.
func (h *Hub) Summary() Summary {
	return h.summary(64)
}

func (h *Hub) summary(recentLimit int) Summary {
	h.summaryQueries.Add(1)
	now := h.now().UTC()

	h.mu.Lock()
	win := h.windowStatsLocked(now)
	recent := h.recentLocked(recentLimit)
	h.mu.Unlock()

	sum := Summary{
		GeneratedAt:   now,
		WindowSeconds: h.window.Seconds(),
		Window:        win,
		Recent:        recent,
		Posture:       h.providers.posture(now),
		Subsystems:    h.providers.enabled(),
	}
	return sum
}

// windowStatsLocked sums the buckets that fall within the rolling window ending
// at now. Caller holds h.mu.
func (h *Hub) windowStatsLocked(now time.Time) WindowStats {
	minEpoch := now.Add(-h.window).UnixNano() / int64(h.bucketDur)
	gate := map[string]int64{}
	subject := map[string]int64{}
	severity := map[string]int64{}
	var ws WindowStats
	for i := range h.buckets {
		b := &h.buckets[i]
		if b.byGate == nil || b.epoch < minEpoch {
			continue
		}
		ws.Total += b.total
		ws.Blocks += b.byOutcome[0]
		ws.Warns += b.byOutcome[1]
		ws.Admits += b.byOutcome[2]
		mergeCounts(gate, b.byGate)
		mergeCounts(subject, b.bySubject)
		mergeCounts(severity, b.bySeverity)
	}
	ws.ByGate = topCounts(gate, 0)
	ws.BySubject = topCounts(subject, 12)
	ws.BySeverity = topCounts(severity, 0)
	return ws
}

func mergeCounts(dst, src map[string]int64) {
	for k, v := range src {
		dst[k] += v
	}
}

// topCounts renders a count map as a slice sorted by descending value then key,
// truncated to limit (0 = all).
func topCounts(m map[string]int64, limit int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Metrics is the Hub's cumulative dashboard telemetry, surfaced as Prometheus
// counters by the observability layer.
type Metrics struct {
	EventsObserved uint64
	SummaryQueries uint64
	StreamOpened   uint64
	StreamClosed   uint64
	StreamDropped  uint64
	ActiveStreams  int
	WindowSeconds  float64
	FeedRetained   int
}

// MetricsSnapshot returns the Hub's cumulative telemetry. A nil Hub returns the
// zero value.
func (h *Hub) MetricsSnapshot() Metrics {
	if h == nil {
		return Metrics{}
	}
	h.mu.Lock()
	active := len(h.subs)
	retained := h.feedLen
	h.mu.Unlock()
	return Metrics{
		EventsObserved: h.eventsObserved.Load(),
		SummaryQueries: h.summaryQueries.Load(),
		StreamOpened:   h.streamOpened.Load(),
		StreamClosed:   h.streamClosed.Load(),
		StreamDropped:  h.streamDropped.Load(),
		ActiveStreams:  active,
		WindowSeconds:  h.window.Seconds(),
		FeedRetained:   retained,
	}
}
