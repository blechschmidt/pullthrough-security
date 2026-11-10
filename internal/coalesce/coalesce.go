// Package coalesce implements a performance and resilience layer for the proxy's
// pull path. It eliminates redundant upstream fetches under concurrent load with
// two cooperating mechanisms:
//
//   - Request coalescing (singleflight): N simultaneous cache-miss requests for
//     the same artifact key trigger exactly one upstream fetch (the "leader");
//     every other caller (a "waiter") blocks on that single in-flight fetch and
//     is then served its own independent stream from the now-filled cache. This
//     collapses a thundering herd into one origin request.
//
//   - Negative caching: terminal upstream failures (404/410, authentication
//     failures) are remembered for a short, bounded TTL so a burst of requests
//     for a genuinely missing artifact does not repeatedly hammer the upstream.
//     Transient failures (5xx, throttling, network errors) are remembered for a
//     jittered backoff window instead, so retries are spread out rather than
//     synchronized.
//
// The coalescer is deliberately key-agnostic: the caller is responsible for
// constructing a key that encodes the tenant/auth scope of a request, so private
// artifacts fetched with one tenant's credentials are never shared with another
// (see the gateway's coalesceKey). The negative cache is keyed the same way, so a
// 403 observed by one tenant never suppresses another tenant's (possibly
// authorized) fetch.
//
// Coalescer is generic over the value type T the load produces (the proxy uses
// *cache.Entry). The leader returns the value its load produced; each waiter
// obtains a fresh value via the supplied reopen function so that independent
// resources (such as content streams) are never shared between callers.
package coalesce

import (
	"container/list"
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// ErrOverloaded is returned by Do when starting a new in-flight fetch would
// exceed the configured MaxInflight ceiling. Callers should map it onto a
// retryable status (the gateway returns 503 with a Retry-After). It is never
// returned to a caller that merely joins an existing in-flight fetch.
var ErrOverloaded = errors.New("coalesce: too many concurrent in-flight fetches")

// Verdict is the classifier's decision about whether and how to negatively cache
// a failed load. A zero Verdict (Cache=false) means "do not negatively cache"
// (used for client cancellations and other non-deterministic conditions).
type Verdict struct {
	// Cache reports whether a negative entry should be stored for this error.
	Cache bool
	// Retryable marks a transient failure (5xx/throttle/network). Such entries
	// use a short jittered backoff TTL rather than the standard NegativeTTL so
	// retries against a recovering upstream are spread out.
	Retryable bool
	// Kind is a low-cardinality label for the failure class ("not_found",
	// "gone", "auth", "server", "throttled", "error"), surfaced in metrics.
	Kind string
}

// Classifier maps a load error onto a negative-caching Verdict.
type Classifier func(error) Verdict

// Info reports how a single Do call was served, for the caller's own telemetry
// (e.g. an X-Cache header). Exactly one of the boolean fields is set on a
// successful or coalesced call; an overloaded rejection sets none.
type Info struct {
	// Lead is set when this call ran the load (it was the leader, or coalescing
	// was disabled).
	Lead bool
	// Coalesced is set when this call joined an already in-flight leader.
	Coalesced bool
	// Negative is set when this call was served from the negative cache without
	// contacting the upstream.
	Negative bool
}

// Config tunes the coalescer. The zero value is disabled; withDefaults fills in
// sensible values for the enabled knobs.
type Config struct {
	// Enabled turns the layer on. When false, Do is a thin pass-through that runs
	// the load directly with no coalescing or negative caching.
	Enabled bool
	// NegativeTTL is how long a terminal negative result (404/410/auth) is
	// remembered. Default 30s. A short value bounds how long a transiently-missing
	// artifact stays shadowed once it appears upstream.
	NegativeTTL time.Duration
	// MaxNegativeEntries bounds the negative cache; the least-recently-used entry
	// is evicted when the bound is exceeded. Default 4096; <=0 means unbounded.
	MaxNegativeEntries int
	// MaxInflight caps the number of distinct in-flight leader fetches. A new
	// fetch beyond the cap fails fast with ErrOverloaded (waiters joining an
	// existing fetch are never rejected). Default 0 means unbounded.
	MaxInflight int
	// Backoff5xxBase and Backoff5xxMax bound the jittered backoff window used for
	// retryable (5xx/throttle/network) negative entries. The effective TTL is
	// chosen uniformly at random from [Base, Max]. Defaults 1s and 5s.
	Backoff5xxBase time.Duration
	Backoff5xxMax  time.Duration
}

const (
	defaultNegativeTTL        = 30 * time.Second
	defaultMaxNegativeEntries = 4096
	defaultBackoffBase        = 1 * time.Second
	defaultBackoffMax         = 5 * time.Second
)

// withDefaults returns a copy of c with unset enabled-mode knobs filled in.
func (c Config) withDefaults() Config {
	if c.NegativeTTL <= 0 {
		c.NegativeTTL = defaultNegativeTTL
	}
	if c.MaxNegativeEntries == 0 {
		c.MaxNegativeEntries = defaultMaxNegativeEntries
	}
	if c.Backoff5xxBase <= 0 {
		c.Backoff5xxBase = defaultBackoffBase
	}
	if c.Backoff5xxMax <= 0 || c.Backoff5xxMax < c.Backoff5xxBase {
		c.Backoff5xxMax = max(defaultBackoffMax, c.Backoff5xxBase)
	}
	return c
}

// call is one in-flight leader fetch other callers can wait on.
type call struct {
	wg  sync.WaitGroup
	err error
}

// negEntry is one cached negative result.
type negEntry struct {
	key       string
	err       error
	kind      string
	retryable bool
	expiresAt time.Time
}

// counters holds the lock-free cumulative metrics read at scrape time.
type counters struct {
	lookups      atomic.Int64
	coalesced    atomic.Int64
	leads        atomic.Int64
	negHits      atomic.Int64
	negStored    atomic.Int64
	negEvictions atomic.Int64
	negExpired   atomic.Int64
	overloaded   atomic.Int64
}

// Coalescer coalesces concurrent loads for the same key and negatively caches
// terminal failures. It is safe for concurrent use.
type Coalescer[T any] struct {
	cfg      Config
	classify Classifier

	now   func() time.Time
	rngMu sync.Mutex
	rng   *rand.Rand

	mu       sync.Mutex
	calls    map[string]*call
	neg      map[string]*list.Element // key -> *negEntry element in negLRU
	negLRU   *list.List               // front = most recently stored/refreshed
	inflight int
	byKind   map[string]*kindCounters // per-failure-class breakdown

	m counters
}

// kindCounters breaks negative-cache activity down by failure class.
type kindCounters struct {
	stored  int64
	hits    int64
	evicted int64
}

// New constructs a Coalescer. classify may be nil when Enabled is false; when
// the layer is on it is required to decide negative-caching behavior (a nil
// classifier then negatively caches nothing).
func New[T any](cfg Config, classify Classifier) *Coalescer[T] {
	cfg = cfg.withDefaults()
	if classify == nil {
		classify = func(error) Verdict { return Verdict{} }
	}
	return &Coalescer[T]{
		cfg:      cfg,
		classify: classify,
		now:      time.Now,
		// A fixed seed keeps backoff jitter deterministic across restarts; its
		// only job is to de-correlate concurrent waiters, which it does because
		// they draw sequentially from the shared generator.
		rng:    rand.New(rand.NewSource(0x1E3779B97F4A7C15)),
		calls:  make(map[string]*call),
		neg:    make(map[string]*list.Element),
		negLRU: list.New(),
		byKind: make(map[string]*kindCounters),
	}
}

// setClock overrides the time source (tests only).
func (c *Coalescer[T]) setClock(now func() time.Time) { c.now = now }

// Enabled reports whether coalescing/negative-caching is active.
func (c *Coalescer[T]) Enabled() bool { return c != nil && c.cfg.Enabled }

// Do coalesces a load for key.
//
//   - If a fresh negative entry exists for key, its error is returned
//     immediately without running load (Info.Negative).
//   - If a leader is already loading key, this call waits for it; on the
//     leader's success it returns reopen(ctx) (its own independent value), and on
//     the leader's failure it returns the same error (Info.Coalesced).
//   - Otherwise this call becomes the leader: it runs load exactly once, shares
//     the result with any waiters, records a negative entry on a classified
//     failure, and returns load's value (Info.Lead).
//
// When the coalescer is disabled (or nil), Do simply runs load(ctx).
func (c *Coalescer[T]) Do(
	ctx context.Context,
	key string,
	load func(context.Context) (T, error),
	reopen func(context.Context) (T, error),
) (T, Info, error) {
	var zero T
	if c == nil || !c.cfg.Enabled {
		v, err := load(ctx)
		return v, Info{Lead: true}, err
	}

	c.m.lookups.Add(1)

	c.mu.Lock()
	// 1) Negative cache: short-circuit a known-bad key.
	if el, ok := c.neg[key]; ok {
		ne := el.Value.(*negEntry)
		if c.now().Before(ne.expiresAt) {
			c.negLRU.MoveToFront(el)
			err := ne.err
			c.kindLocked(ne.kind).hits++
			c.mu.Unlock()
			c.m.negHits.Add(1)
			return zero, Info{Negative: true}, err
		}
		// Expired: drop it and fall through to a fresh fetch.
		c.removeNegLocked(el)
		c.m.negExpired.Add(1)
	}

	// 2) Join an in-flight leader if one exists.
	if cl, ok := c.calls[key]; ok {
		c.mu.Unlock()
		c.m.coalesced.Add(1)
		cl.wg.Wait()
		if cl.err != nil {
			// The leader failed; propagate its error to every waiter. The leader
			// has already recorded the negative entry on its behalf.
			return zero, Info{Coalesced: true}, cl.err
		}
		v, err := reopen(ctx)
		return v, Info{Coalesced: true}, err
	}

	// 3) Become the leader, subject to the in-flight ceiling.
	if c.cfg.MaxInflight > 0 && c.inflight >= c.cfg.MaxInflight {
		c.mu.Unlock()
		c.m.overloaded.Add(1)
		return zero, Info{}, ErrOverloaded
	}
	cl := &call{}
	cl.wg.Add(1)
	c.calls[key] = cl
	c.inflight++
	c.mu.Unlock()

	c.m.leads.Add(1)
	v, err := load(ctx)
	cl.err = err
	cl.wg.Done()

	c.mu.Lock()
	if c.calls[key] == cl {
		delete(c.calls, key)
	}
	c.inflight--
	if err != nil {
		c.recordNegativeLocked(key, err)
	} else if el, ok := c.neg[key]; ok {
		// A positive fill clears any stale negative entry for the key so a later
		// request is served the freshly-cached artifact rather than a stale 404.
		c.removeNegLocked(el)
	}
	c.mu.Unlock()

	return v, Info{Lead: true}, err
}

// recordNegativeLocked classifies err and, when cacheable, stores or refreshes a
// negative entry for key. Callers must hold c.mu.
func (c *Coalescer[T]) recordNegativeLocked(key string, err error) {
	v := c.classify(err)
	if !v.Cache {
		return
	}
	ttl := c.cfg.NegativeTTL
	if v.Retryable {
		ttl = c.jitteredBackoff()
	}
	if ttl <= 0 {
		return
	}
	kind := v.Kind
	if kind == "" {
		kind = "error"
	}
	exp := c.now().Add(ttl)

	if el, ok := c.neg[key]; ok {
		ne := el.Value.(*negEntry)
		ne.err, ne.kind, ne.retryable, ne.expiresAt = err, kind, v.Retryable, exp
		c.negLRU.MoveToFront(el)
		return
	}

	ne := &negEntry{key: key, err: err, kind: kind, retryable: v.Retryable, expiresAt: exp}
	c.neg[key] = c.negLRU.PushFront(ne)
	c.m.negStored.Add(1)
	c.kindLocked(kind).stored++

	if c.cfg.MaxNegativeEntries > 0 {
		for c.negLRU.Len() > c.cfg.MaxNegativeEntries {
			back := c.negLRU.Back()
			if back == nil {
				break
			}
			evicted := back.Value.(*negEntry)
			c.removeNegLocked(back)
			c.m.negEvictions.Add(1)
			c.kindLocked(evicted.kind).evicted++
		}
	}
}

// removeNegLocked deletes a negative entry. Callers must hold c.mu.
func (c *Coalescer[T]) removeNegLocked(el *list.Element) {
	ne := el.Value.(*negEntry)
	delete(c.neg, ne.key)
	c.negLRU.Remove(el)
}

// kindLocked returns the per-kind counter, creating it on first use. Callers
// must hold c.mu.
func (c *Coalescer[T]) kindLocked(kind string) *kindCounters {
	kc, ok := c.byKind[kind]
	if !ok {
		kc = &kindCounters{}
		c.byKind[kind] = kc
	}
	return kc
}

// jitteredBackoff returns a TTL drawn uniformly from [Base, Max].
func (c *Coalescer[T]) jitteredBackoff() time.Duration {
	base, hi := c.cfg.Backoff5xxBase, c.cfg.Backoff5xxMax
	if hi <= base {
		return base
	}
	spread := int64(hi - base)
	c.rngMu.Lock()
	j := c.rng.Int63n(spread + 1)
	c.rngMu.Unlock()
	return base + time.Duration(j)
}

// Purge removes the negative entry for key, if any, and reports whether one was
// removed. It lets an operator (admin API) clear a stuck negative result.
func (c *Coalescer[T]) Purge(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.neg[key]; ok {
		c.removeNegLocked(el)
		return true
	}
	return false
}

// PurgeNegativeCache drops every negative entry and reports how many were
// removed.
func (c *Coalescer[T]) PurgeNegativeCache() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.negLRU.Len()
	c.neg = make(map[string]*list.Element)
	c.negLRU.Init()
	return n
}
