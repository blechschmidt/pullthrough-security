package ratelimit

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Options configures a Limiter.
type Options struct {
	// Global is the process-wide policy applied to every request in addition to
	// the per-tenant policy. The zero value imposes no global limits.
	Global Policy
	// Default is the policy used for tenants without an explicit per-tenant
	// override. The zero value is unlimited.
	Default Policy
	// PerTenant maps tenant key to its policy override.
	PerTenant map[string]Policy
	// Store coordinates the windowed byte-quota counters. When nil, an in-memory
	// store is used (single-replica enforcement).
	Store Store
	// Now overrides the clock (for tests). When nil, time.Now is used; the
	// in-memory store (when Store is nil) shares this clock.
	Now func() time.Time
}

// Limiter enforces per-tenant and global rate, concurrency, and byte-quota
// policies. It is safe for concurrent use. A nil *Limiter admits everything, so
// rate limiting can be disabled without nil checks at call sites.
type Limiter struct {
	now   func() time.Time
	store Store

	mu       sync.RWMutex
	global   Policy
	def      Policy
	policies map[string]Policy       // explicit per-tenant overrides
	states   map[string]*tenantState // live state, keyed by tenant (and GlobalKey)

	// Aggregate counters (process-wide), read at scrape time.
	allowed   atomic.Int64
	throttled atomic.Int64
	thrRPS    atomic.Int64
	thrConc   atomic.Int64
	thrBytes  atomic.Int64
}

// tenantState holds the live, mutable enforcement state for one tenant.
type tenantState struct {
	bucket *tokenBucket // nil when RPS unlimited
	sem    *semaphore   // nil when concurrency unlimited

	allowed   atomic.Int64
	throttled atomic.Int64
}

// New constructs a Limiter from Options.
func New(opts Options) *Limiter {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	store := opts.Store
	if store == nil {
		store = newMemStore(now)
	}
	l := &Limiter{
		now:      now,
		store:    store,
		global:   opts.Global,
		def:      opts.Default,
		policies: make(map[string]Policy, len(opts.PerTenant)),
		states:   make(map[string]*tenantState),
	}
	for k, v := range opts.PerTenant {
		l.policies[k] = v
	}
	return l
}

// effectivePolicy returns the policy in force for tenant. Caller holds at least
// a read lock.
func (l *Limiter) effectivePolicy(tenant string) Policy {
	if p, ok := l.policies[tenant]; ok {
		return p
	}
	return l.def
}

// stateFor returns the live state for key, lazily creating it and reconciling
// its bucket/semaphore against the policy. Caller holds the write lock.
func (l *Limiter) stateFor(key string, p Policy) *tenantState {
	st, ok := l.states[key]
	if !ok {
		st = &tenantState{}
		l.states[key] = st
	}
	// Reconcile the token bucket with the current rate policy.
	if p.RPS > 0 {
		burst := p.effectiveBurst()
		if st.bucket == nil {
			st.bucket = newTokenBucket(p.RPS, burst)
		} else {
			st.bucket.setRate(p.RPS, burst)
		}
	} else {
		st.bucket = nil
	}
	// Reconcile the concurrency semaphore.
	if p.MaxConcurrent > 0 {
		if st.sem == nil {
			st.sem = newSemaphore(p.MaxConcurrent)
		} else {
			st.sem.setMax(p.MaxConcurrent)
		}
	} else {
		st.sem = nil
	}
	return st
}

// scope binds a policy to the concrete bucket/semaphore for one admission. The
// bucket and semaphore pointers are captured while holding the limiter lock, so
// the lock-free admission body never races a concurrent policy reconciliation.
type scope struct {
	key    string
	policy Policy
	bucket *tokenBucket
	sem    *semaphore
}

// Admit performs the full admission decision for one request on behalf of
// tenant: it checks the byte quota, acquires concurrency slots, and consumes a
// rate token, for both the global and the per-tenant policy. On success it
// returns a Reservation the caller must Release when the request completes (and
// whose RecordBytes it should call with the served byte count) and a Decision
// with Allowed true. On rejection it returns a no-op Reservation and a Decision
// describing the violated limit (with a Retry-After hint where applicable).
//
// A nil *Limiter admits everything.
func (l *Limiter) Admit(ctx context.Context, tenant string) (Reservation, Decision) {
	if l == nil {
		return Reservation{}, Decision{Allowed: true}
	}

	l.mu.Lock()
	tp := l.effectivePolicy(tenant)
	// Resolve the per-request tenant state for metrics accounting even when the
	// tenant policy is unlimited (so allowed/throttled are attributed). The
	// *tenantState pointer is stable and its counters are atomics, so it is safe
	// to retain past the unlock.
	tenantState := l.stateFor(tenant, tp)
	scopes := make([]scope, 0, 2)
	if !l.global.unlimited() {
		gst := l.stateFor(GlobalKey, l.global)
		scopes = append(scopes, scope{key: GlobalKey, policy: l.global, bucket: gst.bucket, sem: gst.sem})
	}
	if !tp.unlimited() {
		scopes = append(scopes, scope{key: tenant, policy: tp, bucket: tenantState.bucket, sem: tenantState.sem})
	}
	l.mu.Unlock()

	if len(scopes) == 0 {
		l.allowed.Add(1)
		tenantState.allowed.Add(1)
		return Reservation{}, Decision{Allowed: true}
	}

	now := l.now()

	// 1) Byte-quota pre-check (read-only). A quota already exhausted is rejected
	// before any rate token is spent or slot acquired. Store errors fail open:
	// a transient backend hiccup must not wedge serving.
	for _, sc := range scopes {
		if sc.policy.ByteQuota <= 0 {
			continue
		}
		used, err := l.store.Current(ctx, byteKey(sc.key), sc.policy.effectiveWindow())
		if err != nil {
			continue
		}
		if used >= sc.policy.ByteQuota {
			return l.reject(tenantState, LimitBytes, "byte quota exhausted", retryAfterForWindow(sc.policy.effectiveWindow()))
		}
	}

	// 2) Concurrency acquisition, in scope order. On failure, release whatever we
	// already acquired so a rejection never leaks a slot.
	var acquired []*semaphore
	for _, sc := range scopes {
		if sc.sem == nil {
			continue
		}
		if !sc.sem.acquire() {
			for _, s := range acquired {
				s.release()
			}
			return l.reject(tenantState, LimitConcurrency, "concurrency limit reached", 0)
		}
		acquired = append(acquired, sc.sem)
	}

	// 3) Rate token, in scope order. On failure, release acquired slots.
	for _, sc := range scopes {
		if sc.bucket == nil {
			continue
		}
		ok, retry := sc.bucket.take(now)
		if !ok {
			for _, s := range acquired {
				s.release()
			}
			return l.reject(tenantState, LimitRPS, "request rate limit exceeded", retry)
		}
	}

	// Admitted. Build the reservation: release slots and record bytes against
	// every scope that meters them.
	byteScopes := make([]scope, 0, len(scopes))
	for _, sc := range scopes {
		if sc.policy.ByteQuota > 0 {
			byteScopes = append(byteScopes, sc)
		}
	}
	l.allowed.Add(1)
	tenantState.allowed.Add(1)

	res := Reservation{
		release: func() {
			for _, s := range acquired {
				s.release()
			}
		},
	}
	if len(byteScopes) > 0 {
		res.recordBytes = func(n int64) {
			for _, sc := range byteScopes {
				_, _ = l.store.Add(ctx, byteKey(sc.key), n, sc.policy.effectiveWindow())
			}
		}
	}
	return res, Decision{Allowed: true}
}

// reject increments the appropriate counters and returns a denial decision.
func (l *Limiter) reject(st *tenantState, typ LimitType, reason string, retry time.Duration) (Reservation, Decision) {
	l.throttled.Add(1)
	if st != nil {
		st.throttled.Add(1)
	}
	switch typ {
	case LimitRPS:
		l.thrRPS.Add(1)
	case LimitConcurrency:
		l.thrConc.Add(1)
	case LimitBytes:
		l.thrBytes.Add(1)
	}
	return Reservation{}, Decision{Allowed: false, Type: typ, Reason: reason, RetryAfter: retry}
}

// SetPolicy installs or replaces a tenant's policy at runtime. The tenant's live
// state (current tokens, in-flight count) is preserved and reconciled to the new
// limits. It rejects the reserved global key and invalid policies.
func (l *Limiter) SetPolicy(tenant string, p Policy) error {
	if l == nil {
		return nil
	}
	if tenant == GlobalKey {
		return errReservedKey
	}
	if err := p.validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.policies[tenant] = p
	l.stateFor(tenant, p) // reconcile live state immediately
	return nil
}

// SetGlobalPolicy replaces the process-wide policy at runtime.
func (l *Limiter) SetGlobalPolicy(p Policy) error {
	if l == nil {
		return nil
	}
	if err := p.validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global = p
	l.stateFor(GlobalKey, p)
	return nil
}

// Policy returns the effective policy for a tenant and whether an explicit
// override exists for it.
func (l *Limiter) Policy(tenant string) (Policy, bool) {
	if l == nil {
		return Policy{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	p, ok := l.policies[tenant]
	if ok {
		return p, true
	}
	return l.def, false
}

// byteKey namespaces the byte-quota counter for a scope within the store.
func byteKey(scope string) string { return "ratelimit/bytes/" + scope }

// retryAfterForWindow caps a window-based Retry-After hint to a client-friendly
// upper bound (the full window can be days for a monthly quota).
func retryAfterForWindow(window time.Duration) time.Duration {
	const max = time.Hour
	if window <= 0 || window > max {
		return max
	}
	return window
}

// snapshotTenants assembles the per-tenant metrics rows. Caller holds no lock.
func (l *Limiter) snapshotTenants(ctx context.Context) []TenantSnapshot {
	l.mu.RLock()
	keys := make([]string, 0, len(l.states))
	for k := range l.states {
		if k == GlobalKey {
			continue
		}
		keys = append(keys, k)
	}
	type row struct {
		key    string
		policy Policy
		st     *tenantState
	}
	rows := make([]row, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, row{key: k, policy: l.effectivePolicy(k), st: l.states[k]})
	}
	l.mu.RUnlock()

	sort.Slice(rows, func(i, j int) bool { return rows[i].key < rows[j].key })
	out := make([]TenantSnapshot, 0, len(rows))
	for _, r := range rows {
		out = append(out, l.tenantSnapshot(ctx, r.key, r.policy, r.st))
	}
	return out
}

// tenantSnapshot builds one snapshot row, reading live byte usage from the store.
func (l *Limiter) tenantSnapshot(ctx context.Context, key string, p Policy, st *tenantState) TenantSnapshot {
	ts := TenantSnapshot{
		Tenant:    key,
		Policy:    p,
		Allowed:   st.allowed.Load(),
		Throttled: st.throttled.Load(),
	}
	if st.sem != nil {
		ts.InFlight = st.sem.inFlight()
	}
	if p.ByteQuota > 0 {
		if used, err := l.store.Current(ctx, byteKey(key), p.effectiveWindow()); err == nil {
			ts.BytesUsed = used
		}
		if ws, ok := l.store.(windowStart); ok {
			if start, ok := ws.windowStart(byteKey(key)); ok {
				ts.WindowEnds = start.Add(p.effectiveWindow())
			}
		}
	}
	return ts
}

// Metrics returns a point-in-time snapshot of the limiter's state for metrics
// export and the admin API.
func (l *Limiter) Metrics() Snapshot {
	if l == nil {
		return Snapshot{}
	}
	ctx := context.Background()
	snap := Snapshot{
		Allowed:   l.allowed.Load(),
		Throttled: l.throttled.Load(),
		ThrottledByReason: map[string]int64{
			string(LimitRPS):         l.thrRPS.Load(),
			string(LimitConcurrency): l.thrConc.Load(),
			string(LimitBytes):       l.thrBytes.Load(),
		},
		Tenants: l.snapshotTenants(ctx),
	}
	l.mu.RLock()
	gp := l.global
	gst := l.states[GlobalKey]
	l.mu.RUnlock()
	if gst != nil {
		snap.Global = l.tenantSnapshot(ctx, GlobalKey, gp, gst)
	} else {
		snap.Global = TenantSnapshot{Tenant: GlobalKey, Policy: gp}
	}
	return snap
}
