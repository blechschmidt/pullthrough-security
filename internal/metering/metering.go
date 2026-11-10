// Package metering implements a tenant-scoped usage-metering and chargeback
// subsystem (Task 84) so operators can attribute proxy cost and observe (or
// alert on) consumption per tenant.
//
// It mirrors the secops notifier-tap pattern: a single low-overhead in-process
// accumulator is fed by narrow taps wired onto the existing pull path, cache,
// and admission gates. Nothing here re-derives any verdict or re-counts bytes
// the gateway already serves — it only folds the events it is told about into
// per-tenant counters.
//
// The accumulator tracks, per tenant:
//   - bytes served, split by cache-hit vs upstream-fetch;
//   - the storage footprint of cached artifacts the tenant caused to be filled;
//   - request counts, broken down by backend and ecosystem;
//   - admission-scan invocations and an estimated LLM/scan cost (a configurable
//     per-gate cost model);
//   - quarantine and block counts.
//
// Live counters are cumulative since process start (monotonic, so they back
// Prometheus counters cleanly). On a periodic tick the Meter snapshots the
// delta since the previous tick into a bounded, optionally file-durable history
// of rollups, from which time-ranged chargeback reports (hourly/daily) are
// assembled. A nil *Meter is a valid no-op so metering can be disabled without
// nil checks at the call sites.
package metering

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

const (
	// unscopedTenant buckets traffic from unauthenticated / tenant-less requests
	// so it is still accounted rather than silently dropped.
	unscopedTenant = "(unscoped)"
	// defaultRetentionHours bounds how many hourly rollups are retained (14 days).
	defaultRetentionHours = 24 * 14
	// defaultRollupInterval is the periodic snapshot cadence.
	defaultRollupInterval = time.Hour
	// defaultScanCostMicros is the estimated cost charged per admission scan when
	// no per-gate override is configured (micro-units of an operator-chosen
	// currency; e.g. 1_000_000 == one unit).
	defaultScanCostMicros = 1000
	// maxDistinctKeys caps the per-tenant breakdown maps so a flood of distinct
	// backends/ecosystems/gates cannot grow memory without bound.
	maxDistinctKeys = 256
)

// Counters is the set of usage counters tracked for one tenant over one period
// (or cumulatively). The breakdown maps are allocated lazily.
type Counters struct {
	Requests        int64 `json:"requests"`
	BytesCacheHit   int64 `json:"bytesCacheHit"`
	BytesUpstream   int64 `json:"bytesUpstream"`
	StorageBytes    int64 `json:"storageBytes"`
	ScanInvocations int64 `json:"scanInvocations"`
	ScanCostMicros  int64 `json:"scanCostMicros"`
	Blocked         int64 `json:"blocked"`
	Quarantined     int64 `json:"quarantined"`

	ByBackend   map[string]int64 `json:"byBackend,omitempty"`
	ByEcosystem map[string]int64 `json:"byEcosystem,omitempty"`
	ByScanGate  map[string]int64 `json:"byScanGate,omitempty"`
	ByBlockGate map[string]int64 `json:"byBlockGate,omitempty"`
}

// BytesServed is the total served bytes (cache-hit plus upstream-fetch).
func (c Counters) BytesServed() int64 { return c.BytesCacheHit + c.BytesUpstream }

// IsZero reports whether the counters carry no activity, so an empty rollup
// period is dropped rather than persisted.
func (c Counters) IsZero() bool {
	return c.Requests == 0 && c.BytesCacheHit == 0 && c.BytesUpstream == 0 &&
		c.StorageBytes == 0 && c.ScanInvocations == 0 && c.ScanCostMicros == 0 &&
		c.Blocked == 0 && c.Quarantined == 0
}

// add folds other into c, summing scalars and merging the breakdown maps.
func (c *Counters) add(other Counters) {
	c.Requests += other.Requests
	c.BytesCacheHit += other.BytesCacheHit
	c.BytesUpstream += other.BytesUpstream
	c.StorageBytes += other.StorageBytes
	c.ScanInvocations += other.ScanInvocations
	c.ScanCostMicros += other.ScanCostMicros
	c.Blocked += other.Blocked
	c.Quarantined += other.Quarantined
	c.ByBackend = mergeMap(c.ByBackend, other.ByBackend)
	c.ByEcosystem = mergeMap(c.ByEcosystem, other.ByEcosystem)
	c.ByScanGate = mergeMap(c.ByScanGate, other.ByScanGate)
	c.ByBlockGate = mergeMap(c.ByBlockGate, other.ByBlockGate)
}

// sub returns c minus base, used to derive a period delta from two cumulative
// snapshots. Breakdown maps are differenced key-by-key (a key absent from base
// is zero).
func (c Counters) sub(base Counters) Counters {
	out := Counters{
		Requests:        c.Requests - base.Requests,
		BytesCacheHit:   c.BytesCacheHit - base.BytesCacheHit,
		BytesUpstream:   c.BytesUpstream - base.BytesUpstream,
		StorageBytes:    c.StorageBytes - base.StorageBytes,
		ScanInvocations: c.ScanInvocations - base.ScanInvocations,
		ScanCostMicros:  c.ScanCostMicros - base.ScanCostMicros,
		Blocked:         c.Blocked - base.Blocked,
		Quarantined:     c.Quarantined - base.Quarantined,
	}
	out.ByBackend = subMap(c.ByBackend, base.ByBackend)
	out.ByEcosystem = subMap(c.ByEcosystem, base.ByEcosystem)
	out.ByScanGate = subMap(c.ByScanGate, base.ByScanGate)
	out.ByBlockGate = subMap(c.ByBlockGate, base.ByBlockGate)
	return out
}

// clone returns a deep copy so a cumulative snapshot can be retained as a
// baseline without aliasing the live maps.
func (c Counters) clone() Counters {
	out := c
	out.ByBackend = cloneMap(c.ByBackend)
	out.ByEcosystem = cloneMap(c.ByEcosystem)
	out.ByScanGate = cloneMap(c.ByScanGate)
	out.ByBlockGate = cloneMap(c.ByBlockGate)
	return out
}

// Rollup is a per-tenant usage delta for one closed period [Start, End).
type Rollup struct {
	Tenant string    `json:"tenant"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Counters
}

// Budget is an optional per-tenant consumption ceiling. A zero field means "no
// limit for that dimension". Crossing a ceiling fires a one-shot notify alert.
type Budget struct {
	// MaxBytes caps cumulative served bytes (cache-hit + upstream).
	MaxBytes int64 `json:"maxBytes,omitempty"`
	// MaxScanCostMicros caps the cumulative estimated scan/LLM cost.
	MaxScanCostMicros int64 `json:"maxScanCostMicros,omitempty"`
}

func (b Budget) isZero() bool { return b.MaxBytes == 0 && b.MaxScanCostMicros == 0 }

// Config configures a Meter.
type Config struct {
	// Enabled reports whether the subsystem is active. A disabled Meter still
	// constructs (so wiring is unconditional) but its taps are no-ops.
	Enabled bool
	// RetentionHours bounds the retained rollup history (default 14 days).
	RetentionHours int
	// RollupInterval is the periodic snapshot cadence (default 1h).
	RollupInterval time.Duration
	// StatePath, when set, persists the rollup history as JSON so usage survives a
	// restart. Empty keeps history in memory only.
	StatePath string
	// DefaultScanCostMicros is charged per scan absent a per-gate override.
	DefaultScanCostMicros int64
	// ScanCostMicros overrides the estimated cost per admission-scan gate.
	ScanCostMicros map[string]int64
	// Budgets are optional per-tenant ceilings; the "*" key sets a default applied
	// to any tenant without an explicit entry.
	Budgets map[string]Budget
	// Notifier receives one-shot budget-threshold alerts. Nil disables alerting.
	Notifier notify.Emitter
	// Now overrides the clock (tests); defaults to time.Now.
	Now func() time.Time
}

// Meter is the tenant-scoped usage accumulator and rollup store.
type Meter struct {
	enabled        bool
	retentionHours int
	rollupInterval time.Duration
	statePath      string
	defaultCost    int64
	scanCosts      map[string]int64
	budgets        map[string]Budget
	notifier       notify.Emitter
	now            func() time.Time

	mu       sync.Mutex
	live     map[string]*Counters // cumulative-since-start, per tenant (monotonic)
	baseline map[string]Counters  // cumulative at the last rollup, per tenant
	history  []Rollup             // bounded, oldest-first
	lastRoll time.Time
	fired    map[string]string // tenant -> highest budget dimension already alerted

	rollupsTotal atomic.Uint64
	budgetAlerts atomic.Uint64

	stop     chan struct{}
	stopOnce sync.Once
	started  bool
}

// New constructs a Meter from cfg. It is always safe to construct; a disabled
// config yields a no-op meter that still answers (empty) reads.
func New(cfg Config) *Meter {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	retention := cfg.RetentionHours
	if retention <= 0 {
		retention = defaultRetentionHours
	}
	interval := cfg.RollupInterval
	if interval <= 0 {
		interval = defaultRollupInterval
	}
	cost := cfg.DefaultScanCostMicros
	if cost <= 0 {
		cost = defaultScanCostMicros
	}
	m := &Meter{
		enabled:        cfg.Enabled,
		retentionHours: retention,
		rollupInterval: interval,
		statePath:      strings.TrimSpace(cfg.StatePath),
		defaultCost:    cost,
		scanCosts:      lowerKeys(cfg.ScanCostMicros),
		budgets:        cfg.Budgets,
		notifier:       cfg.Notifier,
		now:            now,
		live:           make(map[string]*Counters),
		baseline:       make(map[string]Counters),
		fired:          make(map[string]string),
		lastRoll:       now().UTC(),
		stop:           make(chan struct{}),
	}
	if m.statePath != "" {
		if err := m.load(); err == nil {
			// Trim any history already past retention on load.
			m.mu.Lock()
			m.pruneLocked(m.now().UTC())
			m.mu.Unlock()
		}
	}
	return m
}

// Enabled reports whether the subsystem is active.
func (m *Meter) Enabled() bool { return m != nil && m.enabled }

// normalizeTenant collapses an empty/whitespace tenant to the unscoped bucket.
func normalizeTenant(tenant string) string {
	t := strings.TrimSpace(tenant)
	if t == "" {
		return unscopedTenant
	}
	return t
}

// tenantLocked returns the live counters for tenant, creating them if absent.
// Caller holds m.mu.
func (m *Meter) tenantLocked(tenant string) *Counters {
	c := m.live[tenant]
	if c == nil {
		c = &Counters{}
		m.live[tenant] = c
	}
	return c
}

// --- taps (Recorder surface) -----------------------------------------------
//
// These methods are the narrow surface the gateway records into. They are all
// nil-safe and no-op when the subsystem is disabled, so the call sites need no
// guards.

// RecordRequest accounts one served backend request to a tenant, broken down by
// backend and ecosystem.
func (m *Meter) RecordRequest(tenant, backend, ecosystem string) {
	if !m.Enabled() {
		return
	}
	t := normalizeTenant(tenant)
	m.mu.Lock()
	c := m.tenantLocked(t)
	c.Requests++
	if backend != "" {
		c.ByBackend = bumpCapped(c.ByBackend, backend, 1)
	}
	if ecosystem != "" {
		c.ByEcosystem = bumpCapped(c.ByEcosystem, ecosystem, 1)
	}
	m.mu.Unlock()
}

// RecordTraffic accounts served bytes to a tenant, categorized by whether the
// bytes came from the cache (cacheHit) or required an upstream fetch.
func (m *Meter) RecordTraffic(tenant string, bytes int64, cacheHit bool) {
	if !m.Enabled() || bytes <= 0 {
		return
	}
	t := normalizeTenant(tenant)
	m.mu.Lock()
	c := m.tenantLocked(t)
	if cacheHit {
		c.BytesCacheHit += bytes
	} else {
		c.BytesUpstream += bytes
	}
	budget := m.budgetFor(t)
	used := c.BytesServed()
	m.mu.Unlock()
	if budget.MaxBytes > 0 && used >= budget.MaxBytes {
		m.fireBudget(t, "bytes", used, budget.MaxBytes)
	}
}

// RecordStorage accounts the storage footprint a tenant caused by filling the
// cache with a newly-fetched artifact.
func (m *Meter) RecordStorage(tenant string, bytes int64) {
	if !m.Enabled() || bytes <= 0 {
		return
	}
	t := normalizeTenant(tenant)
	m.mu.Lock()
	m.tenantLocked(t).StorageBytes += bytes
	m.mu.Unlock()
}

// RecordScan accounts one admission-scan invocation against a tenant and adds
// the configured estimated cost for the owning gate.
func (m *Meter) RecordScan(tenant, gate string) {
	if !m.Enabled() {
		return
	}
	t := normalizeTenant(tenant)
	cost := m.scanCost(gate)
	m.mu.Lock()
	c := m.tenantLocked(t)
	c.ScanInvocations++
	c.ScanCostMicros += cost
	if gate != "" {
		c.ByScanGate = bumpCapped(c.ByScanGate, gate, 1)
	}
	budget := m.budgetFor(t)
	used := c.ScanCostMicros
	m.mu.Unlock()
	if budget.MaxScanCostMicros > 0 && used >= budget.MaxScanCostMicros {
		m.fireBudget(t, "scanCost", used, budget.MaxScanCostMicros)
	}
}

// RecordBlock accounts one admission-gate refusal against a tenant, attributed
// to the owning gate.
func (m *Meter) RecordBlock(tenant, gate string) {
	if !m.Enabled() {
		return
	}
	t := normalizeTenant(tenant)
	m.mu.Lock()
	c := m.tenantLocked(t)
	c.Blocked++
	if gate != "" {
		c.ByBlockGate = bumpCapped(c.ByBlockGate, gate, 1)
	}
	m.mu.Unlock()
}

// Observe is the notify tap (mirroring secops.Hub.Observe): it folds quarantine
// events into the per-tenant quarantine counter. Tenant attribution is
// best-effort from the event (a "tenant" field, else the subject); unattributed
// quarantines fall into the unscoped bucket. It must not block.
func (m *Meter) Observe(ev notify.Event) {
	if !m.Enabled() {
		return
	}
	if ev.Type != notify.EventQuarantine {
		return
	}
	t := normalizeTenant(eventTenant(ev))
	m.mu.Lock()
	m.tenantLocked(t).Quarantined++
	m.mu.Unlock()
}

// eventTenant extracts the tenant a notify event pertains to, preferring an
// explicit "tenant" field over the subject.
func eventTenant(ev notify.Event) string {
	if ev.Fields != nil {
		if v := strings.TrimSpace(ev.Fields["tenant"]); v != "" {
			return v
		}
	}
	return strings.TrimSpace(ev.Subject)
}

// scanCost returns the estimated cost for a scan gate.
func (m *Meter) scanCost(gate string) int64 {
	if c, ok := m.scanCosts[strings.ToLower(strings.TrimSpace(gate))]; ok {
		return c
	}
	return m.defaultCost
}

// budgetFor returns the effective budget for a tenant (explicit entry, else the
// "*" default, else the zero budget). Caller holds m.mu.
func (m *Meter) budgetFor(tenant string) Budget {
	if m.budgets == nil {
		return Budget{}
	}
	if b, ok := m.budgets[tenant]; ok {
		return b
	}
	if b, ok := m.budgets["*"]; ok {
		return b
	}
	return Budget{}
}

// fireBudget emits a one-shot budget-threshold alert for a tenant/dimension,
// deduplicated (via the fired set keyed by "tenant\x00dimension") so a tenant is
// alerted at most once per dimension per process.
func (m *Meter) fireBudget(tenant, dimension string, used, limit int64) {
	key := tenant + "\x00" + dimension
	m.mu.Lock()
	if _, done := m.fired[key]; done {
		m.mu.Unlock()
		return
	}
	m.fired[key] = dimension
	m.mu.Unlock()

	m.budgetAlerts.Add(1)
	if m.notifier != nil {
		m.notifier.Emit(context.Background(), notify.MeteringBudgetEvent(tenant, dimension, used, limit))
	}
}

// --- rollups ----------------------------------------------------------------

// Rollup snapshots the per-tenant delta since the previous rollup into the
// bounded history, advances the baseline, prunes expired history, and persists
// when a state path is configured. It is safe to call from a scheduler or
// directly from a test with an injected clock. A nil/disabled meter is a no-op.
func (m *Meter) Rollup(now time.Time) {
	if !m.Enabled() {
		return
	}
	now = now.UTC()
	m.mu.Lock()
	start := m.lastRoll
	if start.IsZero() || !start.Before(now) {
		start = now.Add(-m.rollupInterval)
	}
	for tenant, live := range m.live {
		delta := live.sub(m.baseline[tenant])
		if delta.IsZero() {
			continue
		}
		m.history = append(m.history, Rollup{Tenant: tenant, Start: start, End: now, Counters: delta})
		m.baseline[tenant] = live.clone()
	}
	m.lastRoll = now
	m.pruneLocked(now)
	m.rollupsTotal.Add(1)
	persist := m.statePath != ""
	var snap []Rollup
	if persist {
		snap = append([]Rollup(nil), m.history...)
	}
	m.mu.Unlock()

	if persist {
		_ = m.save(snap)
	}
}

// pruneLocked drops rollups whose period ended before the retention horizon and
// caps total retained rollups as a hard backstop. Caller holds m.mu.
func (m *Meter) pruneLocked(now time.Time) {
	horizon := now.Add(-time.Duration(m.retentionHours) * time.Hour)
	cut := 0
	for cut < len(m.history) && m.history[cut].End.Before(horizon) {
		cut++
	}
	if cut > 0 {
		m.history = append(m.history[:0], m.history[cut:]...)
	}
	// Hard backstop: never retain more than retentionHours * a generous per-hour
	// tenant fan-out, to bound memory if many tenants roll up every interval.
	const maxRollups = 200000
	if len(m.history) > maxRollups {
		m.history = append(m.history[:0], m.history[len(m.history)-maxRollups:]...)
	}
}

// pendingLocked returns the not-yet-rolled-up delta per tenant as synthetic
// rollups ending at now, so a report reflects current traffic without waiting
// for the next rollup tick. Caller holds m.mu.
func (m *Meter) pendingLocked(now time.Time) []Rollup {
	out := make([]Rollup, 0, len(m.live))
	for tenant, live := range m.live {
		delta := live.sub(m.baseline[tenant])
		if delta.IsZero() {
			continue
		}
		out = append(out, Rollup{Tenant: tenant, Start: m.lastRoll, End: now, Counters: delta})
	}
	return out
}

// Start launches the periodic rollup scheduler using the real interval. It is a
// no-op for a disabled meter or if already started. Stop terminates it.
func (m *Meter) Start() {
	if !m.Enabled() {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(m.rollupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				// Capture a final rollup so a clean shutdown does not lose the tail.
				m.Rollup(m.now())
				return
			case <-ticker.C:
				m.Rollup(m.now())
			}
		}
	}()
}

// Stop terminates the scheduler (flushing a final rollup). It is idempotent.
func (m *Meter) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stop) })
}

// --- helpers ----------------------------------------------------------------

func bumpCapped(m map[string]int64, key string, by int64) map[string]int64 {
	if m == nil {
		m = make(map[string]int64, 8)
	}
	if _, ok := m[key]; !ok && len(m) >= maxDistinctKeys {
		m["(other)"] += by
		return m
	}
	m[key] += by
	return m
}

func mergeMap(dst, src map[string]int64) map[string]int64 {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]int64, len(src))
	}
	for k, v := range src {
		dst[k] += v
	}
	return dst
}

func subMap(cur, base map[string]int64) map[string]int64 {
	if len(cur) == 0 {
		return nil
	}
	out := make(map[string]int64, len(cur))
	for k, v := range cur {
		d := v - base[k]
		if d != 0 {
			out[k] = d
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneMap(src map[string]int64) map[string]int64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]int64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func lowerKeys(src map[string]int64) map[string]int64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]int64, len(src))
	for k, v := range src {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

func sortedTenants(keys map[string]*Counters) []string {
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
