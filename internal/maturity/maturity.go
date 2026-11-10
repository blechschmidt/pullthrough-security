// Package maturity implements the release-maturity / version-cooldown admission
// gate (Task 61). It quarantines newly-published package versions until they age
// past a configurable cooldown window — a well-known control against fast-moving
// supply-chain attacks where a malicious version is published and then yanked
// within hours, before defenders (or the upstream registry) can react.
//
// The gate derives a version's publish timestamp from the per-ecosystem registry
// metadata via a pluggable TimestampResolver (see resolver.go for the live HTTP
// implementation), caches the result in a bounded TTL cache, and blocks the pull
// while age < cooldown. It fails OPEN when the publish timestamp cannot be
// determined (the default), trading a small coverage gap for availability; set
// FailClosedOnUnknown to invert that trade.
//
// Cooldown durations are resolved per (tenant, ecosystem) with a global default,
// an allowlist of trusted packages/scopes bypasses the gate entirely, and the
// wiring layer composes a still-cooling block with the human-in-the-loop
// break-glass approval workflow so an operator can release a version early.
//
// The Service is self-contained (standard library only) so it can be shared by
// the gateway, the admin API, the metrics bridge, and tests. A nil *Service is a
// valid no-op gate, so call sites need no nil check.
package maturity

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Coordinate is the per-pull input the gate evaluates: a concrete
// (ecosystem, name, version). Version is empty for index/listing requests, which
// have no single artifact to age and are always admitted.
type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

// Decision is the outcome of Check. Only Cooling is load-bearing for the pull
// path (true ⇒ refuse the pull); the remaining fields explain the verdict for
// the response body, audit log, notification, and admin view.
type Decision struct {
	// Cooling reports that the version is still within its cooldown window (or,
	// under FailClosedOnUnknown, that its publish timestamp is unknown) and the
	// pull must be refused.
	Cooling bool
	// Allowlisted reports that the coordinate matched a trusted allowlist entry
	// and bypassed the cooldown entirely.
	Allowlisted bool
	// Unknown reports that the publish timestamp could not be determined.
	Unknown bool
	// PublishedAt is the derived publish timestamp (zero when Unknown).
	PublishedAt time.Time
	// Age is now-PublishedAt (zero when Unknown).
	Age time.Duration
	// Cooldown is the cooldown window that applied to this (tenant, ecosystem).
	Cooldown time.Duration
	// Remaining is the time until the version ages past the cooldown (only
	// meaningful when Cooling and not Unknown).
	Remaining time.Duration
	// Reason is a human-readable explanation of the verdict.
	Reason string
}

// AvailableAt returns the wall-clock instant at which a cooling version will age
// past its cooldown window. It is the zero time when the publish timestamp is
// unknown.
func (d Decision) AvailableAt() time.Time {
	if d.PublishedAt.IsZero() {
		return time.Time{}
	}
	return d.PublishedAt.Add(d.Cooldown)
}

// TimestampResolver derives the publish timestamp of a concrete package version
// from the per-ecosystem registry metadata. It returns ok=false (with a nil
// error) when the ecosystem is unsupported or the registry exposes no timestamp,
// and a non-nil error for a transient failure (network/parse) — both are treated
// as "unknown" by the gate, which then fails open (or closed per policy).
type TimestampResolver interface {
	PublishedAt(ctx context.Context, c Coordinate) (time.Time, bool, error)
}

// TenantConfig overrides the cooldown model for a single tenant. A nil
// DefaultCooldown / absent ecosystem entry inherits the global default.
type TenantConfig struct {
	// DefaultCooldown overrides the global default for this tenant. Nil inherits.
	DefaultCooldown *time.Duration
	// Ecosystems overrides the cooldown for specific ecosystems for this tenant.
	// An entry with a zero value explicitly disables the cooldown for that
	// ecosystem.
	Ecosystems map[string]time.Duration
	// Allowlist adds tenant-scoped trusted coordinates/scopes that bypass the
	// cooldown in addition to the global allowlist.
	Allowlist []string
}

// Config configures the Service.
type Config struct {
	// DefaultCooldown is applied when no per-ecosystem / per-tenant override
	// matches. Zero (or negative) disables the gate globally.
	DefaultCooldown time.Duration
	// Ecosystems overrides the cooldown per canonical ecosystem (npm/pip/cargo/
	// go/nuget/maven/rubygems/composer/...). An entry with a zero value explicitly
	// disables the cooldown for that ecosystem.
	Ecosystems map[string]time.Duration
	// Tenants holds per-tenant overrides keyed by tenant id (team).
	Tenants map[string]TenantConfig
	// Allowlist is the global set of trusted package coordinates/scopes that
	// bypass the cooldown. See allowlisted for the supported pattern forms.
	Allowlist []string
	// FailClosedOnUnknown blocks a pull whose publish timestamp cannot be
	// determined. The default (false) fails open: an unknown timestamp admits the
	// pull rather than penalize a package the resolver can't date.
	FailClosedOnUnknown bool
	// Resolver derives publish timestamps. When nil every timestamp is unknown
	// (so the gate either admits everything, or — under FailClosedOnUnknown —
	// blocks every dated coordinate), which makes the gate inert without a
	// resolver wired.
	Resolver TimestampResolver
	// Timeout bounds a single resolver call (default 10s).
	Timeout time.Duration
	// CacheTTL bounds how long a successfully-resolved (immutable) publish
	// timestamp is cached (default 6h).
	CacheTTL time.Duration
	// NegativeCacheTTL bounds how long an unknown/failed resolution is cached
	// before it is retried (default 15m).
	NegativeCacheTTL time.Duration
	// CacheSize bounds the resolved-timestamp cache (default 4096 entries).
	CacheSize int
	// MaxCooling bounds the currently-cooling registry surfaced to the admin
	// (default 1024).
	MaxCooling int
	// Now is an injectable clock for deterministic tests; defaults to time.Now.
	Now func() time.Time
	// Logger receives debug diagnostics; defaults to slog.Default.
	Logger *slog.Logger
}

const (
	defaultTimeout    = 10 * time.Second
	defaultCacheTTL   = 6 * time.Hour
	defaultNegTTL     = 15 * time.Minute
	defaultCacheSize  = 4096
	defaultMaxCooling = 1024
)

// tsEntry is one resolved (or known-unknown) publish timestamp, with an
// expiry after which it is re-resolved.
type tsEntry struct {
	ts    time.Time
	found bool
	exp   time.Time
}

// coolingEntry records a version currently held in the cooldown window so the
// admin tab can list cooling coordinates with their time remaining. Remaining is
// computed live from publishedAt+cooldown so a single record stays accurate.
type coolingEntry struct {
	tenant      string
	coord       Coordinate
	publishedAt time.Time
	cooldown    time.Duration
	firstSeen   time.Time
}

// ecoCounters holds the per-ecosystem cumulative tallies surfaced as labeled
// Prometheus metrics.
type ecoCounters struct {
	checks      uint64
	blocked     uint64
	allowlisted uint64
	unknown     uint64
}

// Service is the release-cooldown admission gate.
type Service struct {
	cfg Config
	now func() time.Time
	log *slog.Logger

	checks  atomic.Uint64
	blocks  atomic.Uint64
	allowed atomic.Uint64
	unknown atomic.Uint64

	mu      sync.Mutex
	cache   map[string]tsEntry
	order   []string // FIFO of cache keys for bounded eviction
	cooling map[string]coolingEntry
	byEco   map[string]*ecoCounters
}

// NewService constructs a Service from cfg, applying defaults for any unset
// bound. It never returns an error; an absent resolver simply makes the gate
// inert (every timestamp unknown).
func NewService(cfg Config) *Service {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultCacheTTL
	}
	if cfg.NegativeCacheTTL <= 0 {
		cfg.NegativeCacheTTL = defaultNegTTL
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = defaultCacheSize
	}
	if cfg.MaxCooling <= 0 {
		cfg.MaxCooling = defaultMaxCooling
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg:     cfg,
		now:     now,
		log:     log,
		cache:   make(map[string]tsEntry),
		cooling: make(map[string]coolingEntry),
		byEco:   make(map[string]*ecoCounters),
	}
}

// Enabled reports whether the gate is wired. The admin/metrics surfaces use it.
func (s *Service) Enabled() bool { return s != nil }

// Check evaluates a coordinate for the given tenant and returns the cooldown
// decision. A nil *Service, an empty/disabled cooldown for the scope, a
// version-less (listing) request, or an allowlisted coordinate all admit the
// pull. The call is cheap when the timestamp is cached and otherwise bounded by
// the resolver timeout.
func (s *Service) Check(tenant string, c Coordinate) Decision {
	if s == nil {
		return Decision{}
	}
	c.Ecosystem = normalizeEco(c.Ecosystem)
	cooldown := s.cooldownFor(tenant, c.Ecosystem)

	s.checks.Add(1)
	s.incEco(c.Ecosystem, func(e *ecoCounters) { e.checks++ })

	if cooldown <= 0 || c.Name == "" || c.Version == "" {
		// Gate disabled for this scope, or no concrete version to age.
		return Decision{Cooldown: cooldown}
	}

	if s.allowlisted(tenant, c) {
		s.allowed.Add(1)
		s.incEco(c.Ecosystem, func(e *ecoCounters) { e.allowlisted++ })
		return Decision{Allowlisted: true, Cooldown: cooldown, Reason: "coordinate is on the maturity allowlist"}
	}

	ts, ok := s.publishedAt(c)
	if !ok {
		s.unknown.Add(1)
		s.incEco(c.Ecosystem, func(e *ecoCounters) { e.unknown++ })
		if s.cfg.FailClosedOnUnknown {
			s.blocks.Add(1)
			s.incEco(c.Ecosystem, func(e *ecoCounters) { e.blocked++ })
			return Decision{
				Cooling:  true,
				Unknown:  true,
				Cooldown: cooldown,
				Reason:   "publish timestamp could not be determined and the maturity gate is fail-closed",
			}
		}
		return Decision{Unknown: true, Cooldown: cooldown, Reason: "publish timestamp unknown (admitted: fail-open)"}
	}

	now := s.now()
	age := now.Sub(ts)
	if age < 0 {
		// Clock skew or a future-dated timestamp: treat as freshly published
		// rather than instantly mature (the safer reading).
		age = 0
	}
	if age >= cooldown {
		s.clearCooling(tenant, c)
		return Decision{PublishedAt: ts, Age: age, Cooldown: cooldown,
			Reason: fmt.Sprintf("published %s ago, past the %s cooldown", roundDur(age), roundDur(cooldown))}
	}

	remaining := cooldown - age
	s.blocks.Add(1)
	s.incEco(c.Ecosystem, func(e *ecoCounters) { e.blocked++ })
	s.recordCooling(tenant, c, ts, cooldown, now)
	return Decision{
		Cooling:     true,
		PublishedAt: ts,
		Age:         age,
		Cooldown:    cooldown,
		Remaining:   remaining,
		Reason: fmt.Sprintf("version published %s ago is within the %s release-cooldown window (%s remaining)",
			roundDur(age), roundDur(cooldown), roundDur(remaining)),
	}
}

// cooldownFor resolves the applicable cooldown for (tenant, ecosystem) by
// specificity, then scope: a tenant ecosystem-specific rule, then a global
// ecosystem-specific rule, then the tenant default, then the global default. A
// present ecosystem entry with a zero value explicitly disables the cooldown.
func (s *Service) cooldownFor(tenant, eco string) time.Duration {
	if t, ok := s.cfg.Tenants[tenant]; ok {
		if t.Ecosystems != nil {
			if d, ok := t.Ecosystems[eco]; ok {
				return d
			}
		}
		if d, ok := s.cfg.Ecosystems[eco]; ok {
			return d
		}
		if t.DefaultCooldown != nil {
			return *t.DefaultCooldown
		}
		return s.cfg.DefaultCooldown
	}
	if d, ok := s.cfg.Ecosystems[eco]; ok {
		return d
	}
	return s.cfg.DefaultCooldown
}

// allowlisted reports whether the coordinate matches any global or tenant
// allowlist entry. Supported entry forms (case-insensitive on the package name):
//
//	name                 exact package name, any ecosystem
//	eco:name             exact name within an ecosystem
//	@scope/              npm scope prefix (trailing slash) — matches @scope/*
//	prefix*              glob prefix on the package name
//	eco:@scope/  / eco:prefix*   the above, scoped to an ecosystem
func (s *Service) allowlisted(tenant string, c Coordinate) bool {
	for _, pat := range s.cfg.Allowlist {
		if matchAllow(pat, c) {
			return true
		}
	}
	if t, ok := s.cfg.Tenants[tenant]; ok {
		for _, pat := range t.Allowlist {
			if matchAllow(pat, c) {
				return true
			}
		}
	}
	return false
}

// matchAllow reports whether a single allowlist pattern matches a coordinate.
func matchAllow(pat string, c Coordinate) bool {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return false
	}
	// Optional "eco:" scoping prefix. Distinguish from an npm "@scope" by only
	// treating a colon before any '/' or '@' as an ecosystem separator.
	if i := strings.IndexByte(pat, ':'); i > 0 {
		head := pat[:i]
		if !strings.ContainsAny(head, "/@*") {
			if normalizeEco(head) != c.Ecosystem {
				return false
			}
			pat = pat[i+1:]
		}
	}
	name := strings.ToLower(c.Name)
	p := strings.ToLower(strings.TrimSpace(pat))
	switch {
	case p == "":
		return false
	case strings.HasSuffix(p, "/"):
		// Scope prefix, e.g. "@acme/" matches "@acme/widget".
		return strings.HasPrefix(name, p)
	case strings.HasSuffix(p, "*"):
		return strings.HasPrefix(name, strings.TrimSuffix(p, "*"))
	default:
		return name == p
	}
}

// publishedAt returns the cached or freshly-resolved publish timestamp for a
// coordinate. Both successful and unknown/failed resolutions are cached (the
// latter for the shorter NegativeCacheTTL) to bound load on the upstream
// registries. Resolution errors are logged at debug and reported as unknown.
func (s *Service) publishedAt(c Coordinate) (time.Time, bool) {
	key := cacheKey(c)
	now := s.now()

	s.mu.Lock()
	if e, ok := s.cache[key]; ok && now.Before(e.exp) {
		s.mu.Unlock()
		return e.ts, e.found
	}
	s.mu.Unlock()

	if s.cfg.Resolver == nil {
		return time.Time{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	ts, found, err := s.cfg.Resolver.PublishedAt(ctx, c)
	if err != nil {
		s.log.Debug("maturity: publish-timestamp resolution failed",
			"ecosystem", c.Ecosystem, "name", c.Name, "version", c.Version, "error", err)
		found = false
		ts = time.Time{}
	}

	ttl := s.cfg.CacheTTL
	if !found {
		ttl = s.cfg.NegativeCacheTTL
	}
	s.storeTS(key, tsEntry{ts: ts, found: found, exp: now.Add(ttl)})
	return ts, found
}

// storeTS inserts a resolved-timestamp entry, evicting the oldest entry (FIFO)
// when the cache is at capacity.
func (s *Service) storeTS(key string, e tsEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[key]; !exists {
		if len(s.cache) >= s.cfg.CacheSize && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.cache, oldest)
		}
		s.order = append(s.order, key)
	}
	s.cache[key] = e
}

// recordCooling registers (or refreshes) a currently-cooling coordinate for the
// admin view, pruning matured entries and bounding the registry size.
func (s *Service) recordCooling(tenant string, c Coordinate, publishedAt time.Time, cooldown time.Duration, now time.Time) {
	key := coolingKey(tenant, c)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prune matured entries opportunistically.
	for k, e := range s.cooling {
		if !now.Before(e.publishedAt.Add(e.cooldown)) {
			delete(s.cooling, k)
		}
	}
	if existing, ok := s.cooling[key]; ok {
		existing.publishedAt = publishedAt
		existing.cooldown = cooldown
		s.cooling[key] = existing
		return
	}
	if len(s.cooling) >= s.cfg.MaxCooling {
		// Drop the entry that will mature soonest to make room; it is the least
		// useful to keep surfacing.
		var soonestKey string
		var soonest time.Time
		for k, e := range s.cooling {
			avail := e.publishedAt.Add(e.cooldown)
			if soonestKey == "" || avail.Before(soonest) {
				soonestKey, soonest = k, avail
			}
		}
		if soonestKey != "" {
			delete(s.cooling, soonestKey)
		}
	}
	s.cooling[key] = coolingEntry{
		tenant:      tenant,
		coord:       c,
		publishedAt: publishedAt,
		cooldown:    cooldown,
		firstSeen:   now,
	}
}

// clearCooling removes a coordinate from the cooling registry once it matures.
func (s *Service) clearCooling(tenant string, c Coordinate) {
	key := coolingKey(tenant, c)
	s.mu.Lock()
	delete(s.cooling, key)
	s.mu.Unlock()
}

// incEco applies a mutation to the per-ecosystem counters under the lock.
func (s *Service) incEco(eco string, f func(*ecoCounters)) {
	s.mu.Lock()
	e := s.byEco[eco]
	if e == nil {
		e = &ecoCounters{}
		s.byEco[eco] = e
	}
	f(e)
	s.mu.Unlock()
}

func cacheKey(c Coordinate) string {
	return c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version
}

func coolingKey(tenant string, c Coordinate) string {
	return tenant + "\x00" + c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version
}

// normalizeEco lower-cases and trims an ecosystem label so config keys and
// coordinate ecosystems compare consistently.
func normalizeEco(eco string) string {
	return strings.ToLower(strings.TrimSpace(eco))
}

// roundDur renders a duration at a human-friendly granularity for messages.
func roundDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d >= 24*time.Hour:
		return d.Round(time.Hour).String()
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Minute:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Second).String()
	}
}

// sortCooling orders cooling entries by ascending time-remaining (soonest to
// mature first) for a stable admin presentation.
func sortCooling(entries []CoolingView) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].RemainingSeconds != entries[j].RemainingSeconds {
			return entries[i].RemainingSeconds < entries[j].RemainingSeconds
		}
		if entries[i].Ecosystem != entries[j].Ecosystem {
			return entries[i].Ecosystem < entries[j].Ecosystem
		}
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Version < entries[j].Version
	})
}
