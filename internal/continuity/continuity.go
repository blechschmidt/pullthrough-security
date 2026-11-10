// Package continuity implements maintainer/publisher continuity monitoring
// (Task 91): a trust-on-first-use (TOFU) ownership-change admission gate.
//
// For each (ecosystem, name) coordinate the gate records the set of publisher
// principals observed the first time the package is pulled — the maintainer
// roster (npm maintainers, PyPI author/uploader, RubyGems owners), the publishing
// namespace (npm @scope, Maven groupId, Go module path, Composer vendor), and any
// signing-key identity surfaced by the signature-verification path. On every
// subsequent pull it re-derives the publisher principals from the per-ecosystem
// registry metadata and compares them against that durable "known maintainer set".
// When a previously-unseen maintainer, publishing key, or namespace owner appears
// for an already-known package it raises a `maintainer_drift` admission signal —
// the classic precursor to an account-takeover or hijack (event-stream,
// ua-parser-js, coa, rc). A configurable cooldown holds a newly-appeared
// maintainer "untrusted" for a window before it is folded into the known set, and
// a per-tenant disposition (observe / warn / block) governs whether the drift is
// merely recorded, surfaced to the client, or refused outright.
//
// The Service is self-contained (standard library only) so it can be shared by
// the gateway, the admin API, the metrics bridge, and tests. It derives publisher
// metadata through a pluggable PublisherResolver (resolver.go holds the live HTTP
// implementation) and fails OPEN when the publisher cannot be determined, trading
// a coverage gap for availability. A nil *Service is a valid no-op gate, so call
// sites need no nil check.
package continuity

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
// (ecosystem, name, version). The trusted maintainer set is keyed by
// (ecosystem, name); Version is carried for the verdict/audit context and to
// record which release first introduced a new maintainer.
type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

// Identity is the publisher metadata observed for a coordinate: the maintainer
// roster, any publishing/signing key identities, and the ownership namespace.
// Each field is optional; an Identity with no principals is "unknown".
type Identity struct {
	// Maintainers is the per-registry maintainer/owner/author roster (npm
	// maintainers, PyPI author + maintainer, RubyGems owners/authors, crates.io
	// owners).
	Maintainers []string
	// Keys are signing-key / signer identities (cosign certificate identity, GPG
	// key id) surfaced by the signature-verification path, reused here as a
	// continuity principal so a key rotation is itself an ownership-change signal.
	Keys []string
	// Namespace is the ownership namespace the artifact publishes under: an npm
	// @scope, a Maven groupId, a Go module path prefix, a Composer vendor. A change
	// of namespace owner is a dependency-confusion / hijack tell.
	Namespace string
}

// empty reports whether the identity carries no principals at all.
func (i Identity) empty() bool {
	return len(i.Maintainers) == 0 && len(i.Keys) == 0 && strings.TrimSpace(i.Namespace) == ""
}

// merge returns the union of two identities (used to fold a signature-derived key
// identity into the registry-derived maintainer roster).
func (i Identity) merge(o Identity) Identity {
	out := Identity{Namespace: i.Namespace}
	if out.Namespace == "" {
		out.Namespace = o.Namespace
	}
	out.Maintainers = append(append([]string(nil), i.Maintainers...), o.Maintainers...)
	out.Keys = append(append([]string(nil), i.Keys...), o.Keys...)
	return out
}

// principals renders the identity as the normalized, sorted, de-duplicated set of
// typed principal strings the TOFU comparison operates on. Maintainers are keyed
// "maintainer:<v>", keys "key:<v>", and the namespace "ns:<v>", all lower-cased so
// a cosmetic change in casing is not mistaken for an ownership change.
func (i Identity) principals() []string {
	set := make(map[string]struct{}, len(i.Maintainers)+len(i.Keys)+1)
	add := func(prefix, v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		set[prefix+":"+v] = struct{}{}
	}
	for _, m := range i.Maintainers {
		add("maintainer", m)
	}
	for _, k := range i.Keys {
		add("key", k)
	}
	add("ns", i.Namespace)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Disposition is the gate's action when maintainer drift is detected for a scope.
type Disposition string

const (
	// DispositionObserve records the drift signal (for policy/risk/findings and
	// the admin tab) but always admits the pull. It is the safe default.
	DispositionObserve Disposition = "observe"
	// DispositionWarn admits the pull but annotates the response and emits a
	// notification.
	DispositionWarn Disposition = "warn"
	// DispositionBlock refuses the pull while the new maintainer is within its
	// trust cooldown (subject to the break-glass override).
	DispositionBlock Disposition = "block"
)

// NormalizeDisposition coerces an arbitrary string to a known disposition,
// defaulting to observe.
func NormalizeDisposition(s string) Disposition {
	switch Disposition(strings.ToLower(strings.TrimSpace(s))) {
	case DispositionWarn:
		return DispositionWarn
	case DispositionBlock:
		return DispositionBlock
	default:
		return DispositionObserve
	}
}

// Decision is the outcome of Check. Only Block() is load-bearing for the pull
// path; the remaining fields explain the verdict for the response body, audit
// log, notification, admission signal, and admin view.
type Decision struct {
	// Drift reports that one or more previously-unseen maintainer/key/namespace
	// principals appeared for an already-known package.
	Drift bool
	// FirstUse reports that this was the first observation of the coordinate and
	// the trusted set was established (TOFU). Not a drift.
	FirstUse bool
	// Allowlisted reports that the coordinate bypassed the gate via the allowlist.
	Allowlisted bool
	// Unknown reports that no publisher metadata could be derived (admitted:
	// fail-open).
	Unknown bool
	// Disposition is the effective per-(tenant, ecosystem) disposition.
	Disposition Disposition
	// Added are the newly-appeared (untrusted) principals that drove the drift.
	Added []string
	// Removed are principals that were trusted but are no longer present
	// (informational; a maintainer departing is lower-signal than one appearing).
	Removed []string
	// TrustedCount is the size of the established trusted set after this check.
	TrustedCount int
	// PreviousVersion is the last version observed before this pull (the version
	// whose maintainer roster the new one is compared against).
	PreviousVersion string
	// Version is the version under evaluation.
	Version string
	// Cooldown is the trust-cooldown window that applied.
	Cooldown time.Duration
	// Remaining is the time until the newest added principal ages into the trusted
	// set (zero when no cooldown is configured).
	Remaining time.Duration
	// Reason is a human-readable explanation of the verdict.
	Reason string
}

// Block reports whether the pull must be refused: drift detected under a block
// disposition while the new maintainer is still within its trust cooldown.
func (d Decision) Block() bool { return d.Drift && d.Disposition == DispositionBlock }

// PublisherResolver derives the current publisher identity of a concrete package
// version from the per-ecosystem registry metadata. It returns ok=false (with a
// nil error) when the ecosystem is unsupported or the registry exposes no
// publisher metadata, and a non-nil error for a transient failure — both are
// treated as "unknown" by the gate, which fails open.
type PublisherResolver interface {
	Publishers(ctx context.Context, c Coordinate) (Identity, bool, error)
}

// TenantConfig overrides the disposition / cooldown model for a single tenant.
type TenantConfig struct {
	// Disposition overrides the global default disposition for this tenant. Nil
	// inherits.
	Disposition *Disposition
	// Ecosystems overrides the disposition for specific ecosystems for this tenant.
	Ecosystems map[string]Disposition
	// Cooldown overrides the global trust cooldown for this tenant. Nil inherits.
	Cooldown *time.Duration
	// Allowlist adds tenant-scoped trusted coordinates/scopes that bypass the gate.
	Allowlist []string
}

// Config configures the Service.
type Config struct {
	// DefaultDisposition is applied when no per-ecosystem / per-tenant override
	// matches. Empty defaults to observe.
	DefaultDisposition Disposition
	// Ecosystems overrides the disposition per canonical ecosystem.
	Ecosystems map[string]Disposition
	// Tenants holds per-tenant overrides keyed by tenant id (team).
	Tenants map[string]TenantConfig
	// Cooldown is the global trust-cooldown window: a newly-appeared maintainer is
	// held untrusted (drift active) for this long before it is folded into the
	// known set. Zero trusts a new maintainer immediately (drift is still signalled
	// once, on first observation).
	Cooldown time.Duration
	// Allowlist is the global set of trusted coordinates/scopes that bypass the
	// gate. See allowlisted for the supported pattern forms.
	Allowlist []string
	// Resolver derives publisher identities. When nil every publisher is unknown
	// (the gate becomes inert), so the wiring layer must supply one.
	Resolver PublisherResolver
	// StorePath is the JSON file backing the durable per-coordinate known-maintainer
	// set. Empty keeps state in memory only (lost on restart).
	StorePath string
	// Timeout bounds a single resolver call (default 10s).
	Timeout time.Duration
	// CacheTTL bounds how long a resolved publisher identity is cached (default 1h).
	CacheTTL time.Duration
	// NegativeCacheTTL bounds how long an unknown/failed resolution is cached before
	// retry (default 15m).
	NegativeCacheTTL time.Duration
	// CacheSize bounds the resolved-identity cache (default 4096 entries).
	CacheSize int
	// MaxRecords bounds the durable known-maintainer-set store (default 50000).
	MaxRecords int
	// MaxPending bounds the currently-drifting registry surfaced to the admin
	// (default 1024).
	MaxPending int
	// Now is an injectable clock for deterministic tests; defaults to time.Now.
	Now func() time.Time
	// Logger receives debug diagnostics; defaults to slog.Default.
	Logger *slog.Logger
}

const (
	defaultTimeout    = 10 * time.Second
	defaultCacheTTL   = time.Hour
	defaultNegTTL     = 15 * time.Minute
	defaultCacheSize  = 4096
	defaultMaxRecords = 50000
	defaultMaxPending = 1024
)

// record is the durable per-(ecosystem, name) known-maintainer set.
type record struct {
	Ecosystem   string               `json:"ecosystem"`
	Name        string               `json:"name"`
	Trusted     []string             `json:"trusted"`
	Pending     map[string]time.Time `json:"pending,omitempty"`
	FirstSeen   time.Time            `json:"firstSeen"`
	LastSeen    time.Time            `json:"lastSeen"`
	LastVersion string               `json:"lastVersion,omitempty"`
	DriftEvents int                  `json:"driftEvents"`
}

func (r *record) trustedSet() map[string]struct{} {
	m := make(map[string]struct{}, len(r.Trusted))
	for _, p := range r.Trusted {
		m[p] = struct{}{}
	}
	return m
}

// idEntry is one cached (or known-unknown) resolved publisher identity.
type idEntry struct {
	id    Identity
	found bool
	exp   time.Time
}

// ecoCounters holds per-ecosystem cumulative tallies surfaced as labeled metrics.
type ecoCounters struct {
	checks   uint64
	firstUse uint64
	drift    uint64
	blocked  uint64
	unknown  uint64
}

// Service is the maintainer/publisher continuity admission gate.
type Service struct {
	cfg   Config
	now   func() time.Time
	log   *slog.Logger
	store *store

	checks     atomic.Uint64
	firstUse   atomic.Uint64
	drifts     atomic.Uint64
	blocks     atomic.Uint64
	warns      atomic.Uint64
	unknown    atomic.Uint64
	allowlists atomic.Uint64

	mu      sync.Mutex
	records map[string]*record // (eco\x00name) -> known-maintainer set
	idCache map[string]idEntry // (eco\x00name\x00version) -> resolved identity
	idOrder []string           // FIFO of id-cache keys for bounded eviction
	byEco   map[string]*ecoCounters
}

// New constructs a Service from cfg, applying defaults for any unset bound and
// loading the durable known-maintainer set when a StorePath is configured. It
// returns an error only for a persistence failure on load.
func New(cfg Config) (*Service, error) {
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
	if cfg.MaxRecords <= 0 {
		cfg.MaxRecords = defaultMaxRecords
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = defaultMaxPending
	}
	if cfg.DefaultDisposition == "" {
		cfg.DefaultDisposition = DispositionObserve
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Service{
		cfg:     cfg,
		now:     cfg.Now,
		log:     cfg.Logger,
		store:   &store{path: cfg.StorePath},
		records: make(map[string]*record),
		idCache: make(map[string]idEntry),
		byEco:   make(map[string]*ecoCounters),
	}
	if err := s.store.load(s); err != nil {
		return nil, fmt.Errorf("continuity: loading store: %w", err)
	}
	return s, nil
}

// Enabled reports whether the gate is wired. The admin/metrics surfaces use it.
func (s *Service) Enabled() bool { return s != nil }

// Check derives the current publisher identity for a coordinate, compares it
// against the durable known-maintainer set, and returns the continuity decision.
// The optional extra identity is merged into the registry-derived one (used to
// fold a signature-verified signer key into the principal set). A nil *Service or
// an undeterminable publisher admits the pull.
func (s *Service) Check(ctx context.Context, tenant string, c Coordinate, extra Identity) Decision {
	if s == nil {
		return Decision{}
	}
	c.Ecosystem = normalizeEco(c.Ecosystem)
	disp := s.dispositionFor(tenant, c.Ecosystem)
	cooldown := s.cooldownFor(tenant)

	s.checks.Add(1)
	s.incEco(c.Ecosystem, func(e *ecoCounters) { e.checks++ })

	if c.Name == "" {
		return Decision{Disposition: disp}
	}

	if s.allowlisted(tenant, c) {
		s.allowlists.Add(1)
		return Decision{Allowlisted: true, Disposition: disp, Version: c.Version,
			Reason: "coordinate is on the continuity allowlist"}
	}

	observed := s.resolve(ctx, c).merge(extra)
	if observed.empty() {
		s.unknown.Add(1)
		s.incEco(c.Ecosystem, func(e *ecoCounters) { e.unknown++ })
		return Decision{Unknown: true, Disposition: disp, Version: c.Version,
			Reason: "publisher identity could not be determined (admitted: fail-open)"}
	}
	principals := observed.principals()

	now := s.now()
	key := recordKey(c.Ecosystem, c.Name)

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[key]
	if !ok {
		// Trust-on-first-use: establish the known-maintainer set.
		rec = &record{
			Ecosystem:   c.Ecosystem,
			Name:        c.Name,
			Trusted:     principals,
			FirstSeen:   now,
			LastSeen:    now,
			LastVersion: c.Version,
		}
		s.putRecordLocked(key, rec)
		s.firstUse.Add(1)
		s.incEco(c.Ecosystem, func(e *ecoCounters) { e.firstUse++ })
		s.persistLocked()
		return Decision{
			FirstUse:     true,
			Disposition:  disp,
			TrustedCount: len(principals),
			Version:      c.Version,
			Cooldown:     cooldown,
			Reason:       fmt.Sprintf("first observation: established %d trusted publisher principal(s)", len(principals)),
		}
	}

	prevVersion := rec.LastVersion

	// Promote pending principals whose cooldown has elapsed into the trusted set
	// before recomputing what is new, so an aged-in maintainer no longer drifts.
	s.promotePendingLocked(rec, now, cooldown)

	trusted := rec.trustedSet()
	observedSet := make(map[string]struct{}, len(principals))
	for _, p := range principals {
		observedSet[p] = struct{}{}
	}
	var added, removed []string
	for _, p := range principals {
		if _, ok := trusted[p]; !ok {
			added = append(added, p)
		}
	}
	for _, p := range rec.Trusted {
		if _, ok := observedSet[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	rec.LastSeen = now
	rec.LastVersion = c.Version

	if len(added) == 0 {
		// No new maintainer: the roster is unchanged (or only shrank). Admit.
		s.persistLocked()
		return Decision{
			Disposition:     disp,
			TrustedCount:    len(rec.Trusted),
			Removed:         removed,
			PreviousVersion: prevVersion,
			Version:         c.Version,
			Cooldown:        cooldown,
			Reason:          "publisher roster unchanged",
		}
	}

	// Maintainer drift: previously-unseen principals appeared.
	s.drifts.Add(1)
	s.incEco(c.Ecosystem, func(e *ecoCounters) { e.drift++ })
	rec.DriftEvents++

	var remaining time.Duration
	if cooldown <= 0 {
		// No cooldown configured: trust the new principals immediately, but still
		// signal the change once (this observation).
		for _, p := range added {
			rec.Trusted = appendUnique(rec.Trusted, p)
		}
		sort.Strings(rec.Trusted)
	} else {
		if rec.Pending == nil {
			rec.Pending = make(map[string]time.Time)
		}
		for _, p := range added {
			if _, ok := rec.Pending[p]; !ok {
				rec.Pending[p] = now
			}
			if rem := rec.Pending[p].Add(cooldown).Sub(now); rem > remaining {
				remaining = rem
			}
		}
		if remaining < 0 {
			remaining = 0
		}
	}

	disposition := disp
	switch disposition {
	case DispositionBlock:
		s.blocks.Add(1)
		s.incEco(c.Ecosystem, func(e *ecoCounters) { e.blocked++ })
	case DispositionWarn:
		s.warns.Add(1)
	}

	s.persistLocked()

	reason := fmt.Sprintf("%d new publisher principal(s) appeared for a previously-seen package (%s)",
		len(added), strings.Join(added, ", "))
	if cooldown > 0 && remaining > 0 {
		reason += fmt.Sprintf("; untrusted for %s", roundDur(remaining))
	}
	return Decision{
		Drift:           true,
		Disposition:     disposition,
		Added:           added,
		Removed:         removed,
		TrustedCount:    len(rec.Trusted),
		PreviousVersion: prevVersion,
		Version:         c.Version,
		Cooldown:        cooldown,
		Remaining:       remaining,
		Reason:          reason,
	}
}

// promotePendingLocked folds any pending principal whose cooldown has elapsed
// into the trusted set. Caller holds s.mu.
func (s *Service) promotePendingLocked(rec *record, now time.Time, cooldown time.Duration) {
	if len(rec.Pending) == 0 {
		return
	}
	for p, firstSeen := range rec.Pending {
		if cooldown <= 0 || !now.Before(firstSeen.Add(cooldown)) {
			rec.Trusted = appendUnique(rec.Trusted, p)
			delete(rec.Pending, p)
		}
	}
	sort.Strings(rec.Trusted)
	if len(rec.Pending) == 0 {
		rec.Pending = nil
	}
}

// putRecordLocked inserts a record, evicting the least-recently-seen record when
// the store is at capacity. Caller holds s.mu.
func (s *Service) putRecordLocked(key string, rec *record) {
	if _, exists := s.records[key]; !exists && len(s.records) >= s.cfg.MaxRecords {
		var oldestKey string
		var oldest time.Time
		for k, r := range s.records {
			if oldestKey == "" || r.LastSeen.Before(oldest) {
				oldestKey, oldest = k, r.LastSeen
			}
		}
		if oldestKey != "" {
			delete(s.records, oldestKey)
		}
	}
	s.records[key] = rec
}

// dispositionFor resolves the applicable disposition for (tenant, ecosystem) by
// specificity, mirroring the maturity gate's cooldown resolution: a tenant
// ecosystem-specific rule, then a global ecosystem-specific rule, then the tenant
// default, then the global default.
func (s *Service) dispositionFor(tenant, eco string) Disposition {
	if t, ok := s.cfg.Tenants[tenant]; ok {
		if t.Ecosystems != nil {
			if d, ok := t.Ecosystems[eco]; ok {
				return NormalizeDisposition(string(d))
			}
		}
		if d, ok := s.cfg.Ecosystems[eco]; ok {
			return NormalizeDisposition(string(d))
		}
		if t.Disposition != nil {
			return NormalizeDisposition(string(*t.Disposition))
		}
		return s.cfg.DefaultDisposition
	}
	if d, ok := s.cfg.Ecosystems[eco]; ok {
		return NormalizeDisposition(string(d))
	}
	return s.cfg.DefaultDisposition
}

// cooldownFor resolves the trust cooldown for a tenant (per-tenant override, else
// global).
func (s *Service) cooldownFor(tenant string) time.Duration {
	if t, ok := s.cfg.Tenants[tenant]; ok && t.Cooldown != nil {
		return *t.Cooldown
	}
	return s.cfg.Cooldown
}

// allowlisted reports whether the coordinate matches any global or tenant
// allowlist entry. Supported forms mirror the maturity gate: "name", "eco:name",
// "@scope/" (npm scope prefix), "prefix*" (name glob), each optionally
// "eco:"-scoped.
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

func matchAllow(pat string, c Coordinate) bool {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return false
	}
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
		return strings.HasPrefix(name, p)
	case strings.HasSuffix(p, "*"):
		return strings.HasPrefix(name, strings.TrimSuffix(p, "*"))
	default:
		return name == p
	}
}

// resolve returns the cached or freshly-resolved publisher identity for a
// coordinate. Both successful and unknown resolutions are cached (the latter for
// the shorter NegativeCacheTTL) to bound load on the upstream registries.
func (s *Service) resolve(ctx context.Context, c Coordinate) Identity {
	key := cacheKey(c)
	now := s.now()

	s.mu.Lock()
	if e, ok := s.idCache[key]; ok && now.Before(e.exp) {
		s.mu.Unlock()
		return e.id
	}
	s.mu.Unlock()

	if s.cfg.Resolver == nil {
		return Identity{}
	}

	rctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	id, found, err := s.cfg.Resolver.Publishers(rctx, c)
	if err != nil {
		s.log.Debug("continuity: publisher resolution failed",
			"ecosystem", c.Ecosystem, "name", c.Name, "version", c.Version, "error", err)
		found = false
		id = Identity{}
	}
	if id.empty() {
		found = false
	}
	ttl := s.cfg.CacheTTL
	if !found {
		ttl = s.cfg.NegativeCacheTTL
	}
	s.storeID(key, idEntry{id: id, found: found, exp: now.Add(ttl)})
	return id
}

func (s *Service) storeID(key string, e idEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.idCache[key]; !exists {
		if len(s.idCache) >= s.cfg.CacheSize && len(s.idOrder) > 0 {
			oldest := s.idOrder[0]
			s.idOrder = s.idOrder[1:]
			delete(s.idCache, oldest)
		}
		s.idOrder = append(s.idOrder, key)
	}
	s.idCache[key] = e
}

func (s *Service) incEco(eco string, f func(*ecoCounters)) {
	e := s.byEco[eco]
	if e == nil {
		e = &ecoCounters{}
		s.byEco[eco] = e
	}
	f(e)
}

func recordKey(eco, name string) string { return eco + "\x00" + strings.ToLower(name) }
func cacheKey(c Coordinate) string {
	return c.Ecosystem + "\x00" + strings.ToLower(c.Name) + "\x00" + c.Version
}

func normalizeEco(eco string) string { return strings.ToLower(strings.TrimSpace(eco)) }

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func roundDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d >= 24*time.Hour:
		return d.Round(time.Hour).String()
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	default:
		return d.Round(time.Second).String()
	}
}
