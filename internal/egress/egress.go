// Package egress implements a defense-in-depth SSRF / outbound-egress guard for
// every HTTP fetch the proxy makes to an upstream registry. It hardens the
// proxy against being abused as a confused-deputy / SSRF pivot: even though the
// configured upstreams are trusted, a malicious index document, a redirect, or
// a DNS-rebinding attack could otherwise steer an outbound fetch at an internal
// service (cloud metadata endpoints, RFC1918 hosts, loopback admin panels).
//
// The guard enforces, fail-closed:
//
//   - a scheme allowlist (https-only by default);
//   - an optional per-instance and per-tenant host/domain/CIDR allowlist of
//     permitted upstream destinations;
//   - denial of any request that *resolves* to a private, link-local, loopback,
//     unique-local, carrier-grade-NAT, or cloud-metadata IP range — re-validated
//     immediately before connect (via the dialer control hook) so DNS-rebinding
//     between the policy check and the TCP connect cannot defeat it;
//   - a redirect-following policy that re-checks every hop (each redirect is a
//     fresh RoundTrip, and the destination IP is re-validated on each dial) under
//     a hard max-redirect cap.
//
// It is wired as a transport-level RoundTripper plus a dialer ControlContext hook
// installed on the shared upstream client (internal/upstream) — the same seam the
// health-aware mirror pool (internal/upstreampool) wraps — so the control covers
// every HTTP backend (pip, npm, cargo, go, nuget, maven, docker/OCI, …)
// uniformly without each backend re-implementing it.
//
// A blocked fetch surfaces a *BlockedError (detectable via errors.As), increments
// a per-reason metric, and emits an EventEgressBlocked notification plus an audit
// record so the attempt is alertable and forensically recoverable.
//
// A nil *Guard is a valid, fully-permissive no-op, so callers need no nil checks.
package egress

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// DefaultMaxRedirects bounds the redirect chain when following is enabled and no
// explicit cap is configured.
const DefaultMaxRedirects = 5

// Reason is a stable, machine-readable code for why a fetch was blocked. The
// values double as metric label values and audit/notify field values, so they
// are lowercase, finite, and never change.
type Reason string

const (
	ReasonSchemeNotAllowed Reason = "scheme_not_allowed"
	ReasonHostNotAllowed   Reason = "host_not_allowlisted"
	ReasonInvalidURL       Reason = "invalid_url"
	ReasonPrivateNetwork   Reason = "private_network"
	ReasonLoopback         Reason = "loopback"
	ReasonLinkLocal        Reason = "link_local"
	ReasonMetadata         Reason = "metadata"
	ReasonUniqueLocal      Reason = "unique_local"
	ReasonCGNAT            Reason = "cgnat"
	ReasonUnspecified      Reason = "unspecified"
	ReasonMulticast        Reason = "multicast"
	ReasonResolveError     Reason = "resolve_error"
	ReasonTooManyRedirects Reason = "too_many_redirects"
)

// allReasons is the canonical, ordered set used to pre-seed the per-reason
// counter map so a reason that has not yet fired still reports a zero series.
var allReasons = []Reason{
	ReasonSchemeNotAllowed, ReasonHostNotAllowed, ReasonInvalidURL,
	ReasonPrivateNetwork, ReasonLoopback, ReasonLinkLocal, ReasonMetadata,
	ReasonUniqueLocal, ReasonCGNAT, ReasonUnspecified, ReasonMulticast,
	ReasonResolveError, ReasonTooManyRedirects,
}

// BlockedError is returned when the egress guard refuses a fetch. It is the
// sentinel a caller can detect with errors.As to distinguish a policy block from
// a transport failure.
type BlockedError struct {
	// Reason is the machine-readable cause.
	Reason Reason
	// Host is the destination hostname or IP literal that was refused.
	Host string
	// Detail is a human-readable explanation.
	Detail string
}

func (e *BlockedError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("egress blocked (%s): %s: %s", e.Reason, e.Host, e.Detail)
	}
	return fmt.Sprintf("egress blocked (%s): %s", e.Reason, e.Detail)
}

// AuditLogger is the narrow audit surface the guard records blocked egress to.
// *audit.Logger satisfies it; a nil value disables audit recording.
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// TenantConfig overrides the egress policy for a single tenant. The host
// allowlist is additive to the global allowlist; the IP-range floor is always
// instance-global and cannot be loosened per tenant (a tenant must never be able
// to punch a hole through to the metadata service).
type TenantConfig struct {
	// Allowlist adds permitted host/domain/CIDR entries for this tenant on top of
	// the global allowlist.
	Allowlist []string
	// HTTPSOnly, when non-nil, overrides the global scheme policy for this tenant.
	HTTPSOnly *bool
}

// Config is the decoupled, self-contained egress policy. The wiring layer
// translates the YAML config (config.EgressConfig) into this so the egress
// package takes no dependency on the config package.
type Config struct {
	// Enabled activates the guard. When false, New returns a nil-equivalent
	// permissive guard.
	Enabled bool
	// HTTPSOnly restricts outbound requests to the https scheme. Ignored when
	// AllowedSchemes is non-empty.
	HTTPSOnly bool
	// AllowedSchemes is an explicit scheme allowlist (e.g. ["https","http"]). When
	// empty, the policy is https-only if HTTPSOnly, otherwise https+http.
	AllowedSchemes []string
	// Allowlist is the global host/domain/CIDR allowlist. An empty allowlist means
	// "do not enforce a host allowlist" — the scheme and IP-range floors still
	// apply, so the secure default (no allowlist) already blocks SSRF-to-internal
	// while permitting any public https host. A non-empty allowlist switches the
	// guard to deny-by-default for hosts.
	Allowlist []string
	// BlockPrivateNetworks denies any request resolving to a private, link-local,
	// loopback, unique-local, CGNAT, unspecified, multicast, or metadata IP.
	BlockPrivateNetworks bool
	// AllowedDestinationCIDRs are explicit exceptions to BlockPrivateNetworks — an
	// operator that fronts an internal mirror at, say, 10.0.0.0/8 lists it here so
	// that range alone is reachable while every other private range stays blocked.
	AllowedDestinationCIDRs []string
	// FollowRedirects permits following upstream redirects (each hop re-checked).
	// When false, a redirect response is returned to the caller unfollowed.
	FollowRedirects bool
	// MaxRedirects caps the redirect chain. Zero uses DefaultMaxRedirects.
	MaxRedirects int
	// TenantOverrides maps a tenant (auth team) to its policy override.
	TenantOverrides map[string]TenantConfig
}

// recentLimit bounds the in-memory ring of recent blocks surfaced to the admin
// API.
const recentLimit = 100

// Block records a single blocked egress attempt for the admin surface.
type Block struct {
	Time   time.Time `json:"time"`
	Reason Reason    `json:"reason"`
	Tenant string    `json:"tenant,omitempty"`
	Host   string    `json:"host,omitempty"`
	URL    string    `json:"url,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Guard enforces the egress policy. It is safe for concurrent use; the host
// allowlist can be mutated at runtime (admin API) under its lock.
type Guard struct {
	enabled         bool
	httpsOnly       bool
	allowedSchemes  map[string]bool
	blockPrivate    bool
	followRedirects bool
	maxRedirects    int

	mu         sync.RWMutex
	global     *ruleSet
	tenants    map[string]*tenantRules
	exceptions []*net.IPNet // AllowedDestinationCIDRs

	// Dependencies (all optional).
	tenantFromCtx func(context.Context) string
	notifier      notify.Emitter
	auditLog      AuditLogger
	logger        *slog.Logger
	clock         func() time.Time

	// Counters and recent-block ring.
	statsMu  sync.Mutex
	checked  uint64
	allowed  uint64
	blocked  uint64
	byReason map[Reason]uint64
	recent   []Block
}

type tenantRules struct {
	rules     *ruleSet
	httpsOnly *bool
}

// Options carries the guard's optional dependencies, kept separate from the
// policy Config so the wiring layer can supply them independently.
type Options struct {
	// TenantFromContext resolves the calling tenant from a request context so
	// per-tenant allowlists apply. When nil, only the global policy is used.
	TenantFromContext func(context.Context) string
	// Notifier receives an EventEgressBlocked for each block. Optional.
	Notifier notify.Emitter
	// Audit records blocked egress as a deny decision. Optional.
	Audit AuditLogger
	// Logger receives structured warnings. Defaults to slog.Default().
	Logger *slog.Logger
	// Clock is the time source (overridable in tests). Defaults to time.Now.
	Clock func() time.Time
}

// New builds a Guard from cfg and opts. It returns an error if the allowlist or
// exception CIDRs are malformed. When cfg.Enabled is false it returns a nil
// *Guard, which is a valid permissive no-op.
func New(cfg Config, opts Options) (*Guard, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	global, err := compileRuleSet(cfg.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("egress: allowlist: %w", err)
	}

	exceptions, err := compileCIDRs(cfg.AllowedDestinationCIDRs)
	if err != nil {
		return nil, fmt.Errorf("egress: allowedDestinationCidrs: %w", err)
	}

	tenants := make(map[string]*tenantRules, len(cfg.TenantOverrides))
	for tenant, tc := range cfg.TenantOverrides {
		rs, terr := compileRuleSet(tc.Allowlist)
		if terr != nil {
			return nil, fmt.Errorf("egress: tenant %q allowlist: %w", tenant, terr)
		}
		tenants[tenant] = &tenantRules{rules: rs, httpsOnly: tc.HTTPSOnly}
	}

	schemes := map[string]bool{}
	for _, s := range cfg.AllowedSchemes {
		schemes[normalizeScheme(s)] = true
	}

	maxRedirects := cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	byReason := make(map[Reason]uint64, len(allReasons))
	for _, r := range allReasons {
		byReason[r] = 0
	}

	return &Guard{
		enabled:         true,
		httpsOnly:       cfg.HTTPSOnly,
		allowedSchemes:  schemes,
		blockPrivate:    cfg.BlockPrivateNetworks,
		followRedirects: cfg.FollowRedirects,
		maxRedirects:    maxRedirects,
		global:          global,
		tenants:         tenants,
		exceptions:      exceptions,
		tenantFromCtx:   opts.TenantFromContext,
		notifier:        opts.Notifier,
		auditLog:        opts.Audit,
		logger:          logger,
		clock:           clock,
		byReason:        byReason,
		recent:          make([]Block, 0, recentLimit),
	}, nil
}

// Enabled reports whether the guard actively enforces policy. A nil guard is not
// enabled (fully permissive).
func (g *Guard) Enabled() bool { return g != nil && g.enabled }

// SetAuditLogger attaches an audit sink after construction. The guard is built
// before the audit log exists (so its transport hooks can be wired into the
// client pool at startup), so the wiring layer attaches the logger once it is
// available. It must be called during single-threaded startup, before the guard
// serves any request. A nil guard is a no-op.
func (g *Guard) SetAuditLogger(l AuditLogger) {
	if g == nil {
		return
	}
	g.auditLog = l
}

// schemeAllowed reports whether scheme passes the (possibly tenant-overridden)
// scheme policy.
func (g *Guard) schemeAllowed(scheme string, tenantHTTPSOnly *bool) bool {
	scheme = normalizeScheme(scheme)
	if len(g.allowedSchemes) > 0 {
		return g.allowedSchemes[scheme]
	}
	httpsOnly := g.httpsOnly
	if tenantHTTPSOnly != nil {
		httpsOnly = *tenantHTTPSOnly
	}
	if httpsOnly {
		return scheme == "https"
	}
	return scheme == "https" || scheme == "http"
}

// tenantFor resolves the tenant string for ctx (empty when unresolved).
func (g *Guard) tenantFor(ctx context.Context) string {
	if g.tenantFromCtx == nil || ctx == nil {
		return ""
	}
	return g.tenantFromCtx(ctx)
}

// recordBlock increments counters, appends to the recent ring, emits a
// notification, and writes an audit record for a blocked attempt.
func (g *Guard) recordBlock(ctx context.Context, tenant string, b *BlockedError, rawURL string) {
	g.statsMu.Lock()
	g.checked++
	g.blocked++
	g.byReason[b.Reason]++
	blk := Block{
		Time:   g.clock().UTC(),
		Reason: b.Reason,
		Tenant: tenant,
		Host:   b.Host,
		URL:    rawURL,
		Detail: b.Detail,
	}
	if len(g.recent) >= recentLimit {
		copy(g.recent, g.recent[1:])
		g.recent[len(g.recent)-1] = blk
	} else {
		g.recent = append(g.recent, blk)
	}
	g.statsMu.Unlock()

	if g.logger != nil {
		g.logger.Warn("egress blocked",
			"reason", string(b.Reason), "host", b.Host, "tenant", tenant,
			"url", rawURL, "detail", b.Detail)
	}

	if g.notifier != nil {
		g.notifier.Emit(ctx, egressEvent(tenant, b, rawURL))
	}

	if g.auditLog != nil {
		_ = g.auditLog.Log(ctx, audit.Event{
			Type:     audit.EventEgress,
			Subject:  tenant,
			Resource: rawURL,
			Decision: audit.DecisionDeny,
			Reason:   "egress blocked: " + string(b.Reason) + ": " + b.Detail,
			Detail: map[string]any{
				"reason": string(b.Reason),
				"host":   b.Host,
			},
		})
	}
}

func (g *Guard) recordAllow() {
	g.statsMu.Lock()
	g.checked++
	g.allowed++
	g.statsMu.Unlock()
}

// egressEvent builds the notification for a blocked egress attempt. A block that
// resolved to the cloud-metadata service or an internal range is the highest
// signal (a likely live SSRF attempt), so it is escalated to critical.
func egressEvent(tenant string, b *BlockedError, rawURL string) notify.Event {
	sev := notify.SeverityHigh
	switch b.Reason {
	case ReasonMetadata, ReasonPrivateNetwork, ReasonLoopback, ReasonUniqueLocal, ReasonLinkLocal:
		sev = notify.SeverityCritical
	}
	return notify.Event{
		Type:     notify.EventEgressBlocked,
		Severity: sev,
		Title:    "Outbound egress blocked",
		Summary:  b.Error(),
		Subject:  tenant,
	}.WithField("reason", string(b.Reason)).
		WithField("host", b.Host).
		WithField("url", rawURL)
}

// Snapshot is the admin/JSON view of the guard's effective policy and counters.
type Snapshot struct {
	Enabled                 bool              `json:"enabled"`
	HTTPSOnly               bool              `json:"httpsOnly"`
	AllowedSchemes          []string          `json:"allowedSchemes"`
	AllowlistEnforced       bool              `json:"allowlistEnforced"`
	Allowlist               []string          `json:"allowlist"`
	BlockPrivateNetworks    bool              `json:"blockPrivateNetworks"`
	AllowedDestinationCIDRs []string          `json:"allowedDestinationCidrs"`
	FollowRedirects         bool              `json:"followRedirects"`
	MaxRedirects            int               `json:"maxRedirects"`
	Tenants                 []string          `json:"tenants,omitempty"`
	Checked                 uint64            `json:"checked"`
	Allowed                 uint64            `json:"allowed"`
	Blocked                 uint64            `json:"blocked"`
	BlockedByReason         map[string]uint64 `json:"blockedByReason"`
	Recent                  []Block           `json:"recent,omitempty"`
}

// Snapshot returns the guard's effective configuration and counters. It is
// nil-safe: a nil guard reports Enabled=false.
func (g *Guard) Snapshot() Snapshot {
	if g == nil {
		return Snapshot{BlockedByReason: map[string]uint64{}}
	}
	g.mu.RLock()
	allowlist := g.global.entries()
	exceptions := make([]string, 0, len(g.exceptions))
	for _, n := range g.exceptions {
		exceptions = append(exceptions, n.String())
	}
	tenants := make([]string, 0, len(g.tenants))
	for t := range g.tenants {
		tenants = append(tenants, t)
	}
	allowlistEnforced := g.global.enforced()
	g.mu.RUnlock()
	sort.Strings(tenants)

	schemes := make([]string, 0, len(g.allowedSchemes))
	for s := range g.allowedSchemes {
		schemes = append(schemes, s)
	}
	sort.Strings(schemes)

	g.statsMu.Lock()
	byReason := make(map[string]uint64, len(g.byReason))
	for r, v := range g.byReason {
		byReason[string(r)] = v
	}
	recent := make([]Block, len(g.recent))
	copy(recent, g.recent)
	snap := Snapshot{
		Checked:         g.checked,
		Allowed:         g.allowed,
		Blocked:         g.blocked,
		BlockedByReason: byReason,
		Recent:          recent,
	}
	g.statsMu.Unlock()

	snap.Enabled = g.enabled
	snap.HTTPSOnly = g.httpsOnly
	snap.AllowedSchemes = schemes
	snap.AllowlistEnforced = allowlistEnforced
	snap.Allowlist = allowlist
	snap.BlockPrivateNetworks = g.blockPrivate
	snap.AllowedDestinationCIDRs = exceptions
	snap.FollowRedirects = g.followRedirects
	snap.MaxRedirects = g.maxRedirects
	snap.Tenants = tenants
	return snap
}

// Totals returns the checked/allowed/blocked counters for the metrics bridge.
func (g *Guard) Totals() (checked, allowed, blocked uint64) {
	if g == nil {
		return 0, 0, 0
	}
	g.statsMu.Lock()
	defer g.statsMu.Unlock()
	return g.checked, g.allowed, g.blocked
}

// BlockedByReason returns a copy of the per-reason block counters (as float64 for
// the metrics bridge), including zero-valued series for reasons not yet seen.
func (g *Guard) BlockedByReason() map[string]float64 {
	out := make(map[string]float64, len(allReasons))
	for _, r := range allReasons {
		out[string(r)] = 0
	}
	if g == nil {
		return out
	}
	g.statsMu.Lock()
	defer g.statsMu.Unlock()
	for r, v := range g.byReason {
		out[string(r)] = float64(v)
	}
	return out
}

// AddAllowlistEntry adds a host/domain/CIDR entry to the global allowlist at
// runtime. It returns an error if the entry is malformed.
func (g *Guard) AddAllowlistEntry(entry string) error {
	if g == nil {
		return fmt.Errorf("egress: guard is disabled")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.global.add(entry)
}

// RemoveAllowlistEntry removes a previously-added global allowlist entry. It
// reports whether the entry was present.
func (g *Guard) RemoveAllowlistEntry(entry string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.global.remove(entry)
}
