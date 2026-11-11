package commit

import (
	"strings"
	"sync"
	"time"
)

// Per-tenant token / cost budgeting (Task 78).
//
// LLM commit scanning bills per token. Without a ceiling, a tenant pulling a
// large monorepo's history — or an attacker deliberately submitting many large
// commits — can run up unbounded provider cost. The Budgeter caps spend per
// tenant over a rolling window and, when a tenant is exhausted, the pipeline
// either fails open (admit without an LLM scan, relying on the deterministic
// passes) or fails closed (block the pull) according to policy.

// Pricing maps a model ID to its per-million-token input/output price in USD and
// computes the estimated cost of a completion. Unknown models fall back to a
// conservative default so cost is never silently zero.
type Pricing struct {
	// PerModel maps a model ID to its price. Lookup is case-insensitive and falls
	// back to a longest-prefix match so dated model IDs (e.g.
	// "claude-haiku-4-5-20251001") inherit the base model's price.
	perModel map[string]ModelPrice
	// fallback is used when no entry matches.
	fallback ModelPrice
}

// ModelPrice is the price of a model in USD per one million tokens.
type ModelPrice struct {
	InputPerMTok  float64
	OutputPerMTok float64
}

// DefaultPricing returns the built-in price table for the default Claude models,
// per the latest published list pricing. Operators can override or extend it via
// configuration. Values are USD per 1M tokens.
func DefaultPricing() *Pricing {
	return &Pricing{
		fallback: ModelPrice{InputPerMTok: 15, OutputPerMTok: 75}, // conservative (Opus-tier)
		perModel: map[string]ModelPrice{
			"claude-opus-4":    {InputPerMTok: 15, OutputPerMTok: 75},
			"claude-sonnet-4":  {InputPerMTok: 3, OutputPerMTok: 15},
			"claude-haiku-4":   {InputPerMTok: 1, OutputPerMTok: 5},
			"claude-3-5-haiku": {InputPerMTok: 0.80, OutputPerMTok: 4},
			// Claude 5 family (Task 173), USD per 1M tokens per published list
			// pricing. Without these a 5.x model would fall through to the
			// conservative Opus-tier fallback and exhaust a cost budget several
			// times too early. The longest matching prefix wins, so
			// "claude-opus-5-5" is priced apart from "claude-opus-5".
			"claude-fable-5":   {InputPerMTok: 10, OutputPerMTok: 50},
			"claude-mythos-5":  {InputPerMTok: 10, OutputPerMTok: 50},
			"claude-opus-5":    {InputPerMTok: 5, OutputPerMTok: 25},
			"claude-opus-5-5":  {InputPerMTok: 4, OutputPerMTok: 20},
			"claude-sonnet-5":  {InputPerMTok: 2, OutputPerMTok: 10},
			"claude-haiku-5-5": {InputPerMTok: 0.10, OutputPerMTok: 0.50},
			// OpenAI/Codex models (Task 101), USD per 1M tokens per published list
			// pricing. Dated/suffixed model IDs inherit via longest-prefix match.
			"gpt-4o":      {InputPerMTok: 2.50, OutputPerMTok: 10},
			"gpt-4o-mini": {InputPerMTok: 0.15, OutputPerMTok: 0.60},
			"gpt-4.1":     {InputPerMTok: 2, OutputPerMTok: 8},
			"o4-mini":     {InputPerMTok: 1.10, OutputPerMTok: 4.40},
			"o3":          {InputPerMTok: 2, OutputPerMTok: 8},
		},
	}
}

// WithOverrides returns a copy of the pricing table with the given per-model
// overrides applied (keyed by model ID).
func (p *Pricing) WithOverrides(overrides map[string]ModelPrice) *Pricing {
	if p == nil {
		p = DefaultPricing()
	}
	cp := &Pricing{fallback: p.fallback, perModel: make(map[string]ModelPrice, len(p.perModel)+len(overrides))}
	for k, v := range p.perModel {
		cp.perModel[k] = v
	}
	for k, v := range overrides {
		cp.perModel[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return cp
}

// Cost returns the estimated USD cost of a completion against model.
func (p *Pricing) Cost(model string, inputTokens, outputTokens int) float64 {
	mp := p.priceFor(model)
	return float64(inputTokens)/1e6*mp.InputPerMTok + float64(outputTokens)/1e6*mp.OutputPerMTok
}

// priceFor resolves the price for a model, preferring an exact (case-insensitive)
// match, then the longest matching key prefix, then the fallback.
func (p *Pricing) priceFor(model string) ModelPrice {
	m := strings.ToLower(strings.TrimSpace(model))
	if mp, ok := p.perModel[m]; ok {
		return mp
	}
	var (
		best    ModelPrice = p.fallback
		bestLen int
	)
	for k, v := range p.perModel {
		if strings.HasPrefix(m, k) && len(k) > bestLen {
			best, bestLen = v, len(k)
		}
	}
	return best
}

// BudgetPolicy configures per-tenant cost ceilings and the exhaustion behavior.
type BudgetPolicy struct {
	// DefaultCeilingUSD is the per-tenant spend ceiling per window. Zero or
	// negative disables budgeting (unlimited).
	DefaultCeilingUSD float64
	// TenantCeilingsUSD overrides DefaultCeilingUSD for specific tenants. A value
	// of 0 means "unlimited" for that tenant (explicitly).
	TenantCeilingsUSD map[string]float64
	// Window is the rolling period after which a tenant's usage resets. Zero
	// defaults to 24h.
	Window time.Duration
	// FailOpen selects the behavior when a tenant is exhausted: true admits the
	// pull without an LLM scan (relying on the deterministic passes); false blocks
	// the pull (fail-closed).
	FailOpen bool
}

// TenantBudget is a snapshot of one tenant's usage, for admin reporting.
type TenantBudget struct {
	Tenant       string    `json:"tenant"`
	SpentUSD     float64   `json:"spentUsd"`
	CeilingUSD   float64   `json:"ceilingUsd"` // 0 = unlimited
	InputTokens  int       `json:"inputTokens"`
	OutputTokens int       `json:"outputTokens"`
	WindowStart  time.Time `json:"windowStart"`
	Exhausted    bool      `json:"exhausted"`
}

// Budgeter tracks per-tenant spend against a ceiling over a rolling window. It is
// safe for concurrent use.
type Budgeter struct {
	mu     sync.Mutex
	policy BudgetPolicy
	now    func() time.Time
	usage  map[string]*tenantUsage
	// overrides set at runtime via SetCeiling, layered over policy.TenantCeilingsUSD.
	overrides map[string]float64
}

type tenantUsage struct {
	spentUSD     float64
	inputTokens  int
	outputTokens int
	windowStart  time.Time
}

// NewBudgeter constructs a Budgeter from policy. A zero DefaultCeilingUSD with no
// per-tenant ceilings means budgeting is effectively unlimited but usage is still
// tracked for reporting.
func NewBudgeter(policy BudgetPolicy) *Budgeter {
	if policy.Window <= 0 {
		policy.Window = 24 * time.Hour
	}
	return &Budgeter{
		policy:    policy,
		now:       time.Now,
		usage:     make(map[string]*tenantUsage),
		overrides: make(map[string]float64),
	}
}

// ceilingFor returns the effective ceiling for tenant (0 = unlimited). Runtime
// overrides take precedence over the static per-tenant map, which takes
// precedence over the default.
func (b *Budgeter) ceilingFor(tenant string) float64 {
	if v, ok := b.overrides[tenant]; ok {
		return v
	}
	if v, ok := b.policy.TenantCeilingsUSD[tenant]; ok {
		return v
	}
	return b.policy.DefaultCeilingUSD
}

// usageFor returns the (window-current) usage record for tenant, resetting it if
// the window has elapsed. Caller must hold b.mu.
func (b *Budgeter) usageFor(tenant string) *tenantUsage {
	now := b.now()
	u, ok := b.usage[tenant]
	if !ok {
		u = &tenantUsage{windowStart: now}
		b.usage[tenant] = u
		return u
	}
	if now.Sub(u.windowStart) >= b.policy.Window {
		u.spentUSD = 0
		u.inputTokens = 0
		u.outputTokens = 0
		u.windowStart = now
	}
	return u
}

// Allow reports whether tenant has budget remaining for another scan, and the
// policy's fail-open flag so the caller can decide how to degrade. A tenant with
// no ceiling (0) is always allowed.
func (b *Budgeter) Allow(tenant string) (allowed, failOpen bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ceiling := b.ceilingFor(tenant)
	if ceiling <= 0 {
		return true, b.policy.FailOpen
	}
	u := b.usageFor(tenant)
	return u.spentUSD < ceiling, b.policy.FailOpen
}

// Record adds the cost and tokens of a completion to tenant's usage.
func (b *Budgeter) Record(tenant string, inputTokens, outputTokens int, costUSD float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.usageFor(tenant)
	u.spentUSD += costUSD
	u.inputTokens += inputTokens
	u.outputTokens += outputTokens
}

// SetCeiling sets a runtime per-tenant ceiling override (USD per window). A
// negative value clears the override, reverting to policy.
func (b *Budgeter) SetCeiling(tenant string, ceilingUSD float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ceilingUSD < 0 {
		delete(b.overrides, tenant)
		return
	}
	b.overrides[tenant] = ceilingUSD
}

// Snapshot returns the current usage for every tracked tenant, ordered by spend
// descending.
func (b *Budgeter) Snapshot() []TenantBudget {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]TenantBudget, 0, len(b.usage))
	for tenant, u := range b.usage {
		ceiling := b.ceilingFor(tenant)
		out = append(out, TenantBudget{
			Tenant:       tenant,
			SpentUSD:     u.spentUSD,
			CeilingUSD:   ceiling,
			InputTokens:  u.inputTokens,
			OutputTokens: u.outputTokens,
			WindowStart:  u.windowStart,
			Exhausted:    ceiling > 0 && u.spentUSD >= ceiling,
		})
	}
	// Stable-ish ordering: highest spend first.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].SpentUSD > out[j-1].SpentUSD; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Policy returns the configured budget policy (for admin reporting).
func (b *Budgeter) Policy() BudgetPolicy { return b.policy }
