package llmpkgscan

import (
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// Cost budget.
//
// This gate spends money on demand: every artifact a client pulls for the first
// time is a paid scan. Two ceilings bound that. The per-tenant ceiling keeps
// one team from spending the whole allowance — and keeps it from exhausting
// anyone else's, which matters because an exhausted budget means artifacts go
// unscanned. The global ceiling bounds the bill no matter how spend is spread.
//
// Both reuse the commit scanner's Budgeter (a ceiling over a rolling window);
// the global one is a Budgeter with a single, fixed account.
//
// The ceilings are soft by one scan: the check happens before a scan and the
// cost is known only after, so scans already in flight when a ceiling is
// reached still complete. With bounded concurrency the overshoot is at most a
// handful of scans.

// globalAccount is the single account of the global Budgeter. It cannot collide
// with a tenant: tenants and the global ceiling are tracked in separate
// Budgeters.
const globalAccount = "*"

// Budget scopes reported when a budget is exhausted.
const (
	BudgetScopeTenant = "tenant"
	BudgetScopeGlobal = "global"
)

// budget enforces the per-tenant and global ceilings. A nil *budget allows
// everything and records nothing.
type budget struct {
	tenants *commit.Budgeter
	global  *commit.Budgeter
}

func newBudget(cfg BudgetConfig) *budget {
	if !cfg.Enabled {
		return nil
	}
	return &budget{
		tenants: commit.NewBudgeter(commit.BudgetPolicy{
			DefaultCeilingUSD: cfg.TenantCeilingUSD,
			TenantCeilingsUSD: cfg.TenantCeilingsUSD,
			Window:            cfg.Window,
		}),
		global: commit.NewBudgeter(commit.BudgetPolicy{
			DefaultCeilingUSD: cfg.GlobalCeilingUSD,
			Window:            cfg.Window,
		}),
	}
}

// allow reports whether a scan for tenant may start. When it may not, scope
// names the ceiling that was reached.
func (b *budget) allow(tenant string) (ok bool, scope string) {
	if b == nil {
		return true, ""
	}
	if allowed, _ := b.global.Allow(globalAccount); !allowed {
		return false, BudgetScopeGlobal
	}
	if allowed, _ := b.tenants.Allow(tenant); !allowed {
		return false, BudgetScopeTenant
	}
	return true, ""
}

// record charges a completion to the tenant and to the global account.
func (b *budget) record(tenant string, u commit.Usage, costUSD float64) {
	if b == nil {
		return
	}
	b.tenants.Record(tenant, u.InputTokens+u.CacheReadTokens+u.CacheCreationTokens, u.OutputTokens, costUSD)
	b.global.Record(globalAccount, u.InputTokens+u.CacheReadTokens+u.CacheCreationTokens, u.OutputTokens, costUSD)
}

// BudgetStatus is the budget's current state, for the admin surface.
type BudgetStatus struct {
	Enabled bool `json:"enabled"`
	// GlobalSpentUSD / GlobalCeilingUSD describe the shared ceiling (0 = none).
	GlobalSpentUSD   float64 `json:"globalSpentUsd"`
	GlobalCeilingUSD float64 `json:"globalCeilingUsd"`
	GlobalExhausted  bool    `json:"globalExhausted"`
	// Tenants lists per-tenant usage, highest spend first.
	Tenants []commit.TenantBudget `json:"tenants,omitempty"`
}

func (b *budget) status() BudgetStatus {
	if b == nil {
		return BudgetStatus{}
	}
	st := BudgetStatus{Enabled: true, Tenants: b.tenants.Snapshot()}
	for _, g := range b.global.Snapshot() {
		if g.Tenant == globalAccount {
			st.GlobalSpentUSD = g.SpentUSD
			st.GlobalCeilingUSD = g.CeilingUSD
			st.GlobalExhausted = g.Exhausted
		}
	}
	if st.GlobalCeilingUSD == 0 {
		st.GlobalCeilingUSD = b.global.Policy().DefaultCeilingUSD
	}
	return st
}
