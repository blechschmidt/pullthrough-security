package commit

import (
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/metrics"
)

// Per-provider observability for the commit-scanning pipeline (Task 78).
//
// MetricsRecorder is the narrow hook the pipeline calls; the pipeline never
// depends on a concrete metrics backend, so it stays unit-testable with a no-op.
// Metrics (below) is the Prometheus-backed implementation wired in by main.go.
type MetricsRecorder interface {
	// ObserveProvider records one provider completion: its wall-clock latency,
	// token usage, estimated cost, and whether it succeeded.
	ObserveProvider(provider, model string, latency time.Duration, inputTokens, outputTokens int, costUSD float64, ok bool)
	// ObserveCacheHit / ObserveCacheMiss record verdict-cache outcomes.
	ObserveCacheHit()
	ObserveCacheMiss()
	// ObserveConsensusDisagreement records a deep-pass consensus where providers
	// disagreed on the malicious call.
	ObserveConsensusDisagreement()
	// ObserveBudgetExhausted records that a tenant hit its cost ceiling and the
	// scan was degraded (fail-open or fail-closed).
	ObserveBudgetExhausted(tenant string, failOpen bool)
	// ObserveInjection records that prompt-injection indicators were found in a
	// scanned commit.
	ObserveInjection()
}

// nopMetrics is the default recorder when none is configured.
type nopMetrics struct{}

func (nopMetrics) ObserveProvider(string, string, time.Duration, int, int, float64, bool) {}
func (nopMetrics) ObserveCacheHit()                                                       {}
func (nopMetrics) ObserveCacheMiss()                                                      {}
func (nopMetrics) ObserveConsensusDisagreement()                                          {}
func (nopMetrics) ObserveBudgetExhausted(string, bool)                                    {}
func (nopMetrics) ObserveInjection()                                                      {}

// Metrics is the Prometheus-backed MetricsRecorder. It registers per-provider
// latency/token/cost series and pipeline-level counters on the shared registry.
type Metrics struct {
	latency      *metrics.HistogramVec // labels: provider, model
	tokens       *metrics.CounterVec   // labels: provider, model, kind(input|output)
	cost         *metrics.CounterVec   // labels: provider, model
	requests     *metrics.CounterVec   // labels: provider, model, outcome(ok|error)
	cacheHits    *metrics.Counter
	cacheMisses  *metrics.Counter
	disagreement *metrics.Counter
	injection    *metrics.Counter
	budgetExh    *metrics.CounterVec // labels: tenant, mode(open|closed)
}

// NewMetrics registers the commit-scan metrics on reg and returns the recorder.
func NewMetrics(reg *metrics.Registry) *Metrics {
	if reg == nil {
		return nil
	}
	return &Metrics{
		latency: reg.NewHistogramVec(
			"pullthrough_commitscan_provider_latency_seconds",
			"Latency of LLM commit-scan provider completions, by provider and model.",
			[]string{"provider", "model"},
			[]float64{0.25, 0.5, 1, 2, 4, 8, 16, 32, 64},
		),
		tokens: reg.NewCounterVec(
			"pullthrough_commitscan_provider_tokens_total",
			"Tokens consumed by LLM commit-scan provider completions, by provider, model, and kind.",
			[]string{"provider", "model", "kind"},
		),
		cost: reg.NewCounterVec(
			"pullthrough_commitscan_provider_cost_usd_total",
			"Estimated USD cost of LLM commit-scan provider completions, by provider and model.",
			[]string{"provider", "model"},
		),
		requests: reg.NewCounterVec(
			"pullthrough_commitscan_provider_requests_total",
			"LLM commit-scan provider completions, by provider, model, and outcome.",
			[]string{"provider", "model", "outcome"},
		),
		cacheHits: reg.NewCounter(
			"pullthrough_commitscan_cache_hits_total",
			"Commit-scan verdict cache hits (re-scan avoided).",
		),
		cacheMisses: reg.NewCounter(
			"pullthrough_commitscan_cache_misses_total",
			"Commit-scan verdict cache misses (fresh scan performed).",
		),
		disagreement: reg.NewCounter(
			"pullthrough_commitscan_consensus_disagreement_total",
			"Multi-provider consensus deep passes where providers disagreed on the malicious call.",
		),
		injection: reg.NewCounter(
			"pullthrough_commitscan_injection_detected_total",
			"Commits in which prompt-injection / exfiltration indicators were detected.",
		),
		budgetExh: reg.NewCounterVec(
			"pullthrough_commitscan_budget_exhausted_total",
			"Scans degraded because a tenant exhausted its cost budget, by tenant and mode.",
			[]string{"tenant", "mode"},
		),
	}
}

// BindBudget registers a gauge that reports each tenant's current spend against
// its ceiling at scrape time, read live from the Budgeter.
func (m *Metrics) BindBudget(reg *metrics.Registry, b *Budgeter) {
	if m == nil || reg == nil || b == nil {
		return
	}
	reg.RegisterFuncVec(
		"pullthrough_commitscan_budget_spent_usd",
		"Current per-tenant LLM commit-scan spend in USD within the active budget window.",
		"gauge",
		[]string{"tenant"},
		func() []metrics.LabeledValue {
			snap := b.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap))
			for _, tb := range snap {
				out = append(out, metrics.LabeledValue{Labels: []string{tb.Tenant}, Value: tb.SpentUSD})
			}
			return out
		},
	)
}

func (m *Metrics) ObserveProvider(provider, model string, latency time.Duration, inputTokens, outputTokens int, costUSD float64, ok bool) {
	if m == nil {
		return
	}
	m.latency.With(provider, model).Observe(latency.Seconds())
	if inputTokens > 0 {
		m.tokens.With(provider, model, "input").Add(float64(inputTokens))
	}
	if outputTokens > 0 {
		m.tokens.With(provider, model, "output").Add(float64(outputTokens))
	}
	if costUSD > 0 {
		m.cost.With(provider, model).Add(costUSD)
	}
	outcome := "ok"
	if !ok {
		outcome = "error"
	}
	m.requests.With(provider, model, outcome).Inc()
}

func (m *Metrics) ObserveCacheHit() {
	if m != nil {
		m.cacheHits.Inc()
	}
}

func (m *Metrics) ObserveCacheMiss() {
	if m != nil {
		m.cacheMisses.Inc()
	}
}

func (m *Metrics) ObserveConsensusDisagreement() {
	if m != nil {
		m.disagreement.Inc()
	}
}

func (m *Metrics) ObserveInjection() {
	if m != nil {
		m.injection.Inc()
	}
}

func (m *Metrics) ObserveBudgetExhausted(tenant string, failOpen bool) {
	if m == nil {
		return
	}
	mode := "closed"
	if failOpen {
		mode = "open"
	}
	if tenant == "" {
		tenant = "(none)"
	}
	m.budgetExh.With(tenant, mode).Inc()
}
