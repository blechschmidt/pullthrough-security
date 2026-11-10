package commit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/tracing"
	"golang.org/x/sync/singleflight"
)

// Config tunes the scanning pipeline. Zero-valued fields are replaced with
// sensible defaults by withDefaults.
type Config struct {
	// TriageModel is the cheap model used for the first-pass triage of every
	// commit; DeepModel is the capable model used when triage escalates.
	TriageModel string
	DeepModel   string
	// EscalateAtScore is the triage risk score (0-100) at or above which deep
	// analysis runs. Set 0 to always run deep analysis, or >100 to never.
	EscalateAtScore int
	// MaxDiffTokens is the per-request token budget; larger diffs are chunked.
	MaxDiffTokens int
	// MaxChunks caps chunks per commit (0 = unbounded). Excess diff is dropped
	// and the verdict flagged Truncated.
	MaxChunks int
	// TriageMaxTokens and DeepMaxTokens bound response length per pass.
	TriageMaxTokens int
	DeepMaxTokens   int
	// MaxRetries is the number of additional attempts after the first on a
	// transient provider error.
	MaxRetries int
	// RetryBaseDelay is the base for exponential backoff between retries.
	RetryBaseDelay time.Duration
	// Workers is the number of asynchronous scan workers; QueueSize bounds the
	// async submission queue.
	Workers   int
	QueueSize int

	// Tracer, when set, emits an OpenTelemetry span per commit scan (Task 41) so
	// background LLM-scan latency is visible in the trace backend. A nil Tracer is
	// a no-op.
	Tracer *tracing.Tracer

	// Secrets, when non-nil, runs a deterministic secret/credential detection
	// pass over each commit's added diff lines before the LLM call (Task 29). Its
	// findings are merged into the verdict and raise the risk score, providing
	// reliable offline coverage that is independent of provider availability and
	// gives the LLM pass ground-truth findings to corroborate. When a SecretScanner
	// is configured the pipeline may run without a Provider (deterministic-only
	// mode) and degrades to deterministic findings if the LLM pass fails.
	Secrets SecretScanner

	// Actions, when non-nil, runs a deterministic GitHub Actions pinning pass over
	// each commit's changed .github/workflows/*.yml and composite action.yml files
	// (Task 115), flagging/blocking action references pinned to mutable refs
	// (branches or floating tags) rather than full commit SHAs, and references to
	// disallowed owners. Like Secrets it is cheap, offline, and provider-
	// independent; its findings are merged into the verdict and raise the risk
	// score, and it is sufficient on its own for deterministic-only mode.
	Actions ActionScanner

	// OnVerdict, when set, is invoked once for each freshly-produced verdict
	// (after it is persisted), but not on a cache hit. It is the hook the
	// notification subsystem (Task 21) uses to alert on malicious or high-severity
	// commit findings. It must not block; the pipeline calls it synchronously
	// within the scan, so a slow handler should hand off to its own queue (the
	// Notifier already does). A nil hook is ignored.
	OnVerdict func(ctx context.Context, v *Verdict)

	// Consensus, when non-empty, adds providers to the deep (escalated) pass: the
	// commit is analyzed by the primary provider and every consensus member, and a
	// 'malicious' verdict only blocks when a quorum agree (Task 78). Each member
	// carries its own model ID. The triage pass always uses the primary provider
	// alone (cheap pre-filtering).
	Consensus []ConsensusMember
	// Quorum is the minimum number of agreeing malicious votes required to call a
	// commit malicious under consensus. Zero defaults to a strict majority of the
	// participating providers (primary + consensus members).
	Quorum int

	// Budgeter, when set, enforces per-tenant token/cost ceilings on LLM scanning
	// (Task 78). When a tenant is exhausted the scan is degraded per the budget
	// policy (fail-open: admit without an LLM scan; fail-closed: block).
	Budgeter *Budgeter
	// Pricing is the per-model price table used to estimate provider cost. A nil
	// Pricing falls back to DefaultPricing.
	Pricing *Pricing
	// Metrics, when set, receives per-provider latency/token/cost observations and
	// pipeline counters (Task 78). A nil Metrics is a no-op.
	Metrics MetricsRecorder
	// OnBudgetExhausted, when set, is invoked when a tenant's cost ceiling is hit
	// and the scan is degraded. It is the notify hook for budget alerts. A nil hook
	// is ignored.
	OnBudgetExhausted func(ctx context.Context, tenant string, failOpen bool)

	// RulesetHash identifies the deterministic rulesets in effect (secret rules,
	// etc.); it participates in the verdict cache key so a ruleset change forces a
	// re-scan. Empty still incorporates the injection ruleset version.
	RulesetHash string
	// InjectionRiskFloor is the minimum risk score a detected prompt-injection
	// attempt raises a verdict to. Zero uses defaultInjectionRiskFloor.
	InjectionRiskFloor int

	// RetentionTTL, when > 0, prunes cached verdicts older than this age on a
	// schedule, complementing the cache retention engine (Task 39). Zero disables
	// pipeline-side pruning.
	RetentionTTL time.Duration
	// RetentionInterval is the period between retention sweeps. Zero defaults to
	// one hour when RetentionTTL is set.
	RetentionInterval time.Duration
}

// ConsensusMember is an additional provider+model that participates in the deep
// consensus pass.
type ConsensusMember struct {
	Provider Provider
	Model    string
}

// withDefaults returns cfg with zero fields filled in.
func (cfg Config) withDefaults() Config {
	if cfg.TriageModel == "" {
		cfg.TriageModel = string(DefaultTriageModel)
	}
	if cfg.DeepModel == "" {
		cfg.DeepModel = string(DefaultDeepModel)
	}
	if cfg.EscalateAtScore == 0 {
		cfg.EscalateAtScore = 25
	}
	if cfg.MaxDiffTokens <= 0 {
		cfg.MaxDiffTokens = 60000
	}
	if cfg.TriageMaxTokens <= 0 {
		cfg.TriageMaxTokens = 2048
	}
	if cfg.DeepMaxTokens <= 0 {
		cfg.DeepMaxTokens = 8192
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 500 * time.Millisecond
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if cfg.InjectionRiskFloor <= 0 {
		cfg.InjectionRiskFloor = defaultInjectionRiskFloor
	}
	if cfg.RetentionTTL > 0 && cfg.RetentionInterval <= 0 {
		cfg.RetentionInterval = time.Hour
	}
	if cfg.Pricing == nil {
		cfg.Pricing = DefaultPricing()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = nopMetrics{}
	}
	return cfg
}

// Pipeline orchestrates commit scanning: cache lookup, diff chunking, triage and
// deep analysis with retries, aggregation, persistence, and asynchronous
// background scanning. It is safe for concurrent use.
type Pipeline struct {
	provider Provider
	store    VerdictStore
	cfg      Config
	logger   *slog.Logger

	// signature is the cache-key suffix derived from the model set, prompt
	// version, and ruleset hash; cacheKey(sha, signature) is the storage key.
	signature string

	// metrics holds the MetricsRecorder; it is an atomic so the observability
	// layer can bind a Prometheus-backed recorder after construction (the metrics
	// registry is created later in startup) without racing the scan hot path. It
	// stores a *MetricsRecorder (pointer to the interface) rather than the bare
	// interface so every Store has the same concrete type — atomic.Value panics
	// when successive Stores disagree, which they would otherwise (the no-op
	// recorder and the Prometheus recorder are different concrete types).
	metrics atomic.Value // *MetricsRecorder

	// group coalesces concurrent synchronous scans of the same SHA so the
	// provider is called at most once per in-flight commit.
	group singleflight.Group

	// Asynchronous scanning state.
	queue     chan *Commit
	wg        sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}

	mu      sync.Mutex
	pending map[string]struct{} // SHAs queued or in-flight async, for dedup
}

// New constructs a Pipeline. store is required; provider is required unless a
// deterministic SecretScanner is configured (deterministic-only mode).
func New(provider Provider, store VerdictStore, cfg Config, logger *slog.Logger) (*Pipeline, error) {
	if provider == nil && cfg.Secrets == nil && cfg.Actions == nil {
		return nil, errors.New("commit: a provider is required (or a deterministic scanner for deterministic-only mode)")
	}
	if store == nil {
		return nil, errors.New("commit: a verdict store is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()
	p := &Pipeline{
		provider:  provider,
		store:     store,
		cfg:       cfg,
		logger:    logger,
		signature: signature(PromptVersion, cfg.scanModels(), rulesetHash(cfg.RulesetHash)),
		queue:     make(chan *Commit, cfg.QueueSize),
		stop:      make(chan struct{}),
		pending:   make(map[string]struct{}),
	}
	p.setMetrics(cfg.Metrics)
	return p, nil
}

// rec returns the active metrics recorder (never nil).
func (p *Pipeline) rec() MetricsRecorder { return *p.metrics.Load().(*MetricsRecorder) }

// setMetrics stores m behind a pointer so every atomic Store uses the same
// concrete type (*MetricsRecorder).
func (p *Pipeline) setMetrics(m MetricsRecorder) { p.metrics.Store(&m) }

// SetMetrics swaps the metrics recorder. The observability layer calls it once at
// startup to bind a Prometheus-backed recorder after the metrics registry is
// built. A nil recorder is replaced with a no-op.
func (p *Pipeline) SetMetrics(m MetricsRecorder) {
	if m == nil {
		m = nopMetrics{}
	}
	p.setMetrics(m)
}

// scanModels returns every model ID that may produce a verdict, for the cache
// signature: the triage and deep models plus each consensus member's model.
func (cfg Config) scanModels() []string {
	models := []string{cfg.TriageModel, cfg.DeepModel}
	for _, m := range cfg.Consensus {
		if m.Model != "" {
			models = append(models, m.Model)
		}
	}
	return models
}

// deepMembers returns the providers that participate in the deep pass: the
// primary provider (with the deep model) followed by each consensus member.
func (p *Pipeline) deepMembers() []ConsensusMember {
	members := []ConsensusMember{{Provider: p.provider, Model: p.cfg.DeepModel}}
	members = append(members, p.cfg.Consensus...)
	return members
}

// quorum returns the effective consensus quorum for the deep pass.
func (p *Pipeline) quorum() int {
	n := len(p.deepMembers())
	if p.cfg.Quorum > 0 {
		if p.cfg.Quorum > n {
			return n
		}
		return p.cfg.Quorum
	}
	return defaultQuorum(n)
}

// Get returns the persisted verdict for sha under the pipeline's current cache
// signature, or ErrNotFound. The signature folds the model set, prompt version,
// and ruleset hash, so a verdict produced under a different configuration is not
// returned (it is treated as absent and re-scanned).
func (p *Pipeline) Get(ctx context.Context, sha string) (*Verdict, error) {
	return p.store.Get(ctx, cacheKey(sha, p.signature))
}

// Signature returns the pipeline's cache signature, for admin reporting.
func (p *Pipeline) Signature() string { return p.signature }

// HardeningStatus summarizes the pipeline's Task 78 configuration for the admin
// API: the cache signature inputs, consensus quorum, budget policy, and
// retention. It carries no secrets.
type HardeningStatus struct {
	CacheSignature   string        `json:"cacheSignature"`
	PromptVersion    int           `json:"promptVersion"`
	TriageModel      string        `json:"triageModel"`
	DeepModel        string        `json:"deepModel"`
	ConsensusModels  []string      `json:"consensusModels,omitempty"`
	Quorum           int           `json:"quorum"`
	InjectionDefense bool          `json:"injectionDefense"`
	BudgetEnabled    bool          `json:"budgetEnabled"`
	BudgetPolicy     *BudgetPolicy `json:"budgetPolicy,omitempty"`
	RetentionTTL     string        `json:"retentionTtl,omitempty"`
	QueueDepth       int           `json:"queueDepth"`
	PendingCount     int           `json:"pendingCount"`
}

// HardeningStatus returns the current hardening configuration.
func (p *Pipeline) HardeningStatus() HardeningStatus {
	st := HardeningStatus{
		CacheSignature:   p.signature,
		PromptVersion:    PromptVersion,
		TriageModel:      p.cfg.TriageModel,
		DeepModel:        p.cfg.DeepModel,
		Quorum:           p.quorum(),
		InjectionDefense: true,
		BudgetEnabled:    p.cfg.Budgeter != nil,
		QueueDepth:       p.QueueDepth(),
		PendingCount:     p.PendingCount(),
	}
	for _, m := range p.cfg.Consensus {
		if m.Model != "" {
			st.ConsensusModels = append(st.ConsensusModels, m.Model)
		}
	}
	if p.cfg.Budgeter != nil {
		pol := p.cfg.Budgeter.Policy()
		st.BudgetPolicy = &pol
	}
	if p.cfg.RetentionTTL > 0 {
		st.RetentionTTL = p.cfg.RetentionTTL.String()
	}
	return st
}

// Budgeter returns the pipeline's budgeter, or nil when budgeting is off (for
// binding the live budget gauge).
func (p *Pipeline) Budgeter() *Budgeter { return p.cfg.Budgeter }

// BudgetSnapshot returns per-tenant budget usage, or nil when budgeting is off.
func (p *Pipeline) BudgetSnapshot() []TenantBudget {
	if p.cfg.Budgeter == nil {
		return nil
	}
	return p.cfg.Budgeter.Snapshot()
}

// SetBudget sets a runtime per-tenant cost ceiling (USD per window). A negative
// ceiling clears the override. It errors when budgeting is not enabled.
func (p *Pipeline) SetBudget(tenant string, ceilingUSD float64) error {
	if p.cfg.Budgeter == nil {
		return errors.New("commit: per-tenant budgeting is not enabled")
	}
	if tenant == "" {
		return errors.New("commit: a tenant is required")
	}
	p.cfg.Budgeter.SetCeiling(tenant, ceilingUSD)
	return nil
}

// Verdicts returns every persisted verdict, for administrative inspection.
func (p *Pipeline) Verdicts(ctx context.Context) ([]*Verdict, error) {
	return p.store.List(ctx)
}

// QueueDepth reports the number of commits currently waiting in the async scan
// queue (not counting those already in-flight on a worker).
func (p *Pipeline) QueueDepth() int { return len(p.queue) }

// PendingCount reports the number of commits queued or in-flight for async
// scanning.
func (p *Pipeline) PendingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// Scan returns the verdict for commit, scanning it if not already cached. It is
// the synchronous entry point: a cache hit returns immediately; a miss runs the
// full triage/deep pipeline, persists the verdict, and returns it. Concurrent
// calls for the same SHA are coalesced.
func (p *Pipeline) Scan(ctx context.Context, commit *Commit) (*Verdict, error) {
	if commit == nil || commit.SHA == "" {
		return nil, errors.New("commit: a commit with a SHA is required")
	}

	// Emit a span for the commit scan so background LLM-scan latency is visible
	// alongside the pull traces. On a background worker this roots a fresh trace;
	// on a synchronous scan triggered from a request it parents from it.
	ctx, span := p.cfg.Tracer.Start(ctx, "scan.commit",
		tracing.WithAttributes(tracing.String("vcs.commit.sha", commit.SHA)))
	defer span.End()

	key := cacheKey(commit.SHA, p.signature)
	if v, err := p.store.Get(ctx, key); err == nil {
		span.SetAttributes(tracing.Bool("pullthrough.scan.cached", true))
		p.rec().ObserveCacheHit()
		return v, nil
	} else if !errors.Is(err, ErrNotFound) {
		span.RecordError(err)
		return nil, err
	}

	// singleflight returns the shared result to all callers waiting on the SHA.
	v, err, _ := p.group.Do(key, func() (any, error) {
		// Re-check the store inside the critical section: a prior holder of the
		// key may have just persisted a verdict.
		if v, err := p.store.Get(ctx, key); err == nil {
			p.rec().ObserveCacheHit()
			return v, nil
		}
		p.rec().ObserveCacheMiss()
		verdict, err := p.analyze(ctx, commit)
		if err != nil {
			return nil, err
		}
		verdict.CacheKey = key
		if perr := p.store.Put(ctx, verdict); perr != nil {
			p.logger.Error("persisting commit verdict failed", "sha", commit.SHA, "error", perr)
		}
		// Notify on a freshly-produced verdict (not on a cache hit) so an alert
		// fires once per newly-scanned commit.
		if p.cfg.OnVerdict != nil {
			p.cfg.OnVerdict(ctx, verdict)
		}
		return verdict, nil
	})
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	verdict := v.(*Verdict)
	span.SetAttributes(
		tracing.Int("pullthrough.scan.risk_score", verdict.RiskScore),
		tracing.Bool("pullthrough.scan.malicious", verdict.Malicious),
		tracing.Int("pullthrough.scan.findings", len(verdict.Findings)),
	)
	return verdict, nil
}

// analyze runs the LLM pipeline for a single (uncached) commit: deterministic
// injection/secret detection, a per-tenant budget check, chunk the diff, triage
// every chunk with the cheap model, escalate to the deep model (optionally across
// multiple providers for consensus) when the triage score crosses the threshold,
// then aggregate, apply deterministic ground truth, and stamp the verdict.
func (p *Pipeline) analyze(ctx context.Context, commit *Commit) (*Verdict, error) {
	// Deterministic passes run first: they are cheap, offline, and independent of
	// the LLM provider, so their findings (and the prompt-injection signal) are
	// available even if the provider call fails or is skipped for budget below.
	secretFindings := p.detectSecrets(commit)
	actionFindings := p.detectActionPins(commit)
	injectionHits := detectInjection(commit)
	if len(injectionHits) > 0 {
		p.rec().ObserveInjection()
	}
	// deterministic is the union of the offline ground-truth findings, used for
	// the degraded-verdict risk floor and rationale; finalize re-applies each set.
	deterministic := concatFindings(secretFindings, actionFindings)

	// Deterministic-only mode: no LLM provider configured.
	if p.provider == nil {
		v := p.deterministicVerdict(commit, deterministic, "")
		p.finalize(v, commit, secretFindings, actionFindings, injectionHits)
		return v, nil
	}

	// Per-tenant cost budget: when a tenant is exhausted, degrade per policy.
	if p.cfg.Budgeter != nil {
		if allowed, failOpen := p.cfg.Budgeter.Allow(commit.Tenant); !allowed {
			return p.budgetExhaustedVerdict(ctx, commit, secretFindings, actionFindings, injectionHits, failOpen), nil
		}
	}

	chunks := chunkCommit(commit, p.cfg.MaxDiffTokens, p.cfg.MaxChunks)

	triage, err := p.runPassWith(ctx, p.provider, commit, chunks, p.cfg.TriageModel, p.cfg.TriageMaxTokens, false)
	if err != nil {
		// If the LLM is unavailable but a deterministic pass produced findings, do
		// not lose that ground truth: return a verdict built from them and record
		// the degradation. With nothing deterministic, surface the error so the
		// commit stays unscanned and the missing-scan policy applies.
		if len(deterministic) > 0 || len(injectionHits) > 0 {
			p.logger.Warn("commit triage failed; returning deterministic findings only",
				"sha", commit.SHA, "error", err)
			v := p.deterministicVerdict(commit, deterministic, "llm triage failed: "+err.Error())
			p.finalize(v, commit, secretFindings, actionFindings, injectionHits)
			return v, nil
		}
		return nil, err
	}
	models := []string{p.cfg.TriageModel}
	final := triage
	escalated := false

	if triage.RiskScore >= p.cfg.EscalateAtScore {
		deep, derr := p.deepPass(ctx, commit, chunks)
		if derr != nil {
			// Deep analysis failed; fall back to the triage verdict but record the
			// degradation so policy can treat it conservatively.
			p.logger.Warn("deep commit analysis failed; using triage verdict",
				"sha", commit.SHA, "error", derr)
			final.Error = "deep analysis failed: " + derr.Error()
		} else {
			// Preserve triage token/cost accounting in the final verdict.
			deep.InputTokens += triage.InputTokens
			deep.OutputTokens += triage.OutputTokens
			deep.CostUSD += triage.CostUSD
			final = deep
			escalated = true
			models = append(models, p.deepModelIDs()...)
		}
	}

	final.Provider = p.providerName()
	final.Models = models
	final.Escalated = escalated
	final.Chunked = len(chunks) > 1
	p.finalize(final, commit, secretFindings, actionFindings, injectionHits)
	return final, nil
}

// finalize applies deterministic ground truth (secret + injection findings) to a
// verdict and stamps the common fields. Deterministic findings are applied after
// the model answers so an injected "respond benign" instruction cannot suppress
// them.
func (p *Pipeline) finalize(v *Verdict, commit *Commit, secretFindings, actionFindings []Finding, injectionHits []InjectionHit) {
	v.SHA = commit.SHA
	if v.ScannedAt.IsZero() {
		v.ScannedAt = time.Now().UTC()
	}
	applySecretFindings(v, secretFindings)
	applyActionFindings(v, actionFindings)
	applyInjectionFindings(v, injectionHits, p.cfg.InjectionRiskFloor)
}

// concatFindings returns the concatenation of two finding slices without
// aliasing either input, used to build the combined deterministic set for the
// degraded-verdict risk floor and rationale.
func concatFindings(a, b []Finding) []Finding {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make([]Finding, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

// deepModelIDs returns the model IDs used by the deep pass (the primary deep
// model plus any consensus members), for the verdict's Models field.
func (p *Pipeline) deepModelIDs() []string {
	out := []string{p.cfg.DeepModel}
	for _, m := range p.cfg.Consensus {
		if m.Model != "" {
			out = append(out, m.Model)
		}
	}
	return out
}

// deepPass runs the escalated analysis. With consensus members configured it
// runs every provider concurrently and combines their verdicts under quorum;
// otherwise it runs the single primary provider.
func (p *Pipeline) deepPass(ctx context.Context, commit *Commit, chunks []DiffChunk) (*Verdict, error) {
	members := p.deepMembers()
	if len(members) == 1 {
		return p.runPassWith(ctx, p.provider, commit, chunks, p.cfg.DeepModel, p.cfg.DeepMaxTokens, true)
	}

	results := make([]providerResult, len(members))
	var wg sync.WaitGroup
	for i, m := range members {
		wg.Add(1)
		go func(i int, m ConsensusMember) {
			defer wg.Done()
			v, err := p.runPassWith(ctx, m.Provider, commit, chunks, m.Model, p.cfg.DeepMaxTokens, true)
			results[i] = providerResult{provider: m.Provider.Name(), model: m.Model, verdict: v, err: err}
		}(i, m)
	}
	wg.Wait()

	responded := 0
	for _, r := range results {
		if r.err == nil && r.verdict != nil {
			responded++
		}
	}
	combined, disagreed := combineConsensus(commit.SHA, results, p.quorum())
	if disagreed {
		p.rec().ObserveConsensusDisagreement()
	}
	if responded == 0 {
		return nil, fmt.Errorf("commit: %s", combined.Error)
	}
	return combined, nil
}

// runPassWith analyzes every chunk with the given provider+model and aggregates
// the results into one verdict, recording per-provider metrics and budget usage.
func (p *Pipeline) runPassWith(ctx context.Context, prov Provider, commit *Commit, chunks []DiffChunk, model string, maxTokens int, thinking bool) (*Verdict, error) {
	system := systemPrompt
	if !thinking {
		system = triageSystemPrompt
	}

	agg := &Verdict{SHA: commit.SHA}
	var rationales []string
	for _, chunk := range chunks {
		req := Request{
			Model:     model,
			System:    system,
			User:      buildUserPrompt(commit, chunk),
			MaxTokens: maxTokens,
			Thinking:  thinking,
		}
		text, usage, cost, err := p.callProvider(ctx, prov, req, commit.Tenant)
		agg.InputTokens += usage.InputTokens
		agg.OutputTokens += usage.OutputTokens
		agg.CostUSD += cost
		if err != nil {
			return nil, fmt.Errorf("commit: analyzing %s chunk %d/%d with %s: %w",
				commit.SHA, chunk.Index+1, chunk.Total, model, err)
		}
		// Reject a response that leaked the system prompt (a successful injection)
		// before it is ever trusted as a verdict.
		if verr := validateModelOutput(text); verr != nil {
			return nil, fmt.Errorf("commit: %s chunk %d/%d (%s): %w",
				commit.SHA, chunk.Index+1, chunk.Total, model, verr)
		}
		v, err := parseVerdict(text)
		if err != nil {
			return nil, fmt.Errorf("commit: %s chunk %d/%d (%s): %w",
				commit.SHA, chunk.Index+1, chunk.Total, model, err)
		}
		mergeVerdict(agg, v)
		if r := trimRationale(v.Rationale); r != "" {
			rationales = append(rationales, r)
		}
		if chunk.Truncated {
			agg.Truncated = true
		}
	}
	agg.Rationale = joinRationales(rationales)
	return agg, nil
}

// callProvider invokes a provider with retry, timing the call and recording the
// latency, token usage, estimated cost (per the pricing table), and budget
// consumption. It returns the response text, usage, and estimated cost.
func (p *Pipeline) callProvider(ctx context.Context, prov Provider, req Request, tenant string) (string, Usage, float64, error) {
	start := time.Now()
	text, usage, err := p.completeWithRetry(ctx, prov, req)
	latency := time.Since(start)
	cost := p.cfg.Pricing.Cost(req.Model, usage.InputTokens, usage.OutputTokens)
	p.rec().ObserveProvider(prov.Name(), req.Model, latency, usage.InputTokens, usage.OutputTokens, cost, err == nil)
	if p.cfg.Budgeter != nil {
		p.cfg.Budgeter.Record(tenant, usage.InputTokens, usage.OutputTokens, cost)
	}
	return text, usage, cost, err
}

// budgetExhaustedVerdict produces the verdict when a tenant has exhausted its
// cost budget. Fail-open admits the pull with deterministic findings only;
// fail-closed blocks it with a synthetic critical finding.
func (p *Pipeline) budgetExhaustedVerdict(ctx context.Context, commit *Commit, secretFindings, actionFindings []Finding, injectionHits []InjectionHit, failOpen bool) *Verdict {
	p.rec().ObserveBudgetExhausted(commit.Tenant, failOpen)
	if p.cfg.OnBudgetExhausted != nil {
		p.cfg.OnBudgetExhausted(ctx, commit.Tenant, failOpen)
	}
	mode := "fail-closed (pull blocked)"
	if failOpen {
		mode = "fail-open (admitted without LLM scan)"
	}
	p.logger.Warn("tenant LLM scan budget exhausted; degrading",
		"sha", commit.SHA, "tenant", commit.Tenant, "mode", mode)

	v := p.deterministicVerdict(commit, concatFindings(secretFindings, actionFindings), "scan budget exhausted: "+mode)
	if !failOpen {
		// Block: the model could not weigh in and policy chose fail-closed.
		v.Malicious = true
		v.Findings = append(v.Findings, Finding{
			Category:   CategoryOther,
			Severity:   "critical",
			Title:      "LLM scan budget exhausted (fail-closed)",
			Detail:     "the tenant's commit-scan cost ceiling was reached; per policy the pull is blocked until the budget resets or is raised",
			Confidence: 1,
		})
		if v.RiskScore < 90 {
			v.RiskScore = 90
		}
	}
	p.finalize(v, commit, secretFindings, actionFindings, injectionHits)
	return v
}

// completeWithRetry calls the provider with exponential backoff + full jitter on
// transient (retryable) errors, honoring context cancellation.
func (p *Pipeline) completeWithRetry(ctx context.Context, prov Provider, req Request) (string, Usage, error) {
	var lastErr error
	for attempt := 0; attempt <= p.cfg.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", Usage{}, err
		}
		text, usage, err := prov.Complete(ctx, req)
		if err == nil {
			return text, usage, nil
		}
		lastErr = err
		if !IsRetryable(err) {
			return "", usage, err
		}
		if attempt == p.cfg.MaxRetries {
			break
		}
		delay := backoff(p.cfg.RetryBaseDelay, attempt)
		p.logger.Debug("retrying provider call after transient error",
			"attempt", attempt+1, "delay", delay, "error", err)
		select {
		case <-ctx.Done():
			return "", Usage{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	return "", Usage{}, fmt.Errorf("commit: provider failed after %d attempts: %w", p.cfg.MaxRetries+1, lastErr)
}

// backoff computes an exponential delay with full jitter, capped at 30s.
func backoff(base time.Duration, attempt int) time.Duration {
	const maxDelay = 30 * time.Second
	d := base << attempt
	if d <= 0 || d > maxDelay {
		d = maxDelay
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}

// mergeVerdict folds src into dst: risk is the max, malicious is sticky, and
// findings accumulate.
func mergeVerdict(dst, src *Verdict) {
	if src.RiskScore > dst.RiskScore {
		dst.RiskScore = src.RiskScore
	}
	if src.Malicious {
		dst.Malicious = true
	}
	dst.Findings = append(dst.Findings, src.Findings...)
	if src.Truncated {
		dst.Truncated = true
	}
}

// Start launches the asynchronous scan workers. It is idempotent. Workers run
// until ctx is canceled or Close is called.
func (p *Pipeline) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		for i := 0; i < p.cfg.Workers; i++ {
			p.wg.Add(1)
			go p.worker(ctx)
		}
		if p.cfg.RetentionTTL > 0 {
			p.wg.Add(1)
			go p.retentionLoop(ctx)
			p.logger.Info("commit verdict retention enabled",
				"ttl", p.cfg.RetentionTTL, "interval", p.cfg.RetentionInterval)
		}
		p.logger.Info("commit scan workers started", "workers", p.cfg.Workers)
	})
}

// retentionLoop periodically prunes cached verdicts older than RetentionTTL,
// complementing the content-cache retention engine (Task 39) so the verdict
// store does not grow unbounded. It runs until ctx is canceled or Close is
// called.
func (p *Pipeline) retentionLoop(ctx context.Context) {
	defer p.wg.Done()
	t := time.NewTicker(p.cfg.RetentionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stop:
			return
		case <-t.C:
			n, err := p.Prune(ctx)
			if err != nil {
				p.logger.Error("commit verdict retention sweep failed", "error", err)
				continue
			}
			if n > 0 {
				p.logger.Info("pruned expired commit verdicts", "count", n, "ttl", p.cfg.RetentionTTL)
			}
		}
	}
}

// Prune evicts cached verdicts older than the configured RetentionTTL and
// returns the number removed. It is also invoked on demand from the admin API.
// With no RetentionTTL configured it is a no-op.
func (p *Pipeline) Prune(ctx context.Context) (int, error) {
	if p.cfg.RetentionTTL <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-p.cfg.RetentionTTL)
	return p.store.Prune(ctx, cutoff)
}

// worker drains the async queue, scanning each commit and persisting the result.
func (p *Pipeline) worker(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stop:
			return
		case commit := <-p.queue:
			if commit == nil {
				continue
			}
			if _, err := p.Scan(ctx, commit); err != nil {
				p.logger.Error("async commit scan failed", "sha", commit.SHA, "error", err)
			}
			p.clearPending(commit.SHA)
		}
	}
}

// Submit enqueues a commit for asynchronous scanning. It returns true if the
// commit was accepted (or is already scanned/queued), and false if the queue is
// full. It never blocks. Use Scan for synchronous results.
func (p *Pipeline) Submit(ctx context.Context, commit *Commit) bool {
	if commit == nil || commit.SHA == "" {
		return false
	}
	// Skip work already done.
	if _, err := p.store.Get(ctx, commit.SHA); err == nil {
		return true
	}
	if !p.markPending(commit.SHA) {
		return true // already queued or in-flight
	}
	select {
	case p.queue <- commit:
		return true
	default:
		p.clearPending(commit.SHA)
		return false
	}
}

// markPending records sha as queued; it returns false if it was already pending.
func (p *Pipeline) markPending(sha string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.pending[sha]; ok {
		return false
	}
	p.pending[sha] = struct{}{}
	return true
}

func (p *Pipeline) clearPending(sha string) {
	p.mu.Lock()
	delete(p.pending, sha)
	p.mu.Unlock()
}

// Close stops the async workers and waits for in-flight scans to finish. It does
// not close the underlying store (the owner does that).
func (p *Pipeline) Close() error {
	p.stopOnce.Do(func() { close(p.stop) })
	p.wg.Wait()
	return nil
}

func trimRationale(s string) string {
	const max = 280
	s = collapseSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

func joinRationales(rs []string) string {
	switch len(rs) {
	case 0:
		return ""
	case 1:
		return rs[0]
	}
	out := rs[0]
	for _, r := range rs[1:] {
		if r != "" && r != out {
			out += " " + r
		}
	}
	return trimRationale(out)
}

func collapseSpace(s string) string {
	var b []byte
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\t' || c == '\r' {
			c = ' '
		}
		if c == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		b = append(b, c)
	}
	// trim
	start, end := 0, len(b)
	for start < end && b[start] == ' ' {
		start++
	}
	for end > start && b[end-1] == ' ' {
		end--
	}
	return string(b[start:end])
}
