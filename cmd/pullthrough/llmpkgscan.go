package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// buildLLMPkgScan constructs the sandboxed LLM package-content scan gate (Task
// 173) from configuration. It returns (nil, no-op closer, nil) when disabled.
//
// The provider is built with the same constructors as the commit scanner's —
// the gate adds no LLM client of its own — and, when llmPackageScan.provider is
// left empty, with the commit scanner's provider, key and endpoint. No provider
// connection is made at startup: the gate degrades per its fail mode when the
// provider is unreachable, so construction only validates configuration.
func buildLLMPkgScan(cfg *config.Config, auditLog *audit.Logger, notifier *notify.Notifier, logger *slog.Logger) (*llmpkgscan.Service, func() error, error) {
	noop := func() error { return nil }
	if !cfg.LLMPackageScan.Enabled {
		logger.Info("LLM package-content scan gate disabled (set llmPackageScan.enabled with an LLM provider to have a model review package contents before they are served)")
		return nil, noop, nil
	}
	lc := cfg.EffectiveLLMPackageScan()

	provider, model, canThink, err := llmPkgScanProvider(lc)
	if err != nil {
		return nil, noop, err
	}
	thinking := canThink
	if lc.Thinking != nil {
		thinking = *lc.Thinking
	}

	var store llmpkgscan.VerdictStore
	if dir := strings.TrimSpace(lc.StoreDir); dir != "" {
		fs, serr := llmpkgscan.NewFileStore(dir)
		if serr != nil {
			return nil, noop, fmt.Errorf("opening llmPackageScan.storeDir: %w", serr)
		}
		store = fs
	} else {
		logger.Warn("LLM package-content scan verdicts are kept in memory only (llmPackageScan.storeDir is empty): every artifact is scanned, and paid for, again after a restart")
	}

	pricing := commit.DefaultPricing()
	if len(lc.Budget.Pricing) > 0 {
		pricing = pricing.WithOverrides(modelPriceOverrides(lc.Budget.Pricing))
	}

	failMode := llmpkgscan.FailMode(strings.ToLower(strings.TrimSpace(lc.FailMode)))
	gcfg := llmpkgscan.Config{
		Enabled:             true,
		Provider:            provider,
		Model:               model,
		Mode:                llmpkgscan.Mode(strings.ToLower(strings.TrimSpace(lc.Mode))),
		Thinking:            thinking,
		Action:              llmpkgscan.Action(strings.ToLower(strings.TrimSpace(lc.Action))),
		FailMode:            failMode,
		MaliciousThreshold:  lc.MaliciousThreshold,
		SuspiciousThreshold: lc.SuspiciousThreshold,
		Timeout:             lc.Timeout,
		Limits: llmpkgscan.Limits{
			MaxArtifactBytes:    lc.Limits.MaxArtifactBytes,
			MaxUnpackedBytes:    lc.Limits.MaxUnpackedBytes,
			MaxFileBytes:        lc.Limits.MaxFileBytes,
			MaxFiles:            lc.Limits.MaxFiles,
			MaxDepth:            lc.Limits.MaxDepth,
			MaxCompressionRatio: lc.Limits.MaxCompressionRatio,
			MaxPromptBytes:      lc.Limits.MaxPromptBytes,
			MaxToolResultBytes:  lc.Limits.MaxToolResultBytes,
			MaxToolBytes:        lc.Limits.MaxToolBytes,
			MaxTurns:            lc.Limits.MaxTurns,
			MaxToolCalls:        lc.Limits.MaxToolCalls,
			MaxOutputTokens:     lc.Limits.MaxOutputTokens,
			MaxTotalTokens:      lc.Limits.MaxTotalTokens,
		},
		Include:          lc.Include,
		Exclude:          lc.Exclude,
		ExcludeUpstreams: lc.ExcludeUpstreams,
		Budget: llmpkgscan.BudgetConfig{
			Enabled:           lc.Budget.Enabled,
			GlobalCeilingUSD:  lc.Budget.GlobalCeilingUSD,
			TenantCeilingUSD:  lc.Budget.TenantCeilingUSD,
			TenantCeilingsUSD: lc.Budget.TenantCeilingsUSD,
			Window:            lc.Budget.Window,
		},
		Pricing:           pricing,
		Store:             store,
		CacheTTL:          lc.CacheTTL,
		ErrorTTL:          lc.ErrorTTL,
		MaxConcurrent:     lc.MaxConcurrent,
		MaxRetries:        lc.MaxRetries,
		OnVerdict:         llmPkgScanVerdictRecorder(auditLog, logger),
		OnBudgetExhausted: llmPkgScanBudgetNotifier(notifier, failMode != llmpkgscan.FailClosed, logger),
		Logger:            logger,
	}
	svc, err := llmpkgscan.NewService(gcfg)
	if err != nil {
		if store != nil {
			_ = store.Close()
		}
		return nil, noop, err
	}
	closer := func() error {
		cerr := svc.Close()
		if store != nil {
			if serr := store.Close(); cerr == nil {
				cerr = serr
			}
		}
		return cerr
	}

	st := svc.Status()
	logger.Info("LLM package-content scan gate enabled",
		"provider", st.Provider, "model", st.Model, "toolUse", st.ToolUse, "thinking", st.Thinking,
		"action", st.Action, "failMode", st.FailMode, "ecosystems", st.Ecosystems, "excludedUpstreams", st.ExcludedUpstreams,
		"timeout", lc.Timeout, "budget", lc.Budget.Enabled, "persistent", store != nil)
	if !lc.Budget.Enabled || (lc.Budget.GlobalCeilingUSD <= 0 && lc.Budget.TenantCeilingUSD <= 0 && len(lc.Budget.TenantCeilingsUSD) == 0) {
		logger.Warn("LLM package-content scan has no cost ceiling (llmPackageScan.budget): every distinct artifact a client pulls is a paid scan, so spend is bounded only by what clients request")
	}
	return svc, closer, nil
}

// llmPkgScanProvider builds the LLM provider for the gate and resolves the
// model to use. canThink reports whether extended reasoning should default on
// for that model: for Claude, when the model is one known to support adaptive
// thinking (sending the parameter to a model without it is a hard 400); for an
// OpenAI-compatible endpoint, when a reasoning effort has been configured.
func llmPkgScanProvider(lc config.LLMPackageScanConfig) (provider commit.Provider, model string, canThink bool, err error) {
	model = strings.TrimSpace(lc.Model)
	// Provider-side retries are bounded by the gate's own setting; a negative
	// value disables them at both layers.
	switch lc.Provider {
	case "claude":
		if model == "" {
			model = string(commit.DefaultDeepModel)
		}
		p, perr := commit.NewClaudeProvider(commit.ClaudeOptions{
			APIKey:     lc.APIKey,
			BaseURL:    strings.TrimSpace(lc.BaseURL),
			MaxRetries: lc.MaxRetries,
		})
		if perr != nil {
			return nil, "", false, fmt.Errorf("building claude provider for llmPackageScan: %w", perr)
		}
		return p, model, commit.SupportsAdaptiveThinking(model), nil
	case "openai", "codex":
		if model == "" {
			model = commit.DefaultOpenAIDeepModel
		}
		p, perr := commit.NewOpenAIProvider(commit.OpenAIOptions{
			APIKey:          lc.APIKey,
			BaseURL:         strings.TrimSpace(lc.BaseURL),
			APIVersion:      strings.TrimSpace(lc.APIVersion),
			ReasoningEffort: strings.TrimSpace(lc.ReasoningEffort),
			Timeout:         lc.RequestTimeout,
			MaxRetries:      lc.MaxRetries,
		})
		if perr != nil {
			return nil, "", false, fmt.Errorf("building openai provider for llmPackageScan: %w", perr)
		}
		return p, model, strings.TrimSpace(lc.ReasoningEffort) != "", nil
	default:
		return nil, "", false, fmt.Errorf("unsupported llmPackageScan.provider %q (claude|openai|codex)", lc.Provider)
	}
}

// llmPkgScanVerdictRecorder returns the OnVerdict hook: every fresh verdict —
// benign ones included — is written to the tamper-evident audit log, so "this
// artifact was examined, by this model, with this result" can be proven later
// and so the spend is attributable. Pull-time decisions (served, blocked) are
// audited separately by the gateway, per request.
//
// The record carries the verdict's category and provenance, not the model's
// prose: the reasons are shaped by the package under review, and the audit log
// is forwarded to SIEMs and rendered in timelines that should not have to treat
// one of its fields as hostile. The full verdict stays in the verdict store.
func llmPkgScanVerdictRecorder(auditLog *audit.Logger, logger *slog.Logger) func(*llmpkgscan.Verdict) {
	return func(v *llmpkgscan.Verdict) {
		if v == nil {
			return
		}
		strong := 0
		for _, hit := range v.Injection {
			if hit.Strong {
				strong++
			}
		}
		verified := 0
		for _, ev := range v.Evidence {
			if ev.Verified {
				verified++
			}
		}
		coordinate := v.Name
		if v.Version != "" {
			coordinate += "@" + v.Version
		}
		level := slog.LevelInfo
		if v.Verdict != llmpkgscan.VerdictBenign || strong > 0 || v.StructuralRisk {
			level = slog.LevelWarn
		}
		logger.Log(context.Background(), level, "LLM package-content scan verdict",
			"ecosystem", v.Ecosystem, "artifact", coordinate, "digest", v.Digest,
			"verdict", v.Verdict, "confidence", v.Confidence, "model", v.Model, "mode", v.Mode,
			"turns", v.Turns, "toolCalls", v.ToolCalls, "files", v.Files, "truncated", v.Truncated,
			"injectionIndicators", strong, "structuralRisk", v.StructuralRisk,
			"costUsd", v.CostUSD, "durationMs", v.DurationMS)
		if auditLog == nil {
			return
		}
		decision := audit.DecisionAllow
		if v.Verdict != llmpkgscan.VerdictBenign {
			decision = audit.DecisionDeny
		}
		if err := auditLog.Log(context.Background(), audit.Event{
			Type:      audit.EventScanVerdict,
			Team:      v.Tenant,
			Ecosystem: v.Ecosystem,
			Resource:  v.Ecosystem + "/" + coordinate,
			Decision:  decision,
			Reason:    "llmpkgscan:" + v.Verdict,
			Detail: map[string]any{
				"trigger":             "llm-package-scan",
				"digest":              v.Digest,
				"verdictKey":          v.Key,
				"verdict":             v.Verdict,
				"confidence":          v.Confidence,
				"provider":            v.Provider,
				"model":               v.Model,
				"promptVersion":       v.PromptVersion,
				"mode":                v.Mode,
				"turns":               v.Turns,
				"toolCalls":           v.ToolCalls,
				"files":               v.Files,
				"truncated":           v.Truncated,
				"evidence":            len(v.Evidence),
				"verifiedEvidence":    verified,
				"injectionIndicators": strong,
				"structuralRisk":      v.StructuralRisk,
				"inputTokens":         v.InputTokens,
				"outputTokens":        v.OutputTokens,
				"costUsd":             v.CostUSD,
			},
		}); err != nil {
			logger.Error("LLM package-content scan audit log failed", "artifact", coordinate, "error", err)
		}
	}
}

// llmPkgScanBudgetNotifier returns the OnBudgetExhausted hook. The gate calls
// it once per scope and tenant per budget window, not once per denied pull.
func llmPkgScanBudgetNotifier(n *notify.Notifier, failOpen bool, logger *slog.Logger) func(scope, tenant string) {
	return func(scope, tenant string) {
		logger.Warn("LLM package-content scan budget exhausted; artifacts are not being scanned until the window resets",
			"scope", scope, "tenant", tenant, "failOpen", failOpen)
		if n != nil {
			n.Emit(context.Background(), notify.LLMPackageBudgetEvent(scope, tenant, failOpen))
		}
	}
}
