package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
)

// buildRebuildVerify constructs the reproducible-build verification gate (Task
// 68) from configuration. It returns (nil, nil) when disabled. The source
// repository locator reuses the air-gap-aware mirror clone mechanism from the
// repo-health subsystem (Task 63). The default registry of toolchain-gated stub
// builders is used unless an operator embeds a real sandboxed builder.
func buildRebuildVerify(cfg *config.Config, notifier *notify.Notifier, logger *slog.Logger) (*rebuildverify.Service, error) {
	rc := cfg.RebuildVerify
	if !rc.Enabled {
		logger.Info("reproducible-build verification disabled (set rebuildVerify.enabled to rebuild artifacts from source and compare digests)")
		return nil, nil
	}

	mode := rebuildverify.ModeObserve
	if m, ok := rebuildverify.ParseMode(rc.Mode); ok {
		mode = m
	}
	async := true
	if rc.Async != nil {
		async = *rc.Async
	}

	cacheDir := strings.TrimSpace(rc.RepoCacheDir)
	if cacheDir == "" {
		base := strings.TrimSpace(cfg.Cache.Dir)
		if base == "" {
			base = "."
		}
		cacheDir = filepath.Join(base, "rebuildverify")
	}
	locator, err := reposcore.NewMirrorLocator(reposcore.MirrorLocatorOptions{
		Root:         cacheDir,
		GitBinary:    rc.GitBinary,
		AllowFetch:   rc.AllowFetch,
		Depth:        rc.CloneDepth,
		FetchTimeout: rc.FetchTimeout,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("rebuild-verify: %w", err)
	}

	tenants := make(map[string]rebuildverify.TenantConfig)
	for t, tc := range rc.Tenants {
		if strings.TrimSpace(tc.Mode) == "" {
			continue
		}
		if m, ok := rebuildverify.ParseMode(tc.Mode); ok {
			tenants[t] = rebuildverify.TenantConfig{Mode: m}
		}
	}

	// On an async-completed (or synchronous) confirmed mismatch, alert: the build
	// completes off the request path, so this hook is the notification point for
	// the detection (the gate additionally notifies on an enforce-mode quarantine).
	emitter := notifyEmitter(notifier)
	onResult := func(res rebuildverify.Result) {
		if res.Verdict != rebuildverify.VerdictMismatch {
			return
		}
		logger.Warn("reproducible-build verification detected a mismatch",
			"ecosystem", res.Ecosystem, "coordinate", res.Coordinate, "commit", res.CommitSHA,
			"upstreamDigest", res.UpstreamDigest, "rebuiltDigest", res.RebuiltDigest)
		if emitter != nil {
			emitter.Emit(context.Background(), notify.RebuildVerifyEvent(
				res.Ecosystem, "", res.Coordinate, res.CommitSHA, res.UpstreamDigest, res.RebuiltDigest, "mismatch", res.Reason))
		}
	}

	svc, err := rebuildverify.NewService(rebuildverify.Config{
		Enabled:       true,
		Mode:          mode,
		Async:         async,
		MaxConcurrent: rc.MaxConcurrent,
		BuildTimeout:  rc.BuildTimeout,
		CacheSize:     rc.CacheSize,
		RecentSize:    rc.RecentSize,
		Tenants:       tenants,
		Locator:       locator,
		OnResult:      onResult,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("rebuild-verify: %w", err)
	}

	logger.Info("reproducible-build verification enabled",
		"mode", mode, "async", async, "allowFetch", rc.AllowFetch,
		"repoCacheDir", cacheDir, "builders", svc.Builders(), "tenantOverrides", len(tenants))
	return svc, nil
}
