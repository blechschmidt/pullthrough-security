package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// buildApprovals constructs the human-in-the-loop quarantine-review & break-glass
// approval workflow (Task 50) when enabled. Every state change is recorded to the
// tamper-evident audit log (linked into the Merkle chain) and surfaced as a
// notification event; the request store is persisted to approvals.storePath when
// set so pending reviews and active grants survive a restart. It returns nil when
// disabled, in which case the admission gates block unconditionally and the
// admin/metrics surfaces report it absent.
func buildApprovals(cfg *config.Config, auditLog *audit.Logger, notifier *notify.Notifier, logger *slog.Logger) (*approvals.Service, error) {
	ac := cfg.Approvals
	if !ac.Enabled {
		logger.Info("quarantine-review / break-glass approval workflow disabled (set approvals.enabled to let operators grant time-boxed exceptions to gate blocks)")
		return nil, nil
	}
	svc, err := approvals.New(approvals.Config{
		Enabled:           true,
		RequiredApprovers: ac.RequiredApprovers,
		GrantTTL:          ac.GrantTTL,
		RequestTTL:        ac.RequestTTL,
		MaxRequests:       ac.MaxRequests,
		StorePath:         ac.StorePath,
	}, logger,
		approvals.WithAudit(auditLog),
		approvals.WithNotifier(notifyEmitter(notifier)),
	)
	if err != nil {
		return nil, err
	}
	snap := svc.Snapshot()
	logger.Info("quarantine-review / break-glass approval workflow enabled",
		"requiredApprovers", snap.RequiredApprovers,
		"grantTtl", time.Duration(snap.GrantTTLSeconds)*time.Second,
		"requestTtl", time.Duration(snap.RequestTTLSeconds)*time.Second,
		"persisted", ac.StorePath != "")
	return svc, nil
}

// startApprovalsSweeper runs the background loop that revokes break-glass grants
// whose TTL has elapsed (re-quarantine) and expires stale pending reviews, so an
// expiry is reconciled even for an artifact that is never re-pulled. It returns a
// stop function. A nil service or non-positive interval is a no-op.
func startApprovalsSweeper(ctx context.Context, svc *approvals.Service, interval time.Duration, logger *slog.Logger) func() {
	if svc == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = time.Minute
	}
	loopCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				if n := svc.Sweep(loopCtx); n > 0 {
					logger.Debug("approvals: sweep reconciled expirations", "changed", n)
				}
			}
		}
	}()
	return cancel
}
