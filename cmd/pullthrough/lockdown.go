package main

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// buildLockdown constructs the emergency-lockdown / global kill-switch incident-
// response control (Task 74) from config. It returns nil when disabled. The state
// file defaults to <cache.dir>/lockdown.json so a lockdown survives a restart;
// transitions are recorded to the Merkle audit log, raised as EventLockdown
// notifications, and tagged with the coordination guard's fencing token (Task 56)
// so incident-mode changes are ordered across an HA cluster.
func buildLockdown(cfg *config.Config, auditLog *audit.Logger, notifier *notify.Notifier, coordGuard lockdown.Coordinator, logger *slog.Logger) (*lockdown.Service, error) {
	lc := cfg.Lockdown
	if !lc.Enabled {
		logger.Info("emergency-lockdown control disabled (set lockdown.enabled to expose the global kill-switch)")
		return nil, nil
	}

	storePath := strings.TrimSpace(lc.StorePath)
	if storePath == "" && strings.TrimSpace(cfg.Cache.Dir) != "" {
		storePath = filepath.Join(cfg.Cache.Dir, "lockdown.json")
	}

	opts := []lockdown.Option{}
	if auditLog != nil {
		opts = append(opts, lockdown.WithAudit(auditLog))
	}
	if notifier != nil {
		opts = append(opts, lockdown.WithNotifier(notifier))
	}
	if coordGuard != nil {
		opts = append(opts, lockdown.WithCoordinator(coordGuard))
	}

	svc, err := lockdown.New(lockdown.Config{
		Enabled:    true,
		StorePath:  storePath,
		DefaultTTL: lc.DefaultTTL,
		MaxTTL:     lc.MaxTTL,
	}, logger, opts...)
	if err != nil {
		return nil, fmt.Errorf("lockdown: %w", err)
	}
	st := svc.Status()
	logger.Info("emergency-lockdown control enabled (global kill-switch)",
		"store", dirOrMemory(storePath),
		"defaultTtl", lc.DefaultTTL,
		"maxTtl", lc.MaxTTL,
		"active", st.Active,
		"mode", st.Mode)
	return svc, nil
}
