package main

import (
	"context"
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// cacheIntegrityObserver reacts to a detected cache content-integrity violation
// (Task 107). The IntegrityCache has already quarantined the corrupted entry
// before this runs; the observer records a tamper-evident audit event and emits
// an operator notification. Self-healing is implicit: with the poisoned entry
// removed, the next pull transparently re-fetches a clean copy from upstream.
type cacheIntegrityObserver struct {
	audit    *audit.Logger
	notifier notify.Emitter
	severity notify.Severity
	logger   *slog.Logger
	// repairPinned, when set, is given every corrupted key: a key a release
	// pinned (Task 180) is fetched again at once, or an alert raised. It
	// reports whether the key was pinned.
	repairPinned func(key string) bool
}

// newCacheIntegrityObserver builds the audit+notify observer. A nil audit logger
// or notifier is tolerated (both are safe no-ops), so this works regardless of
// which observability subsystems are enabled.
func newCacheIntegrityObserver(auditLog *audit.Logger, notifier notify.Emitter, severity string, logger *slog.Logger) *cacheIntegrityObserver {
	return &cacheIntegrityObserver{
		audit:    auditLog,
		notifier: notifier,
		severity: notify.NormalizeSeverity(severity),
		logger:   logger,
	}
}

// OnCorruption implements cache.IntegrityObserver.
func (o *cacheIntegrityObserver) OnCorruption(ctx context.Context, ev cache.CorruptionEvent) {
	if o.audit != nil {
		_ = o.audit.Log(ctx, audit.Event{
			Type:     audit.EventCache,
			Decision: audit.DecisionError,
			Reason:   "integrity:corruption",
			Resource: ev.Key,
			Detail: map[string]any{
				"action":      "quarantine",
				"expected":    ev.Expected,
				"computed":    ev.Computed,
				"size":        ev.Size,
				"origin":      ev.Origin,
				"contentType": ev.ContentType,
				"source":      ev.Source,
				"quarantined": ev.Quarantined,
			},
		})
	}
	pinned := false
	if o.repairPinned != nil {
		pinned = o.repairPinned(ev.Key)
	}
	if o.notifier != nil {
		e := notify.CacheIntegrityEvent(
			o.severity, ev.Key, ev.Expected, ev.Computed, ev.Source, ev.Quarantined,
		).WithField("origin", ev.Origin)
		if pinned {
			e = e.WithField("pinnedByRelease", "true").WithField("repair", "re-fetching")
		}
		o.notifier.Emit(ctx, e)
	}
}
