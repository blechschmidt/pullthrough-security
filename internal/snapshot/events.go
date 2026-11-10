package snapshot

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// Option customizes a Service at construction.
type Option func(*Service)

// WithAudit attaches the tamper-evident audit logger so snapshot lifecycle
// actions (capture / freeze / unfreeze / rollback) are recorded into the Merkle
// transparency log — the captured state and the org-wide freeze decisions become
// independently verifiable. A nil logger is a no-op.
func WithAudit(l *audit.Logger) Option {
	return func(s *Service) { s.audit = l }
}

// WithNotifier attaches the notification emitter so snapshot lifecycle actions
// raise EventSnapshot alerts to the configured sinks. A nil emitter is a no-op.
func WithNotifier(n notify.Emitter) Option {
	return func(s *Service) { s.notifier = n }
}

// recordAudit appends a snapshot lifecycle action to the Merkle audit log. The
// action's content digest (for a capture) or target snapshot id (for a
// freeze/rollback) anchors the state into the tamper-evident chain.
func (s *Service) recordAudit(action, by, reason string, detail map[string]any) {
	if s == nil || s.audit == nil {
		return
	}
	ev := audit.Event{
		Type:     audit.EventSnapshot,
		Subject:  by,
		Decision: audit.DecisionAllow,
		Reason:   "snapshot:" + action,
		Detail:   detail,
	}
	if err := s.audit.Log(context.Background(), ev); err != nil {
		s.logger.Warn("snapshot: recording audit event failed", "action", action, "error", err)
	}
}

// emitNotify raises a snapshot lifecycle notification.
func (s *Service) emitNotify(ev notify.Event) {
	if s == nil || s.notifier == nil {
		return
	}
	s.notifier.Emit(context.Background(), ev)
}
