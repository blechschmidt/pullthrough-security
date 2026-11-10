package siem

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

// auditSink decorates an audit.Sink, forwarding each durably-committed record to
// a Forwarder after the inner sink has persisted it. Because the audit Logger
// computes and chains the record's hash before ever calling Append, this
// decorator is strictly read-only with respect to the hash chain: a forwarding
// tap can neither alter nor delay the integrity guarantee of the local log.
//
// The forward happens only after a successful inner Append, so the SIEM never
// sees a record that was not durably committed, and a forwarding failure (queue
// full, sink down) never affects the inner sink's result.
type auditSink struct {
	inner audit.Sink
	fwd   *Forwarder
}

// auditSinkReader additionally satisfies audit.RecordReader by delegating to the
// inner sink, so the Merkle transparency layer can still rebuild its tree across
// restarts. It is used only when the inner sink itself is a RecordReader, so the
// "optional capability" semantics of RecordReader are preserved.
type auditSinkReader struct {
	*auditSink
}

// WrapAuditSink wraps inner so that every appended record is also forwarded to
// fwd. When fwd is nil (or audit forwarding is disabled) the inner sink is
// returned unwrapped, so there is zero overhead in the common no-SIEM case. The
// returned sink preserves the inner sink's optional RecordReader capability.
func WrapAuditSink(inner audit.Sink, fwd *Forwarder) audit.Sink {
	if fwd == nil || !fwd.forwardAudit {
		return inner
	}
	base := &auditSink{inner: inner, fwd: fwd}
	if _, ok := inner.(audit.RecordReader); ok {
		return &auditSinkReader{auditSink: base}
	}
	return base
}

// Append persists the record via the inner sink, then forwards it on success.
func (s *auditSink) Append(ctx context.Context, rec audit.Record) error {
	if err := s.inner.Append(ctx, rec); err != nil {
		return err
	}
	s.fwd.ForwardAudit(rec)
	return nil
}

// Last delegates to the inner sink (chain resume).
func (s *auditSink) Last(ctx context.Context) (audit.Record, bool, error) {
	return s.inner.Last(ctx)
}

// Close delegates to the inner sink. The Forwarder is owned and closed
// separately by the caller (its lifecycle is independent of the audit sink).
func (s *auditSink) Close() error {
	return s.inner.Close()
}

// ReadAll delegates to the inner sink's RecordReader implementation.
func (s *auditSinkReader) ReadAll(ctx context.Context) ([]audit.Record, error) {
	return s.inner.(audit.RecordReader).ReadAll(ctx)
}
