// Package otlplog is a self-contained, dependency-free OpenTelemetry logs
// signal: it exports the proxy's structured operational logs (every slog record
// the process emits) to an OTLP collector over OTLP/HTTP, correlated with the
// active trace and span ids so a log line and the span it was emitted under join
// up in backends such as Grafana Tempo/Loki, Jaeger, or an OpenTelemetry
// Collector fanning out to both.
//
// It complements, rather than duplicates, two existing subsystems:
//
//   - internal/tracing (Task 41) exports the *traces* signal with the same
//     hand-rolled OTLP/HTTP protobuf-JSON encoding and bounded async batch
//     processor. This package reuses that house style for the *logs* signal
//     (there is no official OpenTelemetry-Go SDK dependency anywhere in the
//     codebase, by deliberate design), and reuses tracing.TraceIDFromContext /
//     SpanIDFromContext for the trace/span correlation.
//   - internal/siem (Tasks 119/139) forwards *audit events and gate findings*
//     to SIEMs. This package forwards *operational logs* and mirrors the siem
//     forwarder's resilience design: a bounded in-memory queue drained by a
//     single dispatcher goroutine that batches, retries with exponential
//     backoff, and overflows to a bounded, restart-surviving disk spill, never
//     blocking the caller (a slow or unreachable collector drops logs rather
//     than stalling the code that is logging).
//
// The tap is an slog.Handler (see handler.go) that decorates the process's
// existing JSON/text handler: every record is still written to stderr as before
// and, in addition, projected into an OTLP LogRecord and enqueued for export. A
// nil *Forwarder and a nil *Handler are valid no-ops, so OTLP log export — off
// by default — adds nothing to the logging path when no collector is configured.
package otlplog

import (
	"log/slog"
	"time"
)

// Attr is a single log-record or resource attribute. Values are one of string,
// int64, bool, or float64; any other type is rendered as its string form at
// export time. It mirrors internal/tracing.Attr so the two signals encode
// attributes identically on the wire.
type Attr struct {
	Key   string
	Value any
}

// String constructs a string-valued attribute.
func String(key, value string) Attr { return Attr{Key: key, Value: value} }

// LogRecord is the immutable projection of one slog.Record handed to the
// exporter. Timestamps are wall-clock; the exporter renders them as the OTLP
// *UnixNano string fields. TraceID/SpanID are lowercase hex (empty when the
// record was emitted outside a span), matching the OTLP/JSON id encoding.
type LogRecord struct {
	// Time is when the event occurred (slog.Record.Time). Zero is allowed and
	// encodes as the absent timeUnixNano field.
	Time time.Time
	// ObservedTime is when the logging pipeline observed the event. Defaults to
	// Time when the handler does not set it explicitly.
	ObservedTime time.Time
	// SeverityNumber is the OTLP severity number (1..24); see severityNumber.
	SeverityNumber int
	// SeverityText is the original textual level (e.g. "INFO", "WARN", "ERROR").
	SeverityText string
	// Body is the log message (slog.Record.Message).
	Body string
	// Attributes are the record's structured key/value fields, flattened with
	// group prefixes applied (e.g. "req.method").
	Attributes []Attr
	// TraceID and SpanID correlate the record to the active span, lowercase hex.
	TraceID string
	SpanID  string
	// Flags carries the W3C trace flags (bit 0 = sampled) when a trace is active.
	Flags uint32
}

// OTLP severity numbers. The spec partitions 1..24 into six ranges of four:
// TRACE 1-4, DEBUG 5-8, INFO 9-12, WARN 13-16, ERROR 17-20, FATAL 21-24.
const (
	severityTrace = 1
	severityDebug = 5
	severityInfo  = 9
	severityWarn  = 13
	severityError = 17
	severityFatal = 21
	severityMax   = 24
)

// severityNumber maps an slog.Level to an OTLP severity number. slog's anchor
// levels (DEBUG=-4, INFO=0, WARN=4, ERROR=8) are spaced four apart, exactly like
// the OTLP range bases, so the identity "number = level + 9" places each anchor
// at the base of its OTLP range (DEBUG→5, INFO→9, WARN→13, ERROR→17) and maps
// slog's fractional levels (e.g. INFO+2) linearly within the range. The result
// is clamped to the valid [1,24] band so an extreme custom level never produces
// an out-of-range number.
func severityNumber(level slog.Level) int {
	n := int(level) + severityInfo
	if n < severityTrace {
		return severityTrace
	}
	if n > severityMax {
		return severityMax
	}
	return n
}

// severityText returns the textual severity for a level, reusing slog's own
// rendering ("DEBUG", "INFO", "WARN", "ERROR", and "INFO+2"-style forms for
// levels between the anchors).
func severityText(level slog.Level) string {
	return level.String()
}
