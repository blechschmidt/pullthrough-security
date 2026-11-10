package otlplog

import (
	"context"
	"log/slog"
	"runtime"
	"strconv"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// HandlerOptions configures the OTLP tee handler.
type HandlerOptions struct {
	// ForwardLevel is the minimum level a record must meet to be exported over
	// OTLP. It is independent of the inner handler's own level, so an operator
	// can log everything to stderr while forwarding only warnings and above to
	// the collector. The zero value (slog.LevelInfo, which is 0) forwards info
	// and above.
	ForwardLevel slog.Level
	// AddSource attaches code.filepath/code.function/code.lineno attributes to
	// each exported record (mirrors slog's AddSource for the stderr handler).
	AddSource bool
	// Now overrides the clock for the ObservedTime stamp (tests).
	Now func() time.Time
}

// Handler is an slog.Handler that decorates an inner handler (the process's
// JSON/text stderr handler): every record is still handled by the inner handler
// exactly as before and, when it meets ForwardLevel, additionally projected into
// an OTLP LogRecord — correlated with the active trace/span ids from the record's
// context — and enqueued on the Forwarder for asynchronous OTLP export.
//
// A nil *Handler is a valid no-op; NewHandler returns the inner handler
// unchanged when the forwarder is nil so a disabled pipeline adds nothing to the
// logging path.
type Handler struct {
	inner        slog.Handler
	fwd          *Forwarder
	forwardLevel slog.Level
	addSource    bool
	now          func() time.Time

	// groups is the chain of currently-open groups applied to record attrs; goups
	// is the dotted prefix derived from it. preformatted holds attrs added via
	// WithAttrs, already flattened with their group prefix.
	groups       []string
	preformatted []Attr
}

// NewHandler wraps inner so records are both handled normally and forwarded over
// OTLP via fwd. When fwd is nil (OTLP log export disabled) it returns inner
// unchanged, so there is zero overhead on the logging path.
func NewHandler(inner slog.Handler, fwd *Forwarder, opts HandlerOptions) slog.Handler {
	if fwd == nil {
		return inner
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Handler{
		inner:        inner,
		fwd:          fwd,
		forwardLevel: opts.ForwardLevel,
		addSource:    opts.AddSource,
		now:          now,
	}
}

// Enabled defers to the inner handler so the tee never suppresses a record the
// stderr handler would have emitted. OTLP forwarding applies its own
// ForwardLevel floor inside Handle.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle writes the record to the inner handler and, when it meets ForwardLevel,
// projects it into an OTLP LogRecord and enqueues it for export. A forwarding
// failure never affects the inner result.
func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	err := h.inner.Handle(ctx, rec)
	if rec.Level >= h.forwardLevel {
		h.fwd.Enqueue(h.buildRecord(ctx, rec))
	}
	return err
}

// buildRecord projects an slog.Record into an OTLP LogRecord, flattening grouped
// attributes and binding the active trace/span ids from ctx.
func (h *Handler) buildRecord(ctx context.Context, rec slog.Record) LogRecord {
	attrs := make([]Attr, 0, len(h.preformatted)+rec.NumAttrs())
	attrs = append(attrs, h.preformatted...)
	rec.Attrs(func(a slog.Attr) bool {
		attrs = flattenAttr(attrs, h.groups, a)
		return true
	})
	if h.addSource {
		attrs = appendSource(attrs, rec.PC)
	}

	lr := LogRecord{
		Time:           rec.Time,
		ObservedTime:   h.now(),
		SeverityNumber: severityNumber(rec.Level),
		SeverityText:   severityText(rec.Level),
		Body:           rec.Message,
		Attributes:     attrs,
	}
	sc := tracing.SpanContextFromContext(ctx)
	if sc.TraceID.IsValid() {
		lr.TraceID = tracing.TraceIDFromContext(ctx)
		lr.SpanID = tracing.SpanIDFromContext(ctx)
		lr.Flags = uint32(sc.TraceFlags)
	}
	return lr
}

// WithAttrs returns a handler whose records carry the supplied attrs. The attrs
// are applied to both the inner handler (for stderr) and the OTLP projection
// (flattened with the current group prefix).
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	pre := make([]Attr, len(h.preformatted), len(h.preformatted)+len(attrs))
	copy(pre, h.preformatted)
	for _, a := range attrs {
		pre = flattenAttr(pre, h.groups, a)
	}
	return &Handler{
		inner:        h.inner.WithAttrs(attrs),
		fwd:          h.fwd,
		forwardLevel: h.forwardLevel,
		addSource:    h.addSource,
		now:          h.now,
		groups:       h.groups,
		preformatted: pre,
	}
}

// WithGroup opens a nested group whose name prefixes subsequent attribute keys
// in both the inner handler and the OTLP projection.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	groups := make([]string, len(h.groups), len(h.groups)+1)
	copy(groups, h.groups)
	groups = append(groups, name)
	return &Handler{
		inner:        h.inner.WithGroup(name),
		fwd:          h.fwd,
		forwardLevel: h.forwardLevel,
		addSource:    h.addSource,
		now:          h.now,
		groups:       groups,
		preformatted: h.preformatted,
	}
}

// flattenAttr appends a (possibly grouped) slog.Attr to out, prefixing its key
// with the dotted group chain. Group-valued attrs are recursed into; empty
// groups and empty-key attrs are dropped, matching slog's own rules.
func flattenAttr(out []Attr, groups []string, a slog.Attr) []Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		if len(attrs) == 0 {
			return out
		}
		sub := groups
		if a.Key != "" {
			sub = append(append([]string(nil), groups...), a.Key)
		}
		for _, ga := range attrs {
			out = flattenAttr(out, sub, ga)
		}
		return out
	}
	if a.Key == "" {
		return out
	}
	return append(out, Attr{Key: joinKey(groups, a.Key), Value: attrValue(a.Value)})
}

// joinKey builds a dotted attribute key from the open group chain and a leaf key.
func joinKey(groups []string, key string) string {
	if len(groups) == 0 {
		return key
	}
	n := len(key)
	for _, g := range groups {
		n += len(g) + 1
	}
	buf := make([]byte, 0, n)
	for _, g := range groups {
		buf = append(buf, g...)
		buf = append(buf, '.')
	}
	buf = append(buf, key...)
	return string(buf)
}

// attrValue converts an slog.Value into one of the OTLP AnyValue scalar Go types
// (string, int64, bool, float64), rendering anything else as its string form.
func attrValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return int64(v.Uint64())
	case slog.KindBool:
		return v.Bool()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	default:
		return v.String()
	}
}

// appendSource adds the standard OTLP code.* attributes for the call site.
func appendSource(out []Attr, pc uintptr) []Attr {
	if pc == 0 {
		return out
	}
	fs := runtime.CallersFrames([]uintptr{pc})
	f, _ := fs.Next()
	if f.File == "" {
		return out
	}
	out = append(out, Attr{Key: "code.filepath", Value: f.File})
	out = append(out, Attr{Key: "code.lineno", Value: strconv.Itoa(f.Line)})
	if f.Function != "" {
		out = append(out, Attr{Key: "code.function", Value: f.Function})
	}
	return out
}
