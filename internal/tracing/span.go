package tracing

import (
	"context"
	"sync"
	"time"
)

// Tracer creates spans within a named instrumentation scope. A nil *Tracer is a
// valid no-op, so call sites obtained from a disabled Provider need no nil
// checks.
type Tracer struct {
	provider *Provider
	name     string
}

// SpanStartOption customizes a span at creation.
type SpanStartOption func(*spanConfig)

type spanConfig struct {
	kind  SpanKind
	attrs []Attr
}

// WithSpanKind sets the span's kind.
func WithSpanKind(k SpanKind) SpanStartOption {
	return func(c *spanConfig) { c.kind = k }
}

// WithAttributes seeds the span with initial attributes.
func WithAttributes(attrs ...Attr) SpanStartOption {
	return func(c *spanConfig) { c.attrs = append(c.attrs, attrs...) }
}

// Start begins a new span as a child of any span already in ctx, applies the
// sampler, and returns a context carrying the new span. On a nil Tracer it
// returns ctx unchanged and a nil *Span (a valid no-op).
//
// A span is always created when tracing is enabled — even when sampling drops
// it — so the W3C context continues to propagate downstream with the correct
// sampled flag; only sampled spans are recorded and exported.
func (t *Tracer) Start(ctx context.Context, name string, opts ...SpanStartOption) (context.Context, *Span) {
	if t == nil || t.provider == nil {
		return ctx, nil
	}
	cfg := spanConfig{kind: SpanKindInternal}
	for _, o := range opts {
		o(&cfg)
	}

	p := t.provider
	parent := SpanContextFromContext(ctx)

	var sc SpanContext
	sc.SpanID = p.newSpanID()
	var parentSpanID SpanID
	if parent.IsValid() {
		sc.TraceID = parent.TraceID
		sc.TraceState = parent.TraceState
		parentSpanID = parent.SpanID
	} else {
		sc.TraceID = p.newTraceID()
	}

	sampled := p.sampler.ShouldSample(SamplingParameters{
		ParentContext: parent,
		TraceID:       sc.TraceID,
		Name:          name,
		Kind:          cfg.kind,
	})
	if sampled {
		sc.TraceFlags |= FlagSampled
	}

	p.cStarted.Add(1)
	if sampled {
		p.cSampled.Add(1)
	}

	span := &Span{
		provider:  p,
		name:      name,
		sc:        sc,
		parent:    parentSpanID,
		kind:      cfg.kind,
		start:     p.clock(),
		attrs:     append([]Attr(nil), cfg.attrs...),
		recording: sampled,
	}
	return ContextWithSpanContext(ctx, sc), span
}

// Span is a single traced operation. A nil *Span is a valid no-op for every
// method, so handlers that may run without tracing need no nil checks.
type Span struct {
	provider *Provider
	name     string
	sc       SpanContext
	parent   SpanID
	kind     SpanKind
	start    time.Time

	mu        sync.Mutex
	attrs     []Attr
	status    SpanStatus
	events    []Event
	recording bool
	ended     bool
}

// SpanContext returns the span's immutable context. Safe on a nil Span.
func (s *Span) SpanContext() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return s.sc
}

// TraceID returns the lowercase-hex trace id, or "" on a nil/invalid span. It
// is the value correlated into audit-log entries.
func (s *Span) TraceID() string {
	if s == nil || !s.sc.TraceID.IsValid() {
		return ""
	}
	return encodeTraceID(s.sc.TraceID)
}

// SpanID returns the lowercase-hex span id, or "".
func (s *Span) SpanID() string {
	if s == nil || !s.sc.SpanID.IsValid() {
		return ""
	}
	return encodeSpanID(s.sc.SpanID)
}

// IsRecording reports whether the span will be exported (sampled and not yet
// ended). Callers can skip expensive attribute computation when false.
func (s *Span) IsRecording() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recording && !s.ended
}

// SetAttributes adds or appends attributes. No-op on a nil/non-recording span.
func (s *Span) SetAttributes(attrs ...Attr) {
	if s == nil || len(attrs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.recording || s.ended {
		return
	}
	s.attrs = append(s.attrs, attrs...)
}

// SetStatus records the span's terminal status. A later error status is not
// downgraded by a subsequent OK, matching OpenTelemetry semantics.
func (s *Span) SetStatus(code StatusCode, msg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.recording || s.ended {
		return
	}
	if s.status.Code == StatusError && code != StatusError {
		return
	}
	s.status = SpanStatus{Code: code, Message: msg}
}

// RecordError marks the span as errored and adds an exception event.
func (s *Span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	s.AddEvent("exception", String("exception.message", err.Error()))
	s.SetStatus(StatusError, err.Error())
}

// AddEvent appends a timestamped event. No-op on a nil/non-recording span.
func (s *Span) AddEvent(name string, attrs ...Attr) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.recording || s.ended {
		return
	}
	s.events = append(s.events, Event{Name: name, Time: s.provider.clock(), Attributes: append([]Attr(nil), attrs...)})
}

// End finalizes the span and, when sampled, enqueues it for export. It is
// idempotent. Safe on a nil Span.
func (s *Span) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	end := s.provider.clock()
	if !s.recording {
		s.mu.Unlock()
		s.provider.cEnded.Add(1)
		return
	}
	sd := SpanData{
		Name:        s.name,
		SpanContext: s.sc,
		Parent:      s.parent,
		Kind:        s.kind,
		StartTime:   s.start,
		EndTime:     end,
		Attributes:  append([]Attr(nil), s.attrs...),
		Status:      s.status,
		Events:      append([]Event(nil), s.events...),
	}
	s.mu.Unlock()

	s.provider.cEnded.Add(1)
	s.provider.enqueue(sd)
}

// --- context plumbing ---

type spanContextKey struct{}

// ContextWithSpanContext returns a copy of ctx carrying sc as the active span
// context (the value propagation reads and child spans parent from).
func ContextWithSpanContext(ctx context.Context, sc SpanContext) context.Context {
	return context.WithValue(ctx, spanContextKey{}, sc)
}

// SpanContextFromContext returns the active span context in ctx, or the zero
// (invalid) value when none is present.
func SpanContextFromContext(ctx context.Context) SpanContext {
	if ctx == nil {
		return SpanContext{}
	}
	sc, _ := ctx.Value(spanContextKey{}).(SpanContext)
	return sc
}

type activeSpanKey struct{}

// ContextWithSpan stores span as the enrichable "active" span in ctx. The
// gateway stores the root server span this way so deep handlers (auth, resolve,
// risk scoring) can add attributes to the request-level span via
// SpanFromContext without threading the *Span through every signature. Child
// spans are referenced through their returned value, not this key, so
// SpanFromContext consistently returns the request-level span.
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, activeSpanKey{}, span)
}

// SpanFromContext returns the active span stored by ContextWithSpan, or nil.
// A nil result is a valid no-op for every Span method.
func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(activeSpanKey{}).(*Span)
	return s
}

// TraceIDFromContext returns the active trace id as lowercase hex, or "" when
// no valid span context is present. The gateway uses it to correlate trace ids
// into audit-log entries without threading a *Span through every call.
func TraceIDFromContext(ctx context.Context) string {
	sc := SpanContextFromContext(ctx)
	if !sc.TraceID.IsValid() {
		return ""
	}
	return encodeTraceID(sc.TraceID)
}

// SpanIDFromContext returns the active span id as lowercase hex, or "".
func SpanIDFromContext(ctx context.Context) string {
	sc := SpanContextFromContext(ctx)
	if !sc.SpanID.IsValid() {
		return ""
	}
	return encodeSpanID(sc.SpanID)
}
