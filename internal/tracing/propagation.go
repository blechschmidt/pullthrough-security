package tracing

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
)

// W3C Trace Context propagation (https://www.w3.org/TR/trace-context/). Only the
// traceparent and tracestate headers are handled; baggage is out of scope.

const (
	traceparentHeader = "traceparent"
	tracestateHeader  = "tracestate"
	supportedVersion  = "00"
)

// Carrier is the minimal get/set surface propagation reads from and writes to.
// HeaderCarrier adapts an http.Header to it.
type Carrier interface {
	Get(key string) string
	Set(key, value string)
}

// HeaderCarrier adapts http.Header to the Carrier interface.
type HeaderCarrier http.Header

// Get returns the first value for key (case-insensitively, via http.Header).
func (c HeaderCarrier) Get(key string) string { return http.Header(c).Get(key) }

// Set replaces the value for key.
func (c HeaderCarrier) Set(key, value string) { http.Header(c).Set(key, value) }

// MapCarrier adapts a plain string map to the Carrier interface, for carrying
// trace context across non-HTTP boundaries (e.g. background-worker job records).
type MapCarrier map[string]string

// Get returns the value for key.
func (c MapCarrier) Get(key string) string { return c[key] }

// Set stores value under key.
func (c MapCarrier) Set(key, value string) { c[key] = value }

// Inject writes the active span context in ctx into the carrier as W3C
// traceparent/tracestate headers. It is a no-op when ctx carries no valid span
// context, so it is safe to call unconditionally on outbound requests.
func Inject(ctx context.Context, carrier Carrier) {
	sc := SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return
	}
	carrier.Set(traceparentHeader, formatTraceparent(sc))
	if sc.TraceState != "" {
		carrier.Set(tracestateHeader, sc.TraceState)
	}
}

// Extract parses W3C trace context from the carrier and returns a context
// carrying it as the active (remote) span context. When the carrier holds no
// valid traceparent, ctx is returned unchanged so a new trace is rooted locally.
func Extract(ctx context.Context, carrier Carrier) context.Context {
	sc, ok := parseTraceparent(carrier.Get(traceparentHeader))
	if !ok {
		return ctx
	}
	sc.Remote = true
	if ts := strings.TrimSpace(carrier.Get(tracestateHeader)); ts != "" {
		sc.TraceState = ts
	}
	return ContextWithSpanContext(ctx, sc)
}

// formatTraceparent renders a span context as a version-00 traceparent value.
func formatTraceparent(sc SpanContext) string {
	var b strings.Builder
	b.Grow(55)
	b.WriteString(supportedVersion)
	b.WriteByte('-')
	b.WriteString(encodeTraceID(sc.TraceID))
	b.WriteByte('-')
	b.WriteString(encodeSpanID(sc.SpanID))
	b.WriteByte('-')
	b.WriteString(encodeFlags(sc.TraceFlags))
	return b.String()
}

// parseTraceparent validates and decodes a version-00 traceparent header.
// Per the spec, unknown future versions whose first two fields still parse are
// accepted forward-compatibly; structurally invalid values are rejected.
func parseTraceparent(v string) (SpanContext, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return SpanContext{}, false
	}
	parts := strings.Split(v, "-")
	if len(parts) < 4 {
		return SpanContext{}, false
	}
	version := parts[0]
	if len(version) != 2 || !isHex(version) {
		return SpanContext{}, false
	}
	// Version ff is explicitly invalid.
	if version == "ff" {
		return SpanContext{}, false
	}

	traceIDHex, spanIDHex, flagsHex := parts[1], parts[2], parts[3]
	if len(traceIDHex) != 32 || !isHex(traceIDHex) {
		return SpanContext{}, false
	}
	if len(spanIDHex) != 16 || !isHex(spanIDHex) {
		return SpanContext{}, false
	}
	if len(flagsHex) != 2 || !isHex(flagsHex) {
		return SpanContext{}, false
	}

	var sc SpanContext
	tid, err := hex.DecodeString(traceIDHex)
	if err != nil {
		return SpanContext{}, false
	}
	copy(sc.TraceID[:], tid)
	if !sc.TraceID.IsValid() {
		return SpanContext{}, false
	}
	sid, err := hex.DecodeString(spanIDHex)
	if err != nil {
		return SpanContext{}, false
	}
	copy(sc.SpanID[:], sid)
	if !sc.SpanID.IsValid() {
		return SpanContext{}, false
	}
	flags, err := hex.DecodeString(flagsHex)
	if err != nil {
		return SpanContext{}, false
	}
	sc.TraceFlags = flags[0]
	return sc, true
}

func encodeTraceID(t TraceID) string { return hex.EncodeToString(t[:]) }
func encodeSpanID(s SpanID) string   { return hex.EncodeToString(s[:]) }
func encodeFlags(f byte) string      { return hex.EncodeToString([]byte{f}) }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
