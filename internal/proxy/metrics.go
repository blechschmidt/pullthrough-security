package proxy

import (
	"context"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// MetricsRecorder is the narrow telemetry surface the gateway records into. It
// is satisfied structurally by *metrics.Collector, so the proxy package does not
// depend on the concrete metrics implementation (mirroring the package's other
// optional-dependency interfaces). When no recorder is supplied, the gateway
// records into a no-op.
type MetricsRecorder interface {
	// IncRequest records one served backend request, labeled by backend, HTTP
	// method, and the response status code (as a string).
	IncRequest(backend, method, code string)
	// ObserveUpstreamLatency records the duration, in seconds, of an upstream
	// fetch. ok reports whether the fetch succeeded.
	ObserveUpstreamLatency(backend string, seconds float64, ok bool)
	// AddBytesServed records response body bytes written to a client.
	AddBytesServed(backend string, n int64)
	// IncPolicyDecision records one admission-policy decision (allow|warn|block).
	IncPolicyDecision(ecosystem, action string)
}

// nopMetrics is the recorder used when none is configured.
type nopMetrics struct{}

func (nopMetrics) IncRequest(string, string, string)            {}
func (nopMetrics) ObserveUpstreamLatency(string, float64, bool) {}
func (nopMetrics) AddBytesServed(string, int64)                 {}
func (nopMetrics) IncPolicyDecision(string, string)             {}

// metrics returns the configured recorder, or a no-op when metrics are disabled,
// so call sites never need a nil check.
func (g *Gateway) metrics() MetricsRecorder {
	if g.deps.Metrics != nil {
		return g.deps.Metrics
	}
	return nopMetrics{}
}

// emit dispatches a security alert to the notification subsystem when one is
// wired. It is a no-op when alerting is disabled, so call sites need no nil
// check. Delivery is asynchronous (the Notifier never blocks Emit), so this is
// safe to call from the request path.
func (g *Gateway) emit(ctx context.Context, ev notify.Event) {
	if g.deps.Notify == nil {
		return
	}
	g.deps.Notify.Emit(ctx, ev)
}

// meteredWriter wraps a ResponseWriter to capture the final status code and the
// number of body bytes written, for per-request metrics. It deliberately does
// not implement http.Flusher/Hijacker: the backend serving paths stream plain
// bodies, and omitting those interfaces keeps the wrapper simple without
// changing observable behavior.
type meteredWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
	// errBody keeps the start of an error response's body. A gate's refusal is a
	// small JSON document naming its reason code and explanation; the download
	// log reads them from here. Nothing is kept for a successful response.
	errBody []byte
}

// maxErrBody bounds how much of an error response's body is kept.
const maxErrBody = 8 << 10

func (w *meteredWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer's Flusher so streaming responses can
// push data incrementally through this metering wrapper. No-op when unsupported.
func (w *meteredWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *meteredWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	if w.status >= http.StatusBadRequest && len(w.errBody) < maxErrBody {
		w.errBody = append(w.errBody, b[:min(len(b), maxErrBody-len(w.errBody))]...)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}
