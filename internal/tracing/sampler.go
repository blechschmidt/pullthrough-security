package tracing

import "encoding/binary"

// SamplingParameters are the inputs to a sampling decision.
type SamplingParameters struct {
	ParentContext SpanContext
	TraceID       TraceID
	Name          string
	Kind          SpanKind
}

// Sampler decides whether a span should be recorded and exported.
type Sampler interface {
	ShouldSample(p SamplingParameters) bool
}

// SamplerFunc adapts a function to the Sampler interface.
type SamplerFunc func(SamplingParameters) bool

// ShouldSample implements Sampler.
func (f SamplerFunc) ShouldSample(p SamplingParameters) bool { return f(p) }

// AlwaysSample samples every trace.
func AlwaysSample() Sampler { return SamplerFunc(func(SamplingParameters) bool { return true }) }

// NeverSample samples no traces.
func NeverSample() Sampler { return SamplerFunc(func(SamplingParameters) bool { return false }) }

// ParentBased honors an inbound (remote) parent's sampled flag and falls back
// to root for locally-rooted traces. This is the standard composition: a
// sampling decision made at the edge of a distributed trace is respected by
// every downstream service so a trace is captured whole or not at all.
func ParentBased(root Sampler) Sampler {
	return SamplerFunc(func(p SamplingParameters) bool {
		if p.ParentContext.IsValid() {
			return p.ParentContext.IsSampled()
		}
		return root.ShouldSample(p)
	})
}

// TraceIDRatioBased samples a deterministic fraction of traces by thresholding
// the trace id, so the same trace id always yields the same decision (a sampled
// trace stays sampled across services that share the id). ratio <= 0 never
// samples; ratio >= 1 always samples.
func TraceIDRatioBased(ratio float64) Sampler {
	switch {
	case ratio <= 0:
		return NeverSample()
	case ratio >= 1:
		return AlwaysSample()
	}
	// Threshold the high 8 bytes of the trace id (big-endian) against the ratio
	// scaled across the uint64 range.
	threshold := uint64(ratio * float64(^uint64(0)))
	return SamplerFunc(func(p SamplingParameters) bool {
		x := binary.BigEndian.Uint64(p.TraceID[0:8])
		return x < threshold
	})
}

// NewRatioSampler is the production sampler: parent-based over a trace-id ratio
// root, the conventional default for distributed tracing.
func NewRatioSampler(ratio float64) Sampler {
	return ParentBased(TraceIDRatioBased(ratio))
}
