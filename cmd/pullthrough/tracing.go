package main

import (
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// buildTracing constructs the OpenTelemetry tracing provider (Task 41) from
// config. It returns a nil provider — the valid no-op — when tracing is disabled
// or no OTLP endpoint is configured, so the rest of the wiring needs no special
// casing. It only errors on a malformed endpoint so a typo fails fast at startup.
func buildTracing(cfg *config.Config, logger *slog.Logger) (*tracing.Provider, error) {
	tc := cfg.Tracing
	if !tc.Active() {
		if tc.Enabled && tc.Endpoint == "" {
			logger.Warn("tracing enabled but no endpoint configured; tracing inert (set tracing.endpoint to an OTLP collector)")
		} else {
			logger.Info("distributed tracing disabled (set tracing.enabled and tracing.endpoint to export OTLP traces)")
		}
		return nil, nil
	}

	provider, err := tracing.New(tracing.Config{
		Enabled:       tc.Enabled,
		Endpoint:      tc.Endpoint,
		Insecure:      tc.Insecure,
		TLSSkipVerify: tc.TLSSkipVerify,
		ServiceName:   tc.ServiceName,
		ServiceVer:    version,
		Environment:   tc.Environment,
		SamplerRatio:  tc.SamplerRatio,
		ResourceAttrs: tc.ResourceAttributes,
		Headers:       tc.Headers,
		Timeout:       tc.Timeout,
		BatchTimeout:  tc.BatchTimeout,
		MaxQueueSize:  tc.MaxQueueSize,
		MaxBatchSize:  tc.MaxBatchSize,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("distributed tracing enabled",
		"endpoint", tc.Endpoint,
		"service", provider.ServiceName(),
		"samplerRatio", tc.SamplerRatio)
	return provider, nil
}

// tracingInspector adapts a tracing.Provider to the admin TracingInspector,
// enriching the provider's runtime status with the configured endpoint and
// sampler ratio (which the provider does not itself retain).
type tracingInspector struct {
	provider *tracing.Provider
	endpoint string
	ratio    float64
}

func (t tracingInspector) Status() tracing.Status {
	return t.provider.StatusWith(t.endpoint, t.ratio)
}
