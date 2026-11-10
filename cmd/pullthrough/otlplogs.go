package main

import (
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/otlplog"
)

// buildOTLPLogs constructs the OTLP structured-log export pipeline (Task 160)
// from config. It returns a nil pipeline — the valid no-op — when export is
// disabled or no endpoint is configured, so the rest of the wiring needs no
// special casing. It only errors on a malformed endpoint or an unopenable spill
// file so a typo fails fast at startup.
//
// bootLogger is the pre-tap stderr logger. It is passed as the forwarder's own
// diagnostic logger so a forwarding warning is written only to stderr and never
// re-enters the tap (which would recurse). The caller must NOT pass the tapped
// logger here.
func buildOTLPLogs(cfg *config.Config, bootLogger *slog.Logger) (*otlplog.Pipeline, error) {
	oc := cfg.Telemetry.OTLPLogs
	if !oc.Active() {
		if oc.Enabled && oc.Endpoint == "" {
			bootLogger.Warn("OTLP log export enabled but no endpoint configured; export inert (set telemetry.otlpLogs.endpoint to an OTLP collector)")
		}
		return nil, nil
	}

	// Share the tracing service identity when the logs block does not set its own,
	// so logs and spans report the same service.name in the backend.
	serviceName := oc.ServiceName
	if serviceName == "" {
		serviceName = cfg.Tracing.ServiceName
	}

	pipe, err := otlplog.New(otlplog.Config{
		Enabled:            true,
		Endpoint:           oc.Endpoint,
		Insecure:           oc.Insecure,
		TLSSkipVerify:      oc.TLSSkipVerify,
		ServiceName:        serviceName,
		ServiceVersion:     version,
		Environment:        oc.Environment,
		Tenant:             oc.Tenant,
		ResourceAttributes: oc.ResourceAttributes,
		Headers:            oc.Headers,
		MinLevel:           oc.MinLevel,
		Timeout:            oc.Timeout,
		BatchTimeout:       oc.BatchTimeout,
		MaxQueueSize:       oc.MaxQueueSize,
		MaxBatchSize:       oc.MaxBatchSize,
		MaxRetries:         oc.MaxRetries,
		RetryBaseDelay:     oc.RetryBaseDelay,
		RetryMaxDelay:      oc.RetryMaxDelay,
		SpillPath:          oc.SpillFile,
		SpillMaxBytes:      oc.SpillMaxBytes,
		Logger:             bootLogger,
	})
	if err != nil {
		return nil, err
	}
	pipe.WithSource(cfg.Logging.AddSource)

	bootLogger.Info("OTLP log export enabled",
		"endpoint", pipe.Endpoint(),
		"service", serviceName,
		"minLevel", oc.MinLevel)
	return pipe, nil
}
