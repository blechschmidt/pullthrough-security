package main

import (
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/sbomexport"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// buildSBOMExporter constructs the outbound SBOM/findings federation service
// (Task 153) when enabled. It wires the vulnscan service as the report source
// (each cached report carries the generated CycloneDX SBOM and its findings) and
// the enabled sinks (Dependency-Track and/or GUAC). Credentials have already
// been resolved from any secretRef by config.ResolveRefs at startup. It returns
// nil when the subsystem is disabled or no report source is available.
func buildSBOMExporter(cfg *config.Config, vulnService *vulnscan.Service, logger *slog.Logger) *sbomexport.Service {
	sc := cfg.SBOMExport
	if !sc.Enabled || vulnService == nil {
		return nil
	}

	var sinks []sbomexport.Sink
	if sc.DependencyTrack.Enabled {
		sinks = append(sinks, sbomexport.NewDependencyTrackSink(sbomexport.DependencyTrackConfig{
			Name:          "dependency-track",
			URL:           sc.DependencyTrack.URL,
			APIKey:        sc.DependencyTrack.APIKey,
			AutoCreate:    sc.DependencyTrack.AutoCreateOrDefault(),
			ParentProject: sc.DependencyTrack.ParentProject,
			TLSSkipVerify: sc.DependencyTrack.TLSSkipVerify,
		}, sc.Timeout))
	}
	if sc.GUAC.Enabled {
		sinks = append(sinks, sbomexport.NewGUACSink(sbomexport.GUACConfig{
			Name:          "guac",
			URL:           sc.GUAC.URL,
			Token:         sc.GUAC.Token,
			DocumentType:  sc.GUAC.DocumentType,
			TLSSkipVerify: sc.GUAC.TLSSkipVerify,
		}, sc.Timeout))
	}

	svc := sbomexport.New(sbomexport.Config{
		IncludeFindings: sc.IncludeFindingsOrDefault(),
		MinSeverity:     normalizeExportSeverity(sc.MinSeverity),
		Interval:        sc.Interval,
		MaxRetries:      sc.MaxRetries,
		RetryBaseDelay:  sc.RetryBaseDelay,
		RetryMaxDelay:   sc.RetryMaxDelay,
		Timeout:         sc.Timeout,
	}, vulnService, sinks, logger)
	if svc == nil {
		return nil
	}

	names := make([]string, 0, len(sinks))
	for _, s := range sinks {
		names = append(names, s.Name())
	}
	logger.Info("outbound SBOM/findings federation enabled (export via periodic sweep or `ptctl sbom-export run`)",
		"sinks", names, "interval", sc.Interval.String(), "includeFindings", sc.IncludeFindingsOrDefault())
	return svc
}

// normalizeExportSeverity maps the config severity vocabulary (info|low|…) onto
// the vulnscan severity type used by the finding filter; "info" corresponds to
// the proxy's "none" bucket.
func normalizeExportSeverity(s string) vulnscan.Severity {
	switch s {
	case "":
		return ""
	case "info":
		return vulnscan.SeverityNone
	default:
		return vulnscan.Severity(s)
	}
}

// bindSBOMExportMetrics registers the outbound SBOM/findings federation counters
// (Task 153): total uploads and failures (and their per-target partitions),
// retry attempts, and skipped reports. Safe with a nil service (disabled).
func bindSBOMExportMetrics(c *metrics.Collector, svc *sbomexport.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_sbomexport_uploads_total",
		"Total SBOM/findings documents successfully delivered to a sink.",
		func() float64 { return float64(svc.Metrics().Uploads) })
	c.BindCounter("pullthrough_sbomexport_failures_total",
		"Total SBOM/findings deliveries that failed after exhausting retries.",
		func() float64 { return float64(svc.Metrics().Failures) })
	c.BindCounter("pullthrough_sbomexport_retries_total",
		"Total SBOM/findings delivery retry attempts (backoff).",
		func() float64 { return float64(svc.Metrics().Retries) })
	c.BindCounter("pullthrough_sbomexport_skipped_total",
		"Total reports skipped during export (no usable SBOM).",
		func() float64 { return float64(svc.Metrics().Skipped) })
	c.BindCounterVec("pullthrough_sbomexport_uploads_by_target_total",
		"Total successful deliveries partitioned by sink target (dependency-track|guac).",
		[]string{"target"},
		func() []metrics.LabeledValue {
			m := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(m.UploadsByTarget))
			for target, v := range m.UploadsByTarget {
				out = append(out, metrics.LabeledValue{Labels: []string{target}, Value: float64(v)})
			}
			return out
		})
	c.BindCounterVec("pullthrough_sbomexport_failures_by_target_total",
		"Total failed deliveries partitioned by sink target (dependency-track|guac).",
		[]string{"target"},
		func() []metrics.LabeledValue {
			m := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(m.FailuresByTarget))
			for target, v := range m.FailuresByTarget {
				out = append(out, metrics.LabeledValue{Labels: []string{target}, Value: float64(v)})
			}
			return out
		})
}
