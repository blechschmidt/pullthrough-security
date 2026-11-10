package watch

import "github.com/blechschmidt/pullthrough-security/internal/metrics"

// MetricsRecorder is the narrow observability hook the watcher calls; it keeps
// the Service decoupled from any concrete metrics backend (unit-testable with a
// no-op). Metrics is the Prometheus-backed implementation wired in by main.go.
type MetricsRecorder interface {
	// ObserveScan records one commit scanned by the watcher: the repo, whether it
	// was a fresh scan (vs a verdict-cache hit), and whether the verdict was
	// flagged (malicious or medium+ severity).
	ObserveScan(repo string, fresh, flagged bool)
	// ObserveWebhook records one inbound webhook delivery and whether it was
	// rejected (bad signature / unknown repo / malformed payload).
	ObserveWebhook(rejected bool)
}

// nopMetrics is the default recorder when none is configured.
type nopMetrics struct{}

func (nopMetrics) ObserveScan(string, bool, bool) {}
func (nopMetrics) ObserveWebhook(bool)            {}

// Metrics is the Prometheus-backed MetricsRecorder.
type Metrics struct {
	scans    *metrics.CounterVec // labels: repo, result(fresh|cached)
	flagged  *metrics.CounterVec // labels: repo
	webhooks *metrics.CounterVec // labels: outcome(accepted|rejected)
}

// NewMetrics registers the watcher metrics on reg and returns the recorder. A
// nil registry yields a nil *Metrics, which is a valid no-op recorder.
func NewMetrics(reg *metrics.Registry) *Metrics {
	if reg == nil {
		return nil
	}
	return &Metrics{
		scans: reg.NewCounterVec(
			"pullthrough_commitwatch_scans_total",
			"Commits scanned by the continuous commit watcher, by repo and cache result.",
			[]string{"repo", "result"},
		),
		flagged: reg.NewCounterVec(
			"pullthrough_commitwatch_flagged_total",
			"Scanned commits whose verdict was flagged (malicious or medium+), by repo.",
			[]string{"repo"},
		),
		webhooks: reg.NewCounterVec(
			"pullthrough_commitwatch_webhooks_total",
			"Inbound commit-watch push webhooks, by outcome.",
			[]string{"outcome"},
		),
	}
}

func (m *Metrics) ObserveScan(repo string, fresh, flagged bool) {
	if m == nil {
		return
	}
	if repo == "" {
		repo = "(none)"
	}
	result := "cached"
	if fresh {
		result = "fresh"
	}
	m.scans.With(repo, result).Inc()
	if flagged {
		m.flagged.With(repo).Inc()
	}
}

func (m *Metrics) ObserveWebhook(rejected bool) {
	if m == nil {
		return
	}
	outcome := "accepted"
	if rejected {
		outcome = "rejected"
	}
	m.webhooks.With(outcome).Inc()
}
