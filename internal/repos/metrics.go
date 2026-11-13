package repos

import (
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/metrics"
)

// Metrics are the pullthrough_repo_* series. A nil *Metrics is a no-op.
type Metrics struct {
	repos       *metrics.Gauge
	tags        *metrics.GaugeVec
	tagEvents   *metrics.CounterVec
	pinnedObjs  *metrics.Gauge
	pinnedBytes *metrics.Gauge
	failures    *metrics.CounterVec
	releases    *metrics.CounterVec
	pinSeconds  *metrics.Histogram
	syncErrors  *metrics.CounterVec
	webhooks    *metrics.CounterVec
	queue       *metrics.Gauge
	repairs     *metrics.CounterVec

	mu      sync.Mutex
	tagsNow map[string]int
}

// NewMetrics registers the series on reg; a nil registry yields nil.
func NewMetrics(reg *metrics.Registry) *Metrics {
	if reg == nil {
		return nil
	}
	return &Metrics{
		repos: reg.NewGauge("pullthrough_repo_repositories",
			"Repositories whose tags are tracked (Task 180)."),
		tags: reg.NewGaugeVec("pullthrough_repo_tags_tracked",
			"Tags currently tracked, by repository.", []string{"repo"}),
		tagEvents: reg.NewCounterVec("pullthrough_repo_tag_events_total",
			"Tag history records written, by event (created, moved, deleted).", []string{"event"}),
		pinnedObjs: reg.NewGauge("pullthrough_repo_pinned_objects",
			"Distinct cache objects pinned by release manifests."),
		pinnedBytes: reg.NewGauge("pullthrough_repo_pinned_bytes",
			"Bytes of the cache objects pinned by release manifests."),
		failures: reg.NewCounterVec("pullthrough_repo_pin_failures_total",
			"Dependencies (or objects) a release could not pin, by reason (refused, digest, fetch, unsupported, locate, store).",
			[]string{"reason"}),
		releases: reg.NewCounterVec("pullthrough_repo_releases_total",
			"Release pinning attempts, by resulting status (pinned, partial, failed).", []string{"status"}),
		pinSeconds: reg.NewHistogram("pullthrough_repo_pin_duration_seconds",
			"Time taken by one release pinning attempt.",
			[]float64{1, 5, 15, 60, 300, 900, 3600}),
		syncErrors: reg.NewCounterVec("pullthrough_repo_sync_errors_total",
			"Repository syncs that failed (the repository could not be fetched, or its history does not verify).",
			[]string{"repo"}),
		webhooks: reg.NewCounterVec("pullthrough_repo_webhooks_total",
			"Repository push webhooks, by outcome (accepted, ignored, deferred, rejected).", []string{"outcome"}),
		queue: reg.NewGauge("pullthrough_repo_pin_queue",
			"Releases waiting to be pinned."),
		repairs: reg.NewCounterVec("pullthrough_repo_pin_repairs_total",
			"Pinned objects fetched again after an integrity failure, by outcome (restored, lost).", []string{"outcome"}),
		tagsNow: map[string]int{},
	}
}

func (m *Metrics) setRepos(n int) {
	if m != nil {
		m.repos.Set(float64(n))
	}
}

func (m *Metrics) setTags(repo string, n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.tagsNow[repo] = n
	m.mu.Unlock()
	m.tags.With(repo).Set(float64(n))
}

func (m *Metrics) tagEvent(kind string) {
	if m != nil {
		m.tagEvents.With(kind).Inc()
	}
}

func (m *Metrics) setPins(objects int, bytes int64) {
	if m != nil {
		m.pinnedObjs.Set(float64(objects))
		m.pinnedBytes.Set(float64(bytes))
	}
}

func (m *Metrics) pinFailure(reason string) {
	if m != nil {
		m.failures.With(reason).Inc()
	}
}

func (m *Metrics) release(status string, took time.Duration) {
	if m != nil {
		m.releases.With(status).Inc()
		m.pinSeconds.Observe(took.Seconds())
	}
}

func (m *Metrics) syncError(repo string) {
	if m != nil {
		m.syncErrors.With(repo).Inc()
	}
}

func (m *Metrics) webhook(outcome string) {
	if m != nil {
		m.webhooks.With(outcome).Inc()
	}
}

func (m *Metrics) setQueue(n int) {
	if m != nil {
		m.queue.Set(float64(n))
	}
}

func (m *Metrics) repair(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.repairs.With("restored").Inc()
	} else {
		m.repairs.With("lost").Inc()
	}
}
