package fullmirror

import (
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/metrics"
)

// MetricNames lists the series BindMetrics registers.
var MetricNames = []string{
	"pullthrough_fullmirror_upstreams",
	"pullthrough_fullmirror_leader",
	"pullthrough_fullmirror_paused",
	"pullthrough_fullmirror_state",
	"pullthrough_fullmirror_packages_total",
	"pullthrough_fullmirror_artifacts_total",
	"pullthrough_fullmirror_skipped_total",
	"pullthrough_fullmirror_refused_total",
	"pullthrough_fullmirror_fetched_bytes_total",
	"pullthrough_fullmirror_retries_total",
	"pullthrough_fullmirror_polls_total",
	"pullthrough_fullmirror_queued",
	"pullthrough_fullmirror_deferred",
	"pullthrough_fullmirror_deferrals_total",
	"pullthrough_fullmirror_in_flight",
	"pullthrough_fullmirror_lag",
	"pullthrough_fullmirror_lag_seconds",
	"pullthrough_fullmirror_last_poll_timestamp_seconds",
	"pullthrough_fullmirror_budget_bytes",
	"pullthrough_fullmirror_budget_used_bytes",
}

// snapshotTTL is how long one scrape reuses the status it read.
const snapshotTTL = time.Second

// BindMetrics registers the pullthrough_fullmirror_* series on reg, read from
// the engine's status at scrape time. The counters are the engine's persisted
// tallies, so they carry over restarts (and go back with a restored backup,
// which Prometheus reads as a counter reset). Safe with a nil engine (nothing
// is mirrored: the series are empty).
func BindMetrics(reg *metrics.Registry, e *Engine) {
	if reg == nil {
		return
	}
	var (
		mu   sync.Mutex
		at   time.Time
		snap Status
	)
	status := func() Status {
		mu.Lock()
		defer mu.Unlock()
		if now := time.Now(); now.Sub(at) > snapshotTTL {
			snap, at = e.Status(), now
		}
		return snap
	}
	perUpstream := func(pick func(UpstreamStatus) (float64, bool)) func() []metrics.LabeledValue {
		return func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, u := range status().Upstreams {
				if v, ok := pick(u); ok {
					out = append(out, metrics.LabeledValue{Labels: []string{u.Upstream}, Value: v})
				}
			}
			return out
		}
	}
	byKey := func(pick func(UpstreamStatus) map[string]uint64) func() []metrics.LabeledValue {
		return func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, u := range status().Upstreams {
				m := pick(u)
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					out = append(out, metrics.LabeledValue{Labels: []string{u.Upstream, k}, Value: float64(m[k])})
				}
			}
			return out
		}
	}
	up := []string{"upstream"}

	reg.RegisterFunc("pullthrough_fullmirror_upstreams",
		"Upstreams the full mirror follows (Task 189).", "gauge",
		func() float64 { return float64(len(status().Upstreams)) })
	reg.RegisterFunc("pullthrough_fullmirror_leader",
		"1 when this replica leads the full mirror (only the leader polls and fetches).", "gauge",
		func() float64 {
			st := status()
			if st.Enabled && st.Leader {
				return 1
			}
			return 0
		})
	reg.RegisterFuncVec("pullthrough_fullmirror_paused",
		"1 when an operator paused the upstream's mirror (or every upstream's).", "gauge", up,
		func() []metrics.LabeledValue {
			st := status()
			var out []metrics.LabeledValue
			for _, u := range st.Upstreams {
				v := 0.0
				if st.Paused || u.Paused {
					v = 1
				}
				out = append(out, metrics.LabeledValue{Labels: []string{u.Upstream}, Value: v})
			}
			return out
		})
	reg.RegisterFuncVec("pullthrough_fullmirror_state",
		"1 for the state the upstream's follower is in (following, bootstrapping, paused, off-peak, budget-exhausted, backing-off, lockdown, standby, starting, error).", "gauge",
		[]string{"upstream", "state"},
		func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, u := range status().Upstreams {
				out = append(out, metrics.LabeledValue{Labels: []string{u.Upstream, u.State}, Value: 1})
			}
			return out
		})
	reg.RegisterFuncVec("pullthrough_fullmirror_packages_total",
		"Changes the feed reported, by outcome: mirrored (every file dealt with), excluded (name patterns), deleted, error (versions could not be listed).", "counter",
		[]string{"upstream", "outcome"},
		byKey(func(u UpstreamStatus) map[string]uint64 {
			c := u.Counters
			return map[string]uint64{"mirrored": c.Packages, "excluded": c.Excluded, "deleted": c.Deleted, "error": c.PackageErrors}
		}))
	reg.RegisterFuncVec("pullthrough_fullmirror_artifacts_total",
		"Files the full mirror dealt with, by outcome: fetched (added to the cache through the gated pipeline), refused (by an admission gate), failed, skipped.", "counter",
		[]string{"upstream", "outcome"},
		byKey(func(u UpstreamStatus) map[string]uint64 {
			c := u.Counters
			return map[string]uint64{"fetched": c.Fetched, "refused": c.Refused, "failed": c.Failed, "skipped": c.SkippedTotal()}
		}))
	reg.RegisterFuncVec("pullthrough_fullmirror_skipped_total",
		"Files the full mirror did not fetch, by reason: cached, version-policy, too-large, not-cacheable, dry-run.", "counter",
		[]string{"upstream", "reason"},
		byKey(func(u UpstreamStatus) map[string]uint64 { return u.Counters.Skipped }))
	reg.RegisterFuncVec("pullthrough_fullmirror_refused_total",
		"Files an admission gate refused to the full mirror, by gate.", "counter",
		[]string{"upstream", "gate"},
		byKey(func(u UpstreamStatus) map[string]uint64 { return u.Counters.RefusedBy }))
	reg.RegisterFuncVec("pullthrough_fullmirror_fetched_bytes_total",
		"Bytes the full mirror added to the cache.", "counter", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Counters.FetchedBytes), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_retries_total",
		"Requests the full mirror repeated after a transient failure.", "counter", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Counters.Retries), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_polls_total",
		"Requests made of the registry's feed, by result (ok, error).", "counter",
		[]string{"upstream", "result"},
		byKey(func(u UpstreamStatus) map[string]uint64 {
			c := u.Counters
			ok := uint64(0)
			if c.Polls > c.PollErrors {
				ok = c.Polls - c.PollErrors
			}
			return map[string]uint64{"ok": ok, "error": c.PollErrors}
		}))
	reg.RegisterFuncVec("pullthrough_fullmirror_queued",
		"Changes of the current batch still to do.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Queued), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_deferred",
		"Files waiting in the deferred queue: refused for now by a gate (a maturity cooldown, a scanner that could not judge them), to be asked for again.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Deferred), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_deferrals_total",
		"Times a gate said \"not yet\" to a file the full mirror asked for.", "counter", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Counters.Deferred), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_in_flight",
		"Files being fetched.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.InFlight), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_lag",
		"Changes between the mirror's cursor and the feed's head, when the feed says.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) {
			if u.Lag == nil {
				return 0, false
			}
			return float64(*u.Lag), true
		}))
	reg.RegisterFuncVec("pullthrough_fullmirror_lag_seconds",
		"How far behind the registry the mirror's cursor is, in time, when the feed says.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) {
			if u.LagSeconds == nil {
				return 0, false
			}
			return *u.LagSeconds, true
		}))
	reg.RegisterFuncVec("pullthrough_fullmirror_last_poll_timestamp_seconds",
		"When the feed was last polled (Unix time).", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) {
			if u.LastPoll.IsZero() {
				return 0, false
			}
			return float64(u.LastPoll.UnixNano()) / 1e9, true
		}))
	reg.RegisterFuncVec("pullthrough_fullmirror_budget_bytes",
		"The upstream's byte budget (fullMirror.byteBudget).", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Budget.Limit), true }))
	reg.RegisterFuncVec("pullthrough_fullmirror_budget_used_bytes",
		"Bytes of the budget spent: what the mirror added to the cache.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Budget.Used), true }))
}
