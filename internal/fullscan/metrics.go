package fullscan

import (
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/metrics"
)

// MetricNames lists the series BindMetrics registers.
var MetricNames = []string{
	"pullthrough_fullscan_upstreams",
	"pullthrough_fullscan_leader",
	"pullthrough_fullscan_paused",
	"pullthrough_fullscan_state",
	"pullthrough_fullscan_artifacts",
	"pullthrough_fullscan_oldest_unscanned_seconds",
	"pullthrough_fullscan_queue",
	"pullthrough_fullscan_in_flight",
	"pullthrough_fullscan_scans_total",
	"pullthrough_fullscan_verdicts_total",
	"pullthrough_fullscan_unscanned_total",
	"pullthrough_fullscan_enforced_total",
	"pullthrough_fullscan_rescans_total",
	"pullthrough_fullscan_errors_total",
	"pullthrough_fullscan_spend_usd",
	"pullthrough_fullscan_budget_usd",
	"pullthrough_fullscan_budget_exhausted",
	"pullthrough_fullscan_upstream_spend_usd_total",
	"pullthrough_fullscan_untracked",
	"pullthrough_fullscan_last_sweep_timestamp_seconds",
	"pullthrough_fullscan_dropped_total",
}

// snapshotTTL is how long one scrape reuses the status it read.
const snapshotTTL = time.Second

// BindMetrics registers the pullthrough_fullscan_* series on reg, read from
// the full scan's status at scrape time. The counters are the persisted
// tallies: they carry over restarts. Safe with a nil service (the series are
// empty).
func BindMetrics(reg *metrics.Registry, s *Service) {
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
			snap, at = s.Status(), now
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
	byKey := func(pick func(UpstreamStatus) map[string]float64) func() []metrics.LabeledValue {
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
					out = append(out, metrics.LabeledValue{Labels: []string{u.Upstream, k}, Value: m[k]})
				}
			}
			return out
		}
	}
	counts := func(m map[string]uint64) map[string]float64 {
		out := make(map[string]float64, len(m))
		for k, v := range m {
			out[k] = float64(v)
		}
		return out
	}
	up := []string{"upstream"}

	reg.RegisterFunc("pullthrough_fullscan_upstreams",
		"Upstreams whose cached artifacts the full scan keeps judged (Task 192).", "gauge",
		func() float64 { return float64(len(status().Upstreams)) })
	reg.RegisterFunc("pullthrough_fullscan_leader",
		"1 when this replica leads the full scan (only the leader scans).", "gauge",
		func() float64 {
			if st := status(); st.Enabled && st.Leader {
				return 1
			}
			return 0
		})
	reg.RegisterFuncVec("pullthrough_fullscan_paused",
		"1 when an operator paused the upstream's full scan (or the whole full scan).", "gauge", up,
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
	reg.RegisterFuncVec("pullthrough_fullscan_state",
		"1 for the state the full scan is in (scanning, idle, waiting, paused, budget-exhausted, lockdown, standby, starting, error, stopped).", "gauge",
		[]string{"state"},
		func() []metrics.LabeledValue {
			st := status()
			if !st.Enabled {
				return nil
			}
			return []metrics.LabeledValue{{Labels: []string{st.State}, Value: 1}}
		})
	reg.RegisterFuncVec("pullthrough_fullscan_artifacts",
		"Tracked artifacts by their last reading: cached, scanned (benign, suspicious, malicious), pending, error, refused (the model refused to judge), unscannable, not_applicable, quarantined (evicted by the action ladder), refused_by_action; and gates_passed / gate_refused (every admission gate admitted them, or another gate refused them in a gate pass).", "gauge",
		[]string{"upstream", "status"},
		byKey(func(u UpstreamStatus) map[string]float64 {
			f := u.Figures
			return map[string]float64{
				"cached": float64(f.Cached), "scanned": float64(f.Scanned), "benign": float64(f.Benign),
				"suspicious": float64(f.Suspicious), "malicious": float64(f.Malicious), "pending": float64(f.Pending),
				"error": float64(f.Errors), "refused": float64(f.Refused), "unscannable": float64(f.Unscannable),
				"not_applicable": float64(f.NotApplicable), "quarantined": float64(f.Quarantined),
				"refused_by_action": float64(f.RefusedByAction), "gates_passed": float64(f.GatesPassed),
				"gate_refused": float64(f.GateRefused),
			}
		}))
	reg.RegisterFuncVec("pullthrough_fullscan_oldest_unscanned_seconds",
		"How long the cached artifact that has waited longest for a verdict has been cached.", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) {
			if u.OldestUnscanned == nil {
				return 0, true
			}
			return u.OldestUnscanned.AgeSeconds, true
		}))
	reg.RegisterFuncVec("pullthrough_fullscan_queue",
		"Artifacts waiting in the scan queue, by class (client, mirror, backfill), and those waiting out a retry (delayed) or of paused upstreams (parked).", "gauge",
		[]string{"priority"},
		func() []metrics.LabeledValue {
			st := status()
			if !st.Enabled {
				return nil
			}
			q := st.Queue
			return []metrics.LabeledValue{
				{Labels: []string{"client"}, Value: float64(q.Client)},
				{Labels: []string{"mirror"}, Value: float64(q.Mirror)},
				{Labels: []string{"backfill"}, Value: float64(q.Backfill)},
				{Labels: []string{"delayed"}, Value: float64(q.Delayed)},
				{Labels: []string{"parked"}, Value: float64(q.Parked)},
			}
		})
	reg.RegisterFunc("pullthrough_fullscan_in_flight",
		"The full scan's scans running.", "gauge",
		func() float64 { return float64(status().Queue.InFlight) })
	reg.RegisterFuncVec("pullthrough_fullscan_scans_total",
		"The full scan's readings, by how they were obtained: model (a model call) or cached (the verdict cache).", "counter",
		[]string{"upstream", "result"},
		byKey(func(u UpstreamStatus) map[string]float64 {
			return map[string]float64{"model": float64(u.Counters.Scans), "cached": float64(u.Counters.CachedVerdicts)}
		}))
	reg.RegisterFuncVec("pullthrough_fullscan_verdicts_total",
		"The full scan's readings with a verdict, by the gate's reading (benign, suspicious, malicious).", "counter",
		[]string{"upstream", "verdict"},
		byKey(func(u UpstreamStatus) map[string]float64 { return counts(u.Counters.Verdicts) }))
	reg.RegisterFuncVec("pullthrough_fullscan_unscanned_total",
		"The full scan's readings without a verdict, by reason code.", "counter",
		[]string{"upstream", "code"},
		byKey(func(u UpstreamStatus) map[string]float64 { return counts(u.Counters.Unscanned) }))
	reg.RegisterFuncVec("pullthrough_fullscan_enforced_total",
		"Readings of tracked artifacts the configured action refuses (refused), and the artifacts the ladder evicted (evicted).", "counter",
		[]string{"upstream", "outcome"},
		byKey(func(u UpstreamStatus) map[string]float64 {
			return map[string]float64{"refused": float64(u.Counters.Refused), "evicted": float64(u.Counters.Evicted)}
		}))
	reg.RegisterFuncVec("pullthrough_fullscan_rescans_total",
		"Artifacts put back into the queue, by reason (version: the scan signature changed; operator: a re-scan request).", "counter",
		[]string{"upstream", "reason"},
		byKey(func(u UpstreamStatus) map[string]float64 { return counts(u.Counters.Rescans) }))
	reg.RegisterFuncVec("pullthrough_fullscan_errors_total",
		"Failed attempts to judge an artifact.", "counter", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Counters.Errors), true }))
	reg.RegisterFuncVec("pullthrough_fullscan_spend_usd",
		"What the full scan's model calls cost in the current window (day, month: UTC).", "gauge",
		[]string{"window"},
		func() []metrics.LabeledValue {
			st := status()
			if !st.Enabled {
				return nil
			}
			return []metrics.LabeledValue{
				{Labels: []string{WindowDay}, Value: st.Budget.Daily.SpentUSD},
				{Labels: []string{WindowMonth}, Value: st.Budget.Monthly.SpentUSD},
			}
		})
	reg.RegisterFuncVec("pullthrough_fullscan_budget_usd",
		"The full scan's cost ceiling per window (0: none).", "gauge",
		[]string{"window"},
		func() []metrics.LabeledValue {
			st := status()
			if !st.Enabled {
				return nil
			}
			return []metrics.LabeledValue{
				{Labels: []string{WindowDay}, Value: st.Budget.Daily.CeilingUSD},
				{Labels: []string{WindowMonth}, Value: st.Budget.Monthly.CeilingUSD},
			}
		})
	reg.RegisterFunc("pullthrough_fullscan_budget_exhausted",
		"1 while a cost ceiling is spent and the queue is paused.", "gauge",
		func() float64 {
			if status().Budget.Exhausted {
				return 1
			}
			return 0
		})
	reg.RegisterFuncVec("pullthrough_fullscan_upstream_spend_usd_total",
		"What the full scan's model calls for the upstream cost, in total.", "counter", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return u.SpentUSD, true }))
	reg.RegisterFuncVec("pullthrough_fullscan_untracked",
		"Cached objects of the upstream the last sweep could not track (cached before fill metadata existed).", "gauge", up,
		perUpstream(func(u UpstreamStatus) (float64, bool) { return float64(u.Untracked), true }))
	reg.RegisterFunc("pullthrough_fullscan_last_sweep_timestamp_seconds",
		"When the last backfill sweep finished (Unix time; 0: none yet).", "gauge",
		func() float64 {
			if t := status().Sweep.LastFinished; !t.IsZero() {
				return float64(t.UnixNano()) / 1e9
			}
			return 0
		})
	reg.RegisterFunc("pullthrough_fullscan_dropped_total",
		"Notes about artifacts dropped because the full scan could not keep up (the sweep finds them later).", "counter",
		func() float64 { return float64(status().Dropped) })
}
