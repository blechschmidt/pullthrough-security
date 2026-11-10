package loadbench

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BaselineSchemaVersion is the on-disk schema version of a stored baseline. It
// is bumped if the set of compared metrics or the file layout changes in a way
// that makes an older baseline incomparable, so a stale file is rejected with a
// clear message rather than silently mis-compared.
const BaselineSchemaVersion = 1

// Baseline is a committed snapshot of the performance of the key pull-path
// scenarios, captured on a known machine. It is the reference a later run is
// compared against by the regression guard. It is JSON-serialized to a file
// checked into the repo (see docs/performance.md) and regenerated with
// `ptctl perfguard -update-baseline`.
type Baseline struct {
	// SchemaVersion guards against comparing against an incompatible layout.
	SchemaVersion int `json:"schemaVersion"`
	// CapturedAt is when the baseline run completed (RFC 3339).
	CapturedAt time.Time `json:"capturedAt"`
	// Tool is the version of the harness that produced the baseline, for
	// traceability.
	Tool string `json:"tool,omitempty"`
	// Machine is a free-form, human-supplied note describing the hardware /
	// environment the baseline was captured on. Latency and throughput are
	// machine-specific, so a baseline is only meaningful when re-measured on a
	// comparable host; this field records which host it was.
	Machine string `json:"machine,omitempty"`
	// Scenarios holds one snapshot per benchmark scenario, keyed by scenario
	// name (e.g. "pull", "cache-read", "admission-pipeline").
	Scenarios map[string]ScenarioSnapshot `json:"scenarios"`
}

// ScenarioSnapshot is the subset of a load-run Result that the regression guard
// compares, plus the run parameters needed to reproduce it. Latency values are
// nanoseconds in JSON (matching LatencyStats); throughput is requests/second.
type ScenarioSnapshot struct {
	// Workload is the loadbench workload name this scenario drove.
	Workload string `json:"workload"`
	// Concurrency and Requests are the run parameters, recorded so a comparison
	// run can be driven with the same shape.
	Concurrency int `json:"concurrency"`
	Requests    int `json:"requests"`

	// ThroughputRPS is the achieved request rate (higher is better).
	ThroughputRPS float64 `json:"throughputRps"`

	// Latency percentiles (lower is better).
	P50 time.Duration `json:"p50Nanos"`
	P95 time.Duration `json:"p95Nanos"`
	P99 time.Duration `json:"p99Nanos"`

	// Samples is the measured request count behind the latency distribution. A
	// comparison against a baseline captured from too few samples is noisy, so
	// the guard can warn when either side is below a floor.
	Samples int64 `json:"samples"`

	// ConnReuseRatio is the proxy→upstream connection-reuse ratio measured over
	// the run (reused/acquired, in [0,1]), captured from the server's
	// pullthrough_upstream_conn_* metrics. Higher is better. It is present only
	// for scenarios that drive upstream fetches and had a server-metrics sampler
	// wired (the connection-reuse benchmark); a zero/absent value means the
	// scenario did not measure it and the guard does not gate on it.
	ConnReuseRatio float64 `json:"connReuseRatio,omitempty"`
}

// SnapshotFromResult extracts the compared metrics from a completed run. When
// the run captured server-side connection-pool metrics, the connection-reuse
// ratio is recorded too so the guard can gate on connection churn.
func SnapshotFromResult(workload string, concurrency, requests int, res Result) ScenarioSnapshot {
	snap := ScenarioSnapshot{
		Workload:      workload,
		Concurrency:   concurrency,
		Requests:      requests,
		ThroughputRPS: res.Throughput(),
		P50:           res.Latency.P50,
		P95:           res.Latency.P95,
		P99:           res.Latency.P99,
		Samples:       res.Latency.Count,
	}
	if res.Server != nil {
		snap.ConnReuseRatio = res.Server.ConnReuseRatio()
	}
	return snap
}

// LoadBaseline reads and validates a baseline JSON file.
func LoadBaseline(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodeBaseline(f)
}

// DecodeBaseline reads a baseline from r and validates its schema version.
func DecodeBaseline(r io.Reader) (*Baseline, error) {
	var b Baseline
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode baseline: %w", err)
	}
	if b.SchemaVersion != BaselineSchemaVersion {
		return nil, fmt.Errorf("baseline schema version %d is not supported (this build expects %d); regenerate with -update-baseline",
			b.SchemaVersion, BaselineSchemaVersion)
	}
	if len(b.Scenarios) == 0 {
		return nil, fmt.Errorf("baseline contains no scenarios")
	}
	return &b, nil
}

// Save writes the baseline to path as indented JSON, creating parent
// directories as needed. The write is atomic (temp file + rename) so a crash
// mid-write cannot leave a truncated, un-parseable baseline checked out.
func (b *Baseline) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".perf-baseline-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// MetricKind identifies one compared metric.
type MetricKind int

const (
	// MetricThroughput is requests/second; higher is better.
	MetricThroughput MetricKind = iota
	// MetricP50, MetricP95, MetricP99 are latency percentiles; lower is better.
	MetricP50
	MetricP95
	MetricP99
	// MetricConnReuse is the proxy→upstream connection-reuse ratio; higher is
	// better. Unlike the core four it is compared only for scenarios that
	// measured it (see Compare), so a drop in connection reuse — rising churn —
	// fails the guard without affecting scenarios that never fetch upstream.
	MetricConnReuse
)

// String returns the metric's short label.
func (m MetricKind) String() string {
	switch m {
	case MetricThroughput:
		return "throughput"
	case MetricP50:
		return "p50"
	case MetricP95:
		return "p95"
	case MetricP99:
		return "p99"
	case MetricConnReuse:
		return "connReuse"
	default:
		return "unknown"
	}
}

// higherIsBetter reports whether a larger value for this metric is an
// improvement (throughput, connection reuse) rather than a regression (latency).
func (m MetricKind) higherIsBetter() bool {
	return m == MetricThroughput || m == MetricConnReuse
}

// comparedMetrics is the fixed, ordered set of metrics the guard evaluates.
var comparedMetrics = []MetricKind{MetricThroughput, MetricP50, MetricP95, MetricP99}

// RegressionPolicy configures how much a metric may degrade before it counts as
// a regression. All percentages are expressed as whole percent (e.g. 15 == 15%).
type RegressionPolicy struct {
	// AllowedRegressionPct is the default tolerance applied to every metric
	// that does not have a more specific override.
	AllowedRegressionPct float64
	// LatencyRegressionPct, if > 0, overrides AllowedRegressionPct for the
	// latency percentiles (p50/p95/p99).
	LatencyRegressionPct float64
	// ThroughputRegressionPct, if > 0, overrides AllowedRegressionPct for
	// throughput.
	ThroughputRegressionPct float64
	// MinSamples, if > 0, is the per-side sample floor below which a scenario's
	// latency comparison is flagged as low-confidence (reported, not failed).
	MinSamples int64
}

// DefaultRegressionPolicy is a conservative starting point: a 15% degradation
// on any metric fails the guard. Operators tune this per environment.
func DefaultRegressionPolicy() RegressionPolicy {
	return RegressionPolicy{AllowedRegressionPct: 15, MinSamples: 100}
}

// tolerance returns the allowed-regression percentage for a metric, applying the
// per-class override when set.
func (p RegressionPolicy) tolerance(m MetricKind) float64 {
	switch m {
	case MetricThroughput:
		if p.ThroughputRegressionPct > 0 {
			return p.ThroughputRegressionPct
		}
	case MetricP50, MetricP95, MetricP99:
		if p.LatencyRegressionPct > 0 {
			return p.LatencyRegressionPct
		}
	}
	// Connection reuse (and any metric without a class override) uses the default
	// tolerance; the latency override deliberately does not apply to it.
	return p.AllowedRegressionPct
}

// metricValue returns a scenario's value for a metric as a float64 (throughput
// in req/s, latencies in nanoseconds).
func (s ScenarioSnapshot) metricValue(m MetricKind) float64 {
	switch m {
	case MetricThroughput:
		return s.ThroughputRPS
	case MetricP50:
		return float64(s.P50)
	case MetricP95:
		return float64(s.P95)
	case MetricP99:
		return float64(s.P99)
	case MetricConnReuse:
		return s.ConnReuseRatio
	default:
		return 0
	}
}

// MetricComparison is the evaluation of one metric for one scenario.
type MetricComparison struct {
	Metric MetricKind `json:"metric"`
	// Baseline and Current are the metric values (req/s for throughput,
	// nanoseconds for latency).
	Baseline float64 `json:"baseline"`
	Current  float64 `json:"current"`
	// ChangePct is the signed change of Current relative to Baseline, as a
	// percentage. For throughput a negative value is a slowdown; for latency a
	// positive value is a slowdown.
	ChangePct float64 `json:"changePct"`
	// RegressionPct is the degradation in the "worse" direction as a positive
	// percentage (0 when the metric improved or held). It is what AllowedPct is
	// checked against.
	RegressionPct float64 `json:"regressionPct"`
	// AllowedPct is the tolerance that applied to this metric.
	AllowedPct float64 `json:"allowedPct"`
	// Regressed is true when RegressionPct exceeds AllowedPct.
	Regressed bool `json:"regressed"`
}

// ScenarioComparison is the evaluation of every metric for one scenario.
type ScenarioComparison struct {
	Name string `json:"name"`
	// Missing is set when the scenario is present in one side but not the other.
	Missing string `json:"missing,omitempty"` // "baseline" or "current"
	// LowConfidence is set when either side had fewer than MinSamples samples.
	LowConfidence bool               `json:"lowConfidence,omitempty"`
	Metrics       []MetricComparison `json:"metrics,omitempty"`
}

// Regressed reports whether any metric in the scenario regressed. A scenario
// that is missing from the current run counts as a regression (a benchmark that
// stopped running is a signal, not a pass); one that is new (missing from the
// baseline) does not fail the guard but is surfaced.
func (c ScenarioComparison) Regressed() bool {
	if c.Missing == "current" {
		return true
	}
	for _, m := range c.Metrics {
		if m.Regressed {
			return true
		}
	}
	return false
}

// Report is the full result of comparing a current run against a baseline.
type Report struct {
	Policy    RegressionPolicy     `json:"policy"`
	Baseline  BaselineMeta         `json:"baseline"`
	Scenarios []ScenarioComparison `json:"scenarios"`
}

// BaselineMeta is the provenance of the baseline a report was compared against.
type BaselineMeta struct {
	CapturedAt time.Time `json:"capturedAt"`
	Machine    string    `json:"machine,omitempty"`
	Tool       string    `json:"tool,omitempty"`
}

// Regressed reports whether the run regressed against the baseline on any
// scenario/metric.
func (r Report) Regressed() bool {
	for _, s := range r.Scenarios {
		if s.Regressed() {
			return true
		}
	}
	return false
}

// RegressionCount returns the number of individual metric regressions across all
// scenarios (missing scenarios count as one each).
func (r Report) RegressionCount() int {
	n := 0
	for _, s := range r.Scenarios {
		if s.Missing == "current" {
			n++
			continue
		}
		for _, m := range s.Metrics {
			if m.Regressed {
				n++
			}
		}
	}
	return n
}

// Compare evaluates a current baseline snapshot against a stored one under a
// policy, producing a per-scenario, per-metric report. Scenarios are compared
// by name; the union of both sides is reported so a dropped or added benchmark
// is visible. The two Baselines are snapshots of the same shape — the "current"
// one is produced by a fresh run, not loaded from disk.
func Compare(baseline, current *Baseline, policy RegressionPolicy) Report {
	rep := Report{
		Policy: policy,
		Baseline: BaselineMeta{
			CapturedAt: baseline.CapturedAt,
			Machine:    baseline.Machine,
			Tool:       baseline.Tool,
		},
	}

	// Stable, deterministic scenario ordering over the union of both sides.
	names := map[string]struct{}{}
	for n := range baseline.Scenarios {
		names[n] = struct{}{}
	}
	for n := range current.Scenarios {
		names[n] = struct{}{}
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)

	for _, name := range ordered {
		base, inBase := baseline.Scenarios[name]
		cur, inCur := current.Scenarios[name]
		sc := ScenarioComparison{Name: name}
		switch {
		case inBase && !inCur:
			sc.Missing = "current"
		case !inBase && inCur:
			sc.Missing = "baseline"
		default:
			if policy.MinSamples > 0 && (base.Samples < policy.MinSamples || cur.Samples < policy.MinSamples) {
				sc.LowConfidence = true
			}
			for _, m := range comparedMetrics {
				sc.Metrics = append(sc.Metrics, compareMetric(m, base.metricValue(m), cur.metricValue(m), policy.tolerance(m)))
			}
			// Connection reuse is gated only for scenarios that measured it (an
			// upstream-fetching workload with a server-metrics sampler). Appending
			// it conditionally keeps cache-hit-only scenarios — which never fetch
			// upstream — from reporting a meaningless 0%→0% reuse comparison.
			if base.ConnReuseRatio > 0 || cur.ConnReuseRatio > 0 {
				sc.Metrics = append(sc.Metrics, compareMetric(MetricConnReuse,
					base.metricValue(MetricConnReuse), cur.metricValue(MetricConnReuse),
					policy.tolerance(MetricConnReuse)))
			}
		}
		rep.Scenarios = append(rep.Scenarios, sc)
	}
	return rep
}

// compareMetric evaluates a single metric. A non-positive baseline value is
// treated as un-comparable (no regression can be computed), which avoids a
// divide-by-zero turning an empty baseline into a spurious failure.
func compareMetric(m MetricKind, baseVal, curVal, allowedPct float64) MetricComparison {
	mc := MetricComparison{
		Metric:     m,
		Baseline:   baseVal,
		Current:    curVal,
		AllowedPct: allowedPct,
	}
	if baseVal <= 0 {
		return mc
	}
	// Signed change of current relative to baseline.
	mc.ChangePct = (curVal - baseVal) / baseVal * 100

	// Degradation in the metric's "worse" direction, as a positive percentage.
	var regression float64
	if m.higherIsBetter() {
		// Throughput dropped: fewer req/s than baseline.
		regression = (baseVal - curVal) / baseVal * 100
	} else {
		// Latency grew: more nanoseconds than baseline.
		regression = (curVal - baseVal) / baseVal * 100
	}
	if regression < 0 {
		regression = 0 // improved or held — not a regression
	}
	mc.RegressionPct = regression
	// A tiny epsilon absorbs float rounding so an exactly-at-threshold value is
	// not flipped to a failure by representation error.
	mc.Regressed = regression > allowedPct+1e-9
	return mc
}

// Format renders a human-readable comparison report.
func (r Report) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Performance regression report\n")
	fmt.Fprintf(&b, "  baseline:        captured %s", r.Baseline.CapturedAt.Format(time.RFC3339))
	if r.Baseline.Machine != "" {
		fmt.Fprintf(&b, " on %q", r.Baseline.Machine)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "  tolerance:       %s default", pct(r.Policy.AllowedRegressionPct))
	if r.Policy.LatencyRegressionPct > 0 {
		fmt.Fprintf(&b, ", %s latency", pct(r.Policy.LatencyRegressionPct))
	}
	if r.Policy.ThroughputRegressionPct > 0 {
		fmt.Fprintf(&b, ", %s throughput", pct(r.Policy.ThroughputRegressionPct))
	}
	fmt.Fprintf(&b, "\n\n")

	for _, sc := range r.Scenarios {
		switch sc.Missing {
		case "current":
			fmt.Fprintf(&b, "  ✗ %-20s REGRESSED: not present in the current run (benchmark dropped?)\n", sc.Name)
			continue
		case "baseline":
			fmt.Fprintf(&b, "  + %-20s new scenario (no baseline — not gated; add with -update-baseline)\n", sc.Name)
			continue
		}
		status := "ok"
		marker := "✓"
		if sc.Regressed() {
			status, marker = "REGRESSED", "✗"
		}
		fmt.Fprintf(&b, "  %s %-20s %s", marker, sc.Name, status)
		if sc.LowConfidence {
			fmt.Fprintf(&b, "  (low confidence: few samples)")
		}
		fmt.Fprintf(&b, "\n")
		for _, m := range sc.Metrics {
			fmt.Fprintf(&b, "      %-11s %s  (%+.1f%%, limit %s)%s\n",
				m.Metric.String(),
				formatMetricPair(m.Metric, m.Baseline, m.Current),
				m.ChangePct,
				pct(m.AllowedPct),
				regressionMark(m.Regressed),
			)
		}
	}

	fmt.Fprintf(&b, "\n")
	if r.Regressed() {
		fmt.Fprintf(&b, "RESULT: FAIL — %d metric(s) regressed beyond threshold\n", r.RegressionCount())
	} else {
		fmt.Fprintf(&b, "RESULT: PASS — no metric regressed beyond threshold\n")
	}
	return b.String()
}

func regressionMark(regressed bool) string {
	if regressed {
		return "  <-- regression"
	}
	return ""
}

// formatMetricPair renders "baseline -> current" in the metric's natural unit.
func formatMetricPair(m MetricKind, baseVal, curVal float64) string {
	switch m {
	case MetricThroughput:
		return fmt.Sprintf("%.1f -> %.1f req/s", baseVal, curVal)
	case MetricConnReuse:
		return fmt.Sprintf("%.1f%% -> %.1f%% reuse", baseVal*100, curVal*100)
	default:
		return fmt.Sprintf("%s -> %s", dur(time.Duration(baseVal)), dur(time.Duration(curVal)))
	}
}

func pct(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%.0f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}
