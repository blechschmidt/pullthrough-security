package loadbench

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mkBaseline builds a one-scenario baseline for comparison tests.
func mkBaseline(name string, rps float64, p50, p95, p99 time.Duration, samples int64) *Baseline {
	return &Baseline{
		SchemaVersion: BaselineSchemaVersion,
		CapturedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Scenarios: map[string]ScenarioSnapshot{
			name: {
				Workload:      name,
				Concurrency:   10,
				Requests:      1000,
				ThroughputRPS: rps,
				P50:           p50,
				P95:           p95,
				P99:           p99,
				Samples:       samples,
			},
		},
	}
}

func TestCompareNoRegression(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	// Current is slightly better across the board.
	cur := mkBaseline("pull", 1050, 9*time.Millisecond, 19*time.Millisecond, 29*time.Millisecond, 1000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if rep.Regressed() {
		t.Fatalf("expected no regression, got %d", rep.RegressionCount())
	}
	// Throughput improvement should show a positive change and zero regression.
	m := findMetric(t, rep, "pull", MetricThroughput)
	if m.RegressionPct != 0 {
		t.Fatalf("throughput regression = %v, want 0", m.RegressionPct)
	}
	if m.ChangePct <= 0 {
		t.Fatalf("throughput changePct = %v, want > 0 (improved)", m.ChangePct)
	}
}

func TestCompareLatencyRegressionDetected(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	// p95 grew 20ms -> 25ms = +25%, beyond the default 15%.
	cur := mkBaseline("pull", 1000, 10*time.Millisecond, 25*time.Millisecond, 30*time.Millisecond, 1000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if !rep.Regressed() {
		t.Fatal("expected a regression on p95")
	}
	m := findMetric(t, rep, "pull", MetricP95)
	if !m.Regressed {
		t.Fatalf("p95 should be flagged regressed: %+v", m)
	}
	if m.RegressionPct < 24.9 || m.RegressionPct > 25.1 {
		t.Fatalf("p95 regressionPct = %.2f, want ~25", m.RegressionPct)
	}
	// p50 and p99 held, so they must not be flagged.
	if findMetric(t, rep, "pull", MetricP50).Regressed {
		t.Fatal("p50 should not be flagged")
	}
}

func TestCompareThroughputRegressionDetected(t *testing.T) {
	base := mkBaseline("cache-read", 2000, time.Millisecond, 2*time.Millisecond, 3*time.Millisecond, 5000)
	// Throughput dropped 2000 -> 1600 = -20%, beyond 15%.
	cur := mkBaseline("cache-read", 1600, time.Millisecond, 2*time.Millisecond, 3*time.Millisecond, 5000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if !rep.Regressed() {
		t.Fatal("expected a throughput regression")
	}
	m := findMetric(t, rep, "cache-read", MetricThroughput)
	if !m.Regressed {
		t.Fatalf("throughput should be flagged: %+v", m)
	}
	if m.ChangePct > -19.9 || m.ChangePct < -20.1 {
		t.Fatalf("throughput changePct = %.2f, want ~-20", m.ChangePct)
	}
}

func TestCompareWithinTolerance(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	// p95 grew exactly 10% (20 -> 22ms); default tolerance is 15%, so it passes.
	cur := mkBaseline("pull", 1000, 10*time.Millisecond, 22*time.Millisecond, 30*time.Millisecond, 1000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if rep.Regressed() {
		t.Fatalf("10%% growth under a 15%% tolerance must pass; count=%d", rep.RegressionCount())
	}
}

func TestComparePerMetricTolerance(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	// p95 grew 12% (20 -> 22.4ms). A tight 5% latency override must fail it,
	// even though the default tolerance is 15%.
	cur := mkBaseline("pull", 1000, 10*time.Millisecond, 22400*time.Microsecond, 30*time.Millisecond, 1000)

	policy := RegressionPolicy{AllowedRegressionPct: 15, LatencyRegressionPct: 5}
	rep := Compare(base, cur, policy)
	if !rep.Regressed() {
		t.Fatal("expected the tight latency override to flag a 12% growth")
	}
	if got := findMetric(t, rep, "pull", MetricP95).AllowedPct; got != 5 {
		t.Fatalf("p95 allowedPct = %v, want 5 (override)", got)
	}
	if got := findMetric(t, rep, "pull", MetricThroughput).AllowedPct; got != 15 {
		t.Fatalf("throughput allowedPct = %v, want 15 (default)", got)
	}
}

func TestCompareMissingScenarioFailsGuard(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	cur := &Baseline{SchemaVersion: BaselineSchemaVersion, Scenarios: map[string]ScenarioSnapshot{}}

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if !rep.Regressed() {
		t.Fatal("a scenario that stopped running must fail the guard")
	}
	if len(rep.Scenarios) != 1 || rep.Scenarios[0].Missing != "current" {
		t.Fatalf("expected one scenario missing from current, got %+v", rep.Scenarios)
	}
}

func TestCompareNewScenarioDoesNotFail(t *testing.T) {
	base := &Baseline{SchemaVersion: BaselineSchemaVersion, Scenarios: map[string]ScenarioSnapshot{}}
	cur := mkBaseline("brand-new", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if rep.Regressed() {
		t.Fatal("a scenario new to the baseline must not fail the guard")
	}
	if rep.Scenarios[0].Missing != "baseline" {
		t.Fatalf("expected the new scenario flagged missing from baseline, got %+v", rep.Scenarios[0])
	}
}

func TestCompareLowConfidence(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 10)
	cur := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 10)

	rep := Compare(base, cur, RegressionPolicy{AllowedRegressionPct: 15, MinSamples: 100})
	if !rep.Scenarios[0].LowConfidence {
		t.Fatal("expected low-confidence flag when samples are below the floor")
	}
	// Low confidence is advisory; identical metrics must still pass.
	if rep.Regressed() {
		t.Fatal("low confidence must not by itself fail the guard")
	}
}

func TestCompareZeroBaselineNotComparable(t *testing.T) {
	base := mkBaseline("pull", 0, 0, 0, 0, 0)
	cur := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if rep.Regressed() {
		t.Fatal("a zero/empty baseline value must not be treated as a regression")
	}
}

func TestSnapshotFromResult(t *testing.T) {
	res := Result{
		Elapsed: time.Second,
		Total:   1000,
		Latency: LatencyStats{Count: 1000, P50: 5 * time.Millisecond, P95: 9 * time.Millisecond, P99: 12 * time.Millisecond},
	}
	s := SnapshotFromResult("pull", 10, 1000, res)
	if s.ThroughputRPS != 1000 {
		t.Fatalf("throughput = %v, want 1000", s.ThroughputRPS)
	}
	if s.P95 != 9*time.Millisecond || s.Samples != 1000 {
		t.Fatalf("snapshot = %+v", s)
	}
}

func TestBaselineRoundTripAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "baseline.json")
	orig := mkBaseline("pull", 1234.5, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	orig.Machine = "ci-runner-xl"
	orig.Tool = "test"

	if err := orig.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Machine != "ci-runner-xl" || len(got.Scenarios) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Scenarios["pull"].ThroughputRPS != 1234.5 {
		t.Fatalf("throughput lost in round-trip: %v", got.Scenarios["pull"].ThroughputRPS)
	}
}

func TestDecodeBaselineRejectsBadSchema(t *testing.T) {
	_, err := DecodeBaseline(strings.NewReader(`{"schemaVersion":999,"scenarios":{"x":{}}}`))
	if err == nil {
		t.Fatal("expected a schema-version mismatch error")
	}
	if !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("error = %v, want schema-version message", err)
	}
}

func TestDecodeBaselineRejectsEmpty(t *testing.T) {
	_, err := DecodeBaseline(strings.NewReader(`{"schemaVersion":1,"scenarios":{}}`))
	if err == nil || !strings.Contains(err.Error(), "no scenarios") {
		t.Fatalf("expected a no-scenarios error, got %v", err)
	}
}

func TestReportFormatMentionsResult(t *testing.T) {
	base := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	cur := mkBaseline("pull", 700, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	rep := Compare(base, cur, DefaultRegressionPolicy())
	out := rep.Format()
	if !strings.Contains(out, "RESULT: FAIL") {
		t.Fatalf("formatted report missing FAIL verdict:\n%s", out)
	}
	if !strings.Contains(out, "throughput") {
		t.Fatalf("formatted report missing metric rows:\n%s", out)
	}
}

func TestBaselineSaveIsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	b := mkBaseline("pull", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = buf
	if data.SchemaVersion != BaselineSchemaVersion {
		t.Fatalf("schema = %d", data.SchemaVersion)
	}
}

// findMetric locates one metric comparison in a report, failing the test if it
// is absent.
func TestCompareConnReuseRegressionDetected(t *testing.T) {
	base := mkBaseline("conn-reuse", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	cur := mkBaseline("conn-reuse", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	// Reuse fell from 97% to 70% — a 27.8% relative drop, beyond the default 15%.
	base.Scenarios["conn-reuse"] = withReuse(base.Scenarios["conn-reuse"], 0.97)
	cur.Scenarios["conn-reuse"] = withReuse(cur.Scenarios["conn-reuse"], 0.70)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if !rep.Regressed() {
		t.Fatal("expected a regression on connection reuse")
	}
	m := findMetric(t, rep, "conn-reuse", MetricConnReuse)
	if !m.Regressed {
		t.Fatalf("connReuse should be flagged regressed: %+v", m)
	}
}

func TestCompareConnReuseWithinToleranceAndImprovement(t *testing.T) {
	base := mkBaseline("conn-reuse", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	cur := mkBaseline("conn-reuse", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	// Reuse improved — must never be a regression.
	base.Scenarios["conn-reuse"] = withReuse(base.Scenarios["conn-reuse"], 0.90)
	cur.Scenarios["conn-reuse"] = withReuse(cur.Scenarios["conn-reuse"], 0.99)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	if rep.Regressed() {
		t.Fatalf("improved reuse must not regress, got %d", rep.RegressionCount())
	}
	m := findMetric(t, rep, "conn-reuse", MetricConnReuse)
	if m.RegressionPct != 0 || m.ChangePct <= 0 {
		t.Fatalf("connReuse improvement: regressionPct=%v changePct=%v", m.RegressionPct, m.ChangePct)
	}
}

func TestCompareConnReuseOmittedWhenUnmeasured(t *testing.T) {
	// A cache-hit-only scenario never fetches upstream, so neither side records a
	// reuse ratio; the guard must not synthesize a 0%->0% connReuse comparison.
	base := mkBaseline("cache-read", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)
	cur := mkBaseline("cache-read", 1000, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 1000)

	rep := Compare(base, cur, DefaultRegressionPolicy())
	for _, sc := range rep.Scenarios {
		for _, mc := range sc.Metrics {
			if mc.Metric == MetricConnReuse {
				t.Fatalf("connReuse metric should be omitted for an unmeasured scenario")
			}
		}
	}
}

func withReuse(s ScenarioSnapshot, ratio float64) ScenarioSnapshot {
	s.ConnReuseRatio = ratio
	return s
}

func findMetric(t *testing.T, rep Report, scenario string, m MetricKind) MetricComparison {
	t.Helper()
	for _, sc := range rep.Scenarios {
		if sc.Name != scenario {
			continue
		}
		for _, mc := range sc.Metrics {
			if mc.Metric == m {
				return mc
			}
		}
	}
	t.Fatalf("metric %s not found for scenario %q", m, scenario)
	return MetricComparison{}
}
