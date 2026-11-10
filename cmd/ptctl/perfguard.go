package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/loadbench"
)

// defaultBaselinePath is the committed baseline the guard compares against. It
// lives under perf/ next to the hermetic rig that regenerates it.
const defaultBaselinePath = "perf/perf-baseline.json"

// perfScenario is one entry in the fixed, committed benchmark suite the guard
// runs. The suite is intentionally small and stable so a baseline stays
// comparable across evolve iterations: the three scenarios cover the hot paths
// the project must not silently regress.
type perfScenario struct {
	name     string
	workload string
	desc     string
}

// perfSuite is the committed scenario suite. Each scenario maps to a loadbench
// workload (see docs/performance.md):
//
//   - pull                the cold upstream-fetch + cache-fill path (every
//     request is a unique key -> MISS).
//   - cache-read          steady-state serving from a warmed cache (the hottest
//     read path -> all HITs).
//   - admission-pipeline  a realistic blend of a hot key served from cache and a
//     stream of unique cold keys, so each cold key traverses
//     the full fetch -> admission/scan/gate -> fill chain
//     while hot keys serve from cache.
//   - conn-reuse          a unique cold key every request at high concurrency so
//     the proxy's outbound connection pool is driven hard; the
//     gated metric is the proxy→upstream connection-reuse
//     ratio, so a transport change that increases connection
//     churn (worse keep-alive reuse) fails the guard in CI.
var perfSuite = []perfScenario{
	{name: "pull", workload: "cache-miss", desc: "cold upstream fetch + cache fill"},
	{name: "cache-read", workload: "cache-hit", desc: "steady-state serve from warmed cache"},
	{name: "admission-pipeline", workload: "mixed", desc: "hot cache + cold-key admission blend"},
	{name: "conn-reuse", workload: "conn-reuse", desc: "upstream connection reuse under concurrent cold fetches"},
}

// perfguardFlags are the knobs for `ptctl perfguard`, on top of the global
// connection flags.
type perfguardFlags struct {
	baseline       string
	updateBaseline bool
	allowedRegress float64
	allowedLatency float64
	allowedThrough float64
	minSamples     int64
	concurrency    int
	requests       int
	warmup         int
	backend        string
	scenarioFilter string
	machine        string
	jsonOut        bool
}

// runPerfguard implements `ptctl perfguard`: it runs the committed pull /
// cache-read / admission-pipeline benchmark suite against a running proxy and
// either records a new baseline (-update-baseline) or compares the run against
// the stored baseline and exits non-zero on a regression beyond threshold. It
// is the CI-runnable performance guard built on the Task 105 harness.
func runPerfguard(args []string) error {
	fs := flag.NewFlagSet("perfguard", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)

	var pf perfguardFlags
	fs.StringVar(&pf.baseline, "baseline", defaultBaselinePath, "path to the stored baseline JSON")
	fs.BoolVar(&pf.updateBaseline, "update-baseline", false, "run the suite and overwrite the baseline file instead of comparing")
	fs.Float64Var(&pf.allowedRegress, "allowed-regression", 15, "default allowed regression percent per metric before the guard fails")
	fs.Float64Var(&pf.allowedLatency, "allowed-latency-regression", 0, "override allowed regression percent for latency percentiles (0 = use -allowed-regression)")
	fs.Float64Var(&pf.allowedThrough, "allowed-throughput-regression", 0, "override allowed regression percent for throughput (0 = use -allowed-regression)")
	fs.Int64Var(&pf.minSamples, "min-samples", 100, "flag a scenario as low-confidence when either side has fewer than this many samples")
	fs.IntVar(&pf.concurrency, "concurrency", 50, "number of concurrent workers per scenario")
	fs.IntVar(&pf.requests, "requests", 2000, "fixed total requests per scenario (fixed count keeps sample sizes reproducible)")
	fs.IntVar(&pf.warmup, "warmup", 1, "warmup requests before measuring (fixed-path scenarios)")
	fs.StringVar(&pf.backend, "backend", "npm", "backend mount name used to synthesize workload paths")
	fs.StringVar(&pf.scenarioFilter, "scenarios", "", "comma-separated subset of scenarios to run (default: all)")
	fs.StringVar(&pf.machine, "machine", "", "machine/environment note stored in a new baseline (default: hostname)")
	fs.BoolVar(&pf.jsonOut, "json", false, "emit the baseline (update) or comparison report (compare) as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl perfguard [flags]")
		fmt.Fprintln(os.Stderr, "Run the committed pull-path benchmark suite against a running proxy and guard")
		fmt.Fprintln(os.Stderr, "against performance regressions versus a stored baseline. Exits non-zero when a")
		fmt.Fprintln(os.Stderr, "metric regresses beyond the allowed threshold.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Scenarios (committed suite):")
		for _, s := range perfSuite {
			fmt.Fprintf(os.Stderr, "  %-20s %s\n", s.name, s.desc)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Compared metrics: throughput (req/s), p50 / p95 / p99 latency.")
		fmt.Fprintln(os.Stderr, "Latency and throughput are machine-specific: compare only against a baseline")
		fmt.Fprintln(os.Stderr, "captured on a comparable host (see docs/performance.md#performance-regression-guard).")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if pf.requests <= 0 {
		return fmt.Errorf("-requests must be > 0 (the guard uses a fixed request count for reproducible sample sizes)")
	}

	scenarios, err := selectScenarios(pf.scenarioFilter)
	if err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	// Run every selected scenario and assemble the current snapshot.
	current := &loadbench.Baseline{
		SchemaVersion: loadbench.BaselineSchemaVersion,
		CapturedAt:    time.Now().UTC(),
		Tool:          "ptctl " + version,
		Machine:       resolveMachine(pf.machine),
		Scenarios:     make(map[string]loadbench.ScenarioSnapshot, len(scenarios)),
	}
	for _, s := range scenarios {
		fmt.Fprintf(os.Stderr, ">> running scenario %q (%s): %d requests @ concurrency %d\n",
			s.name, s.workload, pf.requests, pf.concurrency)
		snap, err := runPerfScenario(c, g, pf, s)
		if err != nil {
			return fmt.Errorf("scenario %q: %w", s.name, err)
		}
		current.Scenarios[s.name] = snap
	}

	if pf.updateBaseline {
		if err := current.Save(pf.baseline); err != nil {
			return fmt.Errorf("write baseline %s: %w", pf.baseline, err)
		}
		if pf.jsonOut {
			return writeJSONIndented(os.Stdout, current)
		}
		fmt.Fprintf(os.Stdout, "Baseline written to %s\n", pf.baseline)
		fmt.Fprintf(os.Stdout, "  captured:  %s\n", current.CapturedAt.Format(time.RFC3339))
		fmt.Fprintf(os.Stdout, "  machine:   %s\n", current.Machine)
		fmt.Fprintf(os.Stdout, "  scenarios: %s\n", strings.Join(scenarioNames(scenarios), ", "))
		fmt.Fprintln(os.Stdout, "\nCommit this file. Regenerate it on the same class of CI hardware whenever an")
		fmt.Fprintln(os.Stdout, "intentional, accepted performance change lands.")
		return nil
	}

	baseline, err := loadbench.LoadBaseline(pf.baseline)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no baseline at %s: capture one first with `ptctl perfguard -update-baseline`", pf.baseline)
		}
		return fmt.Errorf("load baseline %s: %w", pf.baseline, err)
	}

	// When the operator ran a subset (-scenarios), restrict the baseline to that
	// subset so the un-run scenarios are not misreported as "dropped" (and thus
	// a false regression). With the full suite, a baseline scenario that the run
	// did not produce legitimately signals a dropped benchmark and still fails.
	if strings.TrimSpace(pf.scenarioFilter) != "" {
		baseline = restrictBaseline(baseline, scenarioNames(scenarios))
	}

	policy := loadbench.RegressionPolicy{
		AllowedRegressionPct:    pf.allowedRegress,
		LatencyRegressionPct:    pf.allowedLatency,
		ThroughputRegressionPct: pf.allowedThrough,
		MinSamples:              pf.minSamples,
	}
	report := loadbench.Compare(baseline, current, policy)

	if pf.jsonOut {
		if err := writeJSONIndented(os.Stdout, report); err != nil {
			return err
		}
	} else {
		fmt.Fprint(os.Stdout, report.Format())
	}

	if report.Regressed() {
		// A non-nil error propagates to main() and exits 1 — the CI gate.
		return fmt.Errorf("performance regression detected: %d metric(s) exceeded the allowed threshold", report.RegressionCount())
	}
	return nil
}

// runPerfScenario drives one scenario and returns its snapshot. It reuses the
// loadtest workload synthesis so the paths match `ptctl loadtest` exactly.
func runPerfScenario(c *client, g globalFlags, pf perfguardFlags, s perfScenario) (loadbench.ScenarioSnapshot, error) {
	targets, warmup, err := buildWorkload(loadtestFlags{
		workload: s.workload,
		backend:  pf.backend,
		warmup:   pf.warmup,
	})
	if err != nil {
		return loadbench.ScenarioSnapshot{}, err
	}

	cfg := loadbench.Config{
		BaseURL:     c.baseURL,
		Targets:     targets,
		Concurrency: pf.concurrency,
		Requests:    pf.requests,
		Warmup:      warmup,
		Token:       c.token,
		Tenant:      c.tenant,
		HTTPClient:  c.http,
		Timeout:     g.timeout,
	}
	// The connection-reuse scenario captures the proxy's outbound connection-pool
	// counters so its snapshot records the reuse ratio and the guard gates on
	// connection churn. The sampler reads only the Prometheus metrics endpoint, so
	// it needs no admin access; if that endpoint is unreachable the scenario still
	// runs and simply records no reuse ratio (ungated) rather than failing.
	if s.workload == "conn-reuse" {
		cfg.ServerMetrics = c.connMetricsSampler()
	}
	runner, err := loadbench.New(cfg)
	if err != nil {
		return loadbench.ScenarioSnapshot{}, err
	}
	res, err := runner.Run(context.Background())
	if err != nil {
		return loadbench.ScenarioSnapshot{}, err
	}
	// Transport-level failures make the measurement meaningless; surface them
	// rather than recording a fast-but-broken baseline.
	if res.Failures > 0 || res.ServerErrors > 0 {
		return loadbench.ScenarioSnapshot{}, fmt.Errorf("%d transport failures, %d 5xx responses — is the proxy healthy and the workload path valid?",
			res.Failures, res.ServerErrors)
	}
	return loadbench.SnapshotFromResult(s.workload, pf.concurrency, pf.requests, res), nil
}

// selectScenarios resolves the --scenarios filter against the committed suite,
// preserving the suite's order and rejecting unknown names.
func selectScenarios(filter string) ([]perfScenario, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return perfSuite, nil
	}
	want := map[string]bool{}
	for _, name := range strings.Split(filter, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			want[name] = true
		}
	}
	var out []perfScenario
	for _, s := range perfSuite {
		if want[s.name] {
			out = append(out, s)
			delete(want, s.name)
		}
	}
	if len(want) > 0 {
		unknown := make([]string, 0, len(want))
		for n := range want {
			unknown = append(unknown, n)
		}
		return nil, fmt.Errorf("unknown scenario(s): %s (known: %s)", strings.Join(unknown, ", "), strings.Join(suiteNames(), ", "))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no scenarios selected")
	}
	return out, nil
}

// restrictBaseline returns a shallow copy of b holding only the named
// scenarios, used when the operator compares a subset of the suite.
func restrictBaseline(b *loadbench.Baseline, names []string) *loadbench.Baseline {
	keep := make(map[string]loadbench.ScenarioSnapshot, len(names))
	for _, n := range names {
		if s, ok := b.Scenarios[n]; ok {
			keep[n] = s
		}
	}
	out := *b
	out.Scenarios = keep
	return &out
}

func suiteNames() []string {
	names := make([]string, 0, len(perfSuite))
	for _, s := range perfSuite {
		names = append(names, s.name)
	}
	return names
}

func scenarioNames(ss []perfScenario) []string {
	names := make([]string, 0, len(ss))
	for _, s := range ss {
		names = append(names, s.name)
	}
	return names
}

// resolveMachine returns the machine note for a new baseline, defaulting to the
// hostname so an un-annotated baseline still records where it came from.
func resolveMachine(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}
