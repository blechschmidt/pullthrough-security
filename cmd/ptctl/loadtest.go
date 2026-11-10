package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/loadbench"
)

// loadtestFlags are the knobs for `ptctl loadtest`, on top of the global
// connection/identity flags.
type loadtestFlags struct {
	workload    string
	paths       multiFlag
	backend     string
	resource    string
	count       int
	concurrency int
	duration    time.Duration
	requests    int
	warmup      int
	noWarmup    bool
	serverStats boolTri
	jsonOut     bool
}

// boolTri is a tri-state bool flag (unset / true / false) so the server-stats
// default can depend on whether a token is present.
type boolTri struct {
	set bool
	val bool
}

func (b *boolTri) String() string {
	if !b.set {
		return "auto"
	}
	if b.val {
		return "true"
	}
	return "false"
}
func (b *boolTri) Set(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		b.set, b.val = true, true
	case "false", "0", "no", "off":
		b.set, b.val = true, false
	default:
		return fmt.Errorf("invalid boolean %q", v)
	}
	return nil
}
func (b *boolTri) IsBoolFlag() bool { return true }

// runLoadtest implements `ptctl loadtest`: it drives concurrent pulls against a
// running proxy and reports latency percentiles, throughput, and the observed
// cache / coalescing / negative-cache behavior.
func runLoadtest(args []string) error {
	fs := flag.NewFlagSet("loadtest", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)

	var lf loadtestFlags
	fs.StringVar(&lf.workload, "workload", "cache-hit", "workload: cache-hit | cache-miss | mixed | coalesce | negative | conn-reuse")
	fs.Var(&lf.paths, "path", "explicit gateway path to pull (repeatable); overrides --workload")
	fs.StringVar(&lf.backend, "backend", "npm", "backend mount name used to synthesize workload paths")
	fs.StringVar(&lf.resource, "resource", "", "resource suffix for the hot-key workloads (default derived from backend)")
	fs.IntVar(&lf.count, "count", 1000, "distinct keys for the cache-miss/mixed workloads")
	fs.IntVar(&lf.concurrency, "concurrency", 50, "number of concurrent workers")
	fs.DurationVar(&lf.duration, "duration", 10*time.Second, "run duration (ignored when --requests > 0)")
	fs.IntVar(&lf.requests, "requests", 0, "total requests to issue (0 = run for --duration)")
	fs.IntVar(&lf.warmup, "warmup", 1, "warmup requests issued before measuring (fixed-path workloads)")
	fs.BoolVar(&lf.noWarmup, "no-warmup", false, "skip the warmup phase")
	fs.Var(&lf.serverStats, "server-stats", "query the admin API for server-side cache/coalescer deltas (default: auto — on when --token is set)")
	fs.BoolVar(&lf.jsonOut, "json", false, "emit the result as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl loadtest [flags]")
		fmt.Fprintln(os.Stderr, "Drive concurrent pulls against a running proxy and report latency percentiles,")
		fmt.Fprintln(os.Stderr, "throughput, and observed cache / coalescing / negative-cache behavior.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Workloads:")
		fmt.Fprintln(os.Stderr, "  cache-hit   repeatedly pull one warmed artifact (steady-state hit serving)")
		fmt.Fprintln(os.Stderr, "  cache-miss  pull a distinct key every request (cold-fill / long tail)")
		fmt.Fprintln(os.Stderr, "  mixed       a hot key plus a stream of unique keys (realistic blend)")
		fmt.Fprintln(os.Stderr, "  coalesce    burst the same cold key from all workers (singleflight dedup)")
		fmt.Fprintln(os.Stderr, "  negative    repeatedly pull a known-missing key (negative-cache serving)")
		fmt.Fprintln(os.Stderr, "  conn-reuse  unique cold key every request to drive the proxy's upstream")
		fmt.Fprintln(os.Stderr, "              connection pool (reports the proxy→upstream reuse ratio)")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	targets, warmup, err := buildWorkload(lf)
	if err != nil {
		return err
	}

	cfg := loadbench.Config{
		BaseURL:     c.baseURL,
		Targets:     targets,
		Concurrency: lf.concurrency,
		Warmup:      warmup,
		Token:       c.token,
		Tenant:      c.tenant,
		HTTPClient:  c.http,
		Timeout:     g.timeout,
	}
	if lf.requests > 0 {
		cfg.Requests = lf.requests
	} else {
		cfg.Duration = lf.duration
	}

	// Decide whether to sample server-side metrics: explicit flag wins, else
	// default to on when a token was supplied (the admin API usually needs one).
	serverStats := lf.serverStats.val
	if !lf.serverStats.set {
		serverStats = c.token != ""
	}
	if serverStats {
		cfg.ServerMetrics = c.serverMetricsSampler()
	}

	runner, err := loadbench.New(cfg)
	if err != nil {
		return err
	}

	ctx := context.Background()
	res, err := runner.Run(ctx)
	if err != nil {
		return err
	}

	if lf.jsonOut {
		return writeJSONIndented(os.Stdout, res)
	}
	fmt.Fprint(os.Stdout, res.Format())
	return nil
}

// serverMetricsSampler returns a loadbench.ServerMetricsFunc that reads the
// proxy's authoritative cache and coalescer counters from the admin API. It
// tolerates a disabled coalescer (the /api/coalesce endpoint reports
// enabled:false) and surfaces an admin-auth failure as the sampler's error so
// the harness can report it rather than silently dropping the server-side view.
func (c *client) serverMetricsSampler() loadbench.ServerMetricsFunc {
	return func(ctx context.Context) (loadbench.ServerMetrics, error) {
		var m loadbench.ServerMetrics

		var ov struct {
			Cache *struct {
				Hits   int64 `json:"hits"`
				Misses int64 `json:"misses"`
			} `json:"cache"`
		}
		if err := c.getJSON(c.adminURL("api/overview", nil), &ov); err != nil {
			return m, err
		}
		if ov.Cache != nil {
			m.CacheHits = ov.Cache.Hits
			m.CacheMisses = ov.Cache.Misses
		}

		var co struct {
			Enabled  bool `json:"enabled"`
			Snapshot *struct {
				Lookups           int64 `json:"lookups"`
				Coalesced         int64 `json:"coalesced"`
				Leads             int64 `json:"leads"`
				NegativeHits      int64 `json:"negativeHits"`
				NegativeStored    int64 `json:"negativeStored"`
				NegativeEvictions int64 `json:"negativeEvictions"`
				NegativeEntries   int   `json:"negativeEntries"`
				InFlight          int   `json:"inFlight"`
			} `json:"snapshot"`
		}
		if err := c.getJSON(c.adminURL("api/coalesce", nil), &co); err != nil {
			return m, err
		}
		if co.Snapshot != nil {
			m.CoalesceLookups = co.Snapshot.Lookups
			m.Coalesced = co.Snapshot.Coalesced
			m.Leads = co.Snapshot.Leads
			m.NegativeHits = co.Snapshot.NegativeHits
			m.NegativeStored = co.Snapshot.NegativeStored
			m.NegativeEvictions = co.Snapshot.NegativeEvictions
			m.NegativeEntries = co.Snapshot.NegativeEntries
			m.InFlight = co.Snapshot.InFlight
		}
		// Best-effort: fold in the outbound connection-pool counters so the report
		// shows proxy→upstream reuse too. A missing metrics endpoint is not fatal
		// to the (already-successful) admin sample.
		_ = c.scrapeConnMetrics(ctx, &m)
		return m, nil
	}
}

// connMetricsSampler returns a loadbench.ServerMetricsFunc that reads only the
// proxy's outbound connection-pool counters from the Prometheus metrics
// endpoint. It is the sampler the connection-reuse benchmark (ptctl perfguard,
// conn-reuse scenario) uses: it needs no admin API access, so it works against a
// proxy whose admin surface is off or differently authenticated.
func (c *client) connMetricsSampler() loadbench.ServerMetricsFunc {
	return func(ctx context.Context) (loadbench.ServerMetrics, error) {
		var m loadbench.ServerMetrics
		if err := c.scrapeConnMetrics(ctx, &m); err != nil {
			return m, err
		}
		return m, nil
	}
}

// scrapeConnMetrics fetches the proxy's Prometheus exposition and extracts the
// outbound connection-pool counters (pullthrough_upstream_conn_*). The metrics
// path is the proxy default (/metrics); a non-default path makes the
// connection-reuse figures simply unavailable rather than failing.
func (c *client) scrapeConnMetrics(ctx context.Context, m *loadbench.ServerMetrics) error {
	u := c.baseURL + "/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("metrics endpoint %s: status %d", u, resp.StatusCode)
	}
	parseConnCounters(string(body), m)
	return nil
}

// parseConnCounters scans a Prometheus text exposition for the three label-less
// outbound connection counters the connection-reuse benchmark needs and writes
// them into m. Unknown lines, comments, and labeled series are ignored.
func parseConnCounters(text string, m *loadbench.ServerMetrics) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "pullthrough_upstream_conn_acquired_total":
			m.ConnAcquired = int64(v)
		case "pullthrough_upstream_conn_reused_total":
			m.ConnReused = int64(v)
		case "pullthrough_upstream_conn_dials_total":
			m.ConnDials = int64(v)
		}
	}
}

// buildWorkload translates the flags into a target set and an effective warmup
// count. Explicit --path values always win; otherwise the named workload is
// synthesized against the configured backend mount.
func buildWorkload(lf loadtestFlags) ([]loadbench.Target, int, error) {
	warmup := lf.warmup
	if lf.noWarmup {
		warmup = 0
	}

	if len(lf.paths) > 0 {
		targets := make([]loadbench.Target, 0, len(lf.paths))
		for _, p := range lf.paths {
			targets = append(targets, loadbench.Target{Path: p, Label: p})
		}
		return targets, warmup, nil
	}

	// The synthesized paths use the npm tarball shape (<name>/-/<file>.tgz), which
	// the default npm backend treats as an immutable, cacheable artifact (the
	// "/-/" marker is what npm keys cacheability on). It is a sensible default for
	// a local/stub npm registry; for a different backend or a real upstream, pass
	// explicit --path values that exist there (or --resource for the hot key).
	mount := "v1/" + strings.Trim(lf.backend, "/")
	hot := lf.resource
	if hot == "" {
		hot = "pullthrough-loadtest/-/pullthrough-loadtest-1.0.0.tgz"
	}
	hotPath := mount + "/" + hot
	missTmpl := mount + "/pullthrough-loadtest/-/pullthrough-loadtest-%d.0.0.tgz"
	missingPath := mount + "/pullthrough-loadtest/-/pullthrough-loadtest-absent.tgz"

	switch strings.ToLower(strings.TrimSpace(lf.workload)) {
	case "cache-hit", "":
		return []loadbench.Target{{Path: hotPath, Label: "hot"}}, warmup, nil
	case "cache-miss", "conn-reuse":
		// Every request is a unique cold key: a warmup would be meaningless. The
		// conn-reuse workload shares this shape — each pull forces a proxy→upstream
		// fetch, so the proxy's outbound connection pool is driven at the configured
		// concurrency and its reuse ratio (reused/acquired) becomes the signal.
		return []loadbench.Target{{Template: missTmpl, Label: "cold"}}, 0, nil
	case "mixed":
		// A hot key (warmed) blended with a stream of unique cold keys at a
		// 3:1 weight, approximating a real cache with a popular head and a long
		// cold tail.
		return []loadbench.Target{
			{Path: hotPath, Weight: 3, Label: "hot"},
			{Template: missTmpl, Weight: 1, Label: "cold"},
		}, warmup, nil
	case "coalesce":
		// Burst the same cold key from all workers with no warmup so the leader
		// takes the MISS and the rest coalesce onto it.
		return []loadbench.Target{{Path: hotPath, Label: "cold-hot"}}, 0, nil
	case "negative":
		// A known-missing key, warmed once so the negative entry is stored, then
		// pulled repeatedly to exercise negative-cache serving.
		w := warmup
		if w == 0 {
			w = 1
		}
		return []loadbench.Target{{Path: missingPath, Label: "absent"}}, w, nil
	default:
		return nil, 0, fmt.Errorf("unknown workload %q (want cache-hit|cache-miss|mixed|coalesce|negative|conn-reuse)", lf.workload)
	}
}
