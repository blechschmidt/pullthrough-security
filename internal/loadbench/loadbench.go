// Package loadbench is a reproducible load/throughput benchmark harness for the
// pull-through proxy's pull path. It drives concurrent GET requests against a
// *running* proxy over HTTP and reports latency percentiles (p50/p90/p99/p99.9),
// request/byte throughput, and the cache behavior it observed — the cache-hit
// ratio, singleflight request-coalescing efficacy, and negative-cache behavior.
//
// The harness classifies every response by the proxy's own `X-Cache` response
// header (HIT / MISS / COALESCED-HIT / BYPASS / BLOCKED), so cache behavior is
// measured from the client side without privileged access. When an admin-metrics
// sampler is supplied (see Config.ServerMetrics), the harness additionally
// captures the proxy's authoritative cache and coalescer counters before and
// after the run and reports the delta — giving a server-side cross-check of the
// client-observed numbers (especially the negative-cache counters, which are not
// otherwise visible to a client).
//
// The package is deliberately transport-focused and dependency-light: it owns
// the worker pool, latency aggregation, and reporting; the caller supplies the
// target set and (optionally) the admin sampler. The ptctl `loadtest` subcommand
// is the reference driver. See docs/performance.md.
package loadbench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Target is one pull to drive. Exactly one of Path or Template identifies the
// gateway resource: Path is a fixed path requested verbatim (the hot-key / cache
// -hit and negative-cache workloads), while Template is a path containing a
// single %d that the harness substitutes with a process-unique, monotonically
// increasing sequence number per request, producing a distinct cache key every
// time (the cold-fill / cache-miss workload).
type Target struct {
	// Path is the exact gateway path to GET, e.g. "/v1/npm/pkg-1.0.0.tgz".
	Path string
	// Template, when non-empty, is a path with a single %d verb substituted with
	// a unique sequence number per request. Takes precedence over Path.
	Template string
	// Weight biases random/weighted selection toward this target (default 1).
	Weight int
	// Label is an optional human-readable name for the target, used in reporting.
	Label string
}

func (t Target) resolve(seq int64) string {
	if t.Template != "" {
		return fmt.Sprintf(t.Template, seq)
	}
	return t.Path
}

// Config parameterizes a run. BaseURL and at least one Target are required.
type Config struct {
	// BaseURL is the proxy's base URL (scheme://host[:port]), no trailing path.
	BaseURL string
	// Targets is the non-empty set of pulls to drive.
	Targets []Target
	// Concurrency is the number of worker goroutines issuing requests in
	// parallel (default 1).
	Concurrency int
	// Duration bounds a time-based run. When > 0 the harness issues requests for
	// this long; otherwise it issues exactly Requests requests.
	Duration time.Duration
	// Requests is the total number of requests for a count-based run (used only
	// when Duration == 0). Default 1.
	Requests int
	// Warmup issues this many sequential (un-timed, un-counted) requests round-
	// robin over the targets before the measured run begins, so the cache-hit
	// and negative-cache workloads start from a warmed state. Fixed-Path targets
	// are warmed; Template targets are skipped (every request is unique by
	// design, so there is nothing to pre-fill).
	Warmup int
	// Token, when set, is sent as a bearer credential on every request so the
	// harness can drive an access-controlled proxy.
	Token string
	// Tenant, when set, is sent as the X-Pullthrough-Tenant header.
	Tenant string
	// HTTPClient overrides the client the harness uses. When nil a client tuned
	// for the configured concurrency is built (see buildClient).
	HTTPClient *http.Client
	// Timeout is the per-request timeout applied when HTTPClient is nil
	// (default 30s).
	Timeout time.Duration
	// ServerMetrics, when set, is sampled once before and once after the measured
	// run so the report can include the proxy's authoritative counter deltas.
	// Errors sampling are reported in the result but do not fail the run.
	ServerMetrics ServerMetricsFunc
}

// ServerMetricsFunc samples the proxy's authoritative cache/coalescer counters
// (typically from the admin API). The ptctl driver wires this to the admin
// /api/overview and /api/coalesce endpoints.
type ServerMetricsFunc func(ctx context.Context) (ServerMetrics, error)

// ServerMetrics is a point-in-time sample of the proxy's cumulative cache and
// coalescer counters.
type ServerMetrics struct {
	CacheHits         int64
	CacheMisses       int64
	CoalesceLookups   int64
	Coalesced         int64
	Leads             int64
	NegativeHits      int64
	NegativeStored    int64
	NegativeEvictions int64
	NegativeEntries   int // gauge (current)
	InFlight          int // gauge (current)

	// Outbound connection-pool counters (Task 130), read from the proxy's
	// pullthrough_upstream_conn_* metrics. They measure the proxy→upstream
	// connection reuse the client cannot otherwise observe, so the
	// connection-reuse benchmark can report (and the perfguard baseline can gate
	// on) connection churn.
	ConnAcquired int64 // conn acquisitions handed to upstream requests
	ConnReused   int64 // acquisitions satisfied from the keep-alive pool
	ConnDials    int64 // new connections dialed
}

// defaultTimeout is applied to harness-built clients when Config.Timeout is 0.
const defaultTimeout = 30 * time.Second

func (c *Config) validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("loadbench: BaseURL is required")
	}
	if len(c.Targets) == 0 {
		return errors.New("loadbench: at least one target is required")
	}
	for i, t := range c.Targets {
		if strings.TrimSpace(t.Path) == "" && strings.TrimSpace(t.Template) == "" {
			return fmt.Errorf("loadbench: target %d has neither Path nor Template", i)
		}
	}
	if c.Duration < 0 {
		return errors.New("loadbench: Duration must not be negative")
	}
	if c.Duration == 0 && c.Requests < 0 {
		return errors.New("loadbench: Requests must not be negative")
	}
	return nil
}

// Runner executes a configured load run.
type Runner struct {
	cfg    Config
	client *http.Client
	base   string

	// targetPick precomputes a weighted selection table (indices into cfg.Targets).
	weighted []int
}

// New validates cfg and returns a ready Runner.
func New(cfg Config) (*Runner, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if cfg.Duration == 0 && cfg.Requests <= 0 {
		cfg.Requests = 1
	}
	client := cfg.HTTPClient
	if client == nil {
		client = buildClient(cfg.Concurrency, cfg.Timeout)
	}
	r := &Runner{
		cfg:    cfg,
		client: client,
		base:   strings.TrimRight(cfg.BaseURL, "/"),
	}
	for i, t := range cfg.Targets {
		w := t.Weight
		if w <= 0 {
			w = 1
		}
		for j := 0; j < w; j++ {
			r.weighted = append(r.weighted, i)
		}
	}
	return r, nil
}

// buildClient returns an http.Client whose connection pool is sized to the
// configured concurrency, so the harness measures the proxy rather than
// client-side connection starvation.
func buildClient(concurrency int, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = concurrency * 2
	tr.MaxIdleConnsPerHost = concurrency * 2
	tr.MaxConnsPerHost = 0 // unbounded; let the proxy be the bottleneck
	return &http.Client{Timeout: timeout, Transport: tr}
}

// Run executes the warmup (if any) and the measured run, returning the aggregated
// Result. It stops early and returns ctx.Err() only if the context is cancelled
// before the run begins; once workers are running, cancellation ends the run
// cleanly and the partial Result is returned.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	r.warmup(ctx)

	var before, after ServerMetrics
	var beforeErr, afterErr error
	if r.cfg.ServerMetrics != nil {
		before, beforeErr = r.cfg.ServerMetrics(ctx)
	}

	res := r.drive(ctx)

	if r.cfg.ServerMetrics != nil {
		after, afterErr = r.cfg.ServerMetrics(ctx)
		if beforeErr == nil && afterErr == nil {
			d := serverDelta(before, after)
			res.Server = &d
		} else if beforeErr != nil {
			res.ServerMetricsError = beforeErr.Error()
		} else {
			res.ServerMetricsError = afterErr.Error()
		}
	}
	return res, nil
}

// warmup issues Warmup sequential requests over the fixed-Path targets to prime
// the cache (and negative cache) before measurement.
func (r *Runner) warmup(ctx context.Context) {
	if r.cfg.Warmup <= 0 {
		return
	}
	// Only fixed-Path targets are warmable; Template targets are unique per call.
	var warmable []Target
	for _, t := range r.cfg.Targets {
		if t.Template == "" {
			warmable = append(warmable, t)
		}
	}
	if len(warmable) == 0 {
		return
	}
	for i := 0; i < r.cfg.Warmup; i++ {
		if ctx.Err() != nil {
			return
		}
		t := warmable[i%len(warmable)]
		_ = r.do(ctx, t.resolve(int64(i)))
	}
}

// drive runs the measured workload across Concurrency workers and aggregates
// their per-worker tallies into a single Result.
func (r *Runner) drive(ctx context.Context) Result {
	var (
		seq       int64 // unique sequence for Template targets
		remaining int64 // request budget for count-based runs
		pick      uint64
	)
	if r.cfg.Duration == 0 {
		remaining = int64(r.cfg.Requests)
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if r.cfg.Duration > 0 {
		runCtx, cancel = context.WithTimeout(ctx, r.cfg.Duration)
		defer cancel()
	}

	shards := make([]*shard, r.cfg.Concurrency)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < r.cfg.Concurrency; w++ {
		sh := &shard{statusCodes: map[int]int64{}}
		shards[w] = sh
		wg.Add(1)
		go func(sh *shard) {
			defer wg.Done()
			for {
				if r.cfg.Duration > 0 {
					if runCtx.Err() != nil {
						return
					}
				} else {
					if atomic.AddInt64(&remaining, -1) < 0 {
						return
					}
				}
				idx := r.weighted[int(atomic.AddUint64(&pick, 1)-1)%len(r.weighted)]
				t := r.cfg.Targets[idx]
				path := t.Path
				if t.Template != "" {
					path = t.resolve(atomic.AddInt64(&seq, 1))
				}
				obs := r.do(runCtx, path)
				sh.record(obs)
			}
		}(shards[w])
	}
	wg.Wait()
	elapsed := time.Since(start)

	return aggregate(shards, start, elapsed)
}

// shard is a single worker's lock-free tally, merged after the run so the hot
// path never contends on a shared mutex.
type shard struct {
	latencies   []time.Duration
	total       int64
	success     int64
	clientErr   int64
	serverErr   int64
	notFound    int64
	transport   int64
	bytes       int64
	hits        int64
	misses      int64
	coalesced   int64
	bypass      int64
	other       int64
	statusCodes map[int]int64
}

// observation is one request's outcome.
type observation struct {
	latency    time.Duration
	status     int
	bytes      int64
	cacheState string
	err        bool
}

func (sh *shard) record(o observation) {
	sh.total++
	sh.latencies = append(sh.latencies, o.latency)
	if o.err {
		sh.transport++
		return
	}
	sh.statusCodes[o.status]++
	sh.bytes += o.bytes
	switch {
	case o.status == http.StatusNotFound:
		sh.notFound++
	case o.status >= 200 && o.status < 300:
		sh.success++
	case o.status >= 400 && o.status < 500:
		sh.clientErr++
	case o.status >= 500:
		sh.serverErr++
	}
	switch strings.ToUpper(o.cacheState) {
	case "HIT":
		sh.hits++
	case "MISS", "MISS-BLOCKED":
		sh.misses++
	case "COALESCED-HIT":
		sh.coalesced++
	case "BYPASS":
		sh.bypass++
	case "":
		// No X-Cache header (e.g. an error page); leave uncategorized.
	default:
		sh.other++
	}
}

// do issues one GET, drains and counts the body, and returns the observation.
func (r *Runner) do(ctx context.Context, path string) observation {
	url := r.base + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return observation{err: true}
	}
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}
	if r.cfg.Tenant != "" {
		req.Header.Set("X-Pullthrough-Tenant", r.cfg.Tenant)
	}
	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		return observation{latency: time.Since(start), err: true}
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return observation{
		latency:    time.Since(start),
		status:     resp.StatusCode,
		bytes:      n,
		cacheState: resp.Header.Get("X-Cache"),
	}
}

// aggregate merges the per-worker shards into a Result and computes the latency
// distribution.
func aggregate(shards []*shard, start time.Time, elapsed time.Duration) Result {
	res := Result{Started: start, Elapsed: elapsed, StatusCodes: map[int]int64{}}
	var all []time.Duration
	for _, sh := range shards {
		res.Total += sh.total
		res.Success += sh.success
		res.ClientErrors += sh.clientErr
		res.ServerErrors += sh.serverErr
		res.NotFound += sh.notFound
		res.Failures += sh.transport
		res.Bytes += sh.bytes
		res.CacheHits += sh.hits
		res.CacheMisses += sh.misses
		res.Coalesced += sh.coalesced
		res.Bypass += sh.bypass
		res.OtherCache += sh.other
		for code, n := range sh.statusCodes {
			res.StatusCodes[code] += n
		}
		all = append(all, sh.latencies...)
	}
	res.Latency = computeLatency(all)
	return res
}

// serverDelta computes the change in cumulative counters (and carries forward
// the gauges, which are current values not deltas).
func serverDelta(before, after ServerMetrics) ServerDelta {
	return ServerDelta{
		CacheHits:         after.CacheHits - before.CacheHits,
		CacheMisses:       after.CacheMisses - before.CacheMisses,
		CoalesceLookups:   after.CoalesceLookups - before.CoalesceLookups,
		Coalesced:         after.Coalesced - before.Coalesced,
		Leads:             after.Leads - before.Leads,
		NegativeHits:      after.NegativeHits - before.NegativeHits,
		NegativeStored:    after.NegativeStored - before.NegativeStored,
		NegativeEvictions: after.NegativeEvictions - before.NegativeEvictions,
		NegativeEntries:   after.NegativeEntries,
		InFlight:          after.InFlight,
		ConnAcquired:      after.ConnAcquired - before.ConnAcquired,
		ConnReused:        after.ConnReused - before.ConnReused,
		ConnDials:         after.ConnDials - before.ConnDials,
	}
}
