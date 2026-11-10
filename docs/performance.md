# Performance: benchmarking, load testing & profiling

This page is the operator/engineer reference for measuring the proxy's
throughput and latency and for finding regressions. It covers three
complementary tools:

1. **Go micro-benchmarks** — isolate the per-request cost of the hot code paths
   (cache read/write, content-addressing, single-flight de-duplication, and the
   gateway request path) with `go test -bench`.
2. **The load harness** (`ptctl loadtest`) — drives concurrent pulls against a
   *running* proxy and reports latency percentiles, throughput, cache-hit ratio,
   request-coalescing efficacy, and negative-cache behavior.
3. **Runtime profiling** (`net/http/pprof` + execution traces) — attributes CPU,
   memory, goroutines, and lock contention in a live process. See
   [observability.md](observability.md#runtime-profiling-pprof--execution-traces).

A fourth, fully hermetic end-to-end rig (`perf/run-loadtest.sh`, driven by
[k6](https://k6.io)) is documented in [`perf/`](../perf/README.md); use it for
black-box, multi-protocol (incl. Docker) runs against a stub upstream.

## Go micro-benchmarks

The benchmarks live next to the code they measure:

| Benchmark | Path | Measures |
|-----------|------|----------|
| `BenchmarkContentAddress` | `internal/cache` | SHA-256 key→storage-name hashing (runs on every Get/Put/Stat) |
| `BenchmarkMemoryCacheGet/Put`, `BenchmarkFilesystemCacheGet/Put` | `internal/cache` | read/write throughput per payload size, both backends |
| `BenchmarkGetOrLoadHit` | `internal/cache` | **steady-state cache-read** path (resident key, loader never runs) |
| `BenchmarkSingleflightDo`, `BenchmarkGetOrLoadContendedMiss` | `internal/cache` | single-flight de-duplication under contention (reports realized `loads/op`) |
| `BenchmarkGatewayCacheHit`, `…CacheHitParallel` | `internal/proxy` | **gateway-dispatch** of a cache hit (routing + backend resolution + serve), serial & parallel |
| `BenchmarkGatewayCacheMiss` | `internal/proxy` | gateway-dispatch of a cold fill (distinct key per request) |

Run them:

```sh
# hot cache-read + de-duplication paths
go test -run=^$ -bench='ContentAddress|GetOrLoad|Singleflight|CacheGet' -benchmem ./internal/cache/

# gateway-dispatch path
go test -run=^$ -bench='Gateway' -benchmem ./internal/proxy/
```

### Tracking regressions with benchstat

Capture a baseline, make a change, and compare:

```sh
go test -run=^$ -bench='Gateway|GetOrLoad' -benchmem -count=10 ./internal/proxy/ ./internal/cache/ | tee old.txt
# …make changes…
go test -run=^$ -bench='Gateway|GetOrLoad' -benchmem -count=10 ./internal/proxy/ ./internal/cache/ | tee new.txt
go install golang.org/x/perf/cmd/benchstat@latest
benchstat old.txt new.txt
```

`BenchmarkGetOrLoadContendedMiss` and `BenchmarkSingleflightDo` report a custom
`loads/op` / `fn-calls/op` metric: it is the realized loader-invocation ratio
under a thundering herd. It should stay at ~`1/concurrency`; a rise to ~1.0 means
de-duplication regressed and every concurrent miss is now hitting the upstream.

Numbers are machine-specific — always compare a before/after captured on the
same host, not against absolute figures. As a rough order of magnitude on a
developer laptop: content-addressing is ~1µs/op, a resident `GetOrLoad` hit is
low-single-digit µs, and a gateway cache-hit dispatch (64 KiB body) is ~100µs
serial / ~36µs parallel.

## Load harness — `ptctl loadtest`

`ptctl loadtest` drives concurrent `GET` pulls against a running proxy and
reports the client-observed distribution plus the cache behavior it saw. It
classifies every response by the proxy's own `X-Cache` response header
(`HIT` / `MISS` / `COALESCED-HIT` / `BYPASS` / `BLOCKED`), so cache behavior is
measured without privileged access. When a `--token` is supplied it additionally
reads the proxy's authoritative cache and coalescer counters from the admin API
(`/api/overview`, `/api/coalesce`) before and after the run and reports the
delta — a server-side cross-check, and the only way to see the **negative-cache**
counters, which are not visible to a client.

The reference package is [`internal/loadbench`](../internal/loadbench); the CLI
is a thin driver, so the harness is reusable from Go tests and other tooling.

### Workloads

| `--workload` | What it drives | Reads |
|--------------|----------------|-------|
| `cache-hit` *(default)* | one warmed artifact, pulled repeatedly | steady-state **hit serving** & p99 under load |
| `cache-miss` | a distinct key every request (unique template) | cold-fill / long-tail throughput |
| `mixed` | a hot key (weight 3) blended with unique cold keys (weight 1) | realistic head + cold tail |
| `coalesce` | the same cold key burst from all workers, no warmup | **single-flight efficacy** (leader takes the MISS, rest `COALESCED-HIT`) |
| `negative` | a known-missing key, warmed then pulled repeatedly | **negative-cache** serving (fast 404s, no upstream) |
| `conn-reuse` | a distinct cold key every request (like `cache-miss`) | **outbound connection-pool reuse** — each pull forces a proxy→upstream fetch, so the report's server-side delta shows the connection-reuse ratio (reused / acquired) |

### Usage

```sh
export PULLTHROUGH_URL=https://proxy.example.com
export PULLTHROUGH_TOKEN=$PTS_ADMIN   # enables the server-side metric delta

# Steady-state hit serving: 50 workers for 30s against a warmed artifact.
ptctl loadtest --workload cache-hit --concurrency 50 --duration 30s

# Cold-fill throughput: 20 workers, 5000 unique keys.
ptctl loadtest --workload cache-miss --concurrency 20 --requests 5000

# Single-flight de-duplication: 200 workers all racing for one cold key.
ptctl loadtest --workload coalesce --concurrency 200 --requests 200 --no-warmup

# Explicit paths (any backend / real upstream), JSON output for CI.
ptctl loadtest --path /v1/npm/lodash/-/lodash-4.17.21.tgz \
               --path /v1/pypi/packages/.../requests-2.31.0-py3-none-any.whl \
               --concurrency 40 --duration 1m --json
```

Key flags (see `ptctl loadtest -h` for the full set):

| Flag | Default | Meaning |
|------|---------|---------|
| `--concurrency` | 50 | parallel workers |
| `--duration` | 10s | run length (ignored when `--requests` > 0) |
| `--requests` | 0 | fixed total request count (0 ⇒ use `--duration`) |
| `--warmup` / `--no-warmup` | 1 | priming pulls before measuring |
| `--backend` / `--resource` | `npm` | synthesizes the workload's gateway paths |
| `--path` | — | explicit gateway path (repeatable); overrides the workload |
| `--server-stats` | auto | query the admin API for server-side deltas (auto = on when `--token` set) |
| `--json` | false | emit the `Result` as JSON |

> The synthesized default paths assume the **npm** backend (the npm tarball
> shape `<name>/-/<file>.tgz`, which the npm backend caches). For a different
> backend or a real upstream, pass `--path` values that exist there.

### Interpreting the report

```
Load test results
  duration:        30.0s
  requests:        48213 total  (48213 ok, 0 404, 0 4xx, 0 5xx, 0 failed)
  throughput:      1607.1 req/s  |  98.0 MiB/s
Latency (client-observed)
  p50 / p90:       27.4ms / 41.1ms
  p95 / p99:       58.2ms / 88.3ms
  p99.9:           140.2ms
Cache behavior (from X-Cache)
  hit ratio:       100.0%  (48190 hit, 23 coalesced, 0 miss)
  coalescing:      0.0%  (23 of 48213 cache decisions joined an in-flight fetch)
Server-side delta (admin metrics)
  cache:           … hits, … misses  (100.0% hit ratio)
  coalescer:       23 coalesced, 48190 leads  (0.0% dedup)
  negative cache:  0 hits, 0 stored, 0 evicted  (now 0 entries)
```

- **Latency percentiles** are client-observed (includes the network path). Run
  the harness from the same network segment as production clients for a
  representative p99.
- **Hit ratio** counts `HIT` + `COALESCED-HIT` over all cache *decisions*
  (hits + coalesced + misses); bypasses, blocks, and errors are excluded.
- **Coalescing** is the fraction of cache decisions satisfied by joining an
  in-flight upstream fetch — the single-flight win. It is naturally small in a
  warm steady state (everything is a plain hit) and large in the `coalesce`
  workload (a burst on one cold key: one MISS, the rest `COALESCED-HIT`).
- **Negative cache** (server-side only) shows the `negative` workload storing a
  single entry and then serving every subsequent miss from it without an
  upstream round-trip.

## Performance regression guard — `ptctl perfguard`

`ptctl perfguard` turns the one-shot load harness into a durable CI gate. It runs
a small, **committed** benchmark suite against a running proxy, compares the
result against a stored baseline, and **exits non-zero** when any metric
regresses beyond an allowed threshold — so a future change (including an
autonomous evolve iteration) cannot silently degrade a hot path.

### The committed suite

The suite is fixed so a baseline stays comparable release to release. Each
scenario reuses a `ptctl loadtest` workload:

| Scenario | Workload | Guards |
|----------|----------|--------|
| `pull` | `cache-miss` | the cold upstream-fetch + cache-fill path (unique key ⇒ MISS every request) |
| `cache-read` | `cache-hit` | steady-state serving from a warmed cache (the hottest read path ⇒ all HITs) |
| `admission-pipeline` | `mixed` | a hot key served from cache blended with unique cold keys, so each cold key traverses the full fetch → admission/scan/gate → fill chain |
| `conn-reuse` | `conn-reuse` | the proxy→upstream **connection pool**: unique cold keys at high concurrency drive constant upstream fetches, and the gated metric is the connection-reuse ratio, so a transport change that increases connection churn fails the guard |

For every scenario it compares four metrics: **throughput** (req/s, higher is
better) and **p50 / p95 / p99** latency (lower is better). The `conn-reuse`
scenario additionally compares the **connection-reuse ratio** (reused / acquired,
higher is better), captured from the proxy's `pullthrough_upstream_conn_*`
metrics; this metric is gated only for scenarios that measure it, so the
cache-only scenarios are unaffected. A scenario present in the baseline but
absent from the run (a *dropped* benchmark) fails the guard; a scenario new to
the baseline is surfaced but does not fail (add it with `-update-baseline`).

> The `conn-reuse` gate reads the proxy's Prometheus metrics endpoint
> (`/metrics`) to sample connection counters; keep that endpoint enabled (the
> default) on the target proxy or the reuse ratio is simply not recorded and the
> scenario falls back to gating on throughput and latency only.

### Capturing and updating the baseline

The baseline lives at [`perf/perf-baseline.json`](../perf/perf-baseline.json)
and is committed. Regenerate it whenever an **intentional, accepted** performance
change lands:

```sh
# Stand up the hermetic rig (or point --url at any representative proxy), then:
ptctl perfguard --url http://127.0.0.1:8080 --update-baseline \
                --machine "ci: 4-vCPU ubuntu-22.04 runner"
```

`-update-baseline` writes the fresh run (with a timestamp and the `--machine`
note) and skips the comparison. Review the diff and commit it like any other
baseline.

### Checking for regressions

```sh
# Default: compare against perf/perf-baseline.json with a 15% per-metric budget.
ptctl perfguard --url http://127.0.0.1:8080

# Tighter latency budget than throughput, JSON for machine parsing.
ptctl perfguard --url http://127.0.0.1:8080 \
                --allowed-latency-regression 10 \
                --allowed-throughput-regression 20 --json

# Guard only one scenario.
ptctl perfguard --url http://127.0.0.1:8080 --scenarios cache-read
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--baseline` | `perf/perf-baseline.json` | stored baseline file |
| `--update-baseline` | false | record a new baseline instead of comparing |
| `--allowed-regression` | 15 | default per-metric regression budget (%) |
| `--allowed-latency-regression` | 0 | override budget for p50/p95/p99 (0 ⇒ use default) |
| `--allowed-throughput-regression` | 0 | override budget for throughput (0 ⇒ use default) |
| `--min-samples` | 100 | flag a scenario low-confidence below this sample count |
| `--concurrency` | 50 | workers per scenario |
| `--requests` | 2000 | fixed requests per scenario (fixed count ⇒ reproducible sample sizes) |
| `--scenarios` | — | comma-separated subset to run (default: all) |
| `--machine` | hostname | environment note stored in a new baseline |
| `--json` | false | emit the report (or new baseline) as JSON |

Sample failing report:

```
Performance regression report
  baseline:        captured 2026-11-04T05:51:48Z on "ci: 4-vCPU ubuntu-22.04 runner"
  tolerance:       15% default

  ✓ cache-read           ok
      throughput  20356.4 -> 20110.2 req/s  (-1.2%, limit 15%)
      ...
  ✗ pull                 REGRESSED
      p99         10.31ms -> 13.02ms  (+26.3%, limit 15%)  <-- regression

RESULT: FAIL — 1 metric(s) regressed beyond threshold
```

### Machine normalization — read before trusting a number

Throughput and latency are **absolute, machine-specific** measurements. A
baseline is only meaningful when the check runs on a *comparable* host, so:

- **Pin the hardware.** Capture and check on the same class of runner (same vCPU
  count, memory, and storage class). The `--machine` note records which host a
  baseline came from; if it does not match your runner, regenerate it rather
  than trusting it. Never commit a baseline captured on a developer laptop as the
  CI gate.
- **Isolate the run.** Use a dedicated runner with nothing else scheduled.
  Shared/burstable CI instances (noisy neighbors, CPU-credit throttling) produce
  swings that dwarf real regressions.
- **Prefer a fixed request count** (`--requests`, the default) over a duration so
  every run compares equal sample sizes.
- **Budget the tail loosely.** Cold-fill **p99** is the noisiest metric — a
  single GC pause or scheduler hiccup moves it tens of percent. Give latency a
  wider budget than throughput (`--allowed-latency-regression`), or gate only
  `throughput` + `p50` + `p95` with `--scenarios` and a tighter
  `--allowed-throughput-regression` if your runners are jittery.
- **Warm the box.** The hermetic rig below starts from a cold cache by design;
  the guard's own per-scenario `--warmup` primes fixed-path workloads, but let
  the machine itself settle (no concurrent build) before the measured run.
- **Re-baseline deliberately.** When an intentional change shifts the numbers,
  regenerate with `-update-baseline` and review the committed diff — never widen
  the threshold just to make red turn green.

### CI workflow snippet

A GitHub Actions job that builds the proxy, stands up the hermetic stub upstream
(no public registries), and fails the build on a regression:

```yaml
# .github/workflows/perf-guard.yml
name: performance-regression-guard
on: [pull_request]

jobs:
  perfguard:
    # Pin the runner so measurements stay comparable to the committed baseline.
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }

      - name: Build proxy, stub upstream, and ptctl
        run: |
          go build -o bin/pullthrough  ./cmd/pullthrough
          go build -o bin/stubupstream ./perf/stubupstream
          go build -o bin/ptctl        ./cmd/ptctl

      - name: Start hermetic stub upstream + proxy
        run: |
          rm -rf ./.perf-cache
          ./bin/stubupstream -addr :9000 -blobs 10 &
          ./bin/pullthrough -config perf/load/config.loadtest.yaml &
          # Wait for readiness before driving load.
          for i in $(seq 1 50); do
            curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && break
            sleep 0.2
          done

      - name: Guard against performance regressions
        run: |
          ./bin/ptctl perfguard \
            --url http://127.0.0.1:8080 \
            --baseline perf/perf-baseline.json \
            --allowed-regression 15 \
            --allowed-latency-regression 25 \
            --requests 2000 --concurrency 50
```

To refresh the baseline after an accepted change, run the same job's build/start
steps locally (or in a manual workflow) and swap the final step for
`ptctl perfguard --update-baseline --machine "ci: ubuntu-22.04"`, then commit the
updated `perf/perf-baseline.json`.

## Outbound HTTP transport tuning (`outbound:`)

Every HTTP-based upstream fetch (package registries, Docker/OCI, Git-over-HTTPS,
provenance metadata) shares a single, properly-sized `http.Transport` per
effective TLS policy so keep-alive connections are reused across requests rather
than re-dialed per fetch. The pool is tuned under `outbound:` in the config; all
fields have safe built-in defaults, so an empty block is production-ready. The
tuning composes with the SSRF/egress allowlist, per-upstream TLS pinning, and
TLS-interception paths — those hooks are layered onto the same transport.

| Key | Default | Purpose |
|-----|---------|---------|
| `outbound.maxIdleConns` | 100 | total idle keep-alive connections pooled across all hosts |
| `outbound.maxIdleConnsPerHost` | 16 | idle connections kept **per upstream host** — the single biggest lever for reuse under concurrency; raise it when many workers hit few upstreams |
| `outbound.maxConnsPerHost` | 0 (unlimited) | cap on total (active + idle) connections per host; set a positive value to shield a fragile upstream |
| `outbound.dialTimeout` | 15s | bound on establishing a TCP connection |
| `outbound.tlsHandshakeTimeout` | 10s | bound on the TLS handshake |
| `outbound.responseHeaderTimeout` | 30s | bound on waiting for upstream response headers |
| `outbound.idleConnTimeout` | 90s | how long an idle keep-alive connection is retained before eviction |
| `outbound.keepAlive` | 30s | TCP keep-alive probe interval (negative disables probes) |
| `outbound.expectContinueTimeout` | 1s | wait for a 100-continue before sending the body |
| `outbound.disableKeepAlives` | false | debugging only — forces a fresh connection per request (defeats reuse) |
| `outbound.disableHTTP2` | false | suppress the opportunistic HTTP/2 upgrade on TLS upstreams |

The transport exports `pullthrough_upstream_conn_*` metrics so reuse can be
watched live and regressions caught in CI:

| Metric | Type | Meaning |
|--------|------|---------|
| `pullthrough_upstream_conn_dials_total` | counter | new connections dialed (the churn signal) |
| `pullthrough_upstream_conn_dial_errors_total` | counter | dials that failed |
| `pullthrough_upstream_conn_dial_duration_seconds_{sum,count}` | counter | dial latency (average = `rate(sum)/rate(count)`) |
| `pullthrough_upstream_conn_acquired_total` | counter | connection acquisitions handed to requests |
| `pullthrough_upstream_conn_reused_total` | counter | acquisitions served from the pool — **reuse rate** = `reused / acquired` |
| `pullthrough_upstream_conn_closed_total` | counter | connections torn down |
| `pullthrough_upstream_conn_open` | gauge | connections currently open |
| `pullthrough_upstream_conn_idle` | gauge | approximate idle-pool size |

The "Upstream connection pool" row of the *Upstream Latency & Errors* Grafana
dashboard charts these, and the [`conn-reuse` perfguard scenario](#the-committed-suite)
gates the reuse ratio in CI.

## Hermetic end-to-end rig (`perf/`)

`perf/run-loadtest.sh` builds the proxy and a stub upstream, starts both, and
drives cache-hit / cache-miss / Docker workloads with k6 — no public registries
are contacted. Use it for black-box, multi-protocol runs and CI throughput
gates. See [`perf/README.md`](../perf/README.md).

## Profiling

When a load test or a production incident points at a hot path, capture a CPU
profile, heap snapshot, or execution trace from the live process via the
authenticated pprof endpoints and open them with `go tool pprof` / `go tool
trace`. Setup, the endpoint table, and examples are in
[observability.md](observability.md#runtime-profiling-pprof--execution-traces).
