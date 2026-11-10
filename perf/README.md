# `perf/` — load & throughput rigs

This directory holds the **hermetic, end-to-end** load-testing rig for the
pull-through proxy. It is black-box (drives the proxy over HTTP) and fully
self-contained: it stands up a stub upstream so **no public registries are
contacted** and runs are reproducible.

For the full performance reference — Go micro-benchmarks, the in-process
`ptctl loadtest` harness, and runtime profiling — see
[`docs/performance.md`](../docs/performance.md).

## Contents

| Path | What it is |
|------|------------|
| `run-loadtest.sh` | orchestrates a complete run: build → start stub → start proxy → drive k6 → summarize → tear down |
| `stubupstream/` | a deterministic stub upstream (package-manager artifacts + a Docker Registry v2 emulation) |
| `load/config.loadtest.yaml` | proxy config pointing every upstream at the stub, with security gates off so the run isolates the caching/serving hot path |
| `load/k6/proxy_load.js` | the [k6](https://k6.io) script: cache-hit, cache-miss, and Docker scenarios |
| `load/results/` | per-run JSON summaries and proxy/stub logs (created on first run) |

## Running it

Requires `go` and [`k6`](https://k6.io/docs/get-started/installation/).

```sh
# default: 20 virtual users x 30s per scenario
perf/run-loadtest.sh

# scale it
VUS=50 DURATION=1m perf/run-loadtest.sh

# knobs: VUS, DURATION, PROXY_PORT, STUB_PORT, BLOBS
```

The summary is written to `perf/load/results/summary-<timestamp>.json`; the
proxy and stub logs sit beside it.

## When to use which tool

- **`perf/run-loadtest.sh` (k6)** — black-box, multi-protocol (including Docker)
  throughput gate against a stub; good for CI and release sign-off.
- **`ptctl loadtest`** — point it at *any* running proxy (incl. staging/prod) to
  measure client-observed latency percentiles and cache/coalescing/negative-cache
  behavior without a k6 install. See
  [`docs/performance.md`](../docs/performance.md#load-harness--ptctl-loadtest).
- **`ptctl perfguard`** — the CI regression gate: runs a committed pull /
  cache-read / admission-pipeline suite, compares throughput + p50/p95/p99 against
  a stored baseline ([`perf-baseline.json`](perf-baseline.json)), and exits
  non-zero on a regression beyond threshold. No k6 required. See
  [`docs/performance.md`](../docs/performance.md#performance-regression-guard--ptctl-perfguard).
- **`go test -bench`** — isolate a single hot path (cache read, gateway dispatch)
  and track regressions with `benchstat`.
- **pprof / execution traces** — attribute CPU, memory, goroutines, and lock
  contention in a live process. See
  [`docs/observability.md`](../docs/observability.md#runtime-profiling-pprof--execution-traces).
