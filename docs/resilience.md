# Resilience & chaos / fault-injection

A pull-through supply-chain proxy sits on the critical path of every build. How
it behaves when a dependency degrades — a slow or failing upstream mirror, an
object-store backend that times out or 5xxs, corrupted bytes on the wire, or the
LLM commit-scanner API being unavailable — is a first-class security property,
not an afterthought:

- A proxy that **stalls** when one mirror is sick halts every build behind it.
- A proxy that **silently fails open** when a scanning gate's backing service is
  down admits unscanned content — the exact failure a supply-chain gate exists
  to prevent.

So each dependency's degraded-mode behavior is an explicit, tested contract. The
`internal/chaos` package (Task 98) is a **deterministic fault-injection test
harness** that reproduces each degraded condition and asserts the proxy's
response. It is a test harness, not a production component — nothing in it runs
on the live pull path.

## How it works

Faults are injected through the same interface seams the production code already
depends on, so the harness never patches or forks behavior:

| Dependency | Seam | Primitive |
| ---------- | ---- | --------- |
| Upstream (per-request) | `upstream.Doer` | `chaos.FaultyDoer` (+ `StatusDoer`, `TransportFailDoer`, `FlakyDoer`, `HealthyDoer`) |
| Upstream (end-to-end HTTP) | `httptest.Server` | `chaos.FaultyUpstream` (healthy / 404 / 503 / slow / truncated) |
| Storage (cache / S3) | `cache.Cache` | `chaos.FaultyCache` (Get/Put/GetOrLoad errors, latency, corruption) |
| Provenance/scan gate | `policy.AssessmentSource` | `chaos.FaultyAssessmentSource` |
| LLM commit scanner | `commit.Provider` | `chaos.FaultyProvider` |
| Generic scanner | `scan.Scanner` | `chaos.FaultyScanner` |

Determinism is a hard requirement: time is driven by a `chaos.ManualClock`
(never the wall clock) so circuit-breaker cooldowns and negative-cache TTLs are
exercised without sleeping; concurrency is sequenced with channels (the slow
upstream's release gate); and the coalescer's jitter is fixed-seeded upstream.
The suite runs clean under `-race` and `-count`.

## The resilience matrix

The catalog in `internal/chaos/guarantees.go` holds one `Guarantee` per
`(dependency, degraded condition)` pair, each with a deterministic verifier.
`chaos.Run` executes the whole catalog and renders the matrix below. The catalog
is the single source of truth: the table-driven test `TestResilienceGuarantees`
drives it, and this document is generated from it, so the two cannot drift.

Regenerate the matrix with:

```sh
go run ./internal/chaos/internal/matrixgen > docs/resilience-matrix.md
```

### Dependency: upstream (multi-mirror routing, circuit breaking, coalescing)

| ID | Degraded condition | Expected behavior | Mechanism |
| -- | ------------------ | ----------------- | --------- |
| `UP-FAILOVER-5XX` | primary mirror returns a retryable 5xx | fail over to a healthy mirror, served 200 | `upstreampool` health-aware routing |
| `UP-FAILOVER-TRANSPORT` | primary mirror connection/TLS error (nil response) | fail over to a healthy mirror, served 200 | `upstreampool` health-aware routing |
| `UP-NO-FAILOVER-404` | primary mirror returns a terminal 404 | 404 returned directly — no failover, no circuit trip (a 404 is an answer, not a fault) | retryable-status classifier |
| `UP-CIRCUIT-OPENS` | an endpoint fails `FailureThreshold` times in a row | its circuit opens; further requests are shed without dialing the dead endpoint | circuit breaker |
| `UP-CIRCUIT-RECOVERS` | an open circuit's endpoint recovers after the open timeout | a half-open trial probe succeeds and, after `SuccessThreshold` successes, the circuit closes | half-open recovery |
| `UP-ALL-OPEN-SHED` | every mirror's circuit is open | fail fast with `AllUnavailableError`; zero upstream requests issued | fail-fast routing |
| `UP-NEGATIVE-CACHE` | a missing artifact is requested repeatedly (404 storm) | only the first request reaches the upstream; the rest are absorbed by the negative cache | `coalesce` negative cache |
| `UP-SINGLEFLIGHT-ERROR` | concurrent misses for the same artifact while the upstream errors | exactly one upstream fetch is issued; the error is shared with every coalesced waiter | `coalesce` singleflight |

### Dependency: storage (cache / object-store backend)

| ID | Degraded condition | Expected behavior | Mechanism |
| -- | ------------------ | ----------------- | --------- |
| `ST-READ-THROUGH-ERROR` | the cache/object-store backend is unreachable on the read-through path | the pull returns **502 Bad Gateway**; no partial or garbage content is served | gateway error mapping |
| `ST-WRITE-ERROR` | the object-store write (`Put`) times out / 5xxs during a cache fill | the pull returns 502 and **nothing is cached**; a retry re-fetches rather than serving a half-written entry | atomic cache fill |
| `ST-PARTIAL-RESPONSE` | the upstream declares a `Content-Length` larger than the body it delivers (truncated/partial response) | the fill fails (502) on the short read and the partial bytes are **never cached**; a retry re-fetches | cache fill read-to-EOF |
| `ST-FILL-INTEGRITY` | the upstream serves bytes that do not match the expected content digest | the fill is aborted (502) and the tampered bytes are **never committed** to the cache | fill-time content-digest verifier |

### Dependency: scanner / LLM (graceful gate degradation, fail-open vs fail-closed)

| ID | Degraded condition | Expected behavior | Mechanism |
| -- | ------------------ | ----------------- | --------- |
| `GATE-POLICY-FAIL-OPEN` | provenance/scan assessment backend unavailable, policy **fail-open** (default) | artifact served **with a warning** rather than halting all pulls | `policy.Engine` `FailClosed=false` |
| `GATE-POLICY-FAIL-CLOSED` | provenance/scan assessment backend unavailable, policy **fail-closed** | artifact **blocked** (safety over availability) | `policy.Engine` `FailClosed=true` |
| `GATE-LLM-DEGRADE` | LLM commit-scan API unavailable, but a deterministic pass found a secret | scan degrades to the **deterministic verdict** (served, finding retained) instead of failing the pull | commit pipeline deterministic fallback |
| `GATE-LLM-PROPAGATE` | LLM commit-scan API unavailable, no deterministic signal | the outage **propagates** so the commit stays unscanned (deferred to the missing-scan policy — no silent pass) | commit pipeline error propagation |

## Resilience guarantees by dependency

### Upstream registries & mirrors

- Multiple equivalent mirrors are configured per backend as an ordered pool
  (`internal/upstreampool`). A **retryable** failure of one endpoint — a 5xx, a
  429, or a transport/TLS/connection error (a `nil` response) — transparently
  fails over to the next healthy mirror; the caller never sees the transient
  failure. See [observability.md](observability.md) for the `FailoverTotal` and
  per-endpoint circuit-state metrics.
- A **terminal** status (404/410/401/403/4xx) is *not* a fault: it is returned
  directly, without failover or a circuit trip, because it is the upstream's
  actual answer. Treating a 404 as a mirror failure would mask missing artifacts
  and waste every mirror on every miss.
- A **circuit breaker** per endpoint opens after `FailureThreshold` consecutive
  failures, sheds traffic for `OpenTimeout`, then admits a bounded number of
  half-open trial probes; `SuccessThreshold` successful probes close it again. A
  flapping or dead mirror is removed from rotation automatically and restored
  only once it demonstrably recovers.
- When **every** endpoint is open or drained, the pool fails fast with
  `AllUnavailableError` and issues **zero** upstream requests — it never hammers
  known-dead endpoints.
- Concurrent cache-miss requests for the same artifact are collapsed by
  **singleflight** (`internal/coalesce`) onto a single upstream fetch; the
  outcome (including an error) is shared with every waiter. Terminal upstream
  failures (404/410/auth) are **negatively cached** for a short TTL, and
  transient failures (5xx/429/network) for a shorter jittered backoff window, so
  a burst for a missing or momentarily-unavailable artifact cannot become a
  thundering herd against the origin. The coalesce/negative-cache key is
  tenant-scoped, so one tenant's negative result never shadows another's
  (possibly authorized) fetch.

### Cache / object-store backend

- A cache or S3-compatible backend error on the **read-through** path surfaces
  as a clean `502 Bad Gateway`; the proxy never serves partial or placeholder
  bytes in place of the artifact.
- A **write** failure during a cache fill (an S3 `Put` that times out or 5xxs)
  fails the pull with 502 and leaves **nothing** cached — writes are atomic
  (stage-then-rename on the filesystem; blob-before-meta with orphan rollback on
  S3), so a reader can never observe a torn or half-written entry, and a retry
  re-fetches rather than serving a corrupt partial.
- A **partial/truncated upstream response** (the origin declares a larger
  `Content-Length` than it delivers, then hangs up) fails the fill on the short
  read: the pull returns 502 and the partial bytes are never cached, so a retry
  re-fetches rather than serving a truncated artifact.
- **Integrity on fill:** when the resolution stage knows the expected content
  digest, the upstream body is streamed through an incremental digest verifier
  on its way into the store. A tampered or truncated response fails the verifier
  on EOF, the cache `Put` is aborted, and the bad bytes are **never committed** —
  a compromised upstream or mirror cannot poison the shared cache.
- **Boundary — no checksum-on-read:** integrity is enforced at *fill* time, not
  at *read* time. A blob corrupted at rest (bit-rot) is served as-is. The harness
  makes this boundary explicit (`TestFaultyCacheCorruptionBoundary`) rather than
  leaving it an unstated assumption; operators relying on at-rest integrity
  should enable object-store checksums / versioning at the storage layer.

### Scanning & admission gates (fail-open vs fail-closed)

Every gate whose verdict depends on a backing service has an explicit posture
for what happens when that service is unavailable. The project-wide default is
**fail-open** (availability over safety) so a transient outage degrades to a
warning rather than halting all pulls, with a per-gate switch to **fail-closed**
(safety over availability) for high-assurance deployments:

| Gate | Config | Default | On dependency outage |
| ---- | ------ | ------- | -------------------- |
| Provenance/scan admission policy | `policy.Config.FailClosed` | open | open → `warn` (served); closed → `block` |
| LLM commit budget exhausted | `commit.BudgetPolicy.FailOpen` | closed | open → deterministic-only verdict; closed → synthetic critical finding |
| Build-provenance gate | `buildprov.Config.FailOnError` + `Mode` | open | open → `warn`; closed (enforce) → configured block action |
| WASM extension gate | `extension.ModuleConfig.FailClosed` | open | open → module skipped; closed → `block` |

- The **LLM commit scanner** degrades in layers: if the provider errors or times
  out but the deterministic passes (secret/credential and prompt-injection
  detection, `internal/secretscan`) found something, the scan returns that
  verdict with the degradation recorded — reliable offline coverage independent
  of provider availability. If there is no deterministic signal, the outage
  propagates so the commit is treated as *unscanned* and the policy engine's
  `OnMissingScan` action applies — the LLM being down never silently produces a
  clean pass.

## Running the harness

The chaos suite runs as part of the default developer/CI loop — it is fast and
deterministic:

```sh
make chaos            # go test ./internal/chaos/...
go test -race ./internal/chaos/...
```

See [testing.md](testing.md) for how it fits alongside the unit, integration,
fuzz, and red-team tiers.
