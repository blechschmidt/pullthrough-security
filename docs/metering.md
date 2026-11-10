# Per-tenant usage metering & chargeback (Task 84)

The metering subsystem (`internal/metering`) attributes proxy cost and
consumption to tenants so operators can produce chargeback reports and observe
(or alert on) per-tenant usage. It is a low-overhead, in-process accumulator —
no external store, no per-request allocation in the hot path beyond a couple of
counter bumps — modeled on the SecOps notifier-tap pattern.

## What is tracked (per tenant)

| Counter | Source tap |
|---|---|
| Requests, by backend and ecosystem | gateway request handler |
| Bytes served — cache hit vs upstream fetch | cacheable/direct serve paths |
| Cache-fill storage footprint | cache miss (the artifact the tenant caused to be cached) |
| Admission-scan invocations + estimated LLM/scan cost | the vulnscan and sigverify gates |
| Block counts (by gate) | the gate wrapper (`gateTrace`), on every refusal |
| Quarantine counts | the notify tap, on `EventQuarantine` |

The tenant is taken from the authenticated principal (`Identity.Team`);
unauthenticated traffic is bucketed under `(unscoped)`.

Live counters are cumulative since process start (monotonic, so they back
Prometheus counters cleanly). On a periodic tick the meter snapshots the delta
since the previous tick into a bounded, optionally file-durable history of
rollups, from which time-ranged reports are assembled.

## Configuration

```yaml
metering:
  enabled: true
  rollupInterval: 1h        # periodic snapshot cadence (reports aggregate to hour/day)
  retentionHours: 336       # bounded rollup history (14 days)
  statePath: /var/lib/pullthrough/usage.json  # optional; durable across restarts
  defaultScanCostMicros: 1000                 # estimated cost charged per scan
  scanCostMicros:                             # per-gate overrides
    commitscan: 50000                         # an LLM commit scan costs more than a sig check
    sigverify: 200
  budgets:                                    # optional per-tenant ceilings
    "*": { maxBytes: 1099511627776 }          # 1 TiB default for every tenant
    acme: { maxBytes: 5497558138880, maxScanCostMicros: 100000000 }
```

Crossing a budget ceiling fires a one-shot `metering_budget` notification
(deduplicated per tenant/dimension). Metering never blocks pulls — it accounts
and alerts only.

## Surfaces

- **Admin `Usage` tab** and `GET <admin>/api/metering` (live cumulative
  snapshot) + `GET <admin>/api/metering/usage` (time-ranged report). The usage
  endpoint takes `tenant`, `start`, `end` (RFC3339 or unix seconds),
  `granularity` (`hour|day|total`), and `format` (`json|csv|markdown`). CSV and
  Markdown are the chargeback exports. This is the cross-tenant operator view.
- **Portal `usage`** (`GET /api/portal/usage`) — the tenant self-service view,
  hard-scoped to the caller's own tenant: the tenant is forced from the
  authenticated identity, so a `tenant-viewer` can never read another tenant's
  usage even by injecting `?tenant=`.
- **`ptctl usage`** — renders the report as a table (default), `--format
  json|csv|markdown`, `--granularity`, `--start/--end`, and `--all-tenants`.
- **Federated query** — each coordinate row is stamped with its consuming
  tenant's cumulative totals (`tenantRequests`, `tenantBytesServed`,
  `tenantStorageBytes`, `tenantScanInvocations`, `tenantScanCostMicros`,
  `tenantBlocked`, `tenantQuarantined`).
- **Prometheus** — per-tenant labeled counters
  (`pullthrough_metering_*_total{tenant="…"}`) plus rollup/budget-alert
  telemetry.
