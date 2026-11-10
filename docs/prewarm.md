# Predictive cache pre-warming (Task 134)

The predictive pre-warming subsystem (`internal/prewarm`) forecasts likely
near-future pulls from historical pull telemetry and proactively fetches +
admission-gates them during off-peak windows, so cache **hits** and gate
**verdicts** are ready before the first client request.

It is **optional and disabled by default**. It is distinct from the air-gapped
mirror `pullthrough prewarm` command (Task 17), which is an on-demand,
manifest-driven cache fill that does **not** run the admission gates.

## What it predicts

The learned history is a bounded, in-process record of the coordinates clients
actually pull, fed by a tap on the gateway serve path (the subsystem's own
synthetic fetches are excluded, so it never bootstraps predictions off its own
activity). From it the built-in heuristic predictor forecasts:

- **New patch / minor releases** of frequently- and recently-pulled coordinates,
  by incrementing the highest observed semver version and substituting it into
  the learned request path. A predicted version that was already observed, or for
  which no fetchable request path can be derived, is never emitted.
- **Direct dependencies** of recently-pulled top-level packages, resolved from
  the provenance/dependency graph (`provgraph`) and addressed through request
  paths learned from history. Requires `prewarm.transitiveDeps: true` **and** the
  provenance graph enabled.

## Safety properties

- **Leader-election aware.** In an HA deployment only the coordination leader
  (Task 56, guard `prewarm`) runs the periodic cycle, so pre-warming happens once
  cluster-wide. On-demand runs (admin / `ptctl prewarm run`) bypass the leader
  and off-peak gates but still honor the kill-switch.
- **Rate / concurrency bounded.** `maxConcurrency`, `maxPerCycle`, and
  `ratePerMinute` cap a cycle's upstream load.
- **Respects the SSRF egress allowlist and the emergency kill-switch.** Every
  fetch goes through the full gated pull pipeline, which enforces the egress
  allowlist (Task 89) at the transport layer and refuses upstream fetches under a
  freeze lockdown (Task 74). The scheduler additionally skips an entire cycle
  while any lockdown is engaged.
- **Never serves a gate failure.** A pre-warmed artifact that fails an admission
  gate is refused and (when quarantined) evicted by the pull pipeline exactly as
  for a client pull. Pre-warming only records the `gate-blocked` outcome.

## Configuration

See the `prewarm:` stanza in `configs/config.example.yaml` and the generated
`docs/configuration-reference.md`. The minimal enablement:

```yaml
prewarm:
  enabled: true
  offPeakStart: "01:00"
  offPeakEnd: "05:00"
  offPeakTimezone: UTC
```

## Observability

Prometheus counters (all `pullthrough_prewarm_*`):

| Metric | Meaning |
| --- | --- |
| `pullthrough_prewarm_predicted_total` | artifacts the predictor forecast |
| `pullthrough_prewarm_fetched_total` | fetched + admitted into the cache ahead of demand |
| `pullthrough_prewarm_already_cached_total` | predicted artifacts already cached |
| `pullthrough_prewarm_gate_blocked_total` | pre-warmed artifacts an admission gate refused |
| `pullthrough_prewarm_errors_total` | pre-warm fetches that failed (e.g. a nonexistent predicted version) |
| `pullthrough_prewarm_hit_attributed_total` | client cache hits served from a prior pre-warm |
| `pullthrough_prewarm_cycles_total` | cycles executed |
| `pullthrough_prewarm_cycles_skipped_total{reason}` | cycles skipped (not-leader / kill-switch / off-peak / no-fetcher) |

## CLI and admin API

- `ptctl prewarm status [-json]` — predictor status, learned-history size,
  leader / kill-switch / window state, and the cumulative counters.
- `ptctl prewarm run [-json]` — trigger an immediate cycle on the target node.
- Admin API: `GET <admin>/api/prewarm` (status), `POST <admin>/api/prewarm/run`.
