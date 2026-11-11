# Observability: metrics, dashboards & alerts

The proxy exposes Prometheus metrics at `observability.metricsPath` (default
`/metrics`). This page is the metric reference and the catalogue of the shipped
**Grafana dashboards** and **Prometheus alerting rules**. The turnkey bundle
lives in [`deploy/observability/`](../deploy/observability/README.md) and deploys
alongside the proxy via Docker Compose, Helm, or kustomize.

- **Enable metrics:** set `observability.metrics: true` (see
  [configuration.md](configuration.md)). Most subsystem metrics only appear once
  that subsystem is enabled and has done work — series are created lazily.
- **Dashboards & alerts:** [`deploy/observability/`](../deploy/observability/README.md).
- **Admin API/UI:** [runbook.md](runbook.md#admin-dashboard--api).

## Quick start

| Platform | Command / setting | Result |
|----------|-------------------|--------|
| Docker Compose | `make compose-up-monitoring` | Grafana :3000 (dashboards) + Prometheus :9090 (rules) |
| Helm | `serviceMonitor.enabled`, `prometheusRule.enabled`, `grafanaDashboards.enabled` | scrape + rules + dashboards via the Prometheus Operator / Grafana sidecar |
| kustomize | `kubectl apply -k deploy/observability` | `PrometheusRule` + dashboard `ConfigMap`s |
| Manual | import `deploy/observability/grafana/dashboards/*.json` | dashboards in any Grafana |

## Dashboards

Four versioned boards (schema 39, Grafana ≥ 10). Each uses a `datasource`
template variable and a `job` filter, so they import unchanged. They are
generated from `deploy/observability/grafana/gen_dashboards.py` — edit that and
run `make observability-gen`, don't hand-edit the JSON.

| Dashboard (uid) | Focus |
|-----------------|-------|
| **Cache Performance** (`pullthrough-cache`) | hit/miss ratio & trend, read throughput, upstream fills/coalesced, I/O bytes, evictions/expiry, **backend (incl. S3) errors** |
| **Supply-chain Security** (`pullthrough-supply-chain`) | vuln severities & gate decisions, scan-backend health, CVE-drift re-scan & quarantine, signature/attestation verification, name-guard findings, **LLM package-content scan** (verdicts, decisions, why artifacts went unscanned, verdict-cache hits, spend, scan effort) |
| **Upstream Latency & Errors** (`pullthrough-upstream`) | request rate, 5xx ratio, upstream latency p50/p95/p99 & error ratio per backend, admission-policy decisions |
| **Per-tenant Traffic & Limits** (`pullthrough-tenant`) | rate-limit allow/throttle & reasons, per-tenant concurrency & byte-quota usage, traffic mix, notification delivery |

## Metric reference

All metrics are prefixed `pullthrough_`. Counters end in `_total`.

### Request / upstream (always on with metrics)

| Metric | Type | Labels |
|--------|------|--------|
| `pullthrough_requests_total` | counter | `backend`, `method`, `code` |
| `pullthrough_upstream_request_duration_seconds` | histogram | `backend` |
| `pullthrough_upstream_errors_total` | counter | `backend` |
| `pullthrough_served_bytes_total` | counter | `backend` |
| `pullthrough_policy_decisions_total` | counter | `ecosystem`, `action` (allow\|warn\|block) |

### Range / partial-content streaming (Task 75)

Range support (RFC 7233) and zero-buffer cache-fill streaming. See
[range-streaming.md](range-streaming.md) for behavior and memory characteristics.

| Metric | Type | Labels |
|--------|------|--------|
| `pullthrough_range_requests_total` | counter | — |
| `pullthrough_range_partial_served_total` | counter | — |
| `pullthrough_range_unsatisfiable_total` | counter | — |
| `pullthrough_range_spill_to_disk_total` | counter | — |
| `pullthrough_streamed_bytes_total` | counter | — |
| `pullthrough_stream_digest_mismatch_total` | counter | — |

A rising `pullthrough_stream_digest_mismatch_total` means upstream content failed
its expected content digest and was refused before serving/caching — investigate
the upstream or a possible tampering attempt.

### Upstream failover & multi-mirror routing (Task 38)

Emitted only for upstreams that declare `mirrors`. Circuit state is `0` closed,
`1` half-open, `2` open.

| Metric | Type | Labels |
|--------|------|--------|
| `pullthrough_upstream_endpoint_requests_total` | counter | `backend`, `endpoint` |
| `pullthrough_upstream_endpoint_failures_total` | counter | `backend`, `endpoint` |
| `pullthrough_upstream_endpoint_probes_total` | counter | `backend`, `endpoint` |
| `pullthrough_upstream_endpoint_circuit_trips_total` | counter | `backend`, `endpoint` |
| `pullthrough_upstream_endpoint_latency_seconds_sum` / `_count` | counter | `backend`, `endpoint` |
| `pullthrough_upstream_circuit_state` | gauge | `backend`, `endpoint` |
| `pullthrough_upstream_healthy_endpoints` | gauge | `backend` |
| `pullthrough_upstream_failover_total` | counter | `backend` |

A circuit opening also emits an `upstream_circuit_open` notification.

### Cache

`pullthrough_cache_` + `hits_total`, `misses_total`, `hit_ratio` (gauge),
`loads_total`, `coalesced_total`, `evictions_total`, `expired_total`,
`written_bytes_total`, `served_bytes_total`, **`errors_total`**. `errors_total`
counts non-miss store failures and is the primary signal for object-storage/S3
backend health in HA deployments.

### Cache lifecycle / garbage collection (Task 39)

Emitted only when `cacheGc.enabled` is set and the backend supports lifecycle
inspection (filesystem or S3). The background sweep evicts by size watermark
(LRU/LFU/FIFO) and per-artifact/per-tenant TTL, never touching pinned,
quarantined-for-evidence, referenced, or in-flight entries.

| Metric | Type |
| --- | --- |
| `pullthrough_cachegc_runs_total` / `_dry_runs_total` | counter |
| `pullthrough_cachegc_evicted_total` / `_expired_evicted_total` | counter |
| `pullthrough_cachegc_bytes_reclaimed_total` | counter |
| `pullthrough_cachegc_delete_errors_total` | counter |
| `pullthrough_cachegc_above_high_watermark_total` | counter |
| `pullthrough_cachegc_used_bytes` / `_capacity_bytes` | gauge |
| `pullthrough_cachegc_high_watermark_bytes` / `_low_watermark_bytes` | gauge |
| `pullthrough_cachegc_utilization_ratio` | gauge |
| `pullthrough_cachegc_entries` | gauge |
| `pullthrough_cachegc_last_duration_seconds` | gauge |
| `pullthrough_cachegc_consecutive_above_high_watermark` | gauge |

A sweep that cannot bring the cache below the high watermark also emits a
`cache_gc` notification. Inspect utilization and trigger an on-demand or dry-run
sweep via `GET`/`POST {adminPrefix}/api/cachegc[/run]` (the run defaults to a safe
dry-run; pass `?dryRun=false` to evict).

### Disaster-recovery backup (Task 44)

| Metric | Type |
| --- | --- |
| `pullthrough_backup_age_seconds` (seconds since last success; `-1` if never) — the **RPO signal** | gauge |
| `pullthrough_backup_last_success_timestamp` | gauge |
| `pullthrough_backup_last_duration_seconds` / `pullthrough_backup_last_bytes` | gauge |
| `pullthrough_backup_success_total` / `pullthrough_backup_failure_total` | counter |

Alert when `backup_age_seconds` exceeds your RPO (`PullthroughBackupTooOld`) or
backups start failing (`PullthroughBackupFailing`). Inspect status and trigger an
on-demand backup via `GET`/`POST {adminPrefix}/api/backup[/run]`. Full runbook:
[backup-restore.md](backup-restore.md).

### Vulnerability gate & CVE re-scan

`pullthrough_vuln_` + `scans_total`, `scan_errors_total`,
`scan_cache_hits_total`, `offline_fallbacks_total`, `blocked_total`,
`warned_total`, `quarantined_total`, `scan_cache_entries` (gauge);
`pullthrough_vulnerabilities_{critical,high,medium,low}_total`;
re-scan: `pullthrough_rescans_total`, `pullthrough_newly_vulnerable_total`,
`pullthrough_last_rescan_timestamp` (gauge), `pullthrough_quarantined_artifacts`
(gauge).
VEX suppression: `pullthrough_vex_suppressed_total`,
`pullthrough_vex_escalated_total`, `pullthrough_vex_statements` (gauge),
`pullthrough_vex_documents` (gauge), `pullthrough_vex_malformed_documents`
(gauge).

### Signature & attestation verification

`pullthrough_sigverify_` + `verifications_total`, `cache_hits_total`,
`errors_total`, `verified_total`, `unsigned_total`, `blocked_total`,
`warned_total`, `quarantined_total`, `signatures_checked_total`,
`attestations_parsed_total`, `rekor_verified_total`, `cache_entries` (gauge).

### Name guard (typosquat & dependency confusion)

`pullthrough_nameguard_` + `inspected_total`, `flagged_total`, `blocked_total`,
`warned_total`, `typosquat_total`, `dependency_confusion_total`,
`homoglyph_total`, `namespace_mismatch_total`, `new_package_total`.

### LLM package-content scan

`pullthrough_llmpkgscan_` (registered when `llmPackageScan.enabled`; see
[llm-package-scan.md](llm-package-scan.md)):

- **What the gate was asked:** `assessed_total`, `not_package_total` (metadata
  documents it left alone), `cache_hits_total` / `cache_misses_total` (verdict
  cache), `negative_cache_hits_total`, `coalesced_total`.
- **Scans:** `scans_total`, `scan_errors_total`,
  `unscanned_total{code}` (why a scan produced no verdict),
  `scans_by_ecosystem_total{ecosystem}`,
  `scans_by_kind_total{kind}` (archive\|file\|oci-image: how the artifact was
  read), `in_flight` and `queued` (gauges),
  `breaker_open` (gauge, 1 while scans are paused after provider failures).
- **What the model said:** `verdicts_total{verdict}`
  (malicious\|suspicious\|benign), `injection_detected_total`,
  `truncated_total` (verdicts resting on an incomplete view),
  `metadata_only_total` (verdicts on an artifact above the size limit, under
  `oversize: metadata-only`).
- **What the gate did:** `blocked_total`, `quarantined_total`,
  `annotated_total`, `failed_open_total`, `failed_closed_total`,
  `budget_exhausted_total{scope}` (tenant\|global),
  `stored_verdict_enforced_total{path}` (blob\|peer: a refusal made from a
  verdict already on record, on a path that scans nothing — a blob of a refused
  image, an entry asked for by a sibling proxy).
- **What it cost:** `provider_calls_total`, `provider_errors_total`,
  `tokens_total{kind}` (input\|output\|cache_read), `turns_total`,
  `tool_calls_total{tool}` (list_files\|read_file\|grep), `cost_usd_total`,
  `scan_seconds_total`.

Every label set is closed (verdict categories, reason codes, tool names,
configured ecosystems, budget scopes): nothing a package or the model writes can
become a label value.

### Rate limiting (per-tenant)

`pullthrough_ratelimit_` + `allowed_total`, `throttled_total`,
`throttled_by_reason_total{reason}` (rps\|concurrency\|bytes),
`concurrent_inflight{tenant}` (gauge), `bytes_used{tenant}` (gauge). The `tenant`
gauges include a `__global__` series for the global policy.

### Notifications & commit scan

`pullthrough_notifications_` + `sent_total{sink}`, `failed_total{sink}`,
`dropped_total{sink}`, `retries_total{sink}`, `queue_depth` (gauge).
Commit scan: `pullthrough_scan_queue_depth`, `pullthrough_scan_pending` (gauges).

### Supply-chain graph (Task 33)

`pullthrough_provgraph_nodes`, `pullthrough_provgraph_edges` (gauges),
`pullthrough_provgraph_events_total` (counter),
`pullthrough_provgraph_nodes_by_kind_total{kind}` and
`pullthrough_provgraph_edges_by_kind_total{kind}` (gauges, kind =
package\|version\|commit\|cve\|signer for nodes, the edge type for edges).

The graph is queryable and visualizable through the admin surface:

- `GET {adminPrefix}/api/provgraph` — node/edge counts by kind.
- `GET {adminPrefix}/api/provgraph/export` — the whole graph as JSON (offline
  analysis; also drives the visualization).
- `GET {adminPrefix}/api/provgraph/blast?id=<cve-or-sha>[&type=cve|commit]` —
  blast radius: every cached artifact affected by a CVE or commit, directly or
  transitively (`type` is inferred from the id shape when omitted).
- `GET {adminPrefix}/api/provgraph/reverse?ecosystem=&name=&version=` — reverse
  dependencies of an artifact.
- `GET {adminPrefix}/api/provgraph/path?ecosystem=&name=&version=` — a path from
  an artifact to the source commit it originates from.
- `{adminPrefix}/graph.html` — force-directed visualization with CVE/commit
  blast-radius highlighting (linked from the dashboard top bar).

### Compliance scorecard (Task 35)

`pullthrough_compliance_score` (gauge, 0..1 overall posture),
`pullthrough_compliance_slsa_build_level` (gauge, estimated SLSA build level
0..3), `pullthrough_compliance_controls_failing` and
`pullthrough_compliance_controls_warning` (gauges),
`pullthrough_compliance_last_computed_timestamp` (gauge), and the per-control
series `pullthrough_compliance_control_score{control}` and
`pullthrough_compliance_control_pass{control}` (gauges; control =
signature-verification\|provenance-association\|vulnerability-gate\|license-compliance\|secret-free\|air-gap-sealed\|audit-transparency).

The scorecard aggregates the security gates' signals into a SLSA/SOC2-style
control checklist, recomputed on a schedule (`compliance.interval`, default 5m)
and on demand. It is served through the admin surface:

- `GET {adminPrefix}/api/compliance` — the structured JSON scorecard
  (`?format=markdown` for Markdown; `?refresh=1` to recompute first).
- `POST {adminPrefix}/api/compliance/refresh` — recompute from the live signals.
- `GET {adminPrefix}/api/compliance/report.html` — a self-contained HTML report
  (the admin UI **Compliance** tab renders the same data and links here).
- `GET {adminPrefix}/api/compliance/export` — a signed, exportable report
  artifact for auditors (scorecard + content digest + optional signature; sign
  with `compliance.signingKey`/`signingKeyFile`, verify with the matching public
  key).

### Distributed tracing (Task 41)

The OTLP exporter's health (see [tracing.md](tracing.md)):

| Metric | Type |
|--------|------|
| `pullthrough_tracing_spans_started_total` / `pullthrough_tracing_spans_sampled_total` | counter |
| `pullthrough_tracing_spans_exported_total` | counter |
| `pullthrough_tracing_spans_dropped_total` (queue full — collector too slow/unreachable) | counter |
| `pullthrough_tracing_export_batches_total` / `pullthrough_tracing_export_errors_total` | counter |
| `pullthrough_tracing_queue_depth` | gauge |

These appear only when tracing is enabled. Alert on a rising
`spans_dropped_total` or `export_errors_total` — both mean spans are being lost
(the request path is unaffected; export is asynchronous and bounded). The admin
API exposes the same status at `{adminPrefix}/api/tracing`.

## Alert catalogue

36 alerts in 9 groups ship in
[`deploy/observability/prometheus/alerts.yaml`](../deploy/observability/prometheus/alerts.yaml).
Thresholds are conservative defaults — tune `expr`/`for` to your traffic and SLOs.
Each alert carries `severity` and `component` labels plus `summary`,
`description`, and `runbook` annotations.

### Availability alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughTargetDown` | critical | `up` for the proxy is 0 for 5m (scrape failing / proxy down). |
| `PullthroughHighRequestErrorRate` | warning | >5% of responses are 5xx for 10m. |
| `PullthroughUpstreamErrorsElevated` | warning | >25% of a backend's upstream fetches fail for 10m. |
| `PullthroughUpstreamOutage` | critical | >75% of a backend's upstream fetches fail for 5m. |
| `PullthroughUpstreamLatencyHigh` | warning | p95 upstream latency >5s for 15m. |

**Respond:** check upstream registry health/credentials and egress; warm content
still serves from cache. See [runbook.md](runbook.md#upstream-is-down-or-rate-limiting).

### Cache alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughCacheBackendErrorsElevated` | warning | cache `errors_total` rate >0.05/s for 15m. |
| `PullthroughCacheBackendErrorsCritical` | critical | cache `errors_total` rate >1/s for 5m. |
| `PullthroughCacheHitRatioLow` | warning | hit ratio <50% for 30m (with real read volume). |

**Respond:** for S3/object-storage backends, cache errors mean bucket I/O, auth,
or connectivity problems — check [ha-shared-cache.md](ha-shared-cache.md). A low
hit ratio usually means the cache is undersized or TTL too short
([runbook.md](runbook.md#cache-management)).

### Supply-chain alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughVulnScanBackendErrors` | warning | vuln scan backend failing for 15m. |
| `PullthroughVulnOfflineFallbacks` | warning | serving stale scan results (backend unreachable). |
| `PullthroughBlockedArtifactsRising` | warning | vuln gate blocked ≥1 artifact in 15m. |
| `PullthroughNewlyVulnerableArtifacts` | critical | cached artifacts became newly vulnerable on re-scan (CVE drift). |
| `PullthroughQuarantineGrowing` | warning | quarantine count rose in 30m. |
| `PullthroughRescanStalled` | warning | last re-scan sweep >25h ago (tune to your interval). |
| `PullthroughSignatureVerificationFailures` | critical | signature/attestation gate blocked ≥1 artifact in 15m. |
| `PullthroughSignatureVerificationErrors` | warning | sigverify backend errors for 15m. |
| `PullthroughDependencyConfusionAttempts` | critical | a public package shadowing an internal namespace was seen. |
| `PullthroughTyposquatAttempts` | warning | typosquat/homoglyph findings in 15m. |

**Respond:** signature-block and dependency-confusion alerts can indicate an
active supply-chain attack — investigate immediately via the admin scans/vuln
surfaces ([security-model.md](security-model.md), [sigverify.md](sigverify.md),
[runbook.md](runbook.md#a-malicious-package-is-being-pulled)).

### LLM package-scan alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughLLMPackageScanMaliciousVerdict` | critical | a newly scanned package was judged malicious in the last 15m. |
| `PullthroughLLMPackageScanPromptInjection` | warning | a scanned package contains text addressed to the scanner. |
| `PullthroughLLMPackageScanFailing` | warning | scans fail more often than they succeed, or the provider circuit breaker is open, for 10m. |
| `PullthroughLLMPackageScanServingUnscanned` | warning | pulls are being served without a verdict (fail-open) for 15m. |
| `PullthroughLLMPackageScanBudgetExhausted` | warning | a tenant or the global cost ceiling was reached. |

**Respond:** a malicious verdict under `action: annotate` means the package **was
served** — treat hosts that installed it as potentially compromised and follow
[runbook.md](runbook.md#a-malicious-package-is-being-pulled). Read the verdict
(reasons, cited files) in the package dossier or at
`GET /admin/api/llmpkgscan/verdicts`; release a confirmed false positive through
the break-glass workflow. For *failing* / *serving unscanned*, the `code` label
of `pullthrough_llmpkgscan_unscanned_total` says why: `provider-error`,
`timeout` and `provider-unavailable` point at the LLM provider (reachability,
credentials, rate limits); `scanner-busy` means scans are queueing — raise
`llmPackageScan.maxConcurrent`; `budget-exhausted` means a ceiling was reached.
While any of these lasts the gate enforces nothing for new artifacts unless
`failMode` is `closed`. See [llm-package-scan.md](llm-package-scan.md).

### Compliance alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughComplianceControlFailing` | warning | a compliance control has been failing for 15m. |
| `PullthroughComplianceScoreRegressed` | warning | overall compliance score <80% for 30m. |
| `PullthroughComplianceSLSARegressed` | warning | estimated SLSA build level dropped below L2 for 1h. |
| `PullthroughComplianceScorecardStale` | info | scorecard not recomputed in >30m (computation loop stalled). |

**Respond:** open the admin **Compliance** tab (or `GET
{adminPrefix}/api/compliance`) and read the failing control's `detail`. A
regression usually traces back to one gate — e.g. dropping signature coverage or
a stalled audit checkpoint sealer — so chase the upstream gate's own alerts and
metrics first.

### Rate-limit alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughRateLimitThrottlingHigh` | warning | >20% of requests throttled for 10m. |
| `PullthroughByteQuotaExhausted` | warning | requests rejected by byte quota in 15m. |
| `PullthroughConcurrencySaturation` | warning | requests rejected by the concurrency cap for 10m. |

**Respond:** review per-tenant policy or scale out; a single tenant spiking may
indicate abuse ([access-control-and-audit.md](access-control-and-audit.md)).

### Notify alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| `PullthroughNotificationDeliveryFailures` | warning | a sink fails delivery (after retries) for 15m. |
| `PullthroughNotificationsDropped` | warning | a sink's delivery queue is full and dropping for 10m. |
| `PullthroughScanQueueBacklog` | warning | >100 commits waiting in the LLM scan queue for 15m. |

**Respond:** failing notification sinks mean operators miss other alerts — fix
the webhook/Slack endpoint first ([notifications.md](notifications.md)). A scan
backlog points at the LLM API backend ([runbook.md](runbook.md#metrics)).

## Runtime profiling (pprof & execution traces)

For diagnosing CPU hotspots, allocation pressure, goroutine leaks, and lock
contention in a live process, the proxy can expose Go's `net/http/pprof`
endpoints and `runtime/trace` execution-trace capture. They are **off by
default** and, when enabled, are mounted **on the admin surface under
`<adminPrefix>/api/debug/pprof/`** — never on a separate or unauthenticated
listener. They therefore inherit the admin API's authentication and RBAC
unchanged: a caller must present a valid admin credential **and** hold the
`operate` capability (profiling is treated as an operational action, since a CPU
or trace capture holds the profiler and consumes resources for its duration).

Enable it:

```yaml
observability:
  admin: true                 # profiling is served on the admin surface
  adminToken: ${PTS_ADMIN}    # (or adminAuth) — do not expose pprof unauthenticated
  profiling: true
  profilingBlockRate: 10000   # optional: enable block profiling (ns between samples; 0 = off)
  profilingMutexFraction: 100 # optional: enable mutex profiling (1/N sampled; 0 = off)
```

> Enabling `profiling` on an **unauthenticated** admin surface is flagged by
> `pullthrough verify-config` / the config preflight: unauthenticated pprof
> leaks runtime internals and lets anyone pin a CPU with a long capture. Always
> pair it with `adminToken` or `adminAuth`.

Available endpoints (all require the `operate` capability):

| Endpoint | Profile |
|----------|---------|
| `…/api/debug/pprof/` | index / profile list (HTML) |
| `…/api/debug/pprof/profile?seconds=N` | CPU profile (pprof proto) |
| `…/api/debug/pprof/heap` | heap / in-use & allocated memory |
| `…/api/debug/pprof/goroutine` | goroutine stacks |
| `…/api/debug/pprof/allocs` | sampled allocations |
| `…/api/debug/pprof/block` | blocking profile (needs `profilingBlockRate` > 0) |
| `…/api/debug/pprof/mutex` | mutex contention (needs `profilingMutexFraction` > 0) |
| `…/api/debug/pprof/threadcreate` | OS-thread creation |
| `…/api/debug/pprof/trace?seconds=N` | runtime/trace execution trace |
| `…/api/debug/pprof/cmdline`, `…/symbol` | process args / symbol lookup |

Because the endpoints sit behind the bearer/OIDC credential, pass it through to
the Go tools. For example, against a proxy at `https://proxy.example.com` with
admin prefix `/admin`:

```sh
# 30s CPU profile, opened in the interactive pprof UI
go tool pprof -http=: "https://proxy.example.com/admin/api/debug/pprof/profile?seconds=30" \
  -H "Authorization: Bearer $PTS_ADMIN"

# heap snapshot
curl -fsS -H "Authorization: Bearer $PTS_ADMIN" \
  "https://proxy.example.com/admin/api/debug/pprof/heap" -o heap.pprof
go tool pprof -http=: heap.pprof

# 5s execution trace
curl -fsS -H "Authorization: Bearer $PTS_ADMIN" \
  "https://proxy.example.com/admin/api/debug/pprof/trace?seconds=5" -o trace.out
go tool trace trace.out
```

For reproducible throughput/latency measurement and the hot-path micro-
benchmarks, see [performance.md](performance.md).

## Routing alerts to Alertmanager

Every alert has `severity` (critical|warning) and `component` labels. Route on
them, e.g.:

```yaml
route:
  routes:
    - matchers: ['severity="critical"']
      receiver: pager
    - matchers: ['component=~"sigverify|nameguard|rescan|vulnscan"']
      receiver: security-team
```

In Helm, `prometheusRule.additionalLabels` stamps extra labels (e.g.
`team: platform`) onto every alert for routing.
