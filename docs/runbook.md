# Admin runbook

Operational guide for running `pullthrough-security` in production: startup,
health, monitoring, the admin surface, routine tasks, and incident response. For
deployment mechanics (Docker/Helm/k8s) see [../deploy/README.md](../deploy/README.md).

## The binary

```sh
pullthrough -config /etc/pullthrough/config.yaml
```

Command-line flags:

| Flag | Purpose |
|------|---------|
| `-config <path>` | Path to the YAML config file. |
| `-version` | Print the version and exit. |
| `-verify-audit <path>` | Verify the tamper-evidence of an audit log and exit (see [Audit](#audit-log)). |
| `-audit-key <string>` | HMAC key for `-verify-audit` (defaults to `$PTS_AUDIT_HMAC_KEY`). |

Configuration is validated at startup; on a config error the process exits
non-zero with a descriptive message and serves nothing. Use this for a pre-deploy
config check.

## Startup checklist

- [ ] `cache.dir` (and `git.mirrorDir`, `*.storeDir`, `audit.file` if used) are on
      a **persistent** volume under `/var/lib/pullthrough`.
- [ ] Stable keys are set: `audit.hmacKey`, the `secrets` master key,
      `git.ssh.hostKeyFile` (if SSH is enabled).
- [ ] `server.publicUrl` is the externally reachable URL (correct index rewrites).
- [ ] In shared/production deployments, `auth.enabled: true` with deny-by-default
      RBAC, and the admin API behind `observability.adminToken` or network policy.
- [ ] Upstream TLS verification on; CAs pinned for private mirrors.
- [ ] Prometheus is scraping `/metrics`; alerts wired (see [Alerts](#suggested-alerts)).

## Health & readiness

Always served at the root, regardless of `observability`:

| Endpoint | Behavior | Use |
|----------|----------|-----|
| `GET /healthz` | `200 ok` always (process is up). | Liveness probe. |
| `GET /readyz` | `200 ready` when ≥1 backend is registered; `503 no backends registered` otherwise. | Readiness/rollout gate. |

```sh
curl -fsS localhost:8080/healthz
curl -fsS localhost:8080/readyz
```

## Metrics

Prometheus exposition at `observability.metricsPath` (default `/metrics`). The
full metric reference, the four shipped **Grafana dashboards**, and the 24
**Prometheus alerting rules** (with import/deploy instructions for Compose, Helm,
and kustomize) are documented in [observability.md](observability.md); the bundle
lives in [`../deploy/observability/`](../deploy/observability/README.md). The
highlights below are the metrics operators reach for most.

**Request / upstream:**

- `pullthrough_requests_total{backend,method,code}` — counter.
- `pullthrough_upstream_request_duration_seconds{backend}` — histogram (5ms–30s).
- `pullthrough_upstream_errors_total{backend}` — counter.
- `pullthrough_served_bytes_total{backend}` — counter.
- `pullthrough_policy_decisions_total{ecosystem,action}` — counter (`action` ∈ allow|warn|block).

**Cache:**

- `pullthrough_cache_hits_total`, `pullthrough_cache_misses_total`,
  `pullthrough_cache_hit_ratio` (gauge), `pullthrough_cache_loads_total`,
  `pullthrough_cache_evictions_total`, `pullthrough_cache_expired_total`,
  `pullthrough_cache_written_bytes_total`, `pullthrough_cache_served_bytes_total`,
  `pullthrough_cache_errors_total` (non-miss store failures — the key signal for
  S3/object-storage backend health), `pullthrough_cache_coalesced_total`.

**Scanning:**

- `pullthrough_scan_queue_depth` (gauge) — commits queued.
- `pullthrough_scan_pending` (gauge) — queued or in-flight.

### Suggested alerts

A ready-to-deploy rule file with 24 alerts (availability, cache/S3 errors,
supply-chain, rate-limit, notify) ships in
[`../deploy/observability/prometheus/alerts.yaml`](../deploy/observability/prometheus/alerts.yaml)
— see the [alert catalogue](observability.md#alert-catalogue). The table below is
the at-a-glance subset.

| Condition | Signal | Likely cause |
|-----------|--------|--------------|
| Upstream failing | `rate(pullthrough_upstream_errors_total[5m]) > 0` sustained | Upstream down, creds expired, egress blocked. |
| Blocks spiking | `rate(pullthrough_policy_decisions_total{action="block"}[5m])` jump | Malicious dependency surge, or policy too strict. |
| Scan backlog | `pullthrough_scan_pending` climbing | LLM throttling/outage, too few `commit.workers`. |
| Cache thrash | `pullthrough_cache_hit_ratio` dropping | Cache too small (`maxSizeBytes`) or TTL too low. |
| Readiness flapping | `/readyz` 503 | No backends registered → config/wiring error. |

## Admin dashboard & API

Mounted under `observability.adminPathPrefix` (default `/admin`); the browser
dashboard is at `<prefix>/`, the JSON API under `<prefix>/api/`. Guard it with
`observability.adminToken` (Bearer) and/or network policy — the dashboard shell
loads unauthenticated so a browser can prompt, but the API requires the token.

| Endpoint | Purpose |
|----------|---------|
| `GET <prefix>/api/overview` | Config summary, cache stats, scan/provenance counters. |
| `GET <prefix>/api/policy` | Effective policy configuration. |
| `GET <prefix>/api/cache` | List cache entries (`q` search, `limit`). |
| `GET <prefix>/api/cache/entry?key=` | Single cache entry metadata. |
| `DELETE <prefix>/api/cache/entry?key=` | Evict a cache entry. |
| `GET <prefix>/api/scans` | Verdicts (highest risk first) + queue depth. |
| `GET <prefix>/api/scans/entry?sha=` | Single commit verdict. |
| `GET <prefix>/api/provenance?ecosystem=&name=&version=&digest=` | Resolve an artifact's provenance. |
| `GET <prefix>/api/provenance/links` | Established package→commit links with verdicts. |

```sh
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
  localhost:8080/admin/api/overview | jq .
```

The dashboard shows cache stats (hit ratio, evictions), scan verdicts (SHA, risk
score, malicious flag, findings), and provenance links (package, version, commit,
repo, confidence).

## Audit log

When `audit.enabled`, every pull (with cache HIT/MISS/BYPASS, status, bytes) and
every authz/quota/policy decision is appended to a keyed hash chain at
`audit.file`. Verify integrity any time — runnable from cron/CI:

```sh
pullthrough -verify-audit /var/lib/pullthrough/audit/audit.log \
  -audit-key "$PTS_AUDIT_HMAC_KEY"
# verify-audit: OK — 12345 records form an intact tamper-evident chain
```

It exits non-zero and names the first broken record on tampering. The chain
resumes across restarts. The log is integrity-protected, not encrypted, and
contains no secrets. See
[access-control-and-audit.md](access-control-and-audit.md#tamper-evident-audit-log).

## Routine operations

### Rotating secrets

- **Upstream credentials / API keys:** update the `${ENV}`/`enc:v1:` value and
  restart (rolling). Clients are unaffected (they auth to the proxy).
- **`audit.hmacKey`:** rotating starts a *new* chain; archive the old log with its
  old key for later verification. Don't rotate mid-stream if you need one
  continuous verifiable chain.
- **Proxy access tokens (`auth.tokens`):** add the new token, roll out, then
  remove the old. Use `tokenHash` to avoid storing plaintext.
- **`secrets` master key:** re-encrypt all `enc:v1:` values with the new key
  before switching `keyEnv`/`keyFile`.

### Cache management

- The cache is **rebuildable** — losing it only causes upstream re-fetches.
- Evict a single poisoned/stale entry via the admin API
  (`DELETE <prefix>/api/cache/entry?key=`).
- Reclaim space by lowering `cache.maxSizeBytes` (LRU eviction) or `cache.ttl`.
- To purge entirely: stop the proxy, clear `cache.dir`, restart. (Do **not** clear
  `audit.file` or the scan/provenance stores this way.) With the `s3` backend,
  purge by emptying the bucket under `cache.s3.prefix` instead.

### Forcing re-scan of a commit

Verdicts are cached by SHA in `commit.storeDir`. To re-evaluate after a model or
policy change, remove that commit's verdict from the store (or clear the store to
re-scan all on next pull). A commit with no stored verdict is treated per
`policy … onMissingScan` until the async scan completes.

### Upgrades & rollback

Images are immutable-tagged. With Helm: `helm upgrade` for a rolling update
(`maxUnavailable: 0`, PDB, config-checksum-triggered restart), `helm rollback`
to revert. Cache/state persist across upgrades on the PVC. See
[../deploy/README.md](../deploy/README.md).

### Scaling

For horizontal, multi-node scaling the recommended approach is the **shared
object-storage cache** (`cache.backend: s3`): all replicas share one cache in an
S3/MinIO/GCS bucket, so they are stateless with respect to the cache and you can
raise `replicaCount`/the HPA without a `ReadWriteMany` volume. See
[ha-shared-cache.md](ha-shared-cache.md) for the full guide; manage cache
retention with a bucket lifecycle policy (leave `maxSizeBytes: 0`).

Without the shared backend, the default `ReadWriteOnce` cache PVC can't be shared
across nodes — use a `ReadWriteMany` StorageClass or accept node-pinned replicas
(each maintains an independent cache). Optionally set `auth.cacheNamespacing: true`
to partition cache by tenant. The Git SSH gateway needs its own Service (it can't
share the HTTP ingress).

## Incident response

> For the full, step-by-step incident procedures — responding to a
> quarantine/break-glass event, engaging and clearing the emergency lockdown
> kill-switch, interpreting the risk verdict and compliance scorecard, DR
> backup/restore, rotating signing keys and OIDC secrets, and handling a
> malware-feed hit — each with decision trees and the RBAC role required per
> action, see the
> [operator runbook & incident-response playbook](incident-response-playbook.md).
> The quick responses below cover the most common cases.

### A malicious package is being pulled

1. Confirm via the admin API: `GET /admin/api/scans` (high risk / `malicious`) and
   `GET /admin/api/provenance/links` for affected artifacts.
2. Block immediately: add the name to `policy.ecosystems.<eco>.denylist` (or raise
   enforcement) and roll out — denied pulls return 403 and never cache/fetch.
3. Evict any already-cached copy: `DELETE /admin/api/cache/entry?key=`.
4. Audit the blast radius from the audit log (who pulled it, when).

### Upstream is down or rate-limiting

- Cached artifacts keep serving. For new misses, add/refresh upstream
  `credentials` to raise limits (e.g. Docker Hub), or wait out the outage.
- Check `pullthrough_upstream_errors_total{backend}` to scope the affected
  upstream.

### Suspected tampering

- Run `-verify-audit` to confirm chain integrity.
- Restrict access to `/var/lib/pullthrough`; treat a cache-write-capable
  compromise as content-poisoning (purge and re-pull).

### Policy is too strict (false positives blocking builds)

- Inspect the 403 body / `X-Policy-Code` to see which rule fired.
- Temporarily switch the offending check to `warn`, or whitelist the specific
  package via `allowlist`, then tune thresholds. See
  [security-model.md](security-model.md#policy-admission-gating).

## Quick reference

```sh
# Health
curl -fsS localhost:8080/healthz && curl -fsS localhost:8080/readyz
# Smoke test a backend
curl -fsS localhost:8080/v1/npm/lodash | head
# Overview (admin)
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" localhost:8080/admin/api/overview | jq .
# Verify audit chain
pullthrough -verify-audit "$AUDIT_LOG" -audit-key "$PTS_AUDIT_HMAC_KEY"
```
