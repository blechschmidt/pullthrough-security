# Notifications & alerting

The proxy can dispatch **structured security alerts** to external systems —
generic HTTP webhooks and Slack incoming webhooks — whenever a security-relevant
event occurs. This turns the supply-chain controls from "blocks a build and logs
a line" into "blocks a build, logs a line, **and pages the platform-security
channel**".

Implemented in [`internal/notify`](../internal/notify). Off by default; enable it
under the [`notifications`](configuration.md#notifications) config block.

## What it alerts on

| Event type | Fired when | Default severity |
|------------|-----------|------------------|
| `policy_block` | The admission policy (Task 9) blocks an artifact (denylist, allowlist, risk score, malicious commit). | `high` |
| `provenance_failure` | A block caused by a provenance signature/attestation requirement (`signature-required`, `attestation-required`, `low-confidence`). | `high` |
| `vulnerability` | The SBOM/OSV gate (Task 15) warns on, blocks, or quarantines an artifact. | the finding's max severity |
| `commit_scan` | An LLM commit-scan verdict (Task 7) is produced. A malicious verdict is escalated to ≥ `high`. | the verdict's max severity |
| `quarantine` | An artifact is quarantined (made unservable and evicted). | the finding's max severity |
| `rescan_regression` | The continuous re-scan subsystem (Task 18) finds a cached artifact became vulnerable against a newly-disclosed CVE. | the new max severity |
| `lockdown` | The emergency-lockdown / global kill-switch (Task 74) was engaged, cleared, or auto-expired (freeze/strict/targeted-block). | `critical` on engage, else `high` |

Each alert carries a stable `type`, a `severity`, a `title`/`summary`, the
affected coordinate (`ecosystem`, `backend`, `artifact`), the triggering
`subject` when authenticated, and a small map of structured `fields` (advisory
id, reason code, CVSS, commit SHA, …).

## Design guarantees

- **Never blocks the request path.** Producers call a non-blocking `Emit`; the
  Notifier hands deliveries to a bounded worker pool. If the queue is full, the
  notification is **dropped and counted** (`…_dropped_total`) rather than applying
  backpressure to a client pull.
- **Retry with backoff.** A retryable failure (`5xx`, `429`, or a network error)
  is retried up to `maxRetries` times with exponential backoff
  (`retryBaseDelay` … `retryMaxDelay`). A permanent `4xx` is not retried.
- **Severity filtering.** A global `minSeverity` floor plus an optional per-route
  floor keep low-signal events off your pager.
- **Redaction.** Sensitive-looking fields (anything whose key contains `token`,
  `password`, `secret`, `authorization`, `apikey`, … plus your `redactFields`)
  are scrubbed to `[REDACTED]` before the payload leaves the process — a
  notification endpoint may log or index what it receives.
- **De-duplication.** A sink reachable via two matching routes receives an event
  once.

## Sinks

### Generic webhook (`kind: webhook`)

POSTs a stable JSON document:

```json
{
  "type": "vulnerability",
  "severity": "critical",
  "title": "Vulnerable artifact blocked",
  "summary": "…",
  "timestamp": "2026-06-19T12:00:00Z",
  "ecosystem": "npm",
  "backend": "npm-proxy",
  "artifact": "left-pad@1.0.0",
  "subject": "alice",
  "fields": { "advisory": "CVE-2026-9999", "action": "block", "maxCvss": "9.8" },
  "source": "pullthrough-security"
}
```

Add `headers` for an `Authorization` bearer token or an HMAC-signature header your
receiver expects.

### Slack (`kind: slack`)

POSTs to a Slack **incoming webhook** URL with a severity-colored attachment and
the structured fields rendered as attachment fields. Optional `channel`,
`username`, and `iconEmoji` overrides are honored.

## Routing

`routes` map event types and a severity floor to sinks. With no routes, an
implicit catch-all delivers **every** event type to **every** sink at the global
`minSeverity`.

```yaml
notifications:
  enabled: true
  minSeverity: medium          # global floor
  redactFields: ["internalTicket"]
  sinks:
    - name: secops-slack
      kind: slack
      url: ${SLACK_WEBHOOK_URL} # treat as a secret; ${ENV}/enc:v1: supported
      channel: "#supply-chain-alerts"
      username: pullthrough
      iconEmoji: ":shield:"
    - name: siem
      kind: webhook
      url: https://siem.internal.example.com/ingest/pullthrough
      headers:
        Authorization: Bearer ${SIEM_TOKEN}
  routes:
    # Page Slack only for the serious, actionable blocks.
    - sinks: [secops-slack]
      eventTypes: [policy_block, provenance_failure, quarantine, rescan_regression]
      minSeverity: high
    # Forward everything (above the global medium floor) to the SIEM.
    - sinks: [siem]
```

## Operating it

- **Test a sink end-to-end** without waiting for a real event:

  ```bash
  curl -XPOST -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$PROXY/admin/api/notify/test?sink=secops-slack"
  ```

  Omit `?sink=` to test every configured sink. The response reports each sink's
  delivery result (the call performs a single attempt, no retries).

- **Inspect status & metrics:** `GET <admin>/api/notify` returns the configured
  sinks and cumulative per-sink delivery counters.

- **Prometheus metrics** (all labeled by `sink` except the queue gauge):

  | Metric | Meaning |
  |--------|---------|
  | `pullthrough_notifications_sent_total{sink}` | Successful deliveries. |
  | `pullthrough_notifications_failed_total{sink}` | Deliveries that failed after exhausting retries. |
  | `pullthrough_notifications_dropped_total{sink}` | Notifications dropped because the queue was full. |
  | `pullthrough_notifications_retries_total{sink}` | Delivery retries. |
  | `pullthrough_notifications_queue_depth` | Notifications currently waiting for a worker. |

  Alert on a rising `failed`/`dropped` rate — it means a sink is misconfigured,
  unreachable, or the proxy is producing alerts faster than the sink accepts them.

## Security notes

- Sink URLs (especially Slack incoming-webhook URLs) are secrets. Supply them via
  `${ENV_VAR}` or `enc:v1:` encryption rather than committing them.
- Redaction is defense-in-depth, not a license to put secrets in event fields:
  producers should never place raw credentials in an `Event`.
- The admin test endpoint is guarded by the same `observability.adminToken` as the
  rest of the admin API.
