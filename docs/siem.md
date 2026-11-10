# SIEM / log forwarding

The proxy can stream its two most security-relevant event streams — the
**tamper-evident audit log** (Task 31) and the **admission-gate findings** (Task
42) — to an external **SIEM** in real time. This turns the proxy from a system
that *records* supply-chain decisions locally into one that *feeds your detection
and compliance platform*, so an analyst can alert, correlate, and retain the
proxy's decisions alongside the rest of the estate.

Implemented in [`internal/siem`](../internal/siem). Off by default; enable it
under the [`siem`](configuration-reference.md#siem) config block.

Three sink types ship:

| Kind | Destination | Transport | Wire format |
|------|-------------|-----------|-------------|
| `splunk_hec` | Splunk HTTP Event Collector | HTTPS (or HTTP) | newline-delimited HEC event envelopes (JSON) |
| `syslog` | Any syslog/CEF collector (QRadar, ArcSight, Sentinel via forwarder, rsyslog, …) | TCP, UDP, or TCP+TLS | ArcSight **CEF** over an RFC 5424 syslog header |
| `ocsf` | Any OCSF-aware platform (AWS Security Lake, Snowflake, …) | HTTPS (or HTTP) | **OCSF**-normalized JSON objects, newline-delimited (NDJSON) |

## What is forwarded

- **Audit records** — every durably-committed entry in the hash-chained audit
  log: pulls, cache hits/misses, authN/authZ decisions, policy decisions, admin
  mutations, egress denials, snapshot/GitOps actions, etc. Each forwarded event
  preserves the record's sequence number and chain hashes (`seq`, `hash`,
  `prevHash`) so an analyst can correlate it back to — and, with the chain key,
  verify it against — the local log.
- **Gate findings** — after the admission gates run for a pull, each normalized
  finding (vulnscan/VEX, license, secretscan, sigverify, nameguard, riskscore,
  policyengine, provenance, installhooks, rebuildverify, buildprov, continuity,
  commitscan, actionpin) is forwarded as its own event with the artifact
  coordinate, rule id, identifier (e.g. CVE), severity, and suppression state.

Either stream can be turned off independently (`siem.forwardAudit`,
`siem.forwardFindings`); both default to on when the subsystem is enabled.

## Design guarantees

- **Never blocks the pull path.** Forwarding is fully asynchronous. Producers
  enqueue onto a bounded in-memory queue (`siem.queueSize`); the audit tap runs
  *after* the record is durably committed. A slow or unreachable SIEM can never
  stall a client pull.
- **Bounded memory with optional disk spill.** When the in-memory queue is full,
  events overflow to a bounded, file-backed spill queue (`siem.spill`) that
  survives a restart; only when **both** are full is an event dropped (and
  counted). Without spill, overflow is dropped rather than growing memory.
- **Batching.** The dispatcher coalesces queued events into batches of up to
  `siem.batchSize`, flushed at least every `siem.batchTimeout`. One HEC request
  carries a whole batch; a syslog batch is written as consecutive framed lines.
- **Retry with backoff.** A retryable failure (`5xx`, `429`, or a network/write
  error) is retried up to `siem.maxRetries` times with exponential backoff
  (`siem.retryBaseDelay` … `siem.retryMaxDelay`). A permanent `4xx` is not
  retried. `siem.timeout` bounds a single delivery attempt.
- **TLS.** The HEC and OCSF sinks and a `tcp+tls` syslog sink verify the endpoint against
  the system roots by default; a private CA bundle (`tls.caFile`), an SNI
  override (`tls.serverName`), and a TLS floor (`tls.minVersion`) are
  configurable. `tls.insecureSkipVerify` exists for testing only.
- **Audit-log integrity is unaffected.** The forwarder taps audit records through
  a *decorating sink* that forwards a read-only copy only after the inner durable
  sink has persisted the record. The hash chain is computed and committed by the
  audit `Logger` **before** the sink is ever called, so forwarding can neither
  alter nor delay the local log's tamper-evidence, and the Merkle transparency
  layer's resume path is preserved.

## Configuration

```yaml
siem:
  enabled: true
  queueSize: 1024          # in-memory queue bound (events)
  batchSize: 100           # max events per delivered batch
  batchTimeout: 5s         # flush a partial batch at least this often
  maxRetries: 3            # extra attempts after the first on a retryable failure
  retryBaseDelay: 500ms
  retryMaxDelay: 30s
  timeout: 10s             # per-attempt delivery timeout
  minSeverity: info        # floor: info|low|medium|high|critical (empty = info)
  forwardAudit: true       # forward the tamper-evident audit records
  forwardFindings: true    # forward admission-gate findings

  spill:                   # bounded disk overflow (recommended in production)
    enabled: true
    file: /var/lib/pullthrough/siem-spill.log
    maxBytes: 536870912    # cap on-disk spill at 512 MiB; further overflow is dropped

  sinks:
    - name: splunk
      kind: splunk_hec
      url: https://splunk.example.com:8088   # bare base URL gets /services/collector/event appended
      token: ${SPLUNK_HEC_TOKEN}             # supports ${ENV} and enc:v1: encryption
      index: security
      source: pullthrough-security
      sourceType: pullthrough:security
      tls:
        caFile: /etc/pki/splunk-ca.pem

    - name: corp-siem
      kind: syslog
      address: siem.example.com:6514
      network: tcp+tls                       # tcp | udp | tcp+tls
      facility: 16                            # 0..23, default 16 (local0)
      appName: pullthrough
      vendor: Blechschmidt
      product: pullthrough-security
      tls:
        minVersion: "1.2"

    - name: security-lake
      kind: ocsf
      url: https://ocsf-collector.example.com/ingest  # used verbatim (no path appended)
      token: ${OCSF_INGEST_TOKEN}            # sent as "Authorization: Bearer <token>" by default
      # authHeader: X-Api-Key                # override the header name …
      # authScheme: ""                       # … and/or the value prefix (empty = bare token)
      tls:
        minVersion: "1.2"

  ocsf:                      # OCSF encoder settings, shared by all kind: ocsf sinks
    schemaVersion: "1.1.0"   # stamped into metadata.version (default 1.1.0)
    # productName: pullthrough-security
    # vendorName: Blechschmidt
    classMap:                # optional category -> OCSF class overrides
      commitscan: detection_finding
```

The HEC/OCSF `token` and sink `url` support `${ENV_VAR}` expansion and `enc:v1:`
encryption, so no secret need be committed to disk (see
[configuration.md](configuration.md)).

### OCSF output (AWS Security Lake, Snowflake, …)

The `ocsf` sink emits each event as an [Open Cybersecurity Schema
Framework](https://schema.ocsf.io/) object so OCSF-aware data platforms can
ingest the proxy's decisions as normalized, queryable security events rather
than vendor-specific blobs. Events map onto OCSF event classes:

| Internal event | OCSF class | `class_uid` |
|----------------|-----------|-------------|
| `vulnscan` / `vex` findings | Vulnerability Finding | 2002 |
| `license` findings | Compliance Finding | 2003 |
| all other gate findings; `policy_decision`/`scan_verdict`/`egress_blocked`/`tls_pin` audit denials | Detection Finding | 2004 |
| `auth` audit records | Authentication | 3002 |
| all other audit records (pulls, cache, admin, …) | API Activity | 6003 |

Every record carries the OCSF core fields (`category_uid`, `class_uid`,
`activity_id`, `type_uid`, `severity_id`, `time` in epoch-ms, and a `metadata`
block with the schema version and product). Finding classes carry a
`finding_info` object (and Vulnerability Finding a `vulnerabilities[]` array with
the CVE and affected package `purl`); activity classes carry an `api`/`user`
object and a success/failure `status`. Any structured detail without a
first-class OCSF home — including the audit `seq`/`hash` chain-correlation keys —
is preserved under the OCSF-reserved `unmapped` object, so nothing is lost.

Override the default routing per category with `siem.ocsf.classMap`: each key is
a gate name (for findings) or audit event type (for audit records) and each value
names an OCSF class (`detection_finding`, `vulnerability_finding`,
`compliance_finding`, `authentication`, or `api_activity`). The target schema
version is set with `siem.ocsf.schemaVersion`.

### Severity mapping

Findings carry their native severity. Audit records have none, so a conservative
mapping is applied: policy/egress/scan **deny** and any **error** → `high`,
other denials and admin/gitops/snapshot mutations → `medium`, routine
pulls/cache events → `info`. CEF severities are rendered on the 0–10 scale
(`info`=1, `low`=3, `medium`=5, `high`=8, `critical`=10); syslog severities on
the standard 0–7 scale.

## Metrics

When the metrics endpoint is enabled, the forwarder exposes (all prefixed
`pullthrough_siem_`):

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `…_queue_depth` | gauge | — | events waiting in the in-memory queue |
| `…_spill_depth` | gauge | — | events buffered on disk |
| `…_events_enqueued_total` | counter | — | events accepted onto the queue |
| `…_events_spilled_total` | counter | — | events written to disk on overflow |
| `…_events_dropped_total` | counter | — | events dropped (both queues full) |
| `…_events_delivered_total` | counter | `sink` | events delivered successfully |
| `…_events_failed_total` | counter | `sink` | events dropped after exhausting retries |
| `…_retries_total` | counter | `sink` | batch retry attempts |
| `…_batches_total` | counter | `sink` | batches attempted |
| `…_ocsf_events_encoded_total` | counter | `class` | events encoded to OCSF, by OCSF class name |
| `…_ocsf_encode_errors_total` | counter | — | events that failed to encode to OCSF JSON |

Alert on a rising `…_events_dropped_total` or a persistently non-zero
`…_spill_depth`: either indicates the SIEM is not keeping up (raise `queueSize`,
`batchSize`, enable/enlarge spill, or investigate the sink).

## Receiver setup notes

- **Splunk HEC** — create an HEC token, enable the collector, and (if desired) a
  dedicated index. Point `url` at `https://<host>:8088`; the standard
  `/services/collector/event` path is appended automatically. The proxy
  authenticates with `Authorization: Splunk <token>`.
- **Syslog/CEF** — any collector that accepts CEF over syslog works. For TLS,
  use `network: tcp+tls` and point `tls.caFile` at the collector's CA. UDP is
  fire-and-forget (no delivery guarantee); prefer TCP or TCP+TLS for audit data.
- **OCSF** — point `url` at an HTTP(S) endpoint that accepts OCSF NDJSON (an AWS
  Security Lake custom-source ingestion gateway, a Snowflake ingestion REST
  endpoint, or any OCSF collector). The proxy authenticates with
  `Authorization: Bearer <token>` by default; use `authHeader`/`authScheme` or a
  static `headers` map for endpoints with a different scheme, or rely on mTLS and
  omit `token`.

## Verifying a forwarded audit record

Because each forwarded audit event carries `seq`, `prevHash`, and `hash`, an
analyst holding the audit HMAC key can independently recompute the chain hash for
the forwarded record and confirm it matches — detecting any tampering that
occurred between the proxy and the SIEM. The local log and its signed Merkle
checkpoints remain the authoritative tamper-evidence; SIEM forwarding is an
additional, out-of-band copy.
