# Outbound SBOM & findings federation (Dependency-Track / GUAC)

The proxy can push the CycloneDX SBOMs it generates during admission scanning
(Task 15/64) — optionally enriched with the vulnerability findings produced by
the scanning gate — into external supply-chain graph systems. This closes the
loop between what the proxy *sees pulled* and the organization's central
inventory and risk tooling.

Two pluggable sinks are supported, and either or both may be enabled:

- **OWASP Dependency-Track** — one CycloneDX BOM is uploaded per coordinate via
  `PUT {url}/api/v1/bom` with `X-Api-Key` authentication and project
  auto-create. The project name is `<ecosystem>:<name>` and the project version
  is the artifact version (falling back to the content digest), so the same
  package name in two ecosystems maps to two distinct Dependency-Track projects.
- **GUAC** — the CycloneDX document (or an in-toto statement wrapping the BOM as
  its predicate) is emitted to a GUAC collector HTTP ingestion endpoint, with an
  optional bearer token.

## How it runs

- A **periodic sweep** renders every cached scan report and delivers it to each
  enabled sink. The sweep is **leader-gated** (Task 56): in an HA deployment only
  the coordination leader exports, so a BOM is not uploaded N times by N
  replicas. Set `sbomExport.interval` to enable it; leave it at `0` for
  manual-only operation.
- An operator can trigger an **immediate export** on a specific node with
  `ptctl sbom-export run` (or `POST {admin}/api/sbomexport/run`). The manual
  trigger **bypasses the leader gate** — the operator explicitly asked *this*
  node to export.
- Delivery uses bounded exponential-backoff retries. HTTP `5xx`/`429` and
  transport errors are retried; other `4xx` (e.g. a bad API key) fail fast.

## Configuration

Credentials (`dependencyTrack.apiKey`, `guac.token`) accept a **secretRef**
(`env://`, `file://`, `vault://…#key`) and are resolved centrally at startup via
the secrets provider (Task 133), so they never need to appear inline and a Vault
rotation is not misreported as config drift.

```yaml
sbomExport:
  enabled: true
  includeFindings: true          # embed findings as CycloneDX `vulnerabilities`
  minSeverity: ""                # optional floor for embedded findings
  interval: 1h                   # 0 = manual trigger only (leader-gated when > 0)
  maxRetries: 3
  retryBaseDelay: 500ms
  retryMaxDelay: 30s
  timeout: 30s
  dependencyTrack:
    enabled: true
    url: https://dtrack.example.com
    apiKey: vault://secret/data/dtrack#apiKey
    autoCreate: true
    parentProject: ""            # optional parent for auto-created projects
  guac:
    enabled: true
    url: https://guac.example.com/ingest
    token: env://GUAC_TOKEN
    documentType: cyclonedx       # or "intoto"
```

See the generated [configuration reference](configuration-reference.md#sbomexport)
for every key and its default.

## Operating

```
ptctl sbom-export status     # sinks, sweep interval, leader state, counters
ptctl sbom-export run        # trigger an immediate export sweep on this node
ptctl sbom-export status -json
```

## Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `pullthrough_sbomexport_uploads_total` | counter | documents delivered to a sink |
| `pullthrough_sbomexport_failures_total` | counter | deliveries that failed after retries |
| `pullthrough_sbomexport_retries_total` | counter | retry attempts (backoff) |
| `pullthrough_sbomexport_skipped_total` | counter | reports with no usable SBOM |
| `pullthrough_sbomexport_uploads_by_target_total` | counter (`target`) | uploads by sink (`dependency-track`/`guac`) |
| `pullthrough_sbomexport_failures_by_target_total` | counter (`target`) | failures by sink |
