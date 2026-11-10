# pullthrough-security

An enterprise pull-through proxy focused on software supply-chain security. It
caches content pulled from upstream registries and source forges, scans Git
commits with an LLM API, and associates package artifacts with the Git commits
that produced them (e.g. via build-provenance attestations).

It supports package managers (pip, npm, cargo, Go modules, NuGet), Docker/OCI
registries, and Git over HTTPS and SSH, with content-addressable caching, LLM
commit scanning, package→commit provenance resolution, admission policy,
authentication/RBAC/quotas, a tamper-evident audit log, and Prometheus metrics
plus an admin dashboard.

> **Documentation:** see [docs/](docs/) for the full operator and user guides —
> [architecture](docs/architecture.md), [configuration](docs/configuration.md),
> [client setup](docs/clients.md), [security model](docs/security-model.md),
> [threat model](docs/threat-model.md), and the [admin runbook](docs/runbook.md).
> To point tooling at the proxy, start with [docs/clients.md](docs/clients.md).

## Architecture

```
                 ┌─────────────────────────────────────────────┐
   clients  ───▶ │  Gateway (internal/proxy)                   │
  (pip/npm/      │   HTTP + Git-over-SSH                        │
   cargo/go/     │   routing • access control • health • audit │
   nuget/maven/  └───────┬─────────────────────────────────────┘
   docker/git)          │ resolve → policy → cache → fetch → verify → serve
                         ▼
        ┌────────────────────────────┬───────────────────────────┐
        ▼                            ▼                           ▼
  Backends (internal/backends)  Cache (internal/cache)   Security pipeline
   one per protocol:             content-addressable      Scanner (internal/scan)
   git/pip/npm/cargo/go/         Get / Put / Stat         Resolver (internal/provenance)
   nuget/maven/docker            LRU + TTL + metrics      Policy (internal/policy)
   Resolve / Fetch
```

For a deeper walkthrough see [docs/architecture.md](docs/architecture.md).

### Packages

| Package                  | Responsibility                                                        |
|--------------------------|-----------------------------------------------------------------------|
| `cmd/pullthrough`        | Process entrypoint: config → wiring → serve.                          |
| `cmd/ptctl`              | Client CLI for developer onboarding: generate per-tenant config snippets, self-test connectivity/auth, inspect an artifact's admission verdict/findings, and fetch its attestation. See [docs/client-cli.md](docs/client-cli.md). |
| `internal/proxy`         | Core gateway: routing, request lifecycle, graceful shutdown.          |
| `internal/backends`      | `Backend` interface (`Resolve`/`Fetch`) and the backend `Registry`.   |
| `internal/backends/httpbackend` | Generic HTTP pull-through engine: routing, conditional fetch, credential injection, index-document rewriting. |
| `internal/backends/pkgmgr` | Per-ecosystem backends (pip, npm, cargo, Go modules, NuGet) built on the HTTP engine. See [docs/clients.md](docs/clients.md). |
| `internal/cache`         | `Cache` interface + in-memory and content-addressable filesystem stores (LRU + TTL, single-flight, metrics). |
| `internal/scan`          | `Scanner` interface and finding/severity model.                       |
| `internal/vulnscan`      | CycloneDX SBOM generation + pluggable vulnerability scanning (OSV.dev by default), result caching by digest, and the CVSS/severity admission gate. |
| `internal/license`       | License-compliance gate: SPDX expression parser (AND/OR/WITH), allow/deny/review policy with per-tenant overrides, license-drift detection. Reuses the vulnscan SBOM. See [docs/licenses.md](docs/licenses.md). |
| `internal/malfeed`       | Known-malicious-package gate: matches a pull's concrete `(ecosystem, name, version)` against curated malware datasets (OpenSSF/OSV malicious-packages + GitHub Advisory malware), with periodic ETag-conditional feed refresh and a signed offline bundle for air-gapped use. See [docs/malfeed.md](docs/malfeed.md). |
| `internal/maturity`      | Release-maturity / version-cooldown gate: quarantines newly-published versions until they age past a configurable cooldown window (per-ecosystem/per-tenant, allowlist bypass), deriving publish timestamps from the upstream registry metadata. Fails open on unknown timestamps; composes with break-glass. See [docs/maturity.md](docs/maturity.md). |
| `internal/reposcore`     | Source-repository health (OpenSSF Scorecard-style) signal provider: derives branch-protection/signed-commit/CI/security-policy/maintainer-bus-factor/activity/dep-automation signals from the package's associated Git repository (offline/air-gap friendly, optional online enrichment) and feeds a per-repo health/risk score into the policy & risk engines with per-tenant weights. See [docs/reposcore.md](docs/reposcore.md). |
| `internal/sbomdiff`      | SBOM diff & dependency-drift report: keeps a bounded per-coordinate history of resolved SBOMs and diffs each new version against the prior one (added/removed/version-bumped deps, newly-introduced licenses cross-referenced against the license policy, new namespaces/maintainers, net-new vulnerabilities), deriving an explainable "drift risk" score that feeds an optional admission signal so a quiet package that suddenly grows a suspicious dependency footprint can be quarantined. See [docs/sbom-diff.md](docs/sbom-diff.md). |
| `internal/snapshot`      | Organization dependency snapshot, freeze & instant rollback (the supply-chain "time machine"): captures the served dependency state (coordinate→digest, source commit, verdict, risk band, attestation digest) into signed, content-addressed point-in-time manifests; freezes the org to a snapshot via a pull-path gate that refuses pulls outside the frozen set; and rolls the org back to the last-known-good snapshot in one action when a shipped version is later found malicious. Signed with the audit key, recorded to the Merkle audit log. See [docs/snapshots.md](docs/snapshots.md). |
| `internal/lockdown`      | Emergency lockdown / global kill-switch incident-response mode: one durable, coord-guarded, TTL'd piece of state consulted as the FIRST pull-path check. Modes — `freeze` (serve only already-cached artifacts, block all new upstream fetches), `strict` (flip every observe-mode gate to enforce + harden thresholds, surfaced as an admission signal), and targeted `block` (deny a specific `(eco,name[,version])` coordinate everywhere, ahead of the malfeed refresh). Mandatory reason + incident ID to the Merkle audit log, EventLockdown notify, break-glass override. See [docs/lockdown.md](docs/lockdown.md). |
| `internal/egress`        | SSRF / outbound-egress guard: a transport-level (RoundTripper + dialer ControlContext) defense-in-depth control installed on every upstream client so all backends are covered uniformly. Enforces a scheme allowlist (https-only by default), an optional per-instance/per-tenant host/domain/CIDR allowlist, and denial of any request resolving to a private/link-local/loopback/unique-local/CGNAT/metadata IP range — re-validated immediately before connect to defeat DNS-rebinding — plus a redirect policy that re-checks every hop under a max-redirect cap. Fail-closed with `EventEgressBlocked` + per-reason metrics + Merkle audit. See [docs/egress-ssrf.md](docs/egress-ssrf.md). |
| `internal/notify`        | Event-notification & alerting (webhooks + Slack): per-event routing, severity filtering, field redaction, retry-with-backoff, bounded async delivery. See [docs/notifications.md](docs/notifications.md). |
| `internal/provenance`    | `Resolver` interface linking artifacts to source commits.             |
| `internal/config`        | YAML + environment configuration loading and validation.             |
| `internal/logging`       | Structured logging via `log/slog`.                                    |

### Core interfaces

- **`backends.Backend`** — `Resolve(req) → Resolved` maps an inbound request to
  an upstream resource and cache key; `Fetch(resolved) → FetchResult` transfers
  the bytes. The split lets the gateway consult the cache and apply policy
  between resolution and retrieval.
- **`cache.Cache`** — `Get` / `Put` / `Stat` / `Delete` over a
  content-addressable keyspace, safe for concurrent use.
- **`scan.Scanner`** — `Scan(target) → Result` inspects commits or artifacts and
  emits findings with severities.
- **`provenance.Resolver`** — `Resolve(artifact) → Link` associates an artifact
  digest with a repository and commit, with a confidence level.
- **`vulnscan.Scanner`** — `Scan(sbom) → []Vulnerability` resolves an SBOM's
  components against a vulnerability database. The OSV.dev client is the default;
  a Trivy/Grype adapter satisfies the same contract. The `vulnscan.Service`
  generates the CycloneDX SBOM, caches results by content digest (TTL + offline
  fallback), and turns CVSS/severity thresholds into a block/warn/quarantine
  admission decision. SBOMs are served at `GET /admin/api/sbom?digest=…` and
  findings at `/admin/api/vulns`.

## Configuration

Configuration is YAML with `${ENV_VAR}` expansion (and `enc:v1:` encrypted
values) for secrets, plus a few top-level environment overrides (e.g.
`PTS_HTTP_ADDR`, `PTS_LOG_LEVEL`, `PTS_SCAN_API_KEY`). See the annotated
[`configs/config.example.yaml`](configs/config.example.yaml) and the full
[configuration reference](docs/configuration.md).

## Build & run

```sh
make build                 # → bin/pullthrough and bin/ptctl (client CLI)
make build-client          # → bin/ptctl only
make run                   # run with configs/config.example.yaml
make test                  # unit tests
make help                  # list targets
```

Requires Go 1.24+.

Binaries and container images are built, tested, and released for **`linux/amd64`
and `linux/arm64`** (macOS amd64/arm64 binaries are published best-effort). See
[docs/platforms.md](docs/platforms.md) for the full support matrix, how the
multi-arch guarantee is enforced in CI, and multi-arch build commands
(`make docker-buildx`).
