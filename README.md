# pullthrough-security

[![CI](https://github.com/blechschmidt/pullthrough-security/actions/workflows/ci.yml/badge.svg)](https://github.com/blechschmidt/pullthrough-security/actions/workflows/ci.yml)
[![Docs](https://github.com/blechschmidt/pullthrough-security/actions/workflows/pages.yml/badge.svg)](https://blechschmidt.github.io/pullthrough-security/)
[![Go](https://img.shields.io/github/go-mod/go-version/blechschmidt/pullthrough-security)](go.mod)
[![Release](https://img.shields.io/github/v/release/blechschmidt/pullthrough-security?sort=semver&display_name=tag)](https://github.com/blechschmidt/pullthrough-security/releases)
[![Container](https://img.shields.io/badge/ghcr.io-pullthrough--security-2496ED?logo=docker&logoColor=white)](https://github.com/blechschmidt/pullthrough-security/pkgs/container/pullthrough-security)
![Platforms](https://img.shields.io/badge/platforms-linux%2Famd64%20%7C%20linux%2Farm64-informational)

📖 **Documentation site:** <https://blechschmidt.github.io/pullthrough-security/>

An enterprise pull-through proxy focused on software supply-chain security. It
caches content pulled from upstream registries and source forges, scans Git
commits with an LLM API, and associates package artifacts with the Git commits
that produced them (e.g. via build-provenance attestations).

It supports package managers (pip, npm, cargo, Go modules, NuGet), Docker/OCI
registries, and Git over HTTPS and SSH, with content-addressable caching, LLM
commit scanning, a sandboxed LLM review of each downloaded package's contents,
package→commit provenance resolution, admission policy,
authentication/RBAC/quotas, a tamper-evident audit log, a download log that
shows which package was downloaded from which client address, and Prometheus
metrics plus an admin dashboard.

> **Documentation:** see [docs/](docs/) for the full operator and user guides —
> [architecture](docs/architecture.md), [configuration](docs/configuration.md),
> [client setup](docs/clients.md), [security model](docs/security-model.md),
> [threat model](docs/threat-model.md), and the [admin runbook](docs/runbook.md).
> For a screenshot tour of the admin dashboard, see the
> [admin UI walkthrough](docs/admin-ui-walkthrough.md).
> To point tooling at the proxy, start with [docs/clients.md](docs/clients.md):
> one page per package manager — what to configure, how to hand it a token and
> a private CA, how to check it works, and what it does to your lock files.
>
> **Every ecosystem is tested with its real package manager.** On each push, CI
> runs the real `npm`, `pip`, `cargo`, `go`, `dotnet`, `mvn`, Docker Engine,
> `helm`, `bundler`, `composer`, `terraform`, `conan`, `conda`, `apt-get`, `dnf`,
> `git`, `mix`, `bazel`, `julia`, `cpanm`, `R`, `dart pub`, `ovsx`, `nix`, `deno`,
> `cabal`, `brew`, `ansible-galaxy`, `r10k` and `huggingface_hub` clients —
> configured to use the proxy, with no other network route — against the real
> proxy binary and registries: a good
> package installs (and re-installs from the cache), and a package whose source
> commit the LLM scan flagged malicious is refused. See
> [docs/ecosystem-tests.md](docs/ecosystem-tests.md); the verified client
> configuration for each ecosystem is in
> [docs/ecosystem-tests-reference.md](docs/ecosystem-tests-reference.md).
>
> **The client guide is executed, too.** Every configuration snippet in
> [docs/clients/](docs/clients.md) is, line for line, in a script that the real
> client runs (the four that are not say so) — in the ecosystem tests, or in the
> [client lab](docs/client-lab.md), which serves the proxy over HTTPS with a
> private CA, with and without a required token, to some sixty client
> configurations (Yarn, pnpm, Bun, uv, Poetry, Gradle, containerd, skopeo,
> OpenTofu, micromamba, …) on a network where the proxy is the only reachable
> host and every name a client looks up is recorded. A test fails when a
> snippet and its script drift apart.
>
> **Every package is read before it is served — in every ecosystem, proven.**
> With `llmPackageScan` enabled, a language model reviews the unpacked contents
> of each artifact a client pulls — in a sandbox: nothing is executed, the model
> has three read-only tools over an in-memory copy and no network — and the
> proxy refuses what it judges malicious, quarantines it, and records a finding.
> A CI suite proves it for every upstream type the proxy fronts, through the
> real proxy binary with a mock model: a benign package is served and the model
> saw its contents, a flagged one is refused and stays refused, verdicts are
> reused, both fail modes behave, and a prompt injection inside a package does
> not turn the verdict. See
> [docs/llm-package-scan.md](docs/llm-package-scan.md); the ecosystem × scenario
> matrix is attached to every CI run.
>
> **Who pulled what.** The admin console's Downloads tab (and
> `GET /admin/api/downloads`, `ptctl downloads`) lists every package download
> with the client address it came from — and every attempt an admission gate
> refused — filterable by address, CIDR, package and outcome. It is on by
> default and tested end to end with the real `cargo` and `go` clients. See
> [docs/download-log.md](docs/download-log.md).
>
> **And by whom.** An address is a machine, a NAT gateway or a shared build
> host. With personal cache links, a cache user signs in through your OpenID
> Connect identity provider and gets their own address for every package source
> — `https://proxy.example.com/u/<link>/v1/npm/` — and every download through
> it is recorded under their name. Tested end to end with the real `npm`,
> `pip`, `cargo`, `go`, Docker Engine and `git`. See
> [docs/user-links.md](docs/user-links.md).

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
| `internal/backends/pkgmgr` | Per-ecosystem backends (pip, npm, cargo, Go modules, NuGet) built on the HTTP engine. See [docs/backends.md](docs/backends.md). |
| `internal/clientguide`   | Keeps the client guide honest: every fenced block of `docs/clients.md` and `docs/clients/*.md` carries a marker naming the scripts that execute it (an ecosystem test script, or a client-lab script under `scripts/client-lab`), and tests fail when a line of a block is in none of them, when an upstream type has no page, or when a link does not resolve. |
| `internal/cache`         | `Cache` interface + in-memory and content-addressable filesystem stores (LRU + TTL, single-flight, metrics). |
| `internal/scan`          | `Scanner` interface and finding/severity model.                       |
| `internal/vulnscan`      | CycloneDX SBOM generation + pluggable vulnerability scanning (OSV.dev by default), result caching by digest, and the CVSS/severity admission gate. |
| `internal/license`       | License-compliance gate: SPDX expression parser (AND/OR/WITH), allow/deny/review policy with per-tenant overrides, license-drift detection. Reuses the vulnscan SBOM. See [docs/licenses.md](docs/licenses.md). |
| `internal/malfeed`       | Known-malicious-package gate: matches a pull's concrete `(ecosystem, name, version)` against curated malware datasets (OpenSSF/OSV malicious-packages + GitHub Advisory malware), with periodic ETag-conditional feed refresh and a signed offline bundle for air-gapped use. See [docs/malfeed.md](docs/malfeed.md). |
| `internal/llmpkgscan`    | Sandboxed LLM package-content scan gate: unpacks a fetched package into a bounded, read-only, in-memory tree and has a language model judge it malicious / suspicious / benign *before it is served* — through three read-only tools (list, read, grep) or a prioritized single-shot bundle; package code is never executed and the model has no network or host access. Package content is treated as untrusted data (per-scan nonce delimiters, a strict JSON verdict, deterministic prompt-injection and archive-structure cross-checks; a failed scan is "unscanned", never benign). Verdicts are cached by artifact digest + model + prompt version, concurrent scans of one digest are coalesced, and spend is bounded by per-tenant and global budgets. Covers every upstream type on every serve path — each ecosystem's own format (wheels to `.deb`/`.rpm` maintainer scripts to NARs), OCI images judged as a whole at the manifest with their blobs following the verdict, binaries shown as strings, non-cacheable responses held until the verdict exists, Git LFS objects, and verdicts carried across an air gap. Reuses the commit scanner's provider abstraction. See [docs/llm-package-scan.md](docs/llm-package-scan.md) and the generated [coverage record](docs/llm-package-scan-coverage.md). |
| `internal/scancoverage`  | The catalog of how every upstream type's artifacts reach the LLM scans (payload paths, formats, serve paths). `docs/llm-package-scan-coverage.md` is generated from it, and tests resolve every example against the real backends and fail when an upstream type has no entry. |
| `internal/maturity`      | Release-maturity / version-cooldown gate: quarantines newly-published versions until they age past a configurable cooldown window (per-ecosystem/per-tenant, allowlist bypass), deriving publish timestamps from the upstream registry metadata. Fails open on unknown timestamps; composes with break-glass. See [docs/maturity.md](docs/maturity.md). |
| `internal/reposcore`     | Source-repository health (OpenSSF Scorecard-style) signal provider: derives branch-protection/signed-commit/CI/security-policy/maintainer-bus-factor/activity/dep-automation signals from the package's associated Git repository (offline/air-gap friendly, optional online enrichment) and feeds a per-repo health/risk score into the policy & risk engines with per-tenant weights. See [docs/reposcore.md](docs/reposcore.md). |
| `internal/sbomdiff`      | SBOM diff & dependency-drift report: keeps a bounded per-coordinate history of resolved SBOMs and diffs each new version against the prior one (added/removed/version-bumped deps, newly-introduced licenses cross-referenced against the license policy, new namespaces/maintainers, net-new vulnerabilities), deriving an explainable "drift risk" score that feeds an optional admission signal so a quiet package that suddenly grows a suspicious dependency footprint can be quarantined. See [docs/sbom-diff.md](docs/sbom-diff.md). |
| `internal/snapshot`      | Organization dependency snapshot, freeze & instant rollback (the supply-chain "time machine"): captures the served dependency state (coordinate→digest, source commit, verdict, risk band, attestation digest) into signed, content-addressed point-in-time manifests; freezes the org to a snapshot via a pull-path gate that refuses pulls outside the frozen set; and rolls the org back to the last-known-good snapshot in one action when a shipped version is later found malicious. Signed with the audit key, recorded to the Merkle audit log. See [docs/snapshots.md](docs/snapshots.md). |
| `internal/lockdown`      | Emergency lockdown / global kill-switch incident-response mode: one durable, coord-guarded, TTL'd piece of state consulted as the FIRST pull-path check. Modes — `freeze` (serve only already-cached artifacts, block all new upstream fetches), `strict` (flip every observe-mode gate to enforce + harden thresholds, surfaced as an admission signal), and targeted `block` (deny a specific `(eco,name[,version])` coordinate everywhere, ahead of the malfeed refresh). Mandatory reason + incident ID to the Merkle audit log, EventLockdown notify, break-glass override. See [docs/lockdown.md](docs/lockdown.md). |
| `internal/egress`        | SSRF / outbound-egress guard: a transport-level (RoundTripper + dialer ControlContext) defense-in-depth control installed on every upstream client so all backends are covered uniformly. Enforces a scheme allowlist (https-only by default), an optional per-instance/per-tenant host/domain/CIDR allowlist, and denial of any request resolving to a private/link-local/loopback/unique-local/CGNAT/metadata IP range — re-validated immediately before connect to defeat DNS-rebinding — plus a redirect policy that re-checks every hop under a max-redirect cap. Fail-closed with `EventEgressBlocked` + per-reason metrics + Merkle audit. See [docs/egress-ssrf.md](docs/egress-ssrf.md). |
| `internal/notify`        | Event-notification & alerting (webhooks + Slack): per-event routing, severity filtering, field redaction, retry-with-backoff, bounded async delivery. See [docs/notifications.md](docs/notifications.md). |
| `internal/downloadlog`   | The download log: a bounded (entries + retention), queryable, optionally file-persisted record of which package was downloaded from which client address — and by which authenticated identity — including attempts an admission gate refused. Fed by the gateway (and the Git-over-SSH endpoint), served by the admin API's `/api/downloads` endpoints, shown in the console's Downloads tab and by `ptctl downloads`. Filters by address or CIDR, package (with wildcards), ecosystem, outcome, identity and time; aggregates "who pulled this package" / "what did this address pull"; CSV export. See [docs/download-log.md](docs/download-log.md). |
| `internal/clientip`      | Resolves the address a request is attributed to: the TCP peer, or — for the reverse proxies listed in `server.trustedProxies` — the client they forwarded the request for (`X-Forwarded-For`, read from the right, honored from trusted peers only). One answer per request, shared by the download log, the audit log and anomaly detection. |
| `internal/userlinks`     | Personal cache links: cache users sign in through an OpenID Connect identity provider (authorization code + PKCE) on a self-service page and get their own address of every package source (`/u/<link>/v1/<upstream>/…`, or `<host>/u/<link>/<upstream>/<image>` for container clients; the link also works as a credential), so the download log attributes each download to a person. Tokens are stored as hashes only; the link registry is shared between replicas through a directory or the S3 bucket; links expire and can be revoked by their user or an operator (`ptctl userlinks`, the console's User links tab). The gateway strips the prefix at its edge and puts it back into the index documents that link to the mount, so nothing behind the edge — cache, gates, logs, upstreams — ever sees a link. See [docs/user-links.md](docs/user-links.md). |
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
