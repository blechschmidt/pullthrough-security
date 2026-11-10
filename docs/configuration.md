# Configuration reference

The proxy is configured by a single YAML file, selected with `-config`:

```sh
pullthrough -config /etc/pullthrough/config.yaml
```

A fully annotated template lives at
[`configs/config.example.yaml`](../configs/config.example.yaml) — copy it and
edit. This page is the field-by-field reference.

## Value substitution

- **`${ENV_VAR}`** — any string value may interpolate environment variables, so
  secrets stay out of the file (e.g. `token: ${GITHUB_TOKEN}`).
- **`enc:v1:...`** — values carrying this prefix are decrypted at load time using
  the master key from the [`secrets`](#secrets) block (AES-256-GCM). Plaintext,
  `${ENV}`, and `enc:v1:` values may be mixed. An `enc:v1:` value with no
  configured key is a hard error. See
  [access-control-and-audit.md](access-control-and-audit.md#secrets-at-rest).
- **`secretRef` providers** — any credential field may instead hold a reference
  that is resolved at startup from an external secrets provider:
  - `env://NAME` — the value of environment variable `NAME` (errors if unset or
    empty). Equivalent to `${NAME}` but explicit.
  - `file://PATH` — the contents of a file (trailing whitespace trimmed). The
    file must be owner-readable only (mode `0600`/`0400`); a group- or
    world-accessible secret file is rejected.
  - `vault://PATH#KEY` — field `KEY` of the HashiCorp Vault KV v2 secret at
    `PATH`. Requires the [`secrets.vault`](#secrets) block to be enabled; a
    background refresher renews the auth lease and re-reads cached secrets so
    long-lived processes survive token expiry and observe rotations.
  - `literal://VALUE` — `VALUE` verbatim; an escape hatch for a literal that
    would otherwise look like a reference.
  A value with no recognized scheme is a plain literal (unchanged behavior).
  Resolution is central: no resolved secret value ever appears in logs, metrics
  labels, the admin API, or the drift fingerprint (credential fields are redacted
  before fingerprinting, so a rotated secret is not misreported as drift).
  Resolution/refresh counts are exported as `pullthrough_secrets_*`.
- **`PTS_*` environment overrides** — a small set of top-level settings can be
  overridden by environment variables, convenient for containers (see
  [Environment overrides](#environment-overrides)).

Everything is **off by default**: with a minimal config (a `server` address, a
`cache`, and one or more `upstreams`) the proxy runs as a plain caching mirror.
Authentication, scanning, provenance, policy, and audit are opt-in.

> **Field-by-field reference.** The exhaustive list of every setting, its type,
> and its default is auto-generated from the code in
> [configuration-reference.md](configuration-reference.md) — it can never drift
> from the schema (CI regenerates and diffs it).

---

## Validation, preflight & drift detection

The configuration surface is large, so the proxy ships a single authoritative
validation pass and a drift detector to keep deployments operable.

**Validate a candidate file before rollout.** All three entry points share the
same `internal/config` validation — type/range checks, cross-field invariants,
unknown/typo'd keys (strict mode), and inter-subsystem consistency (e.g. a gate
enabled without the peer subsystem or credential it needs). Every problem is
reported at once with its field path; the command exits non-zero on any error
(`-strict` also fails on warnings):

```sh
pullthrough verify-config -config /etc/pullthrough/config.yaml   # server binary
ptctl config validate /etc/pullthrough/config.yaml               # client, over HTTP
ptctl config validate                                            # validate the live config
```

The same validation is exposed for automation at the admin endpoint
`GET /api/config/validate` (validates the running config) and
`POST /api/config/validate` with `{"content": "<yaml>"}` or `{"path": "<file>"}`
(validates a candidate). It is read-only and requires only the read capability.

**Drift detection.** The proxy fingerprints the effective configuration it
loaded at startup. `GET /api/config/drift` (or `ptctl config drift`) re-reads the
on-disk file and reports whether it has diverged from what the process is
running — the operability companion to the hot-reload subsystems. The
`pullthrough_config_drift` gauge exposes the same signal (1 = drifted or the file
no longer loads) for alerting. A comment-only edit is *not* reported as drift
(the effective config is unchanged); a semantic change, or a file that no longer
parses/validates, is.

The reference doc is regenerated (and CI fails if stale) with:

```sh
make config-reference-gen     # rewrite docs/configuration-reference.md
make config-reference-check   # CI staleness gate
```

---

## `server`

| Field | Default | Description |
|-------|---------|-------------|
| `httpAddr` | `:8080` | Main HTTP listen address. Required. |
| `publicUrl` | _(empty)_ | Externally reachable base URL. Used to rewrite index documents (npm/PyPI/cargo/NuGet) to absolute proxy URLs. Strongly recommended in production; when empty, rewrites are root-relative. |
| `sshAddr` | _(empty)_ | Enables the Git-over-SSH gateway on this address (e.g. `:2222`). Requires `git.mirrorDir`. Empty disables SSH. |
| `readTimeout` | `30s` | Max time to read a request. |
| `writeTimeout` | `5m` | Max time to write a response (large artifacts need headroom). |
| `shutdownTimeout` | `30s` | Grace period for in-flight requests on shutdown. |
| `registry.enabled` | `true` | Also serve the Docker/OCI Registry v2 API at the host root (`/v2/...`). Container clients put `/v2/` directly after the registry host and cannot address the path-prefixed `/v1/<upstream>/v2/` mount; the alias maps each request onto it, through the same access control and admission gates. No effect without a registry upstream (type `docker`, or `helm` with `oci: "true"`). |
| `registry.defaultUpstream` | _(empty)_ | Registry upstream that serves **un-prefixed** repositories, i.e. registry-mirror mode (`"registry-mirrors": ["https://proxy.example.com"]`). When empty, only `<proxy>/<upstream>/<repository>` references and containerd `?ns=`-hinted requests are served. See [clients.md](clients.md#docker--oci-images). |

## `logging`

| Field | Default | Description |
|-------|---------|-------------|
| `level` | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `format` | `json` | `json` \| `text`. |
| `addSource` | `false` | Include source file:line in log records. |

## `cache`

| Field | Default | Description |
|-------|---------|-------------|
| `backend` | `filesystem` | `memory` (dev) \| `filesystem` (content-addressable on disk) \| `s3` (shared object storage, see below). |
| `dir` | — | Cache directory. Required for `filesystem`. |
| `maxSizeBytes` | `0` | `0` = unbounded; otherwise evicts least-recently-used past this size. |
| `ttl` | `0s` | `0` = no expiry; otherwise the max entry age (e.g. `168h`). |
| `sealed` | `false` | Offline/air-gapped mode: serve only cached content, never reach upstreams. |

### `cache.s3` (shared object-storage backend)

The `s3` backend stores the content-addressable cache in an S3-compatible bucket
(AWS S3, MinIO, Ceph RGW, or GCS via its S3-compatible endpoint) so multiple proxy
replicas share one cache — the foundation for horizontally-scaled, highly-available
deployments. It preserves content-addressing, single-flight de-duplication, sealed
mode, and metrics; see [ha-shared-cache.md](ha-shared-cache.md) for the full HA guide.

| Field | Default | Description |
|-------|---------|-------------|
| `endpoint` | AWS endpoint for `region` | Service endpoint, e.g. `http://minio:9000` or `https://storage.googleapis.com`. |
| `region` | `us-east-1` | SigV4 signing region. MinIO/GCS accept any stable value. |
| `bucket` | — | Target bucket (**required**). |
| `prefix` | _(empty)_ | Key prefix isolating this cache within a shared bucket, e.g. `cache/`. |
| `accessKeyId` | — | Access key (**required**; supports `${VAR}` / `enc:v1:`). |
| `secretAccessKey` | — | Secret key (**required**; supports `${VAR}` / `enc:v1:`). |
| `sessionToken` | _(empty)_ | Optional STS/temporary-credential session token. |
| `usePathStyle` | `false` | Use path-style addressing. **Set `true` for MinIO/Ceph.** |
| `insecureSkipVerify` | `false` | **UNSAFE** — disable endpoint TLS verification (self-signed test only). |
| `maxRetries` | `2` | Automatic retries on transient (5xx/network) failures. |
| `spoolDir` | OS temp dir | Directory used to spool streamed uploads (length/digest for signed PUT). |
| `sharedMode` | `true` | HA store-fallback reads: serve content another replica wrote after this one started. |

For a shared bucket, leave `maxSizeBytes` at `0` and manage retention with an
object-store lifecycle/expiration policy rather than per-replica LRU eviction.

## `outbound`

Shared outbound HTTP client used to fetch from upstreams. Upstreams that share an
effective TLS policy also share a connection pool. All fields optional.

| Field | Default | Description |
|-------|---------|-------------|
| `userAgent` | `pullthrough-security/1` | `User-Agent` sent to upstreams. |
| `dialTimeout` | `15s` | TCP connect timeout. |
| `responseHeaderTimeout` | `30s` | Wait for upstream response headers. |
| `idleConnTimeout` | `90s` | Idle keep-alive lifetime. |
| `tlsHandshakeTimeout` | `10s` | TLS handshake timeout. |
| `maxIdleConns` | `100` | Total idle connections. |
| `maxIdleConnsPerHost` | `16` | Idle connections per host. |
| `tls.caCertFile` | _(empty)_ | Extra PEM CA bundle for private registries. |
| `tls.insecureSkipVerify` | `false` | **UNSAFE** — disables upstream certificate verification. |
| `tls.minVersion` | `1.2` | `1.0` \| `1.1` \| `1.2` \| `1.3`. |

## `upstreams`

A map of `<name> → upstream`. Each upstream is exposed under `/v1/<name>/...`.
See [clients.md](clients.md) for repointing each ecosystem's tooling.

| Field | Description |
|-------|-------------|
| `type` | One of `npm`, `pip`, `cargo`, `go`, `nuget`, `maven`, `rubygems`, `composer`, `helm`, `apt`/`deb`, `yum`/`rpm`, `docker`, `terraform`, `conan`, `conda`, `cran`, `hex`, `bazel`, `swift`, `dart`/`pub`, `huggingface`, `git`. (Validated.) |
| `settings.gpgKeyFile` / `.gpgKey` | (`apt`/`yum`) ASCII-armored public keyring — file path or inline — that the repository Release/repomd.xml signature is validated against. Omit to rely on the SHA-256 content chain alone. |
| `url` | Upstream base URL (for `git`, an `https://` or `ssh://` origin). |
| `credentials.username` / `.password` / `.token` | Optional upstream credentials, injected by the proxy toward the upstream. Support `${ENV}` / `enc:v1:`. |
| `tls.*` | Per-upstream TLS override (same fields as `outbound.tls`), e.g. a private mirror behind an internal CA. |
| `mirrors` | Optional ordered list of equivalent mirror endpoints for health-aware failover (see below). Not supported for `git`. |
| `failover.*` | Circuit-breaker and active-probe tuning for `mirrors` (see below). |
| `settings` | Free-form `string → string` map of ecosystem-specific tuning (see below). |

### Health-aware failover and multi-mirror routing

When an upstream declares one or more `mirrors`, the proxy fronts the primary
`url` and the mirrors as an ordered pool. Each pull is tried against the
highest-priority healthy endpoint and **fails over** to the next on a transport
error or a retryable status (`5xx`, `429`). A non-retryable answer (including a
`404`/`401`) is returned as-is — the mirror responded, so there is no failover.

Each endpoint carries an independent **circuit breaker** (`closed` → `open` →
`half-open`): repeated failures take a mirror out of rotation, and after a
cooldown a limited number of trial requests probe its recovery. Health is tracked
passively from real request outcomes and, optionally, from lightweight active
probes. A circuit-open event fires the `upstream_circuit_open` notification.

Auth-passthrough and every security gate are preserved regardless of which mirror
served the bytes: because content is verified against its digest as it streams,
**cache integrity is identical across mirrors** — a mirror serving different bytes
for the same digest fails verification exactly as the primary would.

| `mirrors[]` field | Description |
|-------------------|-------------|
| `id` | Stable label for metrics/admin (defaults to the URL host). |
| `url` | Mirror base URL. |
| `credentials.*` | Optional per-mirror credentials (override the upstream's for that mirror only). |
| `tls.*` | Optional per-mirror TLS override (else the default outbound TLS). |

| `failover` field | Default | Description |
|------------------|---------|-------------|
| `failureThreshold` | `5` | Consecutive failures that trip a mirror's breaker open. |
| `successThreshold` | `2` | Consecutive half-open successes that close it. |
| `openTimeout` | `30s` | How long a tripped breaker stays open before a trial probe. |
| `halfOpenMaxProbes` | `1` | Concurrent trial requests admitted while half-open. |
| `probe.enabled` | `false` | Enable background active health probing. |
| `probe.interval` | `15s` | Time between probe sweeps. |
| `probe.timeout` | `5s` | Per-probe timeout. |
| `probe.path` | `/` | Path probed on each endpoint base (`/v2/` for Docker). |

Operators can inspect endpoint health and force a mirror in/out of rotation at
runtime via the admin API: `GET /admin/api/upstreams`,
`POST /admin/api/upstreams/drain`, and `POST /admin/api/upstreams/circuit`.
Per-endpoint success/failure/latency, circuit state, and failover counts are
exported as `pullthrough_upstream_*` Prometheus metrics.

**Per-type `settings` keys**

| Type | Key | Purpose |
|------|-----|---------|
| `pip` | `filesUrl` | Artifact host (default `https://files.pythonhosted.org`). |
| `pip` | `fileHosts` | Allowlist of artifact hosts the proxy will fetch. |
| `cargo` | `downloadUrl` | `.crate` download host (default `https://crates.io`). |
| `git` | `sshPrivateKeyFile` | SSH key for an SSH-transport upstream. |
| `git` | `sshKnownHostsFile` | Pins the upstream's SSH host key. |
| `git` | `sshInsecureIgnoreHostKey` | `"true"` skips the upstream host-key check (**unsafe**). |

## `git`

Global Git pull-through configuration (in addition to per-`git`-upstream settings).

| Field | Default | Description |
|-------|---------|-------------|
| `mirrorDir` | _(empty)_ | Enables mirror-mode caching (local bare mirrors). Required for the SSH gateway and for caching packs/objects. Empty = pass-through streaming. |
| `refreshInterval` | `1m` | Minimum interval between upstream mirror refreshes; within it, cached refs/objects are served. |
| `fetchTimeout` | `10m` | Bounds a single clone/fetch from upstream. |
| `infoRefsTtl` | `0` | Caches smart-HTTP ref advertisements in pass-through mode for this long. `0` disables. |
| `gitBinary` | `git` | Path to the `git` executable. |
| `ssh.hostKeyFile` | _(ephemeral)_ | PEM server host key. **Set in production** for a stable fingerprint. |
| `ssh.authorizedKeysFile` | _(empty)_ | OpenSSH `authorized_keys` of permitted clients. |
| `ssh.authorizedKeys` | `[]` | Inline list of OpenSSH client public keys. |
| `ssh.noClientAuth` | `false` | Disable client auth (trusted networks only; still read-only). |

## `scanning`

LLM-based Git commit scanning. See
[security-model.md](security-model.md#scanning-llm-commit-analysis).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `provider` | `claude` | `claude` \| `openai` \| `codex` \| `none`. `codex` is an alias for `openai`. |
| `model` | — | Provider model id (superseded by `commit.triageModel`/`commit.deepModel` for commit scanning). |
| `apiKey` | — | Provider API key (`${ENV}`/`enc:v1:`). Falls back to `ANTHROPIC_API_KEY` for Claude, `OPENAI_API_KEY` for OpenAI. |
| `baseUrl` | _(empty)_ | Override the provider API endpoint (e.g. a gateway). For OpenAI, an absolute http(s) root to which `/chat/completions` is appended; also points at Azure OpenAI or any OpenAI-compatible gateway (vLLM, LiteLLM, ...). |
| `apiVersion` | _(empty)_ | **OpenAI only.** Selects Azure OpenAI mode: sent as the `api-version` query parameter, and the key is sent via the `api-key` header instead of `Authorization: Bearer`. |
| `reasoningEffort` | _(empty)_ | **OpenAI only.** `minimal`\|`low`\|`medium`\|`high`. Forwarded as `reasoning_effort` on the deep (escalated) pass for OpenAI reasoning models; omitted for plain chat models. |
| `timeout` | _(impl default)_ | **OpenAI only.** Per-attempt HTTP timeout (Go duration). `0` uses the provider default (60s). |
| `failOn` | `high` | Minimum severity that marks a commit as not passing: `info`\|`low`\|`medium`\|`high`\|`critical`. |
| `commit.triageModel` | `claude-haiku-4-5-20251001` (Claude) / `gpt-4o-mini` (OpenAI) | Cheap model that triages every commit. |
| `commit.deepModel` | `claude-opus-4-8` (Claude) / `gpt-4o` (OpenAI) | Capable model used when triage escalates. |
| `commit.escalateAtScore` | `25` | Triage risk score (0–100) at/above which deep analysis runs. `0` always escalates; `>100` never. |
| `commit.maxDiffTokens` | _(impl default)_ | Per-request token budget; larger diffs are chunked. |
| `commit.maxChunks` | `0` | Cap on chunks per commit (`0` = unbounded). |
| `commit.maxRetries` | _(impl default)_ | Transient-error retries per provider call. |
| `commit.workers` | _(impl default)_ | Async scan workers. |
| `commit.queueSize` | _(impl default)_ | Async submission queue bound. |
| `commit.storeDir` | _(empty)_ | Persistent verdict store. Empty = in-memory (lost on restart). |

### `scanning.secrets` (deterministic secret detection)

A fast, offline regex + Shannon-entropy pass over each commit's **added** diff
lines, running before/alongside the LLM call. Findings merge into the verdict
and raise the commit risk score, so a live credential blocks the associated
package/Docker pulls through the [`policy`](#policy) gate — even when no LLM is
configured. Enabled by default wherever `scanning.enabled` is true; set
`scanning.secrets.enabled: true` with `provider: none` to run LLM-free.
Per-rule hit counts are exported as `pullthrough_secrets_found_by_rule_total{rule=…}`.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | _(follows `scanning.enabled`)_ | Master switch for the deterministic pass. |
| `disableBuiltinRules` | `false` | Drop the built-in high-confidence ruleset (AWS/GCP/GitHub/GitLab/Slack/private-key/JWT/…). |
| `rules` | `[]` | Pluggable rules (`id`, `description`, `severity`, `pattern`, `group`, `keywords`, `minEntropy`). A matching `id` overrides a built-in. |
| `entropy.enabled` | `true` | Generic high-entropy heuristic. |
| `entropy.minLength` / `entropy.maxLength` | `20` / `100` | Candidate token length bounds. |
| `entropy.base64Entropy` / `entropy.hexEntropy` | `4.5` / `3.5` | Bits/char thresholds (hex requires a secret-named key). |
| `entropy.severity` | `medium` | Severity for entropy findings. |
| `allowlist.disableBuiltins` | `false` | Built-ins exempt `testdata/`/fixtures and `EXAMPLE`/placeholder keys. |
| `allowlist.paths` / `allowlist.patterns` | `[]` | Regexes exempting file paths / matched secrets. |
| `allowlist.stopWords` | `[]` | Case-insensitive substrings that exempt a line. |
| `allowlist.fingerprints` | `[]` | Baseline of accepted finding fingerprints to suppress. |
| `revealPrefix` | `4` | Leading chars kept when redacting a finding (0–8). |
| `maxFindingsPerFile` | `100` | Cap on findings per file. |

## `provenance`

Package-to-commit association. See
[security-model.md](security-model.md#provenance-package--commit).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `requireAttested` | `false` | Reject artifacts lacking verified provenance (a coarse gate; finer control via `policy`). |
| `githubToken` | — | Raises GitHub API limits and reaches private repos (`${ENV}`/`enc:v1:`). |
| `githubApiBase` | _(public)_ | GitHub Enterprise API base, e.g. `https://github.example.com/api/v3`. |
| `storeDir` | _(empty)_ | Persist resolved package→commit links. |
| `trustRootsFile` | _(empty)_ | PEM trust anchor for attestation signing certs. With it set, signatures that chain to it are `attested`; otherwise verified signatures are downgraded to `claimed`. |
| `useSystemTrustRoots` | `false` | When no `trustRootsFile`, trust the system CA pool. |
| `pins` | `[]` | Operator-asserted package → commit associations for packages no attestation or metadata covers: `{ecosystem, name, version, repository, commit}`. Authoritative for the coordinates they match; the pinned commit's scan verdict gates the package through `policy`. `claimed` confidence — never satisfies `requireAttested`. See [security-model.md](security-model.md#operator-pins). |

## `policy`

Admission gating on scan verdicts and provenance. See
[security-model.md](security-model.md#policy-admission-gating). `default` applies
to every ecosystem; an entry under `ecosystems.<name>` **fully replaces** the
default for that ecosystem.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `failClosed` | `false` | On an assessment/lookup error: `false` = serve + warn; `true` = block. |
| `default.blockAtRiskScore` | `80` | Block when source-commit risk ≥ this (`0` disables). |
| `default.warnAtRiskScore` | `50` | Warn at ≥ this but below the block threshold (`0` disables). |
| `default.blockMalicious` | `true` | Always block commits the scanner flagged malicious. |
| `default.onMissingProvenance` | `warn` | Action when no package→commit link could be established. |
| `default.onMissingScan` | `allow` | Action when provenance exists but the commit was not scanned. |
| `default.requireSignature` | `false` | Block artifacts whose provenance signature did not verify. |
| `default.requireAttested` | `false` | Block unless fully attested (verified signature → trusted root). |
| `default.minConfidence` | _(empty)_ | `heuristic`\|`claimed`\|`attested`; below it → `onLowConfidence`. |
| `default.onLowConfidence` | `warn` | Action when confidence is below `minConfidence`. |
| `default.denylist` | `[]` | Block package-name globs, e.g. `["evil-*", "@bad/*"]`. |
| `default.allowlist` | `[]` | If non-empty, **only** these globs are admitted. |

Each check's action is `allow` \| `warn` \| `block` (empty = `allow`).

## `nameguard`

Typosquatting & dependency-confusion detection on package names at pull time. See
[security-model.md](security-model.md#name-guard-typosquatting--dependency-confusion).
Runs before any upstream fetch or cache fill; off by default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `action` | `block` | Action when a finding meets `failSeverity`: `warn` \| `block` \| `quarantine`. |
| `failSeverity` | `high` | Min finding severity that triggers `action` (`none`\|`low`\|`medium`\|`high`\|`critical`). |
| `warnSeverity` | `medium` | Min severity that triggers a warning below the fail threshold. |
| `distanceThreshold` | `2` | Max Damerau-Levenshtein distance treated as a typosquat (auto-reduced for short names). |
| `minNameLength` | `4` | Names shorter than this skip distance-based checks (limits false positives). |
| `detectHomoglyphs` | `true` | Flag non-ASCII look-alike / mixed-script characters. |
| `disableBuiltins` | `false` | Use only the lists below, ignoring the built-in popular/allow seeds. |
| `internalNamespaces.<eco>[]` | `[]` | Private names a public copy must not shadow. Entry ending `*`/`/`, or an npm `@scope`, = namespace prefix. **The key dependency-confusion knob.** |
| `popularNames.<eco>[]` | `[]` | Extra popular names to measure typosquats against (merged with built-ins). |
| `allowlist.<eco>[]` | `[]` | Legitimate names that must never be flagged. |

Ecosystem keys (`<eco>`): `pip`, `npm`, `cargo`, `nuget`, `go`.

## `malfeed`

Known-malicious-package blocking: hard-blocks pulls of concrete
`(ecosystem, name, version)` coordinates listed in curated malware datasets
(OpenSSF/OSV malicious-packages + GitHub Advisory malware). Distinct from
nameguard (heuristics) and vulnscan (CVEs). Runs before any upstream fetch. Full
treatment in [malfeed.md](malfeed.md). On by default but inert until a feed or
offline bundle supplies data.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch. |
| `sources[].url` | _(none)_ | HTTP(S) endpoint serving an OSV record or array of records. |
| `sources[].name` | _(url)_ | Provenance label for the source. |
| `refreshInterval` | `6h` | Background feed-refresh period (`0` disables the loop). |
| `staleAfter` | `24h` | Data is considered stale this long after the last success (`0` disables). |
| `failClosed` | `false` | While stale: `false` fails open (still blocks matches); `true` blocks all pulls. |
| `timeout` | `30s` | Per-feed fetch timeout. |
| `bundlePath` | `""` | Signed offline bundle imported at startup (air-gapped). |
| `bundlePublicKeyFile` | `""` | PEM Ed25519 public key the bundle signature must verify against. |

Refresh is conditional (ETag / `If-None-Match`). Build offline bundles with
`pullthrough malfeed keygen|export|import`. Supported ecosystems: `pip`, `npm`,
`cargo`, `go`, `nuget`, `maven`, `rubygems`, `composer`.

## `maturity`

Release-maturity / version-cooldown gating: quarantines newly-published package
versions until they age past a configurable cooldown window — a control against
fast-moving supply-chain attacks where a malicious version is published and yanked
within hours. The gate derives each version's publish timestamp from the upstream
registry metadata (npm `time`, PyPI `upload_time`, crates `created_at`, RubyGems
`created_at`, Maven Central `timestamp`, Go `.info` `Time`, NuGet `published`,
Composer `time`), caches it, and blocks the pull while `age < cooldown`. Runs
after nameguard/malfeed and before the policy gate. Full treatment in
[maturity.md](maturity.md). On by default but inert until a positive cooldown is
configured. Fails **open** on an undeterminable publish timestamp by default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch. |
| `defaultCooldown` | `0s` | Global cooldown; `0` admits every version (gate inert). |
| `ecosystems.<eco>` | _(none)_ | Per-ecosystem cooldown override; `0s` disables for that ecosystem. |
| `tenants.<id>.defaultCooldown` | _(inherit)_ | Per-tenant default cooldown override. |
| `tenants.<id>.ecosystems.<eco>` | _(inherit)_ | Per-tenant, per-ecosystem cooldown override. |
| `tenants.<id>.allowlist` | _(none)_ | Tenant-scoped trusted coordinates/scopes. |
| `allowlist` | _(none)_ | Trusted coordinates/scopes that bypass cooldown. |
| `failClosedOnUnknown` | `false` | Block (`true`) or admit (`false`) when the publish timestamp can't be determined. |
| `timeout` | `10s` | Per-lookup upstream metadata timeout. |
| `cacheTTL` | `6h` | How long a resolved (immutable) publish timestamp is cached. |
| `negativeCacheTTL` | `15m` | How long an unknown/failed resolution is cached before retry. |
| `cacheSize` | `4096` | Bound on the resolved-timestamp cache. |
| `userAgent` | _(built-in)_ | User-Agent sent with metadata lookups (some registries require one). |
| `baseURLs.<eco>` | _(public)_ | Per-ecosystem registry base-URL override for private mirrors. |

Cooldowns resolve by **specificity then scope**: a tenant ecosystem override, then
a global ecosystem override, then a tenant default, then the global default.
Allowlist entry forms (each optionally `eco:`-scoped): `name` (exact, any
ecosystem), `eco:name`, `@scope/` (npm scope prefix), `prefix*` (name glob). A
still-cooling block composes with the [break-glass approval workflow](approvals.md)
so an operator can release a version early; per-ecosystem `cooling`/`blocked`
metrics and an admin **Cooldown** tab (currently-cooling coordinates with
time-remaining) surface the gate's activity.

## `depfirewall`

Dependency-firewall **version-pinning & allowlist** enforcement (Task 65). Rules
keyed by `(ecosystem, name)` combine pinned exact versions, allowed semver ranges,
a minimum-version floor, and an explicit denylist; the denylist always blocks and
the positive constraints are ANDed. For an ungoverned coordinate, `defaultAction`
decides (`allow` enforces only explicit rules; `block` is deny-by-default). Tenant
rules override global rules; rules can be imported from a lockfile via the admin
UI/API. Runs **after nameguard, before** the heavier scanning gates, and composes
with the [break-glass approval workflow](approvals.md). Off by default. Full
treatment in [dependency-firewall.md](dependency-firewall.md).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch; enforces only what you configure. |
| `defaultAction` | `allow` | Disposition for an ungoverned coordinate (`allow`/`block`). |
| `rules` | _(none)_ | Global rules (see below). |
| `rules[].ecosystem` | _(req)_ | Canonical ecosystem (npm/pip/cargo/go/nuget/...). |
| `rules[].name` | _(req)_ | Package coordinate within the ecosystem. |
| `rules[].pinned` | _(none)_ | Exact-version allowlist. |
| `rules[].ranges` | _(none)_ | Allowed semver range expressions (`>=1.2 <2`, `^1.4`, `~1.2`, `1.x`). |
| `rules[].minVersion` | _(none)_ | Minimum-version floor. |
| `rules[].denied` | _(none)_ | Always-blocked exact versions. |
| `rules[].note` | _(none)_ | Operator annotation for the admin view. |
| `tenants.<id>.defaultAction` | _(inherit)_ | Per-tenant default-action override. |
| `tenants.<id>.rules` | _(none)_ | Per-tenant rules (override globals for the same coordinate). |

A malformed range is a **fatal** startup error. Per-ecosystem and per-violation
(`not-pinned`/`out-of-range`/`below-floor`/`denied`/`not-governed`) metrics plus an
admin **Firewall** tab (rule CRUD + lockfile upload) surface the gate's activity.

## `license`

License-compliance admission gating on each artifact's SPDX license. Reuses the
vulnerability subsystem's SBOM (or extracts one on demand) and runs fully offline.
See [licenses.md](licenses.md). Off by default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `action` | `block` | Action when a license is **denied**: `warn` \| `block` \| `quarantine`. |
| `reviewAction` | `warn` | Action for **review** / **unknown** licenses. |
| `driftAction` | `warn` | Action when license **drift** is detected. |
| `unknown` | `review` | Disposition for an unrecognized / `NOASSERTION` license: `allow` \| `review` \| `deny`. |
| `default` | `allow` | Disposition for a recognized license matching no list. |
| `allow[]` | `[]` | Permitted SPDX ids / globs / `@family` keywords. |
| `deny[]` | `[]` | Prohibited entries (deny wins over review wins over allow). |
| `review[]` | `[]` | Entries permitted only after manual review (flagged/warned). |
| `allowExceptions[]` | `[]` | SPDX `WITH` exception ids that rescue an otherwise-denied license. |
| `driftDetection` | `false` | Track and flag cross-version license changes. |
| `driftMaxEvents` | `256` | Recent drift events retained for the admin API. |
| `tenants.<team>` | _(none)_ | Per-tenant override: lists are unioned with the base; set scalars replace it. |

A list entry is an exact SPDX id (case-insensitive), a glob (`GPL-*`), or an
`@family` keyword (`@permissive`, `@weak-copyleft`, `@strong-copyleft`,
`@network-copyleft`, `@copyleft`, `@public-domain`, `@proprietary`, `@unknown`).

## `sigverify`

Cryptographic signature & attestation verification (cosign/Sigstore) as a
pull-path admission gate. Verifies cosign signatures and SLSA provenance
attestations for OCI images and Sigstore publish attestations for npm packages
before content is served. Full treatment in [sigverify.md](sigverify.md). Off by
default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `ecosystems[]` | `[docker]` | Which ecosystems to verify: `docker`, `npm` (pip best-effort). |
| `action` | `block` | Action when a finding meets `failSeverity`: `warn` (advisory) \| `block` \| `quarantine`. |
| `failSeverity` | `high` | Min finding severity that triggers `action`. |
| `warnSeverity` | `medium` | Min severity that triggers a warning below the fail threshold. |
| `requireSignature` | `false` | Treat an unsigned artifact as a (high-severity) finding. |
| `requireAttestation` | `false` | Additionally require a verified SLSA provenance attestation. |
| `requireRekorProof` | `false` | Keyless signatures must carry a verified Rekor inclusion proof (SET). |
| `failOnError` | `false` | Fail-open (warn) when material can't be fetched; `true` blocks (fail-closed). |
| `trustRootsFile` | `""` | PEM bundle of Fulcio root CAs for keyless chain trust. |
| `useSystemTrustRoots` | `false` | Use the host trust store when no `trustRootsFile`. |
| `rekorKeyFiles[]` | `[]` | PEM public keys of trusted Rekor transparency logs. |
| `keys[]` | `[]` | Operator public keys for keyed verification (`name` + `file`/`pem`). |
| `identities[]` | `[]` | Allowed keyless signers (`issuer` + `subjectPattern`). Empty = any chaining to the root. |
| `npmRegistryUrl` | `https://registry.npmjs.org` | npm registry whose attestations endpoint is queried. |
| `offline` | `false` | Air-gapped: load all trust material from `trustBundleFile`. |
| `trustBundleFile` | `""` | Portable trust bundle (roots, Rekor keys, keys, identities). |
| `trustBundleDigest` | `""` | Optional `sha256:<hex>` the bundle is verified against on load. |
| `cacheTtl` | `0` | How long a verification result is reused (`0` = never expire). |

## `notifications`

Event-notification & alerting subsystem (webhooks + Slack). Dispatches structured
alerts on security-relevant events to one or more sinks, asynchronously and
bounded so the request path is never blocked. Full treatment in
[notifications.md](notifications.md). Off by default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `minSeverity` | `info` | Global severity floor; events below it are never delivered (`none`\|`low`\|`medium`\|`high`\|`critical`). |
| `workers` | `2` | Async delivery workers. |
| `queueSize` | `256` | Bound on the delivery queue; when full a notification is **dropped** (counted), never blocking a pull. |
| `maxRetries` | `3` | Additional attempts after the first on a retryable (`5xx`/`429`/network) failure. |
| `retryBaseDelay` | `500ms` | Base of the exponential backoff between retries. |
| `retryMaxDelay` | `30s` | Cap on the backoff delay. |
| `timeout` | `10s` | Bound on a single delivery attempt. |
| `redactFields[]` | `[]` | Extra field-key substrings to scrub (in addition to the built-in credential set). |
| `sinks[]` | — | Delivery destinations (see below). |
| `routes[]` | — | Per-event-type / severity routing (see below). Empty = every event to every sink at `minSeverity`. |

**`sinks[]`** — `name` (unique), `kind` (`webhook`\|`slack`), `url`
(`${ENV}`/`enc:v1:` supported — treat as a secret), plus per-kind options:

| Field | Applies to | Description |
|-------|-----------|-------------|
| `headers.<k>: <v>` | `webhook` | Extra HTTP headers (e.g. an `Authorization` or HMAC-signature header). |
| `channel` / `username` / `iconEmoji` | `slack` | Optional Slack display overrides. |
| `insecureSkipVerify` | both | Disable TLS verification of the endpoint (test only). |

**`routes[]`** — `sinks[]` (sink names), `eventTypes[]` (empty = all), and
`minSeverity`. Routable event types: `policy_block`, `vulnerability`,
`commit_scan`, `provenance_failure`, `quarantine`, `rescan_regression`.

Admin endpoints: `GET <admin>/api/notify` (status + per-sink metrics) and
`POST <admin>/api/notify/test[?sink=<name>]` (send a synchronous test
notification). Metrics: `pullthrough_notifications_{sent,failed,dropped,retries}_total{sink}`
and `pullthrough_notifications_queue_depth`.

## `secrets`

Master key for `enc:v1:` decryption. Resolution order: `keyEnv` → `keyFile` →
`passphrase`+`salt`. When none is set, encryption is disabled and any `enc:v1:`
value is a hard error.

| Field | Description |
|-------|-------------|
| `keyEnv` | Env var holding a 32-byte key (hex or base64). |
| `keyFile` | File holding the key. |
| `passphrase` / `salt` | scrypt-stretched passphrase (dev only). |

### `secrets.vault`

Enables the HashiCorp Vault provider for `vault://PATH#KEY` references (see
[Value substitution](#value-substitution)). The `env://` and `file://` providers
are always available and need no configuration.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Register the Vault provider. When off, a `vault://` reference anywhere is a load-time error. |
| `address` | — | Vault API base URL (**required** when enabled), e.g. `https://vault.internal:8200`. |
| `namespace` | — | Vault Enterprise namespace. |
| `kvMount` | `secret` | KV v2 secrets-engine mount path. |
| `authMethod` | `token` | `token` or `approle`. |
| `token` | — | Vault token for `token` auth (`${ENV}`/`enc:v1:`). |
| `roleId` / `secretId` | — | AppRole login credentials for `approle` auth (`${ENV}`/`enc:v1:`). |
| `approleMount` | `approle` | AppRole auth mount path. |
| `refreshInterval` | `1m` | Lease-renewal / cached-secret re-read cadence (clamped to ≥ 10s). |
| `requestTimeout` | `10s` | Per-request timeout for Vault API calls. |
| `caCertFile` | — | PEM bundle trusted for the Vault TLS connection. |
| `tlsSkipVerify` | `false` | Disable Vault TLS verification (test/bootstrap only). |

## `auth`

Authentication, RBAC, multi-tenancy, quotas. Full treatment in
[access-control-and-audit.md](access-control-and-audit.md).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | When false, all requests are served anonymously. |
| `allowAnonymous` | `false` | Permit unauthenticated requests (bounded by anonymous role/team). |
| `anonymousTeam` | `public` | Team assigned to anonymous requests. |
| `anonymousRoles` | `[]` | Roles granted to anonymous requests. |
| `cacheNamespacing` | `false` | Partition cached content per team (trades dedup for isolation). |
| `roles[]` | — | `name`, `ecosystems[]`, `upstreams[]`. A pull is allowed iff a held role lists the ecosystem (or `*`) **and** the upstream (or `*`). |
| `tokens[]` | — | Static API tokens: `name`, `team`, `roles[]`, and exactly one of `token` or `tokenHash` (`sha256:<hex>`). |
| `defaultQuota` / `teams.<team>.quota` | — | `maxRequests`, `maxBytes`, `window` (`0` window = hard cumulative cap; `0` limit = unlimited on that axis). |
| `oidc.*` | disabled | OIDC/JWT bearer auth (`issuer`, `audience`, `jwksUrl`/`jwks`, `subjectClaim`, `teamClaim`, `rolesClaim`, `roleMap`, `jwksCacheTtl`, `leeway`). `alg=none`/HMAC rejected. |

## `clientAuth.mtls`

SPIFFE/SVID mutual-TLS workload identity (Task 58). When enabled, a verified
client-certificate SPIFFE ID is mapped to a tenant + roles and flows through the
same RBAC, quota, rate-limit, and audit machinery as a token identity. Composes
with `auth` (either-or) or can be made mandatory. Full treatment in
[spiffe-mtls.md](spiffe-mtls.md). Requires `auth.enabled` and gateway TLS
(`server.tlsCertFile`/`server.tlsKeyFile`).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Turn on the mTLS workload-identity authenticator. |
| `required` | `false` | `true` demands a client cert at the TLS handshake (token/OIDC no longer suffice); `false` requests one opportunistically (either-or). |
| `trustBundle` | — | Path to the SPIFFE CA trust bundle (PEM or SPIFFE Trust Bundle JSON). Read from disk; offline-friendly. |
| `trustBundleFormat` | `auto` | `auto` (sniff), `pem`, or `spiffe`. |
| `trustDomain` | — | Default trust domain for PEM / single-domain JSON bundles. |
| `allowedTrustDomains[]` | `[]` | Restrict accepted domains even if present in the bundle. |
| `reloadInterval` | `0` | Poll the bundle file and hot-reload on change (`0` = on restart only). |
| `expiryWarning` | `720h` | Window for the "certificate expiring soon" gauge. |
| `defaultTenant` | — | Tenant for a matched ID whose rule names none. |
| `rules[]` | — | Ordered `pattern` (glob or `re:<regexp>`) → `tenant` + `roles[]`. First match wins; roles must be defined under `auth.roles`. |
| `tenantOverrides.<tenant>[]` | — | Override rules consulted after a global rule selects that tenant; first match replaces the role set. |

Metrics: `pullthrough_clientauth_mtls_success_total{method}`,
`pullthrough_clientauth_mtls_failure_total{reason}`,
`pullthrough_clientauth_cert_expiry_seconds`,
`pullthrough_clientauth_certs_expiring_soon`,
`pullthrough_clientauth_trust_bundle_reloads_total`, and
`pullthrough_clientauth_trust_bundle_expiry_seconds`.

## `rateLimit`

Per-tenant and global request-rate, upstream-concurrency, and byte-quota
enforcement (Task 24). The limiter runs as a middleware in the reverse-proxy core
**inside** the access-control envelope, so the tenant is the authenticated
principal's team; `auth.teams.<team>.rateLimit` overrides `rateLimit.default`.
Every request must satisfy **both** the global policy and its tenant policy.
Throttled requests receive `429 Too Many Requests` with a `Retry-After` header
and an `X-RateLimit-Limit: rps|concurrency|bytes` marker.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch; when false the middleware is not installed. |
| `shared` | `false` | Coordinate byte quotas across replicas via the shared object store (requires `cache.backend: s3`). RPS/burst and concurrency are always per replica. |
| `global.*` | — | Process-wide ceiling applied to every request. |
| `default.*` | — | Policy for tenants without an explicit override. |

Each policy (`global`, `default`, and `auth.teams.<team>.rateLimit`) has: `rps`
(sustained requests/sec), `burst` (token-bucket capacity; `0` derives from
`rps`), `maxConcurrent` (simultaneous in-flight pulls), `byteQuota` (bytes per
`window`), and `window` (byte-quota period; `0` ⇒ 30 days when `byteQuota > 0`).
A `0` dimension is unlimited.

Limits are viewable and tunable at runtime via the admin API:
`GET <adminPathPrefix>/api/ratelimit` returns the live policy/usage snapshot;
`PUT <adminPathPrefix>/api/ratelimit/policy` (body `{"tenant":"…","policy":{…}}`
or `{"global":true,"policy":{…}}`) replaces a policy without a restart, preserving
live bucket/concurrency state. Metrics: `pullthrough_ratelimit_allowed_total`,
`pullthrough_ratelimit_throttled_total`,
`pullthrough_ratelimit_throttled_by_reason_total{reason}`,
`pullthrough_ratelimit_concurrent_inflight{tenant}`, and
`pullthrough_ratelimit_bytes_used{tenant}`.

## `coalesce`

Pull-path request coalescing (singleflight) and bounded negative caching
(Task 36). N concurrent cache-miss requests for the same artifact collapse onto a
single upstream fetch (every caller is then served its own stream from the
freshly-filled cache), and terminal upstream failures are remembered briefly so a
burst of requests for a missing artifact does not repeatedly hit the upstream. The
coalesce/negative-cache key is always partitioned by the caller's tenant, so a
private artifact — or a negative result such as a `403` — is never shared across
tenants. A pure performance/resilience layer, enabled by default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch. When off, each miss fetches independently. |
| `negativeTtl` | `30s` | How long an upstream `404`/`410`/auth failure is remembered. |
| `maxNegativeEntries` | `4096` | LRU bound on the negative cache (`0` ⇒ default). |
| `maxInflight` | `0` | Cap on distinct in-flight upstream fetches; over the cap a new fetch is shed with `503` (callers joining an existing fetch are never shed). `0` ⇒ unbounded. |
| `backoff5xxBase` / `backoff5xxMax` | `1s` / `5s` | Jittered backoff window applied to transient (`5xx`/`429`/network) negative entries. |

Inspect at runtime: `GET <adminPathPrefix>/api/coalesce` returns the dedup ratio,
in-flight count, and negative-cache hit/eviction/entry counts (with a per-
failure-class breakdown); `DELETE <adminPathPrefix>/api/coalesce/negative` flushes
the negative cache. Metrics: `pullthrough_coalesce_hits_total`,
`pullthrough_coalesce_leads_total`, `pullthrough_coalesce_dedup_ratio`,
`pullthrough_coalesce_inflight`, `pullthrough_coalesce_overloaded_total`,
`pullthrough_negative_cache_hits_total`,
`pullthrough_negative_cache_evictions_total`,
`pullthrough_negative_cache_entries`, and
`pullthrough_negative_cache_hits_by_kind_total{kind}`.

## `findings`

Unified SARIF findings-aggregation layer (Task 42). It normalizes every
admission gate's verdict (vulnscan/OSV, VEX, license, secretscan, sigverify,
nameguard/typosquatting, riskscore, policyengine, provenance) into one canonical
model, retains the most recent findings per artifact, and exports SARIF 2.1.0 so
a CI pipeline can decorate pull requests and fail builds natively. A passive
observability layer — it never affects admission — enabled by default.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch. When off, nothing is retained and the SARIF endpoint reports the surface absent (the CLI's file-input mode still works). |
| `maxEntries` | `2048` | Bound on retained per-artifact findings documents (oldest-evicted). Non-positive ⇒ default. |

Export: `GET <adminPathPrefix>/api/findings/sarif?tenant=&package=` returns SARIF
2.1.0 for one artifact (or, with no `package`, a batch over the tenant);
`GET <adminPathPrefix>/api/findings` returns the canonical model. Offline, the
`pullthrough findings sarif` CLI subcommand renders SARIF from a batch of
admission-input documents. See [findings.md](findings.md).

## `simReplay`

Policy & risk what-if simulation/replay harness (Task 47). When enabled, the
proxy captures a sampled, redacted ring buffer of recent admission inputs along
with the verdict each produced live, so an operator can replay that traffic
through a candidate policy/risk configuration **before** rolling it out and see
exactly which pulls would flip admit↔block, which risk bands shift, what new
policy violations appear, and the per-tenant blast radius. Capture is passive —
it never affects admission.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch for live capture and the admin endpoint. When off, nothing is captured and the admin surface reports itself absent (the `simulate` CLI still works against an exported capture file). |
| `capacity` | `1024` | Ring-buffer size; the oldest record is evicted once full. Non-positive ⇒ default. |
| `sampleRate` | `1` | Capture one in every N observed pulls (deterministic, counter-based). `1` captures every pull. |
| `redact` | `true` | Strip sensitive leaf fields (secret file paths, signer identity/issuer, source repo URL/commit) from each captured input. Redaction preserves the scalar signals the engines score on, so a redacted record still replays to the same verdict. |

Replay: `POST <adminPathPrefix>/api/simreplay/simulate` with a candidate config
(YAML/JSON) returns the diff report (`?format=markdown` for Markdown);
`GET <adminPathPrefix>/api/simreplay` reports recorder status;
`GET <adminPathPrefix>/api/simreplay/capture` exports the buffer for offline use.
The `pullthrough simulate` CLI replays an exported capture file against a
candidate config with no running proxy. See [simreplay.md](simreplay.md).

## `coordination`

Distributed coordination & leader election for HA, multi-replica deployments
(Task 56). When enabled, each shared-state scheduled job (CVE-drift re-scan,
backup scheduler, audit Merkle checkpoint signing) runs on only the lease-holding
replica. **Disabled by default** — a single replica needs no coordination.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch for lease-based leader election. Leave off for a single replica. |
| `mode` | `memory` | Lease backend: `memory` (in-process; single replica only), `s3` (shared object store; inherits `cache.s3` for unset fields), `file` (shared POSIX volume). |
| `nodeId` | `<hostname>-<pid>` | This replica's identity in lease records. In Kubernetes set it to the pod name via the downward API. |
| `leaseTtl` | `30s` | Lease validity without a heartbeat before another replica may take over. |
| `renewInterval` | `10s` | Leader heartbeat period. Must be below `leaseTtl` (validated). |
| `retryInterval` | `10s` | Follower re-acquisition attempt period. |
| `jobTtls` | — | Optional per-job `leaseTtl` overrides (`backup`, `cve-drift-rescan`, `audit-checkpoint`). |
| `s3` | inherits `cache.s3` | Object-store connection for the `s3` backend; any unset field falls back to `cache.s3`. `prefix` defaults to `coord/leases/`. |
| `dir` | — | Shared lease directory for the `file` backend (required for `mode: file`). |

Leaseholders across the cluster are visible at
`GET <adminPathPrefix>/api/coordination`; per-job leadership and lease counters
are exported as `pullthrough_coordination_*` metrics. See
[coordination.md](coordination.md).

## `cacheGc`

Cache lifecycle manager (Task 39): a background sweep that keeps the
content-addressable cache (local or S3-backed) bounded. It is enabled by default
and degrades to a no-op when the cache backend cannot be inspected (e.g. the
in-memory dev cache).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch. When off, on-demand admin runs still work. |
| `interval` | `1h` | Period between automatic sweeps; `0` = on-demand only. |
| `capacityBytes` | `0` | Capacity for watermark math; `0` falls back to `cache.maxSizeBytes`. |
| `highWatermarkPct` | `0.9` | Evict when utilization rises above this fraction of capacity. |
| `lowWatermarkPct` | `0.7` | Evict down to this fraction. Must be below the high watermark. |
| `policy` | `lru` | Eviction order under size pressure: `lru`, `lfu`, or `fifo`. |
| `defaultTtl` | `0` | Max entry age before TTL eviction; `0` falls back to `cache.ttl`. |
| `tenantTtls` | — | Per-tenant TTL overrides (an explicit `0` disables TTL for that tenant). |
| `minIdle` | `1m` | Protects entries accessed within this window (so an actively-streamed artifact is never evicted mid-read). |
| `maxDeletesPerRun` | `0` | Cap on evictions per sweep; `0` = unlimited. |
| `allowEvictPinned` | `false` | Permit evicting metadata-pinned entries. |
| `dryRun` | `false` | Periodic sweeps report only (delete nothing). |

Retention safety: entries that are pinned (metadata `pin` truthy — e.g. set on
signed-and-attested artifacts), quarantined for evidence, referenced by an active
hold, or mid-fetch are never evicted (unless `allowEvictPinned` for the pin case).
Deletion is idempotent and tolerates a peer replica having already removed an
entry, so it is safe for the HA shared store.

Inspect at runtime: `GET <adminPathPrefix>/api/cachegc` returns the utilization
snapshot (used vs high/low watermark, bytes reclaimed, eviction counts) and the
last run report; `POST <adminPathPrefix>/api/cachegc/run` triggers a sweep —
defaulting to a safe dry-run preview, with `?dryRun=false` to evict. A sweep that
cannot drop below the high watermark emits a `cache_gc` notification. See the
metric list in [observability.md](observability.md#cache-lifecycle--garbage-collection-task-39).

## `audit`

Tamper-evident keyed hash chain. See
[access-control-and-audit.md](access-control-and-audit.md#tamper-evident-audit-log).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `file` | — | Audit log path. Empty = in-memory (dev only). |
| `hmacKey` | — | HMAC key (`${ENV}`/`enc:v1:`), or set `hmacKeyEnv`. |
| `hmacKeyEnv` | — | Env var holding the HMAC key. |

## `observability`

| Field | Default | Description |
|-------|---------|-------------|
| `metrics` | `true` | Expose Prometheus metrics. |
| `metricsPath` | `/metrics` | Scrape path. |
| `admin` | `true` | Expose the admin REST API + dashboard. |
| `adminPathPrefix` | `/admin` | Dashboard served at `<prefix>/`, API under `<prefix>/api/`. |
| `adminToken` | _(empty)_ | Bearer token guarding the admin API (`${ENV}`). Empty = unauthenticated (trusted networks only). |

Health/readiness probes (`/healthz`, `/readyz`) are always served, regardless of
this block.

## `tracing`

OpenTelemetry distributed tracing (Task 41). Disabled by default; active only
when `enabled: true` **and** `endpoint` is set. Full guide: [tracing.md](tracing.md).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `endpoint` | _(empty)_ | OTLP collector URL (`${ENV}`). Base URL → `/v1/traces` appended; scheme-less → `http://`/`https://` per `insecure`. |
| `insecure` | `false` | Use `http://` for a scheme-less endpoint. |
| `tlsSkipVerify` | `false` | Skip server-cert verification over HTTPS (dev only). |
| `serviceName` | `pullthrough` | `service.name` resource attribute. |
| `serviceVersion` / `environment` | _(build version)_ / _(empty)_ | `service.version` / `deployment.environment`. |
| `samplerRatio` | `1.0` | Head-sampling probability (0..1) for locally-rooted traces; a remote parent's decision is always honored. |
| `resourceAttributes` | _(none)_ | Extra OTLP resource attributes (map). |
| `headers` | _(none)_ | Headers on every export request, e.g. an ingest token (`${ENV}`). |
| `timeout` / `batchTimeout` | `10s` / `5s` | Per-export request timeout / max delay before a non-full batch flushes. |
| `maxQueueSize` / `maxBatchSize` | `2048` / `512` | Span queue bound (over-full spans are dropped, not blocking) / spans per export. |

---

## Environment overrides

These environment variables override the corresponding config fields at load
time (handy for containers and 12-factor deploys):

| Env var | Overrides |
|---------|-----------|
| `PTS_HTTP_ADDR` | `server.httpAddr` |
| `PTS_SSH_ADDR` | `server.sshAddr` |
| `PTS_LOG_LEVEL` | `logging.level` |
| `PTS_LOG_FORMAT` | `logging.format` |
| `PTS_CACHE_BACKEND` | `cache.backend` |
| `PTS_CACHE_DIR` | `cache.dir` |
| `PTS_CACHE_S3_ENDPOINT` | `cache.s3.endpoint` |
| `PTS_CACHE_S3_REGION` | `cache.s3.region` |
| `PTS_CACHE_S3_BUCKET` | `cache.s3.bucket` |
| `PTS_CACHE_S3_PREFIX` | `cache.s3.prefix` |
| `PTS_CACHE_S3_ACCESS_KEY_ID` | `cache.s3.accessKeyId` |
| `PTS_CACHE_S3_SECRET_ACCESS_KEY` | `cache.s3.secretAccessKey` |
| `PTS_CACHE_S3_SESSION_TOKEN` | `cache.s3.sessionToken` |
| `PTS_SCAN_ENABLED` | `scanning.enabled` (parsed as bool) |
| `PTS_SCAN_API_KEY` | `scanning.apiKey` |
| `PTS_ADMIN_TOKEN` | `observability.adminToken` |
| `PTS_TRACING_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` | `tracing.endpoint` (also auto-enables tracing) |
| `PTS_TRACING_ENABLED` | `tracing.enabled` (bool) |
| `PTS_TRACING_INSECURE` | `tracing.insecure` (bool) |
| `PTS_TRACING_SAMPLER_RATIO` | `tracing.samplerRatio` (float) |
| `OTEL_SERVICE_NAME` | `tracing.serviceName` |

Beyond these, any `${VAR}` referenced inside the YAML is resolved from the
environment, and `secrets.keyEnv` / `audit.hmacKeyEnv` name the env vars holding
their respective keys.

## Validation

Config is validated at startup; the process exits non-zero with a descriptive
error on problems such as an empty `server.httpAddr`, a `filesystem` cache with no
`cache.dir`, an unknown `cache.backend`, an unknown upstream `type`, or an invalid
`outbound.tls.minVersion`. Validate a config without serving traffic by starting
the binary against it in a throwaway environment and checking the exit code.
