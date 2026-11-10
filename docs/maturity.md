# Release-maturity / version-cooldown gate

The maturity gate (`internal/maturity`) quarantines **newly-published package
versions** until they age past a configurable cooldown window. It is a well-known
control against fast-moving supply-chain attacks: an attacker who compromises a
maintainer account (or registers a confusable name) typically publishes a
malicious version and relies on CI pulling it within minutes — before the
registry, the maintainer, or defenders notice and yank it. Holding every version
for, say, 72 hours collapses that attack window: by the time a held version is
served, a malicious release has usually already been pulled and an advisory filed.

## How it works

The gate runs on the pull path **after** nameguard and malfeed and **before** the
policy gate — a confirmed look-alike or known-malicious coordinate should be
refused outright, not merely held — and before any upstream fetch or cache fill.

For each concrete `(ecosystem, name, version)` it:

1. Resolves the applicable cooldown for the request's `(tenant, ecosystem)`.
2. Skips index/listing requests (no single version to age) and allowlisted
   coordinates.
3. Derives the version's **publish timestamp** from the upstream registry
   metadata (cached), and computes `age = now - publishedAt`.
4. If `age < cooldown`, the pull is **held** with an actionable `403` describing
   how long the version has been published, the cooldown window, and when it will
   be released (also surfaced as a `Retry-After` header).
5. A held block first consults the [break-glass approval workflow](approvals.md):
   an operator can grant a time-boxed exception to release a still-cooling
   version.

When the publish timestamp **cannot be determined** (unsupported ecosystem,
registry error, or a registry that exposes no timestamp) the gate **fails open**
by default — admitting the pull rather than penalizing an undatable package — or
fails closed if `failClosedOnUnknown` is set.

### Publish-timestamp sources

| Ecosystem | Source endpoint | Field |
|-----------|-----------------|-------|
| `npm` | `registry.npmjs.org/<name>` | `time[<version>]` |
| `pip` | `pypi.org/pypi/<name>/<version>/json` | earliest `urls[].upload_time_iso_8601` |
| `cargo` | `crates.io/api/v1/crates/<name>/<version>` | `version.created_at` |
| `go` | `proxy.golang.org/<module>/@v/<version>.info` | `Time` |
| `nuget` | `api.nuget.org` registration leaf | `catalogEntry.published` |
| `rubygems` | `rubygems.org/api/v1/versions/<name>.json` | matching `created_at` |
| `composer` | `repo.packagist.org/p2/<vendor>/<pkg>.json` | matching `time` |
| `maven` | `search.maven.org/solrsearch` (`g`/`a`/`v`) | `timestamp` (epoch ms) |

Resolved timestamps are immutable and cached for `cacheTTL` (default 6h);
unknown/failed resolutions are cached for the shorter `negativeCacheTTL` (default
15m) so the gate retries without hammering the upstream. Override `baseURLs.<eco>`
to point a private mirror at the gate.

## Configuration

See the [`maturity` configuration reference](configuration.md#maturity) for the
full field table. A minimal policy:

```yaml
maturity:
  enabled: true
  defaultCooldown: 72h          # hold every version for 3 days
  ecosystems:
    go: 0s                      # exempt Go modules (immutable, append-only proxy)
    pip: 96h                    # a longer window for a higher-risk ecosystem
  allowlist:
    - "@my-org/"                # trust our own npm scope
    - "go:golang.org/x/*"       # trust the Go sub-repositories
  failClosedOnUnknown: false
  tenants:
    release-eng:
      defaultCooldown: 24h      # a trusted team gets a shorter window
```

**Cooldown precedence** (most specific first): tenant ecosystem override → global
ecosystem override → tenant default → global default. A per-ecosystem entry of
`0s` explicitly disables the cooldown for that ecosystem.

**Allowlist forms** (each optionally `eco:`-scoped): `name` (exact, any
ecosystem), `eco:name`, `@scope/` (npm scope prefix → matches `@scope/*`),
`prefix*` (name glob).

## Releasing a still-cooling version

When a team legitimately needs a version still inside its cooldown window, an
operator grants a [break-glass](approvals.md) exception scoped to the exact
`(tenant, ecosystem, coordinate)`. The gate then serves the version and records
the override in the tamper-evident audit log; the grant auto-expires.

## Observability

- **Metrics** (`pullthrough_maturity_*`): `checks_total`, `cooling_total`
  (blocks), `allowlisted_total`, `unknown_total`, the `cooling_current` gauge, and
  per-ecosystem labeled `checks_by_ecosystem_total`, `blocks_by_ecosystem_total`,
  and `cooling_by_ecosystem`.
- **Notifications**: `EventMaturity` (medium severity for a too-new hold, low for
  a fail-closed unknown-timestamp hold) flows to the configured webhook/Slack
  sinks.
- **Admin**: the **Cooldown** tab (`GET /admin/api/maturity`) shows the effective
  configuration, cumulative tallies, and every coordinate currently cooling with
  its time-remaining.

## Failure modes

- **Unknown timestamp** → fail open (default) or closed (`failClosedOnUnknown`).
- **Registry latency** → bounded by `timeout`; a timeout is treated as unknown.
- **Clock skew / future-dated release** → treated as freshly published (age 0),
  the safer reading.
