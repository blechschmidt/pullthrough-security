# Reproducible-build verification

The strongest supply-chain guarantee is not "the artifact is signed" or "the
artifact maps to a commit" — it is **"the artifact provably *derives* from that
commit"**. The reproducible-build verification gate (`internal/rebuildverify`,
Task 68) closes that gap: for a package coordinate the proxy has already mapped
to a source Git commit (via the [provenance](architecture.md) subsystem, Task 8,
plus reposcore/provgraph), it **rebuilds the artifact from that source commit**
inside a pluggable, sandboxed builder and compares the rebuilt artifact's
byte/normalized digest against the upstream-served artifact.

The result is a four-value **verdict** that feeds the policy-as-code engine and
the unified risk score, surfaces as a SARIF finding and a notification, and — in
the optional enforce mode — can quarantine an artifact whose served binary does
not derive from its attested source.

| Verdict | Meaning |
| --- | --- |
| `reproducible` | The rebuilt digest matched the upstream-served artifact. The binary provably derives from the attested source commit. |
| `mismatch` | The rebuilt digest did **not** match. The served binary does not derive from the attested source — a strong supply-chain-tampering / build-injection indicator. |
| `unsupported` | Verification could not run: no builder for the ecosystem, the build toolchain is unavailable (air-gapped), or the source repository could not be located offline. The gate **fails open**. |
| `unattested` | The artifact has no source-commit provenance association to rebuild from. There is nothing to verify against. |

## How it runs

The gate runs **right after the signature/attestation gate** (both establish
authenticity/integrity) and **before** the aggregating policy/risk gates, so its
verdict feeds them.

Verification is **asynchronous and non-blocking by default**. Rebuilds are
expensive, so the first pull of an artifact *schedules* a bounded background
rebuild and serves the artifact immediately; the verdict is cached per
`(coordinate, digest)` so a subsequent pull observes it (and feeds it to the
policy/risk engines and the SARIF findings layer). In the optional **enforce**
mode a *confirmed* mismatch (a cached terminal `mismatch`) is refused with a
`403`, the artifact is evicted from the cache, and the
[break-glass](approvals.md) workflow is consulted first so an operator can grant
a time-boxed exception.

The pipeline for a single verification:

1. **Resolve the source commit.** Prefer the provenance signal earlier gates
   already recorded for the request; otherwise resolve directly via the
   provenance resolver (which caches). No commit → `unattested`.
2. **Select a builder** for the ecosystem. None → `unsupported`.
3. **Locate the source repository** via an air-gap-aware mirror clone (the same
   mechanism as [repo-health scoring](reposcore.md)). Not available offline →
   `unsupported` (fail-open).
4. **Rebuild** via the builder, inside its sandbox.
5. **Compare** the rebuilt digest against the upstream digest after digest
   normalization → `reproducible` or `mismatch`.

## Builders

The actual rebuild is delegated to a pluggable, sandboxed **`Builder`**:

```go
type Builder interface {
    Name() string
    Supports(ecosystem string) bool
    Build(ctx context.Context, bc BuildContext) (BuildOutput, error)
}
```

Builders **must be offline/air-gap aware**: when the toolchain or source is
unavailable they return `ErrToolchainUnavailable` / `ErrUnsupported` (mapped to
the `unsupported` verdict) rather than failing the verification — a builder that
cannot run must never produce a false `mismatch`. They are bounded by a
concurrency cap (`maxConcurrent`) and an optional rate limiter, and every result
is cached per `(coordinate, digest)`.

The subsystem ships **toolchain-gated stub builders** for the ecosystems with
reproducible toolchains — Go modules, npm packages (with install scripts
disabled), Python sdists/wheels, and container images via buildkit. Each detects
whether its toolchain is present and **degrades gracefully** (`unsupported`)
otherwise, so the subsystem is fully wired and air-gap aware out of the box. A
production operator embeds a real sandboxed builder (network-isolated, pinned
toolchain) via `Config.Registry` **without changing any wiring**. Stub builders
for unsupported ecosystems make "unsupported" an explicit, observable verdict
rather than a silent gap.

## Configuration

```yaml
rebuildVerify:
  enabled: true            # default; on but observe-only
  mode: observe            # observe | enforce (enforce quarantines a confirmed mismatch)
  async: true              # rebuild off the request path (non-blocking)
  maxConcurrent: 2         # in-flight background rebuilds
  buildTimeout: 10m        # bound on a single rebuild
  cacheSize: 4096          # per-(coordinate,digest) result cache
  recentSize: 100          # recent results shown in the admin tab
  # Source-repository locator (reuses the air-gap-aware mirror mechanism):
  repoCacheDir: ""         # defaults to <cache.dir>/rebuildverify
  gitBinary: git
  allowFetch: false        # false = strict air-gapped (serve only pre-mirrored clones)
  cloneDepth: 0
  fetchTimeout: 60s
  tenants:                 # per-tenant mode overrides
    payments:
      mode: enforce
```

It is **on by default but observe-only** (`mode: observe`): it records and
surfaces verdicts and feeds the policy/risk engines without ever blocking a pull
until an operator raises the mode to `enforce`. It defaults to **strict
air-gapped** (`allowFetch: false`): only repositories already mirrored locally
are rebuilt; everything else is `unsupported`.

## How the verdict is consumed

- **Policy-as-code** ([policyengine](architecture.md)) sees `input.rebuildVerify`
  with `verdict`, `reproducible`, `mismatch`, `commitSha`, `builder`,
  `upstreamDigest`, and `rebuiltDigest`. A rule can deny a `mismatch`:

  ```
  input.rebuildVerify.mismatch
  ```

- **Risk score** ([riskscore](architecture.md)) folds the verdict into the
  composite score: `mismatch` is near-maximal (0.95), `unattested` is a mild
  risk (0.25), `reproducible` is zero, and `unsupported` is *not applicable*
  (excluded from the weighted average, so an air-gapped deployment that cannot
  rebuild does not inflate every score). Default weight `0.10`.

- **SARIF findings** ([findings](findings.md)) emit a
  `rebuildverify/reproducibility-mismatch` rule (SARIF `error`) for a confirmed
  mismatch, keyed to the source commit, so CI can fail a build or annotate the
  PR.

- **Notifications** ([notify](notifications.md)) emit `EventRebuildVerify` on a
  confirmed mismatch (`action: mismatch`) and on an enforce-mode quarantine
  (`action: quarantine`).

## Admin & metrics

The admin dashboard's **Reproducible Builds** tab (`GET
/admin/api/rebuildverify`) shows the effective configuration, the registered
builders, the per-verdict and per-ecosystem tallies, and the recent verification
results.

Prometheus metrics (all `pullthrough_rebuildverify_*`):

| Metric | Description |
| --- | --- |
| `verifications_total` | Terminal verifications. |
| `reproducible_total` / `mismatch_total` / `unsupported_total` / `unattested_total` | Per-verdict counters. |
| `builds_run_total` / `build_errors_total` | Rebuild attempts and errors. |
| `cache_hits_total` | Requests served from the result cache. |
| `cache_size` / `inflight` | Cached results and in-flight rebuilds (gauges). |
| `verdicts_total{ecosystem,verdict}` | Per-ecosystem, per-verdict labeled vector — alert on `verdict="mismatch"`. |

## Threat model

A `mismatch` is the signal that matters: a signed artifact with valid provenance
can *still* fail to reproduce if the published binary was tampered with after the
build, if the build pipeline was compromised, or if a malicious maintainer
shipped a binary that does not correspond to the public source. Reproducible-
build verification is the only gate that catches this class of attack, because it
is the only one that re-derives the artifact rather than trusting metadata about
it. See [the threat model](threat-model.md) for where it sits among the gates.
