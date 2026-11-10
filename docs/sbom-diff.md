# SBOM diff & dependency-drift report

The proxy keeps a bounded, per-coordinate history of the **SBOMs it has already
generated** (by the [vulnerability](security-model.md) and
[findings](findings.md) subsystems) and, whenever it serves a *new version* of a
package, diffs that version against the one before it. The diff answers the
supply-chain question operators actually ask:

> *"What changed since the version I last approved?"*

It surfaces, for a given `(tenant, ecosystem, coordinate)`:

1. **Dependency-set delta** — transitive dependencies that were **added**,
   **removed**, or **version-bumped**.
2. **Newly-introduced licenses** — cross-referenced against the
   [license-compliance policy](licenses.md), so a freshly-pulled GPL/copyleft
   dependency is flagged (not just *any* new license).
3. **Newly-introduced namespaces / maintainers** — the owning organisation or
   scope of each dependency. A quiet package that suddenly depends on a
   never-before-seen namespace is a classic dependency-confusion / hijack tell.
4. **Net-new vulnerabilities** — advisories affecting the new version that did
   **not** affect the prior one, taken from the already-computed scan reports (no
   re-scan, no extra network calls).

From those deltas it derives a single, explainable **drift-risk score** (0–100).
A well-behaved package that suddenly pulls in a large or suspicious new
dependency footprint scores high and can be flagged or quarantined.

It **reuses the existing SBOM extraction** — it never re-implements a manifest
parser — and is fully deterministic, so its reports are stable and golden-testable.

## How it works

```
pull → cache → vuln gate (SBOM) → license gate → sbom-diff gate → serve
                     │                                  │
                     └────────── reused SBOM + ─────────┘
                                 scan vulnerabilities
```

1. The vulnerability gate caches the artifact's SBOM (and its vulnerabilities)
   by content digest.
2. The sbom-diff gate reduces that SBOM + vulnerabilities to a compact
   **snapshot** for the pulled version and records it in the per-coordinate
   history (replacing an existing snapshot for the same version in place).
3. If a snapshot for a *different* prior version exists, it computes the diff and
   the drift score.
4. The score drives an admission **action** and a **policy signal**:
   - `>= warnThreshold` → the response is annotated with `X-Sbom-Drift-*`
     headers.
   - `>= significantThreshold` → an `EventSbomDrift` notification fires and the
     drift is exposed to the [policy-as-code engine](policyengine.md) as the
     `sbomDrift` input.
   - `>= blockThreshold` → the configured `action` (`warn`/`block`/`quarantine`)
     is applied. A `block`/`quarantine` returns an actionable `403` (and a
     quarantine evicts the artifact from the cache). It composes with the
     [break-glass approval workflow](approvals.md), so an operator can release a
     drift-blocked pull.

When vulnerability scanning is disabled the gate extracts the SBOM on demand from
the cached content, so it still works standalone (without the net-new-vuln
dimension).

## Drift-risk score

The score is the clamped sum of weighted contributions:

| Factor | Default weight |
|--------|----------------|
| net-new **critical** vulnerability | 50 |
| net-new **high** vulnerability | 28 |
| net-new **medium** vulnerability | 10 |
| net-new **low** vulnerability | 3 |
| newly-introduced **denied** license | 30 |
| newly-introduced **review** license | 12 |
| newly-introduced **allowed** license | 2 |
| new dependency namespace | 8 |
| added dependency | 3 |
| version-bumped dependency | 1 |
| removed dependency | 0.5 |

Each factor's contribution is reported in the diff's `contributions` array, so
the score is fully explainable. Every weight is individually tunable; an omitted
weight keeps its default.

## Configuration

```yaml
sbomDiff:
  enabled: true
  historySize: 16            # version snapshots retained per coordinate
  maxCoordinates: 4096       # distinct coordinate histories retained (LRU-evicted)
  action: warn               # action at blockThreshold: warn | block | quarantine
  warnThreshold: 25          # drift score that annotates the response
  significantThreshold: 40   # drift score reported (EventSbomDrift) + policy signal
  blockThreshold: 60         # drift score at which `action` is applied
  weights: {}                # override individual drift-score weights
```

Defaults are **observe-and-alert**: `action: warn` records history and surfaces
drift without ever blocking a pull until an operator raises the action to
`block`/`quarantine`. The thresholds must satisfy
`warnThreshold <= blockThreshold` and all lie within `[0,100]`.

## Admin API

| Endpoint | Returns |
|----------|---------|
| `GET {adminPrefix}/api/sbomdiff` | cumulative drift metrics + the tracked coordinates and their retained versions |
| `GET {adminPrefix}/api/sbomdiff/diff?ecosystem=&package=&from=&to=&format=` | the version-to-version diff. `from`/`to` optional (defaults to the two most recent versions). `format=md` renders a Markdown report; otherwise JSON. `tenant=` selects a tenant's history. |

The admin UI's **Drift** tab shows the metrics, the recent significant drifts,
and an interactive "what changed?" form that renders the Markdown report.

## Client CLI (`ptctl`)

```console
$ ptctl sbom-diff --ecosystem npm left-pad 1.3.0 1.4.0
# Dependency drift: left-pad 1.3.0 → 1.4.0
- Ecosystem: `npm`
- Drift score: **41 / 100** ⚠️ significant
...
$ ptctl sbom-diff --ecosystem npm left-pad        # diff the two most recent versions
$ ptctl sbom-diff --ecosystem npm left-pad --json # raw JSON diff
```

`ptctl sbom-diff` is HTTP-only and read-only: it calls the admin diff endpoint
and prints the rendered Markdown report (or the raw JSON with `--json`). It needs
a read-capable `--token`.

## Policy-as-code signal

The drift verdict is exposed to the policy engine as the `sbomDrift` input, so a
rule can refuse a pull on excessive drift independently of the built-in
thresholds:

```cel
sbomDrift.evaluated && sbomDrift.driftScore >= 50 && sbomDrift.newVulnerabilities > 0
```

Available fields: `evaluated`, `fromVersion`, `toVersion`, `driftScore`,
`significant`, `addedDeps`, `removedDeps`, `versionBumps`, `newNamespaces`,
`newLicenses`, `newDeniedLicenses`, `newVulnerabilities`.

## Observability

Metrics (Prometheus):

| Metric | Meaning |
|--------|---------|
| `pullthrough_sbomdiff_observed_total` | version snapshots recorded |
| `pullthrough_sbomdiff_compared_total` | version-to-version diffs computed |
| `pullthrough_sbomdiff_significant_total` | diffs over the significance threshold |
| `pullthrough_sbomdiff_warned_total` | pulls warned on for drift |
| `pullthrough_sbomdiff_blocked_total` | pulls blocked for drift |
| `pullthrough_sbomdiff_quarantined_total` | pulls quarantined for drift |
| `pullthrough_sbomdiff_coordinates` | coordinates with a retained history |
| `pullthrough_sbomdiff_significant_by_ecosystem_total{ecosystem}` | significant drift by ecosystem |

Notifications: an `sbom_drift` event is emitted on every significant drift and
routed through the [notification subsystem](notifications.md).

## Offline / air-gapped

The diff is computed entirely from the SBOMs and scan reports the proxy already
holds; it performs **no network access** and is enabled unchanged in
sealed/air-gapped deployments. The history is in-memory (bounded), so it requires
no external store and rebuilds naturally as versions are pulled.
