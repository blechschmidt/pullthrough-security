# Dependency Snapshots, Freeze & Instant Rollback — the supply-chain time machine

The **snapshot subsystem** (`internal/snapshot`, Task 70) captures the complete
resolved dependency state the proxy *actually served* into signed,
content-addressed, point-in-time **snapshots**, lets operators **freeze** the
organization to a snapshot, and provides one-action **instant rollback** to the
last-known-good snapshot when a newly-published version is later found malicious.

Where the [dependency firewall](dependency-firewall.md) enforces a
forward-looking *version policy* and [malfeed](security-model.md) hard-blocks
*known-malicious* coordinates, the snapshot subsystem is the *time-travel* control:
"capture exactly what we are serving right now", "freeze everyone to that exact
set", and "when something we already shipped turns out to be bad, put the whole
org back to the last state we trusted — in one click".

## Concepts

| Concept       | Meaning                                                                       |
|---------------|-------------------------------------------------------------------------------|
| **Live state**| The most-recently-served resolved state per coordinate, captured continuously |
| **Snapshot**  | A signed, content-addressed manifest of the live state at a point in time     |
| **Freeze**    | Pinning the org to a snapshot; a pull-path gate refuses pulls outside its set |
| **Rollback**  | One action: freeze to the last-known-good snapshot                            |

### What a snapshot captures

On every **admitted** pull, the gateway folds the served coordinate's resolved
state into the live set. A snapshot manifest then records, per coordinate:

- `ecosystem`, `name`, `version`, normalized `coordinate`
- served content `digest`
- `sourceCommit` + `repositoryUrl` (from the [provenance](architecture.md) association)
- admission `verdict` (`admit` / `warn`) and `riskScore` / `riskBand`
- the digest of the proxy's outbound [attestation bundle](attestbundle.md) for the artifact

The manifest is **content-addressed**: its `id` is `sha256:<hex>` over the
canonical, sorted content, so two captures of an identical state share an id. It
is **signed** with the audit signing key (the same key that signs the audit
[transparency](access-control-and-audit.md) checkpoints and outbound
attestations), and its content digest is recorded in the **Merkle audit log** —
the captured state is itself tamper-evident.

## Taking snapshots

- **On demand** — admin `POST /api/snapshots/create`, the admin UI "Snapshots"
  tab, or `ptctl snapshot create [name]`.
- **On a schedule** — set `snapshot.scheduleInterval`. The scheduler is
  **coord-guarded** (Task 56): in an HA deployment only the lease-holder for the
  `snapshot` job captures on each tick, so replicas don't each write a snapshot.

## Freezing the organization

Freezing pins the org to a snapshot. A new pull-path **freeze gate** (running
right after the dependency firewall — both are coordinate-set gates that need no
artifact content) then consults the active frozen set for every concrete pull:

- coordinate **in the frozen set** → allowed;
- coordinate **not in the set** (e.g. a version published after the snapshot) →
  **refused** (`not-in-frozen-set`);
- coordinate in the set but **served with a different digest** than the frozen
  one → **refused** (`digest-mismatch`, a tamper signal) when digest enforcement
  is on.

Freeze modes:

| Mode          | Behaviour on an out-of-set pull                                            |
|---------------|---------------------------------------------------------------------------|
| `block`       | refuse with `403` and an actionable JSON body                             |
| `quarantine`  | refuse, but consult the [break-glass](approvals.md) workflow first        |

A freeze is **observe-only** until `snapshot.freezeEnforce: true` — a safety valve
for staging a freeze (the gate records what it *would* block but serves the pull).
Listing/index requests (no concrete version) are never gated.

Freeze and rollback are **administrator-only** (`CapAdminister`) on the admin
surface; capturing and marking-good require `CapOperate`.

## Instant rollback

Every captured snapshot is presumed **known-good**. When a snapshot is later
found to contain a compromised artifact — surfaced by
[malfeed](malfeed.md) or [CVE-drift re-scan](security-model.md) — an operator
(or an automation) clears its good flag (`ptctl snapshot markgood <id> false`),
then runs **rollback**:

```
ptctl snapshot rollback --reason "left-pad@2.0.0 found malicious"
```

Rollback pins the org (a `block`-mode, digest-enforcing freeze) to the **most
recent known-good snapshot that is not the currently-active target**. Because the
freeze gate then blocks every coordinate outside that snapshot's set, the
newly-published malicious version is refused org-wide and clients are forced back
to the previously-served safe digests (still in cache). It is a single action and
takes effect immediately for every replica (the freeze state is persisted and
shared).

## Diffing two snapshots

`GET /api/snapshots/diff?from=<id>&to=<id>` (or `ptctl snapshot diff <from> <to>`)
reports what changed between two points in time, reusing the
[sbom-diff](sbom-diff.md) drift-scoring concepts:

- **added** / **removed** coordinates,
- **digest changes** for the same `name@version` (the strongest tamper signal),
- **verdict**, **risk-band**, and **source-commit** changes,
- an explainable, weighted, clamped **0–100 drift score** with a per-factor
  contribution breakdown.

Digest changes, commit changes, and band escalations dominate the score because
they signal tampering or a security regression rather than normal churn.

## Configuration

```yaml
snapshot:
  enabled: true                # off by default
  dir: /var/lib/pullthrough/snapshots   # defaults to <cache.dir>/snapshots; empty = in-memory
  maxLiveEntries: 50000        # bound on distinct coordinates in the live set
  maxSnapshots: 200            # retained manifests (good/frozen snapshots are never pruned)
  scheduleInterval: 24h        # 0 disables scheduled capture
  freezeEnforce: true          # false = freeze gate is observe-only
```

Manifests are signed when an attestation or audit-transparency signing key is
configured (`attest.signingKey[File]` or `audit.transparency.signingKey[File]`);
without one, snapshots are captured **unsigned** (still content-addressed and
audit-logged).

## Admin & CLI surface

| Endpoint                              | Capability       | Purpose                                |
|---------------------------------------|------------------|----------------------------------------|
| `GET /api/snapshots`                  | read             | list snapshots + active freeze + metrics |
| `GET /api/snapshots/get?id=`          | read             | one full manifest                      |
| `GET /api/snapshots/diff?from=&to=`   | read             | drift report (JSON or `format=md`)     |
| `POST /api/snapshots/create`          | operate          | capture a snapshot                     |
| `POST /api/snapshots/markgood`        | operate          | (un)mark a known-good rollback target  |
| `POST /api/snapshots/freeze`          | **administer**   | freeze the org to a snapshot           |
| `POST /api/snapshots/unfreeze`        | **administer**   | lift the active freeze                 |
| `POST /api/snapshots/rollback`        | **administer**   | instant rollback to last-known-good    |

`ptctl snapshot {list|get|diff|create|freeze|unfreeze|rollback|markgood}` wraps
these, and the admin UI **"Snapshots"** tab exposes capture / diff / freeze /
rollback interactively.

## Observability

- **Metrics** (`pullthrough_snapshot_*`): `live_entries`, `count`,
  `captured_total`, `recorded_total`, `freezes_total`, `rollbacks_total`,
  `freeze_active`, `frozen_set_size`, and freeze-gate `allowed`/`blocked`/
  `quarantined` totals.
- **Notifications**: `EventSnapshot` is raised on capture / freeze / unfreeze /
  rollback and on every freeze-gate block.
- **Query API**: the federated [query API](query-api.md) exposes `snapshotted`,
  `frozen`, `snapshotVerdict`, and `snapshotBand` fields per coordinate.
- **Audit**: every lifecycle action is recorded to the Merkle audit log
  (`snapshot:captured|frozen|unfrozen|rollback`).
