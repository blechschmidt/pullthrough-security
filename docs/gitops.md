# GitOps policy & config synchronization

The proxy can continuously reconcile its policy/config bundles from a
version-controlled **source of truth** rather than having operators edit the live
configuration by hand. This is the enterprise GitOps workflow: policy-as-code lives
in Git (or an OCI artifact, or — for air-gapped sites — a local pre-fetched
bundle), and the proxy pulls, verifies, validates, previews, and applies it.

The subsystem lives in `internal/gitops` and is exposed through:

- an admin **GitOps** tab and the `/api/gitops*` endpoints,
- the `ptctl gitops status|sync|rollback` CLI,
- the `gitops:` config block,
- Prometheus metrics (`pullthrough_gitops_*`),
- Merkle-audited `EventGitOps` apply/rollback records and `EventGitOps`
  notifications.

It is **off by default**; an operator opts in by pointing it at a source of truth.

## How reconciliation works

On a coord-guarded interval (so only the HA leader reconciles and mutates the
shared config), and on demand via the admin API / `ptctl gitops sync`, the
reconciler:

1. **Fetches** the desired-state bundle from the configured source.
2. **Verifies** its integrity/authenticity — an optional pinned content digest
   and/or a detached signature against a trusted public key. The signature scheme
   is the same Ed25519/ECDSA/RSA convention used by the audit checkpoint signer and
   the outbound attestation bundles (`internal/attestbundle`), so the proxy can
   reuse its existing signing trust material. When `failClosed` is set, an
   unverified bundle is **never** applied.
3. **Validates and previews** the change: the bundle is projected onto the running
   configuration and run through the existing config validation
   (`internal/config` configcheck) and the simreplay blast-radius what-if
   (`internal/simreplay`) — how many captured pulls would flip admit↔block, shift
   risk band, or gain new policy violations.
4. **Applies or suggests** the change:
   - **apply mode** — the on-disk config file is surgically patched (preserving
     comments, encrypted secrets, and untouched settings), and a full
     `EventGitOps` apply record (commit SHA + before/after diff) is written to the
     Merkle audit log.
   - **suggest mode** — the pending change is surfaced for **dual-control
     approval** (`internal/approvals`). It is applied only once an approver grants
     it; until then it shows as a pending change in the GitOps tab.
5. **Detects drift** — when the live config diverges from the source of truth the
   status reports `driftDetected`, and a configcheck drift status reports whether
   the on-disk file differs from the running process (a reload is pending after an
   apply, since changes take effect on the next reload/restart).

If a change turns out badly, **rollback** restores the configuration to the
last-known-good applied revision (the state captured immediately before the most
recent apply).

## The bundle format

A desired-state bundle is a small declarative document (YAML, a superset of JSON):

```yaml
apiVersion: pullthrough.gitops/v1
revision: 2025-06-01-hardening     # optional; a Git source overrides with the commit SHA
description: Tighten policy + license posture
settings:
  - path: policyEngine.mode
    value: enforce
  - path: license.deny
    value: [GPL-3.0-only, AGPL-3.0-only]
  - path: riskScore.thresholdAction
    value: block
```

Each setting is a dotted path into the proxy configuration and the value to set
there (`bool`, `string`, `int`, `float64`, or a string list). This is the same
shape as a compliance preset (`internal/presets`), so the projection, validation,
fingerprinting, surgical on-disk patch, and simreplay what-if are all reused.

This covers policyengine settings, depfirewall rules, license allow/deny lists,
preset-style gate settings, tenant overrides — anything addressable by a config
path.

### Signing a bundle

The bundle is verified by a **detached signature** alongside it. For a local
source the reconciler reads `<bundle>.sig`; for a Git source it reads
`<bundlePath>.sig` within the repo. The signature is the raw (or base64) signature
bytes over the exact bundle document, produced with the trusted private key. For an
Ed25519 key the message is signed directly; for ECDSA/RSA the SHA-256 digest is
signed (PKCS#1 v1.5 for RSA) — identical to the audit/attestbundle scheme.

Alternatively (or additionally), pin the bundle's SHA-256 with
`gitops.verify.expectedDigest` — the simplest integrity control for air-gapped
sites that transfer the bundle out of band.

## Configuration

```yaml
gitops:
  enabled: true
  mode: suggest               # suggest (dual-control) | apply (auto)
  interval: 5m                # reconcile cadence (coord-guarded; 0 = 5m)
  storePath: ""               # durable state file; empty = <cache.dir>/gitops.json
  failClosed: true            # refuse to apply an unverified bundle
  source:
    type: git                 # local | git
    path: policy/bundle.yaml  # local: file path; git: bundle path within the repo
    git:
      url: https://github.com/acme/policy.git
      ref: main
      workDir: ""             # clone dir; empty = <cache.dir>/gitops-repo
  verify:
    publicKeyFile: /etc/pullthrough/gitops-trust.pem
    expectedDigest: ""        # optional pinned SHA-256 of the bundle document
```

### Air-gapped / disconnected operation

Set `source.type: local` and `source.path` to a file an out-of-band process
maintains (a sidecar, a CI job, or the air-gap mirror import). No network or `git`
binary is required. Place the detached signature at `<path>.sig` and/or pin
`verify.expectedDigest`. The `git` source requires the host `git` binary and uses
whatever auth the host git is configured for (SSH agent, credential helper, HTTPS
token).

## Admin API

| Method & path | Capability | Description |
|---|---|---|
| `GET /api/gitops` | read | Reconciliation status + metrics |
| `POST /api/gitops/sync` | administer | Force an immediate reconcile |
| `POST /api/gitops/rollback` | administer | Roll back to last-known-good (`{"reason": "..."}`) |

Sync and rollback rewrite the on-disk configuration, so they require the
`administer` capability and are recorded in the audit log attributed to the
authenticated operator.

## CLI

```console
$ ptctl gitops status
GitOps: DRIFT (mode=suggest)
  source:    git:https://github.com/acme/policy.git@main:policy/bundle.yaml
  interval:  5m0s
  lastSync:  2025-06-01T12:00:00Z (pending_approval)
  revision:  3f2a1c9e...
  PENDING APPROVAL: 3f2a1c9e (2 change(s)) request=ab12cd
  pending changes (2):
    - policyEngine.mode: audit -> enforce
    - license.action: warn -> block
  blast radius: 14/220 pulls change (12 now-blocked, 2 now-admitted)

$ ptctl gitops sync
sync: applied
  revision:  3f2a1c9e...
  verified:  true
  changed:   2
  applied to the on-disk config (takes effect on next reload/restart)

$ ptctl gitops rollback -reason "policy change broke CI"
rolled back 3f2a1c9e -> 9a8b7c6d
```

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `pullthrough_gitops_in_sync` | gauge | Live config matches the source of truth (1/0) |
| `pullthrough_gitops_drift` | gauge | Live config has drifted from the source of truth (1/0) |
| `pullthrough_gitops_pending_change` | gauge | A change is pending dual-control approval (1/0) |
| `pullthrough_gitops_reconciles_total` | counter | Reconcile passes performed |
| `pullthrough_gitops_applies_total` | counter | Desired-state bundles applied |
| `pullthrough_gitops_rollbacks_total` | counter | Rollbacks to last-known-good |
| `pullthrough_gitops_verify_failures_total` | counter | Bundles that failed verification |
| `pullthrough_gitops_errors_total` | counter | Reconcile passes that failed with an infrastructure error |

## Notes & caveats

- **Takes effect on reload/restart.** Applying a bundle rewrites the on-disk config
  file; the running process keeps its current effective configuration until it is
  reloaded or restarted. The configcheck drift status in the GitOps tab makes a
  pending reload visible.
- **HA safety.** The scheduled reconcile is gated by the `gitops` coordination
  guard so only the leader applies; manual syncs run on whichever replica received
  the request.
- **Idempotency.** After a successful apply the reconciler updates its in-memory
  running config, so a subsequent reconcile reports `in_sync` rather than
  re-applying.
- **Backups.** Every apply snapshots the prior config to a timestamped
  `<config>.gitops.bak.<ts>` file; rollback uses it to restore the last-known-good
  state and snapshots the current config to `<config>.gitops.rollback.<ts>`.
