# Quarantine review & break-glass approvals

When an admission gate refuses an artifact, the default outcome is a hard `403`.
That is the right behavior for a confirmed threat, but it is too blunt for the
common operational reality: a known false positive, an urgent hotfix that depends
on a package with an as-yet-unfixed CVE, or a quarantine an operator has triaged
and accepts the risk of. Historically the only escape was to edit policy config
and redeploy — slow, coarse (it weakens the gate for *everyone*), and easy to
forget to revert.

The **approval workflow** (`internal/approvals`) adds a stateful,
human-in-the-loop layer in front of the blocks. An operator can review a pending
decision and either:

- **grant a break-glass exception** — a time-boxed, `(tenant, ecosystem,
  coordinate, gate)`-scoped override that lets the *specific* blocked artifact be
  served until the grant expires, at which point it auto-revokes and the artifact
  is re-quarantined; or
- **deny** — confirm the block, so the artifact stays refused.

No config edits, no redeploys, and the override is narrow (one coordinate, one
gate, one tenant) and self-expiring.

## Which gates participate

The pull path consults the workflow **before returning a block** for:

| Gate | Block it overrides |
|------|--------------------|
| `vulnscan` | CVE severity/CVSS block or quarantine (Task 15) |
| `cve-drift` | re-scan quarantine of a previously-clean cached artifact (Task 18) |
| `malfeed` | known-malicious-package match (Task 48) |
| `sigverify` | signature/attestation verification failure (Task 23) |
| `policy` | hard provenance/admission policy block (Task 9) |

A grant is keyed by `(tenant, ecosystem, coordinate, gate, reason)`, so approving
a vulnerability block on `npm left-pad@1.0.0` does **not** also bypass a separate
signature failure on the same artifact, nor the same finding for another tenant.

## Lifecycle

```
   pull blocked ─▶ pending review ─┬─▶ approve (Nth distinct approver) ─▶ active grant ─▶ serve…
                                   │                                          │
                                   │                                          └─▶ TTL elapses ─▶ expired ─▶ re-quarantine ─▶ (fresh pending review)
                                   └─▶ deny ─▶ block confirmed (stays refused)
```

- A blocked pull with no active grant **opens a pending review** (and bumps a hit
  counter on subsequent blocked pulls for the same scope).
- An approval records one approver's vote. With `requiredApprovers > 1`
  (**dual control**) the request stays pending until `N` **distinct** identities
  have voted; the same identity cannot vote twice.
- An **active grant** serves the blocked artifact (and, for quarantine gates,
  skips eviction so the cached bytes are retained) until `grantTtl` elapses.
- On expiry the grant auto-revokes, the artifact is re-quarantined, and a fresh
  pending review is opened so the next pull blocks again.
- A **denied** request keeps blocking and is not auto-reopened.

## Configuration

```yaml
approvals:
  enabled: false               # off by default; gates block unconditionally until you opt in
  requiredApprovers: 1         # set >= 2 for dual control (distinct identities)
  grantTtl: 1h                 # break-glass grant lifetime before auto-revoke + re-quarantine
  requestTtl: 72h              # unreviewed pending request lifetime before auto-expiry
  sweepInterval: 1m            # background reconciliation of due grants / stale requests
  # maxRequests: 1000          # cap on retained requests (oldest terminal records trimmed first)
  # storePath: /var/lib/pullthrough/approvals.json  # durability across restarts
```

When `storePath` is set, the request store (pending reviews and active grants) is
persisted to disk and restored on startup, so a restart does not silently drop an
active grant or lose the review backlog.

## Operating it

### Admin UI

The **Approvals** tab lists requests filtered by status (pending / active grants /
denied / expired) with the cumulative counters (open, active grants,
approved/denied/expired, average time-to-approval). Each pending row has
**Approve** and **Deny** actions that prompt for the approver identity, a required
justification, and (for approvals) an optional grant duration override.

### Admin API

```
GET  /admin/api/approvals?status=pending&limit=200
POST /admin/api/approvals/approve   {"id","approver","justification","durationSeconds"?}
POST /admin/api/approvals/deny      {"id","approver","justification"}
```

Both decision endpoints require an `approver` identity and a `justification`; a
missing one returns `400`. An unknown `id` returns `404`; a decision on an
already-decided request returns `400`. The admin surface is guarded by the admin
bearer token (see [access-control-and-audit.md](access-control-and-audit.md)).

A served-under-grant pull carries `X-Approval-Decision: break-glass` and
`X-Approval-Request: <id>` headers so the override is visible to the client and in
logs.

## Audit & notifications

Every state change — **requested**, **granted**, **denied**, **expired**, and each
**break-glass serve** — is written to the tamper-evident audit log and linked into
the Merkle transparency chain (see
[access-control-and-audit.md](access-control-and-audit.md)). Entries record the
deciding identity (`who`), the justification (`why`), the grant duration and
expiry, and the full scope. Grant/expiry/deny/request events are also emitted to
the configured notify sinks ([notifications.md](notifications.md)) as `approval`
events.

## Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `pullthrough_approvals_open_requests` | gauge | reviews awaiting a decision |
| `pullthrough_approvals_active_grants` | gauge | grants currently within their TTL |
| `pullthrough_approvals_requests_total` | counter | reviews ever opened |
| `pullthrough_approvals_approved_total` | counter | grants issued |
| `pullthrough_approvals_denied_total` | counter | blocks confirmed |
| `pullthrough_approvals_expired_total` | counter | grants/reviews auto-expired |
| `pullthrough_approvals_break_glass_serves_total` | counter | serves authorized by a grant |
| `pullthrough_approvals_time_to_approval_seconds_sum` / `_count` | counters | divide for the average time-to-approval |

A rising `open_requests` with a low approval rate signals a stalled review queue;
a non-zero `active_grants` is your live break-glass exposure.
