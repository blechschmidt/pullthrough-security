# Emergency lockdown / global kill-switch

During an active supply-chain incident an operator needs to tighten the proxy's
posture **instantly** — without redeploying or hand-editing dozens of individual
gate configs. The emergency-lockdown control (`internal/lockdown`, Task 74) is
that single, org-wide lever. It holds one durable, coordinated piece of state —
the active incident mode — that the pull path consults as its very **first** check,
ahead of every other admission gate.

```
pull → resolve coordinate → [ LOCKDOWN ] → nameguard → depfirewall → snapshot-freeze
                                  │            → malfeed → maturity → policy → … → serve
                                  │
            freeze / strict / targeted-block  (+ break-glass override, Task 50)
```

## Modes

| Mode | Effect | Enforced where |
|------|--------|----------------|
| **freeze** | Serve only already-cached, last-known-good artifacts and block **all** new upstream fetches. | Cache-miss boundary: a cache hit still serves; a miss (which would require a fetch) is refused with `403`. Pair with a [snapshot freeze](snapshots.md) to additionally pin clients to known-good digests. |
| **strict** | Flip every observe-mode gate to enforce and harden the risk/maturity/firewall thresholds. | Surfaced as an admission signal (`input.incident.strict`) the aggregating [policy-as-code](../README.md) and risk engines consume — so the hardened posture applies without editing each gate's own config. |
| **block** | Immediately deny a specific `(eco,name)` or `(eco,name,version)` coordinate **everywhere**, ahead of the [malfeed](malfeed.md) feed's next refresh. | The first pull-path check: a matching coordinate is refused on every backend before any upstream fetch. |

Every transition carries a **mandatory operator-supplied reason and incident ID**,
is recorded to the [Merkle audit log](access-control-and-audit.md), raises an
`EventLockdown` [notification](notifications.md), and carries a **TTL with automatic
expiry** so a forgotten lockdown self-heals. The
[break-glass workflow](approvals.md) still composes on top, so an individual
exception can be granted under dual control while the lockdown stands.

## Durability & HA

The active state is persisted to `lockdown.storePath` (default
`<cache.dir>/lockdown.json`, atomic writes) so a lockdown survives a restart. On a
shared store every replica reads the same record. The control is **coord-guarded**
([Task 56](coordination.md)): each transition is tagged with the coordination
guard's fencing token (so incident-mode changes are monotonically ordered across
the cluster), and only the lease leader persists the auto-expiry sweep (followers
compute the same effective `expired→inactive` state without writing).

## Configuration

```yaml
lockdown:
  enabled: true          # exposes the kill-switch, the admin "Incident" tab, and metrics
  storePath: ""          # durable state file; empty = <cache.dir>/lockdown.json
  defaultTtl: 1h         # TTL applied when an engagement omits one
  maxTtl: 24h            # cap on an operator-supplied TTL (0 = no cap)
```

The active posture is **engaged at runtime**, never from config.

## Operating it

### `ptctl`

```console
$ ptctl lockdown status
$ ptctl lockdown freeze -incident INC-42 -reason "investigating compromised upstream" -ttl 2h
$ ptctl lockdown strict -incident INC-42 -reason "harden everything during triage"
$ ptctl lockdown block  -incident INC-42 -reason "freshly-disclosed malware" npm:evil-pkg@1.3.0 pip:badlib
$ ptctl lockdown clear  -reason "incident resolved"
```

A block coordinate is `[ecosystem:]name[@version]`; omit the version to block the
whole package.

### Admin API

| Method & path | Capability | Body |
|---------------|-----------|------|
| `GET /admin/api/lockdown` | read | — |
| `POST /admin/api/lockdown/engage` | administer | `{mode, reason, incidentId, ttl, targets?}` |
| `POST /admin/api/lockdown/clear` | administer | `{reason}` |

The admin UI surfaces a prominent red **Incident** banner across every tab while a
lockdown is active, plus an **Incident** tab to engage/clear it.

## A pull refused by a lockdown

```
HTTP/1.1 403 Forbidden
X-Lockdown-Decision: block
X-Lockdown-Mode: block
X-Lockdown-Incident: INC-42
X-Cache: BLOCKED

{
  "error": "pull refused by an active emergency lockdown (incident-response mode)",
  "code": "lockdown-block",
  "mode": "block",
  "incidentId": "INC-42",
  "coordinate": "evil-pkg@1.3.0"
}
```

A freeze that refuses a cache miss returns `X-Lockdown-Decision: freeze-block` and
`X-Cache: MISS-BLOCKED`.

## Metrics

`pullthrough_lockdown_active`, `pullthrough_lockdown_mode_active{mode=…}`,
`pullthrough_lockdown_seconds_remaining`, `pullthrough_lockdown_block_targets`, and
the cumulative `pullthrough_lockdown_{checks,blocks,freeze_fetch_blocks,engagements,clears,expirations}_total`.

## Cluster-runtime enforcement

The kill-switch extends to Kubernetes via the admission webhook
([admission-webhook.md](admission-webhook.md)): a targeted **block** denies any
Pod referencing the blocked image cluster-wide, and while **any** lockdown is
engaged the webhook denies un-vetted (`unknown`) images at deploy time. Point the
webhook's `lockdown.storePath` at the same shared store the proxy uses so both
boundaries read one incident state.
