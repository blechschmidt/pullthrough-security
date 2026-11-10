# Distributed coordination & leader election (HA)

When you run more than one proxy replica behind a load balancer — the
horizontally-scaled topology enabled by the [shared S3 cache](ha-shared-cache.md)
— each replica independently runs the same scheduled background jobs. Without
coordination that means:

- **Duplicated work** — every replica re-scans every cached artifact against new
  CVEs, refreshes the same feeds, signs the same checkpoints.
- **Races on shared state** — concurrent CVE-drift re-scans race to quarantine /
  release the same cache entries.
- **Double writes** — N replicas each write a backup snapshot to the same
  destination at the same instant.
- **N× notifications** — an event detected by every replica fires N webhook/Slack
  alerts.

The `coordination:` block turns on lease-based **leader election** so that, for
each such job, exactly one replica acts at a time. It is **disabled by default**;
a single-replica deployment needs nothing here and behaves exactly as before.

## What gets coordinated

Only **shared-state / singleton-side-effect** jobs are leader-gated. Each has a
named lease:

| Job lease name      | Subsystem            | Why single-leader                                   |
|---------------------|----------------------|-----------------------------------------------------|
| `cve-drift-rescan`  | CVE-drift re-scan (Task 18) | Mutates the shared quarantine state; emits notifications. |
| `backup`            | Backup scheduler (Task 44)  | Writes a snapshot to a shared destination.          |
| `audit-checkpoint`  | Audit Merkle log (Task 31)  | Signs and writes checkpoints to the shared store.   |

**Not coordinated, by design:**

- **Malware-feed refresh** (malfeed, Task 48) and other read-side caches maintain
  *per-replica in-memory* state that every replica needs to enforce its gate on
  its own requests. Gating their refresh on leadership would leave followers with
  a stale matcher and silently weaken the gate, so every replica refreshes
  independently. (De-duplicating the *upstream fetch* would require shared feed
  storage and is out of scope here.)
- **Air-gapped mirror prewarm** (Task 17) is an on-demand CLI command
  (`pullthrough prewarm`), not a server-side scheduler — there is nothing running
  in the replicas to coordinate.

On-demand, operator-triggered actions are **never** gated: an admin "run backup
now", a manual rescan trigger, and the shutdown checkpoint seal always run on the
replica that received the request.

## How it works

Each leader-gated scheduler holds a `coord.Guard`. Before each scheduled tick it
checks `Guard.IsLeader()`; followers skip the tick. A background *campaign*
goroutine per job continuously:

1. **Acquires** the named lease via a compare-and-swap write to the backend. The
   first holder creates the lease at fencing token 1.
2. **Renews** it every `renewInterval` (the heartbeat) to push out the expiry.
3. **Steps down** if a renewal shows the lease is no longer ours.

A lease record carries a holder ID, an **expiry** (`now + leaseTtl`), and a
**fencing token**. If the leader crashes or stalls past `leaseTtl` without
heartbeating, its lease expires; another replica then *steals* it, incrementing
the fencing token. On a clean shutdown the leader **resigns** (releases the lease
in place, preserving the token) so a survivor can take over immediately instead
of waiting for expiry.

### Fencing tokens and split-brain

The fencing token strictly increases across every acquisition of a lease name. A
process that pauses (GC, CPU starvation) past its lease expiry and resumes
believing it is still leader carries a **stale, lower** token than the replica
that took over. Any resource that records the highest token it has seen can
reject the stale writer — the standard defense against split-brain. The current
token per job is exposed in metrics (`pullthrough_coordination_fencing_token`)
and the admin API.

Correctness rests on the timing assumption that a leader can renew well within
`leaseTtl`. Keep `renewInterval` comfortably below `leaseTtl` (the default 10s vs
30s tolerates two missed heartbeats). The config validator rejects a
`renewInterval >= leaseTtl`.

## Backends

`mode` selects the pluggable lease store:

- **`memory`** — in-process map. The single-node default: with one replica it is
  always the leader, with zero coordination overhead. It performs **no**
  cross-replica election, so the wiring logs a warning if you select it with
  coordination enabled — use it only for a single replica or tests.
- **`s3`** — lease objects in an S3-compatible bucket, using **conditional
  writes** (`If-None-Match` to create, `If-Match` to renew/steal) over the same
  dependency-free SigV4 client as the shared cache. Any connection field left
  unset under `coordination.s3` **inherits `cache.s3`**, so a deployment already
  on the shared s3 cache needs only `mode: s3`. Requires an object store that
  honors conditional writes (AWS S3, MinIO, Ceph RGW).
- **`file`** — a JSON lease file per job on a **shared POSIX volume** (an NFS/EFS
  PVC mounted by every replica), with an advisory `flock` serializing the
  compare-and-swap. The Redis-free / SQL-free option when you already share a
  filesystem but have no object store.

## Configuration

```yaml
coordination:
  enabled: true
  mode: s3                 # memory | s3 | file
  nodeId: ${POD_NAME}      # default: <hostname>-<pid>
  leaseTtl: 30s
  renewInterval: 10s       # must be < leaseTtl
  retryInterval: 10s
  # jobTtls:               # optional per-job TTL overrides
  #   backup: 5m
  # s3:                    # inherits cache.s3 when unset
  #   bucket: my-org-pullthrough-cache
  #   prefix: coord/leases/
  # dir: /var/lib/pullthrough/leases   # file backend only
```

In Kubernetes, set `nodeId` to the pod name via the downward API so lease records
and metrics identify the holder unambiguously:

```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
```

## Observability

**Admin** — `GET /admin/api/coordination` returns this replica's per-job
leadership state *and* the observed cluster-wide leaseholders read live from the
backend (a follower can answer for the whole deployment):

```json
{
  "enabled": true,
  "mode": "s3",
  "nodeId": "proxy-0",
  "jobs": [
    {"job": "backup", "isLeader": true, "fencingToken": 7, "renewals": 41, "timeAsLeaderSeconds": 410}
  ],
  "leaseholders": [
    {"job": "backup", "held": true, "holder": "proxy-0", "fencingToken": 7, "self": true},
    {"job": "cve-drift-rescan", "held": true, "holder": "proxy-1", "fencingToken": 3}
  ]
}
```

**Metrics** (Prometheus), partitioned by `job`:

| Metric                                                  | Meaning                                            |
|---------------------------------------------------------|----------------------------------------------------|
| `pullthrough_coordination_enabled`                      | 1 when coordination is on, 0 in single-node fallback. |
| `pullthrough_coordination_leader{job}`                  | 1 when *this* replica holds the lease.             |
| `pullthrough_coordination_fencing_token{job}`           | Fencing token of the held lease (0 when follower). |
| `pullthrough_coordination_time_as_leader_seconds_total{job}` | Cumulative seconds held.                      |
| `pullthrough_coordination_lease_acquisitions_total{job}`| Acquisitions / steals.                             |
| `pullthrough_coordination_lease_renewals_total{job}`    | Successful heartbeats.                             |
| `pullthrough_coordination_lease_losses_total{job}`      | Times leadership was lost (takeover after stall).  |
| `pullthrough_coordination_lease_acquire_contended_total{job}` | Attempts that found the lease already held.  |
| `pullthrough_coordination_lease_errors_total{job}`      | Backend errors acquiring/renewing.                 |

The invariant to alert on: **`sum(pullthrough_coordination_leader) by (job)`
should be `1`** across the fleet. A sustained `0` means no replica is leading (a
job is stalled); a sustained `>1` would indicate split-brain (it should never
happen with a conformant backend). Frequent `lease_losses` indicate a
`leaseTtl`/`renewInterval` set too tight for your scheduling jitter.

## Operational notes

- **Rolling upgrades** are graceful: a replica resigns its leases on shutdown, so
  a survivor takes over within a heartbeat rather than after a full TTL.
- **Enabling/disabling** coordination is a config change + restart. With it
  disabled every replica is a leader (the original behavior) — never disable it
  while running multiple replicas or you reintroduce duplicate work.
- The `memory` backend with multiple replicas is a misconfiguration (each replica
  leads independently). Always use `s3` or `file` for true HA.
