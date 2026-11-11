# Cross-proxy peer cache federation (Task 143)

In a multi-replica (HA) deployment, each proxy instance normally maintains its
own cache and independently reaches out to the upstream registry on a miss. Peer
cache federation lets a cluster of instances **satisfy a local miss from a
sibling peer's cache first**, before paying the egress and latency of an upstream
fetch. This warms a freshly-started or cold replica from its already-warm
siblings and cuts redundant upstream traffic.

Federation is **off by default** and strictly opt-in (`cacheFed.enabled`).

## How it works

```
client ── miss ──▶ proxy A ──┬── peer HEAD/GET ──▶ proxy B (sibling cache)
                             │        │ verified bytes
                             │        ▼
                             └── (peer miss) ──────▶ upstream registry
```

On a local cache miss, and **after** the emergency-lockdown freeze check (a
freeze never reaches a sibling), the cacheable pull path:

1. Selects up to `cacheFed.maxPeerFanout` healthy peers (a per-peer circuit
   breaker sheds unhealthy ones, mirroring the Task 38 upstream health-aware
   routing state machine).
2. Issues an authenticated `GET` by cache key to each, with a per-peer
   time-to-headers deadline (`cacheFed.peerTimeout`) and optional request
   **hedging** (`cacheFed.hedgeDelay`) so a slow peer never holds up a request a
   fast one could answer.
3. Takes the first verified `200`, streams it into the local cache, and cancels
   the losing requests.

A federated fill is otherwise identical to an upstream fetch: the bytes still
flow through the **fill-time digest verifier** and **every local admission gate**
(signature verification, vulnerability scanning, license, malware, …). Federation
reduces egress without weakening any guarantee.

## Security model

- **Peer bytes are never trusted blindly.** Every peer response is re-verified
  against the expected content digest *as it streams*; a mismatch aborts the
  cache fill (`ErrDigestMismatch`) before any byte is committed, and penalizes
  the offending peer's circuit breaker. By default (`cacheFed.requireDigest:
  true`) a miss is only offered to peers when an authoritative expected digest is
  known, defending against a *malicious* peer, not merely transit corruption.
  Disabling `requireDigest` falls back to the peer-advertised digest (transit
  integrity only) and is **not recommended**.
- **Only cached artifacts are exchanged, and the receiver gates them itself.** A
  serving proxy answers a sibling only from its local cache. The cache is not a
  set of admitted artifacts, though: an artifact is in it from the moment it is
  fetched until a gate that refuses it evicts it, and a gate in an observe-only
  mode leaves a flagged artifact there for good. The defense is therefore on the
  receiving side — a miss filled from a peer is put before the receiving proxy's
  own admission gates exactly like one fetched from the upstream.
- **A proxy does not hand out what it has itself refused.** The peer endpoint
  consults a serve guard before any byte is written, for `HEAD` and `GET` alike.
  With the [LLM package-content scan](llm-package-scan.md) enabled, an entry
  whose bytes have a verdict the gate currently refuses — or that is a blob
  implicated by a refused image, which stays in the cache — is answered `403`.
  Nothing is scanned on this path; a stored verdict is enforced.
- **A peer that declines is not a failed peer.** A `404` (the peer does not hold
  the key) or a `403` (it declines to serve it) is a healthy answer and does not
  count against the peer's circuit breaker; transport errors, `401` and `5xx`
  do. A sibling that lacked — or had refused — a few keys in a row is not taken
  out of rotation for every other key.
- **Authenticated protocol.** The peer endpoint (`/internal/cachefed/v1/blob`)
  requires a shared bearer token (`cacheFed.auth.secretRef`, resolvable from
  env/file/Vault via the Task 133 secrets layer) presented as
  `Authorization: Bearer <token>`, compared in constant time. With no token
  configured the serving endpoint **fails closed** (serves nothing) rather than
  exposing an unauthenticated cache. The token must be identical across every
  federated instance.
- **No self-federation.** A peer whose name matches this node's coordination
  NodeID (Task 56) is dropped from the roster.

## Configuration

```yaml
cacheFed:
  enabled: true
  serve: true                      # answer sibling requests (default true)
  auth:
    secretRef: env://CACHEFED_TOKEN  # shared bearer token (identical on all nodes)
  peers:
    - name: proxy-b
      url: https://proxy-b.internal:8443
    - name: proxy-c
      url: https://proxy-c.internal:8443
  maxPeerFanout: 2                 # peers queried concurrently per miss
  peerTimeout: 3s                  # time-to-headers per peer
  hedgeDelay: 150ms                # stagger between fanned-out peers (0 = all at once)
  requireDigest: true              # only federate verifiable (content-addressed) misses
  failureThreshold: 3              # consecutive failures that trip a peer's breaker
  successThreshold: 2              # half-open successes that close it
  openTimeout: 30s                 # how long a tripped peer is shed
  halfOpenMaxProbes: 1
```

Validate a candidate config before rollout with
`pullthrough verify-config -config <file>` or `ptctl config validate <file>`;
preflight warns about an enabled federation with no peers, a missing auth secret,
or a disabled `requireDigest`.

## Metrics

All series carry the `pullthrough_cachefed_` prefix:

| Metric | Meaning |
| --- | --- |
| `pullthrough_cachefed_hits_total` | local misses served by a sibling peer |
| `pullthrough_cachefed_misses_total` | local misses no peer could satisfy (fell through to the upstream) |
| `pullthrough_cachefed_peer_errors_total` | peer read-through requests that failed (transport error, `401`, `5xx`; a peer that answers `404` or `403` did not fail) |
| `pullthrough_cachefed_verify_failures_total` | peer responses rejected on digest re-verification |
| `pullthrough_cachefed_skipped_no_digest_total` | misses not offered to peers (no verifiable digest) |
| `pullthrough_cachefed_served_total` | sibling requests answered from this instance's cache |
| `pullthrough_cachefed_served_misses_total` | sibling requests for a key this instance did not hold |
| `pullthrough_cachefed_served_refused_total` | sibling requests refused by a serve guard (an entry this proxy has itself refused) |
| `pullthrough_cachefed_unauthorized_total` | sibling requests rejected for a bad/missing token |
| `pullthrough_cachefed_peer_requests_total{peer,outcome}` | per-peer success/failure counts |
| `pullthrough_cachefed_peer_latency_seconds_{sum,count}{peer}` | per-peer read-through latency |
| `pullthrough_cachefed_peer_circuit_state{peer}` | per-peer breaker state (0=closed, 1=half-open, 2=open) |

## Resilience

The chaos / fault-injection harness (Task 98) covers the federation degraded
modes as machine-checked guarantees (`CF-PEER-HIT`, `CF-DIGEST-MISMATCH`,
`CF-PEER-DOWN`, `CF-CIRCUIT-SHED`); see [resilience-matrix.md](resilience-matrix.md).
