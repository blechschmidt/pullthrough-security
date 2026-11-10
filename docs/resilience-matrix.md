# Chaos / fault-injection resilience matrix

20 guarantees — 20 upheld, 0 violated.

## Dependency: upstream

| ID | Degraded condition | Expected behavior | Mechanism | Status |
| -- | ------------------ | ----------------- | --------- | ------ |
| UP-ALL-OPEN-SHED | every mirror's circuit is open | the pool fails fast with AllUnavailableError and issues zero upstream requests | upstreampool fail-fast | ✅ upheld |
| UP-CIRCUIT-OPENS | an endpoint fails FailureThreshold times in a row | its circuit opens; further requests are shed (AllUnavailable) without dialing the dead endpoint | upstreampool circuit breaker | ✅ upheld |
| UP-CIRCUIT-RECOVERS | an open circuit's endpoint recovers after the open timeout | a half-open trial probe succeeds and, after SuccessThreshold successes, the circuit closes | upstreampool half-open recovery | ✅ upheld |
| UP-FAILOVER-5XX | primary mirror returns a retryable 5xx | request fails over to a healthy mirror and is served 200 | upstreampool health-aware routing | ✅ upheld |
| UP-FAILOVER-TRANSPORT | primary mirror connection/TLS error (nil response) | request fails over to a healthy mirror and is served 200 | upstreampool health-aware routing | ✅ upheld |
| UP-NEGATIVE-CACHE | a missing artifact is requested repeatedly (404 storm) | only the first request reaches the upstream; the rest are absorbed by the negative cache | coalesce negative cache | ✅ upheld |
| UP-NO-FAILOVER-404 | primary mirror returns a terminal 404 | 404 is returned directly: no failover, no circuit trip (404 is an answer, not a fault) | upstreampool retryable-status classifier | ✅ upheld |
| UP-SINGLEFLIGHT-ERROR | concurrent misses for the same artifact while the upstream errors | exactly one upstream fetch is issued; the error is shared with every coalesced waiter | coalesce singleflight | ✅ upheld |

## Dependency: storage

| ID | Degraded condition | Expected behavior | Mechanism | Status |
| -- | ------------------ | ----------------- | --------- | ------ |
| ST-FILL-INTEGRITY | the upstream serves bytes that do not match the expected content digest | the fill is aborted (502) and the tampered bytes are never committed to the cache | fill-time content-digest verifier | ✅ upheld |
| ST-PARTIAL-RESPONSE | the upstream declares a Content-Length larger than the body it delivers (truncated/partial response) | the fill fails (502) on the short read and the partial bytes are never cached; a retry re-fetches | cache fill read-to-EOF | ✅ upheld |
| ST-READ-THROUGH-ERROR | the cache/object-store backend is unreachable on the read-through path | the pull returns 502 Bad Gateway; no partial or garbage content is served | gateway writeFetchError | ✅ upheld |
| ST-WRITE-ERROR | the object-store write (Put) times out / 5xxs during a cache fill | the pull returns 502 and nothing is cached; a retry re-fetches rather than serving a half-written entry | atomic cache fill | ✅ upheld |

## Dependency: scanner/llm

| ID | Degraded condition | Expected behavior | Mechanism | Status |
| -- | ------------------ | ----------------- | --------- | ------ |
| GATE-LLM-DEGRADE | the LLM commit-scan API is unavailable but a deterministic pass found a secret | the scan degrades to the deterministic verdict (served, finding retained) instead of failing the pull | commit pipeline deterministic fallback | ✅ upheld |
| GATE-LLM-PROPAGATE | the LLM commit-scan API is unavailable and no deterministic signal exists | the outage propagates so the commit stays unscanned (deferred to the missing-scan policy — no silent pass) | commit pipeline error propagation | ✅ upheld |
| GATE-POLICY-FAIL-CLOSED | the provenance/scan assessment backend is unavailable and policy is fail-closed | the artifact is blocked (safety over availability) | policy.Engine FailClosed=true | ✅ upheld |
| GATE-POLICY-FAIL-OPEN | the provenance/scan assessment backend is unavailable and policy is fail-open (default) | the artifact is served with a warning rather than halting all pulls | policy.Engine FailClosed=false | ✅ upheld |

## Dependency: peer-federation

| ID | Degraded condition | Expected behavior | Mechanism | Status |
| -- | ------------------ | ----------------- | --------- | ------ |
| CF-CIRCUIT-SHED | a peer fails FailureThreshold times in a row | its circuit opens and further misses skip it without issuing a request | cachefed per-peer circuit breaker | ✅ upheld |
| CF-DIGEST-MISMATCH | a peer returns bytes that do not match the expected content digest (compromised/corrupt sibling) | the stream fails with a digest mismatch and the tampered bytes are never trusted or cached | cachefed streaming digest verifier | ✅ upheld |
| CF-PEER-DOWN | the only configured peer is unreachable (connection refused) on a local miss | the read-through reports no-peer (so the caller falls through to the upstream); no partial content is served | cachefed per-peer error handling | ✅ upheld |
| CF-PEER-HIT | a local cache miss whose artifact a healthy sibling peer holds | the miss is served from the peer (egress saved) with the bytes re-verified against the expected digest | cachefed read-through + digest re-verification | ✅ upheld |

