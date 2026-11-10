# Architecture overview

`pullthrough-security` is a single Go binary that sits between your developer/CI
tooling and the public registries and source forges they depend on. Every pull
flows through one request lifecycle: **resolve → admit (policy) → cache lookup →
fetch → verify → serve**, with asynchronous security analysis (LLM commit
scanning, provenance resolution) feeding the admission decision.

```
                  ┌──────────────────────────────────────────────────────┐
  clients   ────▶ │  Gateway (internal/proxy)                            │
 pip · npm        │   /v1/<upstream>/...   ·  /healthz · /readyz          │
 cargo · go       │   access control envelope · request logging          │
 nuget · docker   │   /metrics · /admin/                                  │
 git (HTTP/SSH)   └───────┬──────────────────────────────────────────────┘
                          │ resolve → policy admit → cache → fetch → verify → serve
                          ▼
   ┌──────────────────────┬─────────────────────────┬────────────────────────┐
   ▼                      ▼                         ▼                        ▼
 Backends             Cache                  Security pipeline          Auth / tenancy
 (internal/backends)  (internal/cache)       scan  (internal/scan)      (internal/auth)
  one per protocol:   content-addressable    provenance                 tokens · OIDC
  pip/npm/cargo/go/   Get/Put/Stat/Delete    (internal/provenance)      RBAC · quotas
  nuget · docker      LRU + TTL + single-    policy  (internal/policy)   audit
  · git               flight + metrics       admission gating           (internal/audit)
  Resolve / Fetch
```

## Request lifecycle

1. **Route.** The gateway matches `/v1/<upstream>/...` and selects the backend
   registered for `<upstream>` (the key under `upstreams:` in config). Operational
   endpoints (`/healthz`, `/readyz`, `/metrics`, `/admin/`) live at the root,
   outside the `/v1` access-control envelope.
2. **Access control** (if `auth.enabled`). The request is authenticated (static
   token or OIDC/JWT) and authorized against the caller's RBAC roles for that
   ecosystem/upstream; the team quota is checked. Unauthenticated/unauthorized/
   over-quota requests are rejected with `401`/`403`/`429` before any upstream or
   cache access. See [access-control-and-audit.md](access-control-and-audit.md).
3. **Resolve.** The backend maps the inbound request to an upstream resource and
   a cache key, classifying it as an immutable artifact or a mutable index
   document.
4. **Admit (policy).** For artifacts that carry supply-chain signal (a resolvable
   source commit / provenance), the policy engine renders an allow/warn/block
   decision *before* the cache or upstream is touched. A block returns an
   actionable `403` and never caches or fetches. See
   [security-model.md](security-model.md).
5. **Cache lookup.** Content-addressable store keyed by the resolved key.
   Immutable artifacts are served straight from cache on a hit; mutable documents
   are conditionally revalidated upstream with `ETag`/`Last-Modified`.
6. **Fetch.** On a miss the shared outbound HTTP client fetches from the upstream,
   injecting any configured upstream credentials. Concurrent identical misses are
   collapsed with single-flight so the upstream sees one request.
7. **Verify & serve.** Digest-addressed content (Docker blobs/manifests, etc.) is
   hashed and compared to its expected digest before it is cached or served; a
   mismatch aborts the stream. Index documents are rewritten so embedded artifact
   URLs flow back through the proxy. The response is streamed to the client and,
   when cacheable, persisted.
8. **Observe.** Every pull and policy decision is metered (Prometheus) and, when
   `audit.enabled`, appended to the tamper-evident audit chain.

## Packages

| Package | Responsibility |
|---------|----------------|
| `cmd/pullthrough` | Process entrypoint: load config → wire components → serve; the `-verify-audit` and `-version` subcommands. |
| `internal/proxy` | Core gateway: routing, request lifecycle, conditional revalidation, access-control envelope, graceful shutdown. |
| `internal/backends` | `Backend` interface (`Resolve`/`Fetch`) and the backend `Registry`. |
| `internal/backends/httpbackend` | Generic HTTP pull-through engine: routing, conditional fetch, credential injection, index-document rewriting. |
| `internal/backends/pkgmgr` | Per-ecosystem package backends (pip, npm, cargo, Go modules, NuGet). |
| `internal/backends/docker` | Docker Registry v2 / OCI distribution pull-through, including the upstream bearer-token handshake and digest verification. |
| `internal/git` | Git pull-through over smart-HTTP and SSH, with optional local mirror-mode caching. |
| `internal/cache` | `Cache` interface + in-memory and content-addressable filesystem stores (LRU + TTL, single-flight, metrics). |
| `internal/upstream` | Shared outbound HTTP client/connection pool and per-upstream TLS policy. |
| `internal/scan`, `internal/scan/commit` | `Scanner` interface, the finding/severity/verdict model, and the LLM commit-scanning pipeline. |
| `internal/provenance` | `Resolver` interface and resolver chain linking artifacts to source commits (attestations, ecosystem metadata, heuristics). |
| `internal/policy` | Admission policy engine: turns scan verdicts + provenance into allow/warn/block decisions. |
| `internal/auth` | Authentication (static tokens, OIDC/JWT), RBAC, multi-tenancy, quotas. |
| `internal/audit` | Tamper-evident keyed-hash-chain audit log. |
| `internal/secrets` | `enc:v1:` secret decryption (AES-256-GCM) at config load. |
| `internal/metrics` | Dependency-free Prometheus registry and exposition. |
| `internal/admin` | Admin REST API + browser dashboard (cache, scans, provenance, policy). |
| `internal/config` | YAML + environment configuration loading, expansion, and validation. |
| `internal/logging` | Structured logging via `log/slog`. |

## Core interfaces

- **`backends.Backend`** — `Resolve(req) → Resolved` maps an inbound request to an
  upstream resource and cache key; `Fetch(resolved) → FetchResult` transfers the
  bytes. Splitting resolution from retrieval lets the gateway consult the cache
  and apply policy in between. Backends needing full control of the response
  (Docker, Git) additionally implement `backends.HTTPHandler`.
- **`cache.Cache`** — `Get` / `Put` / `Stat` / `Delete` over a content-addressable
  keyspace, safe for concurrent use.
- **`scan.Scanner`** — `Scan(target) → Result` inspects commits or artifacts and
  emits findings with severities.
- **`provenance.Resolver`** — `Resolve(artifact) → Link` associates an artifact
  digest with a repository and commit, with a confidence level.

## Design properties

- **Pull-only.** No protocol path publishes to an upstream; even the Git SSH/HTTP
  gateways are fetch-only. This shrinks the blast radius and keeps the proxy a
  pure read-through cache.
- **Fail-open caching, fail-configurable policy.** A cache or upstream hiccup
  degrades to a re-fetch; the *security* posture on assessment errors is your
  choice (`policy.failClosed`).
- **Stateless except for caches.** All durable state (content cache, audit log,
  scan/provenance stores) lives under `/var/lib/pullthrough` and is rebuildable;
  the process holds no other state, so replicas scale horizontally given shared
  or node-local storage.
- **Secure defaults, opt-in enforcement.** Authentication, scanning, provenance,
  policy, and audit are all **off by default** so the proxy works as a plain cache
  out of the box, and you turn on enforcement deliberately.

## Further reading

- [configuration.md](configuration.md) — full configuration reference.
- [security-model.md](security-model.md) — scanning, provenance, and policy.
- [threat-model.md](threat-model.md) — what the proxy defends against (and not).
- [clients.md](clients.md) — per-ecosystem client setup.
- [runbook.md](runbook.md) — operations and incident response.
- [../deploy/README.md](../deploy/README.md) — containerization and deployment.
