# Access control, multi-tenancy & audit

This document describes the enterprise access-control layer added in Task 10:
client authentication, per-team namespaces and quotas, role-based authorization
(RBAC), the tamper-evident audit log, and encryption of secrets at rest.

All of it is **off by default** so existing deployments keep working; turn it on
per the [example config](../configs/config.example.yaml).

> This document covers access control for **package pulls**. Access control for
> the **admin API/UI** (OIDC/OAuth2 SSO + fine-grained RBAC) is a separate
> subsystem — see [admin-sso-rbac.md](admin-sso-rbac.md).

## Threat model & design goals

- **Deny by default.** With `auth.enabled: true`, a request that is not
  authenticated *and* authorized never reaches an upstream or the cache.
- **Least privilege.** A role grants nothing unless it explicitly lists an
  ecosystem/upstream (or `"*"`). A principal with no matching role is denied.
- **Tenant isolation.** Each client belongs to a team; quotas and (optionally)
  cache namespaces are scoped per team.
- **Tamper-evident accountability.** Every pull and policy decision is written
  to a keyed hash chain that detects after-the-fact edits, deletions, and
  reordering.
- **No plaintext secrets at rest.** Credentials, API tokens, and the audit key
  can be stored AES-256-GCM-encrypted in the config file.

## Authentication

Two mechanisms can run together (tried in order: static token, then OIDC):

### Static API tokens (`auth.tokens`)

Each token maps to a principal (`name` = subject, `team`, `roles`). Provide
either the secret inline (`token:`, supporting `${ENV}` and `enc:v1:` values) or
a precomputed digest (`tokenHash: "sha256:<hex>"`) so the plaintext never needs
to touch disk. Tokens are matched by SHA-256 digest; the plaintext is never
stored in memory.

Clients may present the token as `Authorization: Bearer <t>`, `Authorization:
token <t>`, HTTP Basic (token as username or password — covers pip/Go/cargo), or
the `X-Api-Token` / `X-Auth-Token` headers.

### OIDC / JWT (`auth.oidc`)

Bearer JWTs are verified against the issuer's asymmetric keys (RS256/384/512,
ES256/384/512) fetched from `jwksUrl` (cached) or pinned via inline `jwks`. The
verifier validates the signature and the `exp`, `nbf`, `iss`, and `aud` claims.
**`alg=none` and HMAC algorithms are rejected** to prevent algorithm-confusion
downgrade attacks. Subject/team/roles are read from configurable claims
(`subjectClaim`, `teamClaim`, `rolesClaim`); IdP group names can be translated
with `roleMap`.

## Authorization (RBAC)

A pull of upstream `U` (ecosystem `E`) is allowed iff some role the caller holds
satisfies **both**: `E ∈ ecosystems` (or `"*"`) **and** `U ∈ upstreams` (or
`"*"`). Empty lists match nothing. Examples:

```yaml
roles:
  - name: npm-reader        # all npm upstreams, nothing else
    ecosystems: ["npm"]
    upstreams: ["*"]
  - name: corp-mirror-only  # one named upstream, any ecosystem it serves
    ecosystems: ["*"]
    upstreams: ["corp-mirror"]
  - name: admin             # everything
    ecosystems: ["*"]
    upstreams: ["*"]
```

Denied requests return `401` (unauthenticated), `403` (unauthorized), or `429`
(quota exhausted).

## Multi-tenancy & quotas

Each principal has a `team`. Quotas are per team (`auth.teams.<team>.quota`, with
`auth.defaultQuota` as fallback):

- `maxRequests` — admitted pulls per `window`
- `maxBytes` — bytes served per `window`
- `window` — rolling reset period (`0` = a hard cumulative cap)

Quota is consumed only **after** a request is authorized, so denied requests
never burn a tenant's budget. Set `auth.cacheNamespacing: true` to additionally
partition cached content by team namespace (trading cross-tenant dedup for
isolation). Team names are sanitized to a path-safe namespace, preventing
traversal or case-folding collisions.

## Tamper-evident audit log

When `audit.enabled: true`, every pull (with cache HIT/MISS/BYPASS, status,
bytes) and every deny decision is appended to a **keyed hash chain**: each record
stores `seq`, the event, the previous record's hash, and an HMAC-SHA256 of the
whole thing under `audit.hmacKey`. Records are newline-delimited JSON (greppable)
and `fsync`-ed per write.

Editing, deleting, or reordering any record breaks the chain.

### Merkle transparency log (signed checkpoints)

On top of the hash chain the proxy maintains an **RFC 6962 Merkle transparency
log**. Periodically (every `audit.transparency.sealEvery` records and/or every
`sealInterval`, and once at shutdown) it seals a **checkpoint** — a signed tree
head: the Merkle root over the records sealed so far. Checkpoints are persisted
out-of-band in `<file>.checkpoints`. This adds a second, key-independent
guarantee:

- The hash chain detects tampering **to anyone holding the HMAC key**.
- A sealed (ideally signed) checkpoint detects a retroactive edit, deletion, or
  truncation **even without the HMAC key** — an attacker who steals the key and
  re-forges a self-consistent chain still cannot make an altered prefix match a
  previously-sealed root. Signing (`signingKeyFile`/`signingKey`, the same kind
  of key material the signature-verification gate uses) anchors checkpoints to
  the operator's key so a forged checkpoint is rejected too.

The transparency layer also yields **inclusion proofs** (a specific event is in
the log) and **consistency proofs** (the log only grew, append-only).

### Verifying a log

```sh
# Subcommand form (full transparency cross-check):
pullthrough verify-audit -log /var/lib/pullthrough/audit/audit.log \
  -key "$PTS_AUDIT_HMAC_KEY" -pubkey audit-pub.pem
# verify-audit: hash chain OK — 12345 records form an intact tamper-evident chain
#   checkpoint treeSize=12000 root=9be418288fcb… signed+verified [OK]
#   ...
# verify-audit: transparency OK — 13 checkpoints consistent with the log
```

`-checkpoints` defaults to `<log>.checkpoints` when present, and `-pubkey` is
optional (omit it to skip signature checks). The legacy
`-verify-audit <log> -audit-key …` flag form is still accepted. It exits
non-zero and names the first break (chain, checkpoint root, or signature) on
tampering, so it can be run from monitoring/CI. The chain and Merkle tree both
resume across restarts.

### Admin API & metrics

The admin API exposes the latest checkpoint and on-demand proofs:

- `GET <adminPrefix>/api/audit` — chain length, tree size, checkpoint count,
  last-seal time, verification-failure count, and the latest checkpoint.
- `GET <adminPrefix>/api/audit/checkpoint` — the latest signed checkpoint.
- `GET <adminPrefix>/api/audit/proof?seq=N` — an inclusion proof for record `N`.
- `GET <adminPrefix>/api/audit/consistency?from=A&to=B` — a consistency proof.

Prometheus metrics: `pullthrough_audit_chain_length`,
`pullthrough_audit_tree_size`, `pullthrough_audit_checkpoints_total`,
`pullthrough_audit_last_seal_timestamp`, and
`pullthrough_audit_verification_failures_total`.

> The audit log is integrity-protected, not encrypted; it deliberately contains
> no secrets (no tokens, no credentials).

## Secrets at rest

Any config value carrying the `enc:v1:` prefix is decrypted at load time with
the master key from `secrets` (resolved as `keyEnv` → `keyFile` →
`passphrase`+`salt`). Plaintext, `${ENV}`, and encrypted values can be mixed, so
you can migrate incrementally. An `enc:v1:` value with **no** configured key is a
hard error (never a silent passthrough of ciphertext). Encryption is
AES-256-GCM, which also authenticates the ciphertext — a tampered or wrong-key
value fails to decrypt rather than yielding garbage.

Fields that support `enc:v1:`: upstream credentials, `scanning.apiKey`,
`provenance.githubToken`, `observability.adminToken`, `auth.tokens[].token`, and
`audit.hmacKey`.
