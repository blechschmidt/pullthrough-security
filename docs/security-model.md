# Security model: scanning, provenance & policy

The proxy's supply-chain defense is three cooperating layers:

1. **Scanning** — an LLM analyzes the Git commits behind code to flag malicious
   or suspicious changes, producing a per-commit **risk score** and **verdict**.
2. **Provenance** — artifacts (npm tarballs, wheels, Go modules, container
   images, …) are linked back to the source repository and commit that produced
   them, with a **confidence** level.
3. **Policy** — an admission engine turns those signals into an **allow / warn /
   block** decision *before* an artifact is cached or served.

Each layer is independent and **off by default**. Scanning and provenance produce
*signal*; policy is what *enforces*. You can run any subset (e.g. provenance +
policy with no LLM, or scanning for visibility with policy disabled).

This page covers the trust mechanics. For the threat boundaries, see
[threat-model.md](threat-model.md); for client access control and audit, see
[access-control-and-audit.md](access-control-and-audit.md).

---

## Scanning (LLM commit analysis)

Configured under [`scanning`](configuration.md#scanning).

### What it does

When a pull resolves to a source commit (via provenance), that commit is queued
for asynchronous analysis. The pipeline:

1. **Triage** every commit with a cheap, fast model
   (`commit.triageModel`, default `claude-haiku-4-5-20251001`): it inspects the
   commit metadata and diff and emits a preliminary risk score.
2. **Escalate** to a capable model (`commit.deepModel`, default
   `claude-opus-4-8`) when the triage score reaches `commit.escalateAtScore`
   (default `25`). Large diffs are chunked within a token budget
   (`commit.maxDiffTokens`, `commit.maxChunks`).
3. **Persist** the verdict keyed by commit SHA (`commit.storeDir`), so a commit
   is never re-scanned and verdicts survive restarts.

Scanning is asynchronous: it never blocks the pull on the LLM round-trip. The
verdict feeds the *next* policy evaluation for artifacts from that commit; until a
verdict exists, policy treats the commit per `onMissingScan`.

### Providers

- **`claude`** — implemented. Uses the Anthropic API; the key comes from
  `scanning.apiKey` (or the `ANTHROPIC_API_KEY` environment variable / the
  `PTS_SCAN_API_KEY` override). `scanning.baseUrl` can point at a gateway.
- **`openai`** (alias **`codex`**) — implemented. Targets the OpenAI Chat
  Completions API; the key comes from `scanning.apiKey` (or the `OPENAI_API_KEY`
  environment variable / the `PTS_SCAN_API_KEY` override). `scanning.baseUrl`
  points at the public API by default and can be redirected to Azure OpenAI
  (set `scanning.apiVersion` for Azure's `api-version`/`api-key` convention) or
  any OpenAI-compatible gateway (vLLM, LiteLLM, OpenRouter, a corporate proxy).
  It shares the same prompt, chunking, consensus, budget, and verdict-store
  plumbing as the Claude provider, so the two are fully interchangeable; only
  the model ids and the wire protocol differ. The provider applies its own
  retry/backoff (honoring `Retry-After`) on `429`/`5xx`/network errors in
  addition to the pipeline's outer retry loop.
- **`none`** — disables scanning explicitly.

### The verdict model

A **Verdict** records, per commit SHA:

| Field | Meaning |
|-------|---------|
| `riskScore` | `0` (benign) … `100` (almost certainly malicious). Model-assigned, clamped to range. |
| `malicious` | Boolean kill-switch flag — overrides severity-based passing. |
| `findings[]` | Individual issues (see below). |
| `rationale` | Human-readable explanation. |
| `provider`, `models` | What produced the verdict (auditability). |
| `escalated`, `chunked`, `truncated` | Pipeline status flags. |
| `inputTokens`, `outputTokens` | Cost accounting. |
| `error` | Set when the scan itself failed. |
| `scannedAt` | Timestamp. |

Each **Finding** carries a `category`
(`malicious_code`, `secret`, `obfuscation`, `suspicious_dependency`,
`data_exfiltration`, `backdoor`, `build_tampering`, `other`), a **severity**, a
title/detail, optional `file`/`line`, and a `confidence` (0–1).

**Severity levels** (ascending): `info` < `low` < `medium` < `high` < `critical`.

### `failOn`

`scanning.failOn` (default `high`) is the minimum severity at which a commit is
considered *not passing*. A commit passes when its highest-severity finding is
below `failOn` — **unless** `malicious` is set, which never passes. This pass/fail
verdict and the raw `riskScore` are both available to the policy engine.

---

## Provenance (package → commit)

Configured under [`provenance`](configuration.md#provenance).

### What it does

For each artifact, a chain of resolvers attempts to establish a link to the
source **repository and commit**, returning the highest-confidence result. The
chain runs strongest-first and short-circuits once a fully attested link is found;
hints (e.g. a repository URL from package metadata) are threaded forward to help
later resolvers.

### Resolvers

| Resolver | Mechanism | Typical confidence |
|----------|-----------|--------------------|
| **GitHub attestations** | `GET /repos/{owner}/{repo}/attestations/{algo}:{digest}` → Sigstore bundle, signature-verified, subject-digest matched. | `attested` |
| **OCI / cosign** | Cosign / Sigstore attestations resolved from the OCI registry (docker/oci ecosystems). | `attested` |
| **npm** | Signed npm provenance attestations first, else the packument `repository` field. | `attested` / `claimed` |
| **PyPI** | Project repository URL from package metadata. | `claimed` |
| **Go** | Module path → VCS, pseudo-version → commit. | `claimed` |
| **Heuristics** | Tag matching, file-hash matching. | `heuristic` |

A `githubToken` raises API rate limits and reaches private repositories;
`githubApiBase` targets GitHub Enterprise.

### Confidence levels

Ascending trust:

- **`heuristic`** — inferred (e.g. a matching tag or file hash). Weakest.
- **`claimed`** — asserted but not cryptographically verified (e.g. a
  `repository` URL in package metadata).
- **`attested`** — backed by a verified signed attestation (SLSA / in-toto via
  Sigstore).

### Verification & trust roots

An attestation is **fully attested** only when *both* hold:

- **Signature verified** — the DSSE signature checks out against its signing
  certificate, **and**
- **Chain trusted** — that certificate chains to a configured trust anchor.

Set `provenance.trustRootsFile` to the Sigstore Fulcio root (or a corporate CA).
With a root configured, signatures chaining to it are labeled `attested`;
otherwise a verified-but-unchained signature is downgraded to `claimed`. With no
`trustRootsFile`, `useSystemTrustRoots: true` falls back to the system CA pool.

`provenance.requireAttested: true` is a coarse switch that rejects artifacts
lacking verified provenance; the `policy` engine offers finer, per-ecosystem
control.

### Operator pins

Attestations and registry metadata cover only part of the ecosystems the proxy
fronts: most registries publish neither, and an internal package often has no
public metadata at all. For those, an operator states the association explicitly
with a **pin**:

```yaml
provenance:
  enabled: true
  pins:
    - ecosystem: npm                 # the upstream type; omit or "*" for any
      name: "@acme/widgets"          # the package, as the backend reports it
      version: "1.4.2"               # exact; omit to pin every version
      repository: https://github.com/acme/widgets
      commit: 0123456789abcdef0123456789abcdef01234567   # full hash
```

- A pin is **authoritative** for the coordinates it matches: it is consulted
  before previously stored links and before the resolver chain, so an explicit
  operator assertion is never shadowed by a metadata-derived link. The most
  specific pin wins (exact version over every-version, exact ecosystem over any).
- The pinned commit's **scan verdict gates the package** through the admission
  policy exactly as an attested link would: a package pinned to a commit the
  scanner flagged malicious is refused (`blockMalicious`, `blockAtRiskScore`).
  Have the commit scanned by watching the repository (`scanning.watch`).
- A pin is an **assertion, not evidence**: the link is recorded with `claimed`
  confidence under the resolver name `operator-pin`, and never satisfies
  `requireAttested` or `requireSignature`.
- Removing or narrowing a pin takes effect at the next start; a link recorded
  from a pin is not honored once no pin asserts it any more.
- `name` is matched case-insensitively and must be the coordinate the backend
  reports — the `package` field of a policy record in the audit log — which
  follows the ecosystem's protocol, not always the name a user types: a Maven
  `groupId:artifactId`, a CPAN distribution (`Try-Tiny`, not `Try::Tiny`), a
  Julia package UUID, a Nix store-path hash, an OCI repository
  (`library/alpine`).

The real-package-manager [ecosystem tests](ecosystem-tests.md) use pins to gate
every ecosystem's packages on an LLM scan verdict; the pin each test uses is
listed in [ecosystem-tests-reference.md](ecosystem-tests-reference.md).

---

## Policy (admission gating)

Configured under [`policy`](configuration.md#policy). The engine runs as
admission middleware **before** the cache or upstream is consulted.

### Actions

- **`allow`** — serve normally.
- **`warn`** — serve, but record a warning: the response carries
  `X-Policy-Decision: warn` (and `X-Policy-Code` / `X-Policy-Reason`) and an audit
  event is written.
- **`block`** — refuse to serve. Nothing is cached or fetched.

An empty/unset action means `allow` (that check is disabled).

### What a block looks like

A blocked pull returns **HTTP 403** with an actionable JSON body:

```json
{
  "error": "artifact blocked by supply-chain admission policy",
  "code": "risk-score",
  "reason": "source commit risk score 88 >= block threshold 80",
  "ecosystem": "npm",
  "package": "left-pad",
  "version": "1.3.0",
  "commitSha": "…",
  "riskScore": 88,
  "provenanceConfidence": "attested"
}
```

and response headers `X-Policy-Decision: block`, `X-Policy-Code: <code>`,
`X-Policy-Reason: <reason>`, `X-Cache: BLOCKED`.

### Decision codes

| `code` | Triggered when |
|--------|----------------|
| `ok` | Admitted. |
| `denylist` | Package name matched `denylist`. |
| `allowlist` | `allowlist` non-empty and the package isn't on it. |
| `malicious` | Scanner flagged the source commit malicious (`blockMalicious`). |
| `risk-score` | Risk score ≥ `blockAtRiskScore`. |
| `missing-provenance` | No package→commit link (`onMissingProvenance`). |
| `missing-scan` | Provenance exists but the commit was unscanned (`onMissingScan`). |
| `signature-required` | `requireSignature` and the signature didn't verify. |
| `attestation-required` | `requireAttested` and the link isn't fully attested. |
| `low-confidence` | Confidence below `minConfidence` (`onLowConfidence`). |

### Rule resolution

`policy.default` applies to every ecosystem. An entry under
`policy.ecosystems.<name>` **fully replaces** the default for that ecosystem (it
is not merged) — so per-ecosystem rules must restate every field they care about.

```yaml
policy:
  enabled: true
  failClosed: false
  default:
    blockAtRiskScore: 80
    warnAtRiskScore: 50
    blockMalicious: true
    onMissingProvenance: warn
    onMissingScan: allow
  ecosystems:
    docker:
      requireAttested: true   # only serve images with attested provenance
      blockAtRiskScore: 60
      blockMalicious: true
    npm:
      denylist: ["event-stream", "@evilscope/*"]
      blockAtRiskScore: 80
      blockMalicious: true
```

### `failClosed`

When a provenance lookup or scan assessment **errors**:

- `failClosed: false` (default) — *fail open*: serve the artifact and emit a
  `warn`, so a transient provenance-backend outage degrades to a warning rather
  than halting all pulls.
- `failClosed: true` — *fail closed*: block on assessment error. Choose this for
  high-assurance environments where unverifiable means untrusted.

---

## Name guard (typosquatting & dependency confusion)

Configured under [`nameguard`](configuration.md#nameguard). A **name-based**
admission gate that inspects the package *coordinate* — not its content — so it
runs at the very front of the pull path, before any upstream fetch or cache fill,
and fires as soon as a name is known (even at index lookup, before a specific
version is downloaded). It is independent of scanning/provenance and **off by
default**.

Three heuristic families produce findings, each carrying a severity:

- **Typosquatting** — a name within a small Damerau-Levenshtein edit distance of a
  popular package (`reqeusts` → `requests`), or visually identical after folding
  look-alike substitutions (`1odash`/`l0dash` → `lodash`, `rn` → `m`). Popular
  names come from a built-in per-ecosystem seed list merged with your
  `popularNames`; a configurable `allowlist` suppresses legitimate near-neighbors
  (e.g. `preact` vs `react`).
- **Dependency confusion** — a public-registry name that collides with one of your
  configured `internalNamespaces` (exact private names, or namespace prefixes like
  `@acme` / `github.com/acme/*`). This is the classic confusion vector and is the
  highest-severity finding. **This is the key knob to set.**
- **Homoglyph / mixed-script** — non-ASCII look-alike characters in a name (a
  Cyrillic `а` standing in for Latin `a`); critical when the ASCII skeleton matches
  a popular name.

Findings map to an action with the same `warn` / `block` / `quarantine` vocabulary
as the policy gate, via `failSeverity` (default `high` → block) and `warnSeverity`
(default `medium` → warn). A block returns an actionable `403` with a
`X-Nameguard-Decision` header and a `didYouMean` hint; warnings serve the artifact
with an `X-Nameguard-*` advisory header. Every flagged pull emits an audit event
(`reason: nameguard:<kind>`) and increments
`pullthrough_nameguard_*_total` metrics. False positives are curbed by skipping
short names (`minNameLength`), tightening the distance threshold for short names,
and the allowlist.

```yaml
nameguard:
  enabled: true
  action: block
  failSeverity: high       # typosquats + homoglyphs + confusion → block
  warnSeverity: medium     # scope near-misses → warn
  internalNamespaces:
    npm: ["@acme", "acme-design-system"]
    pip: ["acme-internal"]
    go:  ["github.com/acme/*"]
```

---

## Cache integrity verification & self-healing

Configured under [`cache.integrity`](configuration.md). A **content-fixity**
defense for the content-addressable store itself: it detects tampering with, or
bit-rot of, already-cached bytes and heals from it. It is independent of the
scanning/provenance/policy layers above — those vet what enters the cache; this
guards what *stays* in the cache.

### The fixity baseline

Every blob the cache writes is recorded with a **content digest** (`sha256`)
computed over the exact bytes persisted, stored on the entry's metadata record
(`Record.Digest`, surfaced as the `digest` metadata key). It is computed on the
write path with no extra I/O pass:

- **Filesystem backend** — the digest is accumulated as the blob streams to disk.
- **S3 backend** — the digest reuses the SHA-256 the signed `PUT` already
  computes, so recording it is free.

Unlike an upstream `ETag` (a server-supplied validator), this digest is the
proxy's own authoritative fixity baseline. Entries written before digest
recording existed (empty digest) are **skipped** by verification rather than
treated as corrupt.

### On serve (read-time, streaming)

With `verifyOnServe: true` (the default), every **fully-served** immutable blob
is streamed through its recorded digest as the bytes flow to the client —
bounded memory, no whole-blob buffering, no second read. A byte-range or
otherwise partial read is **not** verified (a subset cannot be checked against
the whole-blob digest) and never raises a false alarm.

When the recomputed digest does not match the recorded one, the store has been
tampered with or has rotted. The proxy:

1. **Quarantines** the entry — removes it from the cache so it is never served
   again.
2. Increments **`pullthrough_integrity_failures_total`** and emits a
   tamper-evident **audit event** (`type: cache`, `decision: error`,
   `reason: integrity:corruption`) and an operator **notification**
   (`cache_integrity`, severity `cache.integrity.notifySeverity`, default
   `critical`).
3. **Self-heals**: because the poisoned entry is gone, the next pull misses and
   transparently re-fetches a clean copy from upstream.

> Streaming verification is detect-on-serve: a mismatch is known only at
> end-of-stream, so the *current* response may already have carried the corrupt
> bytes. That is caught by the client's own digest check (Docker verifies layer
> digests; most package managers verify hashes) and by its automatic retry,
> which hits the now-healed cache. To preserve bounded memory the proxy
> deliberately does not pre-buffer a blob to verify it before the first byte is
> sent.

### Background integrity scan (admin-triggered)

A never-served entry could rot undetected. The admin API triggers a full
re-verification pass that re-reads every cached blob and re-hashes it, reading
straight from the durable store so it does not distort LRU ordering or the
hit/miss ratio:

- **`POST /admin/api/integrity/scan`** — run a scan; returns counts of
  `scanned` / `verified` / `corrupted` / `skipped` / `errors`, the bytes
  re-hashed, and a bounded sample of corrupt keys. Any corruption it finds is
  quarantined and reported exactly as on the serve path (`source: scan`). At
  most one scan runs at a time.
- **`GET /admin/api/integrity`** — the current counters and the most recent scan
  report.

### Metrics

| Metric | Meaning |
|--------|---------|
| `pullthrough_integrity_verifications_total` | Complete verifications performed (serve + scan), pass or fail. |
| `pullthrough_integrity_failures_total` | Of those, the mismatches (tampering / bit-rot). A non-zero value is a serious supply-chain signal — alert on it. |

### Configuration

```yaml
cache:
  integrity:
    verifyOnServe: true      # stream every served blob through its stored digest
    notifySeverity: critical  # severity of the corruption notification
```

Disable `verifyOnServe` only if the per-serve hashing cost is unacceptable and
fixity is enforced elsewhere; the admin scan still works when it is off. For the
behavior across the filesystem and S3 backends in a multi-replica deployment,
see [ha-shared-cache.md](ha-shared-cache.md#cache-integrity-across-backends).

---

## Putting it together: a hardening progression

1. **Visibility** — `scanning.enabled: true`, `provenance.enabled: true`,
   `policy.enabled: true` with everything set to `warn`. Watch
   `X-Policy-Decision` headers, the [admin dashboard](runbook.md#admin-dashboard--api),
   and `pullthrough_policy_decisions_total` to learn your baseline.
2. **Block the unambiguous** — keep `blockMalicious: true` and set a high
   `blockAtRiskScore` (e.g. `90`); leave provenance gaps at `warn`.
3. **Raise the floor** — lower `blockAtRiskScore`, set `minConfidence: claimed`,
   and for sensitive ecosystems require attestation
   (`requireAttested: true`) and consider `failClosed: true`.
4. **Curate** — add `denylist` for known-bad packages, or an `allowlist` to
   restrict an ecosystem to a vetted set.
