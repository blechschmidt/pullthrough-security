# Threat model

This document states what `pullthrough-security` is designed to defend against,
the trust assumptions it makes, and the threats it explicitly does **not** cover.
It complements the mechanism docs:
[security-model.md](security-model.md) (scanning/provenance/policy) and
[access-control-and-audit.md](access-control-and-audit.md) (authn/authz/audit).

## Assets

- **Developer & CI workstations** that install dependencies and pull images.
- **The artifacts themselves** — packages, modules, container images, Git refs.
- **The proxy's trust signals** — scan verdicts, provenance links, policy
  decisions, and the audit log.
- **Secrets** held by the proxy — upstream credentials, LLM API keys, the audit
  HMAC key, admin/auth tokens.

## Trust boundaries

```
   developers / CI          PROXY (trusted, you operate it)        upstreams
   (semi-trusted)   ──────▶  authn · authz · policy · cache  ──────▶ (untrusted)
                            scanning · provenance · audit
```

- **Clients** are *semi-trusted*: authenticated and authorized, rate-limited per
  tenant, but assumed capable of requesting malicious packages (knowingly or not).
- **Upstreams** (registries, forges, the LLM API) are *untrusted for integrity*:
  they may serve corrupted, tampered, or malicious content, or be impersonated.
- **The proxy** is the *trusted enforcement point*. Compromise of the proxy host
  compromises the model; harden and monitor it accordingly.

## Threats addressed

### T1 — Malicious package / commit reaching builds
A dependency contains a backdoor, data-exfiltration, or build-tampering change.
**Mitigation:** LLM commit scanning produces a risk score and `malicious` verdict;
the policy engine blocks (`blockMalicious`, `blockAtRiskScore`) before the
artifact is cached or served. Findings and rationale are surfaced in the 403 body
and the admin dashboard. Where the malice is in the published artifact rather
than in any commit — an extra install script in the tarball, a payload added at
publish time — the [LLM package-content scan](llm-package-scan.md) has a model
read the unpacked artifact itself and refuses (and evicts) what it judges
malicious before the first byte is served. *Residual risk:* LLM analysis is
probabilistic — see [Limitations](#limitations-and-non-goals).

### T2 — Artifact ↔ source mismatch / unverifiable origin
An artifact's published bytes don't correspond to the source it claims, or its
origin can't be established. **Mitigation:** provenance resolution links artifacts
to a repo/commit with a confidence level; policy can require `minConfidence`,
`requireSignature`, or full `requireAttested` (verified signature → trusted root),
and `failClosed` to refuse the unverifiable.

### T3 — Upstream content tampering / MITM
A compromised mirror or network attacker alters bytes in flight.
**Mitigation:** digest-addressed content (Docker blobs and manifests-by-digest,
ecosystem artifacts addressed by hash) is verified against its expected digest
before caching or serving — a mismatch aborts the stream. Upstream TLS is verified
by default (`outbound.tls.minVersion` ≥ 1.2; `insecureSkipVerify` is opt-in and
flagged unsafe); private mirrors can pin a CA via `outbound.tls.caCertFile` or a
per-upstream `tls` override.

### T4 — Unauthorized access / tenant abuse
An untrusted party uses the proxy, or one tenant exhausts shared capacity.
**Mitigation:** authentication (static tokens / OIDC-JWT), deny-by-default RBAC
scoped per ecosystem+upstream, and per-team quotas (`maxRequests`/`maxBytes`/
`window`). Denied requests never reach an upstream or burn a tenant's quota.
JWT verification rejects `alg=none` and HMAC algorithms (algorithm-confusion
downgrade).

### T5 — Credential exposure
Upstream tokens and API keys leak from config or are sent to the wrong party.
**Mitigation:** clients authenticate to the *proxy*, never to upstreams; the proxy
injects upstream credentials server-side. Secrets support `${ENV}` and
`enc:v1:` (AES-256-GCM) at-rest encryption, and are kept out of ConfigMaps/images
in the deployment manifests. The proxy does not forward an upstream's login or
token endpoints: such a request would be answered for the proxy's own account
and the minted credential relayed to the client. The Conan login endpoints
(`/v2/users/authenticate`, `/v2/users/check_credentials`) and everything under a
registry's `/v2/` that is not a pull endpoint (which is where Artifactory, Nexus
and Quay host their token service) are refused for that reason. Package and
registry backends are served over `GET` and `HEAD` only — any other method is
answered with `405` before a backend sees it — so nothing can be published,
changed or revoked with the proxy's credentials. See the limitation on
[upstream credentials](#limitations-and-non-goals) for what remains.

### T6 — Tampering with accountability records
An attacker covers tracks by editing the audit trail. **Mitigation:** the audit
log is a keyed hash chain (HMAC-SHA256) — any edit, deletion, or reordering is
detectable with `-verify-audit`, which is runnable from monitoring/CI.

### T7 — Upstream outage / availability
An upstream is down or rate-limiting. **Mitigation:** the content-addressable
cache continues serving previously pulled artifacts; single-flight collapses
concurrent misses; per-upstream credentials raise rate limits (e.g. Docker Hub).
This is a side benefit, not a high-availability guarantee.

## Trust assumptions

- The **proxy host and its filesystem** (`/var/lib/pullthrough`: cache, audit log,
  scan/provenance stores) are trusted and access-controlled. An attacker with
  write access to the cache directory can serve poisoned content; with the audit
  HMAC key, can forge audit records.
- The **configuration and its secrets** are protected; the `secrets` master key
  and `audit.hmacKey` are managed out-of-band (env/secret store), not committed.
- The **LLM provider** is trusted to return analysis (not to be exfiltrated to).
  Commit diffs — and, when the LLM package-content scan is enabled, the contents
  of scanned packages — are sent to the provider; see
  [Data handling](#data-handling). Its *answers* are not trusted: a verdict is
  parsed strictly and cross-checked, and content under review is treated as an
  attempt to steer the model (see
  [llm-package-scan.md](llm-package-scan.md#prompt-injection-defenses)).
- **Trust roots** (`provenance.trustRootsFile`) are authentic; a wrong root
  silently weakens attestation guarantees.
- **TLS PKI** for upstreams is intact unless you pin CAs explicitly.

## Limitations and non-goals

- **Pull-only.** The proxy never publishes upstream; it does not protect *your*
  publishing pipeline or registries you push to.
- **Upstream credentials authorize every read the proxy forwards.** A client
  that may use an upstream reads through it as the proxy's upstream account.
  Most backends have a protocol route table and forward only that protocol's
  read endpoints: bazel, composer, conan, conda, cpan, cran, dart, docker,
  hackage, helm, hex, huggingface, jsr, julia, maven, nix, rubygems and
  terraform refuse an account or token path outright. **npm, pip, cargo, go,
  nuget, ansible, puppet, apt and yum** do not: they forward any `GET` beneath
  the configured upstream `url` (openvsx and homebrew do so for paths under
  `/api/`). That includes whatever account-information or credential-helper
  endpoint the upstream serves there — npm's `/-/whoami`, a repository
  manager's per-repository `auth` helper — answered for the proxy's account.
  Until those backends have route tables of their own, give each credentialed
  upstream a dedicated **read-only** account scoped to the repositories it
  fronts — never a personal or administrative one — prefer a revocable token
  over a password, and point `url` at the repository rather than at the host
  root.
- **Probabilistic scanning.** LLM commit analysis can produce false negatives
  (missed malice) and false positives. It is a strong signal, not a proof; tune
  `failOn`/`blockAtRiskScore` to your risk tolerance and keep humans in the loop
  for blocks. Verdicts are cached per SHA — a model improvement doesn't re-score
  already-seen commits unless the store is cleared.
- **Static analysis only; nothing is detonated.** Commit scanning judges
  commits. The artifact's own bytes are examined by the deterministic content
  gates and, when enabled, by the [LLM package-content scan](llm-package-scan.md)
  — all of them read the artifact and none of them runs it. There is no sandbox
  detonation and no observation of runtime behavior, binary members are not
  read by the LLM, and a verdict on a package too large to show in full says so
  (`truncated`) rather than claiming more than it saw.
- **No coverage without provenance.** An artifact with no resolvable source link
  can't be scored on its commit; the `onMissingProvenance`/`onMissingScan`
  actions decide how that gap is treated.
- **Not a WAF / DoS shield.** Quotas bound per-tenant volume but the proxy is not
  a denial-of-service mitigation; place it behind your normal ingress controls.
- **Client trust on first use (Git SSH).** If `git.ssh.hostKeyFile` is unset, the
  host key is ephemeral; pin a stable key and distribute the fingerprint.
- **Trust-on-deploy for cache integrity.** The cache assumes its backing store is
  honest; it does not continuously re-verify already-cached content.

## Data handling

- **Commit diffs** are transmitted to the configured LLM provider for analysis.
  In regulated or air-gapped environments, point `scanning.baseUrl` at a
  self-hosted/approved gateway, or disable scanning.
- **Package contents** are transmitted to the configured LLM provider when
  `llmPackageScan` is enabled. For public registries that is public data; for a
  private registry it is your source code. List such upstreams under
  `llmPackageScan.excludeUpstreams` (their artifacts are then never opened for
  scanning), or point `llmPackageScan.baseUrl` at an endpoint you are entitled
  to send that code to. Configuration preflight warns about every authenticated
  upstream that would be scanned. Stored verdicts quote the package and are
  shown, on the admin surface, only to tenants that pulled those bytes.
- **The audit log is integrity-protected, not encrypted**, and deliberately
  contains no secrets (no tokens/credentials).
- **Provenance lookups** contact GitHub (or your `githubApiBase`) and signature
  transparency services; restrict egress accordingly.

## Operator responsibilities

- Run with `auth.enabled: true` and deny-by-default RBAC in any shared/production
  deployment; keep the admin API behind `adminToken` and/or network policy.
- Set stable keys: `git.ssh.hostKeyFile`, `audit.hmacKey`, `secrets` master key.
- Keep upstream TLS verification on; pin CAs for private mirrors.
- Give every credentialed upstream its own read-only, repository-scoped service
  account and token (see [Limitations](#limitations-and-non-goals)): whoever may
  pull through an upstream reads with those credentials.
- Periodically run `-verify-audit` (see [runbook.md](runbook.md)).
- Treat the proxy host as a high-value target: minimal surface, patched,
  monitored, with restricted access to `/var/lib/pullthrough`.
