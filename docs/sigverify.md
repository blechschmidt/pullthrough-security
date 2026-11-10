# Signature & attestation verification (sigverify)

The signature-verification gate (`internal/sigverify`) cryptographically verifies
artifact signatures and provenance attestations **before** content is cached or
served. It is the supply-chain *authenticity* counterpart to the vulnerability
gate ([SBOM/OSV](configuration.md)) and the [name guard](configuration.md): it
proves *who produced an artifact and that it has not been tampered with*, rather
than scanning the artifact's contents.

It exposes the same admission-gate shape as the other gates — a `Verify` step
produces a `Report`, and `Gate` maps that report onto an admission `Decision`
(`allow` / `warn` / `block` / `quarantine`) using configurable severity
thresholds — and is wired into the pull path alongside them.

## What it verifies

| Ecosystem | Material | Discovery |
|-----------|----------|-----------|
| Docker / OCI | cosign signatures + SLSA provenance attestations | OCI Referrers API, then the cosign tag scheme `sha256-<hex>.sig` / `.att` |
| npm | Sigstore publish attestations (DSSE bundles) | `/-/npm/v1/attestations/<name>@<version>` |
| pip / PyPI | PEP 740 provenance | best-effort (requires the artifact filename) |

Two trust models are supported, matching cosign:

- **Keyless (Fulcio/Rekor).** The signing certificate is short-lived and issued
  by Fulcio against an OIDC identity. Trust requires the certificate to chain to
  a configured **Fulcio root**, and the certificate's **identity** (SAN URI/email)
  and **OIDC issuer** to match the configured allowed-identity policy. Optionally
  a **Rekor transparency-log inclusion proof** (the bundle's Signed Entry
  Timestamp) must verify against a configured Rekor public key.
- **Keyed.** The signature verifies against one of a set of operator-configured
  public keys.

The verifier confirms the signature over the DSSE pre-authentication encoding
(for attestations) or the cosign simple-signing payload (for image signatures),
checks that the signed payload **binds the artifact's content digest** (an
attestation for a different artifact is rejected even if cryptographically
valid), and resolves signer trust. SLSA provenance predicates are parsed to
surface the source repository, commit, and builder for the inspection surface.

## Enforcement modes

`action` selects the enforcement mode applied when a finding meets `failSeverity`:

- `block` / `quarantine` — **required/enforcing**: an unverifiable artifact is
  refused (and, for `quarantine`, evicted from the cache).
- `warn` — **advisory**: the artifact is served with `X-Sigverify-*` response
  headers and an audit/alert record, so the condition is visible without breaking
  builds during rollout.

Findings carry severities so a graduated policy is possible:

| Finding | Severity |
|---------|----------|
| `invalid-signature` (present but does not verify — possible tamper) | critical |
| `untrusted-identity` (valid signature, untrusted chain/identity) | high |
| `untrusted-key` (no configured key matched) | high |
| `missing-signature` (when `requireSignature`) | high |
| `missing-rekor-proof` (when `requireRekorProof`) | high |
| `missing-attestation` (when `requireAttestation`) | medium |

`failOnError` controls behavior when verification material cannot be fetched or
parsed (an infrastructure error, distinct from a verification failure): the
default serves with a warning (fail-open); `true` blocks (fail-closed).

## Configuration

See the [`sigverify` block in `config.example.yaml`](../configs/config.example.yaml).
Key fields:

```yaml
sigverify:
  enabled: true
  ecosystems: [docker, npm]
  action: block
  requireSignature: true
  requireAttestation: false
  requireRekorProof: false
  trustRootsFile: /etc/pullthrough/fulcio-root.pem
  rekorKeyFiles: [/etc/pullthrough/rekor.pub]
  identities:
    - issuer: https://token.actions.githubusercontent.com
      subjectPattern: ^https://github\.com/acme/.*
  keys:
    - name: release-signing-key
      file: /etc/pullthrough/cosign.pub
```

An empty `identities` list trusts **any** identity that chains to the configured
root — tighten it to your build system's workflow identities in production.

## Air-gapped / offline trust bundle

For disconnected deployments the trust material — Fulcio roots, Rekor keys,
public keys, and the identity policy — is packaged into a portable **trust
bundle** and transferred to the sealed instance exactly as the
[air-gapped cache mirror](air-gapped.md) is. The bundle is a deterministic,
canonical-JSON document whose SHA-256 digest is its stable identity (mirroring
the mirror subsystem's bundle design); the digest is transferred out-of-band and
verified on load.

```yaml
sigverify:
  enabled: true
  offline: true
  trustBundleFile: /etc/pullthrough/sigverify-trust.json
  trustBundleDigest: "sha256:…"   # optional out-of-band integrity check
```

In offline mode the OCI source still reads cosign signatures from the (mirrored)
registry; pre-warm the `.sig` / `.att` artifacts alongside the images.

## Post-quantum & hybrid signatures

The gate can optionally verify **post-quantum** and **hybrid classical+PQC**
signatures so cosign/Sigstore bundles and attestations signed with quantum-safe
key material are admissible during (and after) the PQC migration. The supported
algorithms are the NIST standards **ML-DSA** (FIPS 204, formerly Dilithium) and
**SLH-DSA** (FIPS 205, formerly SPHINCS+), plus hybrid `Ed25519-Dilithium2` /
`Ed448-Dilithium3` composites. Classical RSA/ECDSA/Ed25519 remain verified by
the Go standard library; the post-quantum primitives are provided by
`cloudflare/circl`.

Support is **off by default**. Enable it and choose how PQC participates in the
trust decision:

```yaml
sigverify:
  enabled: true
  pqc:
    enabled: true          # default false
    policy: allow-hybrid    # classical-only | allow-hybrid | require-pqc
  keys:
    - name: release-pqc-key
      file: /etc/pullthrough/release-mldsa65.pub.pem
```

- **`classical-only`** — a presented PQC/hybrid signature is cryptographically
  checked (for reporting) but never establishes trust. Use it to stage PQC key
  distribution before sanctioning PQC trust.
- **`allow-hybrid`** (default when enabled) — classical, hybrid, and pure PQC
  signatures all establish trust.
- **`require-pqc`** — demands post-quantum protection: an artifact whose only
  trusted signature is classical is flagged **quantum-vulnerable** and gated.

A post-quantum public key is configured as a PEM block of type
`PQC PUBLIC KEY` carrying the scheme in its header, e.g.:

```
-----BEGIN PQC PUBLIC KEY-----
Scheme: ML-DSA-65

<base64 raw public key>
-----END PQC PUBLIC KEY-----
```

**FIPS interaction.** The `cloudflare/circl` provider implements the FIPS 204 /
205 *algorithms* but is **not itself a FIPS 140-3 validated cryptographic
module**. To avoid a false sense of compliance, enabling `sigverify.pqc` while
`fips.enabled` is set **fails startup preflight** with a clear message rather
than silently disabling PQC or running a non-validated provider. Choose one or
the other until the provider completes validation.

The per-verification algorithm (e.g. `ML-DSA-65`) is recorded in the
tamper-evident audit log and surfaced in the verification report
(`algorithms`, `postQuantum`). Served responses signed with a PQC/hybrid key
carry `X-Sigverify-PQC: true`.

## Observability

**Metrics** (`/metrics`): `pullthrough_sigverify_verifications_total`,
`_verified_total`, `_unsigned_total`, `_blocked_total`, `_warned_total`,
`_quarantined_total`, `_signatures_checked_total`, `_attestations_parsed_total`,
`_rekor_verified_total`, `_errors_total`, and the `pullthrough_sigverify_cache_entries`
gauge. When post-quantum verification is enabled:
`pullthrough_sigverify_pqc_signatures_total`, `_pqc_verified_total`,
`_pqc_rejected_total`, and the per-algorithm
`pullthrough_sigverify_pqc_algorithm_signatures_total{algorithm,class}`.

**Admin API** (under the admin prefix):

- `GET /api/sigverify` — list cached verification reports (filter with `?q=`),
  with the cumulative metrics.
- `GET /api/sigverify/entry?digest=<digest>` — the full verification report for
  an artifact, including every signature/attestation result and the extracted
  SLSA source reference.

**Audit & alerts.** Every block/warn/quarantine is recorded in the tamper-evident
audit log (`sigverify:<code>`) and dispatched as a provenance-failure
[notification](notifications.md).

**Response headers.** Served responses carry `X-Sigverify-Decision`
(`allow`/`warn`), `X-Sigverify-Attested: true` when an attestation verified, and
on a refusal an actionable `403` JSON body plus `X-Sigverify-Code` /
`X-Sigverify-Reason`.
