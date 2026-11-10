# Outbound attestation bundle (proxy as attester)

The proxy does not only *verify* the attestations an artifact arrives with (the
inbound sigverify / provenance gates) — it **issues its own signed attestation**
for every artifact it admits and serves. This turns the proxy into a supply-chain
*attester*: downstream CI can require *"only deploy what our proxy admitted and
signed"*, and verify that claim offline against the proxy's public key.

Implemented in `internal/attestbundle` (Task 46).

## What is attested

When an artifact clears every admission gate and is about to be served, the proxy
assembles an [in-toto](https://github.com/in-toto/attestation) v1 Statement,
wraps it in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope, and
signs it. The statement binds, in one signed claim:

- **the served artifact's content digest** — the in-toto *subject*, so a verifier
  can tie the attestation to the exact bytes it is consuming;
- **its source repository and Git commit** — recovered from the provenance
  association (Tasks 8/33);
- **the admission verdicts it passed** — vulnerability scan (post-VEX), license,
  signature/attestation verification, secret scan, nameguard, the policy-as-code
  decision, and the unified risk score/band;
- **the VEX status** folded into the vulnerability verdict; and
- **the attester identity** — the proxy instance and its signing key id.

The bundle's digest is then embedded in the tamper-evident **audit log** (event
type `attestation`), so the audit chain commits to the exact bytes of every
attestation the proxy ever issued.

> An attestation only asserts what the proxy actually established at serve time. A
> gate that did not run is **omitted**, never reported as passed. The proxy only
> attests artifacts it admitted.

## Schema

### DSSE envelope (the signed, portable unit)

```jsonc
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(in-toto Statement)>",
  "signatures": [{ "keyid": "<short key id>", "sig": "<base64(signature)>" }]
}
```

The signature is over the DSSE **PAE** encoding
(`DSSEv1 <len> <payloadType> <len> <payload>`), exactly as cosign/Sigstore and the
proxy's own inbound verifier use, so off-the-shelf tooling can verify it.

### in-toto Statement (the DSSE payload)

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "<coordinate>", "digest": { "sha256": "<hex>" } }
  ],
  "predicateType": "https://pullthrough.dev/attestations/served/v1",
  "predicate": { /* see below */ }
}
```

### Predicate (`https://pullthrough.dev/attestations/served/v1`)

| Field | Meaning |
| --- | --- |
| `attester` | `{id, name, version, instance, keyId}` — the signing proxy (SLSA `builder.id` analogue). |
| `artifact` | `{ecosystem, backend, name, version, coordinate, digest, tenant}` — the admitted artifact. |
| `source` | `{repositoryUrl, commitSha, confidence, signatureVerified, chainTrusted}` — the associated source commit. Omitted when none was established. |
| `admission` | The serve-time verdicts (below). |
| `servedAt` | RFC 3339 UTC timestamp of admission/serving. |

`admission`:

| Field | Meaning |
| --- | --- |
| `verdict` | `admitted` (the proxy only attests admitted artifacts). |
| `warned` | true when any gate warned (non-blocking). |
| `gates` | Ordered `[{gate, decision: pass\|warn, summary}]` audit trail. |
| `vuln` | `{scanner, maxSeverity, total, criticalCount, highCount, vexSuppressed}` (post-VEX). |
| `license` | `{action, code, allowed}`. |
| `signature` | `{verified, attested, keyless, chainTrusted, slsaProvenance, identity, issuer}`. |
| `secret` | `{findingCount, maxSeverity}`. |
| `nameguard` | `{findingCount, maxSeverity, typosquat, dependencyConfusion}`. |
| `risk` | `{score, band}` — the unified composite risk score. |
| `policy` | `{action, matchedRules}` — the policy-as-code decision. |
| `vex` | `{suppressed, escalated}` — VEX adjudication counts. |

A canonical example is in
`internal/attestbundle/testdata/statement.golden.json`.

## Signing key

By default the proxy reuses the **audit-log checkpoint signing key**
(`audit.transparency.signingKey[File]`), so a deployment that already signs its
audit checkpoints becomes an attester with no extra key material. A dedicated key
may be configured instead. ECDSA, RSA, and Ed25519 PEM keys are supported (same
trust material as the signature-verification gate). With no signing key available
anywhere, the engine stays inactive (an unsigned attestation would be worthless)
and logs why.

## Retrieval

### OCI referrers-style sidecar endpoint

```
GET {admin}/api/attest/referrers?digest=sha256:<hex>
```

Returns an OCI image index (`application/vnd.oci.image.index.v1+json`) whose
`manifests` are the attestations the proxy produced for that subject digest, each
tagged with the in-toto `artifactType` — the conventional discovery shape
(`oras discover`, cosign) adapted to the proxy's store.

### Admin / programmatic

```
GET {admin}/api/attest?tenant=&package=&q=&limit=   # status + retained bundles (or one with ?package=)
GET {admin}/api/attest/bundle?tenant=&package=       # the raw, verifiable DSSE envelope
```

### CLI (offline)

```
# Build & sign a bundle from an exported admission document (air-gapped path):
pullthrough attest export -key signing-key.pem -input admission.json [coordinate] > bundle.json

# Verify a bundle against the proxy's public key and print the statement:
pullthrough attest verify -pubkey signing-pub.pem -input bundle.json
```

`attest export <coordinate>` accepts a trailing `name@version` to override the
artifact coordinate in the input document.

## Configuration

```yaml
attest:
  enabled: true            # default true; also requires a signing key
  maxEntries: 2048         # retained bundles (oldest-evicted)
  attesterId: pullthrough-proxy
  instance: ""             # optional host/pod identity in the predicate
  signingKey: ""           # inline PEM (or ${ENV}/enc:v1:); else reuse audit key
  signingKeyFile: ""       # PEM key file; else reuse audit key
```

## Metrics

| Metric | Meaning |
| --- | --- |
| `pullthrough_attest_bundles_total` | Attestations signed for served artifacts. |
| `pullthrough_attest_bundles_with_source_total` | Of those, how many bound a source commit. |
| `pullthrough_attest_bundles_warned_total` | Attestations for artifacts admitted with a gate warning. |
| `pullthrough_attest_sign_errors_total` | Signing failures (best-effort; never blocks serving). |
| `pullthrough_attest_retained_bundles` | Bundles currently retained for the referrers/export surfaces. |

## Trust model

Verification is the consumer's job and needs only the proxy's **public key**:

1. Check the DSSE signature over the PAE-encoded payload against the public key.
2. Check that one subject digest equals the artifact being consumed.

Both must hold. (1) without (2) lets a valid attestation for a *different* benign
artifact be replayed against a malicious one; (2) without (1) lets anyone forge a
predicate. The proxy's attestation is a transferable, non-repudiable record of an
admission decision — not a substitute for the consumer's own digest pinning.
