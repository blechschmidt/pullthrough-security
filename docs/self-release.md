# Verifying the proxy binary itself (self-release)

The proxy admits or blocks third-party artifacts on the strength of signatures,
SLSA provenance, and SBOMs. The tool that enforces that trust must itself be
held to the same bar — otherwise a tampered proxy binary could silently disable
every gate. This page describes how `pullthrough-security` is released with, and
verified against, the same class of evidence it demands of everything else
(Task 135).

> **TL;DR for operators:** run `ptctl verify-self` next to the installed binary.
> A `VERIFIED` result means the binary's digest is covered by a cosign-keyless
> signed checksums manifest produced by this project's release workflow, a SLSA
> provenance attestation binds that digest to a trusted builder, and an SBOM
> ships with it. It works **offline**; install `cosign` for the additional
> Fulcio-root + Rekor transparency check.

## What a release contains

Every tagged release (`v*`) publishes, for both the **standard** and the
**FIPS 140-3** build variant:

| Artifact | Purpose |
|----------|---------|
| `pullthrough-<os>-<arch>`, `ptctl-<os>-<arch>` (FIPS: `*-fips-*`) | the binaries, built reproducibly |
| `SHA256SUMS` | checksums manifest over every binary **and** SBOM |
| `SHA256SUMS.sig`, `SHA256SUMS.pem` | cosign **keyless** (Fulcio/OIDC) signature + signing certificate over the manifest |
| `*.sbom.cdx.json` | a CycloneDX SBOM per binary |
| `pullthrough.intoto.jsonl` / `pullthrough-fips.intoto.jsonl` | SLSA (L3) provenance attestation for the binaries |
| container image | multi-arch (`linux/amd64` + `linux/arm64`), cosign-signed, with **per-architecture** provenance + SBOM attestations attached in the registry (see [platforms.md](platforms.md)) |

The signed `SHA256SUMS` is the **root of trust**: the binary's integrity and
authenticity reduce to "its digest appears in a manifest signed by this
project's release workflow identity". Provenance and the SBOM are
defence-in-depth build-platform transparency on top of that anchor.

## How it is built

The build is **reproducible**: two independent builds of the same source and
version produce bit-for-bit identical binaries. This is enforced before every
release and on every PR (CI fails otherwise), using the same digest-equality
comparison the proxy's reproducible-build gate applies to third-party artifacts
(`internal/rebuildverify`).

Reproducibility comes from `scripts/release-build.sh` (the single source of
truth shared by `make release*` and CI):

- `CGO_ENABLED=0` — pure-Go static binary, no host C toolchain;
- `-trimpath` — no absolute `$GOPATH`/module paths in the binary;
- `-ldflags "-s -w -buildid="` — cleared build id, stripped;
- `-buildvcs=false` — no VCS stamping; the version is injected explicitly via
  `-X main.version`;
- `GOFLAGS=-mod=readonly` and a pinned Go toolchain (the `go` directive in
  `go.mod`; CI installs it with `setup-go`);
- a fixed build order and an `LC_ALL=C`-sorted checksum manifest.

```bash
# Build the signed-release binaries locally (standard and FIPS):
make release           VERSION=v1.2.3      # -> dist/
make release-fips      VERSION=v1.2.3      # -> dist-fips/

# Prove the build is reproducible (build twice, compare digests):
make release-repro-check        VERSION=v1.2.3
make release-repro-check-fips   VERSION=v1.2.3
```

Signing, SLSA provenance, and SBOM generation happen in CI
(`.github/workflows/release.yml`) because they need `cosign`, `syft`, and a
GitHub OIDC identity; the Makefile covers the deterministic build, the
reproducibility proof, SBOMs (`make release-sbom`, needs `syft`), and a local
`verify-self` smoke test (`make release-verify`).

## `ptctl verify-self`

`verify-self` checks the running binary (or a sibling named with `--binary`)
against the release artifacts sitting next to it. The **expected signer
identity is embedded in the binary at build time** (`internal/selfrelease`), so
verification needs no external, mutable trust configuration — the trust anchor
travels inside the binary being verified.

```bash
# Verify the installed ptctl against the artifacts in its own directory:
ptctl verify-self

# Verify the server binary, artifacts in a specific directory, JSON output:
ptctl verify-self --binary /usr/local/bin/pullthrough --release-dir /opt/pullthrough/release --json

# Mandate the full cosign transparency check (fail if cosign is unavailable):
ptctl verify-self --require-cosign
```

### Checks performed

| Check | What it proves | Offline? |
|-------|----------------|----------|
| `checksums` | the binary's SHA-256 is listed in `SHA256SUMS` | yes |
| `signature-identity` | the signature over `SHA256SUMS` verifies, and the signer's SAN identity + OIDC issuer match the embedded expected identity | yes |
| `signature-transparency` | `cosign verify-blob` confirms the Fulcio chain + Rekor inclusion | needs `cosign` |
| `provenance` | a SLSA provenance subject carries this binary's digest, produced by the embedded expected builder | yes |
| `sbom` | a CycloneDX/SPDX SBOM is present and bound to the release (records the binary digest, or is covered by the signed manifest) | yes |

Without `cosign` on `PATH`, `signature-transparency` is a **warning**
(the offline identity check still gates the result); with `--require-cosign`
it becomes a hard failure. Any `fail` check makes `verify-self` exit non-zero.

### The embedded identity

The compile-time defaults pin verification to this repository's release
workflow and the canonical SLSA generic generator:

- certificate identity (regexp): `…/blechschmidt/pullthrough-security/.github/workflows/release.yml@refs/tags/v*`
- OIDC issuer: `https://token.actions.githubusercontent.com`
- builder id (regexp): this repo's `release.yml` **or** `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml`

A fork that publishes its own releases overrides these at build time with
`-ldflags "-X github.com/blechschmidt/pullthrough-security/internal/selfrelease.CertificateIdentityPattern=… -X ….BuilderIDPattern=…"`.

### Full cryptographic verification with upstream tooling

`verify-self` is the fast, dependency-free, embedded-anchor check. For the
canonical, externally-rooted verification use the upstream tools directly:

```bash
# Checksums signature (keyless):
cosign verify-blob \
  --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/blechschmidt/pullthrough-security/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum --check SHA256SUMS

# SLSA provenance for a binary:
slsa-verifier verify-artifact pullthrough-linux-amd64 \
  --provenance-path pullthrough.intoto.jsonl \
  --source-uri github.com/blechschmidt/pullthrough-security

# Container image signature + attestations:
cosign verify \
  --certificate-identity-regexp '^https://github\.com/blechschmidt/pullthrough-security/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/blechschmidt/pullthrough-security:v1.2.3
cosign verify-attestation --type slsaprovenance … ghcr.io/blechschmidt/pullthrough-security:v1.2.3
```

## Using it as a deployment gate

Because `verify-self` exits non-zero on failure and needs nothing but the files
next to the binary, wire it into deployment:

- **Kubernetes init container / startup probe** — run `ptctl verify-self` (or
  `pullthrough`'s container with `ptctl verify-self --require-cosign`) before
  the server starts; a failure blocks rollout.
- **Config-management post-install hook** — verify immediately after placing the
  binary and its release directory.
- **CI smoke test** — `make release-verify` after a build.

Keep the release sidecar files (`SHA256SUMS*`, `*.intoto.jsonl`, `*.sbom.*`)
alongside the binary, or point `--release-dir` / `PULLTHROUGH_RELEASE_DIR` at
wherever they live.

## FIPS variant

The FIPS 140-3 build variant travels the **same** signed-release path: it is
built reproducibly (`make release-fips` / `scripts/release-build.sh fips`),
covered by its own `SHA256SUMS`, cosign-signed, SLSA-attested, and SBOM'd, and
`verify-self` verifies a `*-fips-*` binary identically (reporting
`build: fips variant`). See [fips-compliance.md](fips-compliance.md).
