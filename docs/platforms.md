# Supported platforms

`pullthrough-security` ships and tests binaries and container images for more
than one CPU architecture. This page is the authoritative statement of which
OS/architecture combinations are **supported** (built, tested, and released),
which are **best-effort** (built but not continuously tested), and how the
multi-architecture guarantee is enforced in CI and in the release pipeline.

## Support matrix

| OS / Arch | Server (`pullthrough`) | Client (`ptctl`) | Container image | FIPS variant | Support tier |
|-----------|:----------------------:|:----------------:|:---------------:|:------------:|--------------|
| `linux/amd64` (x86-64) | ✅ | ✅ | ✅ | ✅ | **Supported** — built, tested (incl. `-race`), released |
| `linux/arm64` (aarch64) | ✅ | ✅ | ✅ | ✅ | **Supported** — built, tested (incl. `-race`), released |
| `darwin/amd64` | ✅ | ✅ | — | ✅ | **Best-effort** — released binary; not in the test matrix |
| `darwin/arm64` (Apple silicon) | ✅ | ✅ | — | ✅ | **Best-effort** — released binary; not in the test matrix |

- **Supported** means the full test suite (race detector + fuzz seed corpora)
  runs on that architecture on every PR, reproducible release binaries are
  produced and digest-verified, and the published container image carries a
  manifest for that platform with its own provenance + SBOM attestation.
- **Best-effort** means the release pipeline cross-compiles and publishes a
  signed, provenance-attested binary, but the architecture is not exercised by
  the CI test matrix. macOS has no container image (the runtime image is Linux
  Alpine).
- There is no `windows/*` or 32-bit (`386`, `arm`) target. The code is portable
  (see *Why this is portable*, below) and will cross-compile, but those targets
  are neither tested nor released.

The container runtime base image (`alpine`) and the build image
(`golang:*-alpine`) are both multi-arch manifests, so the `Dockerfile` builds
unmodified for every listed `linux/*` platform.

## How multi-arch is enforced

### CI test matrix (`.github/workflows/ci.yml`)

The `test` and `fips` jobs carry an `arch: [amd64, arm64]` matrix dimension:

- the **amd64** leg runs on the standard `ubuntu-latest` x86-64 hosted runner;
- the **arm64** leg runs on GitHub's native aarch64 hosted runner
  (`ubuntu-24.04-arm`).

Both legs run `go test -race ./...` and the fuzz seed-corpus regression, so an
architecture-specific miscompile, endianness assumption, or word-size bug fails
the build on the affected architecture. Architecture-independent gates (`gofmt`,
`go vet`, `go mod tidy`, config-reference staleness) run once, on the amd64 leg.

> **No native arm64 runner?** If a fork cannot use `ubuntu-24.04-arm`, change the
> arm64 leg's `runs-on` to `ubuntu-latest` and run the suite under QEMU user
> emulation. Register the emulator once and build/run the test binaries for
> `GOARCH=arm64`:
>
> ```bash
> docker run --privileged --rm tonistiigi/binfmt --install arm64
> # per package, cross-compile the test binary and run it under emulation:
> CGO_ENABLED=0 GOARCH=arm64 go test -c -o pkg.arm64.test ./internal/backends/nix
> qemu-aarch64-static ./pkg.arm64.test
> ```
>
> Emulation is correct but slow; the native runner is preferred.

### Reproducible-build guard (`self-release` job)

The `self-release` CI job proves the release build is bit-for-bit reproducible
for **both** `linux/amd64` and `linux/arm64`, for both the standard and FIPS
variants, by building twice and comparing per-file SHA-256 digests. These are
pure-Go cross-compiles (`CGO_ENABLED=0`) from the x86-64 runner, so the arm64
artifacts are produced and verified without an arm64 host.

### Release pipeline (`.github/workflows/release.yml`)

On a `v*` tag the self-releasing pipeline (see [self-release.md](self-release.md)):

1. reproducibly builds the standard and FIPS binaries for every
   `RELEASE_PLATFORMS` entry (`linux/amd64 linux/arm64 darwin/amd64
   darwin/arm64`) — each architecture's binary is a distinct `SHA256SUMS`
   subject;
2. generates SLSA L3 provenance whose subjects are **all** the per-arch binaries,
   and a CycloneDX SBOM per binary;
3. signs `SHA256SUMS` with keyless cosign (Fulcio/OIDC);
4. builds and pushes the container image with
   `docker buildx --platform linux/amd64,linux/arm64`, producing an OCI image
   index (manifest list) with one manifest per architecture. With
   `provenance: mode=max` and `sbom: true`, **each architecture's manifest
   carries its own SLSA provenance and SBOM attestation** — not a single
   attestation over the index — and the whole image is cosign-signed.

`ptctl verify-self` verifies the signed, reproducible, provenance-attested
binary for whichever architecture the operator downloaded.

## Why this is portable

The audit backing this support statement (Task 149) found no architecture
-specific code to fix:

- **No cgo.** Every binary is built with `CGO_ENABLED=0` — a pure-Go static
  binary with no host C toolchain. The WASM extension runtime uses `wazero`, a
  pure-Go interpreter (no cgo, no native codegen).
- **No assembly.** There are no `.s` files and no `//go:build amd64|arm64`
  architecture build constraints in the source tree.
- **No native-endianness assumptions.** Every byte-order conversion goes through
  an explicit `encoding/binary.BigEndian` / `LittleEndian` codec — never
  `NativeEndian` and never an `unsafe` reinterpret of an integer. This covers the
  wire-format and hashing paths: `internal/cache/encrypt.go`,
  `internal/backup/crypto.go`, `internal/git/ssh.go`, `internal/avscan/clamd.go`,
  and `internal/tracing/sampler.go`.
- **No word-size assumptions in the content-addressing math.** The hand-rolled
  Nix base-32 codec (`internal/backends/nix/nixbase32.go`), the git tree-hash
  (`internal/backends/julia/treehash.go`), and the RFC 6962 Merkle code
  (`internal/rekor`, `internal/audit`) operate on `byte`/`uint16`/`uint64` with
  explicit bit masks, so they produce identical digests on 64-bit amd64 and
  arm64.
- **Portable syscalls only.** The only direct syscalls are `Flock` (advisory
  file locking) and POSIX signal handling, both available and identical on
  `linux/arm64`.

These invariants are verified continuously: the arm64 CI leg runs the race suite
over all of the above packages on a real aarch64 host.

## Local multi-arch builds

```bash
# Cross-compile binaries for all release platforms (standard + FIPS):
make release RELEASE_PLATFORMS="linux/amd64 linux/arm64"
make release-fips RELEASE_PLATFORMS="linux/amd64 linux/arm64"

# Prove the build is reproducible across both Linux arches:
make release-repro-check RELEASE_PLATFORMS="linux/amd64 linux/arm64"

# Build the multi-arch container image locally (requires docker buildx):
make docker-buildx IMAGE_PLATFORMS=linux/amd64,linux/arm64
# ...and push the multi-arch manifest with per-arch provenance + SBOM:
make docker-buildx-push IMAGE_PLATFORMS=linux/amd64,linux/arm64
```
