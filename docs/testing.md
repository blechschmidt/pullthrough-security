# Testing

The proxy is covered by several tiers of automated tests, each gated so the
default developer loop stays fast and deterministic.

| Tier | Build tag | How to run | When it runs |
| ---- | --------- | ---------- | ------------ |
| Unit + component | _(none)_ | `make test` | every PR, locally |
| Integration | `integration` | `make test-integration` | on demand (needs Git/MinIO fixtures); the hermetic per-ecosystem suites in `internal/e2e` run on every PR (`integration` job) |
| Ecosystem (real package managers) | `ecosystem` | `make test-ecosystems` | every PR and nightly, one CI job per ecosystem (needs Docker + network) |
| Fuzz | `fuzz` | `make fuzz` / `make fuzz-seed` | seed corpora on every PR; extended nightly |
| Red-team gate-efficacy | _(none)_ | `make redteam` / `ptctl redteam` | every PR (regression gate) |
| Chaos / fault-injection | _(none)_ | `make chaos` | every PR (resilience gate) |
| Coverage-regression gate | _(none)_ | `make covguard` / `ptctl covguard` | every PR (coverage gate) |

The **ecosystem** tier (`internal/ecotest`, Task 170) is the only one that does
not speak HTTP to the proxy itself: for every supported ecosystem it runs the
ecosystem's real client — `npm`, `pip`, `cargo`, `go`, `dotnet`, `mvn`, the
Docker Engine, `helm`, `bundler`, `composer`, `terraform`, `conan`, `conda`,
`apt-get`, `dnf`, `git`, `mix`, `bazel`, `julia`, `cpanm`, `R`, `dart pub`,
`ovsx`, `nix`, `deno`, `cabal`, `brew`, `ansible-galaxy`, `r10k`,
`huggingface_hub` — configured to use the proxy, against the real
proxy binary and the real registry, with a mock LLM scanning the packages' source
commits. A good package must install (and re-install from the cache); a bad one
must be refused and the client must fail. Client containers have no network, so
an install that succeeds took nothing from anywhere but the proxy. See
[ecosystem-tests.md](ecosystem-tests.md); the verified client configurations are
published in [ecosystem-tests-reference.md](ecosystem-tests-reference.md).

The hermetic **per-ecosystem integration suites** (`internal/e2e`, Tasks 144 and
168) drive an in-process gateway over a recorded upstream for every ecosystem:
the whole pull + admission pipeline, and the LLM commit-scan admission path
(benign commit admits, malicious commit blocks). They need no network or client
tooling and run in CI's `integration` job:

```sh
go test -tags integration ./internal/e2e/...
```

The **red-team** tier (`internal/redteam`, Task 76) injects a catalog of
synthetic supply-chain attacks end-to-end through the full admission pipeline of
an in-process gateway and asserts the expected gate blocks each one, emitting a
coverage matrix and failing CI on any block→admit regression. See
[redteam.md](redteam.md).

The **chaos / fault-injection** tier (`internal/chaos`, Task 98) injects
degraded conditions — slow/failing upstreams, transport/TLS errors, partial
responses, object-store timeouts and 5xx, cache corruption, and scanner/LLM API
unavailability — through the production interface seams and asserts the proxy's
failover, circuit breaking, negative caching, singleflight, graceful gate
degradation (fail-open vs fail-closed per policy), and cache-fill integrity. It
is deterministic (manual clock, channel-sequenced concurrency) and renders a
resilience matrix that is the source of [resilience.md](resilience.md).

The **coverage-regression** gate (`ptctl covguard` / `make covguard`, Task 117)
measures statement coverage across the module, compares it against the committed
baseline at `coverage/coverage-baseline.json`, and fails CI when total coverage
drops beyond a threshold or a security-critical package falls under its floor —
the coverage analogue of the performance guard. See [coverage.md](coverage.md).

## Fuzzing the protocol & manifest parsers

A pull-through proxy parses bytes it did not produce: package-manager index and
metadata documents, OCI/Docker manifests and tag/referrer lists, SBOMs, VEX/CSAF
documents, and SPDX license expressions all arrive from an upstream registry,
mirror, or operator-supplied feed that may be compromised or malicious. A parser
that panics, recurses without bound, or allocates without bound on adversarial
input is a denial-of-service (and, for a shared proxy, a multi-tenant) hazard.

To harden that surface the repository ships native Go fuzz targets
(`testing.F`). They live in `_test.go` files gated behind the **`fuzz`** build
tag, mirroring the `integration` convention, so `go test ./...` never picks them
up by default.

### Targets

| Package | Target | Untrusted input |
| ------- | ------ | --------------- |
| `internal/license` | `FuzzParseExpression` | SPDX license expressions |
| `internal/backends/pkgmgr` | `FuzzApplyRules` | index-document URL rewriting |
| `internal/backends/pkgmgr` | `FuzzRewriteCargoConfig` | Cargo `config.json` |
| `internal/backends/pkgmgr` | `FuzzMaybeGunzip` | NuGet gzip metadata (bomb surface) |
| `internal/backends/pkgmgr` | `FuzzPipNameVersion` | PyPI distribution filenames |
| `internal/backends/docker` | `FuzzParseReference` | Registry v2 request paths |
| `internal/backends/docker` | `FuzzParseDigest` | content digests |
| `internal/backends/swift` | `FuzzClassify` | Swift registry request paths |
| `internal/backends/swift` | `FuzzParseReleaseMetadata` | Swift release metadata JSON |
| `internal/backends/dart` | `FuzzClassify` | pub request paths |
| `internal/backends/dart` | `FuzzParseVersionList` | pub list-versions JSON |
| `internal/backends/dart` | `FuzzRewriteArchiveURLs` | pub list-versions `archive_url` rewriting |
| `internal/backends/conda` | `FuzzClassify` | Conda channel request paths |
| `internal/backends/conda` | `FuzzRepodataChecksum` | Conda `repodata.json` index JSON |
| `internal/backends/cran` | `FuzzClassify` | CRAN repository request paths |
| `internal/backends/cran` | `FuzzParsePackages` | CRAN `PACKAGES` DCF index |
| `internal/backends/hex` | `FuzzClassify` | Hex repository request paths |
| `internal/backends/hex` | `FuzzParsePackageResource` | Hex signed `/packages/<name>` protobuf |
| `internal/backends/bazel` | `FuzzClassify` | Bazel registry request paths |
| `internal/backends/bazel` | `FuzzParseSource` | Bazel `source.json` descriptor JSON |
| `internal/backends/bazel` | `FuzzParseIntegrity` | Bazel SRI `integrity` strings |
| `internal/backends/cpan` | `FuzzClassify` | CPAN mirror request paths |
| `internal/backends/cpan` | `FuzzParseChecksums` | CPAN per-author `CHECKSUMS` Perl data structure |
| `internal/vulnscan` | `FuzzExtract` | artifact archives → SBOM (gzip/tar, zip) |
| `internal/vulnscan` | `FuzzParseVEX` | OpenVEX / CSAF VEX documents |
| `internal/vulnscan` | `FuzzParseGoRequires` | `go.mod` require directives |
| `internal/vulnscan` | `FuzzParseNuspec` | `.nuspec` XML metadata |
| `internal/vulnscan` | `FuzzOSVRecord` | OSV advisory records |
| `internal/vulnscan` | `FuzzParseCVSSBaseScore` | CVSS vectors |
| `internal/sigverify` | `FuzzOCIManifest` | OCI image manifest / index JSON |

Each target seeds its corpus (`f.Add`) with real-world samples and a battery of
known-malformed inputs (truncated archives, unterminated grammars, deeply nested
expressions, decompression bombs, invalid UTF-8, …), and asserts the parser's
contract: no panic, graceful error, and — where applicable — round-trip and
range invariants.

### Running locally

```sh
# Replay every seed corpus as fast, deterministic regression tests (no fuzzing).
make fuzz-seed

# Fuzz every target for FUZZTIME each (default 20s). Raise it to dig deeper.
make fuzz
make fuzz FUZZTIME=2m

# Fuzz a single target by hand:
go test -tags fuzz -run='^$' -fuzz=FuzzParseExpression -fuzztime=30s ./internal/license/
```

`go test -fuzz` runs **one** target per package invocation, which is why
`make fuzz` iterates over the targets individually.

### CI

- **Every PR / push** runs `go test -tags fuzz ./...`, which executes all fuzz
  seed corpora (including any committed regression inputs) as ordinary tests.
  This is fast and deterministic — it re-runs every previously discovered
  crasher so a fix can't silently regress, but it does **not** generate new
  inputs.
- **Nightly** (and via manual `workflow_dispatch`) the `fuzz` job runs
  `make fuzz FUZZTIME=5m`, generating new inputs. Set the `fuzztime` dispatch
  input to fuzz longer (e.g. `30m`). A discovered crasher is written under the
  package's `testdata/fuzz/<Target>/` directory and uploaded as the
  `fuzz-crashers` artifact.

### Triage workflow for a discovered crasher

1. Download the `fuzz-crashers` artifact (or, locally, find the file `go test`
   reports under `testdata/fuzz/<Target>/`).
2. Reproduce deterministically — the corpus file is itself the regression test:
   ```sh
   go test -tags fuzz -run=FuzzParseExpression/<hash> ./internal/license/
   ```
3. Fix the parser so it fails gracefully (return an error; never panic; bound
   recursion and allocation).
4. Commit the `testdata/fuzz/<Target>/<hash>` file alongside the fix so the
   seed-corpus regression run guards it forever.

### Hardening already done

Fuzzing during development surfaced and fixed several real issues, e.g.:

- `rewriteCargoConfig` panicked on a literal JSON `null` body (nil-map
  assignment) — now passes the document through untouched.
- `maybeGunzip` (NuGet) decompressed without bound — a gzip bomb could exhaust
  memory; it is now capped (`maxGunzipBytes`).
- `ParseExpression` (SPDX) recursed once per nested parenthesis — a crafted
  license field could exhaust the goroutine stack; token count is now bounded
  (`maxExpressionTokens`).
- `pipNameVersion` returned a "valid" coordinate with an empty name/version for
  inputs like `-.whl` — now rejected.
