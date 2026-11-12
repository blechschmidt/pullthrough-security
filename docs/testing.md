# Testing

The proxy is covered by several tiers of automated tests, each gated so the
default developer loop stays fast and deterministic.

| Tier | Build tag | How to run | When it runs |
| ---- | --------- | ---------- | ------------ |
| Unit + component | _(none)_ | `make test` | every PR, locally |
| Integration | `integration` | `make test-integration` | on demand (needs Git/MinIO fixtures); the hermetic per-ecosystem suites in `internal/e2e` run on every PR (`integration` job) |
| LLM package scan, every ecosystem | `integration` | `make test-llm-package-scan` | every PR (`llm-package-scan` job; gates the image build) |
| Ecosystem (real package managers) | `ecosystem` | `make test-ecosystems` | every PR and nightly, one CI job per ecosystem (needs Docker + network) |
| Client lab (the client guide, executed) | _(scripts)_ | `make client-lab` | nightly, on demand, and when the lab or the guide changes, one CI job per client image (needs Docker + network) |
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
an install that succeeds took nothing from anywhere but the proxy. For cargo and
go the suite also asserts the [download log](download-log.md): each client run
reaches the proxy from its own address, and the log must attribute the served
and the refused package to the right ones. See
[ecosystem-tests.md](ecosystem-tests.md); the verified client configurations are
published in [ecosystem-tests-reference.md](ecosystem-tests-reference.md).

The **client lab** (`scripts/client-lab`, Task 171) runs every configuration the
[client guide](clients.md) prints — some sixty scripts: the other clients of an
ecosystem (Yarn, pnpm, uv, Poetry, Gradle, containerd, skopeo, OpenTofu, …), a
private CA to trust, a token to present — with the real clients against the
real proxy, served as `https://proxy.example.com`, in three access-control
modes. Its network has no way out *and* a name server that records every name
a client looks up, so a client that quietly tries the public registry fails its
run instead of passing unnoticed. `go test ./internal/clientguide/` (part of
`make test`) holds the guide to those scripts: every fenced block of the guide
names the scripts that execute it, and a line that none of them executes fails
the test — as does a script that was edited after its result was recorded on
the lab's page. See [client-lab.md](client-lab.md).

The **LLM package-scan suite** (`internal/e2e/pkgscan`, Task 175) proves that
the [LLM package-content scan](llm-package-scan.md) gates every upstream type
the proxy fronts. For each, the real `pullthrough` binary — started from a
configuration file with `llmPackageScan` enabled — pulls packages in the
ecosystem's own format from a stub registry speaking its protocol, while a mock
LLM endpoint (Anthropic and OpenAI wire formats) stands in for the model: a
benign package is served and the model saw its marker file; a flagged one is
refused, quarantined, recorded as a finding and in the audit log, and stays
refused across retries, restarts and the cache; verdicts are reused; failMode
closed and open each behave on a provider error and a timeout; a prompt
injection inside the package does not turn the verdict. Git: LFS objects go
through the same scenarios, and the commit scan still refuses the package built
from a flagged commit. It writes an ecosystem × scenario matrix
(`llm-package-scan-matrix.{md,json}`) and fails when any upstream type has no
fully passing row. Hermetic; CI runs it in its own `llm-package-scan` job. See
[llm-package-scan.md](llm-package-scan.md#testing).

```sh
make test-llm-package-scan                                 # go test -tags integration ./internal/e2e/pkgscan/
make test-llm-package-scan PKGSCAN_ECOSYSTEMS="npm docker"  # a selection
```

The hermetic **per-ecosystem integration suites** (`internal/e2e`, Tasks 144 and
168) drive an in-process gateway over a recorded upstream for every ecosystem:
the whole pull + admission pipeline, and the LLM commit-scan admission path
(benign commit admits, malicious commit blocks). They need no network or client
tooling and run in CI's `integration` job:

```sh
go test -tags integration ./internal/e2e/...
```

The same package holds the **interception suite** (`internal/e2e/intercept_test.go`,
Task 172): for every ecosystem fixture it puts the
[TLS-interception](intercept-mode.md) listeners — the forward proxy and the NAT
TLS and plain-HTTP listeners — in front of that gateway and pulls the fixture's
resources the way a client that is *not* pointed at the proxy does: from the
upstream's own host, through a `CONNECT`, and through a connection the network
sent to the NAT listener. Each pull must be routed by host, the artifact fetched
from the upstream once and served from the cache to every later intercepted
client, a host without a rule refused, and a known-malicious coordinate blocked
before anything is fetched. The same modes with every ecosystem's real client
run in the [ecosystem tests](ecosystem-tests.md).

The same job runs the **download-log suite** (`internal/e2e/downloadlog`, Task
176), which tests "which package was downloaded from which address" with the
Rust and Go ecosystems against the real `pullthrough` binary: the real `cargo`
and the real `go` command fetch packages from stub registries through the
proxy, every client machine from its own source address (one behind a trusted
reverse proxy, one forging `X-Forwarded-For`), and the log is read through the
admin API. `PT_DOWNLOADLOG_CLIENTS=real` (set in CI) makes a missing package
manager a failure instead of falling back to a scripted client. See
[download-log.md](download-log.md#tests).

```sh
go test -tags integration ./internal/e2e/downloadlog/
```

And the **personal-links suite** (`internal/e2e/userlinks`, Task 177), which
tests "downloads tracked per user": two users sign in at an OpenID Connect
identity provider (authorization code with PKCE, RS256 ID tokens), each gets a
personal cache link from the self-service page, and the real `npm`, `pip`,
`cargo`, `go`, Docker Engine and `git` — configured with the snippet the page
hands out — install a package through the real `pullthrough` binary. The log
must tell the two users apart although every client runs on one machine; a
revoked link must stop working, on a second replica too; and no link's token
may be found in anything a proxy wrote or sent upstream.
`PT_USERLINKS_CLIENTS=real` (set in CI) makes a missing client a failure
instead of a skipped row. See [user-links.md](user-links.md#tests).

```sh
make test-user-links     # go test -tags integration ./internal/e2e/userlinks/
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
| `internal/llmpkgscan` | `FuzzParseVerdict` | the LLM's verdict JSON (model output shaped by untrusted package content) |
| `internal/llmpkgscan` | `FuzzSafePath` | archive member names → root-relative keys (path traversal) |
| `internal/llmpkgscan` | `FuzzBuildTree` | package archives → the bounded in-memory tree |
| `internal/llmpkgscan` | `FuzzToolCalls` | the model's tool-call arguments (list/read/grep) |
| `internal/clientip` | `FuzzResolve` | peer address + `X-Forwarded-For` → the address a download is logged under |
| `internal/clientip` | `FuzzForgedPrefixCannotMoveTheClient` | a forged `X-Forwarded-For` in front of what the trusted proxy appended |
| `internal/downloadlog` | `FuzzClean` | every string a log entry stores (control and invisible format characters, bounds) |
| `internal/downloadlog` | `FuzzGlobMatch` | the package filter's wildcard matcher, against a reference |
| `internal/downloadlog` | `FuzzQueryFromValues` | the admin API's filter parameters |
| `internal/downloadlog` | `FuzzWriteCSV` | the CSV export (formula injection, row integrity) |
| `internal/downloadlog` | `FuzzLoad` | the on-disk log file after a crash or an edit |
| `internal/userlinks` | `FuzzWellFormed` | personal-link tokens: only what the generator can produce is well-formed |
| `internal/userlinks` | `FuzzCleanText` | every string a link record stores (names from an ID token, labels, addresses) |
| `internal/userlinks` | `FuzzDecodeCookie` | the links page's sign-in cookies: nothing unsigned or re-purposed decodes |
| `internal/userlinks` | `FuzzLoadLink` | link records read back from the registry's store |
| `internal/proxy` | `FuzzLinkRewriter` | the personal-link response rewriter: rewriting in chunks equals rewriting at once, and nothing but links to the mount changes |
| `internal/proxy` | `FuzzRedactPersonalPath` | request-path redaction: a link's token never survives into a log line |
| `internal/git` | `FuzzFetchSniffer` | a Git client's SSH session stream (pkt-lines) |
| `internal/git` | `FuzzDescribeDownload` | a Git `upload-pack` request body, plain or gzip |
| `internal/git` | `FuzzAsksForNothingButRefs` | the decision that keeps a Git request out of the download log |
| `internal/git` | `FuzzParseTree` | Git tree objects read from a repository by the lock-file scanner |
| `internal/lockfiles` | `FuzzPackageLock`, `FuzzNpmShrinkwrap`, `FuzzYarnLock`, `FuzzPnpmLock` | npm lock files: package-lock.json, npm-shrinkwrap.json, yarn.lock (Classic and Berry), pnpm-lock.yaml |
| `internal/lockfiles` | `FuzzRequirementsTxt`, `FuzzPipfileLock`, `FuzzPoetryLock`, `FuzzUVLock`, `FuzzPDMLock` | Python lock files |
| `internal/lockfiles` | `FuzzCargoLock`, `FuzzGoMod`, `FuzzGoSum`, `FuzzNuGetLock`, `FuzzGradleLock`, `FuzzPOM`, `FuzzGemfileLock`, `FuzzComposerLock`, `FuzzDockerfile`, `FuzzCompose` | the other lock files, POMs, Dockerfiles and Compose files |
| `internal/lockfiles` | `FuzzTOML` | the TOML reader behind Cargo.lock, poetry.lock, uv.lock and pdm.lock |
| `internal/lockfiles` | `FuzzProxyMapping` | lock-file URLs mapped back from the proxy: a personal link's token never survives |

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
  `make fuzz FUZZTIME=5m`, generating new inputs, in nine parallel shards
  (`FUZZ_SHARDS=9 FUZZ_SHARD=0…8`; target *i* is in shard *i* mod 9): over a
  hundred targets at five minutes each take longer than a hosted CI job may
  run. The scheduled run has a concurrency group of its own, so a push to
  `main` does not cancel it. Set the `fuzztime` dispatch input to fuzz longer
  (e.g. `30m`). A discovered crasher is written under the package's
  `testdata/fuzz/<Target>/` directory and uploaded as the
  `fuzz-crashers-<shard>` artifact.

### Triage workflow for a discovered crasher

1. Download the `fuzz-crashers-<shard>` artifact (or, locally, find the file `go test`
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
