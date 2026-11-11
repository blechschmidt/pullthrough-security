# Ecosystem tests: real package managers through the proxy

Every other suite in this repository drives the proxy with HTTP requests written
by the same people who wrote the backend. That proves the proxy implements each
registry protocol *as its author read the specification*. It does not prove that
`npm`, `pip`, `cargo`, the Docker Engine, `dnf` or `bazel` can install anything
through it.

The ecosystem tests close that gap. For **every supported ecosystem** they run
the ecosystem's **real client**, configured to use the pull-through proxy instead
of the public registry, against the **real proxy binary** fronting the **real
upstream registry** — and they run in CI on every push.

| What is real | What is mocked |
|---|---|
| the package manager (official container image) | the LLM's judgement |
| the `pullthrough` binary and its configuration file | |
| the upstream registry and the packages | |
| the commit scanner, provenance, policy, audit log | |

The LLM is replaced by a mock that speaks the provider's wire format (Anthropic
Messages or OpenAI Chat Completions), so the proxy's provider client, prompt
construction, verdict parsing and scoring all run for real; only "is this commit
malicious?" is answered by a fixed rule.

The verified client configuration for each ecosystem — the exact script CI runs
— is published in **[ecosystem-tests-reference.md](ecosystem-tests-reference.md)**
(generated from the test catalog, so it cannot drift from what is tested).

## What is asserted

Each ecosystem runs the same five checks — the Rust and Go ecosystems a sixth —
reported as one row of a matrix:

| Check | Meaning |
|---|---|
| **Installs via proxy** | The real client, pointed at the proxy, installs a real package. |
| **Stored in cache** | The package's artifact is in the proxy's cache — the download really flowed through the proxy. |
| **Admitted by LLM scan** | The package was admitted *because* the LLM scan of its source commit was benign: the proxy holds a provenance link from the package to that commit, the commit has a benign verdict, and the policy engine recorded an allow decision. |
| **Re-install from cache** | A second install from a pristine client succeeds and the artifact is **not** fetched from the upstream again. |
| **Bad package blocked** | A package whose source commit the LLM flagged malicious is refused by the proxy (`403`, reason `malicious`, recorded in the audit log with the offending commit) **and the real client fails**. |
| **Downloads logged by client address** | The proxy's [download log](download-log.md) — read through the admin API, as the console's Downloads tab reads it — shows the installed package as *served* to the address of each client run that installed it (the second from the cache), and the refused package as *blocked* by the admission policy for the run that tried, and served to nobody. Filtering the log by one run's address lists that run's entries only. Asserted for the ecosystems that opt in (`DownloadLog` in the catalog): **cargo** and **go**. |

The last check needs both halves. A client that fails for another reason (a
flaky registry, a typo) does not count as a block; a proxy that blocks while the
client quietly installs the package some other way does not count either.

Git is the one ecosystem with no package coordinate to gate and, in
pass-through mode, nothing immutable to cache; its row checks that a real `git`
client can clone through the proxy.

Two backends have no row because there is no public upstream to pull from:
`swift` (no public SE-0292 package registry exists) and `generic` (declarative,
deployment-specific routes).

## How a run works

```
              ┌──────────────────────────── host ─────────────────────────────┐
              │                                                               │
  fixture     │   mock LLM  ◄──── Messages API ────┐                          │
  source repo │   (marker ⇒ malicious)             │                          │
  ├ benign  ──┼──► commit scanner ─► verdicts ─► provenance pins ─► policy    │
  └ malicious │        (scanning.watch)             (good→benign,             │
              │                                      bad→malicious)           │
              │                      pullthrough ───────────────► real registry
              │                          ▲ 127.0.0.1:PORT                     │
              │                unix socket│                                   │
              └───────────────────────────┼───────────────────────────────────┘
                                          │
              ┌── client container (--network none) ──┐
              │  forwarder 127.0.0.1:PORT ────────────┘
              │  real client  →  http://127.0.0.1:PORT/v1/<ecosystem>/…
              └───────────────────────────────────────┘
```

1. **Source repository.** A small Git repository is created with two commits: an
   ordinary change, and one that adds an install hook piping a remote script into
   a shell (it carries the marker the mock LLM keys on).
2. **Proxy.** The real binary is started with a generated configuration that is
   the production shape of "gate package pulls on the LLM scan of their source
   commit":
   - the ecosystem's `upstreams:` entry, pointing at the real registry;
   - `scanning:` with an LLM provider (the mock's URL) and `scanning.watch`
     scanning the source repository, history included;
   - `provenance.pins:` tying the good package to the benign commit and the bad
     package to the malicious one (see below);
   - `policy:` with `blockMalicious: true`, admitting unpinned packages so the
     transitive dependencies of a real install pass.
3. **Scan.** The harness waits until the proxy's commit scanner has produced a
   verdict for both commits and checks they are benign and malicious
   respectively, and that the mock LLM actually served the completions.
4. **Client.** The ecosystem's script
   ([`internal/ecotest/clients/`](../internal/ecotest/clients)) runs in the
   ecosystem's official image. It configures the client to use the proxy and
   installs `$PKG_NAME`. The same script, unchanged, is run for the good package
   (twice) and for the bad one.
5. **Evidence.** The harness reads the proxy's admin API (cache entries,
   provenance links, scan verdicts), its Prometheus metrics (cache hits, policy
   decisions) and its tamper-evident audit log (the block, with the coordinate,
   the reason code and the commit).

### Clients have no network

Client containers run with **`--network none`**. The only thing they can talk to
is the proxy: the harness places a small forwarder in the container that listens
on the proxy's loopback address and relays over a unix socket to the real proxy
on the host. Consequences:

- An install that succeeds provably took **nothing** from anywhere but the proxy.
  A backend that leaks a direct upstream URL to the client (a metadata link, a
  download redirect) fails the test instead of going unnoticed.
- A client that silently falls back to another source when the proxy refuses a
  package fails, as it would in a network without direct egress — which is where
  a supply-chain proxy is deployed. Two clients do fall back when they can; see
  [Client behaviours worth knowing](#client-behaviours-worth-knowing).
- The client uses the same `http://127.0.0.1:PORT` URL the proxy advertises as
  its `server.publicUrl`, so no client needs an "insecure host" exception that
  would not exist in an HTTPS deployment.

### Every client run has its own address

Each client run gets a unix socket of its own, and the harness relays that
socket's connections to the proxy from a loopback address that belongs to this
run alone (`127.77.0.2`, `127.77.0.3`, …). To the proxy every run is therefore a
different client machine — which is what makes the *download log* check
meaningful: the address the log attributes a package to is one the proxy
observed on the connection, and it differs between the run that installed the
good package first, the run that re-installed it from the cache, and the run
that was refused the bad one.

### Tying a package to a commit: provenance pins

The admission policy gates a package on the scan verdict of the commit it was
built from. Attestations give that link for some ecosystems; most publish none.
The tests therefore use the mechanism an operator uses for exactly that case — an
explicit pin in the proxy configuration:

```yaml
provenance:
  enabled: true
  pins:
    - ecosystem: npm                 # the upstream type
      name: is-number                # the package, as the backend reports it
      version: 7.0.0                 # omit to pin every version
      repository: /path/to/source.git
      commit: df64cf02bd943e778957d319cf9002b7e9f5dae4
```

A pin is authoritative for the coordinates it matches and its commit's verdict
gates the package like an attested link would. It is an assertion, not evidence:
a pinned link has `claimed` confidence and never satisfies `requireAttested`.

## Running it

Requirements: Docker, Git, Go, and network access to the public registries. No
other toolchain — every client runs in its ecosystem's official image.

```sh
make test-ecosystems                        # every ecosystem (takes a while)
make test-ecosystems ECOSYSTEMS="npm pip"   # a selection
make test-ecosystems-list                   # the ecosystems covered
```

or directly (CGO must be off — the test binary doubles as the in-container
forwarder and has to be statically linked):

```sh
CGO_ENABLED=0 ECOTEST_ECOSYSTEMS=npm \
  go test -tags ecosystem ./internal/ecotest/ -run '^TestEcosystems$' -v
```

| Variable | Default | Meaning |
|---|---|---|
| `ECOTEST_ECOSYSTEMS` | all | Space- or comma-separated ecosystem IDs to run. |
| `ECOTEST_BIN` | built from source | A prebuilt `pullthrough` binary to test. |
| `ECOTEST_WORKDIR` | a temp dir | Where per-ecosystem workspaces go: `<eco>/proxy/config.yaml`, `<eco>/logs/proxy.log`, `<eco>/logs/client-*.log`. |
| `ECOTEST_REPORT_DIR` | `<workdir>/report` | Receives `<eco>.json` per ecosystem and `ecosystem-matrix.{md,json}`. |
| `ECOTEST_KEEP` | unset | Keep the workspace of passing ecosystems too (a failing one is always kept). |
| `ECOTEST_ATTEMPTS` | `3` | Tries per client step. The registries are real; one transient 5xx must not fail the build. |
| `ECOTEST_LLM_PROVIDER` | `claude` | Wire format the proxy speaks to the mock LLM: `claude` or `openai`. |
| `ECOTEST_OPEN_NETWORK` | unset | Debugging aid: run clients on the host network. Tells "cannot work through the proxy" apart from "needs something besides the proxy". Weakens the suite; never use in CI. |

When an ecosystem fails, its workspace is kept and the test output names it. The
client log shows what the package manager printed; the proxy log is JSON, one
record per request.

The parts that need neither Docker nor network run on every `go test ./...`: the
catalog covers every supported ecosystem, every client script follows the
contract, and the proxy configuration the harness renders is accepted by the real
configuration loader.

## In CI

The `CI` workflow (`.github/workflows/ci.yml`) runs the suite on every push and
pull request, and nightly:

| Job | What it does |
|---|---|
| `ecosystem-build` | Builds the proxy and the static test binary once; derives the job matrix **from the test catalog**, so a new ecosystem gets a CI leg without editing the workflow. |
| `ecosystem` (one per ecosystem) | Downloads the two binaries and runs that ecosystem. Needs only Docker — no Go, no sources. Uploads its result row, and the proxy and client logs on failure. |
| `ecosystem-matrix` | Assembles the matrix into the run summary and fails unless **every** catalog ecosystem ran and passed — a leg that never started cannot go unnoticed. |
| `integration` | The hermetic per-ecosystem suites (`internal/e2e`, build tag `integration`): the whole-pipeline suite and the in-process LLM-scan admission suite. Deterministic, so it gates the image build. |

The `ecosystem` jobs depend on public registries being up, so they do not gate
the image build; they do turn the workflow red, and the nightly run doubles as a
canary for upstream protocol or client changes.

`make ecosystem-reference-check` (part of the `test` job) fails when
[ecosystem-tests-reference.md](ecosystem-tests-reference.md) no longer matches
the catalog and scripts.

## Client behaviours worth knowing

Running real clients surfaced behaviour that matters when deploying the proxy:

- **Docker registry mirrors fall back.** With `registry-mirrors`, the Docker
  Engine fetches from Docker Hub directly when the mirror refuses a pull. Mirror
  mode therefore enforces admission only where direct egress to Docker Hub is
  blocked. The explicit form `<proxy>/<upstream>/<repository>` is fail-closed by
  construction. (The test daemon has no network, so both are exercised
  fail-closed.)
- **The Docker Engine rejects a mirror URL with a path.** The mirror must be the
  proxy's host root; the proxy serves the Registry v2 API at `/v2/` for this
  (`server.registry`).
- **Julia's Pkg falls back to Git.** When the Pkg server refuses a package, Pkg
  clones the package's repository instead — silently. As with Docker mirrors,
  admission is enforced where direct egress is blocked.
- **Go verifies against the checksum database directly** unless the proxy serves
  it. The proxy does (`/sumdb/<name>/…`), so a client that can reach only the
  proxy keeps full checksum verification instead of needing `GONOSUMDB`.
- **NuGet requires HTTPS** for the repository-signature resource; that ecosystem
  is tested over TLS with a throwaway CA.
- **Terraform needs no `.tf` changes.** A `host` block in the CLI configuration
  serves `registry.terraform.io` from the proxy, so provider addresses stay as
  they are.
- **Homebrew's formula index is signed**, so the proxy cannot rewrite bottle URLs
  in it; `HOMEBREW_ARTIFACT_DOMAIN` is what routes bottles through the proxy and
  is required.
- **The Hugging Face client reads a file's identity from response headers**
  (`X-Repo-Commit`, `X-Linked-Etag`) and rejects a response without them, so the
  proxy persists those headers with the cached file and replays them on a hit.
- **Composer keeps consulting packagist.org** unless the default repository is
  replaced or switched off; listing the proxy as an additional repository is not
  enough.
- **The first pull of a large package can outlast a client's timeout.** The
  proxy scans an artifact before it serves the first byte, so the time to first
  byte includes the upstream download and the content scan. `pip`'s default read
  timeout is 15 s; raise it (`--timeout`, `PIP_DEFAULT_TIMEOUT`) for large
  wheels, or pre-warm the cache.

## Adding an ecosystem

1. Add an entry to `catalog` in
   [`internal/ecotest/catalog_data.go`](../internal/ecotest/catalog_data.go):
   the client image (pinned to an explicit tag), the upstream, a small package
   that must install and an unrelated one that must be refused, and a pattern for
   the good artifact's cache key. Spell `Coordinate` the way the backend reports
   the package (the `package` field of a policy audit record).
2. Add `internal/ecotest/clients/<id>.sh`: configure the client to use `$MOUNT`,
   install `$PKG_NAME`. See
   [`clients/README.md`](../internal/ecotest/clients/README.md) for the contract.
3. `make ecosystem-reference-gen` and commit the regenerated reference.
4. `make test-ecosystems ECOSYSTEMS=<id> ECOTEST_KEEP=1`.

`go test ./...` fails until a supported ecosystem (`internal/testset`) has a
catalog entry and a script, so an ecosystem cannot be added without its
real-client test.
