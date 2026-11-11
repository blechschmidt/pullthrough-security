# The client lab

The [client guide](clients.md) tells people what to put into `.npmrc`,
`settings.xml`, `daemon.json` and thirty other files. The client lab is where
those configurations are run: every one of them is a script that the real
client executes against the real proxy.

The [ecosystem tests](ecosystem-tests.md) already do that in CI for one client
per ecosystem — on loopback, over plain HTTP, without access control. The lab
covers what a deployment adds on top of that, and what the guide documents for
it:

| | Ecosystem tests | Client lab |
|---|---|---|
| Runs | on every push | nightly, on demand, and when the lab or the guide changes |
| Clients | one per ecosystem (30) | every client the guide documents: also Yarn, pnpm, Bun, uv, Poetry, PDM, Gradle, containerd, skopeo, OpenTofu, micromamba, gem, `puppet module`, … |
| Proxy address | `http://127.0.0.1:<port>` | `https://proxy.example.com`, with a certificate from a private CA |
| Access control | off | off, on (a token is required), and on with an anonymous role |
| Asserts | install, cache hit, refusal of a blocked package | the configuration works — CA, token and all; lock files say what the guide says they do; a limitation the guide states is still there |
| A client that asks another host | cannot reach it (no network) | cannot reach it, **and is caught asking** |

## How it works

<!-- illustration -->

```
        ┌────────────── lab network (internal: no way out) ──────────────┐
        │                                                                │
        │  client container                    proxy.example.com         │
        │   the real client, its own image  ──►  the real pullthrough ───┼──► registries
        │   /etc/ssl/corp-ca.pem (the CA)        HTTPS, private CA       │
        │   /etc/resolv.conf ──► dnslog                                  │
        │                         answers proxy.example.com,             │
        │                         logs every other name: NXDOMAIN        │
        └────────────────────────────────────────────────────────────────┘
```

- **The proxy** is the binary built from the checkout, with
  [`proxy.yaml`](../scripts/client-lab/proxy.yaml): every upstream type, under
  the names the guide uses, served as `https://proxy.example.com` with a
  certificate from a CA the lab creates. There are three of them, one per
  **mode**, each on a network of its own:

  | Mode | Access control |
  |---|---|
  | `open` | off |
  | `auth` | on: every request needs the token ([`proxy-auth.yaml`](../scripts/client-lab/proxy-auth.yaml)) |
  | `anon` | on, and anonymous reads admitted for the Conan upstream alone ([`proxy-anon.yaml`](../scripts/client-lab/proxy-anon.yaml)) |

- **A client** runs in its ecosystem's own container image on that network. It
  gets the CA certificate at `/etc/ssl/corp-ca.pem` — the path the guide uses —
  and, in `auth` and `anon`, the token in `$PROXY_TOKEN`. Nothing else: the
  script has to configure the client the way the guide says.
- **The name server**
  ([`dnslog`](../scripts/client-lab/dnslog/main.go)) is the client's only
  resolver. It answers the proxy's name, answers "no such domain" for every
  other one, and logs each question. After a run, the names a client looked up
  besides the proxy's are the hosts it would have gone to. A run **fails** when
  a client asks for a host its script does not declare.

That last point is what the lab adds to "the client has no other network". A
package manager that tries the public registry first and shrugs when it does
not answer installs just fine on a network without a way out — and talks to the
registry directly on one that has it. The lab found one such configuration in
the first hour (Composer, below), in a test that had been green in CI all
along.

## Run it

Requirements: Docker, Go, `openssl`, and network access to the public
registries. Every client runs in its own image; nothing else is installed.

<!-- illustration -->

```sh
make client-lab                           # start the lab, run every script (a while)
make client-lab CLIENTS="npm yarn pnpm"   # a selection
make client-lab-report                    # write the result table below into this page
make client-lab-down

scripts/client-lab/lab.sh run npm auth    # one script in one mode
scripts/client-lab/lab.sh logs npm auth   # its output, the requests it made, the names it looked up
scripts/client-lab/lab.sh list            # every script, with its image and modes
```

| Variable | Default | Meaning |
|---|---|---|
| `CLIENT_LAB_DIR` | `$TMPDIR/pullthrough-client-lab` | Where the lab keeps its state: the CA, the proxies' caches, logs, results. |
| `CLIENT_LAB_PROXY_BIN` | built from the checkout | A prebuilt, statically linked `pullthrough` to test. |
| `LAB_KEEP_IMAGES` | `1` | `0` removes an image the lab pulled once its last script has run (small disks). |
| `LAB_KEEP_WORK` | `0` | `1` keeps a run's scratch directory for inspection. |

## Results

<!-- results:begin -->

Last run: 2026-11-11, linux/x86_64.

| Client | Version | No access control | Token required | Token required, anonymous role | Other hosts looked up | Script |
|---|---|---|---|---|---|---|
| ansible-galaxy | 2.21.6 | ✔ | ✔ | — | — | [`ansible.sh`](../scripts/client-lab/clients/ansible.sh) |
| APT | 2.6.1 | ✔ | ✔ | — | — | [`apt.sh`](../scripts/client-lab/clients/apt.sh) |
| Bazel | 7.4.1 | ✔ | ✔ | — | — | [`bazel.sh`](../scripts/client-lab/clients/bazel.sh) |
| Homebrew | 4.6.20 | ✔ | ✔ | — | — | [`brew.sh`](../scripts/client-lab/clients/brew.sh) |
| Bundler | 2.5.22 | ✔ | ✔ | — | — | [`bundler.sh`](../scripts/client-lab/clients/bundler.sh) |
| Bun | 1.1.45 | ✔ | ✔ | — | — | [`bun.sh`](../scripts/client-lab/clients/bun.sh) |
| cabal | 3.16.1.0 | ✔ | ✔ | — | _mirrors.proxy.example.com | [`cabal.sh`](../scripts/client-lab/clients/cabal.sh) |
| cargo (--config flags) | 1.99.1 | ✔ | — | — | index.crates.io | [`cargo-flags.sh`](../scripts/client-lab/clients/cargo-flags.sh) |
| cargo | 1.99.1 | ✔ | — | — | — | [`cargo.sh`](../scripts/client-lab/clients/cargo.sh) |
| cargo (with a token: refused) | 1.99.1 | — | ✔ | ✔ | — | [`cargo-token.sh`](../scripts/client-lab/clients/cargo-token.sh) |
| Composer | 2.11.2 | ✔ | ✔ | — | — | [`composer.sh`](../scripts/client-lab/clients/composer.sh) |
| Conan 2 | 2.34.0 | ✔ | — | ✔ | — | [`conan.sh`](../scripts/client-lab/clients/conan.sh) |
| Conan 2 (with a token: refused) | 2.34.0 | — | ✔ | — | — | [`conan-token.sh`](../scripts/client-lab/clients/conan-token.sh) |
| conda | 24.9.2 | ✔ | ✔ | — | — | [`conda.sh`](../scripts/client-lab/clients/conda.sh) |
| containerd | v1.7.25 | ✔ | ✔ | — | — | [`containerd.sh`](../scripts/client-lab/clients/containerd.sh) |
| cpanm | 1.7049 | ✔ | ✔ | — | — | [`cpanm.sh`](../scripts/client-lab/clients/cpanm.sh) |
| R (install.packages) | 4.4.1 | ✔ | ✔ | — | — | [`cran.sh`](../scripts/client-lab/clients/cran.sh) |
| dart pub | 3.5.4 | ✔ | ✔ | — | — | [`dart.sh`](../scripts/client-lab/clients/dart.sh) |
| Deno | 2.9.8 | ✔ | ✔ | — | — | [`deno.sh`](../scripts/client-lab/clients/deno.sh) |
| DNF | 4.14.0 | ✔ | ✔ | — | — | [`dnf.sh`](../scripts/client-lab/clients/dnf.sh) |
| Docker Engine (with a token: refused) | 27.5.1 | — | ✔ | — | — | [`docker-login.sh`](../scripts/client-lab/clients/docker-login.sh) |
| Docker Engine | 27.5.1 | ✔ | — | — | docker.io | [`docker.sh`](../scripts/client-lab/clients/docker.sh) |
| RubyGems (gem) and a Gemfile source | 3.5.22 | ✔ | ✔ | — | — | [`gem.sh`](../scripts/client-lab/clients/gem.sh) |
| Git | 2.49.1 | ✔ | ✔ | — | — | [`git.sh`](../scripts/client-lab/clients/git.sh) |
| go | 1.24.13 | ✔ | ✔ | — | — | [`go.sh`](../scripts/client-lab/clients/go.sh) |
| Gradle | 8.10.2 | ✔ | ✔ | — | — | [`gradle.sh`](../scripts/client-lab/clients/gradle.sh) |
| Helm | v3.16.3+gcfd0749 | ✔ | ✔ | — | — | [`helm.sh`](../scripts/client-lab/clients/helm.sh) |
| mix (Hex) | 1.16.3 | ✔ | — | — | — | [`hex.sh`](../scripts/client-lab/clients/hex.sh) |
| mix (with a token: refused) | 1.16.3 | — | ✔ | — | — | [`hex-token.sh`](../scripts/client-lab/clients/hex-token.sh) |
| huggingface_hub | 2.4.0 | ✔ | ✔ | — | — | [`huggingface.sh`](../scripts/client-lab/clients/huggingface.sh) |
| Julia Pkg | 1.10.13 | ✔ | ✔ | — | — | [`julia.sh`](../scripts/client-lab/clients/julia.sh) |
| Composer (an existing lock file, written against packagist.org) | 2.11.2 | ✔ | ✔ | — | api.github.com | [`lock-composer.sh`](../scripts/client-lab/clients/lock-composer.sh) |
| npm (an existing lock file, written against npmjs.org) | 10.9.9 | ✔ | ✔ | — | — | [`lock-npm.sh`](../scripts/client-lab/clients/lock-npm.sh) |
| Poetry (an existing lock file, written against PyPI) | 2.5.1 | ✔ | ✔ | — | — | [`lock-poetry.sh`](../scripts/client-lab/clients/lock-poetry.sh) |
| dart pub (an existing lock file, written against pub.dev) | 3.5.4 | ✔ | ✔ | — | — | [`lock-pub.sh`](../scripts/client-lab/clients/lock-pub.sh) |
| uv (an existing lock file, written against pypi.org) | 0.13.7 | ✔ | ✔ | — | — | [`lock-uv.sh`](../scripts/client-lab/clients/lock-uv.sh) |
| Yarn 1 (an existing lock file, written against the public registry) | 1.22.22 | ✔ | ✔ | — | registry.yarnpkg.com | [`lock-yarn-classic.sh`](../scripts/client-lab/clients/lock-yarn-classic.sh) |
| Maven (user name + password) | 3.9.16 | — | ✔ | — | — | [`maven-basic.sh`](../scripts/client-lab/clients/maven-basic.sh) |
| Maven | 3.9.16 | ✔ | ✔ | — | — | [`maven.sh`](../scripts/client-lab/clients/maven.sh) |
| micromamba | 2.0.5 | ✔ | ✔ | — | — | [`micromamba.sh`](../scripts/client-lab/clients/micromamba.sh) |
| Nix | 2.35.6 | ✔ | ✔ | — | — | [`nix.sh`](../scripts/client-lab/clients/nix.sh) |
| npm (environment only) | 10.9.9 | ✔ | ✔ | — | — | [`npm-env.sh`](../scripts/client-lab/clients/npm-env.sh) |
| npm (JSR packages through npm.jsr.io) | 10.9.9 | ✔ | ✔ | — | — | [`npm-jsr.sh`](../scripts/client-lab/clients/npm-jsr.sh) |
| npm | 10.9.9 | ✔ | ✔ | — | — | [`npm.sh`](../scripts/client-lab/clients/npm.sh) |
| NuGet (dotnet) | 8.0.428 | ✔ | — | — | — | [`nuget.sh`](../scripts/client-lab/clients/nuget.sh) |
| NuGet (with a token: refused) | 8.0.428 | — | ✔ | — | — | [`nuget-token.sh`](../scripts/client-lab/clients/nuget-token.sh) |
| ovsx | 1.4.0 | ✔ | ✔ | — | — | [`openvsx.sh`](../scripts/client-lab/clients/openvsx.sh) |
| PDM | 2.29.7 | ✔ | ✔ | — | — | [`pdm.sh`](../scripts/client-lab/clients/pdm.sh) |
| pip (environment + ~/.netrc) | 25.0.1 | ✔ | ✔ | — | — | [`pip-netrc.sh`](../scripts/client-lab/clients/pip-netrc.sh) |
| pip | 25.0.1 | ✔ | ✔ | — | — | [`pip.sh`](../scripts/client-lab/clients/pip.sh) |
| pnpm | 9.15.0 | ✔ | ✔ | — | — | [`pnpm.sh`](../scripts/client-lab/clients/pnpm.sh) |
| Poetry | 2.5.1 | ✔ | ✔ | — | — | [`poetry.sh`](../scripts/client-lab/clients/poetry.sh) |
| puppet module | 8.10.0 | ✔ | ✔ | — | — | [`puppet.sh`](../scripts/client-lab/clients/puppet.sh) |
| r10k | 5.0.3 | ✔ | ✔ | — | — | [`r10k.sh`](../scripts/client-lab/clients/r10k.sh) |
| cargo (a refused crate) | 1.99.1 | ✔ | — | — | — | [`refused-cargo.sh`](../scripts/client-lab/clients/refused-cargo.sh) |
| go (a refused module) | 1.24.13 | ✔ | ✔ | — | — | [`refused-go.sh`](../scripts/client-lab/clients/refused-go.sh) |
| npm (a refused package) | 10.9.9 | ✔ | ✔ | — | — | [`refused-npm.sh`](../scripts/client-lab/clients/refused-npm.sh) |
| pip (a refused package) | 25.0.1 | ✔ | ✔ | — | — | [`refused-pip.sh`](../scripts/client-lab/clients/refused-pip.sh) |
| skopeo (Podman, Buildah, CRI-O) | 1.17.0 | ✔ | — | — | — | [`skopeo.sh`](../scripts/client-lab/clients/skopeo.sh) |
| Terraform | v1.9.8 | ✔ | ✔ | — | — | [`terraform.sh`](../scripts/client-lab/clients/terraform.sh) |
| OpenTofu | v1.8.11 | ✔ | ✔ | — | — | [`tofu.sh`](../scripts/client-lab/clients/tofu.sh) |
| uv | 0.13.7 | ✔ | ✔ | — | — | [`uv.sh`](../scripts/client-lab/clients/uv.sh) |
| Yarn 1 (classic) | 1.22.22 | ✔ | ✔ | — | — | [`yarn-classic.sh`](../scripts/client-lab/clients/yarn-classic.sh) |
| Yarn 4 (berry) | 4.5.3 | ✔ | ✔ | — | — | [`yarn.sh`](../scripts/client-lab/clients/yarn.sh) |

<!-- results:end -->

**✔** the script passed · **—** the script is not for that mode · *Other hosts
looked up*: names besides the proxy's that the client asked the name server
for, all declared in the script.

A script whose client name says *refused* asserts a **limitation**: it passes
when the client still cannot do what the guide says it cannot (present a token,
mostly), and fails — telling the guide to be updated — when it can.

## What the lab found

Running the documented configurations for real changed the documentation, the
tooling and the proxy:

- **OpenTofu could not install modules through the proxy.** Its registry names
  a module's source in a JSON body, which the Terraform backend dropped. Fixed
  in the backend ([backends: terraform](backends.md#terraform)).
- **Composer was leaking to packagist.org.** Redefining the `packagist`
  repository — what the ecosystem test and the documentation did — does not
  switch packagist.org off in Composer 2.11; Composer kept asking
  `repo.packagist.org`. Invisible without a way out; caught by the name server.
  The test, the guide and `ptctl config` now switch it off
  ([Composer](clients/composer.md#configure)).
- **Composer and Yarn 1 install an existing lock file from the hosts it
  names** — GitHub, `registry.yarnpkg.com` — not through the proxy; npm, uv,
  Poetry and pub do not. The guide now says what to do for each
  ([moving a project](clients.md#moving-an-existing-project-onto-the-proxy)).
- **A documented cargo configuration never worked.** `CARGO_SOURCE_…`
  environment variables are ignored by cargo; `--config` flags work
  ([cargo](clients/cargo.md#configure)).
- **Mix skips certificate verification** when the CA is not in the system
  trust store, with a warning, instead of failing
  ([Hex](clients/hex.md#trust-a-private-ca)).
- **Homebrew falls back to the public formula API** when it cannot verify the
  proxy's certificate — and no environment variable gives it the CA
  ([Homebrew](clients/homebrew.md#trust-a-private-ca)).
- **dart pub trusts the system store only** — `SSL_CERT_FILE` is ignored
  ([Dart](clients/dart.md#trust-a-private-ca)).
- **Clients ask hosts that are not registries**: Terraform asks
  `checkpoint-api.hashicorp.com` for new versions of itself, the `hf` command
  asks pypi.org, NuGet asks the signing CAs' revocation servers while verifying
  package signatures. Each page says how to switch that off.
- **Several clients cannot present a token to the proxy**: cargo, NuGet, the
  Docker Engine and the clients that share Podman's library, Helm for OCI
  charts, Terraform and OpenTofu for providers, Conan, mix, ovsx; Git and Maven
  only in one of their forms. The guide says so per client, `ptctl config` no
  longer prints credentials those clients cannot send, and the lab asserts each
  limitation so that the guide follows when one is lifted
  ([which clients](clients.md#clients-that-cannot-present-a-token)).
- **An anonymous role turns `401` into `403`** for requests without a token to
  other upstreams, which keeps a client that waits for a `401` from ever
  sending its token ([access control](clients.md#clients-that-cannot-present-a-token)).

## Writing a script

A script is a POSIX `sh` file in
[`scripts/client-lab/clients`](../scripts/client-lab/clients) that configures
one client the way the guide says and uses it. It starts with a few header
lines:

<!-- illustration -->

```sh
#!/bin/sh
# lab: client=npm                 the name in the result table (required)
# lab: image=node:22-slim         the client's image, pinned (required)
# lab: modes=open auth            the modes it is for (this is the default)
# lab: entrypoint=sh              for images whose entrypoint is the tool itself
# lab: daemon=docker              the client is a container engine: run it as a private daemon
# lab: user=0                     for images that default to an unprivileged user
# lab: lookups=docker.io          hosts besides the proxy the client is known to look up
set -eu
echo "LAB_CLIENT_VERSION=$(npm --version)"
```

Rules, most of which a test enforces:

- Write addresses and paths as the guide prints them
  (`https://proxy.example.com/v1/npm/`, `/etc/ssl/corp-ca.pem`): a block of the
  guide is verified by finding its lines in the script.
- Add credential lines only when `$PROXY_TOKEN` is set, so one script serves
  every mode.
- Assert what the guide claims — that a lock file does or does not name the
  proxy, that an alternative that looks right does not work.
- Run under `set -eu`, and print `LAB_CLIENT_VERSION=<version>`.
- Then run it (`lab.sh run <name>`), regenerate the table above
  (`make client-lab-report`), and reference the script from the guide:

<!-- illustration -->

```
<!-- verified: lab:npm -->
(a fenced block whose every line is in scripts/client-lab/clients/npm.sh)
```

The markers a block of the guide may carry, and what
[`internal/clientguide`](../internal/clientguide) checks for each:

| Marker | Meaning | Check |
|---|---|---|
| `verified: lab:<script> ci:<ecosystem>` | executed by these scripts | every line is in one of them; every script named holds at least one |
| `output: lab:<script>` | what a run printed | the script exists |
| `proxy-config` | a fragment of the proxy's configuration | it is YAML, and every key is a real setting |
| `untested: <reason>` | not executed | a reason is given |
| `illustration` | not something to type | — |

## In CI

The `Client lab` workflow
([`.github/workflows/client-lab.yml`](../.github/workflows/client-lab.yml))
builds the proxy once, derives one job per client image from the scripts
themselves (`lab.sh matrix`), runs each group, and assembles the result table
into the run summary. It fails unless every script ran and passed in every
mode it is for. It runs nightly — a canary for client releases and registry
changes — on demand, and on changes to the lab or the guide; it does not gate
a push, because it depends on some thirty images and as many public registries
being up.

`go test ./internal/clientguide/`, which holds the guide to the scripts, is
part of the ordinary test run.
