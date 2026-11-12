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
| Clients | one per ecosystem (32) | every client the guide documents: also Yarn, pnpm, Bun, uv, Poetry, PDM, Gradle, containerd, skopeo, OpenTofu, micromamba, gem, `puppet module`, … |
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
  [`proxy.yaml`](../scripts/client-lab/proxy.yaml): every upstream type —
  `swift` in front of Tuist's public registry, `generic` in front of Alpine's
  package mirror (no lab script runs SwiftPM or apk yet; the ecosystem tests
  do) — under the names the guide uses, served as `https://proxy.example.com`
  with a certificate from a CA the lab creates. There are three of them, one per
  **mode**, each on a network of its own:

  | Mode | Access control |
  |---|---|
  | `open` | off |
  | `auth` | on: every request needs the token ([`proxy-auth.yaml`](../scripts/client-lab/proxy-auth.yaml)) |
  | `anon` | on, and anonymous reads admitted for the Conan upstream alone ([`proxy-anon.yaml`](../scripts/client-lab/proxy-anon.yaml)) |

- **A client** runs in its ecosystem's own container image on that network. It
  gets the CA certificate at `/etc/ssl/corp-ca.pem` — the path the guide uses —
  the mode in `$LAB_MODE` and, in `auth` and `anon`, the token in
  `$PROXY_TOKEN`. Nothing else: the script has to configure the client the way
  the guide says.
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
scripts/client-lab/lab.sh check           # which scripts are missing a passing result
```

The lab's CA and certificate last 30 days — a lab directory is scratch space —
and `lab.sh up` makes new ones when they are about to run out.

| Variable | Default | Meaning |
|---|---|---|
| `CLIENT_LAB_DIR` | `$TMPDIR/pullthrough-client-lab` | Where the lab keeps its state: the CA, the proxies' caches, logs, results. |
| `CLIENT_LAB_PROXY_BIN` | built from the checkout | A prebuilt, statically linked `pullthrough` for linux to test. |
| `CLIENT_LAB_PROXY_IMAGE` | `alpine/git` | The image the proxy runs in: anything with `git`, CA certificates and `wget`. |
| `LAB_KEEP_IMAGES` | `1` | `0` removes an image the lab pulled once its last script has run (small disks). |
| `LAB_KEEP_WORK` | `0` | `1` keeps a run's scratch directory for inspection. |

## Results

<!-- results:begin -->

Last run: 2026-11-12, linux/x86_64.

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
| Docker Engine (docker login) | 27.5.1 | — | ✔ | — | — | [`docker-login.sh`](../scripts/client-lab/clients/docker-login.sh) |
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
| skopeo (Podman, Buildah, CRI-O) | 1.17.0 | ✔ | ✔ | — | — | [`skopeo.sh`](../scripts/client-lab/clients/skopeo.sh) |
| Terraform | v1.9.8 | ✔ | ✔ | — | — | [`terraform.sh`](../scripts/client-lab/clients/terraform.sh) |
| OpenTofu | v1.8.11 | ✔ | ✔ | — | — | [`tofu.sh`](../scripts/client-lab/clients/tofu.sh) |
| uv | 0.13.7 | ✔ | ✔ | — | — | [`uv.sh`](../scripts/client-lab/clients/uv.sh) |
| Yarn 1 (classic) | 1.22.22 | ✔ | ✔ | — | — | [`yarn-classic.sh`](../scripts/client-lab/clients/yarn-classic.sh) |
| Yarn 4 (berry) | 4.5.3 | ✔ | ✔ | — | — | [`yarn.sh`](../scripts/client-lab/clients/yarn.sh) |

<!-- fingerprints: what each script executed when it produced its row (lab.sh document)
ansible 77a1e435e34f
apt 4e9089c4e9ed
bazel 420f0e50fe9f
brew 572f687c1bdf
bundler 99b45664b51f
bun 8996e206868e
cabal 0c7b9131d2cc
cargo-flags 4de24e9c6d54
cargo 4eea2834617f
cargo-token 585539c75afe
composer 43598c625c69
conan 586d2e9917a5
conan-token b3d1b0522a27
conda 96a42a6800a8
containerd 902de43cad4a
cpanm 612b416cd570
cran 0c32c9d5eae9
dart 5fa99b599820
deno 5a34612e29c8
dnf 7b64165e9e5d
docker-login ba02ea48d1cc
docker 9643275c270c
gem 23e5f2282587
git 624ae43130f4
go 71ce814e4af3
gradle 336a42c56280
helm eeef309fef0e
hex ab46b2828f3e
hex-token 1518bdbd0854
huggingface 25375d201adf
julia 74e7e2be3589
lock-composer e3232366259d
lock-npm 4201826a2c6e
lock-poetry 43e9e0e54602
lock-pub 097782e47f0f
lock-uv 289dce3d08c4
lock-yarn-classic ac536d96aa96
maven-basic 1fdebbccc5e2
maven 72ab2ee7d060
micromamba a20141be2b07
nix d0f1dc76eb9b
npm-env dc6655485f89
npm-jsr 4002ea5f9e7a
npm de353d7e54a1
nuget 3a8df6311fd4
nuget-token da49199b38e6
openvsx 544fdc8f90e5
pdm 0656c5ea6c29
pip-netrc 29af0e5f1677
pip e8ab457ae544
pnpm 303ba01e75c1
poetry bd3a8e796e2d
puppet cddda50d22f7
r10k ef9a1ea2f8a7
refused-cargo 2b3150e9baaa
refused-go da63b18d03cd
refused-npm 67d9252420e6
refused-pip f87b2d06a802
skopeo 1010d3830066
terraform 092d85c93c62
tofu edef86277dc2
uv c098c8c7f3f9
yarn-classic aa4145f4eb87
yarn 1a9294439d81
-->

<!-- results:end -->

**✔** the script passed · **—** the script is not for that mode · *Other hosts
looked up*: names besides the proxy's that the client asked the name server
for, all declared in the script.

A script named *with a token: refused* asserts a **limitation**: it passes
when the client still cannot do what the guide says it cannot (present a token,
mostly), and fails — telling the guide to be updated — when it can. So do
single steps of other scripts (`git`, `helm`, `skopeo`, `terraform`, `tofu`,
`openvsx`). The scripts named *a refused package* (crate, module) are
something else: they show what a client prints when the proxy blocks a
package.

A row is the result of the script as it is now. Each run records a fingerprint
of what its script executes, `lab.sh document` writes the table only when
every script has passed in every mode it is for, and a test fails when a
script has changed since its row was written — so an edited script has to be
run again before its ✔ is worth anything.

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
- **Mix skips certificate verification** on a machine with no system trust
  store at all — a slim container image — with a warning, instead of failing
  ([Hex](clients/hex.md#trust-a-private-ca)).
- **Homebrew falls back to the public formula API** when it cannot verify the
  proxy's certificate — and no environment variable gives it the CA
  ([Homebrew](clients/homebrew.md#trust-a-private-ca)).
- **dart pub trusts the system store only** — `SSL_CERT_FILE` is ignored
  ([Dart](clients/dart.md#trust-a-private-ca)).
- **Clients ask hosts that are not registries**: Terraform asks
  `checkpoint-api.hashicorp.com` for new versions of itself, the `hf` command
  asks pypi.org, NuGet asks the signing CAs' revocation servers while verifying
  package signatures, the `dotnet` command reports usage to
  `dc.services.visualstudio.com`, brew updates itself from `github.com`. Each
  page says how to switch that off, and each script that sets such a switch
  was also run without it to see what it is for.
- **Several clients cannot present a token to the proxy**: cargo, NuGet,
  Terraform and OpenTofu for providers, Conan, mix, ovsx; Maven only in some of
  its forms. The guide says so per client, and the lab asserts these
  limitations so that the guide follows when one is lifted
  ([which clients](clients.md#clients-that-cannot-present-a-token)). The Docker
  Engine, the library Podman, Buildah, CRI-O and skopeo share, Helm for OCI
  charts and Git with a credential helper were on this list while the proxy
  challenged every client with `Bearer`: they read it as the address of a token
  service, or answer only a `Basic` challenge. The proxy now challenges
  container registry and Git requests with `Basic`, and the lab asserts that
  `docker login`, `skopeo login`, `helm registry login` and a Git credential
  helper work.
- **`ptctl config` printed configurations that cannot work**: a
  `mix hex.repo add` that Hex rejects, credentials cargo and NuGet never send,
  a token in a Git URL, a conda channel alias whose credentials conda drops, a
  `GOPROXY` with a `,direct` fallback. Those are corrected; where its snippets
  still differ from the guide is listed on [its page](client-cli.md).
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
  (`https://proxy.example.com/v1/npm/`, `/etc/ssl/corp-ca.pem`), and give a
  command the guide prints a line of its own: a line of the guide is verified
  by being a whole line of the script. Write a configuration file with a here
  document, so that the script has the file's lines as the guide shows them.
- Add credential lines only when `$PROXY_TOKEN` is set, so one script serves
  every mode.
- Assert what the guide claims — that a lock file does or does not name the
  proxy, that an alternative that looks right does not work.
- Run under `set -eu`, and print `LAB_CLIENT_VERSION=<version>`. Write "this
  must not be there" as `if grep -q … ; then echo …; exit 1; fi`: a negated
  command (`! grep -q …`) never fails a script, whatever `set -e` suggests.
- A switch that keeps the client from asking another host belongs on the
  client's page as well. A script that needs `DOTNET_CLI_TELEMETRY_OPTOUT=1` to
  stay on the proxy has found something the page has to say: run it once
  without the switch, and write down which host it is for.
- Then run it (`lab.sh run <name>`), regenerate the table above
  (`make client-lab-report`, which refuses while a script is missing, failing
  or changed since it ran), and reference the script from the guide:

<!-- illustration -->

```
<!-- verified: lab:npm -->
(a fenced block whose every line is in scripts/client-lab/clients/npm.sh)
```

The markers a block of the guide may carry, and what
[`internal/clientguide`](../internal/clientguide) checks for each:

| Marker | Meaning | Check |
|---|---|---|
| `verified: lab:<script> ci:<ecosystem>` | executed by these scripts | every line is a whole line one of them executes (a comment in a script is not executed), in the script's order; the lines of a file are written by one script and nested as it nests them; every script named executes a line of the block; the block has no comments of its own |
| `output: lab:<script>` | what a run printed | the script exists; the block has no language |
| `proxy-config` | a fragment of the proxy's configuration | it decodes as the proxy's configuration: real settings, values of their types, upstream types that exist |
| `untested: <reason>` | not executed | a reason is given |
| `illustration` | not something to type | — |

What the check cannot show is that a block is complete: a block may be part of
a file — the registry line of an `.npmrc` under *Configure*, its token line
under *Authenticate* — so one that leaves out a line the client needs passes
all the same. Two things narrow that gap: a block of a configuration language
has to close the brackets it opens (a file cut short does not), and the lines
without which a configured client still goes to the public registry —
`default_channels: []`, `{ "packagist.org": false }`, `<clear />`,
`--mirror-only` and the like — are listed in the test and have to be on their
pages. The rest is for a reader of the page to catch.

The same scripts stand behind `ptctl config`: for the ecosystems listed in the
test (`heldGenerators`), every line it prints is a line a lab script executes.

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
