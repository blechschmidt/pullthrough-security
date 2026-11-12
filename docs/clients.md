# Client configuration

How to point each package manager at the pull-through proxy — and, where a
deployment has them, how to hand it a token and a private CA certificate. There
is one page per ecosystem; this page holds what they have in common.

> **Every configuration in this guide is executed.** Each line of a snippet
> marked as verified is a line of a script that a real client runs: the
> [ecosystem tests](ecosystem-tests.md) run each ecosystem's client through the
> proxy in CI on every push, and the [client lab](client-lab.md) runs the rest
> — other clients of an ecosystem, a private CA, a required token — on a
> network where the proxy is the only host a client can reach and every name
> it looks up is recorded. A test
> ([`internal/clientguide`](../internal/clientguide)) fails when a snippet and
> its script drift apart. What was not executed says so.

## Two ways to use the proxy

This guide covers **explicit package sources**: each tool is told to use
`https://proxy.example.com/v1/<name>/` instead of the public registry. The
proxy can also **intercept TLS** — clients keep the public registry's address
and are given an HTTP proxy and the proxy's CA instead; see
[intercept-mode.md](intercept-mode.md). The CA settings below apply to both.

## What you need

Ask the proxy's operator for four things:

| | In this guide | |
|---|---|---|
| The proxy's address | `https://proxy.example.com` | `server.publicUrl` of the proxy |
| The name of each upstream | `npm`, `pypi`, `crates`, … | A package source is `https://proxy.example.com/v1/<name>/`. Names are the operator's choice; the guide uses those of the lab's proxy ([`scripts/client-lab/proxy.yaml`](../scripts/client-lab/proxy.yaml)). |
| A token, if access control is on | `<token>` | Your **proxy** token — never a registry's. The proxy holds the upstream credentials. |
| The CA certificate, if it is a private one | `/etc/ssl/corp-ca.pem` | Only when the proxy's certificate is not issued by a public CA. |

[`ptctl config`](client-cli.md) asks the proxy for its upstreams and prints a
configuration for each of them as a starting point (where it differs from this
guide, the guide is the one that was executed), and `ptctl selftest` tells a
network problem from a rejected token.

> **Per-user addresses.** With [personal cache links](user-links.md) every
> cache user has their own address of each backend —
> `https://proxy.example.com/u/<link>/v1/<name>/...` — so that downloads are
> recorded per user. Everything in this guide applies with that address in
> place of the mount; the links page (and `ptctl config --personal-link`)
> generates the configuration, and says for each client where the link must not
> end up (lock files that record URLs, files under version control).

## Every ecosystem

| Ecosystem | Clients | What you set | Token |
|---|---|---|---|
| [npm](clients/npm.md) | npm, Yarn, pnpm, Bun | `registry=` in `.npmrc` | ✔ |
| [Python](clients/pip.md) | pip, uv, Poetry, PDM | `index-url` in `pip.conf` | ✔ |
| [Rust](clients/cargo.md) | cargo | source replacement in `config.toml` | ✘ |
| [Go](clients/go.md) | go | `GOPROXY` | ✔ |
| [.NET](clients/nuget.md) | dotnet (NuGet) | `NuGet.config` | ✘ |
| [JVM](clients/maven.md) | Maven, Gradle | a mirror in `settings.xml`; an init script | ✔ |
| [Container images](clients/docker.md) | Docker Engine, containerd, Podman, skopeo | an image reference, or a registry mirror | containerd and skopeo only |
| [Helm](clients/helm.md) | helm | `helm repo add`, or `oci://` | classic repositories only |
| [Ruby](clients/rubygems.md) | Bundler, gem | a Bundler mirror | ✔ |
| [PHP](clients/composer.md) | Composer | repositories in `config.json` | ✔ |
| [Terraform](clients/terraform.md) | terraform, tofu | a `host` block in `.terraformrc` | modules only |
| [C and C++](clients/conan.md) | Conan 2 | `conan remote add` | ✘ |
| [Debian, Ubuntu](clients/apt.md) | apt | a `.sources` file | ✔ |
| [RHEL, Fedora, Rocky](clients/yum.md) | dnf | a `.repo` file | ✔ |
| [Git](clients/git.md) | git | `url.<proxy>.insteadOf` | ✔ |
| [Elixir, Erlang](clients/hex.md) | mix | `HEX_MIRROR` | ✘ |
| [Bazel](clients/bazel.md) | bazel | `--registry` in `.bazelrc` | ✔ |
| [Julia](clients/julia.md) | julia | `JULIA_PKG_SERVER` | ✔ |
| [Perl](clients/cpan.md) | cpanm | `--mirror … --mirror-only` | ✔ |
| [VS Code extensions](clients/openvsx.md) | ovsx | `--registryUrl` | ✘ |
| [Nix](clients/nix.md) | nix | `substituters` in `nix.conf` | ✔ |
| [JSR](clients/jsr.md) | deno | `JSR_URL` | ✔ |
| [Haskell](clients/hackage.md) | cabal | a `repository` stanza | ✔ |
| [Homebrew](clients/homebrew.md) | brew | `HOMEBREW_API_DOMAIN` and `HOMEBREW_ARTIFACT_DOMAIN` | ✔ |
| [Ansible](clients/ansible.md) | ansible-galaxy | a `[galaxy_server.*]` entry | ✔ |
| [Conda](clients/conda.md) | conda, micromamba | `channel_alias` in `.condarc` | ✔ |
| [Hugging Face](clients/huggingface.md) | huggingface_hub | `HF_ENDPOINT` | ✔ |
| [Dart, Flutter](clients/dart.md) | dart pub | `PUB_HOSTED_URL` | ✔ |
| [R](clients/cran.md) | R | `options(repos = …)` | ✔ |
| [Puppet](clients/puppet.md) | r10k, puppet module | `forge.baseurl` | ✔ |
| [Swift](clients/swift.md) | swift | `swift package-registry set` | not tested |
| [Anything else](clients/generic.md) | — | the upstream's address | — |

**Token**: whether the client can present a proxy token, where access control
is on (✘: see [below](#clients-that-cannot-present-a-token)).

Every page has the same sections: *Configure*, *Authenticate*, *Trust a private
CA*, *Check that it works*, *Good to know* (lock files, what does not go through
the proxy, what a refusal looks like) and *On the proxy* (the operator's side,
with a link to the [backend reference](backends.md)).

## Access control

Access control is off unless the operator switches it on (`auth.enabled`). When
it is on, every request needs a proxy token — an API token the operator issued,
or an OIDC token ([access-control-and-audit.md](access-control-and-audit.md)).

### How the proxy takes a token

Package managers disagree about how a credential is sent, so the proxy accepts
one in any of these places:

| Form | Sent by |
|---|---|
| `Authorization: Bearer <token>` (also `token <token>`) | npm, Yarn, pnpm, Bun, Composer, Maven and Gradle (as a configured header), containerd, Git (as a configured header), Julia, Deno, dart pub, Hugging Face, ansible-galaxy, r10k, puppet |
| HTTP Basic, the token as the **password** (any user name) | pip, uv, Poetry, PDM, go, Bundler, gem, apt, dnf, Helm, cpanm, conda, Nix, Bazel, R, cabal (through curl), Homebrew (through curl), the Docker Engine, Podman, Buildah, CRI-O and skopeo (a login), Git (a credential helper) |
| HTTP Basic, the token as the user name | accepted, for tools that put a token there |
| `X-Api-Token: <token>` or `X-Auth-Token: <token>` | scripts and CI steps |

A request without a valid token is answered `401` with the challenge
`WWW-Authenticate: Bearer realm="pullthrough"` — except a request to a
container registry upstream and a Git request, which are challenged with
`Basic realm="pullthrough"`: a container client reads a `Bearer` challenge as
the address of a token service to log in to, and Git answers only a `Basic`
one from its credential helper. The challenge matters for the clients below: a
client that only ever sends its credentials in answer to a `Basic` challenge
never gets to send them to the other upstreams.

A [personal cache link](user-links.md) is a token too: where access control is
on, any of these forms can carry its token instead of an API token.

### Clients that cannot present a token

| Client | Why | See |
|---|---|---|
| cargo | sends its token for crate downloads only when the registry declares `auth-required`, which the proxy's `config.json` does not | [cargo](clients/cargo.md#authenticate) |
| NuGet | sends source credentials only in answer to a `Basic` challenge | [NuGet](clients/nuget.md#authenticate) |
| Terraform, OpenTofu (providers) | fetch checksums, signature and package without the token they send to the registry API | [Terraform](clients/terraform.md#authenticate) |
| Conan | gets its token from a login endpoint the proxy does not serve | [Conan](clients/conan.md#authenticate) |
| mix (Hex) | Mix has no credential setting for downloading Hex; Hex hands its key to hex.pm, not to a mirror | [Hex](clients/hex.md#authenticate) |
| ovsx | has a token only for publishing | [Open VSX](clients/openvsx.md#authenticate) |
| Maven with `<username>`/`<password>` | presents them only in answer to a `Basic` challenge — a header, or preemptive authentication, works | [Maven](clients/maven.md#authenticate) |

For the first six there is no client-side setting that helps. Two ways
remain. With [personal cache links](user-links.md), the client needs no token:
its user's link is part of the package source's address, so every request
carries it (the integration suite installs with the real cargo that way, on a
proxy that requires authentication). Otherwise, where access control is on, the
operator admits such a client **without** a token, for exactly its upstream,
and keeps the token requirement everywhere else — an anonymous role scoped to
that upstream:

<!-- proxy-config -->

```yaml
auth:
  enabled: true
  allowAnonymous: true
  anonymousRoles: ["conan-anonymous"]
  roles:
    - name: all-reader
      ecosystems: ["*"]
      upstreams: ["*"]
    - name: conan-anonymous
      ecosystems: ["conan"]
      upstreams: ["conancenter"]
  tokens:
    - name: alice
      team: platform
      roles: ["all-reader"]
      token: ${PTS_ALICE_TOKEN}
```

The lab runs Conan against a proxy configured this way
([`proxy-anon.yaml`](../scripts/client-lab/proxy-anon.yaml)). Two things to
know about it:

- Such an upstream is open to everyone who can reach the proxy. Restrict *who
  can reach it* by other means (network policy, mutual TLS:
  [spiffe-mtls.md](spiffe-mtls.md)).
- With an anonymous role present, a request without a token to any *other*
  upstream is answered `403` (an anonymous caller without a role for it), not
  `401`. A client that waits for a `401` before it sends its token — cargo —
  then never sends it.

## Private CA settings at a glance

A client only needs this when the proxy's certificate comes from a CA the
client does not already trust. Each ecosystem page has the details; the common
question is *which* setting a tool reads:

| Setting | Clients |
|---|---|
| `SSL_CERT_FILE` (environment) | go, uv, dotnet on Linux, terraform, tofu, Bundler, gem, r10k, puppet, cpanm, ansible-galaxy, huggingface_hub |
| `CURL_CA_BUNDLE` (environment) | R, cabal |
| `NODE_EXTRA_CA_CERTS` (environment) | npm, Yarn, pnpm, Corepack, ovsx |
| a tool's own variable | `PIP_CERT`, `CARGO_HTTP_CAINFO`, `DENO_CERT`, `HEX_CACERTS_PATH`, `JULIA_SSL_CA_ROOTS_PATH`, `REQUESTS_CA_BUNDLE` |
| a line in the tool's configuration | `.npmrc` `cafile=`, `.yarnrc.yml` `httpsCaFilePath`, `bunfig.toml` `cafile`, `pip.conf` `cert`, cargo `[http] cainfo`, Poetry `certificates.<source>.cert`, PDM `pypi.ca_certs`, Composer `cafile`, Conan `core.net.http:cacert_path`, `.condarc` `ssl_verify`, `nix.conf` `ssl-cert-file`, apt `Acquire::https::<host>::CAInfo`, dnf `sslcacert=`, Git `http.<url>.sslCAInfo`, Helm `--ca-file`, containerd `ca =` |
| a directory per registry host | Docker Engine (`/etc/docker/certs.d/<host>/ca.crt`), Podman and friends (`/etc/containers/certs.d/<host>/ca.crt`) |
| a JVM trust store (not a PEM file) | Maven, Gradle, Bazel |
| `~/.curlrc`, once brew is told to read it | Homebrew |
| **the system trust store only** | dart pub, Mix (for `mix local.hex`) |

Two results from the lab worth knowing before you debug one:

- **Mix stops verifying where there is no system trust store at all** — a slim
  container image, say. `mix local.hex` prints a warning and downloads over an
  unverified connection. With a trust store that merely lacks the CA it fails,
  as it should ([Hex](clients/hex.md#trust-a-private-ca)).
- **Homebrew falls back to the public API** when it cannot verify the proxy's
  certificate ([Homebrew](clients/homebrew.md#trust-a-private-ca)).

## When the proxy refuses a package

The proxy answers `403` for an artifact one of its checks refused — a blocked
source commit, a known-malicious package, a policy rule — with the reason in a
JSON body and in response headers:

<!-- illustration -->

```
HTTP/1.1 403 Forbidden
X-Policy-Decision: block
X-Policy-Code: denylist
X-Policy-Reason: package "left-pad" is denylisted by policy …
X-Cache: BLOCKED

{"error":"artifact blocked by supply-chain admission policy","code":"denylist","reason":"…","ecosystem":"npm","package":"left-pad","version":"1.3.0"}
```

How much of that a client shows differs: npm and cargo print the message, pip
and go print only `403`. The ecosystem pages show what each of them prints.

- `ptctl inspect <name>@<version>` shows the verdict and the findings behind
  it ([client CLI](client-cli.md)).
- A refusal is usually about one *version*. Metadata keeps being served, so
  resolving to another version often works.
- A `401` is not a refusal: it is a missing or rejected token. A `403` whose
  body says `no role of […] grants …` is access control too — your token's
  role does not cover that upstream.
- If you believe a refusal is wrong, the operator can review it and grant a
  time-boxed exception ([approvals.md](approvals.md)).

## Does the client stay on the proxy?

Configuring the proxy is half of it; the other half is that the client asks
nobody else. Some clients do, without saying so — and on a network that has no
other way out, such a client looks exactly like one that behaves. The lab
therefore records every name a client looks up, and fails a run when a client
asks for a host its script does not declare. That is how the first entry below
was found.

| Client | What it does | What to do |
|---|---|---|
| Composer | keeps asking packagist.org next to an added repository — also when `packagist` is redefined | switch `packagist.org` off ([Composer](clients/composer.md#configure)) |
| Composer, Yarn 1 | install from an existing lock file by fetching the URLs in it — GitHub, `registry.yarnpkg.com` | rewrite the lock file ([below](#moving-an-existing-project-onto-the-proxy)) |
| Docker Engine (mirror), containerd, Podman | fetch from the registry itself when the mirror refuses or fails | use an explicit reference, or deny the route ([Docker](clients/docker.md)) |
| Julia | clones a package's Git repository when the Pkg server does not serve it | deny the route to the forges ([Julia](clients/julia.md#good-to-know)) |
| go with `,direct` | fetches from the version-control host what the proxy answers `404` for | leave `,direct` off ([Go](clients/go.md#configure)) |
| Homebrew | reads the formula index from `formulae.brew.sh` when the proxy is unreachable or its certificate is not trusted | set the CA ([Homebrew](clients/homebrew.md)) |
| pip, uv, Poetry with a second index | take packages from that index too — pip the best version of either, uv from the first index that has the package | configure one index ([pip](clients/pip.md#good-to-know)) |
| Terraform, OpenTofu | clone a module's Git source with `git` | route Git through the proxy ([Terraform](clients/terraform.md#configure)) |
| Composer `--prefer-source`, cargo `git =` dependencies, Bazel `git_repository`, pip `git+https://` | clone from the forge | the same ([Git](clients/git.md)) |
| NuGet | asks the signing CAs' revocation servers (`crl3.digicert.com`, `ocsp.digicert.com`) while verifying package signatures | `NUGET_CERT_REVOCATION_MODE=offline`, or allow those hosts ([NuGet](clients/nuget.md#good-to-know)) |
| `hf` (Hugging Face CLI) | asks pypi.org whether a newer release of itself exists | `HF_HUB_DISABLE_UPDATE_CHECK=1` ([Hugging Face](clients/huggingface.md#good-to-know)) |
| Terraform | asks `checkpoint-api.hashicorp.com` for new versions of itself | `disable_checkpoint = true` ([Terraform](clients/terraform.md#good-to-know)) |
| dotnet | reports usage to `dc.services.visualstudio.com` | `DOTNET_CLI_TELEMETRY_OPTOUT=1` ([NuGet](clients/nuget.md#good-to-know)) |
| Homebrew | updates itself from `github.com` (and asks `api.github.com`) before an install | `HOMEBREW_NO_AUTO_UPDATE=1`, or route Git through the proxy ([Homebrew](clients/homebrew.md#good-to-know)) |
| Docker Engine | looks up `docker.io` in DNS on a mirrored pull | nothing — the image comes from the mirror |
| cabal | looks up `_mirrors.<proxy host>` in DNS | nothing — it stays on the proxy |

The rule that makes the rest moot: **clients that must go through the proxy
should have no other route.** A proxy is a control only where direct egress to
the registries is closed.

## Lock files

Some lock files record *where* a package came from. Those are tied to the
proxy's address: keep the address stable, and see
[below](#moving-an-existing-project-onto-the-proxy) for what each client does
with a lock file written before the proxy. The lab asserts each line of this
table.

| Records the proxy's address | Does not |
|---|---|
| `package-lock.json` (npm), `yarn.lock` (Yarn 1) | `yarn.lock` (Yarn 2+), `pnpm-lock.yaml` |
| `uv.lock`, `poetry.lock` | `pdm.lock` |
| `composer.lock` (dist URLs) | `Cargo.lock`, `go.sum` |
| `pubspec.lock` | `packages.lock.json` (NuGet) |
| `MODULE.bazel.lock` | `.terraform.lock.hcl` |
| `deno.lock` (npm packages only) | `mix.lock`, `Manifest.toml` (Julia) |
| `Gemfile.lock`, when the Gemfile's `source` is the proxy | `Gemfile.lock`, with a Bundler mirror |

Where a client offers both, prefer the setting that leaves project files
alone: a Bundler *mirror*, cargo *source replacement*, a Maven *mirror*, a
Terraform `host` block, Git `insteadOf`.

### Moving an existing project onto the proxy

A project that was locked against the public registry has those addresses in
its lock file. What the client does with them differs — and two clients go
around the proxy:

| Lock file | With the proxy configured | What to do |
|---|---|---|
| `package-lock.json` naming `registry.npmjs.org` | npm replaces the host itself and installs through the proxy | nothing ([npm](clients/npm.md#good-to-know)) |
| `yarn.lock` (Yarn 1) naming `registry.yarnpkg.com` | **fetched from that host** | rewrite the URLs in the lock file ([npm](clients/npm.md#good-to-know)) |
| `composer.lock` naming `api.github.com` | **fetched from that host** — the proxy is not asked | an update pinned to the locked versions ([Composer](clients/composer.md#good-to-know)) |
| `uv.lock` naming `pypi.org` | uv refuses (`--locked`) | `uv lock` ([pip](clients/pip.md#good-to-know)) |
| `pubspec.lock` naming `pub.dev` | pub refuses (`--enforce-lockfile`) | `dart pub get` ([Dart](clients/dart.md#good-to-know)) |
| `poetry.lock` without a source | installed from the proxy | nothing ([pip](clients/pip.md#good-to-know)) |

The lock files in the right-hand column of the first table need nothing: none
of them names the proxy. They record names, versions and hashes — or keep
naming the public registry (`Cargo.lock`, `.terraform.lock.hcl`, a
`Gemfile.lock` written with a mirror), which is the address the client's
redirection setting replaces.

## CI jobs and container images

Most clients can be configured through the environment alone, which suits a CI
job or a `Dockerfile`. These lines are from the lab's scripts:

<!-- verified: lab:npm-env lab:pip-netrc lab:refused-go lab:cpanm lab:deno lab:brew lab:dart lab:julia lab:huggingface lab:hex lab:uv -->

```sh
export NPM_CONFIG_REGISTRY=https://proxy.example.com/v1/npm/
export PIP_INDEX_URL=https://proxy.example.com/v1/pypi/simple/
export UV_DEFAULT_INDEX=https://proxy.example.com/v1/pypi/simple/
export GOPROXY=https://proxy.example.com/v1/goproxy
export PERL_CPANM_OPT="--mirror https://proxy.example.com/v1/cpan --mirror-only"
export JSR_URL=https://proxy.example.com/v1/jsr
export HOMEBREW_API_DOMAIN=https://proxy.example.com/v1/homebrew/api
export HOMEBREW_ARTIFACT_DOMAIN=https://proxy.example.com/v1/homebrew
export PUB_HOSTED_URL=https://proxy.example.com/v1/pub
export JULIA_PKG_SERVER=https://proxy.example.com/v1/julia
export HF_ENDPOINT=https://proxy.example.com/v1/huggingface
export HEX_MIRROR=https://proxy.example.com/v1/hex
```

cargo, Maven, Gradle, NuGet, Composer, Bundler, apt, dnf, conda, Nix, Git and
the container engines need a file or a command; their pages have it.

Keep tokens out of image layers: pass them as build secrets or at run time,
and prefer the forms that keep a token out of project files (`~/.npmrc`,
`~/.netrc`, an environment variable the tool reads).

## How this guide is verified

- **In CI, on every push** — the [ecosystem tests](ecosystem-tests.md): the
  real client of each of 30 ecosystems installs a package through the real
  proxy, re-installs it from the cache, and is refused a blocked one (Git, which
  has no package to refuse, is cloned). Their scripts are in the
  [reference](ecosystem-tests-reference.md).
- **In the client lab** — [client-lab.md](client-lab.md): the scripts in
  [`scripts/client-lab/clients`](../scripts/client-lab/clients), each run with
  the proxy behind a private CA and, where the client can, with a required
  token. Its last results, with the version of every client, are on that page.
- **By test** — every fenced block in this guide carries a marker that names
  the scripts it is in, and `go test ./internal/clientguide/` fails when a
  line of a block is not a whole line one of them executes, when the lines are
  in another order than the script's, when an upstream type has no page, when
  a page leaves the common structure or when a link does not resolve. The test
  cannot tell whether a block is complete: a block may show part of a file.
- **Not tested, and marked so**: Swift (no public registry implements its
  protocol); the proxy's SSH endpoint for Git; containerd's CRI plugin (the
  lab reads the same `hosts.toml` files through `ctr`); Podman, Buildah and
  CRI-O (skopeo stands in for the library they share); and the clients each
  page lists as not tested.
