# Client configuration

This guide shows how to point each supported package manager at the pull-through
proxy. Replace `https://proxy.example.com` with your deployment's public URL
(the value of `server.publicUrl` in the proxy config) and use the upstream
*name* you configured under `upstreams:` as the path segment after `/v1/`.

> **Two ways to consume the proxy.** This guide covers **explicit package
> sources** — reconfiguring each tool to use `https://proxy/v1/<name>/`. The
> proxy also supports a **TLS-interception** mode where clients keep talking to
> the real upstream hosts and only trust the proxy's CA + set their proxy env
> vars (no per-tool registry reconfiguration). See
> [intercept-mode.md](intercept-mode.md) for when to use each and how to set up
> interception.

Every backend is served under:

```
https://proxy.example.com/v1/<name>/...
```

where `<name>` is the key in the `upstreams` map (e.g. `npm`, `pypi`, `crates`,
`goproxy`, `nuget`). The proxy injects any upstream credentials it was
configured with; clients authenticate to the *proxy* (if you put the proxy
behind auth — see Task 10), never to the upstream.

> **Tip:** the [`ptctl`](client-cli.md) client CLI generates the snippets below
> for *your* proxy automatically (`ptctl config`), self-tests connectivity and
> auth against each backend (`ptctl selftest`), and shows an artifact's
> admission verdict and attestation (`ptctl inspect` / `ptctl attest`). The
> sections below remain the reference for configuring each tool by hand.

> **Why set `server.publicUrl`?** Several ecosystems return index documents that
> embed absolute artifact URLs (npm tarballs, PyPI files, cargo's download
> endpoint, NuGet's service index). The proxy rewrites those URLs so downloads
> also flow through the cache. The rewrite needs to know the proxy's externally
> reachable URL; set `server.publicUrl` so the links are absolute and correct
> behind load balancers.

---

## npm

`registry.npmjs.org` proxied under `/v1/npm`. Packuments are revalidated;
tarballs (`.../-/...tgz`) are cached immutably and their `dist.tarball` URLs are
rewritten through the proxy.

Project-local `.npmrc`:

```ini
registry=https://proxy.example.com/v1/npm/
```

Or per-scope:

```ini
@myscope:registry=https://proxy.example.com/v1/npm/
```

Or via CLI / environment:

```bash
npm config set registry https://proxy.example.com/v1/npm/
# or, one-off:
npm install --registry=https://proxy.example.com/v1/npm/
```

---

## pip (PyPI)

PyPI's Simple API proxied under `/v1/pypi`. The proxy serves the Simple index at
`/simple/` and rewrites distribution file links (which normally point at
`files.pythonhosted.org`) to a cached `/files/<scheme>/<host>/...` route. Only
artifact hosts on the allowlist (`settings.fileHosts`, default
`files.pythonhosted.org`) are fetched.

`pip.conf` (`~/.config/pip/pip.conf` on Linux, `~/.pip/pip.conf`, or
`%APPDATA%\pip\pip.ini` on Windows):

```ini
[global]
index-url = https://proxy.example.com/v1/pypi/simple/
```

Or per-invocation / environment:

```bash
pip install --index-url https://proxy.example.com/v1/pypi/simple/ requests
export PIP_INDEX_URL=https://proxy.example.com/v1/pypi/simple/
```

`uv`, `poetry`, and `pdm` accept the same index URL (e.g.
`uv pip install --index-url https://proxy.example.com/v1/pypi/simple/ ...`).

---

## cargo (crates.io)

The crates.io sparse index proxied under `/v1/crates`. The proxy serves
`config.json` (rewriting its `dl` field to a cached download endpoint), the
sparse index files, and `.crate` downloads.

`~/.cargo/config.toml`:

```toml
[registries.crates-io]
protocol = "sparse"

[source.crates-io]
replace-with = "proxy"

[source.proxy]
registry = "sparse+https://proxy.example.com/v1/crates/"
```

The trailing slash on the `sparse+...` URL is required. To use it for a single
build without editing the global config:

```bash
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
export CARGO_SOURCE_CRATES_IO_REPLACE_WITH=proxy
export CARGO_SOURCE_PROXY_REGISTRY="sparse+https://proxy.example.com/v1/crates/"
```

---

## Go modules (GOPROXY)

`proxy.golang.org` proxied under `/v1/goproxy`. The GOPROXY protocol is fully
path-relative, so no URL rewriting is needed.

```bash
go env -w GOPROXY=https://proxy.example.com/v1/goproxy
# Optionally fall back to direct VCS if the proxy lacks a module:
go env -w GOPROXY=https://proxy.example.com/v1/goproxy,direct
```

If your proxy serves only public modules you can also relax checksum-DB lookups
for private paths with `GONOSUMCHECK`/`GONOSUMDB`/`GOPRIVATE` as appropriate; the
public default keeps `sum.golang.org` verification intact.

---

## NuGet

`api.nuget.org` proxied under `/v1/nuget`. The v3 service index and registration
documents are rewritten so same-host resources (flat container, registration)
route through the proxy; `.nupkg` packages are cached immutably. Cross-host
services such as search are left pointing upstream.

`NuGet.config` (project- or user-level):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="proxy" value="https://proxy.example.com/v1/nuget/v3/index.json" />
  </packageSources>
</configuration>
```

Or via the CLI:

```bash
dotnet nuget add source https://proxy.example.com/v1/nuget/v3/index.json --name proxy
```

---

## Maven / Gradle (JVM)

A Maven upstream (`type: maven`, e.g. Maven Central's `maven2` root) is proxied
under `/v1/maven` using the standard GAV repository layout. Artifacts
(`.jar`/`.pom`/`.module`/`.war`) and their `.sha1`/`.sha256`/`.md5`/`.asc`
sidecars are cached immutably for release versions and resolved/timestamped
snapshots; `maven-metadata.xml` (release version lists and snapshot resolution)
is revalidated each request. Before an artifact is cached it is verified against
the strongest checksum sidecar the upstream publishes (SHA-256 ≫ SHA-1 ≫ MD5);
a mismatch is refused so a tampered mirror cannot poison the cache. The POM is
parsed to feed the artifact's `groupId:artifactId` coordinate, packaging, and
declared licenses into the admission gates.

**Maven** — in `~/.m2/settings.xml`, mirror all repositories through the proxy:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>proxy</id>
      <name>pull-through proxy</name>
      <url>https://proxy.example.com/v1/maven</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

**Gradle** — in `build.gradle[.kts]` (or an init script), declare it as the only
repository:

```kotlin
repositories {
    maven { url = uri("https://proxy.example.com/v1/maven") }
}
```

For an authenticated private repository, set `credentials` on the upstream in the
proxy config; the proxy injects them on the outbound fetch so clients need no
upstream credentials of their own.

---

## RubyGems (Ruby)

A RubyGems upstream (`type: rubygems`, e.g. `https://rubygems.org`) is proxied
under `/v1/rubygems`. The backend serves the modern **compact index** Bundler
uses — `/versions`, `/names`, and per-gem `/info/<gem>` — plus `.gem` fetches
(`/gems/<name>-<version>.gem`), the legacy Marshal gemspecs
(`/quick/Marshal.4.8/...`), the Marshal spec indexes (`/specs.4.8.gz` and
friends), and the dependency API (`/api/v1/dependencies`). Index documents are
mutable and revalidated each request; `.gem` files and per-version gemspecs are
cached immutably. Before a `.gem` is cached it is verified against the **SHA-256
checksum the gem's `/info/<gem>` document declares** for that version (including
platform-specific gems such as `nokogiri-1.13.0-x86_64-linux.gem`); a mismatch is
refused so a tampered mirror cannot poison the cache. The gem name feeds the
admission gates (vulnerability scanning maps it to the OSV `RubyGems` ecosystem).

**Bundler** — point a project (or the global config) at the proxy:

```bash
bundle config mirror.https://rubygems.org https://proxy.example.com/v1/rubygems
```

or set the source in the `Gemfile`:

```ruby
source "https://proxy.example.com/v1/rubygems"
```

---

## Composer / Packagist (PHP)

A Composer upstream (`type: composer`, e.g. `https://repo.packagist.org`) is
proxied under `/v1/packagist`. The backend serves the repository root
(`packages.json`), the Composer **v2 metadata layout**
(`/p2/<vendor>/<package>.json`, including the `~dev` variant and the legacy
`/p/...` provider documents), and **dist archive downloads** under
`/dist/<vendor>/<package>/<reference>.<ext>`. Metadata documents are mutable and
revalidated; dist archives are cached immutably. The v2 metadata's "minified"
delta encoding is expanded so the proxy can recover each version's dist
coordinates. A dist request is resolved by reading the package's v2 metadata,
fetching the upstream download URL it advertises, and verifying the streamed
archive against the **SHA-1 `dist.shasum`** the metadata declares; a mismatch is
refused. The `vendor/package` coordinate and declared licenses feed the admission
gates (vulnerability scanning maps it to the OSV `Packagist` ecosystem).

**Composer** — add the proxy as a repository in `composer.json`:

```json
{
  "repositories": [
    { "type": "composer", "url": "https://proxy.example.com/v1/packagist" }
  ]
}
```

To route *all* Packagist traffic through the proxy, also disable the default
Packagist repository (`"packagist.org": false`) in the same `repositories` block.

---

## Helm charts

Helm has two transports, and the proxy covers both with a single `type: helm`
backend selected by the optional `settings.oci` flag.

### Classic chart repositories (`helm repo add`)

A classic Helm upstream (`type: helm`, e.g. `https://charts.bitnami.com/bitnami`)
is proxied under `/v1/<name>`. The backend serves the repository **index.yaml**
live (it is mutable), and on a chart `.tgz` cache miss it fetches and parses
index.yaml to recover the **SHA-256 `digest`** the repository published for that
chart, verifying the streamed archive against it before the bytes are cached or
served; a mismatch is refused. Chart **provenance** sidecars
(`<name>-<version>.tgz.prov`) are served and cached, and the chart `name` +
`version` coordinate feeds the admission gates (vulnerability scanning of the
images a chart references, signature verification, risk scoring, policy).

```bash
helm repo add bitnami https://proxy.example.com/v1/bitnami
helm repo update
helm pull bitnami/nginx --version 15.0.0   # .tgz fetched + SHA-256-verified by the proxy
helm install web bitnami/nginx
```

### OCI-registry-hosted charts (`helm pull oci://`)

Set `settings.oci: "true"` to serve charts pushed to an OCI registry. The backend
reuses the Docker Registry v2 plumbing (token handshake, digest-addressed caching,
content-digest verification):

```yaml
upstreams:
  helm-oci:
    type: helm
    url: https://registry-1.docker.io
    settings:
      oci: "true"
```

The registry is mounted under `/v1/helm-oci/`, serving the v2 API
(`/v2/<chart>/manifests/<ref>`, `/v2/<chart>/blobs/<digest>`). As with the Docker
backend, the Helm CLI inserts `/v2/` after the host, so front the upstream at a
host root via an ingress `/v2/` rewrite (see the Docker section's Option B), then:

```bash
helm pull oci://charts.proxy.example.com/library/nginx --version 15.0.0
```

---

## Debian / Ubuntu (APT)

An APT upstream (`type: apt`, e.g. `https://deb.debian.org/debian` or
`http://archive.ubuntu.com/ubuntu`) is proxied under `/v1/<name>`. The backend
serves the `dists/<suite>/{InRelease,Release}` trust anchor and the
`Packages[.gz]` indices live (they are mutable), and on a pool `.deb` cache miss
it verifies the package against the **SHA-256** the chain of
`Release → Packages` declares before the bytes are cached or served; a mismatch
is refused. The package `name` + `version` coordinate feeds the admission gates
(vulnerability scanning maps it to the OSV `Debian`/`Ubuntu` ecosystems).

```yaml
upstreams:
  debian:
    type: apt
    url: https://deb.debian.org/debian
    # Optional: validate the Release (InRelease / Release.gpg) signature against a
    # pinned key. With no key, integrity rests on the SHA-256 content chain.
    settings:
      gpgKeyFile: /etc/pullthrough/keys/debian-archive.asc
```

Point a client's sources.list at the proxy (the `dists`/`pool` layout is
preserved verbatim):

```
# /etc/apt/sources.list.d/proxy.list
deb https://proxy.example.com/v1/debian bookworm main
```

```bash
apt-get update          # Release + Packages fetched through the proxy
apt-get install hello   # pool/.../hello_*.deb fetched + SHA-256-verified
```

When a trusted keyring is configured (`settings.gpgKey` inline, or
`settings.gpgKeyFile` by path), a served `InRelease`/`Release` whose signature
fails to validate against that key is refused, anchoring the whole digest chain.

---

## RHEL / Fedora / openSUSE (YUM / DNF, RPM)

A YUM upstream (`type: yum`, e.g. a Fedora/EPEL/CentOS-Stream repository base —
the directory that contains `repodata/`) is proxied under `/v1/<name>`. The
backend serves `repodata/repomd.xml` and the `primary.xml.gz` package list live
(they are mutable), and on an `.rpm` cache miss it verifies the package against
the checksum the chain of `repomd.xml → primary.xml` declares before the bytes
are cached or served; a mismatch is refused. The package `name` + `version`
coordinate feeds the admission gates.

```yaml
upstreams:
  fedora:
    type: yum
    url: https://dl.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os
    # Optional: validate the repomd.xml (repomd.xml.asc) signature against a key.
    settings:
      gpgKeyFile: /etc/pullthrough/keys/fedora.asc
```

Point a `.repo` file's `baseurl` at the proxy:

```ini
# /etc/yum.repos.d/proxy.repo
[fedora-proxy]
name=Fedora via pull-through proxy
baseurl=https://proxy.example.com/v1/fedora
enabled=1
gpgcheck=1
```

```bash
dnf makecache              # repomd.xml + primary.xml fetched through the proxy
dnf install hello          # Packages/hello-*.rpm fetched + checksum-verified
```

As with APT, a configured keyring turns a bad `repomd.xml` signature into a hard
failure at the proxy boundary; otherwise integrity rests on the checksum chain.

---

## Docker / OCI images

A Docker upstream (`type: docker`) proxies a Registry v2 / OCI distribution
endpoint. With

```yaml
upstreams:
  dockerhub:
    type: docker
    url: https://registry-1.docker.io
```

the backend is mounted under `/v1/dockerhub/`, where it serves the v2 API
(`/v2/`, `/v2/<name>/manifests/<ref>`, `/v2/<name>/blobs/<digest>`,
`/v2/<name>/tags/list`). Blobs and manifests requested by digest are cached
immutably and digest-verified; manifests by tag are revalidated live.

The Docker CLI always inserts `/v2/` immediately after the registry host, so it
cannot reach a path-prefixed backend directly (`docker pull host/v1/dockerhub/...`
does **not** work). Use one of the two supported integrations instead.

### Option A — Docker Hub via a registry mirror (daemon-wide)

The daemon's `registry-mirrors` setting only affects pulls of Docker Hub
(`docker.io`) images, and Docker appends `/v2/...` to the mirror base. Point it
at the `dockerhub` upstream's prefix:

`/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["https://proxy.example.com/v1/dockerhub"]
}
```

```bash
sudo systemctl restart docker
docker pull nginx:latest        # transparently fetched through the proxy
```

Verify the pull went through the proxy with `docker system info | grep -A2 Mirrors`.

### Option B — Any registry via an ingress `/v2/` rewrite (per host)

To pull by explicit reference (`docker pull proxy.example.com/library/nginx`) or
to mirror a non–Docker-Hub registry (GHCR, etc.), expose a hostname whose `/v2/`
root maps to a single Docker upstream. Rewrite `/v2/` to `/v1/<name>/v2/` at your
ingress/reverse proxy. With nginx:

```nginx
# docker.example.com → the "dockerhub" upstream
location /v2/ {
    proxy_pass https://proxy-backend/v1/dockerhub/v2/;
}
```

Then:

```bash
docker pull docker.example.com/library/nginx:latest
docker pull docker.example.com/myorg/myimage:1.2.3
```

Give each Docker upstream its own hostname (e.g. `ghcr.example.com` →
`/v1/ghcr/v2/`). Private upstreams authenticate with credentials configured on
the upstream; clients never send registry credentials to the proxy for the pull
itself (proxy access control, if enabled, is separate — see
[access-control-and-audit.md](access-control-and-audit.md)).

---

## Terraform / OpenTofu (providers & modules)

A Terraform/OpenTofu upstream (`type: terraform`, e.g.
`https://registry.terraform.io` or `https://registry.opentofu.org`) is proxied
under `/v1/<name>`. The backend serves a synthesized service-discovery document
and covers both registry protocols:

- **Provider registry** — version lists and the per-os/arch package descriptor
  are served live; the descriptor's artifact URLs (the release ZIP, the
  `SHA256SUMS` manifest, and its `SHA256SUMS.sig` signature) are rewritten so they
  flow through (and are cached by) the proxy. On a ZIP cache miss the proxy
  **independently verifies** that the ZIP's SHA-256 matches the signed SHASUMS
  manifest **and** that the manifest carries a valid GPG signature from a
  registry-asserted key. A digest mismatch or a forged signature is refused
  before any bytes are cached or served, and the signature status is surfaced to
  the admission pipeline (policy + risk gates) and as `X-Terraform-Signature` /
  `X-Checksum-Verified` response headers.
- **Module registry** — version lists and the download endpoint are served live;
  the download endpoint's `X-Terraform-Get` go-getter URL is rewritten so the
  module source archive is fetched and cached through the proxy (for plain
  HTTP(S) sources; `git::`/`s3::`/… getters are passed through unchanged).

```yaml
server:
  # Recommended: set publicUrl so rewritten provider/module artifact URLs are
  # absolute. Without it the proxy passes upstream artifact URLs through
  # unmodified (no caching/verification of those artifacts).
  publicUrl: https://proxy.example.com
upstreams:
  terraform:
    type: terraform
    url: https://registry.terraform.io
```

Point Terraform/OpenTofu at the proxy host with the backend's mount as the
registry hostname prefix; the discovery document advertises the module/provider
endpoints under `/v1/<name>/`. Because the proxy verifies the SHASUMS signature
itself and re-serves the manifest and `.sig`, the client's own verification
continues to work end-to-end through the proxy.

---

## Conan (C/C++)

A Conan upstream (`type: conan`, e.g. `https://center2.conan.io`) is proxied
under `/v1/<name>`. The backend speaks the **Conan 2.x revisions REST API** (the
`/v2/...` endpoints that JFrog Artifactory, ConanCenter, and the reference
`conan_server` expose). Conan 1.x is not supported.

Recipe and package files are addressed beneath an immutable recipe revision
(`rrev`) and package revision (`prev`), each of which is a content hash of the
files it pins, so those files are cached **content-addressably** and served
indefinitely. The mutable discovery endpoints (`/latest`, `/revisions`, search,
`/ping`) are revalidated rather than cached.

On a cache miss the proxy fetches the revision's `conanmanifest.txt` and
**verifies** each fetched file against its declared MD5 before the bytes are
cached or served — streaming for large archives (`conan_package.tgz`,
`conan_sources.tgz`), in memory for the small `conaninfo.txt`. A mismatch is
refused (recorded as `X-Checksum-Verified: md5` on success). The stronger
per-file digests the upstream advertises via `X-Checksum-Sha256` are passed
through unchanged so the client's own checks keep working.

```yaml
upstreams:
  conancenter:
    type: conan
    url: https://center2.conan.io
```

Register the proxy as a Conan remote:

```bash
conan remote add proxy https://proxy.example.com/v1/conancenter
conan remote login proxy pullthrough -p <your-proxy-token>   # if the proxy requires auth
```

---

## Conda (scientific Python / data engineering)

A Conda channel upstream (`type: conda`, e.g.
`https://conda.anaconda.org/conda-forge`) is proxied under `/v1/<name>`, which
the client treats as the **channel root**. The backend honors the channel's
per-subdir layout: each platform selector (`noarch`, `linux-64`, `osx-arm64`,
`win-64`, …) has its own `repodata.json` index and the `.conda` / `.tar.bz2`
package archives it describes.

A package filename pins its `name-version-build` coordinate, so package archives
are cached **content-addressably** and served indefinitely; the mutable
`repodata.json` / `channeldata.json` indices are revalidated rather than cached.

On a cache miss for a package the proxy fetches the subdir's `repodata.json`,
reads the **SHA-256** it records for the archive (falling back to MD5 only for
older indices), and **verifies** the fetched bytes against it — streaming, so a
mismatch aborts the cache write and the client stream (recorded as
`X-Checksum-Verified: sha256` on success). The package coordinate is associated
for nameguard, vulnscan, provenance, policy, and license enforcement.

```yaml
upstreams:
  conda-forge:
    type: conda
    url: https://conda.anaconda.org/conda-forge
```

Point Conda at the proxied channel (in `~/.condarc` or on the command line):

```bash
conda config --add channels https://proxy.example.com/v1/conda-forge
conda install -c https://proxy.example.com/v1/conda-forge numpy
```

---

## CRAN (R)

A CRAN upstream (`type: cran`, e.g. `https://cloud.r-project.org`) is proxied
under `/v1/<name>`, which the client treats as the **repository root**. The
backend serves the standard CRAN tree: the per-area `PACKAGES` indices and the
source (`src/contrib/`) and binary (`bin/windows/`, `bin/macosx/`) package
tarballs they describe. CRAN-compatible repositories (Posit Package Manager,
Bioconductor, a local miniCRAN) use the same layout.

A package filename pins its `name_version` coordinate, so tarballs are cached
**content-addressably** and served indefinitely; the mutable `PACKAGES` indices
are revalidated rather than cached.

On a cache miss for a tarball the proxy fetches the sibling `PACKAGES` index,
reads the **MD5sum** it records for the package, and **verifies** the fetched
tarball against it before the bytes are cached or served — streaming, so a
mismatch is refused (recorded as `X-Checksum-Verified: md5` on success). The
package coordinate is associated for nameguard, vulnscan, provenance, policy, and
license enforcement; CRAN coordinates are additionally OSV-scanned (OSV's `CRAN`
ecosystem).

```yaml
upstreams:
  cran:
    type: cran
    url: https://cloud.r-project.org
```

Point R's package repository at the proxy (interactively or in `~/.Rprofile`):

```r
options(repos = c(PROXY = "https://proxy.example.com/v1/cran"))
install.packages("jsonlite")
```

---

## Hex (Elixir / Erlang)

A Hex upstream (`type: hex`, e.g. `https://repo.hex.pm`) is proxied under
`/v1/<name>`, which mix/hex treats as the **repository root**. The backend serves
the Hex registry-v2 tree: the signed, gzip-compressed protobuf resources
`/names`, `/versions`, and `/packages/<name>`, plus the release tarballs under
`/tarballs/<name>-<version>.tar`.

A tarball filename pins its `name-version` coordinate, so tarballs are cached
**content-addressably** and served indefinitely; the mutable registry resources
are revalidated rather than cached and are passed through **byte-exact**, so a
client that pins the repository public key still performs its own end-to-end
signature verification.

On a cache miss for a tarball the proxy fetches the sibling `/packages/<name>`
resource, decodes the signed protobuf, reads the release's **outer_checksum** (a
SHA-256 over the whole tarball), and **verifies** the fetched bytes against it
before they are cached or served — streaming, so a mismatch is refused (recorded
as `X-Checksum-Verified: sha256` on success). The package coordinate is
associated for nameguard, vulnscan, provenance, policy, and license enforcement;
Hex coordinates are additionally OSV-scanned (OSV's `Hex` ecosystem).

```yaml
upstreams:
  hex:
    type: hex
    url: https://repo.hex.pm
```

Point mix/hex at the proxied repository. For the default public repo, set the
mirror; for an arbitrary repo, register it by name:

```bash
# Default public repo via the proxy mirror:
export HEX_MIRROR=https://proxy.example.com/v1/hex
mix deps.get

# Or register the proxied repository under a name:
mix hex.repo add proxy https://proxy.example.com/v1/hex
```

> The proxy serves the repository tree only (registry resources + tarballs); it
> does not front the hex.pm JSON API (`api.hex.pm`), which `mix hex.publish`,
> `mix hex.search`, and auth flows use directly.

---

## Bazel Central Registry (Bzlmod)

A Bazel registry upstream (`type: bazel`, e.g. `https://bcr.bazel.build`) is
proxied under `/v1/<name>`, which Bazel treats as a **module registry**
(`--registry=<url>`). The backend serves the Bzlmod tree: the registry-root
`bazel_registry.json`, each module's `modules/<name>/metadata.json`, and the
per-version `modules/<name>/<version>/MODULE.bazel`, `source.json`, and
`patches/` files.

A module version's **source archive** lives at an arbitrary external URL
(commonly a GitHub release), not under the registry. `source.json` records that
archive's URL and its **Subresource-Integrity** (`integrity`, e.g.
`sha256-<base64>`) digest. So the proxy can cache and verify the archive, it
**rewrites** each `source.json` so its `url` points at a proxy-synthetic
`modules/<name>/<version>/archive` endpoint, leaving the `integrity` untouched
(Bazel still verifies end-to-end). A request to that endpoint re-reads
`source.json`, fetches the external archive, and **verifies** the fetched bytes
against the SRI digest before they are cached or served — streaming, so a
mismatch aborts the cache write and the client stream (recorded as
`X-Checksum-Verified: <algo>` on success). The module coordinate is associated
for nameguard, provenance, policy, and license enforcement.

> URL rewriting requires the proxy's public URL. Set `server.publicURL` so the
> rewritten `source.json` carries an absolute archive endpoint; without it the
> descriptor is passed through unchanged and archive fetches are not proxied.

> Bazel modules are **not** OSV-scanned by coordinate (OSV defines no
> Bazel-module ecosystem). A module's security posture is carried by its
> underlying source repository, which the provenance/commit-scanning paths cover.

```yaml
server:
  publicURL: https://proxy.example.com
upstreams:
  bazel:
    type: bazel
    url: https://bcr.bazel.build
```

Point Bazel at the proxied registry (in `.bazelrc` or on the command line):

```ini
# .bazelrc
common --registry=https://proxy.example.com/v1/bazel
```

```bash
bazel mod deps --registry=https://proxy.example.com/v1/bazel
```

---

## Julia (Pkg / General registry)

A Julia upstream (`type: julia`, e.g. `https://pkg.julialang.org`) is proxied
under `/v1/<name>`, which the Julia client treats as a **Pkg Server**
(`JULIA_PKG_SERVER`). The backend serves the
[Pkg Server Protocol](https://pkgdocs.julialang.org/dev/protocol/): the mutable
`/registries` listing, each registry's tarball at `/registry/<uuid>/<hash>`,
package source tarballs at `/package/<uuid>/<hash>`, and artifact tarballs at
`/artifact/<hash>`.

Every resource except `/registries` is addressed by its **git-tree-sha1** — the
SHA-1 Git tree object hash of the decompressed tarball's contents — so the URL
is itself the integrity record. On a cache miss the proxy **recomputes** that
tree hash over the fetched gzip-compressed tarball (independently of git, exactly
as the Pkg client does) and **verifies** the bytes against the hash in the URL
before they are cached or served — streaming, so a mismatch aborts the cache
write and the client stream (recorded as `X-Tree-Hash-Verified: git-sha1` on
success). The mutable `/registries` listing is revalidated rather than cached and
passed through byte-exact.

> Julia packages are **not** OSV-scanned by coordinate. OSV defines a `Julia`
> ecosystem, but it is keyed by package name and version, whereas the Pkg Server
> Protocol addresses packages only by UUID and git-tree-sha1 — never a
> name/semver — so no coordinate OSV lookup is possible at the pull layer. A
> package's security posture is carried by its underlying source repository,
> which the provenance/commit-scanning paths cover.

```yaml
upstreams:
  julia:
    type: julia
    url: https://pkg.julialang.org
```

Point the Julia client at the proxied server:

```bash
export JULIA_PKG_SERVER=https://proxy.example.com/v1/julia
julia --project -e 'using Pkg; Pkg.instantiate()'
```

> The proxy fronts the Pkg Server Protocol (registry/package/artifact tarballs),
> which is how Pkg installs registered packages; it does not front unregistered
> `]add <git-url>` dependencies, which Pkg clones directly from their source
> repository (use the `git` backend for those).

---

## CPAN (Perl)

A CPAN upstream (`type: cpan`, e.g. `https://www.cpan.org` or
`https://cpan.metacpan.org`) is proxied under `/v1/<name>`, which the client
treats as the **mirror root**. The backend serves the standard CPAN tree: the
`modules/` master indices (notably `modules/02packages.details.txt.gz`, which
maps a module to its distribution) and the distribution tarballs under the
author tree `authors/id/<A>/<AB>/<AUTHOR>/<Dist>-<Version>.tar.gz`. Every author
directory also publishes a `CHECKSUMS` file — a PGP-clearsigned Perl data
structure recording each file's SHA-256. CPAN-compatible mirrors (a local
minicpan, an Artifactory CPAN repository) use the same layout.

A distribution filename pins its `Dist-Version` coordinate, so tarballs are
cached **content-addressably** and served indefinitely; the mutable module
indices, the `CHECKSUMS` file, and the sidecar `.meta`/`.readme` documents are
revalidated rather than cached.

On a cache miss for a distribution the proxy fetches the sibling `CHECKSUMS`
file, reads the **SHA-256** it records for the tarball, and **verifies** the
fetched bytes against it before they are cached or served — streaming, so a
mismatch is refused (recorded as `X-Checksum-Verified: sha256` on success). The
distribution coordinate is associated for nameguard, vulnscan, provenance,
policy, and license enforcement; CPAN coordinates are additionally OSV-scanned
(OSV's `CPAN` ecosystem, keyed by distribution name and version).

```yaml
upstreams:
  cpan:
    type: cpan
    url: https://cpan.metacpan.org
```

Point `cpanm` (App::cpanminus) at the proxied mirror:

```bash
# Install using only the proxied mirror (no direct upstream fetches):
cpanm --mirror https://proxy.example.com/v1/cpan --mirror-only Try::Tiny

# Or persist it in ~/.cpanm/config / the CPANM_OPT environment:
export PERL_CPANM_OPT="--mirror https://proxy.example.com/v1/cpan --mirror-only"
cpanm --installdeps .
```

The legacy `CPAN.pm` client can target the same mirror by setting its `urllist`
to `https://proxy.example.com/v1/cpan/`.

---

## Swift Package Manager

A Swift registry upstream (`type: swift`) is proxied under `/v1/<name>`. The
backend speaks the **Swift Package Registry API** (SE-0292 — the `/{scope}/{name}`,
`/{scope}/{name}/{version}`, `Package.swift`, and `/{scope}/{name}/{version}.zip`
endpoints the swiftlang reference server and the Swift Package Index implement).

A published release is immutable, so its metadata, manifest, and source archive
are cached **content-addressably** beneath their `{scope}/{name}/{version}`
coordinate and served indefinitely. The mutable discovery endpoints (the
release list and the `/identifiers` SCM-URL lookup) are revalidated rather than
cached.

On a cache miss for a source archive the proxy fetches the release metadata,
reads the SHA-256 `checksum` it records for the `source-archive` resource, and
**verifies** the fetched `.zip` against it before the bytes are cached or served
(recorded as `X-Checksum-Verified: sha256` on success); a mismatch is refused.
The registry's `Content-Version` and `Digest: sha-256=...` headers are passed
through unchanged. The package's source-repository URL (from the release
metadata) is associated for provenance.

```yaml
upstreams:
  swiftpm:
    type: swift
    url: https://swiftpackageregistry.example.com
```

Point the Swift toolchain at the proxy:

```bash
swift package-registry set https://proxy.example.com/v1/swiftpm
swift package-registry login https://proxy.example.com/v1/swiftpm --token <your-proxy-token>   # if the proxy requires auth
swift package-registry resolve
```

---

## Dart / Flutter (pub)

A pub upstream (`type: dart`, or the alias `pub`; e.g. `https://pub.dev`) is
proxied under `/v1/<name>`. The backend speaks the **Hosted Pub Repository API**
(repository-spec v2): the list-versions document (`/api/packages/<package>`) and
package archives.

The list-versions document is served with every `archive_url` **rewritten**
through the proxy, so a client's archive download flows back through the proxy
(where it is cached, verified, and gated) rather than directly to the upstream or
its blob storage. Set `server.publicUrl` so those rewritten URLs are absolute. A
concrete version's `.tar.gz` archive is immutable and cached
**content-addressably**; the list-versions and advisories documents are mutable
and revalidated.

On a cache miss for an archive the proxy re-reads the list-versions document to
recover the real upstream archive URL and the release's `archive_sha256`, fetches
the archive (following any redirect to blob storage), and **verifies** it against
that SHA-256 before the bytes are cached or served (recorded as
`X-Checksum-Verified: sha256`); a mismatch is refused. The package's pubspec
`repository`/`homepage` URL is associated for provenance.

```yaml
upstreams:
  pub:
    type: dart
    url: https://pub.dev
```

Point `dart pub` / `flutter pub` at the proxy:

```bash
export PUB_HOSTED_URL=https://proxy.example.com/v1/pub
dart pub get        # or: flutter pub get
dart pub token add https://proxy.example.com/v1/pub   # if the proxy requires auth
```

---

## Hugging Face (ML models & datasets)

A Hugging Face Hub upstream (`type: huggingface`, e.g. `https://huggingface.co`)
is proxied under `/v1/<name>`. The backend speaks the Hub **resolve protocol**
(`GET /{repo}/resolve/{revision}/{path}` for models, and the `datasets/` and
`spaces/` variants) and the **repository metadata API** (`/api/models/{repo}`,
`/api/datasets/{repo}`).

A resolve pinned to a 40-hex **commit SHA** is immutable, so its blob is cached
**content-addressably** and served indefinitely; a resolve against a branch or
tag (`main`) is mutable and revalidated. Large weight files are stored in Git LFS
and served from a CDN via a redirect the proxy follows transparently; the resolve
response advertises the object's SHA-256 out-of-band (`X-Linked-Etag`), which the
proxy **verifies** the delivered bytes against — streaming, so multi-GB weights
are never buffered — recording `X-Checksum-Verified: sha256` on success and
refusing a mismatch. A git-lfs pointer body returned in place of content is
recognized so the tiny text blob is never mistaken for a real weight.

Because malicious pickles are the dominant ML supply-chain attack, pickle-based
weight files (`.bin`/`.pkl`/`.pt`/`.pth`/`.ckpt`, including the PyTorch ZIP
container) pass through the **ML weight-scanning gate** (`mlGuard`): the proxy
statically disassembles the pickle opcode stream and refuses (and quarantines) a
file that imports a code-execution / network / filesystem primitive
(`os.system`, `subprocess.Popen`, `builtins.eval`, a socket, …) invoked via
`__reduce__` — never unpickling anything. The safe, tensor-only **safetensors**
format is recognized and preferred; a served pickle carries an advisory
`X-MLGuard-Prefer-Safetensors` header. A refusal is an actionable `403` naming
the unsafe imports and the offending opcode stream.

```yaml
upstreams:
  huggingface:
    type: huggingface
    url: https://huggingface.co
    credentials:
      token: <hf-access-token>   # only for gated/private repos
```

Point the Hugging Face client/library at the proxy via `HF_ENDPOINT`:

```bash
export HF_ENDPOINT=https://proxy.example.com/v1/huggingface
huggingface-cli download bigscience/bloom config.json
# transformers / huggingface_hub honor HF_ENDPOINT too:
python -c "from huggingface_hub import hf_hub_download; hf_hub_download('gpt2','model.safetensors')"
```

---

## OpenVSX (VS Code / VSCodium extensions)

An OpenVSX upstream (`type: openvsx`, e.g. `https://open-vsx.org`) is proxied
under `/v1/<name>`. The backend speaks the Eclipse Open VSX **REST API**: the
extension query/metadata documents (`/api/-/query`, `/api/{namespace}`,
`/api/{namespace}/{extension}[/{version}]`) and the `.vsix` archive downloads
(`/api/{ns}/{ext}/…/file/{file}.vsix`). A compatible VS Code **gallery** tree
(`/vscode/…`) is proxied too.

The metadata/query documents are mutable and served live; the proxy **rewrites**
the absolute upstream URLs they embed (`files.download`, `files.sha256`, gallery
asset URLs, …) to its own public base, so an editor's extension download routes
back **through the proxy** (and its content gate) rather than directly to the
registry or its CDN. External links in the metadata (an extension's source
repository, homepage) are left untouched.

A `.vsix` path pins its `{namespace}.{extension}@{version}` coordinate, so the
archive is immutable and cached **content-addressably**. On a cache miss the
proxy fetches the sibling `.sha256` sidecar the registry publishes and
**verifies** the delivered bytes against it — streaming, so a mismatch aborts the
cache write and client stream — recording `X-Checksum-Verified: sha256` on
success and refusing a mismatch.

Because a `.vsix` is a zip whose `extension/package.json` carries the
install/activation manifest, each archive passes through the **install-script /
lifecycle-hook content gate** (`installHooks`): the proxy statically extracts the
manifest's npm-style lifecycle scripts (`vscode:prepublish`, `postinstall`, …),
its `activationEvents`, and its declared `contributes` points, and scores them
against the deterministic high-risk pattern set — never executing anything. A
wildcard `activationEvent: *` (the extension activates on every editor startup) is
flagged, and a malicious install script is refused with an actionable `403`.

> VS Code / OpenVSX extensions are **not** OSV-scanned by coordinate: OSV defines
> no ecosystem keyed by the `{namespace}.{extension}` identifier. The supply-chain
> defense for extensions is the install/activation content gate above plus the
> name / provenance / policy gates.

```yaml
upstreams:
  openvsx:
    type: openvsx
    url: https://open-vsx.org
    credentials:
      token: <open-vsx-token>   # only for a private deployment
```

Point an editor's gallery service at the proxy (VS Code / VSCodium `product.json`
`extensionsGallery.serviceUrl`/`itemUrl`), or use the `ovsx` CLI's registry URL:

```bash
# ovsx CLI (download a .vsix through the proxy, verified end-to-end):
ovsx get dracula-theme.theme-dracula --registryUrl https://proxy.example.com/v1/openvsx

# or configure VSCodium's product.json extensionsGallery.serviceUrl:
#   "serviceUrl": "https://proxy.example.com/v1/openvsx/vscode/gallery"
```

> The POST-based VS Code gallery `extensionquery` is not proxied — the
> pull-through core serves idempotent `GET`/`HEAD` only — so clients use the
> OpenVSX REST API (`GET /api/…`), which this backend fully fronts.

---

## Nix / Flakes (binary cache)

A Nix binary cache (`type: nix`, e.g. `https://cache.nixos.org`, or any HTTP
cache produced by `nix copy --to`) is proxied under `/v1/<name>`. The backend
speaks the binary-cache protocol: the cache descriptor (`/nix-cache-info`), the
per-store-path signed metadata (`/<storehash>.narinfo`), and the
content-addressed NAR archives (`/nar/<filehash>.nar[.xz|.zst|…]`).

Two independent integrity controls are enforced on the pull path:

- **narinfo signatures.** Each narinfo carries one or more `Sig:` ed25519
  signatures over a canonical fingerprint of the store path, `NarHash`,
  `NarSize` and references. The proxy **verifies** this against the
  `trustedPublicKeys` you configure (each in Nix's `name:base64` form) before
  serving the narinfo; with keys configured, an unsigned or untrusted narinfo is
  refused. This is the trust anchor for the store path — it authenticates the
  `NarHash` the Nix client itself re-checks after decompressing the NAR.
- **NAR content address.** A NAR's file name is its own SHA-256
  (`/nar/<filehash>.nar.…`). On a cache miss the proxy recomputes that SHA-256 as
  the (still-compressed) file streams through and refuses to cache or serve bytes
  that do not match the hash in the URL — streaming, so a mismatch aborts the
  cache write and the client stream. It records `X-Content-Hash-Verified: sha256`
  on success.

The narinfo `URL:` field is **rewritten** to the proxy's own `/nar/…` endpoint so
a client's NAR download routes back **through the proxy** (and its content gate).
The signature covers neither the `URL` nor the `FileHash`, so this rewrite never
invalidates it.

> Nix store paths are **not** OSV-scanned by coordinate: a binary cache addresses
> content by an opaque store hash and the NAR's SHA-256, never by a name/version.
> The defense is the signature + content-address verification above plus the
> name / provenance / policy gates; a derivation's underlying source is covered by
> the provenance / commit-scanning paths.

```yaml
upstreams:
  nix:
    type: nix
    url: https://cache.nixos.org
    settings:
      # nix.conf trusted-public-keys form; space-, comma- or newline-separated.
      trustedPublicKeys: "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
```

Point Nix at the proxied cache with a `substituters` entry and the cache's public
key as a `trusted-public-keys` entry:

```bash
nix build .#hello \
  --substituters https://proxy.example.com/v1/nix \
  --trusted-public-keys "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" \
  --option require-sigs true

# or persistently, in nix.conf:
#   substituters = https://proxy.example.com/v1/nix
#   trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
```

---

## Homebrew (macOS / Linux)

Homebrew (`type: homebrew`, `https://formulae.brew.sh`) is proxied under
`/v1/<name>`. It spans two upstreams, both fronted by this backend:

- **Formula metadata**, from the `formulae.brew.sh` JSON API: the full index
  (`/api/formula.json`) and the per-formula documents
  (`/api/formula/<name>.json`). These enumerate each formula's *bottle* — a
  precompiled binary tarball — with its download URL and SHA-256. They are
  mutable and revalidated live.
- **Bottle tarballs**, which Homebrew now distributes as OCI blobs in GitHub
  Packages (`ghcr.io`). A bottle's download URL is a content-addressed OCI blob
  reference (`https://ghcr.io/v2/<repo>/blobs/sha256:<digest>`), fetched via the
  standard Docker Registry v2 bearer-token handshake (anonymous for the public
  `homebrew/core` tap).

On the pull path:

- **Bottle-URL rewriting.** Every bottle download URL in a served formula
  document is **rewritten** to the proxy's own
  `/bottle/<name>/<version>/v2/…/blobs/sha256:<digest>` endpoint (under the
  configured public URL), so a client's bottle download routes back **through
  the proxy** (and its content gates) rather than directly to ghcr. Only bottle
  URLs on the configured bottle-registry host are rewritten; others are left
  untouched (fail-open). The rewrite carries the formula name and version so the
  admission gates see a concrete coordinate.
- **Bottle content verification.** On a request for the rewritten bottle
  endpoint, the proxy reconstructs the exact upstream blob URL, fetches the blob
  (following the token handshake and any blob-storage redirect), and **verifies**
  the streamed bytes against the SHA-256 named in the URL — the same digest the
  formula's bottle manifest records. A mismatch aborts the cache write and the
  client stream with a digest-mismatch error, so a tampered or corrupt bottle can
  neither poison the cache nor reach a client. It records
  `X-Content-Hash-Verified: sha256` on success. Bottles are cached
  content-addressably under their digest.

> Homebrew bottles are **not** OSV-scanned by coordinate: OSV.dev defines no
> Homebrew ecosystem (a bottle is addressed by an opaque OCI digest, and a
> formula coordinate is not an OSV key). The defense is the content-address
> verification above plus the name / content / provenance / policy gates; a
> formula's underlying source is covered by the provenance / commit-scanning
> paths.

```yaml
upstreams:
  homebrew:
    type: homebrew
    url: https://formulae.brew.sh
    settings:
      # OCI registry Homebrew bottles are fetched from (default https://ghcr.io);
      # only bottle URLs on this host are rewritten through the proxy.
      bottleRegistryUrl: https://ghcr.io
```

Point Homebrew at the proxy with its API and artifact domain variables:

```bash
export HOMEBREW_API_DOMAIN="https://proxy.example.com/v1/homebrew/api"
export HOMEBREW_ARTIFACT_DOMAIN="https://proxy.example.com/v1/homebrew"
brew update
brew install wget
# or declaratively, via a Brewfile:
#   brew bundle --file=./Brewfile
```

Because bottle download URLs are already rewritten in the served formula
metadata, `HOMEBREW_ARTIFACT_DOMAIN` is not strictly required, but setting it
keeps any directly-constructed bottle URL flowing through the proxy as well.

---

## Ansible Galaxy

Ansible Galaxy (`type: ansible`, `https://galaxy.ansible.com`) is the registry
for Ansible collections and roles. It is proxied under `/v1/<name>`. The backend
serves the Galaxy v3 REST API — the collection index
(`/api/v3/plugin/ansible/content/<repo>/collections/index/<ns>/<name>/`), the
versions list, and the per-version detail document — plus the content-
addressable collection artifact tarballs
(`.../collections/artifacts/<ns>-<name>-<version>.tar.gz`).

- **Collection artifact verification.** A version-detail document carries an
  `artifact` object with the published tarball's `sha256`. On a cache miss the
  proxy reads the sibling version-detail document, recovers the artifact's
  SHA-256, and **verifies** the fetched bytes against it — streaming, so a
  mismatch aborts the cache write and the client stream. It records
  `X-Checksum-Verified: sha256` on success. An artifact whose version detail is
  unavailable is served byte-exact and recorded as unverified.
- **Metadata URL rewriting.** Any absolute upstream URL a served metadata
  document embeds — in particular a version detail's `download_url` — is
  **rewritten** to the proxy's public base URL, so a client's artifact download
  flows back through the proxy (and its content gates and checksum verification).

> Ansible Galaxy is **not** OSV-scanned by coordinate. OSV.dev defines no
> Ansible-Galaxy ecosystem; a collection is addressed by a `namespace.name` FQCN
> that is not an OSV key, so no coordinate lookup is performed. The defense is
> the artifact SHA-256 verification above plus the name / content / provenance /
> policy gates; a collection's underlying source repository is covered by the
> provenance / commit-scanning paths.

```yaml
upstreams:
  ansible:
    type: ansible
    url: https://galaxy.ansible.com
```

Point `ansible-galaxy` at the proxy via `ansible.cfg`:

```ini
[galaxy]
server_list = pullthrough

[galaxy_server.pullthrough]
url = https://proxy.example.com/v1/ansible/
# token = <your proxy token>
```

```bash
ansible-galaxy collection install community.general
```

---

## Puppet Forge

Puppet Forge (`type: puppet`, `https://forgeapi.puppet.com`) is the registry for
Puppet modules. It is proxied under `/v1/<name>`. The backend serves the Forge
v3 REST API — module metadata (`/v3/modules/<owner>-<name>`), release metadata
(`/v3/releases/<owner>-<name>-<version>`), and the listing/search endpoints —
plus the content-addressable release tarballs
(`/v3/files/<owner>-<name>-<version>.tar.gz`).

- **Release tarball verification.** A release-metadata document carries the
  tarball's `file_sha256` and (for legacy releases) `file_md5`. On a cache miss
  the proxy reads the sibling release-metadata document, recovers the digest —
  **preferring SHA-256**, falling back to MD5 only when no SHA-256 is published —
  and **verifies** the fetched bytes against it — streaming, so a mismatch aborts
  the cache write and the client stream. It records `X-Checksum-Verified:
  sha256` (or `md5`) on success.
- **Metadata URL rewriting.** Forge release documents reference the tarball with
  a relative `file_uri` (e.g. `/v3/files/...`), so a client that resolves it
  against the proxy mount flows the download back through the proxy without any
  rewrite. Any absolute upstream self-reference a document embeds (e.g.
  paginated `next`/`previous` links) is additionally **rewritten** to the
  proxy's public base URL.

> Puppet Forge is **not** OSV-scanned by coordinate. OSV.dev defines no
> Puppet-Forge ecosystem; a module is addressed by an `owner-name` slug that is
> not an OSV key, so no coordinate lookup is performed. The defense is the
> release digest verification above plus the name / content / provenance /
> policy gates; a module's underlying source repository is covered by the
> provenance / commit-scanning paths.

```yaml
upstreams:
  puppet:
    type: puppet
    url: https://forgeapi.puppet.com
```

Point the Puppet module tool at the proxy:

```bash
puppet module install puppetlabs-stdlib \
  --module_repository https://proxy.example.com/v1/puppet
# or, in a Puppetfile for r10k:
#   forge 'https://proxy.example.com/v1/puppet'
#   mod 'puppetlabs-stdlib', '9.4.1'
```

---

## JSR (JavaScript Registry)

The JSR registry (`type: jsr`, `https://jsr.io`) is the modern
JavaScript/TypeScript registry used by Deno, Node, Bun and others. It is proxied
under `/v1/<name>`. The backend serves the JSR static tree: the package metadata
document (`/@<scope>/<name>/meta.json`), the per-version metadata that carries
the publish manifest (`/@<scope>/<name>/<version>_meta.json`), and the
content-addressable module files that make up a published version
(`/@<scope>/<name>/<version>/<path>`).

- **Module content verification.** Each version's `_meta.json` carries a
  `manifest` map of every published file path to its `size` and a
  Subresource-Integrity-style `checksum` (`sha256-<hex>`). On a cache miss the
  proxy reads the manifest, recovers the file's SHA-256, and **verifies** the
  fetched bytes against it — streaming, so a mismatch aborts the cache write and
  the client stream. It records `X-Checksum-Verified: sha256` on success. A file
  the manifest does not cover is served byte-exact and recorded as unverified.
- **Metadata URL rewriting.** Any absolute upstream URL a served metadata
  document embeds is **rewritten** to the proxy's public base URL so a client
  that follows an embedded link flows back through the proxy. JSR's documents are
  predominantly relative, so this is usually a no-op, but it holds defensively.

> JSR is **not** OSV-scanned by coordinate. OSV.dev defines no "JSR" ecosystem;
> although JSR is npm-adjacent (packages are mirrored to npm under the synthetic
> `@jsr/<scope>__<name>` name served from `npm.jsr.io`), a JSR-native coordinate
> (`@scope/name`) is not an npm name and OSV publishes no JSR-keyed advisories,
> so no coordinate lookup is performed. The defense is the manifest content
> verification above plus the name / content / provenance / policy gates.

```yaml
upstreams:
  jsr:
    type: jsr
    url: https://jsr.io
```

Point a JSR-aware client at the proxied registry (Deno honors `JSR_URL`):

```bash
export JSR_URL=https://proxy.example.com/v1/jsr
deno add @std/encoding
```

---

## Hackage (Haskell)

Hackage (`type: hackage`, `https://hackage.haskell.org`) is the central package
repository for the Haskell ecosystem. It is proxied under `/v1/<name>`. The
backend serves the Hackage tree: the incremental package index
(`/01-index.tar.gz`), the TUF security metadata (`/root.json`, `/snapshot.json`,
`/timestamp.json`, `/mirrors.json`), per-package `.cabal` descriptions, and the
immutable source-distribution (sdist) tarballs
(`/package/<name>-<version>/<name>-<version>.tar.gz`).

- **sdist content verification (where available).** Hackage's hackage-security
  (TUF) metadata records a per-version `package.json` target document pinning the
  sdist tarball's SHA-256. On a cache miss the proxy fetches that sibling
  document, reads the declared SHA-256, and **verifies** the fetched bytes against
  it — streaming, so a mismatch aborts the cache write and the client stream. It
  records `X-Checksum-Verified: sha256` on success. The canonical copy of that
  hash lives inside the signed `01-index` (too large to fetch per-pull), so a
  public mirror may not expose a standalone `package.json`; when the declared hash
  is unavailable the tarball is served byte-exact, recorded as unverified in
  metrics, and a `cabal` client still verifies against its own copy of the signed
  index end-to-end.

> Hackage **is** OSV-scanned by coordinate: OSV.dev's `Hackage` ecosystem is
> keyed by Haskell package name and version, exactly the coordinate an sdist
> filename encodes.

```yaml
upstreams:
  hackage:
    type: hackage
    url: https://hackage.haskell.org
```

Point `cabal` at the proxied repository with a `remote-repo` entry in
`~/.cabal/config`, then refresh the index and build through it:

```
repository hackage
  url: https://proxy.example.com/v1/hackage
```

```bash
cabal update
cabal build
```

---

## Generic (ecosystems without a dedicated backend)

When a registry is not covered by any dedicated backend above, a generic
upstream (`type: generic`) fronts it with declarative routing rules — no code
changes. It serves under `/v1/<name>/` and routes through the same gated pull
pipeline. With

```yaml
upstreams:
  mysource:
    type: generic
    url: https://repo.example.com
    generic:
      publicBaseURL: https://proxy.example.com/v1/mysource
      routes:
        - name: metadata
          match: '^/packages/[^/]+/index\.json$'
          rewrite: true            # served live; embedded URLs rewritten through the proxy
        - name: artifact
          match: '^/packages/[^/]+/.+\.tar\.gz$'
          cacheable: true          # cached + routed through the content gates
          verify:                  # verified against a sibling .sha256 before caching/serving
            algorithm: sha256
            source: sidecar
            sidecarSuffix: .sha256
```

clients point at `https://proxy.example.com/v1/mysource/…`. The route set is an
allowlist (an unmatched path is refused), artifacts are content-verified on
fetch, and unsafe configs are rejected at load time. See
[generic-backend.md](generic-backend.md) for the full field reference,
path-embedded digests, content-gate selection, and metrics.

## Git over HTTPS

A Git upstream (`type: git`) is served under `/v1/<name>/`. With

```yaml
upstreams:
  github:
    type: git
    url: https://github.com
    credentials:
      username: git
      token: ${GITHUB_TOKEN}   # optional; injected toward the upstream
```

clone any repository by appending its path to the upstream prefix:

```bash
git clone https://proxy.example.com/v1/github/torvalds/linux.git
```

The proxy speaks the Git **smart-HTTP** protocol
(`/info/refs?service=git-upload-pack` and `git-upload-pack`); it is **read-only**
(fetch/clone only, no push). Configured upstream credentials are injected toward
the forge, so clients clone public *and* private mirrored repos without holding
upstream tokens. To make an existing checkout fetch through the proxy:

```bash
git remote set-url origin https://proxy.example.com/v1/github/torvalds/linux.git
```

If proxy access control is enabled, supply your **proxy** token via the URL or a
credential helper (e.g. `https://<token>@proxy.example.com/v1/github/...`).

When `git.mirrorDir` is set the proxy keeps local bare mirrors and serves
packs/objects from cache (refreshed at most every `git.refreshInterval`); without
it, smart-HTTP requests stream straight through with ref advertisements cached
for `git.infoRefsTtl`.

## Git over SSH

The SSH gateway is active only when `server.sshAddr` is set **and** mirror mode
is enabled (`git.mirrorDir`). It is read-only and serves from the local mirrors.

```yaml
server:
  sshAddr: ":2222"
git:
  mirrorDir: /var/lib/pullthrough/mirrors
  ssh:
    hostKeyFile: /etc/pullthrough/ssh_host_ed25519_key   # stable host key
    authorizedKeysFile: /etc/pullthrough/authorized_keys # permitted clients
    # authorizedKeys: ["ssh-ed25519 AAAA... alice"]
    # noClientAuth: true   # trusted networks only; still read-only
```

The repository path is `<upstream-name>/<repo-path>`. Clone with:

```bash
git clone ssh://git@proxy.example.com:2222/github/torvalds/linux.git
```

Or simplify with `~/.ssh/config`:

```
Host gitproxy
    HostName proxy.example.com
    Port 2222
    User git
    IdentityFile ~/.ssh/id_ed25519
```

```bash
git clone ssh://gitproxy/github/torvalds/linux.git
```

Pin the proxy's host key in `~/.ssh/known_hosts` (always set `hostKeyFile` in
production; otherwise the proxy generates an ephemeral key whose fingerprint
changes on every restart). Client authentication is **public-key only** — the key
must appear in `authorizedKeys`/`authorizedKeysFile` unless `noClientAuth: true`.

SSH-transport *upstreams* are configured per upstream via `settings`:

```yaml
upstreams:
  github-ssh:
    type: git
    url: ssh://git@github.com/
    settings:
      sshPrivateKeyFile: /etc/pullthrough/github_id_ed25519
      sshKnownHostsFile: /etc/pullthrough/known_hosts
      # sshInsecureIgnoreHostKey: "true"   # UNSAFE: skips upstream host-key check
```

---

## Git LFS (large-object pull-through)

When `git.lfs.enabled` is set, the proxy transparently fronts [Git LFS](https://git-lfs.com/)
for HTTPS git upstreams. It implements the LFS batch API
(`POST <repo>/info/lfs/objects/batch`): a client's download negotiation is
forwarded upstream, then every download action is rewritten so its `href` points
back at the proxy's own per-object endpoint
(`GET <repo>/info/lfs/objects/<oid>`). Upstream-issued auth headers are stripped
— the proxy re-authenticates to upstream itself. Upload operations are rejected
(the proxy is read-only).

Each LFS blob is streamed through the content-addressable cache keyed by its
sha256 OID (`sha256:<oid>`), so it inherits the same guarantees as every other
cached artifact:

- **Integrity on fetch** — the content's sha256 must equal the requested OID and
  its length must equal the size the batch API declared, or the fetch is refused
  (`502`) and nothing is cached.
- **Read-time self-healing** — a cached blob that fails verification on serve is
  quarantined and transparently re-fetched (Task 107).
- **Single-flight coalescing** — concurrent misses for the same OID share one
  upstream fetch (Task 36).
- **Range streaming** — partial (`Range`) reads are served as `206`/`416`
  directly from the cache (Task 75).
- **SSRF/egress allowlist** — the upstream object href (which upstream controls)
  is fetched through the egress-guarded outbound client, so `egress.allowlist`
  applies (Task 89). Object-store CDN hosts (e.g. `github-cloud.*`) must be
  allowlisted.

Freshly-fetched **textual** blobs under `git.lfs.scanMaxBytes` are run through the
commit-scan secret detector; set `git.lfs.blockOnFindings: true` to refuse a blob
that contains a detected secret rather than serving it with the finding recorded.

```yaml
git:
  lfs:
    enabled: true
    maxObjectBytes: 5368709120   # 5 GiB cap per object (0 = default)
    scanMaxBytes: 5242880        # scan the first 5 MiB of a text blob (0 = default)
    blockOnFindings: false       # true: fail closed on a secret finding
```

Clients need no special configuration — a normal `git lfs pull` / `git clone`
through the proxy transparently fetches and caches LFS objects. Metrics are
exported under `pullthrough_lfs_*` (batch requests, cache hits/misses, bytes
fetched/served, OID/size mismatches, gate findings/blocks), labeled by backend.

---

## Caching behavior

| Ecosystem | Cached immutably                         | Revalidated each request                |
|-----------|------------------------------------------|-----------------------------------------|
| npm       | tarballs (`.../-/...tgz`)                 | packuments                              |
| pip       | wheels/sdists (`/files/...`)             | Simple pages                            |
| cargo     | `.crate` downloads                       | `config.json`, sparse index files       |
| go        | `.info` / `.mod` / `.zip` per version    | `@v/list`, `@latest`                    |
| nuget     | `.nupkg` packages                        | service index, registration, version lists |
| maven     | release & timestamped-snapshot artifacts (`.jar`/`.pom`/`.module`/`.war`) + sidecars | `maven-metadata.xml`, non-timestamped `-SNAPSHOT` artifacts |
| rubygems  | `.gem` files, `/quick/Marshal.4.8` gemspecs | compact index (`/versions`, `/names`, `/info/<gem>`), Marshal indexes, dependency API |
| composer  | dist archives (`/dist/<vendor>/<package>/<ref>.<ext>`) | `packages.json`, `/p2/...` v2 metadata, `/p/...` providers |
| helm      | chart archives (`<name>-<version>.tgz`) + `.prov` provenance (classic); manifests/blobs by digest (OCI) | `index.yaml` (classic); manifests by tag (OCI) |
| docker    | blobs & manifests by digest              | manifests by tag, tag/ping endpoints    |
| conan     | recipe/package files under a pinned revision (`.../revisions/{rrev}/files/...`), MD5-verified via `conanmanifest.txt` | `/latest`, `/revisions`, search, `/ping` |
| swift     | release metadata, `Package.swift`, source archives (`.../{version}.zip`) under a pinned version, SHA-256-verified via the release metadata `checksum` | release list (`/{scope}/{name}`), `/identifiers` lookup |
| dart      | package archives (`/api/archives/<pkg>-<ver>.tar.gz`), SHA-256-verified via `archive_sha256` | list-versions (`/api/packages/<pkg>`, archive URLs rewritten), advisories |
| huggingface | commit-pinned `resolve` blobs (`.../resolve/{sha}/...`), SHA-256-verified via `X-Linked-Etag`, LFS/CDN-followed, pickle weights opcode-scanned | branch/tag `resolve`, `/api/models` + `/api/datasets` metadata |
| openvsx   | `.vsix` archives (`.../file/{file}.vsix`), SHA-256-verified via the sibling `.sha256` sidecar, install/activation manifest content-scanned | `/api/...` metadata + query (download URLs rewritten), `/vscode/...` gallery, `.sha256`/manifest sidecars |
| git       | packs/objects (mirror mode)              | ref advertisements (`infoRefsTtl`)      |
| git LFS   | LFS blobs by sha256 OID (`sha256:<oid>`), OID+size-verified on fetch | batch-API negotiation (`/info/lfs/objects/batch`) |

Immutable artifacts are stored in the content-addressable cache and served on
subsequent requests without contacting the upstream. Mutable index documents are
revalidated with the upstream using `ETag` / `Last-Modified` conditional
requests, so unchanged documents cost only a `304` round-trip.
