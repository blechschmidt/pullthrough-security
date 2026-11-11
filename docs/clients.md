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

> **Verified in CI.** Every ecosystem's real client is run through the proxy on
> every push ([ecosystem-tests.md](ecosystem-tests.md)); the exact, working
> client configuration for each one is published in
> [ecosystem-tests-reference.md](ecosystem-tests-reference.md).

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

With `,direct`, a module the proxy answers `404`/`410` for is fetched straight
from its VCS host; an admission refusal (`403`) is final either way. Leave
`,direct` out to keep every fetch on the proxy.

**Checksum database.** The go command verifies every module against
`sum.golang.org` and, by default, contacts it directly — which fails for a client
that can reach only the proxy. The proxy therefore serves the database itself
under `/v1/goproxy/sumdb/<name>/` (the GOPROXY protocol's checksum-database
proxying); the go command discovers this on its own and routes its lookups
through the proxy. Every response is signed by the database and verified with
the key built into the go command, so verification stays fully intact and no
trust is placed in the proxy. The `sumdb` upstream setting names the databases to
proxy (default `sum.golang.org`; `off` disables it).

For private modules that are not in the public checksum database, set
`GONOSUMDB`/`GOPRIVATE` for those paths as usual.

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
proxied under `/v1/packagist`. The backend speaks the **Composer 2 repository
protocol**: the repository root (`packages.json`), the **v2 metadata layout**
(`/p2/<vendor>/<package>.json` and its `~dev` sibling), and **dist archive
downloads**.

A Composer client follows whatever URLs the repository hands it: the root names
the URL templates for every later lookup, and each version in the metadata names
the URL its archive is downloaded from. The proxy therefore **rewrites both
documents** on the way out, so a client configured with only the proxy
repository keeps every metadata and dist request on the proxy and never contacts
Packagist or GitHub itself.

- **`packages.json`** is served with its package lookups (`metadata-url`,
  `providers-url`) pointed at this backend's mount. Everything the backend does
  not front is removed rather than left pointing at the upstream: the
  install-statistics endpoint (`notify-batch` — clients do not report their
  installs around the proxy), the discovery APIs (`search`, `list`,
  `providers-api`, `metadata-changes-url`), upstream-declared `mirrors`, and the
  POST-only `api-url` of `security-advisories` and `filter`. With Packagist,
  Composer's security advisories (`composer audit`, blocking of insecure
  versions) and filter (malware) lists keep working, because Packagist embeds
  both in the v2 metadata the client fetches through the proxy; the filter-list
  summary (`/lists/<...>.json`) is proxied as well. An upstream that offers
  advisories only through its API has them dropped. `composer search` finds
  nothing in the proxy repository.
- **v2 metadata** is served with every version's `dist.url` rewritten to the
  proxy's dist endpoint,
  `/dist/<vendor>/<package>/<version>/<reference>.<type>` — for example
  `/v1/packagist/dist/psr/log/3.0.0/fe5ea303b0887d5caefd3d431c3e61ad47037001.zip`.
  The "minified" delta encoding is honored: a version that inherits its
  predecessor's `dist` (two versions on one commit) gets a URL of its own.
  Metadata documents are mutable and revalidated on every request. The legacy
  `/p/...` provider documents are proxied as-is; only the Composer 2 layout is
  rewritten.
- **Dist archives** are cached immutably. A dist URL names the package **and the
  version**, so the admission gates (policy, dependency firewall, malware feed,
  release maturity, …) evaluate the `vendor/package@version` coordinate before
  anything is fetched (vulnerability scanning maps it to the OSV `Packagist`
  ecosystem). It also names the dist *reference* — the commit id — so a moved
  branch or a re-pointed tag is a different URL and a different cache entry. On
  a cache miss the proxy re-reads the package's v2 metadata and fetches **only**
  the download URL the upstream lists for exactly that version, reference and
  type (following redirects such as `api.github.com` → `codeload.github.com`);
  any other request is a `404`. When the metadata declares a **SHA-1
  `dist.shasum`** the archive is verified against it and a mismatch is refused.
  Packagist publishes no shasum for the archives GitHub generates on the fly;
  such an archive is cached exactly as fetched, and every later install is
  served those same bytes.

Set `server.publicUrl` so the rewritten URLs are absolute. Without it they are
root-relative (`/v1/<name>/...`). Composer resolves a root-relative URL in
`packages.json` but not in a `dist.url`, so in that case the proxy also
advertises its dist endpoint as a preferred dist *mirror*, which Composer does
resolve; installs stay on the proxy either way (the lock file then records the
root-relative `dist.url` together with that mirror).

```yaml
upstreams:
  packagist:
    type: composer
    url: https://repo.packagist.org
```

**Composer** — make the proxy the project's *only* repository in
`composer.json`. Adding it is not enough: unless the default repository is
disabled with `"packagist.org": false`, Composer still resolves and downloads
from packagist.org directly.

```json
{
  "repositories": [
    { "type": "composer", "url": "https://proxy.example.com/v1/packagist" },
    { "packagist.org": false }
  ]
}
```

```bash
# the same from the command line
composer config repositories.proxy composer https://proxy.example.com/v1/packagist
composer config repositories.packagist.org false
# if the proxy requires auth
composer config --global --auth http-basic.proxy.example.com pullthrough <token>
```

A proxy reached over plain `http://` additionally needs
`"config": { "secure-http": false }`.

Things to know:

- `composer.lock` records the rewritten dist URLs, so installing from a lock
  file goes through the proxy too (and needs the proxy reachable under the same
  public URL).
- A dev version (`dev-main`, `2.x-dev`) is locked to a commit. Once the branch
  has moved on, the upstream metadata no longer lists that commit, so the proxy
  can only serve it if it is already cached; run `composer update` to move to
  the commit the branch is at now.
- `source` (the package's VCS origin) is not rewritten: an install with
  `--prefer-source` clones from the VCS host directly, not through this
  backend. When the proxy refuses a dist, current Composer (verified with 2.11)
  fails the install, whereas older releases (verified with 2.2) fall back to
  cloning `source`; where that matters, deny clients direct access to the VCS
  host.

---

## Helm charts

Helm has two transports, and the proxy covers both with a single `type: helm`
backend selected by the optional `settings.oci` flag.

### Classic chart repositories (`helm repo add`)

A classic Helm upstream (`type: helm`, e.g. `https://charts.bitnami.com/bitnami`)
is proxied under `/v1/<name>`; point `url` at the repository root that serves
`index.yaml`.

```bash
helm repo add bitnami https://proxy.example.com/v1/bitnami
helm repo update
helm pull bitnami/nginx --version 15.0.0   # .tgz fetched + SHA-256-verified by the proxy
helm install web bitnami/nginx
```

**Chart downloads always come back through the proxy.** A repository's
`index.yaml` tells Helm where each chart archive lives, and real repositories
publish absolute URLs there — often on a different host than the index (a GitHub
Pages index listing release assets) or as `oci://` references into a registry
(Bitnami). Served as-is, such an index would send Helm straight to the upstream
for the archive, past the cache and every gate. So the backend serves
`index.yaml` live (revalidated against the upstream on every request) with each
entry's `urls` replaced, and nothing else changed, by

```
<server.publicUrl>/v1/<name>/-/<chart>/<version>/<file>
```

When `server.publicUrl` is not set the links are written relative to the
repository instead (`-/<chart>/<version>/<file>`); Helm resolves those against
the URL the repository was added under, so they reach the proxy either way.

Such a URL names an index entry rather than a location. On a request the backend
looks the chart name and version up in the upstream index and fetches the
location recorded there — on the upstream's host, on another host, or as the
chart layer of an OCI artifact — so anything the index does not list for that
chart version is a `404` and the proxy cannot be pointed at an arbitrary URL.
The fetch goes through the [egress guard](egress-ssrf.md) like any other (with
an egress allowlist, include the hosts the repository keeps its archives on);
upstream credentials are sent only to the upstream's own host. The archive is
verified against the **SHA-256 `digest`** the index publishes for it before the
bytes are cached or served — a mismatch is refused — and the chart `name` +
`version` coordinate feeds the admission gates (vulnerability scanning of the
images a chart references, signature verification, risk scoring, policy). A
repeat pull is served from the cache. Chart **provenance** is served the same
way, at the archive URL plus `.prov`. A chart requested by its
repository-relative path (`/v1/<name>/<name>-<version>.tgz`) keeps working: it
is fetched from that path under the upstream and verified the same way.

Because the rewrite has to be airtight, an index the backend cannot fully
account for is refused (`502`, reason in the proxy log) rather than passed
through: one it cannot parse, or one that uses a YAML alias, merge key or tag to
declare download locations (no index generator does). The upstream index is
parsed once per change, not per request — the parsed index and the rewritten
document are held in memory per upstream (about the size of the index, capped at
128 MiB) and revalidated with a conditional request — so only the first request
after a change pays for the parse (roughly a second for a 25 MiB index).

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

the backend is mounted under `/v1/dockerhub/`, where it serves the read
endpoints of the v2 API (`/v2/`, `/v2/<name>/manifests/<ref>`,
`/v2/<name>/blobs/<digest>`, `/v2/<name>/referrers/<digest>`,
`/v2/<name>/tags/list`, `/v2/_catalog`). Blobs and manifests requested by digest
are cached immutably and digest-verified; manifests by tag are revalidated live.
Any other path under `/v2/` is refused with `501`: the proxy logs in to the
upstream itself, so a registry-hosted token endpoint (`/v2/token`, `/v2/auth`)
is never forwarded — it would hand the client a token for the proxy's account.

Container clients — the Docker Engine, containerd, podman, skopeo, the Helm OCI
client — always insert `/v2/` immediately after the registry host, so none of
them can address the path-prefixed mount (`docker pull host/v1/dockerhub/...`
does **not** work). The proxy therefore also serves the Registry v2 API at its
**host root** (`/v2/...`, see `server.registry`), mapping each request onto the
upstream's `/v1/<name>/v2/...` mount — through the same access control and
admission gates as any other pull. No reverse proxy is needed in front.

### Option A — Explicit reference (any registry, no daemon configuration)

Prefix the repository with the **upstream name**:

```bash
docker pull proxy.example.com/dockerhub/library/nginx:latest
docker pull proxy.example.com/ghcr/myorg/myimage:1.2.3     # with a "ghcr" docker upstream
```

`/v2/dockerhub/library/nginx/...` is served by the `dockerhub` upstream as
repository `library/nginx`. This works for any number of registry upstreams and
is fail-closed by construction: when the proxy refuses an image, the pull fails.

### Option B — Docker Hub via a registry mirror (daemon-wide, transparent)

The daemon's `registry-mirrors` setting applies to Docker Hub (`docker.io`)
images. The Docker Engine **rejects a mirror URL that carries a path**, so the
mirror is the proxy's host root; name the upstream that should answer
un-prefixed repositories:

```yaml
server:
  registry:
    defaultUpstream: dockerhub
```

`/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["https://proxy.example.com"]
}
```

```bash
sudo systemctl restart docker
docker pull nginx:latest        # transparently fetched through the proxy
```

Verify with `docker system info | grep -A2 Mirrors`.

> **Mirrors are fail-open.** When a mirror refuses a pull (for example because
> the proxy's admission policy blocked the image), the Docker Engine falls back
> to Docker Hub directly. Mirror mode enforces admission only where direct egress
> to Docker Hub is blocked; otherwise use explicit references (Option A).

### containerd / CRI-O (Kubernetes nodes)

containerd names the registry it is mirroring in an `ns` query parameter, which
the proxy uses to pick the upstream fronting that registry — so one proxy
endpoint can mirror several registries:

```toml
# /etc/containerd/certs.d/docker.io/hosts.toml
server = "https://registry-1.docker.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
```

```toml
# /etc/containerd/certs.d/ghcr.io/hosts.toml
server = "https://ghcr.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
```

A request arriving as `/v2/myorg/myimage/manifests/1.2.3?ns=ghcr.io` is served by
the upstream whose `url` is `https://ghcr.io`; `ns=docker.io` selects the upstream
for `registry-1.docker.io`.

### Routing rules at `/v2/`

1. A request carrying `?ns=<registry host>` is served by the upstream fronting
   that registry.
2. Otherwise, if the repository's first path component is the name of a registry
   upstream, that upstream serves the rest (`/v2/<upstream>/<repository>/...`).
3. Otherwise `server.registry.defaultUpstream` serves it; without one the request
   is refused with a registry error naming the configured upstreams.

Avoid naming a registry upstream after a namespace you also mirror (an upstream
called `library` would shadow Docker Hub's `library/...` repositories in rule 2).
Set `server.registry.enabled: false` to serve registries only under
`/v1/<name>/v2/`.

Private upstreams authenticate with credentials configured on the upstream;
clients never send registry credentials to the proxy for the pull itself (proxy
access control, if enabled, is separate — see
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

Serve the public registry's hostname from the proxy with a `host` block in the
CLI configuration (`~/.terraformrc`, or the file named by `TF_CLI_CONFIG_FILE`;
OpenTofu reads `~/.tofurc` the same way). It overrides service discovery for
that hostname, so provider and module addresses in `.tf` files stay exactly as
they are — `hashicorp/null` resolves through the proxy:

```hcl
host "registry.terraform.io" {
  services = {
    "providers.v1" = "https://proxy.example.com/v1/terraform/v1/providers/"
    "modules.v1"   = "https://proxy.example.com/v1/terraform/v1/modules/"
  }
}
```

```bash
terraform init      # versions, package descriptor, zip, SHA256SUMS and .sig via the proxy
```

Because the proxy verifies the SHASUMS signature itself and re-serves the
manifest and `.sig`, the client's own checksum and signature verification
continues to work end-to-end through the proxy.

---

## Conan (C/C++)

A Conan upstream (`type: conan`, e.g. `https://center2.conan.io`) is proxied
under `/v1/<name>`. The backend speaks the **Conan 2.x revisions REST API** (the
`/v2/...` endpoints that JFrog Artifactory, ConanCenter, and the reference
`conan_server` expose), plus the one legacy route a Conan 2.x client still
sends: the capability probe `GET /v1/ping`. The client reads the
`X-Conan-Server-Capabilities` response header of that probe before any `/v2`
call and will not use a remote that does not advertise `revisions`, so the
header is relayed from the upstream. The rest of the Conan 1.x API is not
supported.

Recipe and package files are addressed beneath an immutable recipe revision
(`rrev`) and package revision (`prev`), each of which is a content hash of the
files it pins, so those files (and the per-revision file listings) are cached
**content-addressably** and served indefinitely. The mutable discovery
endpoints (`/latest`, `/revisions`, search, the ping) are served live from the
upstream on every request and never cached.

On a cache miss the proxy **verifies** the MD5 of each fetched content file
before the bytes are cached or served — streaming for the archives, in memory
for the small `conaninfo.txt` — and refuses a mismatch. The expected digest is
taken from:

- the revision's `conanmanifest.txt`, for the files it names: `conanfile.py`
  and `conaninfo.txt`. The manifest lists a revision's files in their unpacked
  form, so it never names the `.tgz` archives.
- the `X-Checksum-Md5` response header, for everything else — the
  `conan_export.tgz`, `conan_sources.tgz`, and `conan_package.tgz` archives.
  Artifactory-based remotes (ConanCenter included) send it with every file. The
  reference `conan_server` does not; its archives are served unverified.

The outcome is recorded in the cache entry's metadata, visible through the
admin cache API: `conan.checksumVerified` is `md5` or `none`, and
`conan.checksumSource` is `manifest` or `upstream-header`. Both digests are
published by the same upstream that serves the file, so they catch corruption
and truncation rather than a compromised upstream. `conanmanifest.txt` itself
is cached as served, and no `X-Checksum-*` header is added to (or replayed on)
the proxy's own file responses — Conan does not use them for downloads.

```yaml
upstreams:
  conancenter:
    type: conan
    url: https://center2.conan.io
```

Register the proxy as a Conan remote (Conan 2.x) and pull through it:

```bash
conan remote add proxy https://proxy.example.com/v1/conancenter
conan install --requires=zlib/1.3.1 -r proxy
conan download zlib/1.3.1 -r proxy --only-recipe
```

> **Authentication.** The proxy authenticates to a private remote with the
> `credentials` configured on the upstream; a client never logs in to the
> upstream through it. The Conan login endpoints (`GET /v2/users/authenticate`
> and `/v2/users/check_credentials`) are therefore refused with `501` rather
> than forwarded — the upstream would answer them with a session token for the
> proxy's own account — so `conan remote login` and `conan remote auth` fail
> against a proxy remote ("Invalid server response"). That endpoint is also the
> only way a Conan client obtains a token to present, so Conan cannot send a
> proxy token. If the proxy enforces authentication, admit anonymous reads for
> the Conan upstream (`auth.allowAnonymous` with an `auth.anonymousRoles` role
> scoped to that upstream); the other upstreams keep requiring a token.

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
`/tarballs/<name>-<version>.tar`, and the `/installs/` tree Mix and Hex use to
install and update themselves (below).

A tarball filename pins its `name-version` coordinate, so tarballs are cached
**content-addressably** and served indefinitely; the mutable registry resources
are revalidated rather than cached and are passed through **byte-exact**, so a
client that pins the repository public key still performs its own end-to-end
signature verification.

On a cache miss for a tarball the proxy fetches the sibling `/packages/<name>`
resource, decodes the signed protobuf, reads the release's **outer_checksum** (a
SHA-256 over the whole tarball), and **verifies** the fetched bytes against it
before they are cached or served — streaming, so a mismatch is refused. The
outcome is recorded as `hex.checksumVerified` (`sha256` or `none`) in the cache
entry's metadata, visible through the admin cache API. The package coordinate is
associated for nameguard, vulnscan, provenance, policy, and license enforcement;
Hex coordinates are additionally OSV-scanned (OSV's `Hex` ecosystem).

**Hex and Rebar self-install (`/installs/`).** With `HEX_MIRROR` set, Mix and
Hex also fetch their own builds from the mirror. Hex's update check (at most
once a day, on `mix deps.get` and friends) reads `/installs/hex-1.x.csv`;
`mix local.hex` and `mix local.rebar` read a builds list (`hex-1.x.csv`,
`rebar3-1.x.csv`; `hex.csv`, `rebar.csv` from Elixir 1.18), its `.signed`
signature, and then the build the list selects
(`/installs/<elixir>/hex-<version>.ez`, `/installs/<elixir>/rebar3-<version>`).
The proxy passes exactly these paths through **live and byte-exact** and refuses
anything else under `/installs/`. Mix checks each list's signature against its
built-in public key (through Elixir 1.18; later releases rely on HTTPS) and each
build against the SHA-512 its list records.

The builds are deliberately **not cached** and not gated. They are not hex.pm
packages, so there is no package coordinate for the admission gates to evaluate;
their only integrity record is a row in the mutable list, so a cached copy could
only go stale against it (and then fail every client's checksum check until
purged); and the client verifies them itself on every install. `repo.hex.pm`
redirects `/installs/` to `builds.hex.pm`, so allow that host if you restrict
the proxy's egress.

```yaml
upstreams:
  hex:
    type: hex
    url: https://repo.hex.pm
```

Point mix/hex at the proxied repository by setting it as the mirror of the
default `hexpm` repository, per shell or persistently:

```bash
# Per shell / CI job:
export HEX_MIRROR=https://proxy.example.com/v1/hex
mix local.hex --force      # Hex itself, through the proxy
mix deps.get

# Or persistently, in Hex's own configuration (Hex's requests only, see below):
mix hex.config mirror_url https://proxy.example.com/v1/hex
```

> `mix local.hex` and `mix local.rebar` read only the environment, not Hex's
> configuration: they use `HEX_BUILDS_URL` when it is set (Elixir 1.15+), then
> `HEX_MIRROR`, then the default builds host.

> Do not register the proxy as a separately named repository
> (`mix hex.repo add <name> <url>`) to mirror hex.pm: the registry resources are
> signed for the repository name `hexpm`, and Hex rejects them under any other
> name.

> The proxy serves the repository tree only (registry resources, tarballs, and
> `/installs/`); it does not front the hex.pm JSON API (`api.hex.pm`), which
> `mix hex.publish`, `mix hex.search`, and auth flows use directly.

---

## Bazel Central Registry (Bzlmod)

A Bazel registry upstream (`type: bazel`, e.g. `https://bcr.bazel.build`) is
proxied under `/v1/<name>`, which Bazel treats as a **module registry**
(`--registry=<url>`). The backend serves the Bzlmod tree: the registry-root
`bazel_registry.json`, each module's `modules/<name>/metadata.json`, and the
per-version `modules/<name>/<version>/MODULE.bazel`, `source.json`, and the
`patches/` and `overlay/` files `source.json` declares (overlay files may be
nested, e.g. `overlay/src/BUILD.bazel`).

A module version's **source archive** lives at an arbitrary external URL
(commonly a GitHub release), not under the registry. `source.json` records that
archive's URL and its **Subresource-Integrity** (`integrity`, e.g.
`sha256-<base64>`) digest. So the proxy can cache and verify the archive, it
**rewrites** each `source.json` so its `url` points at a proxy-synthetic
`modules/<name>/<version>/archive/<file>` endpoint, leaving the `integrity`
untouched (Bazel still verifies end-to-end). A request to that endpoint re-reads
`source.json`, fetches the external archive, and **verifies** the fetched bytes
against the SRI digest before they are cached or served — streaming, so a
mismatch aborts the cache write and the client stream. The outcome is recorded
as `bazel.checksumVerified` (`sha256`/`sha384`/`sha512`, or `none`) in the cache
entry's metadata, next to the upstream URL that served the archive
(`bazel.archiveURL`). The module coordinate is associated for nameguard,
provenance, policy, and license enforcement.

`<file>` is the upstream archive's own file name
(`.../archive/platforms-0.0.10.tar.gz`). Bazel (6, 7, and 8 alike) infers the
archive format from the suffix of the URL's last path segment, so the endpoint
has to end in one; an extension-less URL fails with "Expected a file with a
.zip, … suffix". A declared `archive_type` is kept, and appended to the name
when the upstream URL has no telling suffix. The name only labels the download:
every spelling, including the bare `modules/<name>/<version>/archive`, serves
the same verified bytes from the same cache entry.

What the rewrite does with the other `source.json` fields:

- `mirror_urls` are **removed**. Bazel tries them after `url`, so left in place
  they would let a client fetch the archive straight from the internet whenever
  the proxy refused or failed it. The proxy uses them itself instead, as
  fallbacks when the primary URL is unavailable; whichever location serves the
  archive, the bytes are verified against the same `integrity`.
- `integrity`, `strip_prefix`, `patches`, `patch_strip`, `overlay`,
  `archive_type` (and anything else) are preserved verbatim. Bazel fetches patch
  and overlay files from the registry, i.e. through the proxy, where they are
  cached per module version.
- A `"type": "git_repository"` (or `local_path`) descriptor has no archive and
  is passed through unchanged. Bazel then clones the `remote` itself — **that
  fetch does not go through this backend**.

> URL rewriting requires the proxy's public URL. Set `server.publicUrl` so the
> rewritten `source.json` carries an absolute archive endpoint; without it the
> descriptor is passed through unchanged and archive fetches are not proxied.

> Bazel modules are **not** OSV-scanned by coordinate (OSV defines no
> Bazel-module ecosystem). A module's security posture is carried by its
> underlying source repository, which the provenance/commit-scanning paths cover.

```yaml
server:
  publicUrl: https://proxy.example.com
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
bazel fetch --registry=https://proxy.example.com/v1/bazel @platforms//os:linux
```

> `MODULE.bazel.lock` records the hash of every registry file per registry URL,
> including the rewritten `source.json`. A lockfile written against the proxy is
> therefore valid for that proxy URL, not for `bcr.bazel.build` directly (and
> vice versa); run `bazel mod deps --lockfile_mode=update` after switching.

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

> **The Pkg server is fail-open.** When the server refuses a package (for example
> because the proxy's admission policy blocked it), Pkg silently falls back to
> cloning the package's Git repository. Admission is therefore enforced only
> where clients have no direct route to the forges.

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

- **Formula metadata**, from the `formulae.brew.sh` JSON API. These documents
  enumerate each formula's *bottle* — a precompiled binary tarball — with its
  download URL and SHA-256. They are mutable and served live.
- **Bottle tarballs**, which Homebrew distributes as OCI blobs in GitHub
  Packages (`ghcr.io`): a content-addressed blob
  (`https://ghcr.io/v2/<repo>/blobs/sha256:<digest>`) next to an OCI image index
  per formula version (`https://ghcr.io/v2/<repo>/manifests/<version>`), both
  fetched via the standard Docker Registry v2 bearer-token handshake (anonymous
  for the public `homebrew/core` tap).

Point Homebrew at the proxy with **both** its API and artifact domain variables:

```bash
export HOMEBREW_API_DOMAIN="https://proxy.example.com/v1/homebrew/api"
export HOMEBREW_ARTIFACT_DOMAIN="https://proxy.example.com/v1/homebrew"
brew install wget
# or declaratively, via a Brewfile:
#   brew bundle --file=./Brewfile
```

What the `brew` client does with them:

- **`HOMEBREW_API_DOMAIN` routes the metadata.** `brew` downloads the
  **signed** index — `api/formula.jws.json`, plus `cask.jws.json` and the
  `*_tap_migrations.jws.json` documents — and verifies its JWS signature. The
  proxy therefore passes these documents through **byte-exact**; it cannot (and
  does not) rewrite the bottle URLs inside them.
- **`HOMEBREW_ARTIFACT_DOMAIN` routes the bottles, and is required.** It is the
  only thing that sends `brew`'s bottle downloads through the proxy: `brew`
  itself replaces `https://ghcr.io` in every bottle URL with this value and
  requests the registry-native paths from the proxy:

  ```
  GET /v1/homebrew/v2/homebrew/core/hello/manifests/2.12.3-1
  GET /v1/homebrew/v2/homebrew/core/hello/blobs/sha256:<digest>
  ```

  Without it, `brew` reads its metadata through the proxy and then downloads
  every bottle **directly from ghcr.io**, bypassing the cache and every gate.
  (`brew`'s own portable Ruby is fetched the same way, from
  `/v2/homebrew/portable-ruby/portable-ruby/blobs/sha256:<digest>`.)

On the pull path:

- **Manifests are served live.** `/v2/<repo>/manifests/<reference>` is fetched
  from the bottle registry with the client's `Accept` header forwarded (`brew`
  asks for `application/vnd.oci.image.index.v1+json`) and returned unmodified,
  with the registry's own media type and `Docker-Content-Digest`. `brew` reads
  the bottle's install receipt from it.
- **Bottle content verification.** `/v2/<repo>/blobs/sha256:<digest>` is
  fetched from the bottle registry (following the token handshake and any
  blob-storage redirect) and the streamed bytes are **verified** against the
  SHA-256 named in the URL — the digest the signed index records. A mismatch
  aborts the cache write and the client stream with a digest-mismatch error, so
  a tampered or corrupt bottle can neither poison the cache nor reach a client.
  Verified bottles are cached content-addressably under their digest (recorded
  as `homebrew.digestVerified: sha256` on the cache entry), so the next client
  is served from the cache.
- **Only the configured bottle registry is reachable.** The upstream URL is
  always rebuilt from `bottleRegistryUrl` and strictly validated path
  components: the repository must be a bottle repository
  (`<org>/<tap>/<formula>`, lowercase, with a versioned formula's `@<version>`
  as a fourth segment), a manifest reference an OCI tag or `sha256:` digest, a
  blob reference a `sha256:` digest. Anything else under `/v2/` (the version
  probe, tag listings, uploads, two-segment container images) is refused.
- **Formula coordinate for the admission gates.** The bottle URL names a
  repository and a digest but no version, so the proxy establishes the
  `(formula, version)` coordinate the name / policy / provenance / risk gates
  see:
  - The **name** is mapped back from the repository the way `brew` maps it
    forward (`@` is stored as `/`, `+` as `x`): `homebrew/core/openssl/3` is
    `openssl@3`, `homebrew/core/gtkx3` is `gtk+3`. The `+` spelling cannot be
    told from the path alone, so it is confirmed from the image index (or the
    formula JSON); until one of them has been seen such a formula goes by its
    registry spelling (`gtkx3`). A formula from any other tap is tap-qualified
    (`<org>/<tap>/<formula>`), so it can never pass for a core formula of the
    same name.
  - The **version** is learned from the image index `brew` fetches along with
    the bottle (each platform entry is annotated with the bottle digest and its
    version). With serial downloads the index arrives first; with
    `HOMEBREW_DOWNLOAD_CONCURRENCY` the two requests race, so a bottle request
    that overtakes its manifest waits briefly for it. The version is the
    formula's version — `1.92.0` for the bottle tagged `1.92.0_1`, i.e. without
    `brew`'s `_<revision>` and bottle-rebuild suffixes — the same string the
    formula JSON publishes as `versions.stable`.
  - If the index was not seen by this instance (a restart, or another replica
    served it), the version is recovered from the formula JSON API and
    remembered. If that fails too (API unreachable, a bottle the formula no
    longer lists, a third-party tap), the bottle is still gated under its
    formula name with the stand-in version `sha256:<digest>`, so name-keyed
    rules keep applying; version-keyed rules cannot match it. Which of the three
    applied is recorded as `homebrew.versionSource`
    (`manifest` / `formula-api` / `digest`) on the cache entry, and the last
    case is counted by `pullthrough_homebrew_bottle_version_fallback_total`.
    (A sealed instance never performs the API lookup.)

For consumers of the **unsigned** formula JSON (`/api/formula.json`,
`/api/formula/<name>.json`) — not the `brew` client — every bottle download URL
on the bottle-registry host is additionally **rewritten** to the proxy's own
`/bottle/<name>/<version>/v2/…/blobs/sha256:<digest>` endpoint (under the
configured public URL), which carries the coordinate in its path and serves the
same verified, cached bottle.

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
      # OCI registry Homebrew bottles and their manifests are fetched from
      # (default https://ghcr.io). It is the only registry the /v2/ paths reach,
      # and only bottle URLs on this host are rewritten in the unsigned JSON.
      bottleRegistryUrl: https://ghcr.io
```

Things to know about the client:

- If the proxy is unreachable, `brew` silently falls back to
  `https://formulae.brew.sh` for the **metadata** (the signature is verified
  either way). Bottles have no such fallback: with `HOMEBREW_ARTIFACT_DOMAIN`
  set, a bottle the proxy refuses is simply not installed. Set
  `HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1` as well to make `brew` fail rather
  than try a default URL for the few downloads that have one (e.g. its portable
  Ruby).
- Do **not** use `HOMEBREW_BOTTLE_DOMAIN` for this: it requests a different,
  flat-file layout the proxy does not serve, and `brew` falls back from it to
  `ghcr.io` directly.
- Only bottles flow through `HOMEBREW_ARTIFACT_DOMAIN`. Anything `brew` builds
  from source (`--build-from-source`, a formula with no bottle for the
  platform) and cask downloads are fetched from their own upstream URLs.

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
- **Metadata link rewriting.** Galaxy's documents link to the registry itself,
  and `ansible-galaxy` follows those links, so every one of them is **rewritten**
  onto the proxy mount — otherwise it would resolve against the proxy's host
  root (a `404`) or reach Galaxy directly, past the content gates and checksum
  verification. Each link keeps the shape the client expects:
  - a **root-relative** link (`links.next`/`first`/`last` pagination, `href`,
    `versions_url`, `pulp_href`, the v1 `next_link`, …) stays root-relative and
    gains the mount path: `/api/v3/…?limit=100&offset=100` is served as
    `/v1/<name>/api/v3/…?limit=100&offset=100`;
  - an **absolute** upstream URL — in particular a version detail's
    `download_url` — is served as an absolute URL under `server.publicUrl`.

  Only string values that are links into the registry are touched; a
  description, a file path, or a link to another site is served as-is.
- **Set `server.publicUrl`.** Without it the proxy does not know its own
  address, and `download_url` is served root-relative (`/v1/<name>/api/…`) too.
  ansible-core 2.19 and later resolve that against the server URL and install
  normally; ansible-core 2.18 and earlier open `download_url` exactly as served
  and fail with `unknown url type`.
- **Redirects.** Galaxy answers the short `/api/v3/collections/…` paths the
  client requests with a redirect to the canonical
  `/api/v3/plugin/ansible/content/<repo>/collections/index/…` path, and serves a
  tarball through a redirect to its object storage. The proxy follows both
  upstream, so the client sees neither. With `egress.followRedirects: false`
  the proxy relays a redirect that stays inside the registry instead, with its
  `Location` mapped onto the mount. A redirect that leaves the registry, or one
  answering a tarball request, is never relayed — the request fails with `502`
  — so in that mode metadata is served but a collection cannot be downloaded
  from a registry that, like Galaxy, serves its tarballs through a redirect.
- **Roles.** The legacy v1 role API (`/api/v1/roles/…`) is proxied the same
  way, but Galaxy only indexes roles: a role's archive is hosted on GitHub, and
  `ansible-galaxy role install` downloads it from there directly rather than
  through this backend.

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

or name the server on the command line:

```bash
ansible-galaxy collection install community.general:8.0.0 \
  -s https://proxy.example.com/v1/ansible/
```

Both forms take the mount URL with or without its trailing slash. The client
first requests that URL, finds Galaxy's web page rather than an API root, and
falls back to `<url>/api`; give it `https://proxy.example.com/v1/ansible/api/`
to skip that extra round trip. Dependencies are resolved and downloaded through
the proxy as well.

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

To send existing clone URLs, submodules and dependency manifests through the
proxy without editing them, rewrite the forge's base URL once:

```bash
git config --global url."https://proxy.example.com/v1/github/".insteadOf "https://github.com/"
git clone https://github.com/torvalds/linux.git     # fetched through the proxy
```

The proxy speaks the Git **smart-HTTP** protocol, wire protocol v0/v1 and v2
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
| composer  | dist archives (`/dist/<vendor>/<package>/<version>/<ref>.<ext>`) | `packages.json`, `/p2/...` v2 metadata, `/p/...` providers |
| helm      | chart archives (`<name>-<version>.tgz`) + `.prov` provenance (classic); manifests/blobs by digest (OCI) | `index.yaml` (classic); manifests by tag (OCI) |
| docker    | blobs & manifests by digest              | manifests by tag, tag/ping endpoints    |
| conan     | recipe/package files under a pinned revision (`.../revisions/{rrev}/files/...`), MD5-verified via `conanmanifest.txt` (unpacked files) or the upstream `X-Checksum-Md5` header (archives) | `/latest`, `/revisions`, search, `/ping` |
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
