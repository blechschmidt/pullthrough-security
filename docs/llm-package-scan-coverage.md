# LLM scan coverage (generated)

<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with `make llmscan-coverage-gen`.
     Source of truth: internal/scancoverage (catalog_data.go). -->

This is the record of which content the LLM scans examine, per upstream type: the
request paths that carry something a client installs, unpacks or runs, the format
each arrives in, and the serve path it takes — and the documents next to them that
the scan leaves alone. See [llm-package-scan.md](llm-package-scan.md) for how the
gate works.

It is generated from a catalog that is checked against the code on every build:

- every example path below is resolved against the real backend, built the way
  the server builds it, and must be classified and cached exactly as stated;
- every upstream type the configuration accepts must have an entry, so a backend
  added later cannot be left out of the scan without that being a decision;
- every ecosystem scanned by default must have a test that unpacks, ranks and
  judges an artifact in its real format.

## How a request is classified

Each backend states what a resolved request is. The gate acts on that statement,
and on the bytes:

| Class | Meaning | What the gate does |
|---|---|---|
| `payload` | Something a client installs, unpacks, builds, imports or executes. | Always examined. Bytes that do not unpack are reported `unsupported-format` — never read as a harmless file — unless the backend marked the payload as one that may be a single file. |
| `metadata` | An index, a listing, a checksum or signature sidecar. | Left alone once its first bytes have shown it is not a package archive, an executable, a script or a pickle after all: a hostile repository names each package's download path in its own index, so a path that reads as an index proves nothing. |
| `unclassified` | The backend made no statement (a pass-through path). | Judged from its bytes: an archive, an executable, a script or a pickle is examined; so is content named like a package archive; anything else is left alone. |

A compressed response that will not show what it holds is examined under every
class: "cannot tell" is never read as "nothing there".

## Serve paths

| Path to the client | Where the gate sits |
|---|---|
| Cacheable artifact, cache miss | Fetched into the content cache; the gate runs on the cache entry before any byte is written. A refused artifact is evicted. |
| Cacheable artifact, cache hit | The gate runs on every hit as well. Bytes that already have a verdict are answered from the verdict store (no model call); bytes that do not — an entry written before the gate was enabled — are scanned then. |
| Non-cacheable response (a snapshot build, an image manifest by tag, a file on a moving branch, a path the adapter does not know) | The first bytes decide whether there is anything to examine. If there is, the response is held in a spool file until the verdict exists and is served from the spool; a refusal is written before any byte of it. The verdict is stored under the digest of the held bytes. |
| Non-cacheable response larger than `limits.maxArtifactBytes` | Cannot be held whole: reported `oversized`, and `failMode` decides (under fail-open the held prefix and the rest of the stream are served in order). |
| `Range` request | The cached path cuts the range from the entry after the gate has passed; the non-cacheable path ignores `Range` upstream and serves the gated response whole; Git LFS serves ranges after its serve gate. A range is never a way around a verdict or to a slice of an artifact that has none. |
| `HEAD` request | No body is served. On the cached path the gate still runs (the artifact is fetched); on the non-cacheable path nothing is downloaded or scanned. |
| OCI image manifest (by tag or digest) | The image is examined as a whole — config, history, every layer — and the verdict stored under the manifest digest. The manifest response is held until it exists. |
| OCI blob (config or layer) | Refused when a refusing image verdict implicates it (a layer its confirmed evidence cites; its config, unless an image the gate serves has the same config); served without a scan of its own when an image scan read it in full; examined alone otherwise — a layer the image scan's budget did not reach, or one whose manifest was never pulled here — as a root-filesystem layer, under its own digest. |
| Git LFS object | The Git backend's serve gate: every object request — hit or miss, whole or ranged — passes the gate after the object is cached and before a byte is written. A refused object is evicted. |
| Git clone / fetch | Not this gate, and not gated by any other: the Git backend serves smart-HTTP and SSH itself. The LLM commit scan judges the commits of watched repositories and of the commits packages were built from; its verdicts raise findings and gate those packages, but do not refuse a clone or fetch. |
| Cache-federation peer endpoint (a sibling proxy reads this proxy's cache) | Nothing is scanned there; a stored verdict is enforced: an entry whose bytes have a refusing verdict, or that is a blob implicated by a refused image, is answered 403. The receiving proxy runs its own gates on what it is given. |
| Cache miss filled from a sibling proxy | The filled entry is put before this proxy's own gate like one fetched from the upstream. |
| Predictive pre-warm | Drives the same pipeline as a client pull: the gate runs, and a refused artifact is not left in the cache. |
| TLS-intercepted request (forward-proxy mode) | Decrypted, mapped onto the upstream's route and served by the same pipeline as a request sent to the proxy directly: every row of this table applies. A host no upstream is configured for is refused, or — only with `passthroughUnmatched` — tunnelled without being decrypted, which is outside every gate. |
| Air-gap import / restored cache | Entries arrive in the cache without having been pulled; they are gated when served (the cache-hit row). Verdicts travel with the bundle (`pullthrough export` / `import`) and are imported when the bundle's manifest digest was verified out of band, so an air-gapped instance enforces them without reaching a provider. |

## Artifact formats

| Format | Used by | What the model is shown |
|---|---|---|
| tar, plain or under gzip / bzip2 / xz / zstd / lzma | npm, sdist, .crate, Helm, conda .tar.bz2, CRAN, CPAN, Hackage, pub, Conan, Bazel, Julia, Ansible, Puppet, Homebrew bottles, Terraform modules, OCI layers | members; a damaged header is skipped the way lenient extractors skip it |
| zip (also behind a prefix: zipapp, executable jar, self-extractor) | wheel, Go module, .nupkg, jar / war, .vsix, Composer, Terraform provider, Swift, Bazel | members; the bytes in front of a prefixed zip as an entry of their own |
| .gem (tar holding data.tar.gz) | RubyGems | the files of data.tar.gz, metadata, checksums |
| Hex package (tar holding contents.tar.gz) | Hex | the files of contents.tar.gz, metadata.config |
| .conda (zip holding info-*.tar.zst and pkg-*.tar.zst) | conda | the members of both inner archives |
| .deb (ar holding control.tar.* and data.tar.*) | APT | maintainer scripts and control files under `DEBIAN/`, then the data files |
| .rpm (lead, signature, header, compressed cpio payload; RPM 4 and RPM 6) | YUM / DNF | scriptlets and triggers from the header as `RPM/scriptlets/*` and `RPM/triggers/*`, a header summary, then the payload files |
| cpio (newc, crc, odc) and ar | RPM payloads, static libraries | members |
| NAR, plain or compressed | Nix | the store path's files, with their executable bits |
| OCI image (manifest + config + layers) | Docker / OCI, Helm OCI charts, other OCI artifacts | `image/run.txt` (user, entrypoint, command, environment, …), `image/history.txt`, the config and manifest, and every layer's files under `layers/NNN-<digest>/`, top-most layer first |
| single file, plain or compressed | POM, Package.swift, conanfile.py, MODULE.bazel, JSR module files, model repository files, installers, Git LFS objects | the file; for a binary its kind, a strings view and — for a pickle or a safetensors file — a proxy-written summary of what it imports or declares |
| archive inside an archive (two levels) | any | the inner archive's members under `<member>!/` |
| a file that is two archives at once (zip from its end + another format from its start) | any | both readings: the second under `_same-file-read-as-zip!/` or `_same-file-read-as-tar!/` |

An artifact larger than `limits.maxArtifactBytes` follows `llmPackageScan.oversize`:
`fail` (no verdict; `failMode` decides) or `metadata-only` (the inventory and the
scripts within the limit are judged, and the verdict is recorded as partial).

## Coverage by upstream type

| Upstream type | Examined by | Scope key | Payload formats | Serve paths |
|---|---|---|---|---|
| [`ansible`](#ansible-galaxy) | LLM package scan | `ansible` | tar.gz (collection) | cache |
| [`apt`](#apt-debian--ubuntu) / `deb` | LLM package scan | `apt` | .deb (ar: control.tar.*, data.tar.*) | cache |
| [`bazel`](#bazel-bzlmod-registry) | LLM package scan | `bazel` | tar.gz; zip; single file (Starlark); single file (patch); single file (Starlark BUILD or MODULE file) | cache |
| [`cargo`](#cargo-cratesio) | LLM package scan | `cargo` | tar.gz (.crate) | cache |
| [`composer`](#composer-packagist) | LLM package scan | `composer` | zip | cache |
| [`conan`](#conan) | LLM package scan | `conan` | single file (Python recipe); tar.gz | cache |
| [`conda`](#conda) | LLM package scan | `conda` | .conda (zip: info-*.tar.zst, pkg-*.tar.zst); tar.bz2 | cache |
| [`cpan`](#cpan-perl) | LLM package scan | `cpan` | tar.gz; zip | cache |
| [`cran`](#cran-r) | LLM package scan | `cran` | tar.gz (source package); zip (Windows binary); tar.gz (macOS binary) | cache |
| [`dart`](#dart--flutter-pub) / `pub` | LLM package scan | `dart` | tar.gz | cache |
| [`docker`](#docker--oci-registry) | LLM package scan | `docker` | OCI image: manifest + config + layers (tar, gzip/zstd); layer: tar (gzip/zstd/plain); config: JSON | direct; cache |
| [`generic`](#generic-declarative-backend) | LLM package scan | `generic` | whatever the route serves: an archive or a single file; single file (shell script) | cache; direct |
| [`git`](#git-smart-http-and-ssh) | LLM commit scan (examines the commits of watched repositories; refuses no clone or fetch) | — | — | — |
| [`go`](#go-modules-goproxy) | LLM package scan | `go` | zip (module) | cache |
| [`hackage`](#hackage-haskell) | LLM package scan | `hackage` | tar.gz (sdist) | cache |
| [`helm`](#helm) | LLM package scan | `helm` | tar.gz (chart) | cache |
| [`hex`](#hex-elixir--erlang) | LLM package scan | `hex` | Hex package (tar holding contents.tar.gz); single file (.ez Mix archive, a zip); single file (escript) | cache; direct |
| [`homebrew`](#homebrew) | LLM package scan | `homebrew` | tar.gz (bottle) | cache |
| [`huggingface`](#hugging-face-hub) | LLM package scan | `huggingface` | single file (pickle weights); single file (safetensors weights); single file (GGUF weights); single file (Python source); archive (one repository file) | cache; direct |
| [`jsr`](#jsr) | LLM package scan | `jsr` | single file (TypeScript / JavaScript module) | cache |
| [`julia`](#julia-pkg-server) | LLM package scan | `julia` | tar.gz (package source tree); tar.gz (artifact tree) | cache |
| [`maven`](#maven) | LLM package scan | `maven` | zip (jar); single file (POM XML); zip (aar); tar.gz; single file (native executable) | cache; direct |
| [`nix`](#nix-binary-cache) | LLM package scan | `nix` | NAR (xz / zstd); NAR (plain) | cache |
| [`npm`](#npm) | LLM package scan | `npm` | tar.gz | cache |
| [`nuget`](#nuget) | LLM package scan | `nuget` | zip (.nupkg) | cache |
| [`openvsx`](#open-vsx) | LLM package scan | `openvsx` | zip (.vsix) | cache |
| [`pip`](#pypi-pip) | LLM package scan | `pip` | zip (wheel); tar.gz (sdist); zip (sdist); zip (egg); single file (Windows installer) | cache |
| [`puppet`](#puppet-forge) | LLM package scan | `puppet` | tar.gz (module release) | cache |
| [`rubygems`](#rubygems) | LLM package scan | `rubygems` | .gem (tar: metadata.gz, data.tar.gz, checksums.yaml.gz) | cache |
| [`swift`](#swift-package-registry) | LLM package scan | `swift` | zip (source archive); single file (Swift manifest) | cache |
| [`terraform`](#terraform--opentofu-registry) | LLM package scan | `terraform` | zip (provider plugin binary); tar.gz or zip (module source) | cache |
| [`yum`](#yum--dnf-rpm) / `rpm` | LLM package scan | `yum` | .rpm (cpio payload, scriptlets in the header) | cache |

The scope key is what `llmPackageScan.include` / `exclude` name. With `include`
empty every key in this table is scanned.

### Ansible Galaxy

Upstream type `ansible` — examined by the LLM package scan, scope key `ansible`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| collection artifact | `/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz` | `payload` | tar.gz (collection) | cache |
| collection version detail (names the artifact and its SHA-256) | `/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/8.0.0/` | `metadata` | — | direct |
| collection versions list | `/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=100` | `metadata` | — | direct |
| API root | `/api/` | `metadata` | — | direct |
| legacy role metadata | `/api/v1/roles/?owner__username=geerlingguy&name=docker` | `metadata` | — | direct |
| download path of another layout (forwarded as it is) | `/download/community-general-8.0.0.tar.gz` | `unclassified` | tar.gz | direct |

- Only a collection artifact under `…/collections/artifacts/` whose name reads `<namespace>-<name>-<version>.tar.gz` is a payload. Every other well-formed path is forwarded to the registry: a tarball under `artifacts/` whose name does not decompose, a `/download/<file>.tar.gz` of the older layout, the content tree an artifact URL redirects into. Such a path is not cached and is unclassified, so an archive served there is examined from its bytes on the direct path.
- Roles are not covered by this backend: it proxies the legacy role metadata (`/api/v1/roles/`) only. A role's archive is not served here — `ansible-galaxy role install` downloads it from the source repository the metadata names.

### APT (Debian / Ubuntu)

Upstream type `apt` (also `deb`) — examined by the LLM package scan, scope key `apt`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| binary package | `/pool/main/h/hello/hello_2.10-3_amd64.deb` | `payload` | .deb (ar: control.tar.*, data.tar.*) | cache |
| installer package (.udeb; a .ddeb debug package is the same) | `/pool/main/c/cdrom-detect/cdrom-detect_1.89_all.udeb` | `payload` | .deb (ar: control.tar.*, data.tar.*) | cache |
| signed release index | `/dists/bookworm/InRelease` | `metadata` | — | direct |
| detached release signature | `/dists/bookworm/Release.gpg` | `metadata` | — | direct |
| package index | `/dists/bookworm/main/binary-amd64/Packages.xz` | `metadata` | — | direct |
| index addressed by its digest (Acquire-By-Hash) | `/dists/bookworm/main/binary-amd64/by-hash/SHA256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | `metadata` | — | direct |
| translation, source and contents indices | `/dists/bookworm/main/i18n/Translation-en.bz2` | `metadata` | — | direct |
| AppStream icon set | `/dists/bookworm/main/dep11/icons-64x64.tar.gz` | `metadata` (`index-archive`) | tar.gz (icons) | direct |
| source package file (.dsc, .orig.tar.*, .debian.tar.*) | `/pool/main/h/hello/hello_2.10.orig.tar.gz` | `unclassified` | tar.gz | direct |
| installer image kept under dists/ | `/dists/bookworm/main/installer-amd64/current/images/netboot/netboot.tar.gz` | `unclassified` | tar.gz | direct |
| release upgrader (Ubuntu) | `/dists/jammy-updates/main/dist-upgrader-all/current/jammy.tar.gz` | `unclassified` | tar.gz | direct |

- A path ending in `.deb`, `.udeb` or `.ddeb` is a payload wherever in the tree it is served from, including below `dists/`.
- Source packages are outside the layout the backend names: a `.dsc` and the tarballs it lists (`apt-get source`) are served uncached and unclassified, and are examined from their bytes on the direct path.
- `dists/<suite>/` is not an index-only tree. Archives keep installer images, the Ubuntu release upgrader (`dist-upgrader-all/current/<suite>.tar.gz`, which `do-release-upgrade` unpacks and runs) and signed boot loaders there. Only a name the repository format assigns (Release, Packages, Sources, Contents, Translation, dep11, cnf, their diffs and by-hash forms) is metadata; everything else under `dists/` is unclassified and judged from its bytes.
- An AppStream icon set (`dep11/icons-<size>.tar[.gz]`) is metadata that is a tar archive: at that path a tar is what belongs there and is not examined as a package.
- A flat repository keeps its indices outside `dists/` (`/Packages.gz`, `/InRelease`); there they are unclassified.

### Bazel (Bzlmod registry)

Upstream type `bazel` — examined by the LLM package scan, scope key `bazel`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| source archive (the endpoint a rewritten source.json points at) | `/modules/platforms/0.0.10/archive/platforms-0.0.10.tar.gz` | `payload` | tar.gz | cache |
| source archive, zip | `/modules/rules_go/0.50.1/archive/rules_go-v0.50.1.zip` | `payload` | zip | cache |
| module file | `/modules/platforms/0.0.10/MODULE.bazel` | `payload` (`file`) | single file (Starlark) | cache |
| patch applied to the source tree | `/modules/zlib/1.3.1/patches/module_dot_bazel.patch` | `payload` (`file`) | single file (patch) | cache |
| overlay file laid over the source tree | `/modules/zlib/1.3.1.bcr.3/overlay/BUILD.bazel` | `payload` (`file`) | single file (Starlark BUILD or MODULE file) | cache |
| source descriptor (URL and integrity of the archive) | `/modules/platforms/0.0.10/source.json` | `metadata` | — | direct |
| module metadata (version list) | `/modules/platforms/metadata.json` | `metadata` | — | direct |
| registry configuration | `/bazel_registry.json` | `metadata` | — | direct |

- `MODULE.bazel`, patches and overlay files are payloads served as single files: Bazel evaluates the first and applies the others to the source tree it then builds. Each is examined on its own.
- The source archive lives at an external URL; it reaches the proxy only because the served `source.json` has its `url` rewritten to the archive endpoint. That needs an absolute `server.publicUrl`: without one `source.json` is served as the registry wrote it and Bazel downloads the archive from its upstream URL, outside the proxy.
- A `source.json` of type `git_repository` (or `local_path`) has no archive to proxy and is passed through; Bazel then clones the remote itself, which this backend does not mediate.

### Cargo (crates.io)

Upstream type `cargo` — examined by the LLM package scan, scope key `cargo`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| crate download | `/api/v1/crates/serde/1.0.193/download` | `payload` | tar.gz (.crate) | cache |
| registry configuration | `/config.json` | `metadata` | — | direct |
| sparse index file (one line per published version) | `/se/rd/serde` | `metadata` | — | direct |
| registry web API document | `/api/v1/crates/serde/1.0.193/dependencies` | `metadata` | — | direct |

### Composer (Packagist)

Upstream type `composer` — examined by the LLM package scan, scope key `composer`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| dist archive of a tagged release | `/dist/symfony/console/v6.4.1/a550a7c99daeedef3f9d23fb82e3531525ff11fd.zip` | `payload` | zip | cache |
| dist archive of a dev branch | `/dist/symfony/console/6.4.x-dev/0d9e4eb5ad413075624378f474c4167ea202de78.zip` | `payload` | zip | cache |
| repository root | `/packages.json` | `metadata` | — | direct |
| package metadata, releases (Composer 2) | `/p2/symfony/console.json` | `metadata` | — | direct |
| package metadata, dev versions (Composer 2) | `/p2/symfony/console~dev.json` | `metadata` | — | direct |
| legacy provider document (Composer 1) | `/p/symfony/console.json` | `metadata` | — | direct |
| filter-list summary | `/lists/all/summary.json` | `metadata` | — | direct |

- Only dist archives pass through the proxy. A version's `source` (its VCS origin) is served as the upstream lists it, so a source install (`--prefer-source`) clones the repository directly, outside this backend.
- Dist URLs are routed through the proxy only in Composer 2 metadata (`/p2/…`). A legacy provider document (`/p/…`) and package definitions inlined in `packages.json` are passed through unrewritten: a dist they name is downloaded from wherever it points.

### Conan

Upstream type `conan` — examined by the LLM package scan, scope key `conan`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| recipe | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/files/conanfile.py` | `payload` (`file`) | single file (Python recipe) | cache |
| files exported with the recipe | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/files/conan_export.tgz` | `payload` | tar.gz | cache |
| sources the recipe builds from | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/files/conan_sources.tgz` | `payload` | tar.gz | cache |
| binary package | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/packages/b647c43bfefae3f830561ca202b6cfd935b56205/revisions/9a4a5b5e8a8d0a1d3c0e8f2b7a6c5d4e/files/conan_package.tgz` | `payload` | tar.gz | cache |
| integrity manifest of a revision | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/files/conanmanifest.txt` | `metadata` | — | cache |
| settings record of a binary package | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/packages/b647c43bfefae3f830561ca202b6cfd935b56205/revisions/9a4a5b5e8a8d0a1d3c0e8f2b7a6c5d4e/files/conaninfo.txt` | `metadata` | — | cache |
| file list of a revision | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/files` | `metadata` | — | cache |
| latest recipe revision | `/v2/conans/zlib/1.3.1/_/_/latest` | `metadata` | — | direct |
| recipe search | `/v2/conans/search?q=zlib` | `metadata` | — | direct |
| capability probe | `/v1/ping` | `metadata` | — | direct |
| any other file of a revision | `/v2/conans/zlib/1.3.1/_/_/revisions/f52e03ae3d251dec704634230cd806a2/files/metadata/logs/build.log` | `unclassified` | — | cache |

- `conanfile.py` is a payload served as a single file: it is Python the Conan client executes, and it is examined on its own, apart from the archives of the same revision.
- A file download is classified by its base name. A file of a revision that is none of the six names above is cached like the others but unclassified, and is judged from its bytes.

### Conda

Upstream type `conda` — examined by the LLM package scan, scope key `conda`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| package, .conda format | `/linux-64/numpy-1.26.4-py312heda63a1_0.conda` | `payload` | .conda (zip: info-*.tar.zst, pkg-*.tar.zst) | cache |
| package, legacy format | `/noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2` | `payload` | tar.bz2 | cache |
| subdir index | `/linux-64/repodata.json` | `metadata` | — | direct |
| subdir index, compressed | `/linux-64/repodata.json.zst` | `metadata` | — | direct |
| pruned subdir index | `/noarch/current_repodata.json` | `metadata` | — | direct |
| channel summary | `/channeldata.json` | `metadata` | — | direct |

### CPAN (Perl)

Upstream type `cpan` — examined by the LLM package scan, scope key `cpan`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| distribution archive (.tar.gz; .tgz, .tar.bz2 and .tar.xz are the same) | `/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz` | `payload` | tar.gz | cache |
| distribution archive, zip | `/authors/id/E/ET/ETHER/Try-Tiny-0.32.zip` | `payload` | zip | cache |
| per-directory checksum record | `/authors/id/E/ET/ETHER/CHECKSUMS` | `metadata` | — | direct |
| distribution metadata sidecar | `/authors/id/E/ET/ETHER/Try-Tiny-0.32.meta` | `metadata` | — | direct |
| master package index | `/modules/02packages.details.txt.gz` | `metadata` | — | direct |
| author index | `/authors/01mailrc.txt.gz` | `unclassified` | — | direct |
| the same distribution through a by-module view | `/modules/by-module/DBI/DBI-1.643.tar.gz` | `unclassified` | tar.gz | direct |

- A distribution is a payload only in the author tree (`authors/id/…`). The `modules/by-module/`, `by-category/` and `by-authors/` trees are views of the author directories and serve the very same archives: there they are not cached and are unclassified, so they are examined from their bytes on the direct path.
- An archive in a format the backend does not list (`.tar`, `.tar.Z`, `.tar.zst`, a gzipped single module) is likewise uncached and unclassified, in either tree.

### CRAN (R)

Upstream type `cran` — examined by the LLM package scan, scope key `cran`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| source package | `/src/contrib/ggplot2_3.4.4.tar.gz` | `payload` | tar.gz (source package) | cache |
| archived source package | `/src/contrib/Archive/ggplot2/ggplot2_3.4.3.tar.gz` | `payload` | tar.gz (source package) | cache |
| Windows binary package | `/bin/windows/contrib/4.3/ggplot2_3.4.4.zip` | `payload` | zip (Windows binary) | cache |
| macOS binary package | `/bin/macosx/big-sur-arm64/contrib/4.3/ggplot2_3.4.4.tgz` | `payload` | tar.gz (macOS binary) | cache |
| package index | `/src/contrib/PACKAGES` | `metadata` | — | direct |
| package index, compressed | `/src/contrib/PACKAGES.gz` | `metadata` | — | direct |
| package index, R-serialized | `/src/contrib/PACKAGES.rds` | `metadata` | — | direct |

- `PACKAGES.rds` is the index as a serialized R object, which the client deserializes rather than reads as text. It is metadata like the other encodings of the index.

### Dart / Flutter (pub)

Upstream type `dart` (also `pub`) — examined by the LLM package scan, scope key `dart`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| package archive | `/api/archives/path-1.9.0.tar.gz` | `payload` | tar.gz | cache |
| version listing | `/api/packages/path` | `metadata` | — | direct |
| security advisories | `/api/packages/path/advisories` | `metadata` | — | direct |

### Docker / OCI registry

Upstream type `docker` — examined by the LLM package scan, scope key `docker`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| image manifest by tag | `/v2/library/nginx/manifests/1.27` | `payload` (`oci-manifest`) | OCI image: manifest + config + layers (tar, gzip/zstd) | direct |
| image manifest by digest | `/v2/library/nginx/manifests/sha256:ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34` | `payload` (`oci-manifest`) | OCI image: manifest + config + layers (tar, gzip/zstd) | cache |
| blob (image config or layer) | `/v2/library/nginx/blobs/sha256:ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34` | `payload` (`oci-blob`) | layer: tar (gzip/zstd/plain); config: JSON | cache |
| tag list | `/v2/library/nginx/tags/list` | `metadata` | — | direct |
| referrers of a subject digest | `/v2/library/nginx/referrers/sha256:ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34` | `metadata` | — | direct |
| API version check | `/v2/` | `metadata` | — | direct |

- An image is examined as a whole when its manifest is pulled: the image config (entrypoint, command, environment, user, history) and the file inventory and readable content of every layer, top-most layer first. The verdict is stored under the manifest digest.
- Blobs follow the image's verdict: the config and the layers a refusing verdict's confirmed evidence cites are refused; a blob an image scan read in full needs no scan of its own; a blob no image scan read is examined alone when it is pulled, as a root-filesystem layer, under its own digest.
- The image scan's budgets are shared by all layers and spent top-most first, so on a large image the base layers are not reached. Such a layer is not covered by the image's verdict: it is examined on its own when it is pulled, once, however many images share it.
- A config is refused as the config of a refused image, not as a digest: a blob named as config is implicated only if it reads as an image config, and stays served while an image the gate serves has it as its config — so a throwaway image that names another image's config cannot take that image offline.
- A manifest list (image index) names other manifests and is served unexamined; the platform manifest a client selects from it is examined when it is pulled.

### Generic (declarative backend)

Upstream type `generic` — examined by the LLM package scan, scope key `generic`.

Examples assume these routes:

| Route | Match | Cacheable | Rewrite | Gates |
|---|---|---|---|---|
| artifacts | `^/releases/[^/]+/[^/]+\.(tar\.gz\|zip)$` | true | false | `llmPackageScan` |
| installer | `^/install\.sh$` | false | false | `llmPackageScan` |
| index | `^/index/[^/]+\.json$` | false | true | — |
| files | `^/files/.+$` | true | false | — |

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| artifact on a cacheable route that lists the gate | `/releases/v1.4.2/tool-1.4.2-linux-amd64.tar.gz` | `payload` (`file`) | whatever the route serves: an archive or a single file | cache |
| installer on a route that lists the gate but is not cacheable | `/install.sh` | `payload` (`file`) | single file (shell script) | direct |
| index document on a rewrite route | `/index/tool.json` | `metadata` | — | direct |
| file on a cacheable route that does not list the gate | `/files/tool-1.4.2.bin` | `unclassified` | — | cache |

- A generic upstream serves only the paths its routes match — any other path is refused — and the backend knows nothing of the upstream's protocol: the operator's route declaration is the whole classification.
- A route that lists `llmPackageScan` (or the gate's identifier, `llmpkgscan`) in `gates` serves payloads. What it serves is examined whether or not the route is cacheable, as an archive or as the single file it is. A non-cacheable route takes the direct path.
- A `rewrite: true` route that does not list the gate serves metadata. A path on such a route with a `.` or `..` segment is left unclassified, because the upstream resolves it to something other than what the route matched.
- Any other route makes no statement: what it serves is unclassified and judged from its bytes.

### Git (smart HTTP and SSH)

Upstream type `git` — examined by the LLM commit scan (examines the commits of watched repositories; refuses no clone or fetch).

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| ref advertisement, fetch and clone (upload-pack) | `/org/repo.git/info/refs?service=git-upload-pack` | `unclassified` | — | git |
| Git LFS object (examined by the package scan, scope key `git-lfs`) | `/org/repo.git/info/lfs/objects/<oid>` | `unclassified` | — | git-lfs |

- Clones and fetches are not examined by the package scan, and the commit scan is not duplicated there. Commits are the LLM commit scan's (`scanning.*`, internal/scan/commit): it judges the commits of the repositories it watches (`scanning.watch`, by webhook or polling) and the commits packages were built from (found through provenance), stores a verdict per commit, records findings and alerts on a flagged one. Naming `git` in `llmPackageScan.include` has no effect and is reported by preflight.
- What those verdicts gate is the packages built from a commit: the admission policy refuses an artifact whose source commit is flagged. **A clone or fetch itself is not refused by a verdict.** Git smart-HTTP and SSH traffic is served by the Git backend, which owns the connection and runs no admission gate; a repository that is not watched is not scanned at all when it is cloned through the proxy. A commit the scan flagged therefore still reaches a `git clone`; it is the finding, the alert and the refusal of packages built from it that follow.
- What a commit does not contain is the content behind a Git LFS pointer. Those objects are examined by the package scan under the ecosystem key `git-lfs`, when `git.lfs.enabled` is on: every object request — cache hit or miss, whole or ranged — passes the gate before a byte is written. An LFS object is an opaque blob, so it is judged from its bytes: an archive, an executable, a script or a pickle is examined; an image, a video or a dataset is not.

### Go modules (GOPROXY)

Upstream type `go` — examined by the LLM package scan, scope key `go`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| module zip | `/golang.org/x/mod/@v/v0.14.0.zip` | `payload` | zip (module) | cache |
| Go toolchain download (served as a module zip) | `/golang.org/toolchain/@v/v0.0.1-go1.22.0.linux-amd64.zip` | `payload` | zip (module) | cache |
| go.mod of a version | `/golang.org/x/mod/@v/v0.14.0.mod` | `metadata` | — | cache |
| version info | `/golang.org/x/mod/@v/v0.14.0.info` | `metadata` | — | cache |
| version list | `/golang.org/x/mod/@v/list` | `metadata` | — | direct |
| latest version | `/golang.org/x/mod/@latest` | `metadata` | — | direct |
| checksum database lookup | `/sumdb/sum.golang.org/lookup/golang.org/x/mod@v0.14.0` | `metadata` | — | direct |
| checksum database tile | `/sumdb/sum.golang.org/tile/8/0/x277/878` | `metadata` | — | direct |
| checksum database probe (answered by the proxy) | `/sumdb/sum.golang.org/supported` | `metadata` | — | direct |

### Hackage (Haskell)

Upstream type `hackage` — examined by the LLM package scan, scope key `hackage`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| source distribution | `/package/text-2.1/text-2.1.tar.gz` | `payload` | tar.gz (sdist) | cache |
| source distribution, short path form | `/package/text-2.1.tar.gz` | `payload` | tar.gz (sdist) | cache |
| package index | `/01-index.tar.gz` | `metadata` (`index-archive`) | tar.gz (.cabal files and target metadata) | direct |
| TUF security metadata | `/timestamp.json` | `metadata` | — | direct |
| target metadata of a package (names the sdist's SHA-256) | `/package/text-2.1/package.json` | `metadata` | — | direct |
| package description | `/package/text-2.1/text.cabal` | `metadata` | — | direct |

- The package index (`01-index.tar[.gz]`) is metadata that is a tar archive, served uncached: at that path a tar is what belongs there and is not examined as a package. It holds every package's `.cabal` description, including revisions published after the sdist — the description cabal plans a build from — so a `.cabal` file is examined only as part of the sdist that also carries it.

### Helm

Upstream type `helm` — examined by the LLM package scan, scope key `helm`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| chart archive, index-resolved (the link a rewritten index.yaml hands out) | `/-/nginx/15.4.4/nginx-15.4.4.tgz` | `payload` | tar.gz (chart) | cache |
| chart archive, repository-relative | `/charts/nginx-15.4.4.tgz` | `payload` | tar.gz (chart) | cache |
| provenance file, index-resolved | `/-/nginx/15.4.4/nginx-15.4.4.tgz.prov` | `metadata` | — | cache |
| provenance file, repository-relative | `/charts/nginx-15.4.4.tgz.prov` | `metadata` | — | cache |
| repository index | `/index.yaml` | `metadata` | — | direct |

- These are the paths of the classic chart-repository protocol. With the upstream setting `oci: true` the backend is a front for the Docker / OCI registry backend instead and serves none of them: a chart is then pulled as an OCI artifact (`/v2/<name>/manifests/<reference>`, `/v2/<name>/blobs/<digest>`) and is classified, cached and examined exactly as in the Docker / OCI registry entry, still under the scope key `helm`.
- An index-resolved archive is fetched from whatever location the repository index lists for that chart version — another host, or an `oci://` registry — and is the same payload, cached under the same key, wherever it came from.

### Hex (Elixir / Erlang)

Upstream type `hex` — examined by the LLM package scan, scope key `hex`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| release tarball | `/tarballs/jason-1.4.1.tar` | `payload` | Hex package (tar holding contents.tar.gz) | cache |
| Hex build installed by `mix local.hex` | `/installs/1.16.0/hex-2.0.6.ez` | `payload` (`file`) | single file (.ez Mix archive, a zip) | direct |
| Rebar3 build installed by `mix local.rebar` | `/installs/1.16.0/rebar3-3.22.0` | `payload` (`file`) | single file (escript) | direct |
| package releases (signed registry resource) | `/packages/jason` | `metadata` | — | direct |
| all package names / versions (signed registry resources) | `/versions` | `metadata` | — | direct |
| builds list of the installs tree | `/installs/hex-1.x.csv` | `metadata` | — | direct |
| signature of a builds list | `/installs/hex-1.x.csv.signed` | `metadata` | — | direct |

- The Hex and Rebar builds under `/installs/<elixir>/` are payloads that are never cached: a build is installed and then run by Mix, is served live on every request, and so takes the direct path each time. Each is examined as a single file.

### Homebrew

Upstream type `homebrew` — examined by the LLM package scan, scope key `homebrew`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| bottle, registry-native path (what brew requests with HOMEBREW_ARTIFACT_DOMAIN) | `/v2/homebrew/core/hello/blobs/sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | `payload` | tar.gz (bottle) | cache |
| bottle, proxy endpoint a rewritten formula document points at | `/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | `payload` | tar.gz (bottle) | cache |
| bottle image index | `/v2/homebrew/core/hello/manifests/2.12.1` | `metadata` | — | direct |
| signed formula index | `/api/formula.jws.json` | `metadata` | — | direct |
| formula document | `/api/formula/wget.json` | `metadata` | — | direct |
| signed cask index | `/api/cask.jws.json` | `metadata` | — | direct |
| API path that is not a JSON document (forwarded as it is) | `/api/cask-source/firefox.rb` | `unclassified` | — | direct |

- Only bottles are payloads here. Formula and cask documents are metadata and are served as documents: the proxy routes bottle downloads through itself and nothing else those documents name. A cask's installer and the source archive of a formula built from source are downloaded by brew from the URLs the documents give, outside the proxy.
- A bottle is an OCI blob without a file name; its format is identified from its bytes.
- Any `/api/…` path is forwarded. One that does not name a JSON document in plain path segments — a Ruby cask or formula source, a script, an archive — is unclassified and judged from its bytes.

### Hugging Face Hub

Upstream type `huggingface` — examined by the LLM package scan, scope key `huggingface`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| pickle weight file on a branch | `/bert-base-uncased/resolve/main/pytorch_model.bin` | `payload` (`file`) | single file (pickle weights) | cache |
| safetensors weight file on a branch | `/bert-base-uncased/resolve/main/model.safetensors` | `payload` (`file`) | single file (safetensors weights) | cache |
| GGUF weight file pinned to a commit | `/TheBloke/Llama-2-7B-GGUF/resolve/0123456789abcdef0123456789abcdef01234567/llama-2-7b.Q4_K_M.gguf` | `payload` (`file`) | single file (GGUF weights) | cache |
| custom model code on a branch | `/microsoft/phi-2/resolve/main/modeling_phi.py` | `payload` (`file`) | single file (Python source) | direct |
| custom model code pinned to a commit | `/microsoft/phi-2/resolve/0123456789abcdef0123456789abcdef01234567/modeling_phi.py` | `payload` (`file`) | single file (Python source) | cache |
| dataset loading script on a branch | `/datasets/squad/resolve/main/squad.py` | `payload` (`file`) | single file (Python source) | direct |
| Space application on a branch | `/spaces/gradio/hello_world/resolve/main/app.py` | `payload` (`file`) | single file (Python source) | direct |
| archive committed to a repository, on a branch | `/org/model/resolve/main/bundle.tar.gz` | `payload` (`file`) | archive (one repository file) | direct |
| repository info | `/api/models/bert-base-uncased` | `metadata` | — | direct |
| repository info at a revision | `/api/models/bert-base-uncased/revision/main` | `metadata` | — | direct |
| any other repository file, on a branch | `/bert-base-uncased/resolve/main/config.json` | `unclassified` | — | direct |
| any other repository file, pinned to a commit | `/bert-base-uncased/resolve/0123456789abcdef0123456789abcdef01234567/config.json` | `unclassified` | — | cache |
| any other API path | `/api/models/bert-base-uncased/tree/main` | `unclassified` | — | direct |

- A repository serves its files one by one, so every payload is examined as a single file, on its own: a weight file, a script, an archive someone committed.
- A file is a payload by its name: a weight format (`.bin`, `.pt`, `.pth`, `.ckpt`, `.pkl`, `.safetensors`, `.gguf`, `.onnx`, `.h5`, …) or a code-bearing or archive extension (`.py`, `.ipynb`, `.sh`, `.js`, `.so`, `.keras`, `.joblib`, `.zip`, `.tar.gz`, `.whl`, …). Any other repository file — a JSON config, a tokenizer, a README, a Parquet shard — is unclassified and judged from its bytes, as is every `/api/…` path other than a repository-info document.
- A weight file is cached at any revision. Every other file is cached only when the revision is a 40-hex commit: code or an archive requested at a branch or a tag (`resolve/main/…`) is not cached and takes the direct path on every request.

### JSR

Upstream type `jsr` — examined by the LLM package scan, scope key `jsr`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| module file of a published version | `/@std/path/1.0.8/mod.ts` | `payload` (`file`) | single file (TypeScript / JavaScript module) | cache |
| module file in a subdirectory | `/@std/path/1.0.8/posix/join.ts` | `payload` (`file`) | single file (TypeScript / JavaScript module) | cache |
| version metadata (file manifest with SHA-256 digests) | `/@std/path/1.0.8_meta.json` | `metadata` | — | direct |
| package metadata (version list) | `/@std/path/meta.json` | `metadata` | — | direct |

- JSR serves a package one module file at a time; there is no archive. Every file below a version directory is a payload, whatever its name, and is examined as a single file — each on its own, without the rest of the package next to it.

### Julia (Pkg server)

Upstream type `julia` — examined by the LLM package scan, scope key `julia`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| package source tarball | `/package/7876af07-990d-54b4-ab0e-23690620f79a/46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc` | `payload` | tar.gz (package source tree) | cache |
| artifact tarball (commonly prebuilt binaries) | `/artifact/46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc` | `payload` | tar.gz (artifact tree) | cache |
| registry tarball | `/registry/23338594-aafe-5451-b93e-139f81909106/46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc` | `metadata` (`index-archive`) | tar.gz (TOML index files) | cache |
| registries listing | `/registries` | `metadata` | — | direct |

- A registry tarball is metadata that is a tar archive of TOML index files: at that path a tar is what belongs there and is not examined as a package. It is cached like the package and artifact tarballs.
- A Pkg server resource has no file name (its URL ends in a tree hash); the format is identified from the bytes.

### Maven

Upstream type `maven` — examined by the LLM package scan, scope key `maven`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| release jar | `/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar` | `payload` | zip (jar) | cache |
| release POM | `/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom` | `payload` (`file`) | single file (POM XML) | cache |
| other zip packaging (war, ear, aar, hpi, …) | `/androidx/core/core/1.12.0/core-1.12.0.aar` | `payload` | zip (aar) | cache |
| tarball distribution | `/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.tar.gz` | `payload` | tar.gz | cache |
| native executable or library (.exe, .so, .dll, .dylib) | `/com/google/protobuf/protoc/3.25.1/protoc-3.25.1-linux-x86_64.exe` | `payload` | single file (native executable) | cache |
| snapshot jar, timestamped build | `/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7.jar` | `payload` | zip (jar) | cache |
| snapshot jar, not timestamped | `/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar` | `payload` | zip (jar) | direct |
| snapshot POM, not timestamped | `/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.pom` | `payload` (`file`) | single file (POM XML) | direct |
| checksum sidecar | `/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1` | `metadata` | — | cache |
| signature sidecar | `/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.asc` | `metadata` | — | cache |
| Gradle module metadata | `/com/google/guava/guava/31.1-jre/guava-31.1-jre.module` | `metadata` | — | cache |
| version listing | `/com/google/guava/guava/maven-metadata.xml` | `metadata` | — | direct |
| snapshot build listing | `/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml` | `metadata` | — | direct |
| artifact with an extension the backend does not name | `/com/example/lib/1.0/lib-1.0-cyclonedx.json` | `unclassified` | — | cache |

- A `-SNAPSHOT` artifact whose file name is not a timestamped build is never cached: a jar, a POM or any other payload of that kind is revalidated on every request and takes the direct path each time. A timestamped snapshot build and every release artifact are cached.
- A POM is a payload served as a single file: a parent or a BOM is the whole artifact, and it is examined on its own.
- A native executable or library published as an artifact is a payload and is examined as the single file it is.
- A primary artifact with an extension the backend does not name (`.txt`, `.json`, `.xml`, `.sh`, a `.module` other than the component's own Gradle module metadata) is unclassified and judged from its bytes. A path outside the repository layout is refused, not forwarded.

### Nix binary cache

Upstream type `nix` — examined by the LLM package scan, scope key `nix`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| NAR, xz-compressed | `/nar/1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar.xz` | `payload` | NAR (xz / zstd) | cache |
| NAR, zstd-compressed | `/nar/1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar.zst` | `payload` | NAR (xz / zstd) | cache |
| NAR, uncompressed | `/nar/1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar` | `payload` | NAR (plain) | cache |
| narinfo (signed description of a store path) | `/n5glp21rsz314qssw9fbvfswgy3kc68f.narinfo` | `metadata` | — | direct |
| cache descriptor | `/nix-cache-info` | `metadata` | — | direct |

- A NAR is a payload under every compression suffix the backend serves (`.xz`, `.zst`, `.zstd`, `.bz2`, `.gz`, `.br`, `.lzip`, none). The unpacker opens gzip, bzip2, xz, zstd and lzma: a NAR under brotli or lzip is not waved through but reported `unsupported-format`, and `failMode` decides.
- A NAR reaches the proxy because the served narinfo has its `URL` rewritten to the proxy. That field is the one a narinfo's signature does not cover, and Nix fetches an absolute `http(s)://` or `file://` URL there as it stands. A narinfo whose NAR location cannot be routed through the proxy and would send the client to another host is therefore refused rather than served; a relative location outside `nar/` is passed on, and the path it names is one the backend does not serve.

### npm

Upstream type `npm` — examined by the LLM package scan, scope key `npm`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| package tarball | `/left-pad/-/left-pad-1.3.0.tgz` | `payload` | tar.gz | cache |
| scoped package tarball | `/@scope/pkg/-/pkg-1.0.0.tgz` | `payload` | tar.gz | cache |
| packument (package metadata) | `/left-pad` | `metadata` | — | direct |

### NuGet

Upstream type `nuget` — examined by the LLM package scan, scope key `nuget`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| package | `/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg` | `payload` | zip (.nupkg) | cache |
| service index | `/v3/index.json` | `metadata` | — | direct |
| version list of a package | `/v3-flatcontainer/newtonsoft.json/index.json` | `metadata` | — | direct |
| registration index | `/v3/registration5-gz-semver2/newtonsoft.json/index.json` | `metadata` | — | direct |
| registration page | `/v3/registration5-gz-semver2/newtonsoft.json/page/1.0.0/13.0.3.json` | `metadata` | — | direct |
| package manifest | `/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec` | `metadata` | — | direct |
| symbol package | `/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.snupkg` | `unclassified` | zip (.snupkg) | direct |
| package download whose URL does not end in .nupkg (v2 feed) | `/api/v2/package/Newtonsoft.Json/13.0.3` | `unclassified` | zip (.nupkg) | direct |

- Only a path ending in `.nupkg` is a payload, and only such a path is cached. A feed that serves a package from another URL — the v2 download `/api/v2/package/<id>/<version>`, a registration `packageContent` that ends in the id or the version — has it forwarded uncached and unclassified: the package is then examined from its bytes on the direct path. A symbol package (`.snupkg`) is handled the same way.

### Open VSX

Upstream type `openvsx` — examined by the LLM package scan, scope key `openvsx`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| extension archive | `/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.vsix` | `payload` | zip (.vsix) | cache |
| extension archive for a target platform | `/api/ms-vscode/cpptools/linux-x64/1.0.0/file/ms-vscode.cpptools-linux-x64-1.0.0.vsix` | `payload` | zip (.vsix) | cache |
| the same archive as a VS Code gallery asset | `/vscode/asset/dracula-theme/theme-dracula/2.25.1/Microsoft.VisualStudio.Services.VSIXPackage` | `unclassified` | zip (.vsix) | direct |
| version metadata | `/api/dracula-theme/theme-dracula/2.25.1` | `unclassified` | — | direct |
| query | `/api/-/query?extensionId=dracula-theme.theme-dracula` | `unclassified` | — | direct |
| checksum sidecar of an archive | `/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.sha256` | `unclassified` | — | direct |
| VS Code gallery query | `/vscode/gallery/extensionquery` | `unclassified` | — | direct |

- This backend classifies nothing as metadata. It forwards the whole `/api` and `/vscode` trees rather than a list of known documents, and those trees serve the extension under other names too. Everything but the one archive form above is therefore unclassified and judged from its bytes; a JSON document is left alone on that evidence, not on its path.
- The VS Code gallery protocol downloads the extension as the asset `…/Microsoft.VisualStudio.Services.VSIXPackage`. That path is not cached and is unclassified: the archive is examined from its bytes on the direct path.

### PyPI (pip)

Upstream type `pip` — examined by the LLM package scan, scope key `pip`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| wheel | `/files/https/files.pythonhosted.org/packages/70/8e/0e2d847013cb52cd35b38c009bb167a1a26b2ce6cd6965bf26b47bc0bf44/requests-2.31.0-py3-none-any.whl` | `payload` | zip (wheel) | cache |
| sdist | `/files/https/files.pythonhosted.org/packages/9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3/requests-2.31.0.tar.gz` | `payload` | tar.gz (sdist) | cache |
| legacy sdist (.zip; .tar.bz2, .tar.xz, .tar and .tgz are the same) | `/files/https/files.pythonhosted.org/packages/51/60/3f0fe5b7675a461d96b9d6729beecd3532565743278a9c3fe6dd09697fa7/numpy-1.19.5.zip` | `payload` | zip (sdist) | cache |
| egg | `/files/https/files.pythonhosted.org/packages/ab/cd/0123abcd/pkg-1.0-py3.11.egg` | `payload` | zip (egg) | cache |
| legacy Windows installer (.exe, .msi) | `/files/https/files.pythonhosted.org/packages/ab/cd/0123abcd/pkg-1.0.win32.exe` | `payload` (`file`) | single file (Windows installer) | cache |
| core-metadata sidecar of a distribution (PEP 658) | `/files/https/files.pythonhosted.org/packages/70/8e/0e2d847013cb52cd35b38c009bb167a1a26b2ce6cd6965bf26b47bc0bf44/requests-2.31.0-py3-none-any.whl.metadata` | `metadata` | — | cache |
| project page (Simple API) | `/simple/requests/` | `metadata` | — | direct |
| project JSON document | `/pypi/requests/json` | `metadata` | — | direct |
| provenance of a file (Integrity API, PEP 740) | `/integrity/requests/2.31.0/requests-2.31.0-py3-none-any.whl/provenance` | `metadata` | — | direct |
| distribution an index links relatively, below its project page | `/simple/requests/requests-2.31.0.tar.gz` | `unclassified` | tar.gz (sdist) | direct |
| distribution served from the index host itself | `/packages/9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3/requests-2.31.0.tar.gz` | `unclassified` | tar.gz (sdist) | direct |

- A distribution is a payload, and cached, on the files route (`/files/<scheme>/<host>/…`). A client is sent there only for a file the index page links by an absolute URL on an allowlisted file host (`filesUrl`, `fileHosts`), which the proxy rewrites. An index that links its files relatively or serves them from its own host (a static index, a repository manager) has pip fetch them from a path below the index: that path is forwarded uncached and unclassified, and the distribution is examined from its bytes on the direct path.
- A legacy Windows installer (`.exe`, `.msi`) is a payload served as a single file.
- A sidecar of a distribution (`.metadata`, `.asc`, `.sig`, `.provenance`, `.attestation`) is metadata only on an allowlisted file host; it is cached like the file it belongs to.

### Puppet Forge

Upstream type `puppet` — examined by the LLM package scan, scope key `puppet`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| module release tarball | `/v3/files/puppetlabs-stdlib-9.4.1.tar.gz` | `payload` | tar.gz (module release) | cache |
| release metadata (names the file and its checksums) | `/v3/releases/puppetlabs-stdlib-9.4.1` | `metadata` | — | direct |
| module metadata | `/v3/modules/puppetlabs-stdlib` | `metadata` | — | direct |
| release listing | `/v3/releases?module=puppetlabs-stdlib` | `metadata` | — | direct |
| file under /v3/files/ whose name is not a release (forwarded as it is) | `/v3/files/puppetlabs-stdlib.tar.gz` | `unclassified` | tar.gz | direct |

- Only `/v3/files/<owner>-<name>-<version>.tar.gz` is a payload. Every other well-formed path is forwarded to the Forge: a file under `/v3/files/` whose name does not decompose into a release, and anything outside the `modules`, `releases`, `users` and `search` collections, is not cached and is unclassified, so an archive served there is examined from its bytes on the direct path.

### RubyGems

Upstream type `rubygems` — examined by the LLM package scan, scope key `rubygems`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| gem | `/gems/rails-7.0.4.gem` | `payload` | .gem (tar: metadata.gz, data.tar.gz, checksums.yaml.gz) | cache |
| platform gem (precompiled native extension) | `/gems/nokogiri-1.13.0-x86_64-linux.gem` | `payload` | .gem (tar: metadata.gz, data.tar.gz, checksums.yaml.gz) | cache |
| compact index, versions and checksums of a gem | `/info/rails` | `metadata` | — | direct |
| compact index, all gems | `/versions` | `metadata` | — | direct |
| legacy spec index (Marshal) | `/specs.4.8.gz` | `metadata` | — | direct |
| legacy gemspec of a version (Marshal) | `/quick/Marshal.4.8/rails-7.0.4.gemspec.rz` | `metadata` | — | cache |
| legacy dependency API (Marshal) | `/api/v1/dependencies?gems=rails` | `metadata` | — | direct |

- The legacy documents (`specs.4.8.gz` and its siblings, `quick/Marshal.4.8/<gem>.gemspec.rz`, `/api/v1/dependencies`) are Ruby Marshal data, which a client deserializes rather than reads as text. They are metadata like the compact index.
- The grammar is closed: a path that is none of the above is refused, not forwarded.

### Swift package registry

Upstream type `swift` — examined by the LLM package scan, scope key `swift`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| source archive | `/mona/LinkedList/1.1.1.zip` | `payload` | zip (source archive) | cache |
| package manifest | `/mona/LinkedList/1.1.1/Package.swift` | `payload` (`file`) | single file (Swift manifest) | cache |
| package manifest for a tools version | `/mona/LinkedList/1.1.1/Package.swift?swift-version=5.3` | `payload` (`file`) | single file (Swift manifest) | cache |
| release metadata (names the archive's checksum) | `/mona/LinkedList/1.1.1` | `metadata` | — | cache |
| release list | `/mona/LinkedList` | `metadata` | — | direct |
| identifier lookup by repository URL | `/identifiers?url=https://github.com/mona/LinkedList` | `metadata` | — | direct |
| third segment that is not positively a version | `/mona/LinkedList/1.1.1.ZIP` | `unclassified` | — | cache |

- `Package.swift` (and a `Package@swift-<version>.swift` variant) is a payload served as a single file: it is a Swift program that SwiftPM compiles and runs during dependency resolution, before it downloads the archive. It is examined on its own.
- Release metadata is metadata only where the third path segment is positively a semantic version. Any other segment there (`1.1.1.ZIP`, `latest`) is unclassified, because a registry may answer it with the archive.

### Terraform / OpenTofu registry

Upstream type `terraform` — examined by the LLM package scan, scope key `terraform`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| provider package (the endpoint a rewritten package descriptor points at) | `/v1/providers/hashicorp/aws/5.31.0/download/linux/amd64/zip` | `payload` | zip (provider plugin binary) | cache |
| module source archive (the endpoint a rewritten X-Terraform-Get points at) | `/v1/modules/terraform-aws-modules/vpc/aws/5.5.0/archive` | `payload` | tar.gz or zip (module source) | cache |
| provider SHASUMS manifest | `/v1/providers/hashicorp/aws/5.31.0/download/linux/amd64/shasums` | `metadata` | — | cache |
| provider SHASUMS signature | `/v1/providers/hashicorp/aws/5.31.0/download/linux/amd64/shasums.sig` | `metadata` | — | cache |
| provider package descriptor | `/v1/providers/hashicorp/aws/5.31.0/download/linux/amd64` | `metadata` | — | direct |
| provider version list | `/v1/providers/hashicorp/aws/versions` | `metadata` | — | direct |
| module download endpoint (empty body, X-Terraform-Get header) | `/v1/modules/terraform-aws-modules/vpc/aws/5.5.0/download` | `metadata` | — | direct |
| module version list | `/v1/modules/terraform-aws-modules/vpc/aws/versions` | `metadata` | — | direct |
| service discovery (answered by the proxy) | `/.well-known/terraform.json` | `metadata` | — | direct |
| module archive a registry locates relatively (forwarded as it is) | `/v1/modules/acme/vpc/aws/1.2.0/source.tgz` | `unclassified` | tar.gz | direct |

- Both payloads reach the proxy only through rewriting: the provider package descriptor's download URL and the module download endpoint's `X-Terraform-Get` are pointed at the two endpoints above. That needs an absolute `server.publicUrl`: without one both are served as the registry wrote them and the client downloads the provider or the module from its upstream location, outside the proxy.
- A module is brought through the proxy only when its source is a plain HTTP(S) archive. An `X-Terraform-Get` that names another getter (`git::…`, `s3::…`, …) is forwarded unchanged, as is the version-less `…/download` endpoint: the client then fetches the module itself, and this backend never sees it.
- A registry may give an archive's location relative to the endpoint that announces it. The client then requests it from a path under `/v1/modules/` or `/v1/providers/` that the protocol does not name: such a path is forwarded uncached and unclassified, and the archive is examined from its bytes on the direct path.
- The module archive endpoint has no file name and serves whatever the module's source URL produced; its format is identified from the bytes.

### YUM / DNF (RPM)

Upstream type `yum` (also `rpm`) — examined by the LLM package scan, scope key `yum`.

| Request | Example path | Class | Format | Serve path |
|---|---|---|---|---|
| binary package | `/Packages/h/hello-2.12.1-2.fc40.x86_64.rpm` | `payload` | .rpm (cpio payload, scriptlets in the header) | cache |
| source package | `/SRPMS/hello-2.12.1-2.fc40.src.rpm` | `payload` | .rpm (cpio payload, scriptlets in the header) | cache |
| repository metadata manifest | `/repodata/repomd.xml` | `metadata` | — | direct |
| manifest signature | `/repodata/repomd.xml.asc` | `metadata` | — | direct |
| package list | `/repodata/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-primary.xml.gz` | `metadata` | — | direct |
| delta RPM | `/drpms/hello-2.12.1-1.fc40_2.12.1-2.fc40.x86_64.drpm` | `unclassified` | delta RPM | direct |
| boot or installer image | `/images/pxeboot/vmlinuz` | `unclassified` | — | direct |

- A path ending in `.rpm` is a payload wherever in the tree it is served from, including inside `repodata/`.
- Every other file in the repository's top-level `repodata/` directory is metadata, whatever its name: the names there are free-form. The same names below another directory (`/os/repodata/…`) are outside the layout.
- Paths outside the layout — delta RPMs, boot and installer images, `.treeinfo`, signing keys — are served uncached and unclassified, and are examined from their bytes on the direct path.

