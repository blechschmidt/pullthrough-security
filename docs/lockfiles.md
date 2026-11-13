# Lock files: the exact dependencies of a repository

The lock-file scanner (`internal/lockfiles`, Tasks 178 and 179) reads a Git repository at a
commit, finds every lock file in it and turns each into the exact dependencies it pins — for
every upstream type the proxy fronts that has a lock-file format, from `package-lock.json` to
`flake.lock`, plus the repository's own submodules. It is the groundwork for what follows it:
pinning a release's artifacts, scanning every dependency of a repository, and proposing safe
updates. Today it is available as a library and as `ptctl lockfiles scan`.

```console
$ ptctl lockfiles scan https://github.com/BurntSushi/ripgrep --rev 14.1.0
fetching https://github.com/BurntSushi/ripgrep at 14.1.0 …
Repository https://github.com/BurntSushi/ripgrep, commit e50df40a1967708b9781486b1c017e48040bceb0

LOCATION        TYPE   NAME                          VERSION              FROM                                          DIGEST
Cargo.lock:5    cargo  aho-corasick                  1.1.2                https://github.com/rust-lang/crates.io-index  sha256:b2969dcb958b366…
Cargo.lock:14   cargo  anyhow                        1.0.79               https://github.com/rust-lang/crates.io-index  sha256:080e9890a082662…
Cargo.lock:20   cargo  autocfg                       1.1.0                https://github.com/rust-lang/crates.io-index  sha256:d468802bab17cbc…
…
47 dependencies in 1 lock files.

Not read:
  tests/data/: matches a skip glob
```

## What a dependency records

| Field | Meaning |
| ----- | ------- |
| `type` | The upstream type it is fetched through — one of the configuration's upstream types (`npm`, `pip`, `cargo`, … `terraform`, `git`). Usually the lock file's own type; a lock file can record dependencies of other types (conda-lock's PyPI packages are `pip`, deno.lock's npm packages `npm`, its remote modules `generic`). |
| `name` | The package name, spelled as the proxy's backend names it: as written for npm, Cargo, Go, Composer and RubyGems; PEP 503-normalised for pip (`charset-normalizer`); lower-cased for NuGet; `group:artifact` for Maven; the repository path for Docker (`library/alpine`); `namespace/name` for Terraform providers and `namespace/name/system` for its modules; `scope.name` for a Swift registry package, the identity for a source-control one; `owner-name` for Puppet; `namespace.name` for Ansible; the flake reference for a Nix input (`github:NixOS/nixpkgs`); the path of a submodule. |
| `version` | The exact version, as the lock file writes it. A RubyGems platform gem keeps its platform (`1.16.7-x86_64-linux`, a separate artifact); a Docker image's version is its manifest digest; a Git dependency without a package version gets its commit; a download known only by its URL (a deno.lock remote module, a Nix tarball input, an r10k tarball module) is versioned by its content hash (`sha256:…`). |
| `id` | What the ecosystem identifies the package by when its name and version do not say it all: a Julia package's UUID, a Conan reference's user and channel (`zlib/1.3.1@acme/stable`), a CPAN distribution's path under `authors/id/` (what a client fetches). |
| `digests` | The integrity values the lock file records, normalised to `algorithm` + lower-case hex (`h1` for Go modules and Terraform providers keeps its base64). `of` says what was hashed when it is not simply the artifact the registry serves — see [What a digest is of](#what-a-digest-is-of). |
| `registry` | Where the lock file says the dependency comes from: the registry or index URL, or the repository URL of a Git dependency. Empty when the lock file does not say (pnpm, Yarn Berry, poetry for PyPI, go.mod, NuGet, Gradle); the client's configured default then applies. |
| `url` | The download URL the lock file records, when it records one. |
| `upstream` | The proxy upstream the lock file's URLs point at, when it was resolved through this proxy (see below). |
| `source` | `""` (a registry), `git` (a repository; `revision` is the commit) or `url` (a direct download). |
| `revision` | The commit a Git dependency is pinned to; Composer records one for every package. |
| `dev` | Development-only, where the format says so (package-lock.json, pnpm v5/v6, Pipfile.lock, poetry, pdm, composer.lock, Gradle test configurations, Maven `test` scope, conda-lock's `dev` category, pubspec.lock's `direct dev`). |
| `unverified`, `unverifiedReason` | Set when nothing the lock file records pins the dependency's content: no digest of the artifact (or of a manifest that hashes it) and, for a Git dependency, no commit. The reason says why — the format records no digest at all (renv.lock, a Puppetfile, Chart.lock), this entry has none (a requirement without `--hash`), or only a document next to the artifact is hashed (a Conan 2 recipe, not its binary). Later stages must treat such a dependency as unverified: its version names an artifact, but nothing in the lock file checks the bytes served for it. No digest is ever made up. |
| `file`, `line` | The lock file's path in the repository and the line the entry starts on. |

Every URL is stored without its credentials, query string and fragment. Entries a format
lists more than once (one package version at several places in `node_modules`, or under
several NuGet target frameworks) are one dependency.

<!-- BEGIN GENERATED: lock-file formats. Regenerate with `make lockfile-reference-gen`; source: internal/lockfiles (formats.go, coverage.go). -->

## Formats

Every format the scanner reads, by upstream type. **Digests** says how far the format's entries
carry a digest — `all`, `some` (an entry or an older file may lack one) or `none` — and what
it is a hash of. A dependency nothing in its lock file pins — no digest of the artifact (or
of a manifest that hashes it) and, for a Git dependency, no commit — is marked
`"unverified": true` with the reason quoted below; later stages treat it as unverified.
No digest is ever made up.

| Type | Format | Read | Digests | Limits |
|---|---|---|---|---|
| `ansible` | `requirements.yml`, `requirements.yaml` — only those that yield something are reported (Helm 2 charts use the name too) | Collections and roles pinned to one version (`8.6.0`, `==8.6.0`), in the `collections:`/`roles:` layout and the older top-level list of roles (`src`, `name`, `role`); Git sources (`type: git` — a `,ref` after the URL wins over `version`, as ansible-galaxy reads it; `scm: git`; `git+`; a GitHub http URL) and URL archives. Ansible has no lock file: a requirements file is the only place versions are pinned. | **none** An entry without one is unverified: *requirements.yml records no hash (Galaxy publishes the artifact's SHA-256, the requirements file does not)*. | Every Galaxy entry is unverified, and a Git source pinned to a tag. A range, `*` or no version is a warning; local sources are left out. |
| `bazel` | `MODULE.bazel.lock` | lockFileVersion 11 and later (Bazel 7.2+): every module version whose `source.json` is in `registryFileHashes` — the versions selected; the others were read for version selection only. Versions up to 10 (Bazel 6 to 7.1): `moduleDepGraph`, each module's archive URL and integrity. A section of the other layout, which that Bazel would not read, is refused; a key given twice in a map too (Bazel's Gson refuses it). Yanked versions selected all the same are a warning. | **all** — 13+: the SHA-256 of the module's `source.json` in the registry (`of: source.json`), which names the archive and its integrity, and of its `MODULE.bazel` (`of: MODULE.bazel`, which pins only the declaration). Up to 6: the archive's Subresource Integrity. | The repositories module extensions generate (`moduleExtensions`) are not read. The lock file does not record dev dependencies. Built-in modules (`bazel_tools`) are not in it, nor, in version 13 and later, modules overridden to a Git repository or a local path. |
| `cargo` | `Cargo.lock` | Format v1 (checksums in `[metadata]`) to v4; `registry+`, `sparse+` and `git+` sources. | **all** — `checksum`: the SHA-256 of the `.crate` archive. | Workspace and path crates are left out. Git crates carry no checksum, only the commit. |
| `composer` | `composer.lock` | `packages` and `packages-dev` (dev), the dist URL, the commit (`reference`). | **some** — `dist.shasum`: the SHA-1 of the dist archive. An entry without one is unverified: *composer.lock has no dist shasum for this package (Packagist leaves it empty for archives GitHub builds on demand)*. | `path` packages are left out. The commit a dist was built from does not pin the archive. |
| `conan` | `conan.lock` | Conan 2 (`version: 0.5`): `requires`, `build_requires`, `python_requires`, `config_requires`, each `name/version[@user/channel]#rrev%timestamp` (a user and channel go into `id`). Conan 1 (`version: 0.4` and older): the `graph_lock` nodes, each with its recipe revision and, with revisions enabled, its package revision. The section the other Conan reads is refused. | **some** — The recipe revision: in Conan's default mode the MD5 of the recipe's manifest (`of: conan-recipe`), which pins the recipe, not the binary package. Conan 1's `prev`: the MD5 of the binary package's manifest (`of: conan-package`), which pins the package. An entry without one is unverified: *conan.lock records no revision for this reference*. | A Conan 2 dependency is unverified: its binary package is chosen by package ID at install time and not locked. A recipe revision in `scm` mode is a commit, not a digest. The remote is not recorded. |
| `conda` | `conda-lock.yml`, `*.conda-lock.yml` (and `.yaml`) | conda-lock's unified format (`version: 1`): every package of every platform with its URL and hashes; `manager: pip` packages are PyPI dependencies (type `pip`), Git ones pinned by their commit. One package version is one dependency, with each platform's file and its hashes. The name and version are those of the file the URL names — what `conda-lock install` installs; an entry that says otherwise is a warning. | **all** — conda: the MD5 and SHA-256 of the package file (`of`: `<subdir>/<file name>`). pip: the SHA-256 of the wheel or sdist (`of`: the file name). | `category: dev` and `optional: true` packages are `dev`. Packages from local paths are left out. |
| `conda` | `conda-<platform>.lock`, `*.conda.lock` (conda-lock's explicit kind), `spec-file.txt` | The package URLs after `@EXPLICIT`, as `conda list --explicit`, `mamba env export --explicit` and `conda-lock --kind explicit` write them; name, version and build from the file name. Lines end at LF, CRLF or a lone CR, as in conda's Python text mode. conda-lock's `# pip <name> @ <url>` lines, which `conda-lock install` installs, are PyPI dependencies (type `pip`). | **some** — The URL's fragment: the MD5 (`--md5`) or the SHA-256 (`--sha256`) of the package file — bare hex, told apart by length, or `sha256:<hex>`. A pip line's `#sha256=` hashes the wheel. An entry without one is unverified: *the explicit spec gives no hash for this package (conda list --explicit writes one with --md5 or --sha256)*. | Other names an explicit spec file is saved under are not detected: the format is told by its `@EXPLICIT` line, which detection by path cannot see. Files `conda list --explicit` writes without `--md5` or `--sha256` pin nothing. |
| `conda` | `pixi.lock` | Versions 4 to 7: every `packages` record — `conda: <url>` (name, version and build from the file name; version 6 and later record no name) or `pypi: <url>` with its name and version. A PyPI package from Git (`git+https://…#<commit>`) is pinned by its commit. A record with both a conda and a PyPI location, which pixi never writes, is left out with a warning. | **all** — conda: the SHA-256 and MD5 of the package file. PyPI: the SHA-256 of the wheel or sdist. | Development-only packages are not marked: pixi expresses them as environments, not as a flag on a package. |
| `cpan` | `cpanfile.snapshot` (Carton) | Every distribution under `DISTRIBUTIONS`: name and version from its archive (`Try-Tiny` 0.31), its path under `authors/id/` as `id`. | **none** An entry without one is unverified: *cpanfile.snapshot records no hash (the CHECKSUMS file of the author's directory on CPAN has one, the snapshot does not)*. | Every distribution is unverified. The snapshot does not say which distributions only tests need, nor which mirror they came from. |
| `cran` | `renv.lock` | Every package record with its `Source` (compared ignoring case, as renv does; old lock files say `CRAN`): `Repository` (the URL from `R.Repositories`), `Bioconductor`, `GitHub`/`GitLab`/`Bitbucket` (the repository and `RemoteSha`), `git`, `URL`. A key repeated in an object, or a repository named twice, is refused: R's named lists make it ambiguous. A forge package whose `RemoteHost` names no host the repository can be found on is a warning. | **none** — None. The `Hash` renv wrote before 1.1.0 is its own MD5 over fields of the package's DESCRIPTION file, not a hash of the archive, and is not taken for a digest; renv 1.1.0 and later write the DESCRIPTION fields instead, and no `Hash`. An entry without one is unverified: *renv.lock records no hash of the package archive*. | Every repository package is unverified; forge packages are pinned by their commit. `Local` packages are left out. A repository a record names that `R.Repositories` does not list (renv records itself as from `RSPM`) gives no registry, with a warning. renv leaves development-only (`Suggests`) packages out of the lock file rather than marking them. |
| `dart` | `pubspec.lock` | Every package with its `source` — `hosted` (the registry its description names), `git` (`resolved-ref`, the commit) — and `dependency: direct dev` as `dev`. | **some** — `description.sha256`: the SHA-256 of the package archive (pub writes it from Dart 2.19 on). An entry without one is unverified: *pubspec.lock records no sha256 for this package (pub writes one from Dart 2.19 on)*. | `path` packages are left out, and `sdk` packages (part of the Dart or Flutter SDK) too. Transitive dependencies of dev dependencies are not marked `dev`: the file says only which direct ones are. |
| `docker` | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile` | `FROM` images and `COPY --from=<image>`, with global `ARG` defaults expanded. | **all** — The image's manifest digest (`@sha256:…`), which is also its version. | Only images pinned by digest are dependencies: a tag can be moved, so an image without a digest is a warning. Earlier stages, `scratch` and heredoc bodies are not images. |
| `docker` | `compose.yaml`, `docker-compose.yml` and their `.<variant>.yml` forms | Every service's `image`, through YAML anchors and `<<` merges and `${VAR:-default}`, in the current and the version 1 layout. | **all** — The image's manifest digest, which is also its version. | Only images pinned by digest are dependencies; a repeated key is refused, as Compose refuses it. |
| `git` | `.gitmodules` at the root of the tree | Every `[submodule]` section's `path` and `url`, in git's configuration syntax as git's parser reads it (`[submodule.a "b"]` names submodule `a.b`; only space, tab, CR and LF are blanks); each submodule is pinned to the commit of the gitlink (tree entry of mode 160000) at exactly its path, looked up in the tree even where a skip glob keeps the walk out (a submodule in `third_party/` is still this repository's dependency), each tree object read once per level whatever the number of paths through it, within the scan's tree-entry limit. The name of the dependency is the submodule's path. | **none** — None: the gitlink's commit ID pins the submodule. An entry without one is unverified: *a submodule is pinned by its gitlink's commit, not by a digest*. | A submodule without a gitlink, one whose `path` or `url` is given twice (git commands disagree on which counts), a name git ignores (`..`), a value starting with `-`, a local-path or remote-helper (`ext::`) URL is a warning. A gitlink no declaration names is reported as skipped. A URL relative to the superproject's remote (`../x.git`) is kept as written. |
| `go` | `go.mod` | Requirements after the `replace` directives; the `h1:` hashes of the go.sum in the same directory are merged in. | **some** — None in go.mod itself: a requirement carries the hashes the go.sum next to it has for the module. An entry without one is unverified: *go.mod records no hash, and no go.sum next to it has one for this module*. | A replacement by a local directory is not fetched and is left out. |
| `go` | `go.sum` | Every `h1:` line; merged into the go.mod of the same directory, a module only go.sum names stays a dependency of its own. | **all** — `h1:` is the directory hash of the module zip's files (SHA-256 over the sorted SHA-256 sums); `/go.mod` lines hash only the module's go.mod (`of: go.mod`). | A `/go.mod` line hashes a go.mod needed for version selection only; a module with nothing but such a line is no dependency (its code is not downloaded). |
| `hackage` | `cabal.project.freeze` | The `constraints:` field (blanks allowed before the colon, as Cabal's lexer allows them): every `[qualifier.]name ==version`. | **none** An entry without one is unverified: *cabal.project.freeze pins versions only (its index-state pins the package index, not the packages)*. | Every package is unverified. Flag settings and `installed`/`source` constraints pin no version; a range is a warning. Boot packages are pinned like the others: whether a build takes them from the compiler or from Hackage is not recorded. |
| `hackage` | `stack.yaml.lock` | Every completed package, read in Pantry's order — a repository (`git`, `hg`), an archive URL, a Hackage package (`name-version@sha256:<hash>,<size>`), a GitHub shorthand — so the kind Stack fetches is the kind reported. | **all** — `pantry-tree`: the SHA-256 of Pantry's list of the package's files and their hashes (`of: pantry-tree`), which pins the content. The `@sha256:` of a Hackage package hashes its .cabal file (`of: cabal-file`), pinning the revision of its description. An archive's own SHA-256. | The packages of the resolver snapshot are not listed — the snapshot pins them, and the lock file pins the snapshot by its SHA-256; that is a warning. |
| `helm` | `Chart.lock`, `requirements.lock` (an apiVersion v1 chart's) | Every dependency with its exact version and repository: an HTTP chart repository or an OCI registry (`oci://…`). Read as Helm reads it — YAML 1.1 through encoding/json: keys match ignoring case (`Repository:` is the repository); a key given twice in different cases, or an unquoted name, version or repository that YAML 1.1 reads as a number, boolean or date (`1.10` becomes "1.1" to Helm), is refused. | **none** — None. The top-level `digest` is the SHA-256 over Chart.yaml's dependency list and the locked versions — Helm's check that the lock is current — and pins no chart. An entry without one is unverified: *Chart.lock records no digest of the chart archive (its digest covers the dependency list)*. | Every chart is unverified. `file://` charts are left out; a repository named by an alias of the user's Helm configuration (`@stable`) has no registry, with a warning. |
| `helm` | `requirements.lock` — Helm's for an apiVersion v1 chart, or Rye's (pip) | A YAML mapping is read as Helm's, exactly as `Chart.lock`; anything else as pip requirements (Rye writes its lock file under this name, `requirements-dev.lock` next to it) and reported as `requirements.txt`, with that format's rules. | **none** — None for charts, as `Chart.lock`. Read as pip requirements: the `--hash`es, when Rye was told to generate them. An entry without one is unverified: *Chart.lock records no digest of the chart archive (its digest covers the dependency list)*. | As `Chart.lock`. |
| `hex` | `mix.lock` | Every `:hex` tuple — the 3- to 8-element forms Hex wrote over the years — and `:git` tuples; the package name from the tuple (an atom or a string, as Hex reads it). The repository: hex.pm, or a hex.pm organisation (`hexpm:<org>`). Mix evaluates mix.lock as Elixir code, looks entries up by atom, and reads a file it cannot parse as empty: only literals in Elixir's own syntax are read (a call, a variable, interpolation, `1e5` are refused), and an entry not keyed by an atom is a warning. | **some** — The outer checksum: the SHA-256 of the release tarball. The inner checksum hashes what the tarball holds (`of: hex-inner`). Every entry current Mix writes has both; the oldest lock files have neither. An entry without one is unverified: *mix.lock records no checksum for this package*. | mix.lock does not record which dependencies are development-only. A repository other than hex.pm is named, not given by URL: its dependencies have no registry, with a warning. |
| `homebrew` | `Brewfile.lock.json` | `entries.brew` (formulae with every platform's bottle), `entries.cask`, and `entries.tap` (Git dependencies pinned by the tap's commit). `brew bundle` wrote the file from 2019 until November 2024 (Homebrew 4.4.8 was the last release that did); committed ones remain. | **some** — A bottle's `sha256`: the SHA-256 of the bottle tarball, which is also its blob digest on ghcr.io (`of`: the bottle's file name, one per platform). An entry without one is unverified: *Brewfile.lock.json records no hash for this entry*. | Casks and formulae built from source (`bottle: false`) are unverified. `mas`, `whalebrew` and `vscode` entries are not Homebrew packages: a warning. A tap's repository is assumed on GitHub. |
| `jsr` | `deno.lock` | Lock versions 1 (Deno before 1.28: module URL → hash) to 5, each by its own layout — a section of another version's layout, which Deno would ignore or let overwrite, is refused. JSR packages (type `jsr`), npm packages (type `npm`; a peer-dependency variant `x@1.0.0_peer@2` is x 1.0.0) and remote modules — each a URL, of type `generic` (a generic upstream fronts such hosts), named by the URL without its scheme and versioned by its content hash. A key repeated at the top is refused, as Deno refuses it. | **all** — JSR: the SHA-256 of the version's manifest on jsr.io (`of: jsr-manifest`), which lists the SHA-256 of every file. npm: the registry's Subresource Integrity. Remote modules: the SHA-256 of the file's bytes. | The registry of npm packages is not recorded, except a `tarball` URL in version 5. `redirects` and `workspace` are not dependencies. |
| `julia` | `Manifest.toml`, `JuliaManifest.toml`, `Manifest-v<major>.<minor>.toml` | Manifest format 2.x (`[[deps.<name>]]`) and 1.0 (top-level `[[<name>]]`): name, version, UUID (`id`) and tree hash; a package added from a repository (`repo-url`) is a Git dependency, pinned by its tree hash and, when `repo-rev` is one, its commit. | **all** — `git-tree-sha1`: the SHA-1 of the Git tree of the package's source (`of: git-tree`), which Pkg checks whatever it was fetched from. | Packages developed in place (`path`) are left out, and standard libraries (no tree hash) too: they ship with Julia. |
| `maven` | `gradle.lockfile`, `*-gradle.lockfile`, `gradle/dependency-locks/*.lockfile` | Every module; dependencies only test configurations use are `dev`. | **none** An entry without one is unverified: *gradle.lockfile records no hashes (Gradle keeps them in gradle/verification-metadata.xml, which is not read)*. | The repository is not recorded. |
| `maven` | `pom.xml` | Fixed versions only: a literal, or a property defined in the same POM. The parent, `<dependencies>` (profiles too), build plugins and their dependencies, BOMs imported in `<dependencyManagement>`. | **none** An entry without one is unverified: *a POM records no hashes*. | A version managed elsewhere, a range, a `SNAPSHOT`, `LATEST`/`RELEASE` or an undefined property is a warning. The registry is the one `<repository>` named, if just one is. |
| `nix` | `flake.lock` | Every locked input of the flake's graph: `github`, `gitlab`, `sourcehut` and `git` inputs are Git dependencies named by their flake reference (`github:NixOS/nixpkgs`) and versioned by their commit (by their NAR hash when locked without one); `tarball` and `file` inputs are downloads named by their URL and versioned by their NAR hash. | **all** — `narHash`: the SHA-256 of the NAR serialisation of the fetched source tree (`of: nar`), in SRI or in Nix's older base-32 form. | Inputs are sources, not the store paths the binary cache serves. `path` inputs are left out; Mercurial inputs are a warning. |
| `npm` | `package-lock.json` | lockfileVersion 1 (the nested `dependencies` tree), 2 and 3 (`packages`); aliases resolve to the real package; a tarball URL that is not a registry's `/<name>/-/` download is `source: url`. | **some** — `integrity`: the Subresource Integrity (SHA-512, older entries SHA-1) of the registry tarball. An entry without one is unverified: *package-lock.json records no integrity for this entry*. | Workspace folders, `link`s, bundled and `file:` packages are not fetched and are left out. Git entries carry no integrity, only the commit. |
| `npm` | `npm-shrinkwrap.json` | As `package-lock.json`, of which it is the published form. | **some** — `integrity`: the Subresource Integrity of the registry tarball. An entry without one is unverified: *npm-shrinkwrap.json records no integrity for this entry*. | As `package-lock.json`. |
| `npm` | `yarn.lock` | Yarn Classic (`# yarn lockfile v1`: registry, `integrity`, the SHA-1 in the `resolved` fragment) and Yarn Berry (`__metadata` version 6 to 10: `npm:` resolutions, `checksum`). | **some** — Classic: the tarball's SRI and SHA-1. Berry: `checksum` is the SHA-512 of the zip Yarn builds in its own cache (`of: yarn-cache`), not of the npm tarball. An entry without one is unverified: *yarn.lock records no integrity or checksum for this entry*. | `workspace:`, `patch:`, `file:`, `link:`, `portal:` and `exec:` entries are left out. Yarn records no dev flag. |
| `npm` | `pnpm-lock.yaml` | lockfileVersion 5.x, 6.x and 9.x (each spells package keys differently); registry tarballs, Git and tarball-URL dependencies; every YAML document — pnpm 10 and later write two when the project pins its package manager. | **some** — `resolution.integrity`: the SRI of the registry tarball. An entry without one is unverified: *pnpm-lock.yaml records no integrity for this entry*. | A YAML anchor, alias, merge key or repeated key is refused. lockfileVersion 9 records no dev flag. |
| `nuget` | `packages.lock.json`, `packages.<project>.lock.json` | Every target framework; one dependency per package version. | **all** — `contentHash`: SHA-512 of the package as NuGet hashes it, leaving a signed package's signature out (`of: nuget-content`) — not the hash of the `.nupkg` bytes served. | `Project` references are built here and left out. The registry is not recorded. |
| `pip` | `requirements*.txt`, `*-requirements.txt`, `constraints.txt`, `requirements/*.txt` | `==` and `===` pins with their `--hash`es, the `--index-url`, direct URLs and VCS references pinned to a commit. | **some** — `--hash`: one per distribution file of the release (`of`: the file name, when a direct URL names it). An entry without one is unverified: *no --hash is given for this requirement*. | A range, a wildcard, an editable local path or a VCS reference to a branch is a warning. `-r`/`-c` includes are not followed — the scan reads those files on their own. |
| `pip` | `Pipfile.lock` | `default` and `develop` (dev), the index each entry names, Git and file entries. | **all** — `hashes`: the SHA-256 of each distribution file of the release. | Editable local paths are left out. |
| `pip` | `poetry.lock` | lock-version 1.x (`[metadata.files]`, `category`) and 2.x (inline `files`, `groups`), `[package.source]`. | **all** — The SHA-256 of each distribution file (`of`: the file name). | Directory and file sources are left out. |
| `pip` | `uv.lock` | Registry, Git and URL sources with every sdist and wheel hash. | **all** — The SHA-256 of the sdist and of each wheel (`of`: the file name). | The project's own (`editable`, `virtual`, `directory`) packages are left out. uv records no dev flag per package. |
| `pip` | `pdm.lock` | lock_version 4.x with inline `files`, and the older `[metadata.files]` keyed `"<name> <version>"`. | **all** — The SHA-256 of each distribution file (`of`: the file name). | Local paths are left out. |
| `puppet` | `Puppetfile` | `forge` and `mod` declarations: Forge modules with an exact version (`puppetlabs/stdlib` → `puppetlabs-stdlib`), Git modules (`:git` with `:commit`, `:ref`, `:tag`, `:version` — the last given wins, as r10k folds them into one ref), r10k tarball modules. Puppet has no lock file. A Puppetfile is Ruby that r10k evaluates: any statement other than such a declaration with literal arguments is a warning, never evaluated. | **some** — Only a tarball module's `version`, which r10k checks as the archive's SHA-256. An entry without one is unverified: *a Puppetfile records no hash (the Forge publishes the release's checksums, the Puppetfile does not)*. | Every Forge module is unverified, and a Git module pinned to a tag. `:latest`, no version, or a `:branch` is a warning; `:local` modules are left out. |
| `rubygems` | `Gemfile.lock`, `gems.locked` | `GEM` and `GIT` sections, every platform variant, Bundler's `CHECKSUMS`. | **some** — `CHECKSUMS` (Bundler 2.6 and later, `bundle lock --add-checksums`): the SHA-256 of the `.gem` file of that platform. An entry without one is unverified: *Gemfile.lock has no CHECKSUMS entry for this gem (Bundler writes them from 2.6 on, with bundle lock --add-checksums)*. | `PATH` gems are left out. Gemfile.lock records no groups. |
| `swift` | `Package.resolved` | Versions 1 (`object.pins`), 2 and 3 (`pins`, version 3 with `originHash`), each read as SwiftPM reads it — by the version the file declares; the other layout's pins are ignored, an unknown version refused. Source-control pins with their commit and version (a branch pin is versioned by its commit), and registry pins (`kind: registry`, SE-0292). | **none** — None: a source-control pin is pinned by its commit. An entry without one is unverified: *Package.resolved records no checksum for a registry release (SwiftPM keeps it in its fingerprint storage)*. | Registry pins are unverified. Local packages (`localSourceControl`) are left out. |
| `terraform` | `.terraform.lock.hcl` (Terraform and OpenTofu) | Every `provider` block: the address (`registry.terraform.io/hashicorp/random` → name `hashicorp/random` on that registry), the selected `version` and the `hashes`. A provider locked twice is refused, as Terraform refuses it. | **all** — `zh:` — the SHA-256 of a file of the release's signed `SHA256SUMS`: each platform's zip, and the release's manifest.json (`of: terraform-zip`). `h1:` — Go's directory hash of one platform's unpacked package (`of: terraform-package`). | Terraform records which hashes it has seen, not which platform each belongs to. Modules are not in the lock file (see `*.tf modules`). |
| `terraform` | `*.tf`, `*.tofu` — only those with `module` blocks are reported | Module blocks: a registry module (`namespace/name/system`, optionally behind a host, optionally a `//subdirectory` of it) pinned by an exact `version`; a module from Git (`git::…?ref=`, `github.com/…`) pinned by the commit its `ref` names — a tag or branch there is unverified; an archive URL, with go-getter's `?checksum=`. The override files of the directory are applied as Terraform applies them (see `*.tf overrides`). Expressions that are not literal strings are skipped, never evaluated. | **some** — Only an archive URL's `?checksum=` (the archive's hash). Terraform records no hash of registry modules. An entry without one is unverified: *Terraform records no hash of a module, only the version a module block pins*. | A version range, a Git source without `?ref=` (the default branch) and S3, GCS or Mercurial sources are warnings; local modules (`./x`) are left out. `*.tf.json` is not read. Each `.tf` file counts against the scan's limit on lock files. |
| `terraform` | `override.tf`, `*_override.tf` (and `.tofu`) | The module blocks of Terraform's override files, merged as Terraform merges them: by file name, an override's `source` or `version` replacing the module's of the same name in the directory's other files — whose dependency then says what Terraform installs. | **none** — None: an override file yields no dependency of its own. An entry without one is unverified: *Terraform records no hash of a module, only the version a module block pins*. | An override of a module no other file of the directory declares is a warning. `*_override.tf.json` is not read. |

### What a digest is of

`of` on a digest says what was hashed when it is not simply the artifact the registry serves
for the coordinate. A digest of a document next to the artifact pins only that document: a
dependency with nothing else is unverified. Any other value of `of` is the name of the
distribution file hashed (a wheel, a platform's bottle, a conda package file).

| `of` | Meaning | Pins the content |
|---|---|---|
| (none) | The artifact the registry serves for the coordinate. | yes |
| `MODULE.bazel` | Only a Bazel module's MODULE.bazel declaration, not its source. | no — unverified: *MODULE.bazel.lock hashes only this module's declaration, not its source* |
| `cabal-file` | Only the revision of a Haskell package's .cabal file, not its source. | no — unverified: *stack.yaml.lock hashes only this package's .cabal file, not its source* |
| `conan-package` | The manifest of a Conan binary package (Conan 1's package revision). | yes |
| `conan-recipe` | The manifest of a Conan recipe: the recipe, not the binary package built from it. | no — unverified: *conan.lock pins the recipe revision, not the binary package the client downloads* |
| `git-tree` | The Git tree object of the package's source (Julia's git-tree-sha1). | yes |
| `go.mod` | Only the module's go.mod file, not its code. | no — unverified: *go.sum hashes only this module's go.mod: its code is not pinned (the build does not download it)* |
| `hex-inner` | Hex's inner checksum: what the release tarball holds (its VERSION, metadata.config and contents.tar.gz), not the tarball's bytes. | yes |
| `jsr-manifest` | The JSR version manifest (`<version>_meta.json`), which lists the SHA-256 of every file of the version. | yes |
| `nar` | The NAR serialisation of a fetched source tree (Nix's narHash). | yes |
| `nuget-content` | The package as NuGet hashes it, without a signed package's signature file. | yes |
| `pantry-tree` | Pantry's tree of a Haskell package: the list of its files and their hashes. | yes |
| `source.json` | A Bazel module's source.json in its registry, which names the archive and its integrity. | yes |
| `terraform-package` | The directory hash of one platform's unpacked Terraform provider package. | yes |
| `terraform-zip` | A file of a Terraform provider release's SHA256SUMS: one platform's zip (or the release's manifest.json). | yes |
| `yarn-cache` | The zip Yarn Berry builds from the tarball in its own cache. | yes |

### Git dependencies

The `git` upstream type is covered twice: a repository's own submodules (`.gitmodules`, each
pinned by the gitlink at its path), and the Git dependencies other lock files record — every
dependency with `"source": "git"`, pinned when its `revision` is a commit.
`Report.GitDependencies()` collects both. Formats that record Git dependencies: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `conda-lock.yml`, `@EXPLICIT spec`, `pixi.lock`, `renv.lock`, `mix.lock`, `Package.resolved`, `pubspec.lock`, `Manifest.toml`, `flake.lock`, `*.tf modules`, `stack.yaml.lock`, `Brewfile.lock.json`, `requirements.yml`, `Puppetfile`, `.gitmodules`.

### Types without a lock-file format

Every upstream type the proxy fronts has a parser or an entry saying why it has none
(`internal/lockfiles/coverage.go`); a test fails when a type is added without either.

| Type | Why |
|---|---|
| `apt` | no lock-file format: Debian packages are installed from repository indexes at build time; version pins in a Dockerfile's apt-get line are commands, not a lock file. |
| `generic` | no lock-file format: a generic upstream serves whatever routes its operator declares, so there is no format to know in advance. Remote modules of deno.lock are recorded as dependencies of this type. |
| `huggingface` | no declared manifest in general use: models and datasets are referenced by repository and revision in code (from_pretrained(…, revision=…)) or in each serving tool's own configuration (KServe storageUri, vLLM --revision). The .metadata files `hf download --local-dir` writes are a git-ignored download cache that does not record the repository, and DVC's .dvc files are DVC's own format. |
| `openvsx` | no lock-file format: .vscode/extensions.json recommends extension IDs (publisher.name), and its schema allows no version or hash. devcontainer.json can name an exact version (publisher.name@1.2.3) but records no hash, and devcontainer-lock.json pins Features, not extensions. |
| `yum` | no lock-file format: RPM packages are installed from repository metadata at build time; dnf has no lock file in general use. |

Lock-file formats of the ecosystems above that are not read yet:

| Type | Not read |
|---|---|
| `npm` | `bun.lock`, `bun.lockb` |
| `nuget` | `paket.lock` |
| `pip` | `pylock.toml (PEP 751)` |

<!-- END GENERATED: lock-file formats -->

## Read as the package manager reads it

A lock file edited to show a scanner one artifact while the package manager installs another
must not succeed, so each format is read with its tool's semantics. JSON keys match exactly (not case-insensitively, as Go's struct decoding
would) and a repeated key or entry keeps its last value, as `JSON.parse`, Python's `json` and
PHP's `json_decode` do. YAML lock files (`pnpm-lock.yaml`, Yarn Berry's `yarn.lock`) with an
anchor, an alias, a merge key or a key repeated in one mapping are refused with an error: no
tool writes them, and pnpm's and Yarn's own readers would give them a meaning. Compose files may
use anchors and `<<` merges (followed with a work budget) but not repeated keys, which Compose
refuses too. go.sum `h1:` values are accepted only as the base64 of a SHA-256.

The same rule holds for the formats added since:

- **Files a tool evaluates.** Mix evaluates `mix.lock` as Elixir code and r10k evaluates a
  `Puppetfile` as Ruby. The scanner evaluates neither: it reads the literals the files are made
  of — maps, tuples, keywords, atoms and strings; `mod` and `forge` calls with literal
  arguments — and refuses a `mix.lock` with anything else (a call, a variable, string
  interpolation), or reports a Puppetfile statement it does not evaluate as a warning. What such
  a file pins is decided when it runs, not when it is read. Terraform expressions other than
  literal strings are skipped, never evaluated.
- **Repeated keys.** `renv.lock` (an R list with a name given twice is ambiguous), `deno.lock`
  at the top (serde refuses it), `mix.lock`, the attributes and provider blocks of HCL
  (Terraform refuses them) and the `path` or `url` of one submodule (git commands disagree on
  which value counts) are refused or left out rather than read one way. Elsewhere a repeated
  key keeps its last value, as the tool's JSON reader does.
- **Hashes that are not of the artifact.** renv.lock's `Hash` is renv's MD5 of DESCRIPTION
  fields, Chart.lock's `digest` covers the dependency list, conda-lock writes a Git package's
  commit into `hash.sha256`: none is taken for a digest of what is downloaded.

## Reading a repository

The scan reads **objects at a commit** through the object access of `internal/git` (one
`git cat-file --batch-command` process per scan), never a working tree: uncommitted changes
are not seen, and a lock file is read exactly as the commit holds it.

- **A local path** — a working tree, a directory in one (only that directory is scanned),
  a `.git` directory or a bare repository — is read at `HEAD` or `--rev`. Objects a partial
  clone left out are not fetched unless `--allow-fetch` is given: a fetch runs the repository's
  own configuration (its remote, its ssh command).
- **A remote** (`https://`, `ssh://`, `git://`, `file://`, `user@host:path`) is fetched into
  a temporary directory, removed before anything is printed: one commit deep, as a partial
  clone that leaves out every file larger than `--max-file-size`, so a huge file is never
  downloaded. A commit ID the server will not hand out directly is found by fetching its
  branches and tags. Remote-helper URLs (`ext::…`) are refused. A server that stops sending
  ends the fetch after a minute, and `--scan-timeout` or Ctrl-C ends git with every helper it
  started (it runs in a process group of its own).

The walk:

| Limit | Default | Flag |
| ----- | ------- | ---- |
| Skip globs | `DefaultSkip` (below) | `--skip GLOB` (repeatable, adds), `--no-default-skip` |
| Directory depth | 24 | `--max-depth` |
| Largest lock file read | 32 MiB (its size is asked for first); 16 MiB for the YAML and TOML formats, which are read into a tree | `--max-file-size` |
| Lock files | 2000 | `--max-files` |
| Bytes of lock files | 512 MiB | — |
| Tree entries seen | 2 000 000 | — |

A glob without `/` matches a name at any depth (`node_modules`); one with `/` matches the path
from the repository root, `**` standing for any number of directories (`**/test/data`,
`docs/examples/*`). Matching ignores case (`fixtures` skips `Fixtures`). The defaults skip vendored code — `node_modules`, `bower_components`,
`jspm_packages`, `.pnpm-store`, `.yarn`, `vendor`, `third_party`, `.venv`, `venv`,
`site-packages`, `__pypackages__`, `.tox`, `.nox`, `.bundle`, `Pods`, `Carthage`,
`.terraform`, `target` — and test fixtures — `testdata`, `test-data`, `fixtures`,
`__fixtures__`, `test-fixtures`, `**/test/data`, `**/tests/data`: their lock files pin
another project's dependencies, or describe no build at all.

**Submodules.** A submodule is a dependency of the repository that pins it: the root
`.gitmodules` names its repository and the gitlink at its path pins the commit, so each becomes a
dependency of type `git` (named by its path, `source: git`, its commit the version and the
revision). The gitlink is looked up in the tree even where a skip glob keeps the walk out — a
submodule in `third_party/` is this repository's dependency even though the lock files inside such
a directory are not. A gitlink `.gitmodules` does not declare is listed as skipped (its repository
is unknown); a declaration without a gitlink is a warning. Scanning a directory of the tree reads
the root `.gitmodules` for the submodules inside that directory.

Terraform configuration files are read for their module blocks: every `*.tf` file is read (and
counts against the limit on lock files), and only those that yield something are reported.

Nothing is skipped silently: the report lists the directories a glob or the depth limit
kept the walk out of, the lock files too large or missing from the clone, the symbolic
links named like a lock file (links are not followed) — the first 500 of them, with a count
of all skipped directories in `stats` — and, if a limit ended the walk early, which one.
Submodules are listed with the commit they pin.

## Lock files written against this proxy

A lock file resolved through the proxy records the proxy's URLs — and through a
[personal cache link](user-links.md), the user's token in every one of them:

```
"resolved": "https://proxy.example.com/u/ptl1…/v1/npm/lodash/-/lodash-4.17.21.tgz"
```

The scanner maps such URLs back to the upstream they stand for. Three shapes are recognised:

| Shape | Recognised |
| ----- | ---------- |
| `<base>/u/<token>/v1/<upstream>/…` (personal link) | under a configured public URL, whatever the token looks like; on any other host, when the segment is spelled like a token (`ptl1…`) |
| `https://<upstream host>/_pullthrough/v1/<upstream>/…` (TLS interception) | on any host; the URL keeps its host, and the configured upstream is credited only on that upstream's own host (or the proxy's) |
| `<public URL>/v1/<upstream>/…` (the plain mount) | under a configured public URL |
| `<proxy host>/[u/<token>/]<upstream>/<repository>@sha256:…` (container registry alias) | for the proxy's host, or a token-shaped link on any host |

The dependency then records `upstream`, `registry` — the upstream's own URL when the
configuration is known, the proxy's token-free mount of it otherwise — and the `url` in the
proxy's canonical, token-free form (an intercepted URL stays on the host it names: a lock file
cannot move a download from `evil.example` onto the npm upstream by spelling its path like one). A lock file that resolves a package through an upstream
of another type is kept, with a warning.

The token is never kept or printed: parsers cut anything spelled like a token out of a URL
before it leaves them, the mapping drops the path segment after the personal prefix
whatever it contains, and every warning, error, name and digest file name passes through
the same redaction. The fuzz targets check that no input can get a token through.

`ptctl` learns the deployment from `--config <proxy config>` (`server.publicUrl`,
`userLinks.pathPrefix`, `server.registry.defaultUpstream`, `upstreams`), from `--public-url`
and from `--url`, whose admin API it asks for the upstreams (`--discover=false` to skip).
Without any of them the personal-link and interception shapes are still recognised.

## `ptctl lockfiles`

```bash
ptctl lockfiles scan .                                    # this repository, at HEAD
ptctl lockfiles scan ./services/api                       # one directory of it
ptctl lockfiles scan https://github.com/org/repo --rev v1.4.0 --json
ptctl lockfiles scan git@github.com:org/private.git --skip 'examples/**' --no-default-skip
ptctl lockfiles scan . --config /etc/pullthrough/config.yaml   # map proxy URLs to upstreams
ptctl lockfiles formats                                   # what is read, per upstream type
```

The table lists every dependency with its location; its digest column says `unverified` for a
dependency nothing in the lock file pins, and the summary counts them. `--json` prints the full
report (`commit`, `files[]` with `dependencies`, `warnings` and `error`, `skipped`, `submodules`,
`truncated`, `stats`). A lock file that cannot be read is reported with its error; the scan goes
on. `ptctl lockfiles formats` prints the format table above from the code; `--json` gives each
upstream type's coverage with the description of every format (`details`).

## Parsers of untrusted input

A repository is whatever its last committer made it, and the scanner runs inside the proxy.
Every parser is pure — no network, no file system, no processes — and:

- has a fuzz target in the fuzz harness (`make fuzz`; a test fails for a parser without one),
  checking that no input panics it, that its output is deterministic and well-formed, and
  that no link token survives;
- reads JSON as a stream (a 30 MB `package-lock.json` is not turned into a tree), text
  formats line by line, TOML through a strict reader whose tables and values are budgeted by
  the size of the input, YAML only when it is not denser than a real lock file (a document
  that is all structure would make a tree a hundred times its size), XML without DTD
  entities and without building element paths that cannot match;
- reads the formats of other languages through readers of their own, each bounded in nesting
  and in the values it makes: HCL (Terraform), whose expressions are followed through brackets,
  templates and heredocs and kept only when literal; Elixir literals (`mix.lock`); the
  declarative subset of Ruby a Puppetfile is written in; git's configuration syntax
  (`.gitmodules`), read as git's own parser reads it — what git refuses is an error;
- runs under a recover in the walk: a parser that fails on a file fails that file, not the
  scan.

Tree objects are parsed strictly too: an entry name a checkout could not produce (`..`,
anything with `/`), an unknown mode or a truncated hash makes the directory unreadable,
reported and skipped.

## Testing

- `internal/lockfiles/testdata/fixtures/` holds a directory per format version, generated
  by the package managers themselves wherever one could be run (each fixture's
  `GENERATED.md` names the tool, version and command) — npm 6, 8 and 10, Yarn 1, 3 and 4,
  pnpm 7, 8, 9 and 12, pip-tools-style `uv pip compile`, Pipenv, Poetry 1.1 and 2, uv, PDM
  2.5 and 2.29, Cargo, Go, the .NET SDK, Gradle, Bundler and Composer; conda-lock, conda and
  mamba, pixi, renv, Mix, SwiftPM (Package.resolved versions 1, 2 and 3, and a registry), Dart
  2.18 and 3, Julia 1.6, 1.11 and 1.13, cabal, Stack, Bazel 6, 7 and 9, Nix, Terraform,
  OpenTofu, Conan 1 and 2, Carton, Deno (lock versions 2 to 5), Helm, Homebrew 4.4.8 (the last
  to write `Brewfile.lock.json`) and git — and by hand for what no tool writes: Cargo's v1
  format, a nested npm v1 tree, a POM, Dockerfiles, lock files resolved through the proxy, and
  the Ansible requirements files and Puppetfile users write (each checked with ansible-galaxy or
  r10k), next to a real-world Puppetfile. `testdata/golden/<fixture>.json` is the expected
  output; `go test ./internal/lockfiles/ -run TestGolden -update` rewrites it.
- The format table is held to the fixtures: a format described as recording no digest yields
  none, one described as recording a digest for every entry yields no unverified registry entry,
  and one described as recording Git dependencies has a fixture with one.
- The walk is tested on real repositories: every fixture committed into one monorepo must
  read exactly as the golden files say (a fixture with a `.gitmodules` is committed at the root
  of a repository of its own, with real gitlinks); skip globs, depth, size and count limits,
  symbolic links, submodules (also inside a skipped directory, and for a directory of the
  tree), a subdirectory, an older commit and a size-filtered partial clone each have a test.
