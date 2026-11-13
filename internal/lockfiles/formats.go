package lockfiles

import (
	"sort"
	"strings"
)

// DigestSupport says how far the entries of a format carry digests.
type DigestSupport string

const (
	// DigestsAll: every entry fetched from a registry or by URL carries a
	// digest that pins its content; Git entries are pinned by commit.
	DigestsAll DigestSupport = "all"
	// DigestsSome: the format can record a digest, and some entries — or the
	// files an older version of the tool wrote — have none.
	DigestsSome DigestSupport = "some"
	// DigestsNone: the format records no digest of the artifacts it pins.
	// Only the commit IDs of Git entries pin anything.
	DigestsNone DigestSupport = "none"
)

// FormatInfo describes a format for the coverage table and the generated
// reference (docs/lockfiles.md): the paths it is detected by, what is read
// from it, what its digests are hashes of, and its limits. Tests hold the
// claims to the golden fixtures: a format said to record no digest yields
// none, one said to record digests for every entry yields no unverified
// registry entry, one said to record Git sources has a fixture that shows
// one.
type FormatInfo struct {
	Type   string `json:"type"`
	Format string `json:"format"`
	// Files names the paths detected (Markdown).
	Files string `json:"files"`
	// Read says what is read: the versions of the format, its sections, the
	// kinds of source.
	Read string `json:"read"`
	// Digests is how far entries carry digests; Hashed says what they are
	// hashes of.
	Digests DigestSupport `json:"digests"`
	Hashed  string        `json:"hashed,omitempty"`
	// NoDigest is the reason given on an entry that has no digest
	// (Dependency.UnverifiedReason).
	NoDigest string `json:"noDigest,omitempty"`
	// Limits says what is not read, or is read but is not a dependency.
	Limits string `json:"limits,omitempty"`
	// GitSources says the format records dependencies fetched from Git
	// repositories (Source "git").
	GitSources bool `json:"gitSources,omitempty"`
}

// formatInfo is the description of every built-in parser's format, keyed by
// "<type>/<format>". A parser without an entry fails a test.
var formatInfo = map[string]FormatInfo{
	// npm
	"npm/package-lock.json": {
		Files:      "`package-lock.json`",
		Read:       "lockfileVersion 1 (the nested `dependencies` tree), 2 and 3 (`packages`); aliases resolve to the real package; a tarball URL that is not a registry's `/<name>/-/` download is `source: url`.",
		Digests:    DigestsSome,
		Hashed:     "`integrity`: the Subresource Integrity (SHA-512, older entries SHA-1) of the registry tarball.",
		NoDigest:   "package-lock.json records no integrity for this entry",
		Limits:     "Workspace folders, `link`s, bundled and `file:` packages are not fetched and are left out. Git entries carry no integrity, only the commit.",
		GitSources: true,
	},
	"npm/npm-shrinkwrap.json": {
		Files:      "`npm-shrinkwrap.json`",
		Read:       "As `package-lock.json`, of which it is the published form.",
		Digests:    DigestsSome,
		Hashed:     "`integrity`: the Subresource Integrity of the registry tarball.",
		NoDigest:   "npm-shrinkwrap.json records no integrity for this entry",
		Limits:     "As `package-lock.json`.",
		GitSources: true,
	},
	"npm/yarn.lock": {
		Files:      "`yarn.lock`",
		Read:       "Yarn Classic (`# yarn lockfile v1`: registry, `integrity`, the SHA-1 in the `resolved` fragment) and Yarn Berry (`__metadata` version 6 to 10: `npm:` resolutions, `checksum`).",
		Digests:    DigestsSome,
		Hashed:     "Classic: the tarball's SRI and SHA-1. Berry: `checksum` is the SHA-512 of the zip Yarn builds in its own cache (`of: yarn-cache`), not of the npm tarball.",
		NoDigest:   "yarn.lock records no integrity or checksum for this entry",
		Limits:     "`workspace:`, `patch:`, `file:`, `link:`, `portal:` and `exec:` entries are left out. Yarn records no dev flag.",
		GitSources: true,
	},
	"npm/pnpm-lock.yaml": {
		Files:      "`pnpm-lock.yaml`",
		Read:       "lockfileVersion 5.x, 6.x and 9.x (each spells package keys differently); registry tarballs, Git and tarball-URL dependencies; every YAML document — pnpm 10 and later write two when the project pins its package manager.",
		Digests:    DigestsSome,
		Hashed:     "`resolution.integrity`: the SRI of the registry tarball.",
		NoDigest:   "pnpm-lock.yaml records no integrity for this entry",
		Limits:     "A YAML anchor, alias, merge key or repeated key is refused. lockfileVersion 9 records no dev flag.",
		GitSources: true,
	},
	// pip
	"pip/requirements.txt": {
		Files:      "`requirements*.txt`, `*-requirements.txt`, `constraints.txt`, `requirements/*.txt`",
		Read:       "`==` and `===` pins with their `--hash`es, the `--index-url`, direct URLs and VCS references pinned to a commit.",
		Digests:    DigestsSome,
		Hashed:     "`--hash`: one per distribution file of the release (`of`: the file name, when a direct URL names it).",
		NoDigest:   "no --hash is given for this requirement",
		Limits:     "A range, a wildcard, an editable local path or a VCS reference to a branch is a warning. `-r`/`-c` includes are not followed — the scan reads those files on their own.",
		GitSources: true,
	},
	"pip/Pipfile.lock": {
		Files:      "`Pipfile.lock`",
		Read:       "`default` and `develop` (dev), the index each entry names, Git and file entries.",
		Digests:    DigestsAll,
		Hashed:     "`hashes`: the SHA-256 of each distribution file of the release.",
		NoDigest:   "Pipfile.lock records no hash for this entry",
		Limits:     "Editable local paths are left out.",
		GitSources: true,
	},
	"pip/poetry.lock": {
		Files:      "`poetry.lock`",
		Read:       "lock-version 1.x (`[metadata.files]`, `category`) and 2.x (inline `files`, `groups`), `[package.source]`.",
		Digests:    DigestsAll,
		Hashed:     "The SHA-256 of each distribution file (`of`: the file name).",
		NoDigest:   "poetry.lock records no file hash for this entry",
		Limits:     "Directory and file sources are left out.",
		GitSources: true,
	},
	"pip/uv.lock": {
		Files:      "`uv.lock`",
		Read:       "Registry, Git and URL sources with every sdist and wheel hash.",
		Digests:    DigestsAll,
		Hashed:     "The SHA-256 of the sdist and of each wheel (`of`: the file name).",
		NoDigest:   "uv.lock records no hash for this entry",
		Limits:     "The project's own (`editable`, `virtual`, `directory`) packages are left out. uv records no dev flag per package.",
		GitSources: true,
	},
	"pip/pdm.lock": {
		Files:      "`pdm.lock`",
		Read:       "lock_version 4.x with inline `files`, and the older `[metadata.files]` keyed `\"<name> <version>\"`.",
		Digests:    DigestsAll,
		Hashed:     "The SHA-256 of each distribution file (`of`: the file name).",
		NoDigest:   "pdm.lock records no file hash for this entry",
		Limits:     "Local paths are left out.",
		GitSources: true,
	},
	// cargo
	"cargo/Cargo.lock": {
		Files:      "`Cargo.lock`",
		Read:       "Format v1 (checksums in `[metadata]`) to v4; `registry+`, `sparse+` and `git+` sources.",
		Digests:    DigestsAll,
		Hashed:     "`checksum`: the SHA-256 of the `.crate` archive.",
		NoDigest:   "Cargo.lock records no checksum for this crate",
		Limits:     "Workspace and path crates are left out. Git crates carry no checksum, only the commit. A format 2 or later file that still has `[metadata]` checksums is read as Cargo reads it: Cargo discards every checksum of such a file, so its crates are unverified.",
		GitSources: true,
	},
	// go
	"go/go.mod": {
		Files:    "`go.mod`",
		Read:     "Requirements after the `replace` directives; the `h1:` hashes of the go.sum in the same directory are merged in.",
		Digests:  DigestsSome,
		Hashed:   "None in go.mod itself: a requirement carries the hashes the go.sum next to it has for the module.",
		NoDigest: "go.mod records no hash, and no go.sum next to it has one for this module",
		Limits:   "A replacement by a local directory is not fetched and is left out.",
	},
	"go/go.sum": {
		Files:    "`go.sum`",
		Read:     "Every `h1:` line; merged into the go.mod of the same directory, a module only go.sum names stays a dependency of its own.",
		Digests:  DigestsAll,
		Hashed:   "`h1:` is the directory hash of the module zip's files (SHA-256 over the sorted SHA-256 sums); `/go.mod` lines hash only the module's go.mod (`of: go.mod`).",
		NoDigest: "go.sum has no hash for this module",
		Limits:   "A `/go.mod` line hashes a go.mod needed for version selection only; a module with nothing but such a line is no dependency (its code is not downloaded).",
	},
	// nuget
	"nuget/packages.lock.json": {
		Files:    "`packages.lock.json`, `packages.<project>.lock.json`",
		Read:     "Every target framework; one dependency per package version.",
		Digests:  DigestsAll,
		Hashed:   "`contentHash`: SHA-512 of the package as NuGet hashes it, leaving a signed package's signature out (`of: nuget-content`) — not the hash of the `.nupkg` bytes served.",
		NoDigest: "packages.lock.json records no contentHash for this package",
		Limits:   "`Project` references are built here and left out. The registry is not recorded.",
	},
	// maven
	"maven/gradle.lockfile": {
		Files:    "`gradle.lockfile`, `*-gradle.lockfile`, `gradle/dependency-locks/*.lockfile`",
		Read:     "Every module; dependencies only test configurations use are `dev`.",
		Digests:  DigestsNone,
		NoDigest: "gradle.lockfile records no hashes (Gradle keeps them in gradle/verification-metadata.xml, which is not read)",
		Limits:   "The repository is not recorded.",
	},
	"maven/pom.xml": {
		Files:    "`pom.xml`",
		Read:     "Fixed versions only: a literal, or a property defined in the same POM. The parent, `<dependencies>` (profiles too), build plugins and their dependencies, BOMs imported in `<dependencyManagement>`.",
		Digests:  DigestsNone,
		NoDigest: "a POM records no hashes",
		Limits:   "A version managed elsewhere, a range, a `SNAPSHOT`, `LATEST`/`RELEASE` or an undefined property is a warning. The registry is the one `<repository>` named, if just one is.",
	},
	// rubygems
	"rubygems/Gemfile.lock": {
		Files:      "`Gemfile.lock`, `gems.locked`",
		Read:       "`GEM` and `GIT` sections, every platform variant, Bundler's `CHECKSUMS`.",
		Digests:    DigestsSome,
		Hashed:     "`CHECKSUMS` (Bundler 2.6 and later, `bundle lock --add-checksums`): the SHA-256 of the `.gem` file of that platform.",
		NoDigest:   "Gemfile.lock has no CHECKSUMS entry for this gem (Bundler writes them from 2.6 on, with bundle lock --add-checksums)",
		Limits:     "`PATH` gems are left out. Gemfile.lock records no groups.",
		GitSources: true,
	},
	// composer
	"composer/composer.lock": {
		Files:      "`composer.lock`",
		Read:       "`packages` and `packages-dev` (dev), the dist URL, the commit (`reference`).",
		Digests:    DigestsSome,
		Hashed:     "`dist.shasum`: the SHA-1 of the dist archive.",
		NoDigest:   "composer.lock has no dist shasum for this package (Packagist leaves it empty for archives GitHub builds on demand)",
		Limits:     "`path` packages are left out. The commit a dist was built from does not pin the archive.",
		GitSources: true,
	},
	// docker
	"docker/Dockerfile": {
		Files:   "`Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile`",
		Read:    "`FROM` images and `COPY --from=<image>`, with global `ARG` defaults expanded.",
		Digests: DigestsAll,
		Hashed:  "The image's manifest digest (`@sha256:…`), which is also its version.",
		Limits:  "Only images pinned by digest are dependencies: a tag can be moved, so an image without a digest is a warning. Earlier stages, `scratch` and heredoc bodies are not images.",
	},
	"docker/compose": {
		Files:   "`compose.yaml`, `docker-compose.yml` and their `.<variant>.yml` forms",
		Read:    "Every service's `image`, through YAML anchors and `<<` merges and `${VAR:-default}`, in the current and the version 1 layout.",
		Digests: DigestsAll,
		Hashed:  "The image's manifest digest, which is also its version.",
		Limits:  "Only images pinned by digest are dependencies; a repeated key is refused, as Compose refuses it.",
	},
	// conda
	"conda/conda-lock.yml": {
		Files: "`conda-lock.yml`, `*.conda-lock.yml` (and `.yaml`)",
		Read: "conda-lock's unified format (`version: 1`): every package of every platform with its URL and hashes; `manager: pip` packages are PyPI dependencies (type `pip`), Git ones pinned by their commit. " +
			"One package version is one dependency, with each platform's file and its hashes. The name and version are those of the file the URL names — what `conda-lock install` installs; an entry that says otherwise is a warning.",
		Digests:    DigestsAll,
		Hashed:     "conda: the MD5 and SHA-256 of the package file (`of`: `<subdir>/<file name>`). pip: the SHA-256 of the wheel or sdist (`of`: the file name).",
		NoDigest:   "conda-lock.yml records no hash for this package",
		Limits:     "`category: dev` and `optional: true` packages are `dev`. Packages from local paths are left out.",
		GitSources: true,
	},
	"conda/@EXPLICIT spec": {
		Files: "`conda-<platform>.lock`, `*.conda.lock` (conda-lock's explicit kind), `spec-file.txt`",
		Read: "The package URLs after `@EXPLICIT`, as `conda list --explicit`, `mamba env export --explicit` and `conda-lock --kind explicit` write them; name, version and build from the file name. Lines end at LF, CRLF or a lone CR, as in conda's Python text mode. " +
			"conda-lock's `# pip <name> @ <url>` lines, which `conda-lock install` installs, are PyPI dependencies (type `pip`).",
		Digests:    DigestsSome,
		Hashed:     "The URL's fragment: the MD5 (`--md5`) or the SHA-256 (`--sha256`) of the package file — bare hex, told apart by length, or `sha256:<hex>`. A pip line's `#sha256=` hashes the wheel.",
		NoDigest:   "the explicit spec gives no hash for this package (conda list --explicit writes one with --md5 or --sha256)",
		Limits:     "Other names an explicit spec file is saved under are not detected: the format is told by its `@EXPLICIT` line, which detection by path cannot see. Files `conda list --explicit` writes without `--md5` or `--sha256` pin nothing.",
		GitSources: true,
	},
	"conda/pixi.lock": {
		Files: "`pixi.lock`",
		Read: "Versions 4 to 7: every `packages` record — `conda: <url>` (name, version and build from the file name; version 6 and later record no name) or `pypi: <url>` with its name and version. " +
			"A PyPI package from Git (`git+https://…#<commit>`) is pinned by its commit. A record with both a conda and a PyPI location, which pixi never writes, is left out with a warning.",
		Digests:    DigestsAll,
		Hashed:     "conda: the SHA-256 and MD5 of the package file. PyPI: the SHA-256 of the wheel or sdist.",
		NoDigest:   "pixi.lock records no hash for this package",
		Limits:     "Development-only packages are not marked: pixi expresses them as environments, not as a flag on a package.",
		GitSources: true,
	},
	// cran
	"cran/renv.lock": {
		Files: "`renv.lock`",
		Read: "Every package record with its `Source` (compared ignoring case, as renv does; old lock files say `CRAN`): `Repository` (the URL from `R.Repositories`), `Bioconductor`, `GitHub`/`GitLab`/`Bitbucket` (the repository and `RemoteSha`), `git`, `URL`. " +
			"A key repeated in an object, or a repository named twice, is refused: R's named lists make it ambiguous. A forge package whose `RemoteHost` names no host the repository can be found on is a warning.",
		Digests:    DigestsNone,
		Hashed:     "None. The `Hash` renv wrote before 1.1.0 is its own MD5 over fields of the package's DESCRIPTION file, not a hash of the archive, and is not taken for a digest; renv 1.1.0 and later write the DESCRIPTION fields instead, and no `Hash`.",
		NoDigest:   "renv.lock records no hash of the package archive",
		Limits:     "Every repository package is unverified; forge packages are pinned by their commit. `Local` packages are left out. A repository a record names that `R.Repositories` does not list (renv records itself as from `RSPM`) gives no registry, with a warning. renv leaves development-only (`Suggests`) packages out of the lock file rather than marking them.",
		GitSources: true,
	},
	// hex
	"hex/mix.lock": {
		Files: "`mix.lock`",
		Read: "Every `:hex` tuple — the 3- to 8-element forms Hex wrote over the years — and `:git` tuples; the package name from the tuple (an atom or a string, as Hex reads it). The repository: hex.pm, or a hex.pm organisation (`hexpm:<org>`). " +
			"Mix evaluates mix.lock as Elixir code, looks entries up by atom, and reads a file it cannot parse as empty: only literals in Elixir's own syntax are read (a call, a variable, interpolation, `1e5` are refused), and an entry not keyed by an atom is a warning.",
		Digests:    DigestsSome,
		Hashed:     "The outer checksum: the SHA-256 of the release tarball. The inner checksum hashes what the tarball holds (`of: hex-inner`). Every entry current Mix writes has both; the oldest lock files have neither.",
		NoDigest:   "mix.lock records no checksum for this package",
		Limits:     "mix.lock does not record which dependencies are development-only. A repository other than hex.pm is named, not given by URL: its dependencies have no registry, with a warning.",
		GitSources: true,
	},
	// swift
	"swift/Package.resolved": {
		Files:      "`Package.resolved`",
		Read:       "Versions 1 (`object.pins`), 2 and 3 (`pins`, version 3 with `originHash`), each read as SwiftPM reads it — by the version the file declares; the other layout's pins are ignored, an unknown version refused. Source-control pins with their commit and version (a branch pin is versioned by its commit), and registry pins (`kind: registry`, SE-0292).",
		Digests:    DigestsNone,
		Hashed:     "None: a source-control pin is pinned by its commit.",
		NoDigest:   "Package.resolved records no checksum for a registry release (SwiftPM keeps it in its fingerprint storage)",
		Limits:     "Registry pins are unverified. Local packages (`localSourceControl`) are left out.",
		GitSources: true,
	},
	// dart
	"dart/pubspec.lock": {
		Files:      "`pubspec.lock`",
		Read:       "Every package with its `source` — `hosted` (the registry its description names), `git` (`resolved-ref`, the commit) — and `dependency: direct dev` as `dev`.",
		Digests:    DigestsSome,
		Hashed:     "`description.sha256`: the SHA-256 of the package archive (pub writes it from Dart 2.19 on).",
		NoDigest:   "pubspec.lock records no sha256 for this package (pub writes one from Dart 2.19 on)",
		Limits:     "`path` packages are left out, and `sdk` packages (part of the Dart or Flutter SDK) too. Transitive dependencies of dev dependencies are not marked `dev`: the file says only which direct ones are.",
		GitSources: true,
	},
	// julia
	"julia/Manifest.toml": {
		Files:      "`Manifest.toml`, `JuliaManifest.toml`, `Manifest-v<major>.<minor>.toml`",
		Read:       "Manifest format 2.x (`[[deps.<name>]]`) and 1.0 (top-level `[[<name>]]`): name, version, UUID (`id`) and tree hash; a package added from a repository (`repo-url`) is a Git dependency, pinned by its tree hash and, when `repo-rev` is one, its commit.",
		Digests:    DigestsAll,
		Hashed:     "`git-tree-sha1`: the SHA-1 of the Git tree of the package's source (`of: git-tree`), which Pkg checks whatever it was fetched from.",
		NoDigest:   "Manifest.toml records no tree hash for this package",
		Limits:     "Packages developed in place (`path`) are left out, and standard libraries (no tree hash) too: they ship with Julia.",
		GitSources: true,
	},
	// bazel
	"bazel/MODULE.bazel.lock": {
		Files: "`MODULE.bazel.lock`",
		Read: "lockFileVersion 11 and later (Bazel 7.2+): every module version whose `source.json` is in `registryFileHashes` — the versions selected; the others were read for version selection only. " +
			"Versions up to 10 (Bazel 6 to 7.1): `moduleDepGraph`, each module's archive URL and integrity. A section of the other layout, which that Bazel would not read, is refused; a key given twice in a map too (Bazel's Gson refuses it). Yanked versions selected all the same are a warning.",
		Digests:  DigestsAll,
		Hashed:   "13+: the SHA-256 of the module's `source.json` in the registry (`of: source.json`), which names the archive and its integrity, and of its `MODULE.bazel` (`of: MODULE.bazel`, which pins only the declaration). Up to 6: the archive's Subresource Integrity.",
		NoDigest: "MODULE.bazel.lock records no hash of this module's source",
		Limits:   "The repositories module extensions generate (`moduleExtensions`) are not read. The lock file does not record dev dependencies. Built-in modules (`bazel_tools`) are not in it, nor, in version 13 and later, modules overridden to a Git repository or a local path.",
	},
	// nix
	"nix/flake.lock": {
		Files: "`flake.lock`",
		Read: "Every locked input of the flake's graph: `github`, `gitlab`, `sourcehut` and `git` inputs are Git dependencies named by their flake reference (`github:NixOS/nixpkgs`) and versioned by their commit (by their NAR hash when locked without one); " +
			"`tarball` and `file` inputs are downloads named by their URL and versioned by their NAR hash.",
		Digests:    DigestsAll,
		Hashed:     "`narHash`: the SHA-256 of the NAR serialisation of the fetched source tree (`of: nar`), in SRI or in Nix's older base-32 form.",
		NoDigest:   "flake.lock records no NAR hash for this input",
		Limits:     "Inputs are sources, not the store paths the binary cache serves. `path` inputs are left out; Mercurial inputs are a warning.",
		GitSources: true,
	},
	// terraform
	"terraform/.terraform.lock.hcl": {
		Files:    "`.terraform.lock.hcl` (Terraform and OpenTofu)",
		Read:     "Every `provider` block: the address (`registry.terraform.io/hashicorp/random` → name `hashicorp/random` on that registry), the selected `version` and the `hashes`. A provider locked twice is refused, as Terraform refuses it.",
		Digests:  DigestsAll,
		Hashed:   "`zh:` — the SHA-256 of a file of the release's signed `SHA256SUMS`: each platform's zip, and the release's manifest.json (`of: terraform-zip`). `h1:` — Go's directory hash of one platform's unpacked package (`of: terraform-package`).",
		NoDigest: ".terraform.lock.hcl records no hash for this provider",
		Limits:   "Terraform records which hashes it has seen, not which platform each belongs to. Modules are not in the lock file (see `*.tf modules`).",
	},
	"terraform/*.tf modules": {
		Files: "`*.tf`, `*.tofu` — only those with `module` blocks are reported",
		Read: "Module blocks: a registry module (`namespace/name/system`, optionally behind a host, optionally a `//subdirectory` of it) pinned by an exact `version`; a module from Git (`git::…?ref=`, `github.com/…`) pinned by the commit its `ref` names — a tag or branch there is unverified; an archive URL, with go-getter's `?checksum=`. " +
			"The override files of the directory are applied as Terraform applies them (see `*.tf overrides`). Expressions that are not literal strings are skipped, never evaluated.",
		Digests:    DigestsSome,
		Hashed:     "Only an archive URL's `?checksum=` (the archive's hash). Terraform records no hash of registry modules.",
		NoDigest:   "Terraform records no hash of a module, only the version a module block pins",
		Limits:     "A version range, a Git source without `?ref=` (the default branch) and S3, GCS or Mercurial sources are warnings; local modules (`./x`) are left out. `*.tf.json` is not read. Each `.tf` file counts against the scan's limit on lock files.",
		GitSources: true,
	},
	"terraform/*.tf overrides": {
		Files:    "`override.tf`, `*_override.tf` (and `.tofu`)",
		Read:     "The module blocks of Terraform's override files, merged as Terraform merges them: by file name, an override's `source` or `version` replacing the module's of the same name in the directory's other files — whose dependency then says what Terraform installs.",
		Digests:  DigestsNone,
		Hashed:   "None: an override file yields no dependency of its own.",
		NoDigest: "Terraform records no hash of a module, only the version a module block pins",
		Limits:   "An override of a module no other file of the directory declares is a warning. `*_override.tf.json` is not read.",
	},
	// conan
	"conan/conan.lock": {
		Files: "`conan.lock`",
		Read: "Conan 2 (`version: 0.5`): `requires`, `build_requires`, `python_requires`, `config_requires`, each `name/version[@user/channel]#rrev%timestamp` (a user and channel go into `id`). " +
			"Conan 1 (`version: 0.4` and older): the `graph_lock` nodes, each with its recipe revision and, with revisions enabled, its package revision. The section the other Conan reads is refused.",
		Digests: DigestsSome,
		Hashed: "The recipe revision: in Conan's default mode the MD5 of the recipe's manifest (`of: conan-recipe`), which pins the recipe, not the binary package. " +
			"Conan 1's `prev`: the MD5 of the binary package's manifest (`of: conan-package`), which pins the package.",
		NoDigest: "conan.lock records no revision for this reference",
		Limits:   "A Conan 2 dependency is unverified: its binary package is chosen by package ID at install time and not locked. A recipe revision in `scm` mode is a commit, not a digest. The remote is not recorded.",
	},
	// cpan
	"cpan/cpanfile.snapshot": {
		Files:    "`cpanfile.snapshot` (Carton)",
		Read:     "Every distribution under `DISTRIBUTIONS`: name and version from its archive (`Try-Tiny` 0.31), its path under `authors/id/` as `id`.",
		Digests:  DigestsNone,
		NoDigest: "cpanfile.snapshot records no hash (the CHECKSUMS file of the author's directory on CPAN has one, the snapshot does not)",
		Limits:   "Every distribution is unverified. The snapshot does not say which distributions only tests need, nor which mirror they came from.",
	},
	// hackage
	"hackage/cabal.project.freeze": {
		Files:    "`cabal.project.freeze`",
		Read:     "The `constraints:` field (blanks allowed before the colon, as Cabal's lexer allows them): every `[qualifier.]name ==version`.",
		Digests:  DigestsNone,
		NoDigest: "cabal.project.freeze pins versions only (its index-state pins the package index, not the packages)",
		Limits:   "Every package is unverified. Flag settings and `installed`/`source` constraints pin no version; a range is a warning. Boot packages are pinned like the others: whether a build takes them from the compiler or from Hackage is not recorded.",
	},
	"hackage/stack.yaml.lock": {
		Files:      "`stack.yaml.lock`",
		Read:       "Every completed package, read in Pantry's order — a repository (`git`, `hg`), an archive URL, a Hackage package (`name-version@sha256:<hash>,<size>`), a GitHub shorthand — so the kind Stack fetches is the kind reported.",
		Digests:    DigestsAll,
		Hashed:     "`pantry-tree`: the SHA-256 of Pantry's list of the package's files and their hashes (`of: pantry-tree`), which pins the content. The `@sha256:` of a Hackage package hashes its .cabal file (`of: cabal-file`), pinning the revision of its description. An archive's own SHA-256.",
		NoDigest:   "stack.yaml.lock records no hash for this package",
		Limits:     "The packages of the resolver snapshot are not listed — the snapshot pins them, and the lock file pins the snapshot by its SHA-256; that is a warning.",
		GitSources: true,
	},
	// jsr
	"jsr/deno.lock": {
		Files: "`deno.lock`",
		Read: "Lock versions 1 (Deno before 1.28: module URL → hash) to 5, each by its own layout — a section of another version's layout, which Deno would ignore or let overwrite, is refused. JSR packages (type `jsr`), npm packages (type `npm`; a peer-dependency variant `x@1.0.0_peer@2` is x 1.0.0) and remote modules — each a URL, of type `generic` (a generic upstream fronts such hosts), " +
			"named by the URL without its scheme and versioned by its content hash. A key repeated at the top is refused, as Deno refuses it.",
		Digests:  DigestsAll,
		Hashed:   "JSR: the SHA-256 of the version's manifest on jsr.io (`of: jsr-manifest`), which lists the SHA-256 of every file. npm: the registry's Subresource Integrity. Remote modules: the SHA-256 of the file's bytes.",
		NoDigest: "deno.lock records no integrity for this package",
		Limits:   "The registry of npm packages is not recorded, except a `tarball` URL in version 5. `redirects` and `workspace` are not dependencies.",
	},
	// helm
	"helm/Chart.lock": {
		Files:    "`Chart.lock`, `requirements.lock` (an apiVersion v1 chart's)",
		Read:     "Every dependency with its exact version and repository: an HTTP chart repository or an OCI registry (`oci://…`). Read as Helm reads it — YAML 1.1 through encoding/json: keys match ignoring case (`Repository:` is the repository); a key given twice in different cases, or an unquoted name, version or repository that YAML 1.1 reads as a number, boolean or date (`1.10` becomes \"1.1\" to Helm), is refused.",
		Digests:  DigestsNone,
		Hashed:   "None. The top-level `digest` is the SHA-256 over Chart.yaml's dependency list and the locked versions — Helm's check that the lock is current — and pins no chart.",
		NoDigest: "Chart.lock records no digest of the chart archive (its digest covers the dependency list)",
		Limits:   "Every chart is unverified. `file://` charts are left out; a repository named by an alias of the user's Helm configuration (`@stable`) has no registry, with a warning.",
	},
	"helm/requirements.lock": {
		Files: "`requirements.lock` — Helm's for an apiVersion v1 chart, or Rye's (pip)",
		Read: "A YAML mapping is read as Helm's, exactly as `Chart.lock`; anything else as pip requirements (Rye writes its lock file under this name, `requirements-dev.lock` next to it) " +
			"and reported as `requirements.txt`, with that format's rules.",
		Digests:  DigestsNone,
		Hashed:   "None for charts, as `Chart.lock`. Read as pip requirements: the `--hash`es, when Rye was told to generate them.",
		NoDigest: "Chart.lock records no digest of the chart archive (its digest covers the dependency list)",
		Limits:   "As `Chart.lock`.",
	},
	// homebrew
	"homebrew/Brewfile.lock.json": {
		Files:      "`Brewfile.lock.json`",
		Read:       "`entries.brew` (formulae with every platform's bottle), `entries.cask`, and `entries.tap` (Git dependencies pinned by the tap's commit). `brew bundle` wrote the file from 2019 until November 2024 (Homebrew 4.4.8 was the last release that did); committed ones remain.",
		Digests:    DigestsSome,
		Hashed:     "A bottle's `sha256`: the SHA-256 of the bottle tarball, which is also its blob digest on ghcr.io (`of`: the bottle's file name, one per platform).",
		NoDigest:   "Brewfile.lock.json records no hash for this entry",
		Limits:     "Casks and formulae built from source (`bottle: false`) are unverified. `mas`, `whalebrew` and `vscode` entries are not Homebrew packages: a warning. A tap's repository is assumed on GitHub.",
		GitSources: true,
	},
	// ansible
	"ansible/requirements.yml": {
		Files: "`requirements.yml`, `requirements.yaml` — only those that yield something are reported (Helm 2 charts use the name too)",
		Read: "Collections and roles pinned to one version (`8.6.0`, `==8.6.0`), in the `collections:`/`roles:` layout and the older top-level list of roles (`src`, `name`, `role`); Git sources (`type: git` — a `,ref` after the URL wins over `version`, as ansible-galaxy reads it; `scm: git`; `git+`; a GitHub http URL) and URL archives. " +
			"Ansible has no lock file: a requirements file is the only place versions are pinned.",
		Digests:    DigestsNone,
		NoDigest:   "requirements.yml records no hash (Galaxy publishes the artifact's SHA-256, the requirements file does not)",
		Limits:     "Every Galaxy entry is unverified, and a Git source pinned to a tag. A range, `*` or no version is a warning; local sources are left out.",
		GitSources: true,
	},
	// puppet
	"puppet/Puppetfile": {
		Files: "`Puppetfile`",
		Read: "`forge` and `mod` declarations: Forge modules with an exact version (`puppetlabs/stdlib` → `puppetlabs-stdlib`), Git modules (`:git` with `:commit`, `:ref`, `:tag`, `:version` — the last given wins, as r10k folds them into one ref), r10k tarball modules. " +
			"Puppet has no lock file. A Puppetfile is Ruby that r10k evaluates: any statement other than such a declaration with literal arguments is a warning, never evaluated.",
		Digests:    DigestsSome,
		Hashed:     "Only a tarball module's `version`, which r10k checks as the archive's SHA-256.",
		NoDigest:   "a Puppetfile records no hash (the Forge publishes the release's checksums, the Puppetfile does not)",
		Limits:     "Every Forge module is unverified, and a Git module pinned to a tag. `:latest`, no version, or a `:branch` is a warning; `:local` modules are left out.",
		GitSources: true,
	},
	// git
	"git/.gitmodules": {
		Files: "`.gitmodules` at the root of the tree",
		Read: "Every `[submodule]` section's `path` and `url`, in git's configuration syntax as git's parser reads it (`[submodule.a \"b\"]` names submodule `a.b`; only space, tab, CR and LF are blanks); each submodule is pinned to the commit of the gitlink (tree entry of mode 160000) at exactly its path, " +
			"looked up in the tree even where a skip glob keeps the walk out (a submodule in `third_party/` is still this repository's dependency), each tree object read once per level whatever the number of paths through it, within the scan's tree-entry limit. The name of the dependency is the submodule's path.",
		Digests:  DigestsNone,
		Hashed:   "None: the gitlink's commit ID pins the submodule.",
		NoDigest: "a submodule is pinned by its gitlink's commit, not by a digest",
		Limits: "A submodule without a gitlink, one whose `path` or `url` is given twice (git commands disagree on which counts), a name git ignores (`..`), a value starting with `-`, " +
			"a local-path or remote-helper (`ext::`) URL is a warning. A gitlink no declaration names is reported as skipped. A URL relative to the superproject's remote (`../x.git`) is kept as written.",
		GitSources: true,
	},
}

// Formats returns the description of every format of the registry, in the
// registry's order. A parser without a description gets one with only its
// type and format.
func (r *Registry) Formats() []FormatInfo {
	out := make([]FormatInfo, 0, len(r.parsers))
	for _, p := range r.parsers {
		out = append(out, describe(p))
	}
	return out
}

// describe returns the description of a parser's format.
func describe(p Parser) FormatInfo {
	info := formatInfo[p.Type()+"/"+p.Format()]
	info.Type, info.Format = p.Type(), p.Format()
	return info
}

// DigestKind is a value of Digest.Of: what a digest is a hash of.
type DigestKind struct {
	Of      string `json:"of"`
	Meaning string `json:"meaning"`
	// PinsContent is false for a digest of a document next to the artifact
	// (a go.mod, a module's MODULE.bazel): a dependency with only such
	// digests is unverified.
	PinsContent bool `json:"pinsContent"`
	// Unverified is the reason given on a dependency whose only digests are
	// of this kind.
	Unverified string `json:"-"`
}

// digestKinds are the values of Digest.Of the parsers write. Any other value
// is the name of the distribution file hashed (a wheel, a platform build),
// which pins that file.
var digestKinds = []DigestKind{
	{Of: "", Meaning: "The artifact the registry serves for the coordinate.", PinsContent: true},
	{Of: "go.mod", Meaning: "Only the module's go.mod file, not its code.",
		Unverified: "go.sum hashes only this module's go.mod: its code is not pinned (the build does not download it)"},
	{Of: "yarn-cache", Meaning: "The zip Yarn Berry builds from the tarball in its own cache.", PinsContent: true},
	{Of: "nuget-content", Meaning: "The package as NuGet hashes it, without a signed package's signature file.", PinsContent: true},
	{Of: "hex-inner", Meaning: "Hex's inner checksum: what the release tarball holds (its VERSION, metadata.config and contents.tar.gz), not the tarball's bytes.", PinsContent: true},
	{Of: "git-tree", Meaning: "The Git tree object of the package's source (Julia's git-tree-sha1).", PinsContent: true},
	{Of: "nar", Meaning: "The NAR serialisation of a fetched source tree (Nix's narHash).", PinsContent: true},
	{Of: "jsr-manifest", Meaning: "The JSR version manifest (`<version>_meta.json`), which lists the SHA-256 of every file of the version.", PinsContent: true},
	{Of: "source.json", Meaning: "A Bazel module's source.json in its registry, which names the archive and its integrity.", PinsContent: true},
	{Of: "MODULE.bazel", Meaning: "Only a Bazel module's MODULE.bazel declaration, not its source.",
		Unverified: "MODULE.bazel.lock hashes only this module's declaration, not its source"},
	{Of: "terraform-zip", Meaning: "A file of a Terraform provider release's SHA256SUMS: one platform's zip (or the release's manifest.json).", PinsContent: true},
	{Of: "terraform-package", Meaning: "The directory hash of one platform's unpacked Terraform provider package.", PinsContent: true},
	{Of: "pantry-tree", Meaning: "Pantry's tree of a Haskell package: the list of its files and their hashes.", PinsContent: true},
	{Of: "cabal-file", Meaning: "Only the revision of a Haskell package's .cabal file, not its source.",
		Unverified: "stack.yaml.lock hashes only this package's .cabal file, not its source"},
	{Of: "conan-recipe", Meaning: "The manifest of a Conan recipe: the recipe, not the binary package built from it.",
		Unverified: "conan.lock pins the recipe revision, not the binary package the client downloads"},
	{Of: "conan-package", Meaning: "The manifest of a Conan binary package (Conan 1's package revision).", PinsContent: true},
}

// DigestKinds returns the documented values of Digest.Of, sorted.
func DigestKinds() []DigestKind {
	out := append([]DigestKind(nil), digestKinds...)
	sort.Slice(out, func(i, j int) bool { return out[i].Of < out[j].Of })
	return out
}

// digestKindOf returns the kind of a Digest.Of value; a value not listed is
// the file name of a distribution file, which pins that file.
func digestKindOf(of string) DigestKind {
	for _, k := range digestKinds {
		if k.Of == of {
			return k
		}
	}
	return DigestKind{Of: of, PinsContent: true}
}

// markVerification sets Unverified on a dependency whose content nothing in
// the lock file pins: no digest of the artifact (or of a manifest that hashes
// it), and for a Git dependency no commit. A reason the parser gave is kept.
func markVerification(d *Dependency, info FormatInfo) {
	if d.Source == SourceGit && isCommitID(d.Revision) {
		d.Unverified, d.UnverifiedReason = false, ""
		return
	}
	partial := ""
	for _, dg := range d.Digests {
		k := digestKindOf(dg.Of)
		if k.PinsContent {
			d.Unverified, d.UnverifiedReason = false, ""
			return
		}
		if partial == "" {
			partial = k.Unverified
		}
	}
	d.Unverified = true
	switch {
	case d.UnverifiedReason != "":
	case partial != "":
		d.UnverifiedReason = partial
	case d.Source == SourceGit:
		d.UnverifiedReason = "a Git dependency pinned to a branch or tag, not to a commit"
	case info.NoDigest != "":
		d.UnverifiedReason = info.NoDigest
	default:
		d.UnverifiedReason = "the lock file records no digest for it"
	}
}

// gitSourceFormats returns the formats that record Git dependencies.
func gitSourceFormats(r *Registry) []string {
	var out []string
	for _, f := range r.Formats() {
		if f.GitSources {
			out = append(out, f.Format)
		}
	}
	return out
}

// joinFormats lists formats in Markdown code spans.
func joinFormats(formats []string) string {
	quoted := make([]string, len(formats))
	for i, f := range formats {
		quoted[i] = "`" + f + "`"
	}
	return strings.Join(quoted, ", ")
}
