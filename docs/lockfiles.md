# Lock files: the exact dependencies of a repository

The lock-file scanner (`internal/lockfiles`, Task 178) reads a Git repository at a commit,
finds every lock file in it and turns each into the exact dependencies it pins. It is the
groundwork for what follows it: pinning a release's artifacts, scanning every dependency of a
repository, and proposing safe updates. Today it is available as a library and as
`ptctl lockfiles scan`.

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
| `type` | The upstream type it is fetched through: `npm`, `pip`, `cargo`, `go`, `nuget`, `maven`, `rubygems`, `composer`, `docker`. |
| `name` | The package name, spelled as the proxy's backend names it: as written for npm, Cargo, Go, Composer and RubyGems; PEP 503-normalised for pip (`charset-normalizer`); lower-cased for NuGet; `group:artifact` for Maven; the repository path for Docker (`library/alpine`). |
| `version` | The exact version, as the lock file writes it. A RubyGems platform gem keeps its platform (`1.16.7-x86_64-linux`, a separate artifact); a Docker image's version is its manifest digest; a Git dependency without a package version gets its commit. |
| `digests` | The integrity values the lock file records, normalised to `algorithm` + lower-case hex (`h1` for Go keeps its base64). `of` says what was hashed when it is not simply the artifact: a Python distribution file name (each wheel and the sdist has its own hash), `go.mod`, `yarn-cache` (Yarn Berry hashes the zip in its own cache, not the npm tarball) or `nuget-content` (NuGet's content hash leaves a signed package's signature out, so it is not the hash of the `.nupkg` bytes served). |
| `registry` | Where the lock file says the dependency comes from: the registry or index URL, or the repository URL of a Git dependency. Empty when the lock file does not say (pnpm, Yarn Berry, poetry for PyPI, go.mod, NuGet, Gradle); the client's configured default then applies. |
| `url` | The download URL the lock file records, when it records one. |
| `upstream` | The proxy upstream the lock file's URLs point at, when it was resolved through this proxy (see below). |
| `source` | `""` (a registry), `git` (a repository; `revision` is the commit) or `url` (a direct download). |
| `revision` | The commit a Git dependency is pinned to; Composer records one for every package. |
| `dev` | Development-only, where the format says so (package-lock.json, pnpm v5/v6, Pipfile.lock, poetry, pdm, composer.lock, Gradle test configurations, Maven `test` scope). |
| `file`, `line` | The lock file's path in the repository and the line the entry starts on. |

Every URL is stored without its credentials, query string and fragment. Entries a format
lists more than once (one package version at several places in `node_modules`, or under
several NuGet target frameworks) are one dependency.

## Formats

| Type | Files | Read |
| ---- | ----- | ---- |
| `npm` | `package-lock.json`, `npm-shrinkwrap.json` | lockfileVersion 1 (the nested `dependencies` tree), 2 and 3 (`packages`); aliases resolve to the real package; a tarball URL that is not a registry's `/<name>/-/` download is `source: url`; workspace folders, `link`s, bundled and `file:` packages are not fetched and are left out. |
| `npm` | `yarn.lock` | Yarn Classic (`# yarn lockfile v1`; registry, sha1 from the `resolved` fragment, `integrity`) and Yarn Berry (`__metadata` version 6 to 10; `npm:` resolutions, `checksum`); `workspace:`, `patch:`, `file:`, `link:`, `portal:` and `exec:` entries are left out. |
| `npm` | `pnpm-lock.yaml` | lockfileVersion 5.x, 6.x and 9.x (each spells package keys differently), registry tarballs, Git and tarball-URL dependencies; every YAML document — pnpm 10 and later write two when the project pins its package manager, the package manager's own installation first. |
| `pip` | `requirements*.txt`, `*-requirements.txt`, `constraints.txt`, `requirements/*.txt` | `==` and `===` pins with their `--hash`es, the `--index-url`, direct URLs and VCS references pinned to a commit. A range, a wildcard, an editable local path is a warning. `-r`/`-c` includes are not followed — the scan reads those files on its own. |
| `pip` | `Pipfile.lock` | `default` and `develop`, the index each entry names, Git and file entries. |
| `pip` | `poetry.lock` | lock-version 1.x (`[metadata.files]`, `category`) and 2.x (inline `files`, `groups`), `[package.source]`. |
| `pip` | `uv.lock` | registry, Git and URL sources with every sdist and wheel hash; the project's own (`editable`, `virtual`, `directory`) packages are left out. |
| `pip` | `pdm.lock` | lock_version 4.x with inline `files`, and the older `[metadata.files]` keyed `"<name> <version>"`. |
| `cargo` | `Cargo.lock` | format v1 (checksums in `[metadata]`) to v4; `registry+`, `sparse+` and `git+` sources; workspace crates are left out. |
| `go` | `go.mod`, `go.sum` | go.mod's requirements after its `replace` directives (a local-directory replacement is not fetched); go.sum's `h1:` hashes are merged into the go.mod of the same directory, and a module only go.sum names stays a dependency of its own. `/go.mod`-only lines are hashes of go.mod files, not of code that is downloaded. |
| `nuget` | `packages.lock.json`, `packages.<project>.lock.json` | every target framework; `Project` references are left out. |
| `maven` | `gradle.lockfile`, `*-gradle.lockfile`, `gradle/dependency-locks/*.lockfile` | every module; dependencies only test configurations use are `dev`. Gradle records no hashes. |
| `maven` | `pom.xml` | Fixed versions only: a literal, or a property defined in the same POM (`${guava.version}`, `${project.version}`). Read: the parent, `<dependencies>` (profiles too), build plugins and their dependencies, BOMs imported in `<dependencyManagement>`. A version managed elsewhere, a range, a `SNAPSHOT`, `LATEST`/`RELEASE` or an undefined property is a warning. The registry is the one `<repository>` named (plugins: the one `<pluginRepository>`), if just one is. |
| `rubygems` | `Gemfile.lock`, `gems.locked` | `GEM` and `GIT` sections, every platform variant, Bundler's `CHECKSUMS`; `PATH` gems are left out. Gemfile.lock does not record groups. |
| `composer` | `composer.lock` | `packages` and `packages-dev`, the dist URL and its `shasum` (Packagist leaves it empty for GitHub archives), the commit; `path` packages are left out. |
| `docker` | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile` | `FROM` images and `COPY --from=<image>`, with global `ARG` defaults expanded; earlier stages, `scratch` and heredoc bodies are not images (a heredoc is opened as BuildKit opens one: an unquoted `[n]<<[-]WORD` word of `RUN`, `COPY` or `ADD`; one never closed is a warning). |
| `docker` | `compose.yaml`, `docker-compose.yml` and their `.<variant>.yml` forms | every service's `image`, through YAML anchors and `<<` merges and `${VAR:-default}`, in the current and the version 1 layout. |

Only images pinned by digest are dependencies: a tag can be moved, so an image without a
digest is a warning. `ptctl lockfiles formats` prints the same table from the code.

**Read as the package manager reads it.** A lock file edited to show a scanner one artifact
while the package manager installs another must not succeed, so each format is read with its
tool's semantics. JSON keys match exactly (not case-insensitively, as Go's struct decoding
would) and a repeated key or entry keeps its last value, as `JSON.parse`, Python's `json` and
PHP's `json_decode` do. YAML lock files (`pnpm-lock.yaml`, Yarn Berry's `yarn.lock`) with an
anchor, an alias, a merge key or a key repeated in one mapping are refused with an error: no
tool writes them, and pnpm's and Yarn's own readers would give them a meaning. Compose files may
use anchors and `<<` merges (followed with a work budget) but not repeated keys, which Compose
refuses too. go.sum `h1:` values are accepted only as the base64 of a SHA-256.

### Types without a parser

Every upstream type the proxy fronts either has a parser or an entry saying why not
(`internal/lockfiles/coverage.go`); a test fails when a type is added without either.

| Type | Why |
| ---- | --- |
| `git` | No lock file: a repository pins another with a submodule, a gitlink in its tree. The scan reports submodules separately. |
| `apt` | No lock file: packages come from repository indexes at build time. |
| `yum` | No lock file: packages come from repository metadata at build time. |
| `generic` | No format known in advance: a generic upstream serves whatever routes its operator declares. |
| `huggingface` | No lock file: models and datasets are named by repository and revision in code. |
| `openvsx` | No lock file: `.vscode/extensions.json` recommends extensions without versions. |
| `nix` | `flake.lock` pins flake inputs (sources), not the store paths the binary cache serves. |
| `homebrew` | No lock file in current use. |
| `helm` | `Chart.lock` — not parsed yet. |
| `terraform` | `.terraform.lock.hcl` — not parsed yet. |
| `conan` | `conan.lock` — not parsed yet. |
| `swift` | `Package.resolved` — not parsed yet. |
| `dart` | `pubspec.lock` — not parsed yet. |
| `conda` | conda-lock files, `pixi.lock`, `@EXPLICIT` spec files — not parsed yet. |
| `cran` | `renv.lock` — not parsed yet. |
| `hex` | `mix.lock` — not parsed yet. |
| `bazel` | `MODULE.bazel.lock` — not parsed yet. |
| `julia` | `Manifest.toml` — not parsed yet. |
| `cpan` | `cpanfile.snapshot` (Carton) — not parsed yet. |
| `jsr` | `deno.lock` — not parsed yet. |
| `hackage` | `cabal.project.freeze`, `stack.yaml.lock` — not parsed yet. |
| `ansible` | No lock file; exact pins in `requirements.yml` are not parsed yet. |
| `puppet` | No lock file; exact pins in a `Puppetfile` are not parsed yet. |

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

The table lists every dependency with its location; `--json` prints the full report
(`commit`, `files[]` with `dependencies`, `warnings` and `error`, `skipped`, `submodules`,
`truncated`, `stats`). A lock file that cannot be read is reported with its error; the scan
goes on.

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
  2.5 and 2.29, Cargo, Go, the .NET SDK, Gradle, Bundler and Composer — and by hand for what
  no current tool writes (Cargo's v1 format, a nested npm v1 tree, a POM, Dockerfiles,
  lock files resolved through the proxy). `testdata/golden/<fixture>.json` is the expected
  output; `go test ./internal/lockfiles/ -run TestGolden -update` rewrites it.
- The walk is tested on real repositories: every fixture committed into one monorepo must
  read exactly as the golden files say; skip globs, depth, size and count limits, symbolic
  links, submodules, a subdirectory, an older commit and a size-filtered partial clone each
  have a test.
