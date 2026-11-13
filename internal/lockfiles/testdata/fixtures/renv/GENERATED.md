# renv

Generated 2026-11-13 with renv 1.3.1 on R 4.6.2 in a throwaway container. renv 1.3.1 is what
`install.packages("renv")` got from the image's CRAN mirror. Neither lock file was edited afterwards.

- Tool: renv 1.3.1, R 4.6.2.
- Image: `docker.io/rocker/r-ver:4` (R 4.6.2, Ubuntu 26.04), digest
  `sha256:8739c76d2d9316698a7145b032601f1e82249fdee34670d7b4a0a40d6bacd95a`. Its `Rprofile.site`
  sets `options(repos = c(CRAN = "https://p3m.dev/cran/__linux__/resolute/latest"))` and an R user
  agent, so the CRAN packages were installed as Posit Package Manager (P3M) Linux binaries.
  crayon was built from the source tarball renv fetched from api.github.com.
- Deviation: the requested `rocker/r-ver:4.4` pins its CRAN mirror to the frozen P3M snapshot
  `https://p3m.dev/cran/__linux__/noble/2025-04-10`, which would have given an April-2025 renv.
  The latest 4.x image was used instead.
- Commands (DESCRIPTION was hand-written first):

      podman run --rm -v <scratch>:/work -w /work/proj -e RENV_PATHS_ROOT=/work/renv-root \
        docker.io/rocker/r-ver:4 bash -c '
          Rscript -e "install.packages(\"renv\")"
          Rscript -e "renv::init(bare = TRUE)"
          Rscript -e "renv::install(c(\"jsonlite\", \"R6\", \"glue\", \"lifecycle\", \"praise\"))"
          Rscript -e "renv::install(\"r-lib/crayon@v1.5.3\")"
          Rscript -e "renv::snapshot()"
          RENV_LOCKFILE_VERSION=1 Rscript -e "renv::snapshot(lockfile = \"renv-v1.lock\")"'

  renv resolves GitHub refs and downloads GitHub tarballs through the unauthenticated GitHub
  REST API (60 requests/hour per IP). The first attempts on 2026-11-12 failed with HTTP 403
  because the shared IP had used up that quota. The run above happened after it reset.

Manifest (DESCRIPTION, `Type: project`): `Imports` are jsonlite, R6, glue, lifecycle and crayon,
`Suggests` is praise, and `Remotes` is `r-lib/crayon@v1.5.3`.

Files: `renv.lock` is what `renv::snapshot()` writes by default. `renv-v1.lock` is the same
project snapshotted again with `RENV_LOCKFILE_VERSION=1`, renv's switch for the older compact
records.

Notable features of renv.lock:
- JSON with 2-space indent, LF and a trailing newline. The top level has `R` and `Packages`.
  `R` is `{"Version": "4.6.2", "Repositories": [{"Name": "CRAN", "URL": "https://p3m.dev/cran/latest"}]}`;
  the binary URL configured in the image appears as `https://p3m.dev/cran/latest`. `Packages` is an
  object keyed by package name. There is no lockfile-format version field anywhere, so only the
  record shape distinguishes this from `renv-v1.lock`.
- 8 records: R6 2.6.1, cli 3.6.6, crayon 1.5.3, glue 1.8.1, jsonlite 2.0.0, lifecycle 1.0.5,
  renv 1.3.1 and rlang 1.3.0. cli and rlang come in through lifecycle, and renv records itself.
  praise was installed into the project library but is not recorded. renv's NEWS for 1.0.0
  says `snapshot()` no longer tracks development dependencies and that `Suggests` in
  DESCRIPTION are development dependencies (#1019). Dev-only packages are left out of the
  lock, not marked in it.
- Records are "v2" records (the default since renv 1.1.0, #2057). Package, Version and Source
  come first, then the installed package's DESCRIPTION fields in DESCRIPTION order: Title,
  Authors@R, Description, License, URL, BugReports, Author, Maintainer, Encoding,
  NeedsCompilation, Config/*, RoxygenNote and so on. Per `renv_snapshot_description_impl_v2`,
  renv drops Archs, Built, Date/Publication, File, MD5sum, Packaged and `Github*`, plus the
  `Remote*` fields of CRAN-like packages. Depends, Imports, Suggests, LinkingTo and Enhances
  become JSON arrays of strings that keep the version constraint (`"R (>= 3.6)"`,
  `"cli (>= 3.4.0)"`). Every other field is a string (`"VignetteBuilder": "knitr, R.rsp"`).
- **No record has a `Hash` or a `Requirements` field.** Since renv 1.1.0 the default
  v2 record builder writes no Hash. In the CRAN archive sources, renv 1.0.11
  (2024-10-12) sets `Hash` on every record, while renv 1.1.0 (2025-01-29) adds
  `renv.lockfile.version` (default 2) and a v2 builder that never sets it.
- Repository packages have `"Source": "Repository"`. The six that renv installed have
  `"Repository": "CRAN"`. renv puts `RemoteReposName: CRAN` into their installed DESCRIPTION,
  and the snapshot prefers that over the binary's own `Repository: RSPM`. renv itself was
  installed by `install.packages()` and has `"Repository": "RSPM"`, which matches no `Name` in
  `R.Repositories`.
- The GitHub record crayon has `"Source": "GitHub"`, `"RemoteType": "github"`,
  `"RemoteHost": "api.github.com"`, `"RemoteUsername": "r-lib"`, `"RemoteRepo": "crayon"`,
  `"RemoteRef": "v1.5.3"` and `"RemoteSha": "acaa229926a3ee0ffe6dd5509cce1726f2d33fec"`, and no
  `Repository`. v1.5.3 is a lightweight tag (`git ls-remote` lists `refs/tags/v1.5.3` →
  acaa2299... with no `^{}` entry), so RemoteSha is the tagged commit. The commit is the only
  pin: nothing records a digest of the tarball fetched from api.github.com.

Notable features of renv-v1.lock (same `R` section, same 8 packages):
- The records are compact: Package, Version, Source, Repository, Requirements and Hash. crayon
  has the six `Remote*` fields above instead of Repository.
- `Requirements` is the sorted set of package names from Depends, Imports and LinkingTo, without
  versions. It includes `R` and base packages (grDevices, methods, utils), none of which has a
  record.

What `Hash` is (renv-v1.lock here, and the default records of older renv: checked in the
renv 0.8.0 and 1.0.11 sources and in renv 0.12.5's output):
- It is renv's MD5 over DESCRIPTION metadata (`renv_hash_record` / `renv_hash_fields` in renv 1.3.1):
  - Take the fields Package, Version, Title, Author, Maintainer, Description, Depends,
    Imports, Suggests and LinkingTo.
  - Add every `Remote*` field, except for a CRAN-like package (RemoteType absent, `cran`,
    `repository` or `standard`) whose RemoteSha is shorter than 40 characters. Drop
    RemoteRef when it is `HEAD`.
  - Join list values with ", ", sort the field names in C locale and write `Name: value`
    lines joined by "\n".
  - Delete every whitespace character, then take the MD5 of the UTF-8 bytes plus one
    trailing "\n".
- A Python reimplementation reproduces all 8 Hash values in renv-v1.lock from the installed
  DESCRIPTION files. It also reproduces them from the v2 records in renv.lock alone, because
  those records carry every hashed field.
- It is not a digest of any archive. For jsonlite 2.0.0 the Hash is
  b0776f526d36d8bd4a3344a88fe165c4. The CRAN source tarball `jsonlite_2.0.0.tar.gz` has md5
  3e54e6fbc0c9063936e3d01e91419c14, which is also the `MD5sum` in CRAN's `src/contrib/PACKAGES`.
  The P3M binary renv installed has md5 1b5655741cdfb7a5537f01fecd453060. Hashing the
  DESCRIPTION inside either tarball gives b0776f52..., because the fields where they differ
  (Repository, Built) are not hashed.
- For every package except renv itself, the Hash values equal the ones renv 0.12.5 wrote in
  the `renv-old` fixture.
- None of the files contains a path, user name or credential.

In this fixture `renv-v1.lock` is saved, byte for byte, as `v1/renv.lock`: the scanner detects a renv
lock file by its name, and the second lock file of the project needs a directory of its own.
