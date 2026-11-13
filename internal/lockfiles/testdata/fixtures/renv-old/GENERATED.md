# renv-old

Generated 2026-11-13 with renv 0.12.5 (published on CRAN 2021-01-09), installed from the CRAN
archive and run on R 4.6.2 in a throwaway container. renv.lock was not edited afterwards.

- Tool: renv 0.12.5, installed from source with
  `install.packages("https://cran.r-project.org/src/contrib/Archive/renv/renv_0.12.5.tar.gz", repos = NULL, type = "source")`.
  R 4.6.2.
- Image: `docker.io/rocker/r-ver:4` (R 4.6.2, Ubuntu 26.04), digest
  `sha256:8739c76d2d9316698a7145b032601f1e82249fdee34670d7b4a0a40d6bacd95a`. This is the same image,
  repository setup and DESCRIPTION as the `renv` fixture, so only the renv version differs. The
  image's `Rprofile.site` points CRAN at `https://p3m.dev/cran/__linux__/resolute/latest`, so the
  CRAN packages were installed as P3M Linux binaries. crayon came from
  `https://api.github.com/repos/r-lib/crayon/tarball/acaa229926a3ee0ffe6dd5509cce1726f2d33fec`.
- Commands:

      podman run --rm -v <scratch>:/work -w /work/proj -e RENV_PATHS_ROOT=/work/renv-root \
        docker.io/rocker/r-ver:4 bash -c '
          Rscript -e "install.packages(\"https://cran.r-project.org/src/contrib/Archive/renv/renv_0.12.5.tar.gz\", repos = NULL, type = \"source\")"
          Rscript -e "renv::init(bare = TRUE)"
          Rscript -e "renv::install(c(\"jsonlite\", \"R6\", \"glue\", \"lifecycle\", \"praise\"))"
          Rscript -e "renv::install(\"r-lib/crayon@v1.5.3\")"
          Rscript -e "renv::snapshot()"'

Manifest: DESCRIPTION, byte-identical to the `renv` fixture's (`Imports` jsonlite, R6, glue,
lifecycle and crayon; `Suggests` praise; `Remotes` `r-lib/crayon@v1.5.3`).

Notable features of renv.lock:
- The layout is the same as the current one: JSON with 2-space indent, LF and a trailing newline.
  The top level has `R` (`{"Version": "4.6.2", "Repositories": [{"Name": "CRAN", "URL": "https://p3m.dev/cran/latest"}]}`)
  and `Packages`, an object keyed by package name. There is no format version field.
- 8 records, the same packages and versions as in the `renv` fixture except renv itself (0.12.5).
  praise, a `Suggests`-only package, was installed but is not recorded here either.
- The records are compact. The 7 repository packages have exactly Package, Version, Source,
  Repository and Hash. crayon has Package, Version, `"Source": "GitHub"`,
  `"RemoteType": "github"`, `"RemoteHost": "api.github.com"`, `"RemoteUsername": "r-lib"`,
  `"RemoteRepo": "crayon"`, `"RemoteRef": "v1.5.3"`,
  `"RemoteSha": "acaa229926a3ee0ffe6dd5509cce1726f2d33fec"` (the commit of the lightweight tag
  v1.5.3) and Hash. Compared with the current format there is no `Requirements` (NEWS: added
  in renv 0.15.0) and no DESCRIPTION fields (added in 1.1.0).
- **All 7 repository packages say `"Repository": "RSPM"`**, which matches no `Name` in
  `R.Repositories` (only `CRAN`). It is the `Repository:` field of the installed P3M binaries'
  DESCRIPTION. jsonlite's binary DESCRIPTION says `Repository: RSPM`, while its CRAN source
  tarball's says `Repository: CRAN`. renv 1.3.1 maps these to `CRAN` through the
  `RemoteReposName` it writes at install time; renv 0.12.5 writes no such field.
- **Every record has `Hash`.** Old lock files do not lack it; the current default (renv ≥ 1.1.0)
  does. renv 0.8.0, the first CRAN release (2019-10-25), already writes it in
  `renv_snapshot_description` and documents it as "(Optional) A unique hash for this package,
  used for package caching".
- `Hash` is renv's MD5 over DESCRIPTION metadata, not of any archive. renv 0.12.5's
  `renv_hash_description_impl` takes Package, Version, Title, Author, Maintainer,
  Description, Depends, Imports, Suggests and LinkingTo. It adds all `Remote*` fields unless
  RemoteType is missing or `standard`. It sorts the names in C locale, joins `Name: value`
  lines with "\n", deletes all whitespace, writes the result with `writeLines` (which adds a
  trailing "\n") and takes the MD5 of that file. A Python reimplementation reproduces all 8
  values from the installed DESCRIPTION files.
- The values equal the Hash that renv 1.3.1 writes in v1 records for the same packages (all
  except renv itself, whose version differs), including crayon's 8af0d47f0e56d77af7752d1f629e72f8.
  For jsonlite 2.0.0, Hash b0776f526d36d8bd4a3344a88fe165c4 differs from the md5 of the CRAN
  source tarball (3e54e6fb...) and of the P3M binary (1b565574...); see the `renv` fixture.
- The file contains no path, user name or credential.
