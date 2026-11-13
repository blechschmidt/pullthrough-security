# pixi

Generated 2026-11-12 with pixi 0.84.2 in a throwaway container. Neither file was edited
afterwards. pixi wrote pixi.toml itself (`pixi init`, then each `pixi add` updated it).

- Tool: pixi 0.84.2, the static `pixi-x86_64-unknown-linux-musl` binary from the GitHub release
  v0.84.2 (`releases/latest/download/...` redirected there). Its SHA-256
  6d2a576bde0a7b26533a068fec0aea6e4ee21c36668efc1dc73fce90110906ae matches the release's `.sha256` file.
- Image: `docker.io/condaforge/miniforge3:latest`, digest
  `sha256:0a788afa8b54165d855d08552ce6d86e1e2553be2a9a18d542c69cfb02a6deaa`. It was only used as a
  glibc userland for the static pixi binary, which was mounted into the container.
- Commands:

      podman run --rm -v <pixi-bin>:/opt/pixi-bin:ro -v <scratch>:/work -w /work/proj \
        -e PIXI_CACHE_DIR=/work/cache -e PIXI_HOME=/work/pixi-home -e PIXI_NO_PROGRESS=true \
        docker.io/condaforge/miniforge3:latest bash -c '
          export PATH=/opt/pixi-bin:$PATH
          pixi init -c conda-forge -p linux-64 -p osx-arm64
          pixi add python=3.12 zlib
          pixi add --pypi "six==1.16.0"
          pixi add --pypi --git https://github.com/hukkin/tomli.git --tag 2.0.1 tomli
          pixi add --feature dev jq
          pixi workspace environment add dev --feature dev
          pixi lock'

  `pixi add` also installed the default environment under `.pixi/`. That directory, plus the
  `.gitattributes` and `.gitignore` written by `pixi init`, were not kept. `.gitattributes` marks
  pixi.lock `merge=binary linguist-language=YAML linguist-generated=true -diff`.

Manifest (pixi.toml): `[workspace]` has `channels = ['conda-forge']`, `name = "proj"` (taken from
the directory name) and `platforms = ['linux-64', 'osx-arm64']`. `[dependencies]` has
`python = "3.12.*"` and `zlib = ">=1.3.2,<2"`; pixi turned the bare `zlib` into a range.
`[pypi-dependencies]` has `six = "==1.16.0"` and
`tomli = { git = "https://github.com/hukkin/tomli.git", tag = "2.0.1" }`. The rest is
`[feature.dev.dependencies] jq = "*"` and `[environments] dev = ["dev"]`.

Notable features of pixi.lock:
- `version: 7`. Top-level keys are `version`, `platforms`, `environments` and `packages`.
  `platforms` lists each platform with the virtual packages assumed for solving: linux-64 gets
  `__unix=0`, `__linux=4.18`, `__glibc=2.28` and `__archspec=0=x86_64`; osx-arm64 gets
  `__unix=0`, `__osx=13.0` and `__archspec=0=m1`.
- `environments.default` and `environments.dev` each have `channels: [{url: https://conda.anaconda.org/conda-forge/}]`,
  `indexes: [https://pypi.org/simple]` and `packages: {linux-64: [...], osx-arm64: [...]}`. Those
  per-platform lists hold references only: `- conda: <url>` or `- pypi: <url>`.
  default has 25 entries for linux-64 and 17 for osx-arm64 (2 of them pypi in each). dev has 27
  and 19: everything in default plus jq 1.8.2 and oniguruma 6.9.10. Dev-only is expressed only
  by environment membership. Package records carry no group or optional flag.
- `packages`: 42 records, one per distinct URL. That is 40 conda records (the noarch
  ca-certificates and tzdata are shared by both platforms and listed once) and 2 pypi records.
- **Conda records have no `name`, `version` or `build` keys.** Keys are `conda` (the URL),
  `sha256`, `md5`, `depends`, `constrains` (sometimes), `license`, `license_family` (25 of 40),
  `purls` (always `[]` here), `run_exports`, `size`, `timestamp` (ms since epoch) and, on 2
  records, `build_number`. Name, version and build must be parsed from the file name
  `<name>-<version>-<build>.conda`, where the name can contain `-`
  (`ld_impl_linux-64-2.46.1-default_hbd61a6d_103.conda`). `build_number` is written only for
  `_openmp_mutex-4.5-20_gnu` (20) and `tk-8.6.13-noxft_h1df4ec4_4` (104), the two whose build
  string does not end in `_<build number>` with a non-zero build number. python's
  `..._0_cpython` builds (build number 0) have no key.
- `depends` keeps repodata strings as a list. Two constraints on one name stay separate entries
  (jq: `oniguruma 6.9.*` and `oniguruma >=6.9.10,<6.10.0a0`); conda-lock merges them.
- Conda `md5` and `sha256` are digests of the package archive at the URL. All 40 conda
  artifacts were downloaded, and both digests matched for every one. 38 of the URLs also occur
  in the `conda-lock` fixture, with identical md5 and sha256 there.
- pypi records have `pypi` (the URL), `name`, `version` and `requires_python`. six also has
  `sha256`, the SHA-256 of the wheel at its files.pythonhosted.org URL (the same value is
  checked in the `conda-lock` fixture). The git dependency is
  `pypi: git+https://github.com/hukkin/tomli.git?tag=2.0.1#36ef51d6a5a55e0eca077b58695390d041061bd4`.
  The requested tag is in the query and the resolved commit (the peeled target of the annotated
  tag 2.0.1) is the fragment. It has no `sha256` key.
- There is no `pip` conda package (pixi does not add one). The file contains no path, user name
  or credential.
