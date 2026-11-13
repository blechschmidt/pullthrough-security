# conda-lock

Generated 2026-11-12 with conda-lock 4.1.0 (what an unpinned `pip install conda-lock` got
that day) in a throwaway container. Neither the lock file nor the manifests were edited after the run.

- Tool: conda-lock 4.1.0, installed with pip 26.2.2 into a venv made from the image's
  CPython 3.14.10. conda-lock picked `/opt/conda/bin/mamba` (mamba 2.9.0) as its solver
  (its debug log says `Found conda executable: /opt/conda/bin/mamba`). The pip part is
  solved by conda-lock's vendored Poetry, which fetched the git dependency with dulwich.
- Image: `docker.io/condaforge/miniforge3:latest` (conda 26.9.4, mamba 2.9.0), digest
  `sha256:0a788afa8b54165d855d08552ce6d86e1e2553be2a9a18d542c69cfb02a6deaa`.
- Commands (the three environment files were hand-written first):

      podman run --rm -v <scratch>:/work -w /work docker.io/condaforge/miniforge3:latest bash -c '
        python -m venv /work/cl-venv && /work/cl-venv/bin/pip install conda-lock'
      podman run --rm -v <scratch>:/work -w /work/lock -e CONDA_PKGS_DIRS=/work/pkgs \
        docker.io/condaforge/miniforge3:latest \
        /work/cl-venv/bin/conda-lock lock --log-level DEBUG \
          -f environment.yml -f environment-dev.yml -f environment-docs.yml -p linux-64 -p osx-arm64

Manifests:
- `environment.yml`: channel conda-forge. Conda deps are `python=3.12`, `zlib`, `xz` and `pip`.
  Pip deps are `six==1.16.0` and `tomli @ git+https://github.com/hukkin/tomli.git@2.0.1`.
- `environment-dev.yml`: `category: dev` (a conda-lock extension key that applies to the whole
  file), with `jq=1.6`. That version only exists as `.tar.bz2` on conda-forge.
- `environment-docs.yml`: `category: docs`, with `oniguruma`, which jq also depends on.
- These go beyond the requested single `-f environment.yml`. The dev and docs files make the
  lock mark optional categories, the git pip dep shows how conda-lock writes VCS deps, and jq 1.6
  adds `.tar.bz2` artifacts.
- `python=3.12` is pinned on purpose. Leaving python out does not shrink the lock. conda-lock
  adds the conda package `pip` whenever there is a `- pip:` section, and conda-forge's pip
  depends on python. A trial run with only `zlib`, `xz`, `bzip2`, `ca-certificates` plus
  `pip: [six==1.16.0]` succeeded and locked python 3.15.2. conda-lock only raises
  `Got pip specs without Python` when python is missing from the *solved* set.

Notable features of conda-lock.yml:
- 16 comment lines of help text come first. They include "This lock contains optional
  development dependencies" and "optional dependency categories docs". Then come `version: 1`
  (the unified lock format) and `metadata`, which holds:
  - `content_hash`: one value per platform. It is SHA-256 over a JSON serialization of the
    lock *specification* for that platform (channels, requested specs, pip repositories,
    virtual packages; see `conda_lock/content_hash.py`). It is not a digest of any artifact.
  - `channels: [{url: conda-forge, used_env_vars: []}]`. The channel is a bare name, not a URL.
  - `platforms: [linux-64, osx-arm64]` and `sources` (the three file names, relative).
- `package` is a flat list of 65 entries: 37 for linux-64 and 28 for osx-arm64, 61 `manager: conda`
  and 4 `manager: pip`. Every entry has `name`, `version`, `manager`, `platform`, `dependencies`,
  `url`, `hash`, `category` and `optional`. The git pip entries also have `source`. Each platform
  repeats every package it needs, including the identical noarch ones (6 noarch URLs per platform).
- Category marking: `category: main` with `optional: false`, or `category: dev` / `docs` with
  `optional: true`. Dev-only are `jq` (both platforms), `libgcc-ng` (linux-64, pulled in by
  jq 1.6) and `oniguruma`.
- The same package can appear more than once. `oniguruma` 6.9.10 is in both the dev and docs
  categories, so it is written twice per platform, identical except for `category`. conda-lock
  writes one v1 entry per category, but folds every package that is also in `main` into a
  single `main` entry. A (manager, name, platform) key is therefore not unique.
- `version` values that YAML would read as numbers are quoted (`'4.5'`, `'1.6'`, `'6.6'`, `'8.3'`, `'26.3'`).
- `dependencies` maps name → constraint string. An unconstrained dependency is `''` (pip →
  `setuptools: ''`). Virtual packages (`__glibc`, `__osx`, `__unix`) appear as dependency keys
  but are never locked entries. jq 1.6's two repodata constraints on oniguruma are merged into
  one string: `oniguruma: 6.9.*,>=6.9.3,<6.10.0a0`.
- Conda entries: `url` is `https://conda.anaconda.org/conda-forge/<subdir>/<name>-<version>-<build>.conda`
  (59 entries) or `.tar.bz2` (jq 1.6 on both platforms). noarch packages use subdir `noarch` but
  still carry `platform: linux-64` / `osx-arm64`. `hash` has both `md5` and `sha256`, both of the
  package archive file at `url`. All 53 distinct conda URLs in the file were downloaded, and md5
  and sha256 matched for every one, `.conda` and `.tar.bz2` alike.
- Pip registry entry `six` 1.16.0: `url` is the wheel on files.pythonhosted.org, `hash` has only
  `sha256`, and it is the SHA-256 of that wheel file (checked by download). There is no `source` key.
- Pip git entry `tomli` 2.0.1:
  `url: git+https://github.com/hukkin/tomli.git@36ef51d6a5a55e0eca077b58695390d041061bd4`,
  `source: {type: url, url: <same>}` and **`hash: {sha256: 36ef51d6a5a55e0eca077b58695390d041061bd4}`**.
  That "sha256" is a 40-hex git commit SHA-1, not a SHA-256 of anything. conda-lock copies the
  resolved git reference into the field (`pypi_solver.py`: `HashModel.model_validate({"sha256":
  op.package.source_resolved_reference})`, next to a `TODO: FIXME`). `2.0.1` is an annotated tag:
  the tag object is 19bfd0bc767f9bbd8703cbd918b76d5a5b2489c5 and the commit it points at is
  36ef51d6..., so the lock holds the peeled commit (`git ls-remote`: `refs/tags/2.0.1^{}`).
  The requested ref `2.0.1` is not kept.
- Pip entries have `dependencies: {}`. The file contains no local path, user name or
  credential. PyYAML block style (list items not indented under their key), LF, trailing newline.
