# poetry-1.1

Generated 2026-11-12 by a real tool in a throwaway container. Neither file was
edited by hand afterwards, and poetry did not change pyproject.toml. Poetry
1.1.15, the first version tried, locked against today's PyPI. Only its own
tool environment needed two pins.

- Tool: Poetry 1.1.15 (poetry-core 1.0.8), installed with pip 23.0.1.
- Image: `python:3.9-slim` (CPython 3.9.25), digest
  `sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b`.
  git 2.47.3 was installed from Debian because poetry 1.1 clones git dependencies with it.
- Commands (pyproject.toml was hand-written first; only `poetry lock` was run, never `poetry install`):

      docker run --rm -v <scratch>/poetry-1.1:/work -w /work python:3.9-slim sh -c '
        apt-get update && apt-get install -y --no-install-recommends git
        pip install "poetry==1.1.15" "urllib3<2" "setuptools<70"
        POETRY_NO_INTERACTION=1 POETRY_VIRTUALENVS_IN_PROJECT=false \
          PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring poetry lock -vvv'

  The two extra pins apply only to the tool's own environment, not to the project:
  - `urllib3<2`: poetry 1.1 pins requests-toolbelt 0.9.1, which cannot import with urllib3 2.x.
  - `setuptools<70`: poetry 1.1 pins packaging 20.9, and the image's newer setuptools `_distutils` (imported by virtualenv) calls `canonicalize_version(strip_trailing_zero=...)`, which packaging 20.9 does not have. Without the pin, `poetry` crashes on start.

  Other tool-environment versions pip picked: packaging 20.9, pkginfo 1.13.3, virtualenv 20.39.1, tomlkit 0.15.2, cachecontrol 0.12.14, requests 2.32.5, urllib3 1.26.20, keyring 25.7.0. poetry creates an empty project virtualenv under `/root/.cache/pypoetry/virtualenvs` inside the container. For the git dependency it clones the repository and gets its metadata with an ephemeral PEP 517 build environment, also inside the container. Both were discarded with the container.

Manifest: poetry 1.1 has no `[project]` table and no groups. `[tool.poetry.dependencies]` has `python = "^3.9"`, `requests = "2.32.3"`, `packaging = "24.1"` and `sampleproject = { git = "https://github.com/pypa/sampleproject", branch = "main" }`. `[tool.poetry.dev-dependencies]` has `iniconfig = "2.0.0"`.

Notable features of poetry.lock (the old lock layout):
- There is no `@generated` header comment: the file starts directly with `[[package]]`.
- `[metadata]` comes last: `lock-version = "1.1"`, `python-versions = "^3.9"` and a `content-hash`.
- 9 `[[package]]` entries: certifi 2026.10.23, charset-normalizer 3.5.2, idna 3.20, iniconfig 2.0.0, packaging 24.1, peppercorn 0.6, requests 2.32.3, sampleproject 4.0.0 (git) and urllib3 2.6.3.
- Dev/main is per package: `category = "dev"` for iniconfig and `category = "main"` for everything else. There is no `groups` key.
- Hashes are NOT in the package entries. They are in a separate `[metadata.files]` table keyed by the bare package name, with no version in the key: `certifi = [{file = "...", hash = "sha256:..."}, ...]`. charset-normalizer has 172 entries, every other registry package 2. The git package has an empty list, `sampleproject = []`.
- urllib3 is 2.6.3, not the newest 2.8.0. poetry 1.1 rejected 2.8.0 and 2.7.0 because they require Python >=3.10, and the project allows ^3.9.
- `[package.dependencies]` holds the edges (requests → certifi/charset-normalizer/idna/urllib3, sampleproject → peppercorn). `[package.extras]` values have environment markers stripped (e.g. urllib3 `brotli = ["brotli (>=1.2.0)", "brotlicffi (>=1.2.0.0)"]`, unlike the poetry-2 fixture).
- Git dependency `sampleproject` 4.0.0 has `develop = false` and `[package.source]` = `type = "git"`, `url = "https://github.com/pypa/sampleproject"`, `reference = "main"`, `resolved_reference = "621e4974ca25ce531773def586ba3ed8e736b3fc"`.
- Deviation from the request: the git dependency was meant to be pinned at tag `v4.0.0`, but https://github.com/pypa/sampleproject has no tags at all (`git ls-remote` shows only `HEAD` and `refs/heads/main`). The branch `main` was used instead. It resolves to 621e4974ca25ce531773def586ba3ed8e736b3fc, "pyproject: prep 4.0.0 (#219)", whose pyproject.toml declares version 4.0.0. That is the commit a v4.0.0 tag would point at.
