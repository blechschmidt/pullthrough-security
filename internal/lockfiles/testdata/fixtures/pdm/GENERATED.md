# pdm

Generated 2026-11-12 by a real tool in a throwaway container. Neither file was
edited by hand afterwards, and pdm did not change pyproject.toml.

- Tool: PDM 2.29.7 (latest on PyPI at generation time), installed with pip 25.0.1.
- Image: `python:3.12-slim` (CPython 3.12.16), digest
  `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`.
  git 2.47.3 was installed from Debian because pdm clones VCS requirements with it.
- Commands (pyproject.toml was hand-written first; only `pdm lock` was run, never `pdm install`/`sync`):

      docker run --rm -v <scratch>/pdm:/work -w /work python:3.12-slim sh -c '
        apt-get update && apt-get install -y --no-install-recommends git
        pip install "pdm==2.29.7"
        PDM_NON_INTERACTIVE=1 PDM_CHECK_UPDATE=false PDM_VENV_IN_PROJECT=false pdm lock -v'

  pdm creates an empty virtualenv under `/root/.local/share/pdm/venvs` inside the container, and it was discarded with the container. The `.pdm-python` pointer file it writes was not copied. pdm cloned sampleproject and read its static metadata, so no build backend ran.

Manifest: PEP 621 `[project]` with `requires-python = ">=3.9"`. The main dependencies include the git dependency as a PEP 508 direct reference, `sampleproject @ git+https://github.com/pypa/sampleproject@main`. The PEP 735 `[dependency-groups]` `dev` group holds iniconfig==2.0.0 (current pdm writes `pdm add -d` here instead of `[tool.pdm.dev-dependencies]`). `[tool.pdm] distribution = false` keeps the root project out of the lock.

Notable features of pdm.lock:
- `[metadata]` comes first: `groups = ["default", "dev"]`, `strategy = ["inherit_metadata"]`, `lock_version = "4.5.1"`, `content_hash = "sha256:..."`, plus one `[[metadata.targets]]` with `requires_python = ">=3.9"`.
- 9 `[[package]]` entries: certifi 2026.10.23, charset-normalizer 3.5.2, idna 3.20, iniconfig 2.0.0, packaging 24.1, peppercorn 0.6, requests 2.32.3, sampleproject 4.0.0 (git) and urllib3 2.6.3.
- Groups are per package: `groups = ["dev"]` for iniconfig and `groups = ["default"]` for everything else. No package has a `marker` in this resolution.
- Hashes are inline per package: `files = [{file = "<filename>", hash = "sha256:<hex>"}, ...]`, with file names rather than URLs (no static_urls). charset-normalizer has 172 entries, every other registry package 2. There is no `[metadata.files]` table.
- Dependency edges are PEP 508 strings in `dependencies = [...]` (requests → `"urllib3<3,>=1.21.1"` etc., sampleproject → `"peppercorn"`). peppercorn has no `requires_python` key.
- urllib3 is 2.6.3. pdm skipped 2.8.0 and 2.7.0 because they require Python >=3.10 and the lock target is `>=3.9`.
- Git dependency `sampleproject` 4.0.0 has `git = "https://github.com/pypa/sampleproject"`, `ref = "main"`, `revision = "621e4974ca25ce531773def586ba3ed8e736b3fc"` and no `files` key.
- Deviation from the request: the git dependency was meant to be pinned at tag `v4.0.0`, but https://github.com/pypa/sampleproject has no tags at all (`git ls-remote` shows only `HEAD` and `refs/heads/main`). The branch `main` was used instead. It resolves to 621e4974ca25ce531773def586ba3ed8e736b3fc, "pyproject: prep 4.0.0 (#219)", whose pyproject.toml declares version 4.0.0. That is the commit a v4.0.0 tag would point at.
