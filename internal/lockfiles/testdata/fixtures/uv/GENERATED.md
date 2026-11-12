# uv

Generated 2026-11-12 on the host (no container) by a real tool. Neither file
was edited by hand afterwards, and uv did not change pyproject.toml.

- Tool: uv 0.11.14 (x86_64-unknown-linux-gnu).
- Commands (pyproject.toml was hand-written first; only `uv lock` was run, never `uv sync`, so no `.venv` was created):

      UV_NO_BUILD=1 UV_PYTHON=/usr/bin/python3.12 UV_PYTHON_DOWNLOADS=never UV_CACHE_DIR=<scratch>/uv-cache \
        uv lock -v
      # re-check, lock unchanged byte for byte:
      UV_NO_BUILD=1 UV_PYTHON=/usr/bin/python3.12 UV_PYTHON_DOWNLOADS=never UV_CACHE_DIR=<scratch>/uv-cache \
        uv lock --check

  `UV_NO_BUILD=1` makes sure that no package build backend runs on the host. It leaves no trace in uv.lock, which has no `[options]` table. uv got sampleproject's metadata through its "GitHub fast path": it asked the GitHub API for the commit at `main` and read the static `pyproject.toml` from raw.githubusercontent.com. It did not clone and did not build. The interpreter choice (system CPython 3.12.3) does not affect the universal lock.

Manifest: PEP 621 `[project]` with `requires-python = ">=3.9"`. Main dependencies are requests==2.32.3, packaging==24.1 and sampleproject. The PEP 735 `[dependency-groups]` `dev` group holds iniconfig==2.0.0. `[tool.uv.sources]` has `sampleproject = { git = "https://github.com/pypa/sampleproject", branch = "main" }`. There is no `[build-system]`, so the root project is virtual.

Notable features of uv.lock:
- Top level: `version = 1`, `revision = 3`, `requires-python = ">=3.9"` and a top-level `resolution-markers` list: `python_full_version >= '3.10'` and `python_full_version < '3.10'`.
- The resolution is forked. urllib3 2.8.0 requires Python >=3.10, so urllib3 appears twice: 2.6.3 (`resolution-markers = ["python_full_version < '3.10'"]`) and 2.8.0 (`resolution-markers = ["python_full_version >= '3.10'"]`). requests' `dependencies` refers to both copies, each with `version`, `source` and `marker` to tell them apart.
- 11 `[[package]]` entries: certifi 2026.10.23, charset-normalizer 3.5.2, idna 3.20, iniconfig 2.0.0, lockfixture-uv 0.1.0 (root), packaging 24.1, peppercorn 0.6, requests 2.32.3, sampleproject 4.0.0, urllib3 2.6.3 and urllib3 2.8.0.
- The root package `lockfixture-uv` has `source = { virtual = "." }`, `dependencies` (packaging, requests, sampleproject) and `[package.dev-dependencies] dev = [{ name = "iniconfig" }]`. Its `[package.metadata]` has `requires-dist`, including `{ name = "sampleproject", git = "https://github.com/pypa/sampleproject?branch=main" }`, and its `[package.metadata.requires-dev]` lists iniconfig. iniconfig is dev-only: it is reachable only through the dev group. uv.lock has no per-package group flag.
- Registry packages have `source = { registry = "https://pypi.org/simple" }`, one `sdist = { url, hash = "sha256:...", size, upload-time }` and a `wheels = [{ url, hash, size, upload-time }, ...]` list. charset-normalizer has 171 wheels plus the sdist, every other registry package 1 wheel plus the sdist.
- Git dependency `sampleproject` 4.0.0: `source = { git = "https://github.com/pypa/sampleproject?branch=main#621e4974ca25ce531773def586ba3ed8e736b3fc" }`. The requested ref is in the query string and the resolved commit is the URL fragment. It has no sdist/wheels/hashes, and its `dependencies` holds peppercorn.
- Deviation from the request: the git dependency was meant to be pinned at tag `v4.0.0`, but https://github.com/pypa/sampleproject has no tags at all (`git ls-remote` shows only `HEAD` and `refs/heads/main`). The branch `main` was used instead. It resolves to 621e4974ca25ce531773def586ba3ed8e736b3fc, "pyproject: prep 4.0.0 (#219)", whose pyproject.toml declares version 4.0.0. That is the commit a v4.0.0 tag would point at.
