# pipenv

Generated 2026-11-12 by a real tool in a throwaway container. Neither file was
edited by hand afterwards, and pipenv did not rewrite the Pipfile.

- Tool: pipenv 2026.11.0 (latest on PyPI at generation time), installed with pip 25.0.1.
- Image: `python:3.12-slim` (CPython 3.12.16), digest
  `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`.
  git 2.47.3 was installed from Debian because the VCS entry needs it.
- Commands (the Pipfile was hand-written first; only `pipenv lock` was run, never `pipenv install`/`sync`):

      docker run --rm -v <scratch>/pipenv:/work -w /work python:3.12-slim sh -c '
        apt-get update && apt-get install -y --no-install-recommends git
        pip install "pipenv==2026.11.0"
        PIPENV_NOSPIN=1 PIPENV_YES=1 CI=1 pipenv lock'

  `pipenv lock` creates an empty virtualenv inside the container (`/root/.local/share/virtualenvs/...`), and it was discarded with the container. pip, inside pipenv's resolver, cloned sampleproject. As pip does for every VCS requirement, it prepared the package's metadata through setuptools' PEP 517 metadata hook in an isolated build environment, also inside the container.

Notable features of Pipfile.lock:
- `_meta`: `"pipfile-spec": 6`, `hash.sha256` = 6d03ff506498b77283831a1d4fbd0c7c5c7b59a064708e11ca7308c872a2d9ec (hash of the Pipfile), `requires.python_version` "3.12", one source named `pypi` (https://pypi.org/simple).
- `default` has 8 entries: certifi ==2026.10.23, charset-normalizer ==3.5.2, idna ==3.20, packaging ==24.1, peppercorn ==0.6, requests ==2.32.3, sampleproject (git) and urllib3 ==2.8.0.
- `develop` has 1 entry: iniconfig ==2.0.0.
- Versions are stored with the operator (`"version": "==2.32.3"`). Every registry entry has a `hashes` list of `sha256:<hex>` strings: charset-normalizer has 172, the others 2 each.
- Only direct dependencies (packaging, requests, iniconfig) carry `"index": "pypi"`. Transitive ones do not.
- `markers` come from each release's Requires-Python (e.g. urllib3 `python_version >= '3.10'`). peppercorn has no `markers` key at all.
- Git dependency `sampleproject`: `{"git": "https://github.com/pypa/sampleproject", "ref": "621e4974ca25ce531773def586ba3ed8e736b3fc"}`. It has no `version` and no `hashes` key. The Pipfile asks for `ref = "main"`, and the lock records the resolved commit. Its dependency peppercorn appears as an ordinary registry entry in `default`.
- Deviation from the request: the git dependency was meant to be pinned at tag `v4.0.0`, but https://github.com/pypa/sampleproject has no tags at all (`git ls-remote` shows only `HEAD` and `refs/heads/main`). The branch `main` was used instead. It resolves to 621e4974ca25ce531773def586ba3ed8e736b3fc, "pyproject: prep 4.0.0 (#219)", whose pyproject.toml declares version 4.0.0. That is the commit a v4.0.0 tag would point at.
