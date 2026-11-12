# pip, uv, Poetry, PDM

Point the Python installers at the proxy's PyPI upstream instead of `pypi.org`.
The examples use the upstream name `pypi`; replace it with the name your
operator gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `pip` |
| Package source | `https://proxy.example.com/v1/pypi/simple/` (the Simple index) |
| Clients | pip, uv, Poetry, PDM |
| Tested | pip 25.0: [in CI on every push](../ecosystem-tests-reference.md#pip) and in the [client lab](../client-lab.md). uv 0.13, Poetry 2.5, PDM 2.29: in the client lab. |

## Configure

The index URL ends in `/simple/`. One index is enough: the proxy rewrites the
file links in the pages it serves, so wheels and sdists (hosted on
`files.pythonhosted.org`) come back through it too.

### pip

`pip.conf` — `~/.config/pip/pip.conf` on Linux, `~/Library/Application
Support/pip/pip.conf` on macOS, `%APPDATA%\pip\pip.ini` on Windows:

<!-- verified: lab:pip -->

```ini
[global]
index-url = https://proxy.example.com/v1/pypi/simple/
```

In a CI job or a Dockerfile:

<!-- verified: lab:pip-netrc -->

```sh
export PIP_INDEX_URL=https://proxy.example.com/v1/pypi/simple/
```

For one command, `--index-url` takes the same URL.

### uv

A default index in `~/.config/uv/uv.toml` (or under `[tool.uv]` in a project's
`pyproject.toml`):

<!-- verified: lab:uv -->

```toml
[[index]]
name = "proxy"
url = "https://proxy.example.com/v1/pypi/simple/"
default = true
```

Or in the environment:

<!-- verified: lab:uv -->

```sh
export UV_DEFAULT_INDEX=https://proxy.example.com/v1/pypi/simple/
```

### Poetry

A primary source in the project's `pyproject.toml`:

<!-- verified: lab:poetry -->

```toml
[[tool.poetry.source]]
name = "proxy"
url = "https://proxy.example.com/v1/pypi/simple/"
priority = "primary"
```

### PDM

<!-- verified: lab:pdm -->

```sh
pdm config pypi.url https://proxy.example.com/v1/pypi/simple/
```

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name
(`pullthrough` below) — never a PyPI token.

**pip** — in the index URL:

<!-- verified: lab:pip -->

```ini
index-url = https://pullthrough:<token>@proxy.example.com/v1/pypi/simple/
```

or, to keep the token out of `pip.conf`, the environment and requirements
files, in `~/.netrc` (mode `600`), which pip reads for the index's host:

<!-- verified: lab:pip-netrc -->

```
machine proxy.example.com
  login pullthrough
  password <token>
```

**uv** — per index name, in the environment (`PROXY` is the index's `name`,
upper-cased):

<!-- verified: lab:uv -->

```sh
export UV_INDEX_PROXY_USERNAME=pullthrough
export UV_INDEX_PROXY_PASSWORD="<token>"
```

or in the URL, where the index itself is set in the environment:

<!-- verified: lab:uv -->

```sh
export UV_DEFAULT_INDEX=https://pullthrough:<token>@proxy.example.com/v1/pypi/simple/
```

**Poetry** — per source name, in Poetry's own configuration:

<!-- verified: lab:poetry -->

```sh
poetry config http-basic.proxy pullthrough "<token>"
```

**PDM**:

<!-- verified: lab:pdm -->

```sh
pdm config pypi.username pullthrough
pdm config pypi.password "<token>"
```

## Trust a private CA

Only when the proxy's certificate is issued by a CA that is not in the trust
store the client uses (pip and Poetry bring their own).

**pip** — in `pip.conf`, or in the environment:

<!-- verified: lab:pip -->

```ini
cert = /etc/ssl/corp-ca.pem
```

<!-- verified: lab:pip-netrc -->

```sh
export PIP_CERT=/etc/ssl/corp-ca.pem
```

**uv**:

<!-- verified: lab:uv -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

**Poetry** — per source name:

<!-- verified: lab:poetry -->

```sh
poetry config certificates.proxy.cert /etc/ssl/corp-ca.pem
```

**PDM**:

<!-- verified: lab:pdm -->

```sh
pdm config pypi.ca_certs /etc/ssl/corp-ca.pem
```

## Check that it works

An install says where it looks and where each file comes from — both must name
the proxy:

<!-- output: lab:pip-netrc -->

```
Looking in indexes: https://proxy.example.com/v1/pypi/simple/
Collecting six==1.16.0
  Downloading https://proxy.example.com/v1/pypi/files/https/files.pythonhosted.org/packages/d9/5a/…/six-1.16.0-py2.py3-none-any.whl (11 kB)
```

`ptctl selftest` checks every upstream at once
([client CLI](../client-cli.md)).

## Good to know

- **Do not add `pypi.org` as an extra index.** With `--extra-index-url` pip
  asks both indexes and takes the best version from either; uv takes a package
  from the first index that has it, and an extra index comes before the default
  one; a second Poetry source is searched as well. Whichever the rule, packages
  the proxy refused arrive anyway, and a public package can shadow an internal
  one of the same name. One index, the proxy. (This is the tools' documented
  behaviour; the lab configures one index and does not run a second.)
- **PDM looks for a newer release of itself** on pypi.org now and then, in an
  interactive session. The lab, which runs without a terminal, did not see it
  ask. To switch the check off:

  <!-- verified: lab:pdm -->

  ```sh
  pdm config check_update false
  ```
- **Lock files.** `uv.lock` records the index and the URL of every file — the
  proxy's, without credentials — and `poetry.lock` records the source's name and
  URL, so those lock files are tied to the proxy's address. `pdm.lock` and a
  `requirements.txt` record names, versions and hashes only. Hashes are
  unaffected either way: the proxy serves files byte for byte.
- **An existing `uv.lock` is re-locked, not followed.** A lock file written
  against pypi.org names pypi.org and `files.pythonhosted.org`; uv does not
  fetch from there. `uv sync --locked` stops (`The lockfile … needs to be
  updated`), and re-locking moves the file onto the proxy with the same
  versions and hashes:

  <!-- verified: lab:lock-uv -->

  ```sh
  uv lock
  uv sync --locked
  ```
- **An existing `poetry.lock` needs no change.** One written against PyPI
  names no source; with the proxy as the project's primary source, Poetry
  installs the locked packages from the proxy:

  <!-- verified: lab:lock-poetry -->

  ```sh
  poetry install --no-root
  ```
- **The first download of a large package can outlast pip's read timeout.** The
  proxy checks a file before it sends the first byte of it, so the wait covers
  the upstream download and the scans; pip gives up after 15 seconds of silence.
  Raise it (`PIP_DEFAULT_TIMEOUT=120`, `--timeout 120`); later downloads come
  from the cache.
- **A refused package is a `403`** on the file download:

  <!-- output: lab:refused-pip -->

  ```
  Collecting itsdangerous==2.2.0
    Downloading https://proxy.example.com/v1/pypi/files/https/files.pythonhosted.org/packages/…/itsdangerous-2.2.0-py3-none-any.whl.metadata (1.9 kB)
  ERROR: HTTP error 403 while getting https://proxy.example.com/v1/pypi/files/https/files.pythonhosted.org/packages/…/itsdangerous-2.2.0-py3-none-any.whl
  ```

  pip does not print the response body; `ptctl inspect` shows the reason.
  [What a refusal means and what to do](../clients.md#when-the-proxy-refuses-a-package).
- **Uploading does not go through the proxy** (`twine upload`, `uv publish`,
  `poetry publish`): it is read-only.
- pipenv and conda's bundled pip were not tested; both take the same index URL.
- **With a [personal cache link](../user-links.md)** the index belongs in your
  user-level `pip.conf`; pip records nothing. `uv.lock` and `poetry.lock` record
  the index URL (see above), and with it the link — which works like a password:
  do not lock a project whose lock file is committed through a personal link.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  pypi:
    type: pip
    url: https://pypi.org
```

Simple pages are served live with their file links rewritten to the proxy's
`/files/…` route (which is why `server.publicUrl` must be set); files are
cached immutably, and only from the hosts in `settings.fileHosts`
(`files.pythonhosted.org` by default). Details:
[backends: pip](../backends.md#pip).
