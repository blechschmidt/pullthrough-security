# Client scripts

One POSIX `sh` script per ecosystem. Each script does exactly two things with the
ecosystem's **real** client:

1. **configure it to use the pull-through proxy** instead of the public registry;
2. **install one package** through it.

They are executed by the ecosystem test harness (`internal/ecotest`, build tag
`ecosystem`) inside the ecosystem's container image, once for a package that must
install and once for a package the proxy must refuse. The scripts contain no test
logic and no branching on which of the two they are running: the same code path
that installs the good package is the one that fails on the bad one.

Because CI runs them against the real clients and the real registries on every
push, these scripts are the **continuously verified reference** for how to point
each package manager at the proxy.

## Environment

| Variable | Example | Meaning |
|---|---|---|
| `PROXY_URL` | `http://127.0.0.1:41234` | Base URL of the proxy. |
| `PROXY_HOST` | `127.0.0.1:41234` | `host:port` of the proxy. |
| `MOUNT` | `http://127.0.0.1:41234/v1/npm` | This ecosystem's package source on the proxy (`$PROXY_URL/v1/<upstream>`). |
| `PKG_NAME` | `is-number` | The package to install, in the ecosystem's own notation. |
| `PKG_VERSION` | `7.0.0` | The version to install (may be empty). |
| `PKG_*` | | Ecosystem-specific extras, documented in the script that uses them. |
| `PT_CA_CERT` | `/work/ca.crt` | CA certificate of the proxy. Set only when the proxy is served over HTTPS (clients that refuse plain HTTP). |

## Contract

- The working directory (`/work`) is an empty scratch directory, fresh for every
  run; client caches live in the throwaway container, so every run starts cold.
- Exit `0` when the package was installed, non-zero otherwise.
- Print `ECOTEST_CLIENT_VERSION=<version>` once, so the report names the exact
  client that was exercised.

## Interception scripts (`transparent/`)

`transparent/<id>.sh` installs the same package with the client **not pointed at
the proxy**: it keeps its own registry and only trusts the proxy's interception
CA. The harness runs it in TLS-interception mode and in NAT mode
([docs/intercept-mode.md](../../../docs/intercept-mode.md)).

| Variable | Example | Meaning |
|---|---|---|
| `PT_CA_CERT` | `/work/ca.crt` | The CA the proxy mints the registry's certificates with. Always set. |
| `PT_MODE` | `intercept` | `intercept` or `nat`, for diagnostics. A script must not need it. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy`, `http_proxy` | `http://127.0.0.1:41235` | The forward proxy. Set in interception mode only, as an operator sets it machine-wide. |
| `PT_INTERCEPT_PROXY` | `http://127.0.0.1:41235` | The same, for a client that needs it spelled out in its own configuration (Maven). Empty in NAT mode. |
| `PKG_NAME`, `PKG_VERSION`, `PKG_*` | | As above. |

`PROXY_URL`, `PROXY_HOST` and `MOUNT` are **not** set: a transparent script has
no proxy address to use.
