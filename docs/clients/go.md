# Go modules

Use the proxy as `GOPROXY`. The examples use the upstream name `goproxy`;
replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `go` |
| Package source | `https://proxy.example.com/v1/goproxy` |
| Clients | the `go` command |
| Tested | go 1.24: [in CI on every push](../ecosystem-tests-reference.md#go) and in the [client lab](../client-lab.md). |

## Configure

For a user (written to the go command's own environment file):

<!-- verified: lab:go -->

```sh
go env -w GOPROXY=https://proxy.example.com/v1/goproxy
```

In a CI job or a Dockerfile:

<!-- verified: lab:refused-go -->

```sh
export GOPROXY=https://proxy.example.com/v1/goproxy
```

Leave `,direct` off. With `GOPROXY=<proxy>,direct` the go command fetches a
module the proxy answers `404` or `410` for straight from its version-control
host — past the cache and every check. (A refusal, `403`, is final in both
forms.)

**Checksum verification stays on, with nothing to configure.** The go command
verifies every module against the checksum database (`sum.golang.org`) and by
default contacts it directly, which fails where only the proxy is reachable.
The proxy serves the database under the same address
(`/v1/goproxy/sumdb/sum.golang.org/…`), the go command finds it there by
itself, and every answer is signed by the database and verified with the key
built into the go command: no trust is placed in the proxy. `GOSUMDB`,
`GONOSUMDB` and `GOFLAGS=-insecure` stay unset.

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name.

In `~/.netrc` (mode `600`), which the go command reads for the proxy's host:

<!-- verified: lab:go -->

```
machine proxy.example.com
  login pullthrough
  password <token>
```

or in the `GOPROXY` URL:

<!-- verified: lab:go lab:refused-go -->

```sh
export GOPROXY=https://pullthrough:<token>@proxy.example.com/v1/goproxy
```

The go command sends credentials over HTTPS only.

## Trust a private CA

The go command uses the system trust store; a CA that is not in it is named in
the environment:

<!-- verified: lab:go lab:refused-go -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:go -->

```sh
go mod download rsc.io/quote@v1.5.2
```

`go env GOPROXY` shows the effective setting; with `-x`, `go mod download`
prints every URL it fetches.

## Good to know

- **`go.mod` and `go.sum` do not change.** They hold module paths, versions and
  hashes, no URLs; the same files work with and without the proxy.
- **Private modules** that are not on the public proxy network still need
  `GOPRIVATE` (or `GONOSUMDB`/`GONOPROXY`) for their paths, as without the
  proxy: the go command then fetches them from their version-control host,
  which can itself be routed through the proxy's [Git upstream](git.md).
- **A refused module is a `403`** on the first request that names its version:

  <!-- output: lab:refused-go -->

  ```
  go: github.com/pkg/errors@v0.9.1: reading https://proxy.example.com/v1/goproxy/github.com/pkg/errors/@v/v0.9.1.info: 403 Forbidden
  ```

  [What a refusal means and what to do](../clients.md#when-the-proxy-refuses-a-package).
- `404` answers for path prefixes (`…/github.com/@v/…`, `…/github.com/pkg/@v/…`)
  in the proxy's log are the go command probing which prefix of an import path
  is the module — normal.
- **With a [personal cache link](../user-links.md)** `go env -w GOPROXY=…` keeps
  it in your user configuration; `go.mod` and `go.sum` contain no URLs, so the
  link — which works like a password — is not committed.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  goproxy:
    type: go
    url: https://proxy.golang.org
```

`@v/list` and `@latest` are served live; a version's `.info`, `.mod` and `.zip`
are cached immutably. The `sumdb` upstream setting names the checksum databases
the proxy serves (default `sum.golang.org`; `off` disables it). Details:
[backends: go](../backends.md#go).
