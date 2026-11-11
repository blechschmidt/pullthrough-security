# Open VSX (VS Code extensions)

Download editor extensions through the proxy's Open VSX upstream. The examples
use the upstream name `openvsx`; replace it with the name your operator gave
the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `openvsx` |
| Package source | `https://proxy.example.com/v1/openvsx` |
| Clients | the `ovsx` CLI |
| Tested | ovsx 1.4: [in CI on every push](../ecosystem-tests-reference.md#openvsx) and in the [client lab](../client-lab.md). An editor's gallery (VSCodium, code-server): not tested. |

## Configure

The `ovsx` CLI takes the registry as an option:

<!-- verified: lab:openvsx -->

```sh
npx --yes ovsx get dracula-theme.theme-dracula --versionRange 2.25.1 \
    --registryUrl https://proxy.example.com/v1/openvsx -o extension.vsix
```

`ovsx` is itself an npm package: `npx` fetches it through the proxy's
[npm upstream](npm.md) when npm is configured for it.

An editor reads the extension gallery from its `product.json`
(`extensionsGallery.serviceUrl`, `itemUrl`). The proxy serves the Open VSX REST
API with `GET` requests; an editor's gallery *search* is a `POST`, which the
proxy does not serve, so pointing an editor at the proxy was not tested and is
not expected to give a working extension search.

## Authenticate

**`ovsx` cannot present a proxy token for downloads.** Its token options (`-p`,
`OVSX_PAT`) are for publishing; `ovsx get` sends none, and a proxy that
requires one answers `401`:

<!-- output: lab:openvsx -->

```
❌  The server responded with status 401: Unauthorized
```

Where access control is on, the operator has to admit anonymous reads for the
Open VSX upstream
([how](../clients.md#clients-that-cannot-present-a-token)).

## Trust a private CA

`ovsx` runs on Node.js:

<!-- verified: lab:openvsx -->

```sh
export NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem
```

## Check that it works

The `ovsx get` command above writes the `.vsix`; the proxy verified it against
the registry's SHA-256 before serving it.

## Good to know

- **Download links come back through the proxy**: the metadata the proxy
  serves has its file URLs rewritten, so the `.vsix` is not fetched from the
  registry's storage directly.
- **Extensions are inspected before they are served**: a `.vsix` passes the
  proxy's install-script and activation checks, and a refused extension is a
  `403`.
- **Publishing does not go through the proxy** (`ovsx publish`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  openvsx:
    type: openvsx
    url: https://open-vsx.org
```

Metadata is served live with its URLs rewritten to the proxy (which is why
`server.publicUrl` must be set); a `.vsix` is verified against the registry's
`.sha256` sidecar and cached immutably. Details:
[backends: openvsx](../backends.md#openvsx).
