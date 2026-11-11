# Generic upstreams

A generic upstream fronts a registry that has no dedicated backend, with
routing rules the operator writes. What a client has to be told therefore
depends on the registry's own protocol — this page says what stays the same.

| | |
|---|---|
| Upstream type | `generic` |
| Package source | `https://proxy.example.com/v1/<name>/…`, with the paths the operator's routes allow |
| Clients | whatever speaks the registry's protocol |
| Tested | **Not tested with a real client.** A generic upstream is deployment-specific: its routes, and with them its clients, are the operator's. The backend is covered by protocol-level tests. |

## Configure

Give the client the upstream's address in place of the registry's. Whatever the
registry served under `https://repo.example.com/…` the proxy serves under
`https://proxy.example.com/v1/<name>/…` — for the paths the operator listed; any
other path is refused.

<!-- illustration -->

```
https://repo.example.com/packages/tool/tool-1.2.tar.gz
https://proxy.example.com/v1/mysource/packages/tool/tool-1.2.tar.gz
```

Two things decide whether that is all:

- **Absolute links in metadata.** If the registry's index documents link to
  its own host, the operator marks those routes `rewrite: true`, and the proxy
  rewrites the links to its address. Otherwise the client follows them to the
  registry directly.
- **Downloads from other hosts.** A registry that hands out download URLs on a
  CDN needs those reachable through an upstream as well, or the client fetches
  them directly.

## Authenticate

Only when the proxy has access control switched on. The proxy takes a token in
any of the forms listed in
[the hub page](../clients.md#how-the-proxy-takes-a-token); use the one the
client can send.

## Trust a private CA

Use the client's own setting; the [table of CA settings](../clients.md#private-ca-settings-at-a-glance)
covers the common HTTP stacks (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, a JVM trust
store, `NODE_EXTRA_CA_CERTS`).

## Check that it works

Request one allowed and one unlisted path, with any HTTP client: the first is
served, the second refused.

## Good to know

- **Unmatched paths are refused**, so a client that probes for optional files
  sees errors where the registry answered `404`.
- **Only `GET` and `HEAD`.**

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  mysource:
    type: generic
    url: https://repo.example.com
    generic:
      publicBaseURL: https://proxy.example.com/v1/mysource
      routes:
        - name: metadata
          match: '^/packages/[^/]+/index\.json$'
          rewrite: true
        - name: artifact
          match: '^/packages/[^/]+/.+\.tar\.gz$'
          cacheable: true
          verify:
            algorithm: sha256
            source: sidecar
            sidecarSuffix: .sha256
```

The full field reference, digest verification and content-gate selection are
in [generic-backend.md](../generic-backend.md).
