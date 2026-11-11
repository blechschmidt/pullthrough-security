# Homebrew

Send Homebrew's formula API and its bottle downloads through the proxy. The
examples use the upstream name `homebrew`; replace it with the name your
operator gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `homebrew` |
| Package source | `https://proxy.example.com/v1/homebrew/api` (formula API) and `https://proxy.example.com/v1/homebrew` (bottles) |
| Clients | brew |
| Tested | Homebrew 4.6 on Linux: [in CI on every push](../ecosystem-tests-reference.md#homebrew) and in the [client lab](../client-lab.md). macOS: not tested. |

## Configure

Two variables, and both are required:

<!-- verified: ci:homebrew lab:brew -->

```sh
export HOMEBREW_API_DOMAIN=https://proxy.example.com/v1/homebrew/api
export HOMEBREW_ARTIFACT_DOMAIN=https://proxy.example.com/v1/homebrew
```

`HOMEBREW_API_DOMAIN` routes the formula index. That index is signed, so the
proxy cannot rewrite the bottle URLs in it; it is `brew` itself that replaces
`ghcr.io` in every bottle URL with `HOMEBREW_ARTIFACT_DOMAIN`. Without the
second variable, brew reads its metadata through the proxy and downloads every
bottle from `ghcr.io` directly.

Make brew fail, rather than use a default host, for the few downloads that
have one:

<!-- verified: lab:brew -->

```sh
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1
```

## Authenticate

Only when the proxy has access control switched on. Bottles and the formula API
take the **proxy token** by different routes; the lab runs with both.

For bottle downloads, brew sends a registry token as a bearer token to the
artifact domain:

<!-- verified: lab:brew -->

```sh
export HOMEBREW_DOCKER_REGISTRY_TOKEN="<token>"
```

For the formula API, brew's `curl` takes credentials for the proxy's host from
`~/.netrc`, once `~/.curlrc` (enabled as shown under
[Trust a private CA](#trust-a-private-ca)) says so:

<!-- verified: lab:brew -->

```
netrc
```

<!-- verified: lab:brew -->

```
machine proxy.example.com
  login pullthrough
  password <token>
```

## Trust a private CA

brew runs `curl` with a scrubbed environment and without `~/.curlrc`: neither
`SSL_CERT_FILE` nor `CURL_CA_BUNDLE` reaches it. Tell brew to read `~/.curlrc`:

<!-- verified: lab:brew -->

```sh
export HOMEBREW_CURLRC=1
```

and name the CA there:

<!-- verified: lab:brew -->

```
cacert = "/etc/ssl/corp-ca.pem"
```

> **A certificate brew cannot verify sends it to the public API.** When the
> request to `HOMEBREW_API_DOMAIN` fails — an untrusted certificate is enough —
> brew falls back to `formulae.brew.sh` for the formula index. In the lab,
> where that host does not exist, this showed as a lookup of
> `formulae.brew.sh`; on a network with a way out, brew would simply use it.

## Check that it works

<!-- verified: lab:brew -->

```sh
brew install hello
```

prints the URL of every download (`==> Downloading
https://proxy.example.com/v1/homebrew/v2/homebrew/core/hello/…`).

## Good to know

- **Metadata falls back, bottles do not.** If the proxy cannot be reached, brew
  reads the formula index from `formulae.brew.sh` (its signature is verified
  either way). With `HOMEBREW_ARTIFACT_DOMAIN` set, a bottle the proxy refuses
  is not installed.
- **Not `HOMEBREW_BOTTLE_DOMAIN`.** That variable asks for a different,
  flat-file layout, which the proxy does not serve, and brew falls back from it
  to `ghcr.io`.
- **Only bottles.** What brew builds from source (`--build-from-source`, a
  formula without a bottle for the platform) and cask downloads come from their
  own upstream URLs.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  homebrew:
    type: homebrew
    url: https://formulae.brew.sh
```

The signed index is passed through byte for byte; bottle manifests are served
live and bottle blobs are verified against the SHA-256 in their URL and cached
immutably. `settings.bottleRegistryUrl` names the registry bottles come from
(default `https://ghcr.io`). Details: [backends: homebrew](../backends.md#homebrew).
