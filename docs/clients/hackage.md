# Hackage (Haskell)

Use the proxy as cabal's package repository. The examples use the upstream name
`hackage`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `hackage` |
| Package source | `https://proxy.example.com/v1/hackage/` |
| Clients | cabal |
| Tested | cabal 3.16: [in CI on every push](../ecosystem-tests-reference.md#hackage) and in the [client lab](../client-lab.md). Stack: not tested. |

## Configure

A `repository` stanza in cabal's configuration (`~/.config/cabal/config`, or
`~/.cabal/config` on older installations) that keeps the name
`hackage.haskell.org` and changes its URL:

<!-- verified: ci:hackage lab:cabal -->

```
repository hackage.haskell.org
  secure: True
```

with the proxy as the URL:

<!-- verified: lab:cabal -->

```
  url: https://proxy.example.com/v1/hackage/
```

`secure: True` keeps cabal verifying Hackage's signed (TUF) metadata — which
the proxy serves byte for byte — against the root keys built into cabal.

## Authenticate

Only when the proxy has access control switched on. cabal has no credential
setting the proxy can use: credentials in the URL are sent only in answer to a
challenge the proxy does not send. cabal downloads with `curl`, though, and
curl reads `~/.curlrc`. One line there makes curl take credentials for a host
from `~/.netrc`:

<!-- verified: lab:cabal -->

```
netrc
```

`~/.netrc` (mode `600`), with your **proxy token** as the password and any
user name:

<!-- verified: lab:cabal -->

```
machine proxy.example.com
  login pullthrough
  password <token>
```

`~/.curlrc` applies to every `curl` the user runs; `netrc` only ever sends
credentials to the hosts listed in `~/.netrc`.

## Trust a private CA

curl reads the CA bundle from the environment:

<!-- verified: lab:cabal -->

```sh
export CURL_CA_BUNDLE=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: ci:hackage lab:cabal -->

```sh
cabal update
```

prints `Downloading the latest package list from hackage.haskell.org` — the
repository's name, now served by the proxy. With `-v2`, cabal prints each curl
command and its URL.

## Good to know

- **cabal asks DNS for mirrors.** It looks up `_mirrors.proxy.example.com` (a
  feature of its secure repositories) and prints `Warning: No mirrors found`
  when there is no such record. Harmless, and the one lookup besides the
  proxy's own name the lab sees from cabal.
- **`cabal.project.freeze` and `index-state`** name packages, versions and a
  timestamp, not a URL.
- **Uploading does not go through the proxy** (`cabal upload`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  hackage:
    type: hackage
    url: https://hackage.haskell.org
```

The package index and the TUF metadata are served live and byte-exact; source
tarballs are cached immutably, verified against the SHA-256 of their signed
`package.json` where the upstream exposes one. Details:
[backends: hackage](../backends.md#hackage).
