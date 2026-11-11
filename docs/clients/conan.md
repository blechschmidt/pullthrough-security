# Conan (C and C++)

Make the proxy the only Conan remote. The examples use the upstream name
`conancenter`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `conan` |
| Package source | `https://proxy.example.com/v1/conancenter` |
| Clients | Conan 2 |
| Tested | Conan 2.34: [in CI on every push](../ecosystem-tests-reference.md#conan) and in the [client lab](../client-lab.md). Conan 1.x is not supported. |

## Configure

Remove ConanCenter and register the proxy, so that every recipe and binary
lookup goes through it:

<!-- verified: ci:conan lab:conan -->

```sh
conan remote remove conancenter
```

<!-- verified: lab:conan -->

```sh
conan remote add proxy https://proxy.example.com/v1/conancenter
```

`conan remote list` then shows the proxy alone. Name it in commands with
`--remote proxy` (or leave the option out: it is the only remote).

## Authenticate

**Conan cannot present a proxy token.** A Conan client gets the token it sends
from the remote's own login endpoint, and the proxy does not serve that
endpoint — forwarding it would hand out a session for the proxy's upstream
account. `conan remote login` is answered `501`:

<!-- output: lab:conan-token -->

```
ERROR: b'request not supported by backend\n'

Invalid server response, check remote URL and try again. [Remote: proxy]
```

and without a login Conan asks for credentials it cannot use (`Remote 'proxy'
needs authentication, obtaining credentials`).

Where access control is on, the operator admits Conan without a token — an
anonymous role scoped to exactly the Conan upstream, while every other upstream
keeps requiring a token. The lab runs Conan against such a proxy
([the configuration](../clients.md#clients-that-cannot-present-a-token)).

## Trust a private CA

Conan reads its CA bundle from a setting in `global.conf` (in the directory
`conan config home` prints):

<!-- verified: lab:conan -->

```
core.net.http:cacert_path=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:conan -->

```sh
conan download zlib/1.3.1 --remote proxy --only-recipe
```

## Good to know

- **Conan 2 only.** The proxy serves the revisions API (`/v2/…`) plus the one
  legacy route a Conan 2 client still sends (the capability probe); a Conan 1
  client cannot use it.
- **Uploading does not go through the proxy** (`conan upload`): it is
  read-only.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  conancenter:
    type: conan
    url: https://center2.conan.io
```

Files beneath a recipe or package revision are content-addressed and cached
indefinitely, verified by MD5 against the revision's manifest or the upstream's
checksum header; `latest`, revision lists and search are served live. Details:
[backends: conan](../backends.md#conan).
