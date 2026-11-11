# Hex (Elixir, Erlang)

Mirror hex.pm through the proxy. The examples use the upstream name `hex`;
replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `hex` |
| Package source | `https://proxy.example.com/v1/hex` |
| Clients | mix (Hex) |
| Tested | Elixir 1.16 with Hex 2.7: [in CI on every push](../ecosystem-tests-reference.md#hex) and in the [client lab](../client-lab.md). rebar3: not tested. |

## Configure

Set the proxy as the mirror of the default `hexpm` repository:

<!-- verified: ci:hex lab:hex -->

```sh
export HEX_MIRROR=https://proxy.example.com/v1/hex
```

<!-- verified: lab:hex -->

```sh
mix local.hex --force
mix deps.get
```

With `HEX_MIRROR` set, Mix also installs Hex itself (`mix local.hex`) and
rebar from the mirror.

Do **not** add the proxy as a separately named repository (`mix hex.repo add`):
the registry is signed for the repository name `hexpm`, and Hex rejects it
under any other name.

## Authenticate

**mix cannot use a proxy that requires a token.** Mix has no credential setting
for the download of Hex itself, so `mix local.hex` is answered `401`:

<!-- output: lab:hex-token -->

```
** (Mix) httpc request failed with: {:bad_status_code, 401}

Could not install Hex because Mix could not download metadata at https://proxy.example.com/v1/hex/installs/hex-1.x.csv.
```

Hex, installed some other way, has no setting the proxy could use either. A
key (`HEX_REPOS_KEY`, `HEX_API_KEY`) is not sent to a mirror; and with a
*trusted* mirror (`HEX_TRUSTED_MIRROR`) Hex 2.7 first exchanges the key at
hex.pm — it asked for `hex.pm` and stopped with `Failed to exchange API key for
OAuth token`. **Do not put a proxy token into Hex's key settings.** (The lab's
script asserts the `401` above; the rest was tried by hand on the lab's
network.)

Where access control is on, the operator has to admit anonymous reads for the
Hex upstream ([how](../clients.md#clients-that-cannot-present-a-token)).

## Trust a private CA

Two clients, two settings. **Hex** reads a CA bundle from the environment:

<!-- verified: lab:hex -->

```sh
export HEX_CACERTS_PATH=/etc/ssl/corp-ca.pem
```

**Mix** — which downloads Hex with `mix local.hex` — uses the system trust
store only. Put the CA there (on Debian and Ubuntu: a file in
`/usr/local/share/ca-certificates/` and `update-ca-certificates`; the lab's
image has no such tool and appends to the bundle):

<!-- verified: lab:hex -->

```sh
cat /etc/ssl/corp-ca.pem >> /etc/ssl/certs/ca-certificates.crt
```

> **Where there is no system trust store at all, Mix does not fail — it skips
> verification.** That is the case in slim container images (`elixir:1.16-slim`
> has no `ca-certificates` package). Mix prints "warning: failed to load system
> certificates. SSL peer verification will be skipped but downloads are still
> verified with a checksum" and downloads Hex over an unverified connection;
> what it downloads is still checked against Hex's signed checksum list. The
> lab asserts this. With a trust store that merely lacks the CA, Mix fails
> instead (`Unknown CA`).

## Check that it works

`mix deps.get` prints `* Getting jason (Hex package)`; `mix hex.config` shows
the mirror in effect.

## Good to know

- **`mix.lock` does not change**: it records names, versions and checksums, no
  URL.
- **Signatures are still verified by Hex**: registry resources are served byte
  for byte, so Hex checks them against hex.pm's public key.
- **The proxy serves the repository, not the hex.pm API**: `mix hex.publish`,
  `mix hex.search` and `mix hex.user` talk to `hex.pm` directly.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  hex:
    type: hex
    url: https://repo.hex.pm
```

Registry resources (`/names`, `/versions`, `/packages/<name>`) and the
`/installs/` files are served live and byte-exact; tarballs are verified
against the checksum the signed registry records and cached immutably. Details:
[backends: hex](../backends.md#hex).
