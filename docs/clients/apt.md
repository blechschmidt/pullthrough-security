# APT (Debian, Ubuntu)

Point APT at the proxy's Debian or Ubuntu upstream. The examples use the
upstream name `debian`; replace it with the name your operator gave the
upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `apt` |
| Package source | `https://proxy.example.com/v1/debian` (the archive root: `dists/`, `pool/`) |
| Clients | apt, apt-get |
| Tested | apt 2.6 (Debian 12): [in CI on every push](../ecosystem-tests-reference.md#apt) and in the [client lab](../client-lab.md). |

## Configure

Replace the distribution's sources with the proxy. One upstream fronts one
archive: `deb.debian.org/debian` here; the security archive
(`security.debian.org/debian-security`) and Ubuntu's are upstreams of their own.

`/etc/apt/sources.list.d/pullthrough.sources` (deb822 format):

<!-- verified: lab:apt -->

```
Types: deb
URIs: https://proxy.example.com/v1/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
```

Remove or disable the files that name the distribution's own mirrors
(`/etc/apt/sources.list`, `/etc/apt/sources.list.d/debian.sources`), or APT
keeps using them next to the proxy.

The one-line form, in `/etc/apt/sources.list`, is `deb
https://proxy.example.com/v1/debian bookworm main` (that is what the CI test
writes).

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name.
`/etc/apt/auth.conf.d/pullthrough.conf` (mode `600`):

<!-- verified: lab:apt -->

```
machine proxy.example.com
login pullthrough
password <token>
```

## Trust a private CA

For this host only, in `/etc/apt/apt.conf.d/99pullthrough`:

<!-- verified: lab:apt -->

```
Acquire::https::proxy.example.com::CAInfo "/etc/ssl/corp-ca.pem";
```

A minimal image has no `ca-certificates` package; with this setting it does not
need one to reach the proxy.

## Check that it works

<!-- verified: lab:apt -->

```sh
apt-get update
apt-cache policy hello | grep -q "https://proxy.example.com/v1/debian bookworm/main"
```

`apt-cache policy <package>` names the source of every candidate version.

## Good to know

- **Signatures are still verified by APT.** `InRelease` is served byte for
  byte, so APT checks the archive signature with the keys the distribution
  ships (`Signed-By`), and each `.deb` against the hashes in the signed index.
- **APT picks the version.** A package is refused by name (and version) at the
  download of its `.deb`; `apt-get update` still succeeds.
- **A container image build** gets the same three files with `COPY` before its
  first `apt-get update`.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  debian:
    type: apt
    url: https://deb.debian.org/debian
```

`dists/` metadata is served live; a `.deb` is verified against the SHA-256
that the chain `Release` → `Packages` declares before it is cached. With
`settings.gpgKeyFile` the proxy also validates the `Release` signature itself.
Details: [backends: apt](../backends.md#apt).
