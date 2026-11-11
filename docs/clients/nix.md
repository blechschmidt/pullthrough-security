# Nix

Use the proxy as the binary cache (substituter). The examples use the upstream
name `nix`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `nix` |
| Package source | `https://proxy.example.com/v1/nix` |
| Clients | nix |
| Tested | Nix 2.35: [in CI on every push](../ecosystem-tests-reference.md#nix) and in the [client lab](../client-lab.md). |

## Configure

In `nix.conf` (`/etc/nix/nix.conf`, or `~/.config/nix/nix.conf` for a trusted
user):

<!-- verified: lab:nix -->

```
substituters = https://proxy.example.com/v1/nix
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
require-sigs = true
```

`substituters` replaces `cache.nixos.org` (use `extra-substituters` to add
instead). `trusted-public-keys` stays the *upstream* cache's key: the proxy
serves each signed `narinfo` as it is, apart from the unsigned NAR location, so
Nix keeps verifying every path against the cache's own signature.

The same as command-line options, as the CI test passes them: `--option
substituters https://proxy.example.com/v1/nix`.

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name. Nix
reads it from a netrc file named in `nix.conf`:

<!-- verified: lab:nix -->

```
netrc-file = /etc/nix/netrc
```

`/etc/nix/netrc` (mode `600`; with a Nix daemon, readable by the daemon):

<!-- verified: lab:nix -->

```
machine proxy.example.com
  login pullthrough
  password <token>
```

## Trust a private CA

In `nix.conf`:

<!-- verified: lab:nix -->

```
ssl-cert-file = /etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:nix -->

```sh
nix-store --realise /nix/store/n5glp21rsz314qssw9fbvfswgy3kc68f-hello-2.12.1
```

Nix prints `copying path '…' from 'https://proxy.example.com/v1/nix'...` for
every path it substitutes. `nix config show substituters` prints the setting in
effect.

## Good to know

- **Sources are not substitutes.** Only binary-cache traffic goes to the
  substituter. Flake inputs, `fetchurl` and `fetchgit` sources are fetched from
  their own hosts when something has to be built or evaluated.
- **A store path the proxy refuses is built locally** if Nix can build it
  (`--fallback`, or no substitute at all): a refusal is not an install failure
  here.
- **Policies see store hashes, not names**: a binary cache addresses content
  by hash, so the coordinate of a store path is its 32-character hash, as name
  and as version — `n5glp21rsz314qssw9fbvfswgy3kc68f`, not `hello-2.12.1`. A
  rule written against a package name never matches; pin or deny the hash.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  nix:
    type: nix
    url: https://cache.nixos.org
    settings:
      trustedPublicKeys: "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
```

The proxy verifies each `narinfo` signature against `trustedPublicKeys` and
each NAR against its content address before serving it. Details:
[backends: nix](../backends.md#nix).
