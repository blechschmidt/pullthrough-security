# Puppet Forge

Point r10k or the Puppet module tool at the proxy's Forge upstream. The
examples use the upstream name `puppet`; replace it with the name your operator
gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `puppet` |
| Package source | `https://proxy.example.com/v1/puppet` |
| Clients | r10k, `puppet module` |
| Tested | r10k 5.0: [in CI on every push](../ecosystem-tests-reference.md#puppet) and in the [client lab](../client-lab.md). `puppet module` 8.10: in the client lab. |

## Configure

**r10k** — the Forge's address in `r10k.yaml`:

<!-- verified: lab:r10k -->

```yaml
forge:
  baseurl: 'https://proxy.example.com/v1/puppet'
```

<!-- verified: ci:puppet lab:r10k -->

```sh
r10k puppetfile install --config r10k.yaml --verbose info
```

**puppet module** — the repository as an option (or `module_repository` in
`puppet.conf`):

<!-- verified: lab:puppet -->

```sh
puppet module install puppetlabs-stdlib --version 9.4.1 --target-dir "$PWD/modules" \
    --module_repository https://proxy.example.com/v1/puppet
```

## Authenticate

Only when the proxy has access control switched on. Both tools send a
configured value as the `Authorization` header as it is, so the value is
`Bearer` followed by your **proxy token**.

**r10k**:

<!-- verified: lab:r10k -->

```yaml
forge:
  baseurl: 'https://proxy.example.com/v1/puppet'
  authorization_token: 'Bearer <token>'
```

**puppet module**:

<!-- verified: lab:puppet -->

```sh
    --forge_authorization "Bearer <token>"
```

## Trust a private CA

Both run on Ruby, which reads the CA bundle from the environment:

<!-- verified: lab:r10k lab:puppet -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

## Check that it works

r10k with `--verbose info` prints each module it deploys; `puppet module
install` prints `Downloading from https://proxy.example.com/v1/puppet ...`.

## Good to know

- **A `Puppetfile` names modules and versions, not the Forge**; it works
  unchanged. (`mod` entries with a `:git` source are cloned from their forge —
  see [Git](git.md).)
- **r10k and Puppet are gems**: install them through the proxy's
  [RubyGems upstream](rubygems.md).
- **Publishing does not go through the proxy.**

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  puppet:
    type: puppet
    url: https://forgeapi.puppet.com
```

Module and release metadata is served live; a release tarball is verified
against the SHA-256 (or, for old releases, the MD5) the Forge publishes and
cached immutably. Details: [backends: puppet](../backends.md#puppet).
