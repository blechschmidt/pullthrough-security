# conda, mamba, micromamba

Resolve conda channels through the proxy. The examples use the upstream name
`conda-forge` — the name of the channel it fronts, which is what makes the
configuration below work; replace or extend it with the channels your operator
configured ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `conda` |
| Package source | `https://proxy.example.com/v1/conda-forge` (the channel root) |
| Clients | conda, micromamba (mamba reads the same file) |
| Tested | conda 24.9: [in CI on every push](../ecosystem-tests-reference.md#conda) and in the [client lab](../client-lab.md). micromamba 2.0: in the client lab. pixi: not tested. |

## Configure

A **channel alias** turns every channel *name* into an address under the proxy:
`conda-forge` becomes `https://proxy.example.com/v1/conda-forge`. Name the
upstreams after the channels and `-c conda-forge`, `environment.yml` files and
existing habits keep working unchanged.

`~/.condarc` (read by conda, mamba and micromamba):

<!-- verified: lab:conda lab:micromamba -->

```yaml
channel_alias: https://proxy.example.com/v1
channels:
  - conda-forge
default_channels: []
```

`default_channels: []` matters: it empties the `defaults` channel, which
otherwise still points at `repo.anaconda.com`.

A channel given by full URL bypasses the alias — and with it the proxy — unless
the URL is the proxy's (`-c https://proxy.example.com/v1/conda-forge`, which is
what the CI test passes together with `--override-channels`).

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name, in
the alias:

<!-- verified: lab:conda lab:micromamba -->

```yaml
channel_alias: https://pullthrough:<token>@proxy.example.com/v1
```

The user name is needed: conda sends nothing for a URL that has the token
alone before the `@`, and every request is answered `401`.

## Trust a private CA

In `~/.condarc`:

<!-- verified: lab:conda lab:micromamba -->

```yaml
ssl_verify: /etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:conda -->

```sh
conda create --yes --quiet --prefix "$PWD/env" tzdata=2024a
conda config --show channels default_channels | grep -q "conda-forge"
```

`conda config --show-sources` prints which file each setting comes from — a
system-wide `.condarc` (Miniforge ships one) is merged with yours.
`conda install --dry-run -v` prints the channel URLs it queries.

## Good to know

- **One upstream per channel.** A channel that has no upstream on the proxy
  resolves, through the alias, to an address the proxy does not serve: the
  install fails rather than going around the proxy.
- **Explicit lock files** (`conda list --explicit`, conda-lock) record package
  URLs: written through the proxy they name the proxy.
- **Packages are verified by the proxy** against the SHA-256 the channel's
  `repodata.json` records.
- **pip inside a conda environment** is a separate client: see [pip](pip.md).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  conda-forge:
    type: conda
    url: https://conda.anaconda.org/conda-forge
```

`repodata.json` is served live; package archives (`.conda`, `.tar.bz2`) are
cached immutably. Details: [backends: conda](../backends.md#conda).
