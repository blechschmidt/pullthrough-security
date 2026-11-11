# Julia (Pkg)

Use the proxy as the Pkg server. The examples use the upstream name `julia`;
replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `julia` |
| Package source | `https://proxy.example.com/v1/julia` |
| Clients | julia (Pkg) |
| Tested | Julia 1.10: [in CI on every push](../ecosystem-tests-reference.md#julia) and in the [client lab](../client-lab.md). |

## Configure

<!-- verified: ci:julia lab:julia -->

```sh
export JULIA_PKG_SERVER=https://proxy.example.com/v1/julia
```

Set it in the shell profile, or in `~/.julia/config/startup.jl` as
`ENV["JULIA_PKG_SERVER"] = "…"`. The registry, package and artifact downloads
all go to the Pkg server.

## Authenticate

Only when the proxy has access control switched on. Pkg keeps a server's token
in a file named after the server's host and sends it as a bearer token.
`~/.julia/servers/proxy.example.com/auth.toml`:

<!-- verified: lab:julia -->

```toml
access_token = "<token>"
```

## Trust a private CA

<!-- verified: lab:julia -->

```sh
export JULIA_SSL_CA_ROOTS_PATH=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:julia -->

```sh
julia -e 'using Pkg; Pkg.add(name="Example", version="0.5.3"); using Example; println(Example.hello("lab"))'
```

`Pkg.pkg_server()` returns the server in effect.

## Good to know

- **Pkg falls back to Git.** When the Pkg server does not serve a package —
  because the proxy refused it — Pkg clones the package's Git repository
  instead, silently. The proxy's decisions are enforced only where Julia has no
  route to the forges (or where those go through the proxy's
  [Git upstream](git.md), which does not gate clones).
- **`Manifest.toml` does not change**: it records UUIDs and tree hashes.
- **Unregistered packages** (`Pkg.add(url=…)`) are Git clones, not Pkg-server
  downloads.
- **Policies see UUIDs.** The Pkg protocol names a package by UUID and tree
  hash, not by name and version, so a rule pins a UUID.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  julia:
    type: julia
    url: https://pkg.julialang.org
```

Every resource but the registry list is addressed by its Git tree hash, which
the proxy recomputes over the tarball before caching it. Details:
[backends: julia](../backends.md#julia).
