# cargo

Point cargo at the proxy's crates.io upstream by replacing the `crates-io`
source. The examples use the upstream name `crates`; replace it with the name
your operator gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `cargo` |
| Package source | `sparse+https://proxy.example.com/v1/crates/` (a sparse registry) |
| Clients | cargo |
| Tested | cargo 1.99: [in CI on every push](../ecosystem-tests-reference.md#cargo) and in the [client lab](../client-lab.md). |

## Configure

Source replacement redirects every crates.io dependency to the proxy without
touching a `Cargo.toml`. The trailing slash on the `sparse+` URL is required.

In the user-level configuration, `$CARGO_HOME/config.toml`:

<!-- verified: lab:cargo -->

```toml
[source.crates-io]
replace-with = "proxy"

[source.proxy]
registry = "sparse+https://proxy.example.com/v1/crates/"
```

`$CARGO_HOME` is `~/.cargo` unless the variable is set — and the official Rust
container image sets it to `/usr/local/cargo`, so a `~/.cargo/config.toml`
written there is not read. A `.cargo/config.toml` in the project (or any parent
directory) works the same and can be committed.

Without a file, as in a CI job, pass the two settings as `--config` flags:

<!-- verified: lab:cargo-flags -->

```sh
cargo --config 'source.crates-io.replace-with="proxy"' \
      --config 'source.proxy.registry="sparse+https://proxy.example.com/v1/crates/"' \
      fetch
```

> **`CARGO_SOURCE_…` environment variables do not work.** cargo maps most of its
> configuration to `CARGO_*` variables, but not the `[source]` table: with
> `CARGO_SOURCE_CRATES_IO_REPLACE_WITH` set, cargo still goes to crates.io.

## Authenticate

**cargo cannot use a proxy that requires a token.** cargo presents a registry
token only after the registry answered `401`, and for crate downloads only when
the registry's `config.json` declares `"auth-required": true`, which the proxy's
does not. With a token configured (`[registries.proxy]` with a matching `index`),
cargo reads the index and is then refused the download:

<!-- output: lab:cargo-token -->

```
error: failed to download from `https://proxy.example.com/v1/crates/api/v1/crates/cfg-if/1.0.0/download`

Caused by:
  failed to get successful HTTP response from `https://proxy.example.com/v1/crates/api/v1/crates/cfg-if/1.0.0/download`, got 401
```

Where access control is on, the operator has to admit cargo without a token:
an anonymous role scoped to the cargo upstream
([how](../clients.md#clients-that-cannot-present-a-token)).

## Trust a private CA

In `$CARGO_HOME/config.toml`:

<!-- verified: lab:cargo -->

```toml
[http]
cainfo = "/etc/ssl/corp-ca.pem"
```

or in the environment:

<!-- verified: lab:cargo-flags -->

```sh
export CARGO_HTTP_CAINFO=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:cargo -->

```sh
cargo fetch
```

prints ``Updating `proxy` index`` and ``Downloaded cfg-if v1.0.0 (registry `proxy`)``
— the replacement source by name. An error that mentions `index.crates.io`
means the configuration was not read (see `$CARGO_HOME` above).

## Good to know

- **`Cargo.lock` does not change.** It keeps naming crates.io
  (`source = "registry+https://github.com/rust-lang/crates.io-index"`) and the
  crate checksums; source replacement is a local setting. The same lock file
  works with and without the proxy.
- **Git dependencies do not come from the registry.** A dependency declared
  with `git = "…"` is cloned from its forge. Route those through the proxy's
  [Git upstream](git.md) with an `insteadOf` rule (cargo with
  `net.git-fetch-with-cli = true` uses the `git` command and its configuration;
  not tested).
- **A refused crate is a `403`** on the download, with the proxy's reason in
  the body cargo prints:

  <!-- output: lab:refused-cargo -->

  ```
  error: failed to download from `https://proxy.example.com/v1/crates/api/v1/crates/itoa/1.0.11/download`

  Caused by:
    failed to get successful HTTP response from `https://proxy.example.com/v1/crates/api/v1/crates/itoa/1.0.11/download`, got 403
    debug headers:
    x-cache: BLOCKED
    body:
    {"error":"artifact blocked by supply-chain admission policy","code":"denylist","reason":"package \"itoa\" is denylisted by policy …
  ```

  [What a refusal means and what to do](../clients.md#when-the-proxy-refuses-a-package).
- **Publishing does not go through the proxy** (`cargo publish`, `cargo
  login`, `cargo owner`): it is read-only, and cargo refuses those commands on a
  replaced source anyway.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  crates:
    type: cargo
    url: https://index.crates.io
```

The sparse index is served live; `config.json` is rewritten so `.crate`
downloads come back through the proxy (which is why `server.publicUrl` must be
set) and are cached immutably. Details: [backends: cargo](../backends.md#cargo).
