# Bazel (Bzlmod)

Use the proxy as the module registry. The examples use the upstream name
`bazel`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `bazel` |
| Package source | `https://proxy.example.com/v1/bazel` |
| Clients | bazel (6 and later, with Bzlmod) |
| Tested | Bazel 7.4: [in CI on every push](../ecosystem-tests-reference.md#bazel) and in the [client lab](../client-lab.md). |

## Configure

In the workspace's `.bazelrc` (or `~/.bazelrc`):

<!-- verified: ci:bazel lab:bazel -->

```
common --registry=https://proxy.example.com/v1/bazel
```

A module's source archive — usually a release on GitHub — comes through the
proxy as well: the proxy rewrites each module's `source.json` to point at
itself, and verifies the archive against the registry's integrity hash.

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name. Bazel
reads credentials for a host from `~/.netrc` (mode `600`):

<!-- verified: lab:bazel -->

```
machine proxy.example.com
  login pullthrough
  password <token>
```

## Trust a private CA

Bazel's server is a JVM with its own trust store, and it does not read PEM
bundles. Copy the trust store of a JDK — it holds the public CAs, which Bazel
still needs for what it downloads directly — and add the CA to the copy:

<!-- verified: lab:bazel -->

```sh
cp "$JAVA_HOME/lib/security/cacerts" /etc/ssl/corp-truststore.jks
keytool -importcert -noprompt -trustcacerts -alias corp-ca -file /etc/ssl/corp-ca.pem \
    -keystore /etc/ssl/corp-truststore.jks -storepass changeit
```

(`keytool` on a file that does not exist creates a store with the corporate CA
alone.)

and hand it to the server in `.bazelrc`:

<!-- verified: lab:bazel -->

```
startup --host_jvm_args=-Djavax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks --host_jvm_args=-Djavax.net.ssl.trustStorePassword=changeit
```

Without it, every registry request fails with `PKIX path building failed`.

## Check that it works

<!-- verified: lab:bazel -->

```sh
bazel fetch --repo="@platforms"
```

`bazel mod graph` resolves the whole module graph through the registry.

## Good to know

- **`MODULE.bazel.lock` records the registry URL** of every file it read, with
  a hash. A lock file written through the proxy is valid for the proxy's
  address, not for `bcr.bazel.build`, and the other way round; run `bazel mod
  deps --lockfile_mode=update` after switching.
- **Only Bzlmod.** `http_archive` rules in a `WORKSPACE` file download from the
  URLs they name. `git_repository` module sources are cloned from their forge
  (see [Git](git.md)).
- **Bazel's own downloads** (toolchains fetched by rules, Bazelisk's download
  of Bazel) do not go through the registry.
- **With a [personal cache link](../user-links.md)** the registry belongs in
  your user-level `~/.bazelrc`, not the workspace's `.bazelrc`.
  `MODULE.bazel.lock` records registry URLs, link included, and the link works
  like a password: do not commit one written through a personal link.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  bazel:
    type: bazel
    url: https://bcr.bazel.build
```

Registry files are served live; `source.json` is rewritten so the source
archive is fetched through the proxy (which is why `server.publicUrl` must be
set), verified against its integrity hash and cached immutably. Details:
[backends: bazel](../backends.md#bazel).
