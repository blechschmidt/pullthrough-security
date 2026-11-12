# Swift Package Manager

Use the proxy as a Swift package registry. The examples use the upstream name
`swiftpm`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `swift` |
| Package source | `https://proxy.example.com/v1/swiftpm` |
| Clients | swift (SwiftPM registry support, Swift 5.7 and later) |
| Tested | Swift 6.4, against [Tuist's public registry](https://tuist.dev/blog/2025/11/26/opening-registry): [in CI on every push](../ecosystem-tests-reference.md#swift). Not in the client lab: signing in with a token was tried by hand only. |

## Configure

SwiftPM resolves packages from a registry only for dependencies declared by
registry identity (`.package(id: "scope.name", from: "1.0.0")`); dependencies
declared by Git URL are cloned from their forge (see [Git](git.md)).

<!-- verified: ci:swift -->

```sh
swift package-registry set https://proxy.example.com/v1/swiftpm
swift package resolve
```

`swift package-registry set` writes `.swiftpm/configuration/registries.json` in
the package (or, with `--global`, in the user's configuration). SwiftPM takes a
registry only over HTTPS; `--allow-insecure-http` lifts that for a test proxy.

## Authenticate

Only when the proxy has access control switched on. SwiftPM checks a token
before it stores it — it posts it to the registry address — and then sends it
as a bearer token, which is how the proxy takes it:

<!-- untested: the client lab runs no Swift client yet; tried by hand with Swift 6.4 against the proxy with access control on -->

```sh
swift package-registry login https://proxy.example.com/v1/swiftpm --token <token>
```

On Linux the token is written to `~/.netrc` (`machine proxy.example.com login
token password <token>`), after a question that `--no-confirm` answers. A token
the proxy does not accept fails the login, and nothing is stored.

## Trust a private CA

SwiftPM uses the system trust store; add the CA there — on Debian and Ubuntu,
a file in `/usr/local/share/ca-certificates/` followed by
`update-ca-certificates`, which is how the ecosystem test trusts its test CA.
No per-tool setting was tested.

## Check that it works

`swift package resolve -v` prints every registry request it makes, with the
address it went to.

## Good to know

- **`Package.resolved`** records registry packages by identity and version,
  not by registry URL.
- **Unsigned packages are installed with a warning** ("… source archive from
  … is not signed"). Tuist's registry, for one, serves archives it builds from
  Git tags, unsigned; SwiftPM checks an archive against the checksum in its
  release metadata either way.
- **Publishing does not go through the proxy** (`swift package-registry
  publish`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  swiftpm:
    type: swift
    url: https://tuist.dev/api/registry/swift
```

Release metadata, manifests and source archives of a published version are
cached immutably; a source archive is verified against the SHA-256 the release
metadata records, and served with the registry's `Content-Version` header (and,
for a manifest, the links to its Swift-version-specific variants). A registry
that redirects an archive download — Tuist sends it to its object store — is
followed by the proxy, not by the client. A login check is answered by the
proxy and never forwarded. Details: [backends: swift](../backends.md#swift).
