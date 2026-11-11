# Swift Package Manager

Use the proxy as a Swift package registry. The examples use the upstream name
`swiftpm`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `swift` |
| Package source | `https://proxy.example.com/v1/swiftpm` |
| Clients | swift (SwiftPM registry support, Swift 5.7 and later) |
| Tested | **Not tested with a real client.** No public registry implements the Swift Package Registry API, so neither CI nor the client lab has one to put behind the proxy. The backend is covered by protocol-level tests against a stand-in registry. |

## Configure

SwiftPM resolves packages from a registry only for dependencies declared by
registry identity (`.package(id: "scope.name", from: "1.0.0")`); dependencies
declared by Git URL are cloned from their forge (see [Git](git.md)).

<!-- untested: no public Swift package registry exists to run a real swift client against; these are the commands SwiftPM documents for a registry at this address -->

```sh
swift package-registry set https://proxy.example.com/v1/swiftpm
swift package resolve
```

`swift package-registry set` writes `.swiftpm/configuration/registries.json` in
the package (or, with `--global`, in the user's configuration).

## Authenticate

Only when the proxy has access control switched on. SwiftPM stores a token per
registry and sends it as a bearer token, which is how the proxy takes it:

<!-- untested: no public Swift package registry exists to run a real swift client against -->

```sh
swift package-registry login https://proxy.example.com/v1/swiftpm --token <token>
```

## Trust a private CA

SwiftPM uses the system trust store; add the CA there. No per-tool setting was
tested.

## Check that it works

`swift package resolve -v` prints the registry requests it makes.

## Good to know

- **`Package.resolved`** records registry packages by identity and version,
  not by registry URL.
- **Publishing does not go through the proxy** (`swift package-registry
  publish`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  swiftpm:
    type: swift
    url: https://swiftpackageregistry.example.com
```

Release metadata, manifests and source archives of a published version are
cached immutably; a source archive is verified against the SHA-256 the release
metadata records. Details: [backends: swift](../backends.md#swift).
