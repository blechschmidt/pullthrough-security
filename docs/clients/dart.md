# Dart and Flutter (pub)

Use the proxy as the hosted pub repository. The examples use the upstream name
`pub`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `dart` (alias `pub`) |
| Package source | `https://proxy.example.com/v1/pub` |
| Clients | dart pub (flutter pub uses the same client) |
| Tested | Dart 3.5: [in CI on every push](../ecosystem-tests-reference.md#dart) and in the [client lab](../client-lab.md). Flutter: not tested. |

## Configure

<!-- verified: ci:dart lab:dart -->

```sh
export PUB_HOSTED_URL=https://proxy.example.com/v1/pub
```

<!-- verified: ci:dart lab:dart -->

```sh
dart pub get
```

## Authenticate

Only when the proxy has access control switched on. pub sends a bearer token to
a hosted URL it has one for — your **proxy token**. With `--env-var` the token
is read from an environment variable each time, and stored nowhere:

<!-- verified: lab:dart -->

```sh
dart pub token add https://proxy.example.com/v1/pub --env-var PULLTHROUGH_TOKEN
```

<!-- verified: lab:dart -->

```sh
export PULLTHROUGH_TOKEN="<token>"
```

Without `--env-var`, `dart pub token add` prompts for the token and stores it
in pub's own configuration (not tested).

## Trust a private CA

**dart pub uses the system trust store and nothing else.** Neither
`SSL_CERT_FILE` nor the Dart VM's `--root-certs-file` reaches it; with only
those set, `dart pub get` fails with a TLS error. Add the CA to the store — on
Debian and Ubuntu:

<!-- verified: lab:dart -->

```sh
cp /etc/ssl/corp-ca.pem /usr/local/share/ca-certificates/corp-ca.crt
```

followed by `update-ca-certificates`.

## Check that it works

`dart pub get` succeeds, and `pubspec.lock` names the proxy for every hosted
package (below). `dart pub get -v` prints every request.

## Good to know

- **`pubspec.lock` records the hosted URL** of every package (`url:
  "https://proxy.example.com/v1/pub/"`): a lock file written through the proxy
  is tied to its address.
- **An existing `pubspec.lock` is rewritten, not followed.** One that names
  `pub.dev` is not fetched from there: `dart pub get --enforce-lockfile` stops
  (`Unable to satisfy pubspec.yaml using pubspec.lock`), and a plain `dart pub
  get` moves the lock file onto the proxy with the same versions:

  <!-- verified: lab:lock-pub -->

  ```sh
  dart pub get
  dart pub get --enforce-lockfile
  ```
- **Archives come back through the proxy**: the version listing the proxy
  serves has its archive URLs rewritten, and each archive is verified against
  the SHA-256 pub.dev publishes.
- **Publishing does not go through the proxy** (`dart pub publish`).
- **With a [personal cache link](../user-links.md)** `pubspec.lock` records the
  hosted URL of every package, link included, and the link works like a
  password: do not commit a `pubspec.lock` written through a personal link.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  pub:
    type: dart
    url: https://pub.dev
```

Version listings are served live with their archive URLs rewritten to the
proxy (which is why `server.publicUrl` must be set); archives are cached
immutably. Details: [backends: dart](../backends.md#dart).
