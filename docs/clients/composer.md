# Composer (PHP)

Replace Packagist with the proxy. The examples use the upstream name
`packagist`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `composer` |
| Package source | `https://proxy.example.com/v1/packagist` |
| Clients | composer |
| Tested | Composer 2.11: [in CI on every push](../ecosystem-tests-reference.md#composer) and in the [client lab](../client-lab.md). |

## Configure

**Switch packagist.org off, and add the proxy.** Composer asks a repository
that is merely added *first* — and keeps asking packagist.org too. In the
global configuration, for every project and without touching a `composer.json`:

<!-- verified: ci:composer lab:composer -->

```sh
composer config --global repositories.packagist.org false
```

<!-- verified: lab:composer -->

```sh
composer config --global repositories.pullthrough composer https://proxy.example.com/v1/packagist
```

For a single project, the same two entries in its `composer.json`:

<!-- verified: lab:composer -->

```json
  "repositories": [
    { "type": "composer", "url": "https://proxy.example.com/v1/packagist" },
    { "packagist.org": false }
  ],
```

> **Redefining `packagist` is not enough.** Setting `repos.packagist` to the
> proxy with `composer config --global` looks like a replacement of the default
> repository and is not one (Composer 2.11): Composer installs from the proxy
> and still contacts `repo.packagist.org` — visibly so in `composer audit`,
> which fails where that host is unreachable, and silently during `require`
> and `update`. The lab's name server caught exactly this.

## Authenticate

Only when the proxy has access control switched on. Composer keeps credentials
per host in `auth.json` (next to the global configuration, or in the project —
do not commit it). The proxy takes your **proxy token** either way:

<!-- verified: lab:composer -->

```sh
composer config --global --auth http-basic.proxy.example.com pullthrough "<token>"
```

<!-- verified: lab:composer -->

```sh
composer config --global --auth bearer.proxy.example.com "<token>"
```

## Trust a private CA

<!-- verified: lab:composer -->

```sh
composer config --global cafile /etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:composer -->

```sh
composer require --prefer-dist --no-progress psr/log:3.0.0
composer audit
```

`composer audit` doubles as the check that nothing but the proxy is asked.
`composer config --global --list` shows the repositories; `-vvv` prints every
URL Composer downloads.

## Good to know

- **`composer.lock` records the proxy's address** of every dist archive
  (`"url": "https://proxy.example.com/v1/packagist/dist/psr/log/3.0.0/….zip"`),
  so installing from a lock file goes through the proxy too, and needs the
  proxy under the same public address.
- **An existing `composer.lock` goes around the proxy until it is written
  anew.** A lock file written against packagist.org names each dist archive
  where Packagist said it is — `api.github.com` — and `composer install`
  downloads exactly those URLs: the proxy is not asked. `composer update
  --lock` (or `update mirrors`) does not help; Composer keeps a dist URL that
  points at GitHub. An update pinned to every locked version does — the
  versions stay, the dist URLs become the proxy's:

  <!-- verified: lab:lock-composer -->

  ```sh
  composer update --no-progress --no-install $(php -r '
      $lock = json_decode(file_get_contents("composer.lock"), true);
      foreach (array_merge($lock["packages"], $lock["packages-dev"] ?? []) as $p) {
          echo "--with ", $p["name"], ":", $p["version"], " ";
      }')
  ```
- **`--prefer-source` bypasses the registry upstream.** A package's `source` is
  its Git repository, which Composer clones from the forge; route that through
  the proxy's [Git upstream](git.md), or keep `--prefer-dist` (the default for
  tagged versions). When the proxy refuses a dist, Composer 2.11 fails the
  install; old releases (2.2) fell back to cloning `source`.
- **`composer audit` works through the proxy**, with packagist.org switched
  off: Packagist embeds its security advisories in the package metadata the
  proxy serves. If the audit fails with `curl error 6 … repo.packagist.org`,
  packagist.org is still configured (see above).
- **`composer search` finds nothing**: the discovery APIs are not served.
- **With a [personal cache link](../user-links.md)** configure the repositories
  with `composer config --global`, not in `composer.json`. `composer.lock`
  records the URL of every archive, link included, and the link works like a
  password: do not commit a `composer.lock` written through a personal link.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  packagist:
    type: composer
    url: https://repo.packagist.org
```

`packages.json` and the v2 metadata are served live with every URL rewritten
to the proxy (which is why `server.publicUrl` must be set); dist archives are
cached immutably under a URL that names package, version and reference.
Details: [backends: composer](../backends.md#composer).
