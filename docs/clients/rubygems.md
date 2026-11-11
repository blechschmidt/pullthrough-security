# RubyGems and Bundler

Mirror rubygems.org through the proxy. The examples use the upstream name
`rubygems`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `rubygems` |
| Package source | `https://proxy.example.com/v1/rubygems` |
| Clients | Bundler, gem |
| Tested | Bundler 2.5: [in CI on every push](../ecosystem-tests-reference.md#rubygems) and in the [client lab](../client-lab.md). gem 3.5: in the client lab. |

## Configure

### Bundler: a mirror

A mirror redirects the `source "https://rubygems.org"` of every Gemfile to the
proxy. No Gemfile changes, and `Gemfile.lock` keeps naming rubygems.org:

<!-- verified: ci:rubygems lab:bundler -->

```sh
bundle config set --global mirror.https://rubygems.org https://proxy.example.com/v1/rubygems
```

`--global` writes `~/.bundle/config`; `--local` writes the project's
`.bundle/config`.

### Bundler: the proxy as the Gemfile's source

<!-- verified: lab:gem -->

```ruby
source "https://proxy.example.com/v1/rubygems"
```

`Gemfile.lock` then records the proxy's address (`remote:
https://proxy.example.com/v1/rubygems/`).

### gem

<!-- verified: lab:gem -->

```sh
gem sources --add https://proxy.example.com/v1/rubygems/ --remove https://rubygems.org/
```

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name.

**Bundler** — credentials for the proxy's host, kept in Bundler's configuration
and out of the Gemfile and the lock file:

<!-- verified: lab:bundler lab:gem -->

```sh
bundle config set --global proxy.example.com "pullthrough:<token>"
```

**gem** — in the source URL:

<!-- verified: lab:gem -->

```sh
gem sources --add "https://pullthrough:<token>@proxy.example.com/v1/rubygems/" --remove https://rubygems.org/
```

## Trust a private CA

Ruby reads the CA bundle from the environment — for Bundler's index requests,
for the gem downloads and for `gem`:

<!-- verified: lab:bundler lab:gem -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

Bundler's own `ssl_ca_cert` setting is not enough: it covers the index
requests, and the gem download then fails certificate verification.

## Check that it works

<!-- verified: lab:bundler -->

```sh
bundle install
```

`bundle config list` shows the mirror; `bundle install --verbose` prints every
URL it fetches.

## Good to know

- **Prefer the mirror.** With a mirror, `Gemfile` and `Gemfile.lock` are the
  same files with and without the proxy; with the proxy as the Gemfile's
  source, both name the proxy's address.
- **Gems are verified by the proxy** against the SHA-256 the registry's index
  declares, including platform-specific gems.
- **Publishing does not go through the proxy** (`gem push`): it is read-only.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  rubygems:
    type: rubygems
    url: https://rubygems.org
```

The compact index (`/versions`, `/info/<gem>`) is served live; `.gem` files are
cached immutably. Details: [backends: rubygems](../backends.md#rubygems).
