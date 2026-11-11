# JSR (Deno)

Resolve JSR packages through the proxy. The examples use the upstream name
`jsr`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `jsr` |
| Package source | `https://proxy.example.com/v1/jsr` |
| Clients | deno; Node package managers through JSR's npm-compatible registry |
| Tested | Deno 2.9: [in CI on every push](../ecosystem-tests-reference.md#jsr) and in the [client lab](../client-lab.md). npm with the `@jsr` scope: in the client lab. |

## Configure

### Deno

<!-- verified: ci:jsr lab:deno -->

```sh
export JSR_URL=https://proxy.example.com/v1/jsr
```

<!-- verified: lab:deno -->

```sh
deno add jsr:@luca/flag@1.0.1
```

Deno resolves `npm:` specifiers the way npm does — from `.npmrc`, in the
project or the home directory — so npm packages go through the proxy's
[npm upstream](npm.md):

<!-- verified: lab:deno -->

```ini
registry=https://proxy.example.com/v1/npm/
```

### npm, Yarn, pnpm

Node package managers do not speak JSR's protocol; they install JSR packages
from `https://npm.jsr.io`, an npm registry. Front it with an upstream of type
`npm` and select it for the `@jsr` scope: see
[npm](npm.md#configure).

## Authenticate

Only when the proxy has access control switched on. Deno sends a bearer token
per host — your **proxy token** — to JSR:

<!-- verified: lab:deno -->

```sh
export DENO_AUTH_TOKENS="<token>@proxy.example.com"
```

`DENO_AUTH_TOKENS` does not apply to `npm:` specifiers; those take the token
from `.npmrc`, like npm:

<!-- verified: lab:deno -->

```ini
//proxy.example.com/v1/npm/:_authToken=<token>
```

## Trust a private CA

<!-- verified: lab:deno -->

```sh
export DENO_CERT=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:deno -->

```sh
deno cache "jsr:@luca/flag@1.0.1"
```

Deno prints a `Download https://proxy.example.com/v1/jsr/…` line for every
file it fetches.

## Good to know

- **`deno.lock`** records an integrity hash for a JSR package and nothing
  else. For an npm package that comes from a registry other than npmjs.org it
  also records the tarball's URL — the proxy's.
- **Every module file is verified by the proxy** against the SHA-256 in the
  version's manifest.
- **Publishing does not go through the proxy** (`deno publish`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  jsr:
    type: jsr
    url: https://jsr.io
  npm-jsr:
    type: npm
    url: https://npm.jsr.io
```

Package and version metadata is served live; module files are cached
immutably. Details: [backends: jsr](../backends.md#jsr).
