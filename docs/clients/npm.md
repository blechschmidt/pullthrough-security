# npm, Yarn, pnpm, Bun

Point the JavaScript package managers at the proxy's npm upstream instead of
`registry.npmjs.org`. The examples use the upstream name `npm`; replace it with
the name your operator gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `npm` |
| Package source | `https://proxy.example.com/v1/npm/` |
| Clients | npm, Yarn 1, Yarn 2 and later, pnpm, Bun |
| Tested | npm 10.9: [in CI on every push](../ecosystem-tests-reference.md#npm) and in the [client lab](../client-lab.md). Yarn 1.22, Yarn 4.5, pnpm 9.15, Bun 1.1: in the client lab. |

## Configure

### npm

A project-level `.npmrc` — or `~/.npmrc`, for every project of a user:

<!-- verified: ci:npm lab:npm -->

```ini
registry=https://proxy.example.com/v1/npm/
```

In a CI job or a Dockerfile, the environment does the same without a file:

<!-- verified: lab:npm-env -->

```sh
export NPM_CONFIG_REGISTRY=https://proxy.example.com/v1/npm/
```

To send only one scope through an upstream, name the scope. This is also how
Node package managers install [JSR](jsr.md) packages, which JSR serves from an
npm-compatible registry of its own (`https://npm.jsr.io`, here behind an
upstream called `npm-jsr`):

<!-- verified: lab:npm-jsr -->

```ini
registry=https://proxy.example.com/v1/npm/
@jsr:registry=https://proxy.example.com/v1/npm-jsr/
```

### Yarn 1 (classic)

Yarn 1 has its own file, `.yarnrc` (project) or `~/.yarnrc`:

<!-- verified: lab:yarn-classic -->

```
registry "https://proxy.example.com/v1/npm/"
```

### Yarn 2 and later

`.yarnrc.yml` (project) or `~/.yarnrc.yml`:

<!-- verified: lab:yarn -->

```yaml
npmRegistryServer: "https://proxy.example.com/v1/npm"
```

Corepack — which downloads the Yarn (or pnpm) release that `package.json` names
— is a client of the npm registry too, and has its own setting:

<!-- verified: lab:yarn lab:pnpm -->

```sh
export COREPACK_NPM_REGISTRY=https://proxy.example.com/v1/npm
```

### pnpm

pnpm reads `.npmrc`: the [npm configuration](#npm) above applies as it is.

### Bun

`bunfig.toml` (project) or `~/.bunfig.toml`:

<!-- verified: lab:bun -->

```toml
[install]
registry = "https://proxy.example.com/v1/npm/"
```

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as a bearer token — never an npmjs.org token; the proxy holds the
upstream's credentials itself.

**npm and pnpm** — a line in `.npmrc` that scopes the token to the registry URL
(the trailing slash matters):

<!-- verified: lab:npm lab:pnpm -->

```ini
//proxy.example.com/v1/npm/:_authToken=<token>
```

Keep the token out of a project `.npmrc` that is committed: put this line into
`~/.npmrc`, which is what `npm config set` writes:

<!-- verified: lab:npm-env -->

```sh
npm config set //proxy.example.com/v1/npm/:_authToken "<token>"
```

**Yarn 1** reads the token from `.npmrc` and sends it with every request only
when `always-auth` is set:

<!-- verified: lab:yarn-classic -->

```ini
//proxy.example.com/v1/npm/:_authToken=<token>
always-auth=true
```

**Yarn 2 and later** — in `.yarnrc.yml` (prefer `~/.yarnrc.yml` for the token):

<!-- verified: lab:yarn -->

```yaml
npmAlwaysAuth: true
npmAuthToken: "<token>"
```

**Bun** — the registry entry with its token:

<!-- verified: lab:bun -->

```toml
[install]
registry = { url = "https://proxy.example.com/v1/npm/", token = "<token>" }
```

**Corepack** takes it from the environment:

<!-- verified: lab:yarn lab:pnpm -->

```sh
export COREPACK_NPM_TOKEN="<token>"
```

With several upstreams (the `@jsr` scope above), each registry URL needs its own
`_authToken` line.

## Trust a private CA

Only when the proxy's certificate is issued by a CA that is not in the system
trust store. Node.js does not use the system store by default, so each client is
told where the CA certificate is.

**npm and pnpm** — in `.npmrc`:

<!-- verified: lab:npm lab:pnpm -->

```ini
cafile=/etc/ssl/corp-ca.pem
```

**Yarn 1** — in `.yarnrc`:

<!-- verified: lab:yarn-classic -->

```
cafile "/etc/ssl/corp-ca.pem"
```

**Yarn 2 and later** — in `.yarnrc.yml`:

<!-- verified: lab:yarn -->

```yaml
httpsCaFilePath: /etc/ssl/corp-ca.pem
```

**Bun** — in `bunfig.toml`, under `[install]`:

<!-- verified: lab:bun -->

```toml
cafile = "/etc/ssl/corp-ca.pem"
```

**npm, Yarn, pnpm and Corepack** — Node's own variable, which adds the CA to
the built-in ones for every Node process:

<!-- verified: lab:npm-env lab:yarn lab:pnpm -->

```sh
export NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:npm -->

```sh
npm ping
npm view left-pad version
```

`npm ping` prints the registry it reached (`PING https://proxy.example.com/v1/npm/`).
After an install, the lock file shows where each package came from (below).
`ptctl selftest` checks every upstream at once, and tells a network problem from
a rejected token ([client CLI](../client-cli.md)).

## Good to know

- **Lock files record the proxy's address — for npm and Yarn 1.**
  `package-lock.json` and a Yarn 1 `yarn.lock` store each tarball's URL
  (`"resolved": "https://proxy.example.com/v1/npm/is-number/-/is-number-7.0.0.tgz"`),
  so a lock file written through the proxy is tied to the proxy's address.
  Yarn 2+ (`resolution: "is-number@npm:7.0.0"`) and pnpm (an integrity hash)
  record no URL: their lock files are the same whichever registry served the
  package.
- **An existing `package-lock.json` needs no change.** One that names
  `registry.npmjs.org` is installed through the proxy as it is: npm replaces
  that host with the configured registry (its `replace-registry-host` setting,
  default `npmjs`) and leaves the file alone.

  <!-- verified: lab:lock-npm -->

  ```sh
  npm ci --no-audit --no-fund
  ```
- **An existing Yarn 1 `yarn.lock` has to be rewritten.** Yarn 1 fetches
  exactly the URL the lock file records — `registry.yarnpkg.com` — whatever
  registry is configured: on a network with a way out it goes around the
  proxy, without one the install fails (`getaddrinfo ENOTFOUND
  registry.yarnpkg.com`). Replace the host in the lock file; the integrity
  hashes stay valid:

  <!-- verified: lab:lock-yarn-classic -->

  ```sh
  sed -i 's#https://registry.yarnpkg.com/#https://proxy.example.com/v1/npm/#g' yarn.lock
  ```
- **`npm audit` is not available through the proxy.** Its endpoints are `POST`
  requests, and the proxy serves `GET` and `HEAD` only. An install is unaffected
  (npm ignores the failed audit request); `npm audit` itself reports `audit
  endpoint returned an error`. The proxy's own
  [vulnerability gate](../security-model.md) checks what it serves, and
  `ptctl inspect` shows a package's findings.
- **Publishing does not go through the proxy.** It is read-only: `npm publish`,
  `npm login` and the other write commands need the registry itself.
- **A refused package is a `403`**, with the proxy's reason in the error:

  <!-- output: lab:refused-npm -->

  ```
  npm error code E403
  npm error 403 403 Forbidden - GET https://proxy.example.com/v1/npm/left-pad/-/left-pad-1.3.0.tgz - artifact blocked by supply-chain admission policy
  npm error 403 In most cases, you or one of your dependencies are requesting
  npm error 403 a package version that is forbidden by your security policy, or
  npm error 403 on a server you do not have access to.
  ```

  The metadata of a refused package is still served — it is the tarball that is
  refused — so `npm view` works and the install fails at the download.
  [What a refusal means and what to do](../clients.md#when-the-proxy-refuses-a-package).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  npm:
    type: npm
    url: https://registry.npmjs.org
```

Packuments are served live with their tarball URLs rewritten to the proxy
(which is why `server.publicUrl` must be set); tarballs are cached immutably.
A private or scoped registry is another upstream of type `npm`, with its
`credentials` on the proxy. Details: [backends: npm](../backends.md#npm).
