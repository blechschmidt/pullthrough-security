# Running pullthrough with systemd

This page installs the proxy on one Linux host as a hardened systemd service
that terminates TLS itself, renews its certificate, and upgrades with a
readiness check and automatic rollback. Everything lives in
[`deploy/systemd/`](../deploy/systemd/):

| File | What it is |
|---|---|
| `install.sh` | The installer. The first run sets everything up; every later run is an upgrade |
| `pullthrough.service` | The unit |
| `config.yaml.in` | The configuration template the installer renders once |
| `pullthrough-sync-certs` | Publishes a renewed certificate and restarts the proxy when it changed |
| `pullthrough-sync-certs.service`, `.timer` | Run it once a day |

The project's own instance, `https://aiden.blechschmidt.io:8889`, is installed
this way (see [The project's instance](#the-projects-instance)).

For containers and Kubernetes see [../deploy/README.md](../deploy/README.md).

## Install

As root, from a checkout of this repository:

```sh
deploy/systemd/install.sh \
  --public-url https://proxy.example.com:8443 \
  --listen :8443 \
  --tls-source /etc/letsencrypt/live/proxy.example.com
```

| Option | Meaning |
|---|---|
| `--public-url URL` | The address clients use: `scheme://host[:port]`. Required on the first install |
| `--listen ADDR` | The listen address (default `:8443`) |
| `--tls-source DIR` | A directory with `fullchain.pem` and `privkey.pem`, e.g. a certbot `live/` directory. Without it the proxy serves plain HTTP, for a load balancer in front that terminates TLS |
| `--data-dir DIR` | Keep `/var/lib/pullthrough` in `DIR` (a bind mount), e.g. on a data volume |
| `--cache-max-bytes N` | How large the package cache may grow (default 100 GiB) |
| `--rev REV` | The Git revision to build (default `HEAD`) |
| `--bin-dir DIR` | Install prebuilt `DIR/pullthrough` and `DIR/ptctl` instead of building, e.g. a verified release ([self-release.md](self-release.md)) |
| `--no-start` | Install everything, start nothing |

It needs systemd, `openssl`, `curl`, `git` and, unless `--bin-dir` is given, Go.
In order, it:

1. builds `pullthrough` and `ptctl` from a clean export of the commit, never
   from the working tree, with the version stamped in (`pullthrough -version`);
2. creates the system account `pullthrough` and the directories below;
3. generates, once, the audit-log key, the signing key and the two tokens;
4. publishes the certificate to `/etc/pullthrough/tls` and enables the daily
   renewal check;
5. renders `/etc/pullthrough/config.yaml` from the template (first install only);
6. runs `pullthrough verify-config` with the **new** binary, as the service
   account, against that configuration, and stops if it fails;
7. installs the binaries (keeping the previous one as `pullthrough.prev`) and
   the units, and enables the service;
8. restarts the service and waits up to 90 s for `/readyz`; when it does not
   come up, it puts the previous binary back and restarts that.

At the end it prints where the console, the tokens and the logs are.

## What goes where

| Path | Owner, mode | Contents |
|---|---|---|
| `/usr/local/bin/pullthrough`, `ptctl` | root, 0755 | The binaries; `pullthrough.prev` is the one before the last upgrade |
| `/etc/pullthrough/config.yaml` | root:pullthrough, 0640 | The configuration. Holds no secret |
| `/etc/pullthrough/secrets/audit-hmac-key` | pullthrough, 0400 | Key of the audit log's hash chain |
| `/etc/pullthrough/secrets/signing-key.pem` | pullthrough, 0400 | ECDSA P-256 key that signs audit checkpoints and served-artifact attestations |
| `/etc/pullthrough/signing-key.pub` | root, 0644 | Its public half, for verifiers |
| `/etc/pullthrough/tokens/client-token`, `admin-token` | root, 0600 | The tokens in plaintext, for the operator. The proxy has only their hashes |
| `/etc/pullthrough/tls/` | root:pullthrough | The published certificate (`fullchain.pem` 0644, `privkey.pem` 0640) |
| `/etc/pullthrough/sync-certs.env` | root, 0644 | Where the certificate comes from (`PT_TLS_SOURCE`) |
| `/var/lib/pullthrough/` | pullthrough, 0750 | `cache/` (with `cache/userlinks/`), `audit/`, `downloads.jsonl` |
| `/etc/systemd/system/` | | `pullthrough.service`, `pullthrough-sync-certs.service`, `.timer`, and with `--data-dir` `var-lib-pullthrough.mount` |
| `/usr/local/sbin/pullthrough-sync-certs` | root, 0755 | The certificate publisher |

`secrets/` files are owned by the service account with mode 0400 because a
`file://` secret reference must be owner-only (see
[configuration.md](configuration.md#value-substitution)); systemd's
`LoadCredential=` makes credentials 0440 with an ACL, which that check refuses.

## The configuration

The template, [`config.yaml.in`](../deploy/systemd/config.yaml.in), is a
complete configuration for a proxy on the internet. In short:

- **Every request needs a credential.** `auth.enabled` with no anonymous access:
  the client token (stored as its SHA-256 hash), or a personal link.
- **The admin console** (`<publicUrl>/admin/`; the bare address redirects there)
  accepts only the admin token (`adminAuth.staticTokens`, also a hash). The
  client token does not open it.
- **Personal cache links** are on, issued by the admin, since there is no
  identity provider to sign in at. A link in the path is how the clients that
  cannot send a token get in (below). `verify-config` warns that users cannot
  sign in: that is the intended setup.
- **No unauthenticated endpoint but health**: `observability.metrics` is off
  because the Prometheus endpoint has no authentication and would share the
  public listener. `/healthz` and `/readyz` stay open.
- **Audit log** with its key in a file, checkpoints signed; the same key signs
  the attestations of served artifacts ([attestbundle.md](attestbundle.md)).
- **Download log** persisted across restarts ([download-log.md](download-log.md)).
- **Rate limit** of 50 requests/s (burst 200, 32 concurrent) per tenant.
- **Gates**: those on by default stay on (install hooks, model weights, content
  heuristics, maturity, publisher continuity, build provenance); OSV
  vulnerabilities and typosquatting are added in `warn` mode — they record
  findings and block nothing until you raise `action`.
- **Not on**, because each needs an account somewhere: the LLM scans (an API
  key; the template shows the four lines that turn on
  [llm-package-scan.md](llm-package-scan.md)), provenance lookups (a GitHub
  token), a malware feed ([malfeed.md](malfeed.md)). Neither are the Git SSH
  gateway nor interception mode, which need listeners of their own.
- **Upstreams**: every ecosystem, under the names
  [the client guide](clients.md) uses, so its examples work with your address
  in place of `proxy.example.com`. `writeTimeout` is 1 h, so a large image
  layer or model file reaches a slow client.

`internal/config/systemd_template_test.go` renders the template the way the
installer does and requires it to validate, so it cannot fall behind the
configuration schema.

Change the configuration by editing `/etc/pullthrough/config.yaml`, then:

```sh
pullthrough verify-config -config /etc/pullthrough/config.yaml
systemctl restart pullthrough
```

The unit runs the same check before every start (`ExecStartPre`), so an edit
that does not validate leaves the service stopped with the reason in the
journal instead of in a restart loop.

## Using it

Package managers follow [the client guide](clients.md) with the client token
from `/etc/pullthrough/tokens/client-token`. For example npm, in `~/.npmrc`:

```ini
registry=https://proxy.example.com:8443/v1/npm/
//proxy.example.com:8443/v1/npm/:_authToken=<token>
```

and Docker, whose image names then carry the proxy's address:

```sh
docker login proxy.example.com:8443 -u pullthrough   # the password is the token
docker pull proxy.example.com:8443/library/alpine:3.20
```

`ptctl config --url https://proxy.example.com:8443 --token <token> npm=npm pypi=pip`
prints the settings for each package manager.

**Go on a port other than 443**: the go command looks the credentials in
`~/.netrc` up under the host *and port*, so the machine line is
`machine proxy.example.com:8443` (see [clients/go.md](clients/go.md)).

**cargo, NuGet, Terraform providers, Conan, mix, ovsx** cannot send a token
([clients.md](clients.md#clients-that-cannot-present-a-token)). Give their
users a personal link; it works as the package source of every client:

```sh
PULLTHROUGH_TOKEN="$(cat /etc/pullthrough/tokens/admin-token)" \
  ptctl userlinks issue --url https://proxy.example.com:8443 \
  --user alice --team default --roles reader --label laptop
```

prints `https://proxy.example.com:8443/u/ptl1…` once; cargo then uses
`sparse+https://proxy.example.com:8443/u/ptl1…/v1/crates/`. Links expire after
90 days; `ptctl userlinks list` and `revoke` manage them
([user-links.md](user-links.md)).

## Certificate renewal

The proxy reads its certificate when it starts. `pullthrough-sync-certs`
compares the source directory with `/etc/pullthrough/tls`, publishes a changed
pair (refusing a key that does not match the certificate, or an expired
certificate) and restarts the proxy. The timer runs it daily; ACME clients
renew 30 days before expiry, so a renewal reaches the proxy long before the old
certificate lapses, whatever renewed it.

To pick a renewal up at once, also run it from the ACME client. With certbot on
the host, a deploy hook (`/etc/letsencrypt/renewal-hooks/deploy/pullthrough`,
mode 0755):

```sh
#!/bin/sh
exec /usr/local/sbin/pullthrough-sync-certs "$RENEWED_LINEAGE"
```

A certbot that runs in a container cannot reach the host's systemd from a hook;
there, add `ExecStartPost=-/usr/local/sbin/pullthrough-sync-certs <live dir>`
to the renewal unit with a drop-in, or rely on the timer.

## Upgrade and rollback

Run the installer again, naming the revision:

```sh
git pull
deploy/systemd/install.sh --rev HEAD
```

It keeps the configuration, the secrets and the data, validates the
configuration with the new binary before it installs it, and goes back to the
previous binary if the new one is not ready within 90 s. To go back by hand:

```sh
mv /usr/local/bin/pullthrough.prev /usr/local/bin/pullthrough
systemctl restart pullthrough
```

The template changes over time; the installer never rewrites an existing
`config.yaml`. To take a new template, move `config.yaml` away and run the
installer with the first-install options again: the tokens and keys are kept,
so the new file has the same hashes.

## Operating it

```sh
systemctl status pullthrough
journalctl -u pullthrough -o cat -f          # JSON, one object per line
```

The admin console's Downloads tab (or `ptctl downloads`) shows which package
was downloaded from which address, by whom. To check the audit log's
integrity:

```sh
PTS_AUDIT_HMAC_KEY="$(cat /etc/pullthrough/secrets/audit-hmac-key)" \
  pullthrough verify-audit -log /var/lib/pullthrough/audit/audit.log \
  -pubkey /etc/pullthrough/signing-key.pub
```

To rotate a token, write a new one and put its hash into the configuration:

```sh
openssl rand -hex 32 > /etc/pullthrough/tokens/client-token
printf 'sha256:%s\n' "$(tr -d '\n' < /etc/pullthrough/tokens/client-token | sha256sum | cut -d' ' -f1)"
# replace auth.tokens[0].tokenHash with that value, then
systemctl restart pullthrough
```

(`adminAuth.staticTokens[0].tokenHash` for the admin token.)

**Limits** for a shared host go in a drop-in (`systemctl edit pullthrough`),
for example:

```ini
[Service]
Environment=GOMEMLIMIT=2560MiB
MemoryHigh=3G
MemoryMax=4G
CPUWeight=50
IOWeight=50
```

**Port 443** needs a capability, also in a drop-in:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

**Firewalls**: the port must be open in each one between the clients and the
host — the host's own and, on a cloud server, the provider's.

## Hardening

The unit runs the proxy as `pullthrough` with no capabilities, a read-only
system (`ProtectSystem=strict`: it can write only `/var/lib/pullthrough`), no
access to home directories, a private `/tmp` and `/dev`, no new privileges,
the `@system-service` system-call set, no W+X memory, and only IPv4, IPv6 and
Unix sockets. `systemd-analyze security pullthrough` rates it 1.5 ("OK").
`RequiresMountsFor=/var/lib/pullthrough` keeps it from starting when a data
volume is missing, instead of filling the root file system.

## Remove it

```sh
systemctl disable --now pullthrough.service pullthrough-sync-certs.timer
rm /etc/systemd/system/pullthrough.service /etc/systemd/system/pullthrough-sync-certs.*
rm -r /etc/systemd/system/pullthrough.service.d   # drop-ins, if any
systemctl stop var-lib-pullthrough.mount && rm /etc/systemd/system/var-lib-pullthrough.mount   # with --data-dir
systemctl daemon-reload
rm /usr/local/bin/pullthrough /usr/local/bin/pullthrough.prev /usr/local/bin/ptctl /usr/local/sbin/pullthrough-sync-certs
rm -r /etc/pullthrough /var/lib/pullthrough       # configuration, keys, tokens, cache, logs
userdel pullthrough
```

## The project's instance

`https://aiden.blechschmidt.io:8889` was installed with

```sh
deploy/systemd/install.sh \
  --public-url https://aiden.blechschmidt.io:8889 --listen :8889 \
  --tls-source /etc/letsencrypt/live/aiden.blechschmidt.io \
  --data-dir /mnt/HC_Volume_106716549/pullthrough
```

plus the limits drop-in above, as the host runs other services. Its
certificate is renewed by a certbot in a container; the daily timer publishes
it.
