# `ptctl` — the client CLI

`ptctl` is a standalone command-line tool that streamlines onboarding a
developer (or a CI job) against a running pull-through proxy. Where
[clients.md](clients.md) and its per-ecosystem pages document each client's
configuration (verified with the real clients), `ptctl`
**generates** a starting point for your proxy, **tests** that your connectivity and token
work, and lets you **inspect** the supply-chain verdict and **attestation** for
any artifact — all over HTTP, with no access to the proxy's config file or host.

It ships as a second binary alongside the server:

```bash
make build          # builds bin/pullthrough and bin/ptctl
# or just the client:
make build-client   # builds bin/ptctl
# or directly:
go build -o ptctl ./cmd/ptctl
```

## Connecting

Every command accepts the same connection/identity flags, each of which falls
back to an environment variable so you can set them once per shell:

| Flag | Env | Meaning |
|------|-----|---------|
| `--url` | `PULLTHROUGH_URL` | proxy base URL, e.g. `https://proxy.example.com` |
| `--tenant` | `PULLTHROUGH_TENANT` | tenant/team scope for config and lookups |
| `--token` | `PULLTHROUGH_TOKEN` | your proxy access token (sent as a bearer credential) |
| `--admin-prefix` | `PULLTHROUGH_ADMIN_PREFIX` | admin API prefix (default `/admin`) |
| `--insecure` | — | skip TLS verification (self-signed dev proxies) |
| `--timeout` | — | per-request timeout (default `30s`) |

```bash
export PULLTHROUGH_URL=https://proxy.example.com
export PULLTHROUGH_TENANT=acme
export PULLTHROUGH_TOKEN=…        # your proxy token; its team determines the tenant
```

The token is the **proxy** access token (see
[access-control-and-audit.md](access-control-and-audit.md)), not an upstream
registry credential. The same token is used for the public gateway (the
`selftest` probes) and the read-only admin API (`config` discovery, `inspect`,
`attest`).

## Commands

### `ptctl config` — generate config snippets

Generates per–package-manager configuration for the proxy's enabled backends:
`.npmrc`, `pip.conf`, Cargo `config.toml`, `GOPROXY`, `NuGet.config`, Maven
`settings.xml`, `docker login`, `helm repo add`, Bundler/Composer, APT
`sources.list`, YUM `.repo`, Terraform, Git and the rest — whatever the proxy
actually runs. When a `--token` is supplied, a snippet carries it where the
generator has the client's credential form (treat the output as a secret).

The snippets are a starting point; the reference is the
[client guide](clients.md), whose configurations are executed with the real
clients. Where the two differ, the guide is right. Known differences:

- With a token, the snippets for Composer, apt, dnf, R, Bazel, Deno (JSR),
  r10k and dart print the configuration without credentials; each of those
  pages says how the client presents a token.
- A `generic` upstream has no client of its own: only its address is printed.

```bash
# Auto-discover backends from the proxy and print annotated snippets:
ptctl config

# Only the managers you care about:
ptctl config --manager npm,pip,docker

# Write conventionally-named files (mode 0600) into a directory:
ptctl config --output ./proxy-config

# Generate without admin access by naming the backends explicitly (name=type):
ptctl config npm=npm pypi=pip central=maven dockerhub=docker
```

Backend discovery uses the admin `GET {prefix}/api/overview` endpoint. If your
token cannot read it (or the proxy is locked down), pass explicit `name=type`
arguments instead — no server round-trip is then needed.

With `--personal-link <your link>` the snippets use your [personal cache
link](user-links.md) — the proxy URL is taken from the link, no other
credential appears — and each says where the link must not end up (a lock file,
a file under version control).

### `ptctl selftest` — connectivity & auth check

Probes the proxy's health endpoints and then issues a representative request to
each enabled backend, classifying every result so you can tell a network/TLS
failure from an auth failure from a wired-but-empty backend at a glance:

```text
$ ptctl selftest
✓  health: /healthz   OK          200
✓  ready: /readyz     OK          200
✓  npm (npm)          OK          200
✗  pypi (pip)         AUTH        401  authentication required or token rejected
✓  central (maven)    OK          404  reachable (probe path returned 404)

4/5 checks passed.
```

Verdicts: `OK` (reachable), `AUTH` (401/403 — fix your `--token`), `ERROR`
(5xx), `UNREACHABLE` (DNS/TLS/connection — the detail suggests the fix). The
command exits non-zero if any check fails, so it doubles as a CI smoke test.

### `ptctl doctor` — consolidated health & config self-diagnostic

Runs a single read-only self-diagnostic that folds every operational signal into
one prioritized, color-coded report with remediation hints. It reuses the
proxy's own building blocks rather than reimplementing them: config validation +
drift preflight, backend reachability probes, key/credential/certificate expiry
monitoring, secrets-provider resolution, cache integrity sampling, leader-election
status, kill-switch/lockdown state, and gate-enablement coverage.

```text
$ ptctl doctor
pullthrough doctor — online mode (https://proxy.example.com)
generated 2026-01-01T00:00:00Z

✗  configuration validity     1 error(s), 0 warning(s)
       [error] vulnerabilities.enabled: requires a fail threshold
   → fix the fields above; run `ptctl config validate` for the full report
!  kill-switch / lockdown      LOCKDOWN ACTIVE: FREEZE
       incident: INC-42
   → clear it once the incident is resolved: `ptctl lockdown clear -reason <...>`
✓  proxy reachability          live and ready
✓  upstream reachability       all 3 backend(s) reachable
...

10 checks: 7 ok, 1 warning, 1 error, 1 skipped
verdict: UNHEALTHY
```

Findings sort most-severe first. The command exits non-zero when any check is at
error severity; pass `--warn-as-error` to also fail on warnings (useful as a CI
gate). `--json` emits the machine-readable report, and `--no-color` disables the
ANSI color (also auto-disabled when stdout is not a terminal or `NO_COLOR` is
set).

Offline mode diagnoses a config file with no running proxy — it runs the checks
that are computable statically (config validation, secrets-provider resolution,
gate coverage) and marks the live-only checks as skipped:

```text
$ ptctl doctor --config /etc/pullthrough/config.yaml
```

### `ptctl inspect` — admission verdict & findings

Surfaces the unified admission-gate findings for a coordinate in human-readable
form, reusing the same data behind the SARIF endpoint
([findings.md](findings.md)):

```text
$ ptctl inspect lodash@4.17.21
Artifact:  lodash@4.17.21
Ecosystem: npm
Verdict:   BLOCKED
Findings:  1 critical, 2 high, 1 low

✗ [vuln/CRITICAL] CVE-2021-23337: command injection in lodash
     (CVE-2021-23337)
! [license/HIGH] review-required license: see policy
○ [vuln/LOW] CVE-… (suppressed: VEX not_affected)
```

The verdict is `ADMITTED`, `ADMITTED (with warnings)`, or `BLOCKED`. Use
`--ecosystem` to disambiguate a name that exists in several ecosystems, and
`--sarif` to emit the raw SARIF 2.1.0 document for CI ingestion instead of the
summary.

### `ptctl attest` — fetch the outbound attestation

Fetches the proxy's signed, outbound SLSA/in-toto attestation for a served
artifact ([attestbundle.md](attestbundle.md)) and summarizes the in-toto
predicate, including the per-gate admission verdict:

```text
$ ptctl attest lodash@4.17.21
Coordinate:    lodash@4.17.21
Subject:       sha256:…
Predicate:     https://pullthrough.dev/attestations/served/v1
Bundle digest: sha256:…
Signed by key: …
Source:        https://github.com/lodash/lodash @ <commit>
Admission:     admitted
Gates:
  ✓ vuln: pass
  ✓ license: pass
```

Use `--raw` to emit the verifiable DSSE envelope (for offline verification), or
`--output <file>` to write it. The envelope verifies against the proxy's public
key with the server CLI or cosign:

```bash
ptctl attest lodash@4.17.21 --raw | pullthrough attest verify -pubkey proxy-pub.pem
```

### `ptctl vex export` — export the VEX posture

Generates the proxy's current VEX posture — the `not_affected`/`fixed`
suppression corpus, VEX-adjudicated findings, and active break-glass grants — as
an **OpenVEX** document or a **CycloneDX VEX/VDR** BOM, per coordinate, for a
captured snapshot, or for a whole tenant ([vex.md](vex.md)):

```bash
# OpenVEX for one coordinate (to stdout)
ptctl vex export --ecosystem npm lodash 4.17.21

# CycloneDX VEX/VDR for a coordinate
ptctl vex export --ecosystem pip requests@2.19.0 --format cyclonedx

# Whole-tenant posture, cosign-signed, written to files
ptctl vex export --tenant acme --sign \
    --output acme-vex.json --sig-out acme-vex.sig.json

# Posture for a captured snapshot
ptctl vex export --snapshot <snapshot-id>
```

`--sign` attaches a detached, cosign-compatible signature (written to the
`--sig-out` sidecar); the document itself stays byte-for-byte verifiable and
re-ingestable. It requires a signing key on the proxy
(`vulnerabilities.vex.export.signingKey`, falling back to the attest/audit key).

### `ptctl downloads` — which package went to which client address, and to whom

Queries the proxy's [download log](download-log.md) through the admin API: one
entry per package download or refused attempt, with the client address it came
from — and the user, where one was identified (a [personal cache
link](user-links.md), a token). It needs a token with the admin `read`
capability.

```bash
ptctl downloads --package left-pad                # who pulled left-pad?
ptctl downloads --package 'rsc.io/quote@v1.5.2'   # one exact version
ptctl downloads --ip 10.0.0.7                     # what did 10.0.0.7 pull?
ptctl downloads --user alice@example.com          # what did alice pull?
ptctl downloads --user '*@example.com' --outcome blocked
ptctl downloads --user - --summary                # what was pulled by nobody known?
ptctl downloads --ip 10.0.0.0/16 --outcome blocked --since 24h
ptctl downloads --summary --ecosystem cargo       # busiest addresses, users and crates
ptctl downloads --all --format csv > downloads.csv
```

Filters are ANDed: `--ip` (an address or a CIDR prefix), `--package`
(a name or `name@version`; `*` is a wildcard), `--ecosystem`, `--upstream`,
`--outcome` (`served`, `not_modified`, `blocked`, `not_found`, `error`),
`--user` (the identified client — also spelled `--subject`; `*` is a wildcard,
`-` selects the downloads nobody was identified for), `--link` (one personal
cache link, by its identifier), `--search` (free text), `--since` / `--until`
(an age such as `15m`, `24h`, `7d`, RFC 3339, or unix seconds). `--limit`
(default 50) bounds the table; `--all` pages through every match. `--summary`
prints totals and the busiest client addresses, users and packages (`--top`)
instead of entries. `--format` is `table` (default), `json` or `csv`.

The global `--tenant` narrows the log only when given on the command line: an
exported `PULLTHROUGH_TENANT` does not hide other tenants' downloads.

### `ptctl userlinks` — personal cache links

The operator's view of [personal cache links](user-links.md): the per-user
addresses of the package sources that cache users create after signing in
through the identity provider.

```bash
ptctl userlinks list                                   # every link: user, state, expiry, last use
ptctl userlinks list --users                           # per user
ptctl userlinks list --user alice@example.com --state active
ptctl userlinks revoke --id 273d43ccab040774 --reason "laptop stolen"
ptctl userlinks revoke --user bob@example.com --reason "left the company"
ptctl userlinks issue --user ci-bot --team platform --roles reader --label "nightly build"
```

`list` needs the admin `read` capability and takes `--user`, `--state`
(`active`, `expired`, `revoked`), `--search`, `--limit`, `--users` and
`--format table|json`. `revoke` needs `operate`: `--id` ends one link, `--user`
everything issued to a user — every link on every replica, and their session on
the links page; they may sign in again if the identity provider still lets them.
`issue` needs `administer` and creates a link for an identity the operator
names (`--user`, and optionally `--name`, `--email`, `--team`, `--roles`,
`--label`, `--ttl-days`) — for a service account, or where no identity provider
is configured. It prints the link **once**: the proxy keeps only its hash.

A user who already has a link generates their client configuration with
`ptctl config --personal-link` — no admin access needed:

```bash
ptctl config --personal-link https://proxy.example.com/u/ptl1… npm=npm pypi=pip
```

### `ptctl completion` — shell completion

Emits a static completion script for `bash`, `zsh`, or `fish`:

```bash
ptctl completion bash | sudo tee /etc/bash_completion.d/ptctl >/dev/null
ptctl completion zsh  > "${fpath[1]}/_ptctl"
ptctl completion fish > ~/.config/fish/completions/ptctl.fish
```

## A typical first run

```bash
export PULLTHROUGH_URL=https://proxy.example.com
export PULLTHROUGH_TOKEN=…

ptctl selftest                       # confirm connectivity + auth
ptctl config --output ~/proxy-conf   # drop in ready-to-use config files
ptctl inspect requests@2.31.0        # check an artifact's supply-chain verdict
ptctl attest requests@2.31.0         # see what the proxy attested for it
```
