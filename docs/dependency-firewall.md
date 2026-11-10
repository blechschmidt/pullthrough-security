# Dependency Firewall — version-pinning & allowlist enforcement

The **dependency firewall** (`internal/depfirewall`, Task 65) is an admission gate
that enforces explicit, auditable **version policy** on the pull path. It turns
the proxy into a guarantee that CI can only fetch versions an operator — or a
committed lockfile — has approved.

Where the [name guard](security-model.md) catches *look-alike* names and
[malfeed](security-model.md) hard-blocks *known-malicious* coordinates, the
dependency firewall governs *which versions of a legitimate package* may be
served. It is the enterprise control for "we only consume what our lockfile
resolved" and for "block the known-bad `<2.4.0` range of this library".

## What it enforces

A tenant expresses policy as a set of **rules** keyed by `(ecosystem, name)`.
Each rule combines four orthogonal constraints, any of which may be present:

| Constraint    | Meaning                                                            |
|---------------|-------------------------------------------------------------------|
| `pinned`      | exact-version allowlist — the version must be one of these        |
| `ranges`      | semver range expressions — the version must satisfy at least one  |
| `minVersion`  | minimum-version floor — versions below it are blocked             |
| `denied`      | explicit denylist — these exact versions are always refused       |

Evaluation order for a concrete `(ecosystem, name, version)`:

1. **Denylist** is checked first and **always blocks**, regardless of any
   positive constraint (so you can `ranges: ["*"]` a package but still carve out
   a single compromised release).
2. The positive constraints (`pinned`, `ranges`, `minVersion`) are **ANDed**: the
   version must satisfy *every* constraint that is present.
3. A rule that carries **no constraints** governs the coordinate but restricts
   nothing — an explicit "this package is allowed, unrestricted" statement.

For a coordinate with **no matching rule**, the `defaultAction` decides:

- `allow` (default) — the firewall enforces only the explicit rules it has.
- `block` — **deny-by-default**: only governed coordinates pass. This is the
  strict mode a tenant uses to pin its entire transitive graph from a lockfile.

**Tenant rules override global rules** for the same coordinate, and a tenant may
set its own `defaultAction`. A tenant with no policy falls back to the global
policy.

### Supported semver range syntax

The range parser accepts the common cross-ecosystem forms used in lockfiles and
policy:

```
*  / x / latest        match anything
1.2.3                  exact
=1.2.3                 exact
>=1.2.0 <2.0.0         space-separated AND of comparators
>=1.2.0, <2.0.0        comma-separated AND (Cargo style)
1.2.x / 1.x / 1.*      wildcard ranges
^1.2.3                 caret range (compatible-with)
~1.2.3 / ~1.2          tilde range (approximately-equivalent)
1.2.3 - 2.3.4          hyphen (inclusive) range
a || b                 OR of two ranges
```

Versions are compared with a tolerant SemVer-ish comparator (leading `v` is
ignored; a pre-release suffix orders below its release; build metadata is
ignored). A malformed range is rejected when the rule is loaded or set, so a bad
rule never silently mis-enforces. An unparseable *candidate* version fails safe
(it satisfies no range).

## Lockfile import — pin your whole graph

The most powerful use is importing rules directly from a lockfile. Each distinct
`(ecosystem, name)` becomes a **pinned** rule whose allowlist is exactly the set
of versions the lockfile resolved (transitive duplicates accumulate). Paired with
`defaultAction: block`, the lockfile becomes the *complete* allowlist: CI can
fetch lockfile-approved versions and nothing else.

Supported lockfiles:

| File                 | Ecosystem | Notes                                              |
|----------------------|-----------|----------------------------------------------------|
| `package-lock.json`  | npm       | v1 (`dependencies` tree) and v2/v3 (`packages`)    |
| `requirements.txt`   | pip       | only exact `==` pins; names PEP 503-normalized     |
| `go.sum`             | go        | module + version (the `/go.mod` line is deduped)   |
| `Cargo.lock`         | cargo     | `[[package]]` name/version blocks                  |

Import via the admin UI ("Firewall" tab → *Import lockfile*) or the API:

```bash
curl -X POST \
  "$ADMIN/api/depfirewall/import?tenant=ci-prod&format=package-lock.json&mode=replace" \
  --data-binary @package-lock.json
```

`mode=replace` (the default) clears the target rule set first; `mode=merge` adds
to it. `format=auto` (or omitted) detects the lockfile family from its content.

## Configuration

```yaml
depfirewall:
  enabled: true
  defaultAction: allow          # or "block" for deny-by-default
  rules:
    - ecosystem: pip
      name: requests
      ranges: [ ">=2.20.0 <3.0.0" ]
    - ecosystem: go
      name: golang.org/x/crypto
      minVersion: v0.17.0
    - ecosystem: npm
      name: event-stream
      ranges: [ "*" ]
      denied: [ "3.3.6" ]
      note: "compromised release"
  tenants:
    ci-prod:
      defaultAction: block       # only lockfile-imported coordinates pass
```

The gate is **off by default** — it enforces only what you configure, so it must
be switched on deliberately. A malformed range in any rule is a fatal startup
error.

## Where it runs

The gate runs **early** in the pull path — right after the name guard and before
the heavier scanning gates (malfeed/maturity/policy/vuln). It needs only the
resolved `(ecosystem, name, version)`, no artifact content, so a version outside
the approved set is refused **before any upstream fetch or cache fill**. Index and
listing requests (no concrete version) are always admitted.

A block returns an actionable `403` with the violation code and the approved set:

```
HTTP/1.1 403 Forbidden
X-Depfirewall-Decision: block
X-Depfirewall-Code: not-pinned
X-Depfirewall-Reason: version 1.4.0 of npm/left-pad is not in the pinned-version allowlist (1.3.0)
```

```json
{
  "error": "package version refused by the dependency-firewall (version policy) admission gate",
  "code": "not-pinned",
  "reason": "version 1.4.0 of npm/left-pad is not in the pinned-version allowlist (1.3.0)",
  "ecosystem": "npm",
  "package": "left-pad",
  "version": "1.4.0",
  "pinned": ["1.3.0"]
}
```

Violation codes: `not-pinned`, `out-of-range`, `below-floor`, `denied`,
`not-governed` (deny-by-default), `unparsable`.

### Break-glass exceptions

When the [approval workflow](approvals.md) is enabled, a firewall block consults
the human-in-the-loop **break-glass** path first: if an operator has granted a
time-boxed exception for that exact coordinate, the artifact is served and the
override is recorded in the audit log (`X-Approval-Decision: break-glass`).
Otherwise a pending review is opened and the block stands.

## Admin API

| Method & path                              | Purpose                                  |
|--------------------------------------------|------------------------------------------|
| `GET  /api/depfirewall`                    | status + rules (`?tenant=<id>` / `?tenant=*`) |
| `POST /api/depfirewall/rules`              | create/update a rule (JSON body)         |
| `POST /api/depfirewall/rules/delete`       | delete a rule `{tenant,ecosystem,name}`  |
| `POST /api/depfirewall/default`            | set default action `{tenant,action}`     |
| `POST /api/depfirewall/import`             | import rules from a lockfile (raw body)  |

Mutations require the `operate` admin capability (see
[admin SSO & RBAC](admin-sso-rbac.md)) and are attributed in the audit log.

A rule body:

```json
{
  "tenant": "",
  "ecosystem": "npm",
  "name": "lodash",
  "pinned": ["4.17.21"],
  "ranges": [],
  "minVersion": "",
  "denied": [],
  "note": "approved by AppSec"
}
```

## Observability

Per-block alerts are emitted as `notify` events of type `depfirewall` (medium
severity). Prometheus metrics:

| Metric                                             | Type    | Labels      |
|----------------------------------------------------|---------|-------------|
| `pullthrough_depfirewall_checks_total`             | counter | —           |
| `pullthrough_depfirewall_blocks_total`             | counter | —           |
| `pullthrough_depfirewall_allowed_total`            | counter | —           |
| `pullthrough_depfirewall_checks_by_ecosystem_total`| counter | `ecosystem` |
| `pullthrough_depfirewall_blocks_by_ecosystem_total`| counter | `ecosystem` |
| `pullthrough_depfirewall_blocks_by_code_total`     | counter | `code`      |

Every block is also written to the tamper-evident, Merkle-linked audit log with
reason `depfirewall:<code>`.
```
