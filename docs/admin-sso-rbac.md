# Admin SSO (OIDC/OAuth2) & RBAC

This document describes the enterprise single-sign-on and role-based access
control added in Task 51 for the **admin API and dashboard** (`internal/adminauth`).
It is distinct from the *client* access control in
[access-control-and-audit.md](access-control-and-audit.md), which governs package
pulls. SSO/RBAC governs who may inspect and operate the proxy itself.

Everything is **off by default** (`adminAuth.enabled: false`), so existing
deployments keep their prior behavior — the legacy `observability.adminToken`
bearer check, or open access on a trusted network.

## What it does

When `adminAuth.enabled: true`:

- **UI login** uses the OIDC/OAuth2 **authorization-code flow with PKCE**. The
  browser is redirected to your IdP, returns with an authorization code, and the
  proxy exchanges it (server-side) for an ID token, validates it, and mints a
  short-lived **signed session cookie**. No tokens are stored in the browser.
- **API access** (CI, scripts) uses **OIDC/JWT bearer tokens**, validated against
  the issuer's JWKS (RS\*/ES\* only — `alg=none`/HMAC rejected), checking
  signature and `exp`/`nbf`/`iss`/`aud` with clock-skew leeway.
- **Static tokens** mapped to roles provide a documented **offline/air-gapped
  mode** when no IdP is reachable.
- Every admin endpoint is mapped to the **capability** it requires, and a request
  whose identity lacks that capability is denied (`deny by default`).
- Every authenticated admin **mutation** is recorded in the tamper-evident
  [audit log](access-control-and-audit.md#tamper-evident-audit-log) with the
  caller's subject, so it is attributable to a real identity.

## Roles & capabilities

IdP groups/claims map to a small, fixed role vocabulary. Each role grants a set
of capabilities; an identity's capabilities are the union over its roles.

| Role       | read | operate | approve | administer |
|------------|:----:|:-------:|:-------:|:----------:|
| `viewer`   |  ✓   |         |         |            |
| `operator` |  ✓   |   ✓     |         |            |
| `approver` |  ✓   |         |   ✓     |            |
| `admin`    |  ✓   |   ✓     |   ✓     |     ✓      |

Endpoints require capabilities as follows:

- **read** — all `GET` endpoints, plus the read-only dry-run evaluations
  (`POST /api/policyengine/test`, `POST /api/simreplay/simulate`).
- **operate** — operational mutations that do not change policy/config: release a
  quarantine, trigger a re-scan/backup/GC, purge the negative cache, drain a
  mirror, reset a circuit breaker, send a test notification, delete a cache
  entry.
- **approve** — grant/deny break-glass approvals
  (`POST /api/approvals/approve`, `POST /api/approvals/deny`).
- **administer** — mutate policy and runtime config
  (`POST /api/policyengine/reload`, `PUT /api/ratelimit/policy`).

Denied requests return `401` (unauthenticated) or `403` (authenticated but
lacking the capability). A `401` on an SSO-enabled deployment carries an
`X-Login-URL` header so the dashboard can steer the browser to the login flow.

### Cross-site requests

A request that changes something (any method but `GET`, `HEAD` and `OPTIONS`)
and authenticates with the SSO **session cookie** must carry the header
`X-Pullthrough-Admin`; the dashboard sends it with every request. Without it the
answer is `403 cross-site request refused`. A browser attaches the cookie to a
form another page posts — and `SameSite=Lax` does not stop a page on a sibling
subdomain, or on another port of the same host, which count as the same site —
but it does not let that page add a header of its own choosing. Requests with a
bearer or static token are not affected: a browser never sends those by itself.

## Mapping IdP groups to roles

`adminAuth.roleBindings` maps your IdP's group/claim values to canonical roles.
A group already named like a canonical role (e.g. `operator`) needs no binding.
`adminAuth.defaultRole` is granted to authenticated callers that match nothing
(leave empty to deny them).

```yaml
adminAuth:
  roleBindings:
    pullthrough-admins: admin
    pullthrough-approvers: approver
    platform-sre: operator
    engineering: viewer
  defaultRole: viewer        # optional
```

The group values come from the configured `oidc.groupsClaim` (default `groups`)
on the ID token (UI) or the bearer JWT (API).

### Binding individual users

`adminAuth.subjectBindings` binds a user — the value of `oidc.subjectClaim` — to a
role. Use it for an identity provider that releases no groups (Microsoft Entra
ID unless a groups claim or app roles are configured), or for the first admin
before any group exists:

```yaml
adminAuth:
  subjectBindings:
    alice@example.com: admin
  oidc:
    subjectClaim: preferred_username
```

A subject that contains `@` is compared ASCII case-insensitively, any other
exactly. A user holds the roles of their groups and of their subject together;
`defaultRole` applies only when neither gives them one. Bind by a claim the
identity provider does not let users change for themselves: an e-mail-like
`preferred_username` or `upn` is fine when the issuer is a single organization's
(as below), an `email` claim a user can edit is not.

## The callback path

The identity provider sends the browser back to `oidc.redirectUrl`. With the path
`<adminPathPrefix>/auth/callback` (e.g. `https://proxy.example.com/admin/auth/callback`)
the admin surface serves it. Any other path — such as one a registration that
cannot be changed already lists — is served by the gateway at its root, and the
login-flow cookie is scoped to that path. Such a path must not lie under another
mount of the proxy (`/v1`, `/v2`, `/admin`, `/links`, `/u`, `/healthz`, a webhook
path, …); `pullthrough verify-config` says which one it collides with. The
console and the [personal-links page](user-links.md) may share one callback
path: each request goes to the sign-in whose login state it answers.

## When the identity provider is down

Building the admin surface does not contact the identity provider: its
endpoints are discovered on first use, and a failed discovery is retried after
ten seconds. While the provider cannot be reached, a sign-in answers `503`, OIDC
bearer tokens are refused, and static tokens keep working. If `adminAuth` cannot
be set up at all (a configuration error that validation did not catch), the admin
surface falls back to the legacy `observability.adminToken` when one is
configured and allowed, and is **not served** otherwise — it is never served
without authentication.

## JWKS caching, rotation & clock skew

Keys are fetched from the issuer's `jwks_uri` (discovered, configured, or pinned
inline) and cached for `oidc.jwksCacheTtl` (default 15m). On expiry they are
re-fetched, so **key rotation is picked up automatically**; a transient IdP
outage serves the last good key set rather than failing closed. `oidc.leeway`
(default 60s) tolerates clock skew when checking `exp`/`nbf`.

## Offline / static mode (air-gapped)

For disconnected sites, omit `oidc` and define `staticTokens` mapped to roles.
Each token needs ≥16 bytes of entropy; set exactly one of `token` (plaintext,
supports `${ENV}`/`enc:v1:`) or `tokenHash` (`sha256:<hex>`).

```yaml
adminAuth:
  enabled: true
  staticTokens:
    - name: break-glass-admin
      roles: ["admin"]
      token: ${PTS_ADMIN_BREAKGLASS_TOKEN}
    - name: ci-readonly
      roles: ["viewer"]
      tokenHash: "sha256:<hex-digest>"
```

You can also pin the OIDC keys inline (`oidc.jwks`) and set explicit endpoints to
run SSO without any discovery network call. The legacy `observability.adminToken`
keeps working (as the `admin` role) unless `adminAuth.allowLegacyToken: false`.

## Metrics

Bridged into the Prometheus registry (scrape-time):

- `pullthrough_adminauth_auth_success_total{role}` and
  `pullthrough_adminauth_auth_success_by_method_total{method}`
- `pullthrough_adminauth_auth_failure_total{reason}`
- `pullthrough_adminauth_authz_allowed_total{capability}` /
  `pullthrough_adminauth_authz_denied_total{capability}`
- `pullthrough_adminauth_logins_total`,
  `pullthrough_adminauth_login_failures_total`,
  `pullthrough_adminauth_logouts_total`

## Example wiring

### Keycloak

1. Create a realm client `pullthrough-admin`, *Standard flow* enabled, type
   *confidential* (or *public* for PKCE-only).
2. Set **Valid redirect URI** to
   `https://proxy.example.com/admin/auth/callback`.
3. Add a **group membership** mapper that emits a `groups` claim (token claim
   name `groups`), and put your operators into Keycloak groups.

```yaml
adminAuth:
  enabled: true
  sessionKey: ${PTS_ADMIN_SESSION_KEY}      # >=16 bytes, HMAC cookie signing key
  roleBindings:
    /pullthrough-admins: admin              # Keycloak group paths are "/group"
    /pullthrough-operators: operator
  oidc:
    enabled: true
    issuer: https://keycloak.example.com/realms/corp
    clientId: pullthrough-admin
    clientSecret: ${PTS_ADMIN_OIDC_CLIENT_SECRET}
    redirectUrl: https://proxy.example.com/admin/auth/callback
    scopes: ["openid", "profile", "email", "groups"]
    groupsClaim: groups
```

Endpoints and JWKS are discovered from
`https://keycloak.example.com/realms/corp/.well-known/openid-configuration`.

### Okta

1. Create an **OIDC Web** application; sign-in redirect URI
   `https://proxy.example.com/admin/auth/callback`.
2. Add a **Groups claim** to the ID token (filter to the groups you care about),
   claim name `groups`.
3. Assign Okta groups (e.g. `PullthroughAdmins`) to the app.

```yaml
adminAuth:
  enabled: true
  sessionKey: ${PTS_ADMIN_SESSION_KEY}
  roleBindings:
    PullthroughAdmins: admin
    PullthroughApprovers: approver
    PullthroughSRE: operator
  oidc:
    enabled: true
    issuer: https://example.okta.com/oauth2/default
    clientId: 0oaxxxxxxxxxxxx
    clientSecret: ${PTS_ADMIN_OIDC_CLIENT_SECRET}
    redirectUrl: https://proxy.example.com/admin/auth/callback
    audience: api://pullthrough-admin   # if API bearer JWTs use a custom aud
    groupsClaim: groups
```

### Microsoft Entra ID

Entra ID's discovery document for a tenant addressed by its domain name,
`https://login.microsoftonline.com/<tenant>.onmicrosoft.com/v2.0`, declares the
**tenant-ID** form as its issuer, and its tokens carry that form. Configure the
tenant-ID form as `issuer` and the domain form as `discoveryUrl` — a mismatch is
refused, with an error that names both values:

```bash
curl -s https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration | jq -r .issuer
# https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0
```

1. Register an application (single tenant). Add the redirect URI under the
   **Mobile and desktop applications** platform — a public client, which PKCE
   alone binds the code to; no secret to distribute or rotate. A redirect URI on
   the **Single-page application** platform works too: Entra redeems its codes
   only in a request with an `Origin` header and says so (`AADSTS9002327`), and
   the proxy then repeats the redemption with its own origin, and keeps doing so.
   A **Web** redirect URI needs `clientSecret`.
2. Entra puts the user's sign-in name in `preferred_username`, emits `email` only
   for some accounts, and releases no groups by default; its `sub` differs per
   application. Bind users with `subjectBindings` (or add a groups claim / app
   roles and use `roleBindings` with `groupsClaim: groups` or `roles`).
3. Do not request the `groups` scope: Entra knows no such scope.

```yaml
adminAuth:
  enabled: true
  sessionKey: file:///etc/pullthrough/secrets/admin-session-key
  subjectBindings:
    alice@contoso.com: admin
  oidc:
    enabled: true
    issuer: https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0
    discoveryUrl: https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration
    clientId: 55555555-6666-7777-8888-999999999999
    redirectUrl: https://proxy.example.com/admin/auth/callback
    scopes: ["openid", "profile", "email"]
    subjectClaim: preferred_username
    # The ID tokens Entra issues to this client are not admin-API bearer
    # tokens: expect another audience (one no token carries, unless you expose
    # an API with it).
    audience: urn:pullthrough:admin-api
```

When the application registration is shared with another service, set
`audience` as above: otherwise an ID token issued to that service would also be
accepted as a bearer token here.

> Generate a session key with e.g. `openssl rand -hex 32` and supply it via
> `PTS_ADMIN_SESSION_KEY` (or an `enc:v1:` value). Rotating it invalidates all
> active admin sessions, forcing re-login.

See [`configs/config.example.yaml`](../configs/config.example.yaml) for the full
annotated `adminAuth` block.
