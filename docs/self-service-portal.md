# Tenant self-service security portal

The self-service portal is a **read-only, tenant-scoped** web surface that lets a
developer or team see the supply-chain security posture of **only their own
tenant's pulls** — without any administrative access. It is deliberately
**distinct from the privileged admin UI** (`docs/admin-sso-rbac.md`): a portal
user can never reach an admin endpoint, change configuration, approve a
break-glass request, or observe another tenant's data.

It answers the questions a developer actually has:

- *Did my pull go through, and if it was flagged, why?* — recent pull verdicts
  (admit / warn / block) with the explainable reason from the risk-scoring
  engine.
- *Why was this specific package blocked, and what do I do?* — the gate findings
  for a coordinate, each with remediation guidance, plus a pointer to the
  break-glass approval flow.
- *What is stuck waiting on approval?* — the tenant's quarantined items / open
  break-glass requests, with status-specific guidance.
- *Where are the artifacts' attestations / SARIF?* — download the DSSE
  attestation bundle and the SARIF findings for the tenant's own artifacts.
- *How do I point my tools at the proxy?* — onboarding config snippets for every
  configured package manager.

## How tenant isolation is enforced

Tenant isolation is the portal's central security property and is enforced at
the **handler layer**, not in the front-end:

1. Every `/api/portal/*` data endpoint is wrapped by a single guard middleware
   that (a) authenticates the caller via `adminauth`, (b) requires the dedicated
   `tenant-viewer` capability, and (c) reads the caller's tenant from the
   **authenticated identity** and binds it into the request context as the
   immutable scope.
2. Handlers obtain the tenant **only** from that context value — never from a
   query parameter or header. A request like
   `GET /api/portal/summary?tenant=other` is therefore harmless: the `tenant`
   parameter is ignored and the response is still scoped to the caller.
3. A caller whose identity carries **no tenant** is denied (HTTP 403): there is
   nothing to scope to, so the safe default is to show nothing.
4. Sources that are already keyed by `(tenant, coordinate)` (findings,
   attestations) are queried with the caller's tenant; sources that expose a
   global view (risk assessments, the approval queue) are hard-filtered by
   tenant before anything is rendered. Case-insensitive comparison matches the
   case-folding the stores apply to tenant keys.

`internal/portal/portal_test.go` proves the property end-to-end: two tenants
(`acme`, `globex`) are seeded with overlapping data and the tests assert that one
tenant's caller can never observe the other's verdicts, findings, quarantine
items, SARIF, or attestations — including via a crafted `?tenant=` override.

## Enabling it

The portal requires `adminAuth` (Task 51) so it can identify the caller's
tenant. Add a `tenant-viewer` role binding (OIDC) or a tenant-bound static token,
then turn the portal on:

```yaml
observability:
  admin: true
  adminPathPrefix: /admin
  portal: true                 # enable the self-service portal
  portalPathPrefix: /portal    # UI served at /portal/, API at /api/portal/

adminAuth:
  enabled: true
  roleBindings:
    pullthrough-developers: tenant-viewer   # IdP group -> tenant-viewer
  oidc:
    enabled: true
    issuer: https://login.example.com/realms/corp
    clientId: pullthrough-admin
    redirectUrl: https://proxy.example.com/admin/auth/callback
    tenantClaim: team          # JWT claim carrying the caller's tenant/team
  sessionKey: ${PTS_ADMIN_SESSION_KEY}
```

In air-gapped mode (no IdP), bind a static token to a tenant instead:

```yaml
adminAuth:
  enabled: true
  staticTokens:
    - name: acme-portal
      tenant: acme
      roles: ["tenant-viewer"]
      token: ${PTS_ACME_PORTAL_TOKEN}
```

### Roles and the tenant-viewer capability

`adminAuth` roles map to capabilities. The portal adds one:

| Role            | Capabilities                                   | Admin API | Portal |
|-----------------|------------------------------------------------|:---------:|:------:|
| `viewer`        | read                                           |     ✓     |        |
| `operator`      | read, operate                                  |     ✓     |        |
| `approver`      | read, approve                                  |     ✓     |        |
| `admin`         | read, operate, approve, administer             |     ✓     |        |
| `tenant-viewer` | **tenant-viewer** (portal only)                |           |   ✓    |

The `tenant-viewer` capability is **disjoint** from the admin capabilities: a
tenant-viewer cannot reach the admin API, and an admin/operator/approver does not
implicitly gain portal access. Grant a user both `tenant-viewer` and an admin
role if they genuinely need both surfaces.

### Single sign-on across both surfaces

When the portal is enabled, the SSO session cookie issued by `adminAuth` is
broadened to the site root (`Path=/`) so one login works for both `/admin` and
`/portal`. The cookie stays `HttpOnly`, `Secure` (unless `insecureCookies`), and
HMAC-signed. Bearer-JWT and static-token auth (used by CI) are path-independent
and unaffected.

## API

All endpoints are `GET`, return JSON (except the SARIF/attestation downloads),
and are scoped to the caller's tenant. The UI prefix defaults to `/portal` and
the API prefix to `/api/portal`.

| Endpoint                                   | Description                                                            |
|--------------------------------------------|------------------------------------------------------------------------|
| `/api/portal/userinfo`                     | Caller's portal eligibility (no guard; always 200).                    |
| `/api/portal/summary`                      | At-a-glance posture: verdict tallies, open quarantine, findings count. |
| `/api/portal/verdicts`                     | Recent pull verdicts with score, band, decision, and top risk drivers. |
| `/api/portal/coordinate?coordinate=<c>`    | Why a coordinate was flagged + remediation + break-glass + downloads.  |
| `/api/portal/quarantine`                   | The tenant's quarantined items / break-glass requests, with guidance.  |
| `/api/portal/onboarding`                   | Per-package-manager config snippets (reusing the `ptctl` generators).  |
| `/api/portal/findings/sarif[?package=<c>]` | SARIF 2.1.0 export — one artifact, or the tenant's whole set.           |
| `/api/portal/attestation?package=<c>`      | The DSSE attestation envelope for one of the tenant's artifacts.       |

Unauthenticated requests to guarded endpoints get `401` (with an `X-Login-URL`
header when OIDC login is available); a caller without the `tenant-viewer`
capability or without a tenant gets `403`.

## Front-end

The page is a single, dependency-free HTML/CSS/JS app embedded in the binary
(`internal/portal/ui/`), served at `<portalPathPrefix>/`. It reuses the same
zero-build asset approach as the admin dashboard. It first calls
`/api/portal/userinfo` to render the right affordance (sign-in link, a
"not eligible" notice, or the tabs), then loads each tab from the scoped API.
The front-end sends no tenant parameter — scope is entirely server-side.

The portal and the admin dashboard meet a shared **WCAG 2.1 AA accessibility
baseline** (semantic landmarks, a skip link, a full keyboard tablist, visible
focus, light/dark contrast-safe tokens and `prefers-reduced-motion` handling),
enforced by a static linter in CI. See [accessibility.md](accessibility.md).

## Relationship to other subsystems

The portal is a thin, read-only projection over existing read models and never
duplicates a source of truth:

- **risk scoring** (Task 37) — recent assessments + explainable contributions;
- **findings / SARIF** (Task 42) — per-coordinate findings and remediation;
- **approvals / break-glass** (Task 50) — the quarantine queue and guidance;
- **attestations** (Task 46) — the DSSE bundle download;
- **onboarding snippets** — the shared `internal/onboard` generators that also
  back `ptctl config` (Task 55).
