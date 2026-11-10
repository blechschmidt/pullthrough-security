# SPIFFE/SVID mutual-TLS workload identity

The proxy can authenticate clients by their **SPIFFE/SVID mutual-TLS
certificate** instead of (or in addition to) a long-lived API token or OIDC
bearer token. This is the zero-trust path for enterprises running the proxy
inside a service mesh — Istio, Linkerd, or a bare [SPIRE](https://spiffe.io/)
deployment — where every workload already carries a short-lived X.509-SVID and
no human-managed secret should be needed to pull a package.

A verified SPIFFE ID (e.g. `spiffe://corp.example/ns/payments/sa/web`) is mapped
to a **tenant + roles** by an identity-mapping policy, and from there flows
through the *same* access-control, rate-limit, and audit machinery as a token
identity. The audit log attributes every pull/decision to the full SPIFFE ID.

- **Package:** `internal/spiffe`
- **Config:** `clientAuth.mtls`
- **Composes with:** the token/OIDC auth under `auth` (see
  [access-control-and-audit.md](access-control-and-audit.md))

---

## How it works

```
        ┌── client (workload SVID) ──┐
        │  TLS handshake presents     │
        │  client certificate         │
        ▼                              │
  TLS termination (gateway)            │   ClientAuth = RequestClientCert
        │  r.TLS.PeerCertificates      │   (or RequireAnyClientCert in required mode)
        ▼                              │
  spiffe.Authenticator  ──────────────┘
        │  1. extract SPIFFE ID from the cert SAN URI
        │  2. validate the chain against the trust bundle
        │     (per trust-domain roots, app-level so it hot-reloads)
        │  3. map SPIFFE ID → tenant + roles (policy)
        ▼
  auth.Principal{ Subject: <spiffe-id>, Team: <tenant>, Roles: […], Method: "mtls" }
        │
        ▼
  RBAC authorize → quota → rate-limit → pull → audit (attributed to the SPIFFE ID)
```

Certificate-chain verification runs in the **application layer** (not only at
the TLS handshake). This has two benefits:

1. The **trust bundle can be hot-reloaded** without restarting the listener
   (handy when SPIRE rotates the CA), and
2. SPIFFE-specific checks — the trust domain, the SAN URI shape — are enforced
   explicitly and uniformly.

Because of that, at the TLS layer the gateway only **requests** a client
certificate (`tls.RequestClientCert`) by default, so mTLS composes with token
auth: a client may present *either* a certificate *or* a token. In
**required mode** the gateway uses `tls.RequireAnyClientCert`, so the handshake
itself fails for any client that presents no certificate.

---

## Prerequisites

mTLS terminates at the gateway, so you must:

1. Enable `auth` (`auth.enabled: true`) — the RBAC enforcer and the role
   definitions the mapped capabilities reference live there.
2. Enable TLS at the gateway: `server.tlsCertFile` / `server.tlsKeyFile`.
   (When TLS is terminated by an upstream load balancer that does *not* forward
   the client cert, app-level mTLS is not possible — terminate at the proxy.)

---

## Configuration

```yaml
server:
  httpAddr: ":8443"
  tlsCertFile: /etc/pullthrough/tls/server.crt
  tlsKeyFile:  /etc/pullthrough/tls/server.key

auth:
  enabled: true
  roles:
    - name: reader
      ecosystems: ["*"]
      upstreams:  ["*"]
    - name: publisher
      ecosystems: ["npm"]
      upstreams:  ["*"]

clientAuth:
  mtls:
    enabled: true
    # required: true makes a client certificate mandatory at the TLS handshake
    # (token/OIDC auth no longer suffices). Default false = either-or.
    required: false

    # Trust bundle of SPIFFE CA roots. PEM or SPIFFE Trust Bundle JSON.
    trustBundle: /etc/pullthrough/spiffe/bundle.pem
    trustBundleFormat: auto         # auto | pem | spiffe
    trustDomain: corp.example       # default domain for PEM / single-domain JSON

    # Optionally restrict accepted domains even if present in the bundle.
    allowedTrustDomains: ["corp.example"]

    # Hot-reload the trust bundle when the file changes.
    reloadInterval: 1m
    # Window for the "certificate expiring soon" gauge (default 720h / 30d).
    expiryWarning: 168h

    # Identity-mapping policy: SPIFFE-ID pattern → tenant + roles. First match
    # wins. Patterns are globs ('*' within a path segment, '**' across
    # segments); prefix with "re:" for a Go regular expression.
    defaultTenant: ""
    rules:
      - pattern: "spiffe://corp.example/ns/payments/sa/*"
        tenant:  payments
        roles:   ["reader"]
      - pattern: 're:^spiffe://corp\.example/ns/[^/]+/sa/ci$'
        tenant:  ci
        roles:   ["reader", "publisher"]

    # Per-tenant overrides: consulted after a global rule selects the tenant;
    # the first override that matches replaces the role set. Use it to elevate a
    # single workload without duplicating the global rule.
    tenantOverrides:
      payments:
        - pattern: "spiffe://corp.example/ns/payments/sa/admin"
          roles:   ["reader", "publisher"]
```

### Pattern matching

| Pattern | Matches | Does **not** match |
|---|---|---|
| `spiffe://corp.example/ns/payments/sa/*` | `…/sa/web`, `…/sa/api` | `…/sa/web/extra` (`*` stops at `/`) |
| `spiffe://corp.example/ns/**` | any path under `/ns/` | a different trust domain |
| `re:^spiffe://corp\.example/ns/[^/]+/sa/ci$` | exactly the `ci` SA in any namespace | other service accounts |

An identity that authenticates but matches **no** rule is rejected `403` (it is a
real workload, just not authorized) — distinct from a `401` for a missing or
invalid certificate.

### Trust bundle formats

- **PEM** (`trustBundleFormat: pem`, or `auto` when the file starts with
  `-----BEGIN CERTIFICATE-----`): a concatenation of CA certificates. All roots
  are associated with `trustDomain`. This is the simplest air-gapped form —
  export your SPIRE root CA(s) as PEM and ship the file.
- **SPIFFE Trust Bundle JSON** (`trustBundleFormat: spiffe`, or `auto` when the
  file starts with `{`): a JWKS-style document. Two shapes are accepted:
  - single-domain — a top-level `keys` array (`use: x509-svid`, cert in
    `x5c[0]`), associated with `trustDomain`; and
  - **federated** — a `trust_domains` map keyed by trust domain, each with its
    own `keys` array (no `trustDomain` needed; every domain is named).
  `jwt-svid` keys and SPIFFE sequence/refresh-hint fields are ignored.

The bundle is read from disk and never fetched at request time, so the whole
path is **offline/air-gapped friendly**. A failed reload (corrupt or missing
file) keeps the last known-good roots in place and is surfaced in the logs and
the `…_trust_bundle_reloads_total` metric.

---

## Deploying with SPIRE

SPIRE issues each workload an X.509-SVID whose SAN URI is its SPIFFE ID. Two
common patterns:

### 1. SPIRE Agent + Workload API sidecar (recommended)

The client workload fetches its SVID from the SPIRE Agent's Workload API and
presents it on the TLS connection to the proxy. Export the SPIRE **bundle** for
the proxy's trust anchor:

```sh
# On a host with spire-server access, dump the trust bundle as PEM:
spire-server bundle show -format pem > /etc/pullthrough/spiffe/bundle.pem

# …or the SPIFFE JSON format for federated trust domains:
spire-server bundle show -format spiffe > /etc/pullthrough/spiffe/bundle.json
```

Point `clientAuth.mtls.trustBundle` at that file and set `reloadInterval` so the
proxy picks up CA rotations. A sidecar such as
[`spiffe-helper`](https://github.com/spiffe/spiffe-helper) can keep the bundle
file fresh on disk; the proxy hot-reloads it.

A registration entry determines the SVID a workload receives, e.g.:

```sh
spire-server entry create \
  -spiffeID spiffe://corp.example/ns/payments/sa/web \
  -parentID spiffe://corp.example/spire/agent/k8s_psat/cluster/<node> \
  -selector k8s:ns:payments -selector k8s:sa:web
```

The proxy's `rules` then map `spiffe://corp.example/ns/payments/sa/web` to the
`payments` tenant.

### 2. Istio / Linkerd mesh

Service meshes mint SVIDs of the form
`spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>` and originate mTLS
from the sidecar. If the mesh terminates mTLS at *its own* ingress in front of
the proxy, either:

- let the **proxy be the mTLS peer** (exclude it from the mesh's automatic mTLS
  for that hop, or use a `PERMISSIVE`/passthrough port) so the workload SVID
  reaches the proxy on the TLS connection; or
- have the ingress forward the verified SVID and terminate mTLS there (in which
  case use the mesh's own authorization rather than this feature).

For Istio the trust bundle is the mesh root (`istioctl proxy-config` / the
`istio-ca-root-cert` ConfigMap); convert it to PEM and set `trustDomain` to the
mesh trust domain (default `cluster.local`):

```yaml
clientAuth:
  mtls:
    enabled: true
    trustBundle: /etc/pullthrough/spiffe/istio-root.pem
    trustDomain: cluster.local
    rules:
      - pattern: "spiffe://cluster.local/ns/build/sa/*"
        tenant:  build
        roles:   ["reader"]
```

---

## Audit attribution

Every pull and access-control decision is logged with `subject` set to the full
SPIFFE ID and a `authMethod: mtls` detail, alongside the resolved `team`. An
auditor can therefore attribute a download to a specific workload identity as
readily as to a token:

```json
{
  "type": "pull",
  "subject": "spiffe://corp.example/ns/payments/sa/web",
  "team": "payments",
  "decision": "allow",
  "detail": { "authMethod": "mtls", "cache": "HIT", "bytes": 10240 }
}
```

---

## Metrics

The Prometheus endpoint exposes (see [observability.md](observability.md)):

| Metric | Type | Meaning |
|---|---|---|
| `pullthrough_clientauth_mtls_success_total{method="mtls"}` | counter | Successful mTLS authentications. |
| `pullthrough_clientauth_mtls_failure_total{reason}` | counter | Failures by reason: `no_spiffe_id`, `untrusted_domain`, `chain_invalid`, `expired`, `policy_denied`, `malformed_id`. |
| `pullthrough_clientauth_cert_expiry_seconds` | gauge | Seconds until the soonest-expiring recently-verified client cert expires. |
| `pullthrough_clientauth_certs_expiring_soon` | gauge | Distinct identities whose last-seen cert expires within `expiryWarning`. |
| `pullthrough_clientauth_trust_bundle_reloads_total` | gauge | Number of trust-bundle (re)loads. |
| `pullthrough_clientauth_trust_bundle_expiry_seconds` | gauge | Seconds until the soonest-expiring trust-bundle root expires. |

Alert on a sustained rise in `…_mtls_failure_total{reason="chain_invalid"}`
(possible misconfigured trust anchor or a rogue issuer) and on
`…_cert_expiry_seconds` / `…_trust_bundle_expiry_seconds` approaching zero
(rotation overdue).

---

## Failure modes & semantics

| Situation | Result | Metric reason |
|---|---|---|
| No client certificate (either-or mode) | Falls through to token/OIDC auth | — (not a failure) |
| No client certificate (required mode) | TLS handshake fails | — |
| Cert without a SPIFFE SAN URI | Falls through (not a SPIFFE credential) | `no_spiffe_id` |
| Malformed SPIFFE SAN URI | `401` | `malformed_id` |
| Unknown / disallowed trust domain | `401` | `untrusted_domain` |
| Chain not anchored in the bundle | `401` | `chain_invalid` |
| Expired / not-yet-valid certificate | `401` | `expired` |
| Authentic SVID, no matching rule | `403` | `policy_denied` |
| Authentic SVID, rule matched | `200` (subject to RBAC/quota/rate-limit) | success |

---

## See also

- [access-control-and-audit.md](access-control-and-audit.md) — tokens, OIDC,
  RBAC roles, tenancy, quotas, and the audit log this feature plugs into.
- [admin-sso-rbac.md](admin-sso-rbac.md) — SSO/RBAC for the *admin* surface
  (separate from client auth).
- [air-gapped.md](air-gapped.md) — offline operation; the trust bundle is
  file-based and needs no network.
