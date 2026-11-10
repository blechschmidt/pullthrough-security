# SSRF / Egress Allowlist Enforcement

The proxy fronts dozens of upstream registries on behalf of untrusted clients. That
makes it a tempting **confused-deputy / SSRF pivot**: a malicious index document, a
crafted redirect, or a DNS-rebinding trick could try to steer an outbound fetch at an
internal service — cloud metadata endpoints (`169.254.169.254`), RFC1918 hosts, a
loopback admin panel.

The **egress guard** (`internal/egress`) is a transport-level, defense-in-depth control
installed on *every* outbound HTTP client so all backends (pip, npm, cargo, go, nuget,
maven, docker/OCI, helm, apt, yum, terraform, …) are covered uniformly without each
re-implementing it. It is the same seam the health-aware mirror pool
(`internal/upstreampool`) wraps.

## What it enforces (fail-closed)

1. **Scheme allowlist** — https-only by default. Configure `egress.allowedSchemes` to
   permit `http` for internal mirrors.
2. **Host/domain/CIDR allowlist** — optional, per-instance and per-tenant. An empty
   allowlist enforces only the scheme + IP-range floors (already blocking
   SSRF-to-internal); a non-empty allowlist switches to **deny-by-default** for hosts.
   Entries may be an exact host (`registry.npmjs.org`), a domain suffix (`.npmjs.org`
   or `*.npmjs.org`), or a CIDR / IP literal (`10.0.0.0/8`, `192.0.2.1`).
3. **Private/internal IP denial** — any request that *resolves* to a private (RFC1918),
   link-local (`169.254.0.0/16`, `fe80::/10`), loopback (`127.0.0.0/8`, `::1`),
   unique-local (`fc00::/7`), carrier-grade-NAT (`100.64.0.0/10`), unspecified,
   multicast, or **cloud-metadata** (`169.254.169.254`, `fd00:ec2::254`) address is
   refused. IPv4-mapped, **6to4** (`2002::/16`), and **NAT64** (`64:ff9b::/96`) IPv6
   forms are unwrapped and re-classified so a transition address cannot smuggle an
   internal IPv4 target past the v4 checks.
4. **DNS-rebinding defense** — the destination IP is re-validated *immediately before
   connect* via the dialer's `ControlContext` hook. The IP validated is the exact IP
   connected to, so there is no window for a hostname to resolve "public" during the
   policy check and "internal" at connect time.
5. **Redirect policy** — every redirect hop is re-checked (each hop is a fresh
   RoundTrip whose URL and resolved IP are re-validated), under a hard
   `egress.maxRedirects` cap. Set `egress.followRedirects: false` to refuse following
   entirely.

A blocked fetch returns a clear `*egress.BlockedError` (detectable via `errors.As`),
increments the `pullthrough_egress_blocked_by_reason_total{reason}` metric, emits an
`EventEgressBlocked` notification (escalated to *critical* for metadata/private
targets — a live SSRF indicator), and writes a deny record to the tamper-evident audit
log.

## Configuration

```yaml
egress:
  enabled: true                 # default: true
  httpsOnly: true               # default: true (ignored when allowedSchemes is set)
  allowedSchemes: []            # e.g. ["https", "http"] to allow an internal http mirror
  allowlist:                    # empty = no host allowlist (scheme + IP floors still apply)
    - "*.npmjs.org"
    - "pypi.org"
    - "files.pythonhosted.org"
  blockPrivateNetworks: true    # default: true
  allowedDestinationCidrs:      # exceptions to the private-network block
    - "10.20.0.0/16"            # an internal mirror you deliberately front
  followRedirects: true         # default: true
  maxRedirects: 5               # default: 5
  tenants:                      # optional per-tenant overrides
    team-platform:
      allowlist:                # additive to the global allowlist
        - "artifacts.internal.example.com"
      httpsOnly: false          # optional scheme override for this tenant
```

### Secure defaults

With no `egress:` block the guard is **on**: https-only, private/metadata ranges
blocked, redirects followed up to 5 hops (each re-checked), and **no host allowlist**
(so enabling it does not require enumerating every public registry up front). This
already blocks SSRF-to-internal while permitting any public https host.

> If you front an **internal http mirror**, you must opt in deliberately:
> add its host to `egress.allowlist`, its range to `egress.allowedDestinationCidrs`,
> and `http` to `egress.allowedSchemes` (or set `egress.enabled: false` to turn the
> control off entirely).

The per-tenant allowlist is **additive** and the IP-range floor is always
instance-global: a tenant can be granted extra hosts but can never punch a hole through
to the metadata service.

## Admin & observability

- **Admin → Egress** tab: the effective policy, check/allow/block counters, the
  per-reason breakdown, recent blocks, a **dry-run** evaluator (`POST /api/egress/test`
  — evaluate a candidate URL, read-only), and runtime allowlist add/remove
  (`POST /api/egress/allowlist`, admin-only).
- **Metrics**: `pullthrough_egress_checks_total`, `pullthrough_egress_allowed_total`,
  `pullthrough_egress_blocked_total`, and the labeled
  `pullthrough_egress_blocked_by_reason_total{reason}`. Alert on a non-zero
  `metadata` / `private_network` reason — it is a strong SSRF-attempt signal.
- **Notifications**: `EventEgressBlocked` routes through the standard notify sinks and
  surfaces in the Security Operations dashboard (`egress` gate).
- **Audit**: each block is an `egress_blocked` deny record in the Merkle audit log.
