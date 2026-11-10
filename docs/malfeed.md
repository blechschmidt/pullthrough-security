# Known-malicious package blocking

The proxy can **hard-block** any pull whose concrete coordinate
`(ecosystem, name, version)` appears in a curated dataset of *actively malicious*
packages — crypto-miners, credential stealers, and install-script backdoors. The
data comes from the OpenSSF/OSV **`malicious-packages`** dataset
([github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages))
and the **malware entries in the GitHub Advisory Database**.

This gate (`internal/malfeed`, Task 48) is deliberately distinct from its
neighbours:

| Gate | What it matches | Nature |
|------|-----------------|--------|
| [nameguard](../README.md) (Task 19) | *names that look like* a popular/internal package | heuristic (typosquat, confusion, homoglyph) |
| [vulnscan](security-model.md) (Task 15) | components in an artifact's SBOM with a **CVE** | vulnerability advisory |
| **malfeed** (Task 48) | the **exact** `(ecosystem, name, version)` published as malware | concrete known-bad coordinate |

A malfeed match is never advisory: a listed coordinate is refused with the
advisory ID and reason, **before any upstream fetch or cache fill**, so the
malicious bytes are never transferred.

## How it works

```
pull → resolve coordinate → nameguard → malfeed → policy → … → serve
                                          │
                          (ecosystem, name, version)
                                          │
                         match against the loaded malware feed
                                          │
                    matched ──► 403 + advisory id/reason (no fetch)
```

Because the check needs only the coordinate — no artifact content and not even a
version for a whole-package block — it runs early, right after the name
heuristics and before the artifact is retrieved.

### Matching

Names are normalized per-ecosystem so the spelling variants each registry treats
as equivalent collide on lookup:

- **pip (PyPI)** — PEP 503: lowercase, runs of `-_.` collapse to a single `-`.
- **npm**, **nuget**, **composer** — case-insensitive (lowercased).
- **cargo (crates.io)** — lowercase, `_`≡`-`.
- **go**, **maven**, **rubygems** — identity-sensitive (compared verbatim).

A feed entry covers either the **whole package** (every version — the common
case in the OSV dataset, and the only shape that blocks a version-less index
lookup), an **explicit list of versions**, or a **version range**
(`introduced` / `fixed` / `last_affected`, evaluated with a tolerant SemVer/PEP
440-style comparator). Ecosystem names from the feed (`PyPI`, `crates.io`, `Go`,
`NuGet`, `Maven`, `RubyGems`, `Packagist`, …) and `pkg:` purls are mapped to the
canonical keys above.

## Feeds & refresh

```yaml
malfeed:
  enabled: true
  sources:
    - url: https://feeds.internal.example/malicious-packages.json
      name: ossf-malicious-packages
  refreshInterval: 6h       # background refresh period (0 disables the loop)
  staleAfter: 24h           # data is "stale" this long after the last success (0 disables)
  failClosed: false         # behaviour while stale (see below)
  timeout: 30s              # per-feed fetch timeout
```

Each source serves a single OSV record or a JSON array of OSV records. Refresh is
**conditional**: the gate remembers each source's `ETag` / `Last-Modified` and
sends `If-None-Match` / `If-Modified-Since`, so an unchanged feed returns
`304 Not Modified` and the loaded data is retained untouched. A source that fails
transiently keeps its previously-loaded entries rather than blanking the list; a
refresh errors only when **every** source fails.

The subsystem is **on by default but inert** until a feed (or offline bundle)
supplies data: with an empty matcher the gate fails open and never blocks a pull.

### Fail-open vs fail-closed on staleness

`staleAfter` bounds how long the loaded data is trusted after the last
successful refresh (a never-loaded feed counts as stale immediately).

- **`failClosed: false`** (default, availability-first) — a stale feed still
  blocks **concrete matches**, but an unmatched pull is served.
- **`failClosed: true`** (safety-first) — while the feed is stale, **every** pull
  in the covered path is refused (`code: feed-stale`) until a refresh succeeds.

## Air-gapped: signed offline bundle

For disconnected deployments, build a **signed bundle** on a connected host and
transfer it in. The bundle is an Ed25519-signed envelope over the canonical,
de-duplicated entry set (mirrors the air-gapped pattern of the other gates).

```sh
# One-time: generate a signing keypair.
pullthrough malfeed keygen -private malfeed.key -public malfeed.pub

# On a connected host: fetch the configured feeds and sign a bundle.
pullthrough malfeed export -config config.yaml -key malfeed.key -out malfeed-bundle.json

# (Optional) verify a bundle before transfer.
pullthrough malfeed import -in malfeed-bundle.json -pubkey malfeed.pub
```

Then, on the air-gapped proxy, import the bundle at startup and pin the signer:

```yaml
malfeed:
  enabled: true
  sources: []                              # no network
  bundlePath: /etc/pullthrough/malfeed-bundle.json
  bundlePublicKeyFile: /etc/pullthrough/malfeed.pub
```

Import verifies the payload digest and the Ed25519 signature against the pinned
public key (authenticity); with no pinned key it falls back to verifying against
the bundle's embedded key (integrity only). A tampered or wrong-key bundle is
rejected. An imported bundle counts as a successful load, so an air-gapped
deployment is not immediately "stale".

## Block response

A refused pull returns `403 Forbidden` with `X-Malfeed-Decision: block`,
`X-Malfeed-Code`, `X-Malfeed-Advisory`, and `X-Malfeed-Reason` headers and a JSON
body:

```json
{
  "error": "package refused by known-malicious-package admission policy",
  "code": "malicious",
  "reason": "npm credential stealer in postinstall script (advisory MAL-2024-0001)",
  "ecosystem": "npm",
  "package": "evil-stealer",
  "version": "1.0.0",
  "advisory": "MAL-2024-0001",
  "aliases": ["GHSA-aaaa-bbbb-cccc"],
  "categories": ["credential-stealer"],
  "source": "ossf-malicious-packages"
}
```

Every block is recorded in the tamper-evident **audit log** (`malfeed:<code>`)
and emitted as a **critical** `malicious_block` notification
([notifications](notifications.md)).

## Admin API

| Method & path | Purpose |
|---------------|---------|
| `GET /admin/api/malfeed` | Gate status (entries loaded, per-ecosystem counts, freshness, fail-open/closed) and a search over loaded entries. Query: `?q=`, `?ecosystem=`, `?limit=` (default 200). |
| `POST /admin/api/malfeed/refresh` | Force an immediate (conditional) feed refresh and return the new status. |

## Metrics

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `pullthrough_malfeed_entries_loaded` | gauge | | Known-malicious records loaded. |
| `pullthrough_malfeed_entries_by_ecosystem` | gauge | `ecosystem` | Loaded records per ecosystem. |
| `pullthrough_malfeed_checks_total` | counter | | Coordinates evaluated. |
| `pullthrough_malfeed_blocks_total` | counter | | Pulls blocked (match or fail-closed). |
| `pullthrough_malfeed_blocks_by_ecosystem_total` | counter | `ecosystem` | Concrete-match blocks per ecosystem. |
| `pullthrough_malfeed_stale_blocks_total` | counter | | Pulls blocked solely due to a stale feed (fail-closed). |
| `pullthrough_malfeed_stale_serves_total` | counter | | Unmatched pulls served while stale (fail-open). |
| `pullthrough_malfeed_refreshes_total` | counter | | Refresh attempts. |
| `pullthrough_malfeed_refresh_failures_total` | counter | | Refreshes where every source failed. |
| `pullthrough_malfeed_refresh_age_seconds` | gauge | | Seconds since the last successful refresh (`-1` = never). |
| `pullthrough_malfeed_stale` | gauge | | `1` when the feed is stale, else `0`. |

Alert on a rising `pullthrough_malfeed_refresh_age_seconds` (the feed has stopped
updating) and on any increase in `pullthrough_malfeed_blocks_total` (a client
attempted to pull a known-malicious package).
