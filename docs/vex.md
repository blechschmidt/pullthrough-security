# VEX-based vulnerability suppression

The vulnerability-scanning gate ([SBOM/OSV](configuration.md), `internal/vulnscan`)
resolves every cached artifact's components against a vulnerability database and
admits, warns, or blocks based on the findings' severity/CVSS. In the real world
many of those findings are **not exploitable in the artifact's context** — the
vulnerable code path is unreachable, the component is absent at runtime, or an
inline mitigation already exists. A vendor or operator captures that assessment
in a **VEX** (Vulnerability Exploitability eXchange) document.

The VEX subsystem ingests those documents and correlates their statements against
the scan findings, so an authoritative `not_affected`/`fixed` declaration
**suppresses** a finding (drops it from gating) while an `affected` declaration
**raises** its severity. This eliminates false-positive blocks without weakening
the gate against confirmed-exploitable issues.

## Supported formats

| Format | Detection | Statuses consumed |
|--------|-----------|-------------------|
| **OpenVEX** (`https://openvex.dev/ns/*`) | a top-level `statements` array, or an `@context` mentioning openvex | `not_affected`, `affected`, `fixed`, `under_investigation` |
| **CSAF VEX** (CSAF 2.0) | a `document` + `vulnerabilities` pair | `known_not_affected`→not_affected, `known_affected`→affected, `fixed`/`first_fixed`→fixed, `under_investigation` |

Both formats normalize onto a single internal `VEXStatement` shape (product +
vulnerability + status + justification + timestamp + source), so the matcher and
policy are format-agnostic. The OpenVEX 0.2.0 shape (vulnerability object,
`products` array, `subcomponents`) **and** the legacy shape (vulnerability
string, single `product` string) are both accepted.

## How statements are matched

A statement governs a finding when **both** correlate:

- **Vulnerability** — the statement's id (or any alias) equals the finding's id
  or any of its aliases (case-insensitive). A VEX keyed by GHSA matches a finding
  keyed by the equivalent CVE.
- **Product** — one of the statement's products resolves to the finding's
  component coordinate *or* the pulled artifact's coordinate. Products are
  compared structurally by [purl](https://github.com/package-url/purl-spec)
  (type + namespace + name, with the version matched only when the statement pins
  one — an unpinned statement covers every version). A statement that narrows to
  `subcomponents` matches only when the finding's component is one of them.

When several statements match the same finding, the **most recent** (by
timestamp) wins — this is how OpenVEX expresses *revocation*: a newer statement
supersedes an older one.

## Policy effect

| Status | Effect on a matching finding |
|--------|------------------------------|
| `not_affected` | **Suppressed** — excluded from the counts, headline severity, and gating. The artifact is admitted as if the finding were absent. |
| `fixed` | **Suppressed** (as above). |
| `affected` | **Escalated** — severity raised one step toward critical (floor: high), so an operator-confirmed issue cannot slip below the gate threshold. The original severity is retained for audit. |
| `under_investigation` | Annotated only — neither suppressed nor escalated. |

Every suppression and escalation is logged with its **VEX source** (the document
path/URL and statement index) for audit, and counted in the metrics and admin
API. Suppressed findings remain in the scan `Report` (flagged `suppressed`) so
they stay visible for transparency.

## Loading

Two sources, both optional and combinable:

- **Directory** (`vulnerabilities.vex.dir`) — every `*.json` / `*.vex` /
  `*.vex.json` file under the directory is parsed at startup. A file that fails
  to parse is **logged and skipped**, never blocking the rest. This is the
  **air-gapped** source: drop VEX documents into the directory alongside the
  pre-warmed scan cache and no network is required.
- **Per-artifact fetch** (`vulnerabilities.vex.fetchUrl`) — an optional URL
  template (`{ecosystem}`, `{name}`, `{version}`, `{digest}` placeholders)
  fetched on demand for each scanned artifact, with a short-TTL cache. Ignored
  when the vulnerability subsystem is `offline` (air-gapped).

## CVE-drift integration

The continuous re-scan loop ([Task 18](configuration.md)) re-applies the current
VEX corpus on every sweep. If a `not_affected` statement that was suppressing a
critical finding is **revoked** — its file removed and the directory reloaded, or
a newer `affected` statement superseding it — the next sweep sees the finding
become active again, crosses the policy threshold, and **re-quarantines** the
artifact (emitting the usual audit event and notification). Re-instating the
statement and releasing the quarantine restores admission.

## Configuration

```yaml
vulnerabilities:
  enabled: true
  failSeverity: high
  vex:
    enabled: true
    dir: /etc/pullthrough/vex          # directory of OpenVEX/CSAF documents
    # fetchUrl: https://vex.internal/{ecosystem}/{name}/{version}.json
```

## Metrics & admin

- Metrics: `pullthrough_vex_suppressed_total`, `pullthrough_vex_escalated_total`,
  `pullthrough_vex_statements` (gauge), `pullthrough_vex_documents` (gauge),
  `pullthrough_vex_malformed_documents` (gauge).
- Admin: `GET {prefix}/api/vex` returns the loaded corpus statistics, the
  cumulative suppressed/escalated counts, and the statements (filter with `?q=`).
  Per-artifact suppressed/escalated tallies appear on each row of
  `GET {prefix}/api/vulns` and in the full report at `…/api/vulns/entry`.

# Outbound VEX authoring & export

The subsystem above *consumes* VEX. The proxy can also **emit** VEX: as operators
triage findings — `not_affected`/`fixed` suppression decisions, VEX-adjudicated
findings, and time-boxed break-glass approvals — the export engine
(`internal/vexexport`) renders the current posture as a **signed OpenVEX
document** or a **CycloneDX 1.5 VEX/VDR BOM**, per coordinate or for a whole
snapshot. This lets you publish your VEX posture to downstream consumers (CI,
dependency-track, auditors) directly from the proxy's live state.

An OpenVEX document the proxy emits **re-ingests cleanly** through the suppression
gate above (`ParseVEX` → `VEXStore.Match`), so the round trip is lossless.

## What the posture is assembled from

| Source | VEX statements produced |
|--------|-------------------------|
| **VEX suppression corpus** (`internal/vulnscan`, loaded per the section above) | the authoritative `not_affected`/`fixed`/`affected` decisions, emitted verbatim |
| **VEX-adjudicated findings** (`internal/findings`, gate `vex`) | `not_affected`/`fixed` statements for suppressions observed in scan reports (captures per-artifact fetched VEX and inline adjudications not in the static corpus) |
| **Break-glass grants** (`internal/approvals`, Task 50) | `under_investigation` statements for coordinates served under an active, dual-controlled exception — cross-referenced to the coordinate's real CVE findings when available; the action statement records the approvers and the expiry |

Statements are deduplicated by `(vulnerability, product)` with the corpus taking
precedence, and emitted in a deterministic order so exports are reproducible.

## Scope

- **Single artifact** — pass `ecosystem` + `name` + `version` (or a `coordinate`):
  only corpus statements covering that coordinate are included, plus its findings
  and grants.
- **Captured snapshot** — pass `snapshot=<id>`: the posture for that snapshot's
  coordinate set ([Task 70](snapshots.md)).
- **Whole live posture** — pass neither: every coordinate the proxy has served
  (snapshot live facts ∪ retained findings), scoped by `tenant`.

## Signing

Signing is **optional** and reuses the project's signing-key conventions
(ECDSA-P256 / RSA-PKCS1v15 / Ed25519 PEM, verifiable with
`sigverify.ParsePublicKeyPEM`). The key is resolved from, in order:
`vulnerabilities.vex.export.signingKey[File]` → `attest.signingKey[File]` →
`audit.transparency.signingKey[File]`. When a key is available a **detached**
signature over the exact document bytes is produced, so the signed document stays
byte-for-byte verifiable **and** re-ingestable. The signature travels in the
`X-Vex-Signature*` response headers (and is written to a sidecar by the CLI).

## Endpoints & CLI

- Admin: `GET {prefix}/api/vex/export` with query params `format`
  (`openvex`|`cyclonedx`), `tenant`, `ecosystem`, `name`, `version`,
  `coordinate`, `snapshot`, and `sign` (`true`). Returns the raw document with
  its media type (`application/vnd.openvex+json` or
  `application/vnd.cyclonedx+json; version=1.5`), a `Content-Disposition`
  filename, and `X-Vex-Statements`/`X-Vex-Coordinates`/`X-Vex-Scope` (plus the
  `X-Vex-Signature*` headers when signed). It needs only the read capability.
- CLI (`ptctl vex export`):

  ```sh
  # OpenVEX for one coordinate
  ptctl vex export --ecosystem npm lodash 4.17.21

  # CycloneDX VEX/VDR for a coordinate
  ptctl vex export --ecosystem pip requests@2.19.0 --format cyclonedx

  # Whole-tenant posture, signed, to files
  ptctl vex export --tenant acme --sign \
      --output acme-vex.json --sig-out acme-vex.sig.json

  # Posture for a captured snapshot
  ptctl vex export --snapshot <snapshot-id> --format openvex
  ```

## Configuration

```yaml
vulnerabilities:
  vex:
    enabled: true
    dir: /etc/pullthrough/vex
    export:
      enabled: true
      author: "Acme Security"                # OpenVEX author / CycloneDX metadata author
      idNamespace: "https://acme.example/vex" # base URI for OpenVEX @id values
      # signingKey / signingKeyFile: optional; falls back to the attest/audit key
```

## Metrics

- `pullthrough_vex_exports_total{format,signed}` — documents generated, by format
  and whether signed.
- `pullthrough_vex_export_statements_total` — statements emitted across all
  exports.
- `pullthrough_vex_export_errors_total` — failed export attempts.
