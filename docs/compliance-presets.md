# Curated compliance policy presets (SLSA / NIST SSDF / CIS)

The proxy ships a library of **vetted, versioned baseline security
configurations** so operators get a strong supply-chain posture out of the box
instead of hand-assembling dozens of individual gate settings. Each preset is a
self-contained bundle that maps a standard's controls onto concrete settings
across the existing admission gates (signature verification, build provenance,
vulnerability scanning, license compliance, release-maturity cooldown,
dependency firewall, install-hook analysis, the policy-as-code engine, and
unified risk scoring).

Presets are implemented in [`internal/presets`](../internal/presets). The
control→gate-setting mapping table in `internal/presets/bundles.go` is the single
source of truth for the dry-run differ, the on-disk apply, and the traceability
matrix in this document.

## The three presets

| Name | Standard | Posture |
| --- | --- | --- |
| `slsa-l3` | SLSA v1.0 (Build Level 3) | Enforced verified provenance binding artifacts to source/build, enforced signatures, and a hard **critical**-CVE floor. |
| `nist-ssdf` | NIST SP 800-218 (SSDF v1.1) | Maps SSDF practices (PW/PS/RV) onto the gates: integrity verification, provenance, **high**-CVE response, license & install-hook hygiene, version cooldown. |
| `baseline-hardened` | CIS-style hardening baseline | Defense-in-depth: every gate on, tuned to minimise false-positive blocks (warns where the standards-driven presets block on softer signals). |

Each preset declares the compliance-scorecard controls it satisfies so the
[compliance scorecard](compliance.md) can attribute coverage to an applied
preset (see [Compliance attribution](#compliance-attribution)).

## How it works

A preset is a list of **settings**, each a dotted YAML path into the proxy
configuration plus the value the preset asserts there, the standard clause it
implements, and the scorecard controls it contributes to.

* **Dry-run diff** projects the preset onto the running configuration (in
  memory), computes a per-setting *current → proposed* delta, and validates the
  projected configuration by reusing the [configcheck](../internal/config)
  machinery (`Config.Check`). It also exposes a [simreplay](../internal/simreplay)
  candidate so the preset's policy + risk posture can be replayed against
  captured traffic for a blast-radius estimate (admit↔block flips, band shifts,
  new violations).
* **Apply** surgically patches the **raw on-disk** config file at exactly the
  paths the preset sets — preserving comments, encrypted secrets, key order, and
  every unrelated setting. It validates the patched document before writing,
  snapshots the previous file to a timestamped `.bak`, writes atomically, and
  records the change in the tamper-evident audit log (`EventAdmin`). The applied
  configuration takes effect on the next reload/restart.

Apply refuses to write if the projected configuration would be invalid, so a
preset can never break a running deployment.

## Using presets

### Server-side preflight (`verify-config`)

Dry-run a preset against a candidate config file (or the built-in defaults) from
the proxy host, e.g. in CI before a deploy:

```console
$ pullthrough verify-config preset list
$ pullthrough verify-config preset diff -config /etc/pullthrough/config.yaml slsa-l3
$ pullthrough verify-config preset diff -json nist-ssdf      # machine-readable
```

`diff` exits non-zero if the projected configuration is invalid.

### Client CLI (`ptctl`)

`ptctl` drives the admin API over HTTP:

```console
$ ptctl preset list
$ ptctl preset diff slsa-l3            # preview against the running config
$ ptctl preset apply slsa-l3           # admin-only, audited
```

### Admin API & UI

| Method & path | Capability | Purpose |
| --- | --- | --- |
| `GET /admin/api/presets` | read | List the vetted presets and the controls they satisfy. |
| `GET /admin/api/presets/diff?name=<name>` | read | Dry-run a preset against the running config (mutates nothing). |
| `POST /admin/api/presets/apply` | **administer** | Preview then apply a preset; body `{"name":"…","confirm":true}`. |

The admin dashboard's **Presets** tab lets an operator pick a preset, preview
exactly what it would change (with the projected-config validity), and apply it
with a confirmation prompt. Every apply is recorded in the Merkle-chained audit
log as an `EventAdmin` record carrying the preset name, version, satisfied
controls, and the resulting effective-config fingerprint, attributed to the
authenticated operator.

## Compliance attribution

Each preset declares which [compliance scorecard](compliance.md) controls its
settings satisfy. The scorecard control IDs a preset references are:

| Control ID | Scorecard control |
| --- | --- |
| `signature-verification` | Verified artifact signatures |
| `provenance-association` | Provenance / source-commit association |
| `vulnerability-gate` | Vulnerability (CVE) admission gate |
| `license-compliance` | License compliance |

Coverage by preset:

| Preset | Satisfied scorecard controls |
| --- | --- |
| `slsa-l3` | `provenance-association`, `signature-verification`, `vulnerability-gate` |
| `nist-ssdf` | `license-compliance`, `provenance-association`, `signature-verification`, `vulnerability-gate` |
| `baseline-hardened` | `license-compliance`, `provenance-association`, `signature-verification`, `vulnerability-gate` |

Because applying a preset turns the underlying gates on (and to enforce mode),
the live scorecard naturally reflects the improved posture; the declared control
list lets an auditor trace *which* preset is responsible for *which* control.

## Traceability matrix

The following tables are the authoritative control-to-setting mapping for each
preset (generated from the embedded bundle definitions). The *Setting* column is
the dotted config path; *Value* is what the preset sets it to; *Clause* cites the
standard's control; *Scorecard control* is the compliance control it contributes
to.

### `slsa-l3` — SLSA v1.0 (Build Level 3)

| Setting | Value | Clause | Scorecard control |
| --- | --- | --- | --- |
| `sigverify.enabled` | `true` | SLSA Build L2: signed provenance | signature-verification |
| `sigverify.requireSignature` | `true` | SLSA Build L2: signed provenance | signature-verification |
| `sigverify.action` | `block` | SLSA Build L2: signed provenance | signature-verification |
| `buildProv.enabled` | `true` | SLSA Build L3: provenance | provenance-association |
| `buildProv.mode` | `enforce` | SLSA Build L3: provenance | provenance-association |
| `buildProv.requireProvenance` | `true` | SLSA Build L3: provenance | provenance-association |
| `buildProv.action` | `block` | SLSA Build L3: provenance | provenance-association |
| `vulnerabilities.enabled` | `true` | SLSA: known-vuln hygiene | vulnerability-gate |
| `vulnerabilities.failSeverity` | `critical` | SLSA: known-vuln hygiene | vulnerability-gate |
| `vulnerabilities.action` | `block` | SLSA: known-vuln hygiene | vulnerability-gate |
| `policyEngine.enabled` | `true` | SLSA: admission policy | provenance-association |
| `policyEngine.mode` | `enforce` | SLSA: admission policy | |
| `riskScore.enabled` | `true` | SLSA: risk gating | |
| `riskScore.thresholdBand` | `high` | SLSA: risk gating | |
| `riskScore.thresholdAction` | `block` | SLSA: risk gating | |

### `nist-ssdf` — NIST SP 800-218 (SSDF v1.1)

| Setting | Value | Clause | Scorecard control |
| --- | --- | --- | --- |
| `sigverify.enabled` | `true` | PS.2 / PW.4.4: verify integrity | signature-verification |
| `sigverify.action` | `block` | PS.2: protect integrity | signature-verification |
| `buildProv.enabled` | `true` | PW.4.1: well-secured components | provenance-association |
| `buildProv.mode` | `enforce` | PW.4.1: well-secured components | provenance-association |
| `vulnerabilities.enabled` | `true` | RV.1.1 / PW.4.4: identify vulnerabilities | vulnerability-gate |
| `vulnerabilities.failSeverity` | `high` | RV.1: respond to vulnerabilities | vulnerability-gate |
| `vulnerabilities.action` | `block` | RV.1: respond to vulnerabilities | vulnerability-gate |
| `license.enabled` | `true` | PW.4.1 / PW.4.4: component provenance | license-compliance |
| `license.deny` | strong-copyleft / restricted set¹ | PW.4: reuse well-secured software | license-compliance |
| `license.action` | `block` | PW.4: reuse well-secured software | license-compliance |
| `installHooks.enabled` | `true` | PW.4.4: review acquired components | |
| `installHooks.failSeverity` | `high` | PW.4.4: review acquired components | |
| `installHooks.action` | `block` | PW.4.4: review acquired components | |
| `maturity.enabled` | `true` | PW.4.1: vet new component versions | |
| `maturity.defaultCooldown` | `72h` | PW.4.1: vet new component versions | |
| `policyEngine.enabled` | `true` | PO.3 / PW.4: enforce policy | |
| `policyEngine.mode` | `enforce` | PO.3: enforce policy | |
| `riskScore.enabled` | `true` | RV.2: assess and prioritize | |
| `riskScore.thresholdBand` | `high` | RV.2: assess and prioritize | |
| `riskScore.thresholdAction` | `block` | RV.2: assess and prioritize | |

¹ `license.deny` = `GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only,
GPL-3.0-or-later, AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0, BUSL-1.1,
CC-BY-NC-4.0`.

### `baseline-hardened` — CIS-style hardening baseline

| Setting | Value | Clause | Scorecard control |
| --- | --- | --- | --- |
| `sigverify.enabled` | `true` | CIS: verify software integrity | signature-verification |
| `sigverify.action` | `warn` | CIS: verify software integrity | signature-verification |
| `buildProv.enabled` | `true` | CIS: trace components to source | provenance-association |
| `buildProv.mode` | `observe` | CIS: trace components to source | provenance-association |
| `vulnerabilities.enabled` | `true` | CIS: continuous vulnerability management | vulnerability-gate |
| `vulnerabilities.failSeverity` | `critical` | CIS: continuous vulnerability management | vulnerability-gate |
| `vulnerabilities.action` | `block` | CIS: continuous vulnerability management | vulnerability-gate |
| `license.enabled` | `true` | CIS: software inventory & licensing | license-compliance |
| `license.action` | `warn` | CIS: software inventory & licensing | license-compliance |
| `installHooks.enabled` | `true` | CIS: malicious code defenses | |
| `installHooks.failSeverity` | `critical` | CIS: malicious code defenses | |
| `depfirewall.enabled` | `true` | CIS: allowlisting | |
| `depfirewall.defaultAction` | `allow` | CIS: allowlisting | |
| `maturity.enabled` | `true` | CIS: change management | |
| `maturity.defaultCooldown` | `24h` | CIS: change management | |
| `policyEngine.enabled` | `true` | CIS: enforce policy | |
| `policyEngine.mode` | `enforce` | CIS: enforce policy | |
| `riskScore.enabled` | `true` | CIS: risk-based prioritization | |
| `riskScore.thresholdBand` | `critical` | CIS: risk-based prioritization | |
| `riskScore.thresholdAction` | `warn` | CIS: risk-based prioritization | |

## Versioning

Each preset carries a semantic `version`. Bump it whenever the bundle's settings
change so an applied baseline is pinned exactly in the audit record. The current
bundles are all `1.0.0`.

## Notes & caveats

* **Apply rewrites the on-disk config file**, then relies on a reload/restart to
  take effect; it does not hot-swap every subsystem in place. The previous file
  is always backed up to `<config>.bak.<timestamp>`.
* Apply requires a backing config file (the process must be started with
  `-config <path>`); a defaults-only process can still `list` and `diff`.
* Presets intentionally do **not** set secrets or per-tenant overrides — they set
  the global enforcement posture. Layer tenant overrides and policy bundles on
  top as usual; they take precedence.
* A preset never enables the audit log itself (that requires an HMAC key the
  operator must provide); configure `audit:` separately.
