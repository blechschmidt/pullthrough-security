# Unified SARIF findings export (CI / PR decoration)

The proxy runs a stack of supply-chain admission gates on every artifact it
serves — vulnerability/OSV scanning, VEX adjudication, license compliance,
secret detection, signature/attestation verification, nameguard
(typosquatting / dependency-confusion), the unified risk score, and the
policy-as-code engine. The **findings-aggregation layer** normalizes the
verdicts of all of these gates into one canonical model and exports it as
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html),
the format GitHub code scanning and GitLab ingest natively.

A customer's CI pipeline can therefore call the proxy, retrieve the findings for
an artifact (or a batch of artifacts), and **decorate pull/merge requests** with
inline annotations or **fail the build** on a policy violation — without writing
any glue. Every finding carries a stable rule id, a help URI, a severity→level
mapping, and a location keyed to the package coordinate (and, when known, the
source commit).

## Configuration

```yaml
findings:
  enabled: true           # default; retain normalized findings and serve SARIF
  maxEntries: 2048        # bound on retained per-artifact documents (oldest-evicted)
  dedup: true             # default; collapse overlapping gate findings (see below)
  suppressionTrail: true  # default; record the suppression audit trail (see below)
  maxSuppressions: 8192   # bound on the suppression audit trail (oldest-evicted)
```

The layer is passive: it never affects admission. It records the most recent
findings document per `(tenant, coordinate)` after each pull and serves it on
demand.

## De-duplication (Task 165)

Multiple gates can emit overlapping findings for the same artifact — a secret
reported by both the Git commit scanner (Task 29) and the content-analysis gate
(Task 138), or a vulnerability surfaced by both the scanner and the remediation
advisor (Task 121). Before a findings document is recorded (and thus before
SARIF export, the dossier, and SIEM forwarding read it), the proxy
collapses duplicates keyed by **(coordinate, digest, category, locator)** into a
single canonical finding. The merged finding keeps the strongest, most-visible
signal of the group and preserves every contributing gate's provenance in its
`sources[]` array, so no attribution is lost. De-duplication is deterministic and
idempotent; set `findings.dedup: false` to retain the raw finding set.

The de-duplication counters are exported as the `pullthrough_findings_dedup_*`
family (documents processed, findings in/out, duplicates collapsed, and a
per-category collapse breakdown).

## Suppression audit trail (Task 165)

Every finding that a gate suppressed or downgraded away from a build-failing
verdict — a VEX adjudication (Task 27), a reachability downgrade (Task 118), a
policy downgrade (Task 32), or a human break-glass approval (Task 50) — is
recorded in an immutable, append-only ledger: **who/what** suppressed it, under
which **mechanism**, and **why**. The ledger is queryable per coordinate (it
surfaces as the dossier's *Suppression history* panel, Task 87) and each new
entry is mirrored into the tamper-evident audit log (Task 31) as an
`EventSuppression` record, so an auditor can reconstruct every "why was this not
blocked?" decision. Repeat observations of the same suppression only bump a
bookkeeping count; they are not re-recorded or re-mirrored. Set
`findings.suppressionTrail: false` to disable it.

The ledger counters are exported as the `pullthrough_findings_suppressions_*`
family (distinct suppressions recorded, total observations, the live ledger size,
a per-mechanism breakdown, and audit-mirroring successes/failures).

## Admin / API endpoints

Both are served under the admin prefix (default `/admin`) and honor the admin
bearer token.

### `GET /admin/api/findings/sarif?tenant=&package=`

Exports SARIF 2.1.0.

- With `package=` set to a coordinate (`lodash@4.17.21`) or a bare name
  (`lodash`, newest version wins), exports that single artifact's findings.
  Returns `404` if the artifact has not been pulled through the proxy yet.
- Without `package=`, exports a **batch** SARIF over every retained artifact for
  the tenant — the shape an air-gapped import preflight ingests in one document.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://proxy.example.com/admin/api/findings/sarif?tenant=acme&package=left-pad@1.3.0" \
  > results.sarif
```

Then in GitHub Actions:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### `GET /admin/api/findings?tenant=&q=`

Returns the canonical findings documents (the native model, not SARIF) for the
dashboard and for programmatic clients that prefer it.

## CLI: `pullthrough findings sarif`

For air-gapped import preflight (or any offline rendering), the CLI converts a
batch of **aggregated admission input documents** into a single SARIF log with no
live proxy:

```bash
pullthrough findings sarif -input batch.json -output results.sarif
# or read stdin, write stdout:
cat batch.json | pullthrough findings sarif > results.sarif
```

`batch.json` is a single object, or a JSON array of objects, each matching the
admission-input schema (`artifact`, `vuln`, `license`, `secret`, `signature`,
`nameguard`, `provenance`). Unknown fields are tolerated.

## Severity → SARIF level mapping

| Canonical severity | SARIF level | CI effect (typical) |
| ------------------ | ----------- | ------------------- |
| critical, high     | `error`     | fails the build     |
| medium             | `warning`   | annotates           |
| low, info          | `note`      | annotates           |
| none               | `none`      | informational       |

A VEX-suppressed vulnerability is emitted as a SARIF **suppression** (kind
`external`) so it stays visible for transparency but does not fail the build.

## Rules

The rule catalog is a finite, stable taxonomy; the dynamic specifics of a finding
(which CVE, which license, which name) live in the result's message, identifier,
and properties so a CI policy keyed on a rule id applies uniformly.

<a id="vulnerable-dependency"></a>**`vulnscan/vulnerable-dependency`** — a known
vulnerability (CVE/advisory) affects the artifact. Upgrade to a fixed version or
apply a VEX statement. When [reachability analysis](reachability.md) is enabled,
each result carries a `reachability` property (`reachable`/`unreachable`/
`unknown`); a finding proven unreachable and suppressed by policy is emitted as a
SARIF suppression (level `note`).

<a id="suppressed-vulnerability"></a>**`vex/suppressed-vulnerability`** — a
vulnerability a VEX statement adjudicated `not_affected`/`fixed`. Emitted as a
suppression; no action required.

<a id="non-compliant-license"></a>**`license/non-compliant`** — a component
license violates the allow/deny/review policy.

<a id="license-drift"></a>**`license/drift`** — a component's license changed
from a previously observed value.

<a id="exposed-credential"></a>**`secretscan/exposed-credential`** — a credential
or secret was detected in the artifact's contents. Revoke and rotate it.

<a id="unverified-signature"></a>**`sigverify/unverified-signature`** — the
artifact's authenticity could not be cryptographically verified.

<a id="typosquat"></a>**`nameguard/typosquat`** — the package name closely
resembles a popular package.

<a id="dependency-confusion"></a>**`nameguard/dependency-confusion`** — the public
package name shadows an internal namespace.

<a id="homoglyph"></a>**`nameguard/homoglyph`** — the package name contains
confusable characters.

<a id="suspicious-name"></a>**`nameguard/suspicious-name`** — a name-based
heuristic flagged the package.

<a id="risk-threshold-exceeded"></a>**`riskscore/threshold-exceeded`** — the
composite supply-chain risk score met the admission threshold.

<a id="policy-violation"></a>**`policyengine/policy-violation`** — an
operator-authored admission policy rule fired with a non-allow effect.

<a id="unverified-provenance"></a>**`provenance/unverified`** — no verified
build-provenance association to a source commit.

<a id="malicious-source-commit"></a>**`provenance/malicious-commit`** — the
artifact's source commit was assessed malicious by the commit scanner.

<a id="risky-install-script"></a>**`installhooks/risky-install-script`** — a
package install/lifecycle hook contains a high-risk pattern. The install-hook
analysis gate (Task 62) statically extracts the package's automatically-run
install scripts — npm `preinstall`/`install`/`postinstall`, Python `setup.py` /
`pyproject.toml` build hooks, RubyGems native extensions and
`post_install_message`, and Cargo `build.rs` — and matches them against a fixed,
deterministic catalog of high-risk behaviors **without executing anything**:
remote script piped into a shell (`curl … | sh`), base64/hex-decoded `eval`,
environment-variable exfiltration, network egress during install, shell/process
spawning, writes outside the package directory, obfuscated one-liners, and
native-build steps. The matched rule id, the hook (e.g. `npm:postinstall`), the
file, and a redacted excerpt appear in the result properties. A finding at or
above the configured `failSeverity` warns on or blocks (and evicts) the
artifact.

<a id="suspicious-content"></a>**`contentscan/suspicious-content`** — a package
file contains statically-suspicious content. The package-payload content-analysis
gate (Task 138) unpacks the served source artifact — an npm tarball, a pip
sdist/wheel, a gem/composer/cargo/nuget archive — and applies deterministic,
**no-execution** heuristics to its files: a high-entropy embedded blob (a packed
or encrypted payload hiding under a source/text/data extension), an unexpectedly
embedded native binary in a nominally-source package (ELF/PE/Mach-O/`.so`/`.dll`/
`.node`/…), obfuscated or minified-plus-`eval` JavaScript, a dynamic
code-execution sink (`eval`/`exec`, base64-decode-then-run, or a remote script
piped into a shell), and an in-source credential/secret (reusing the Task 29
detectors against the package files). The category, rule id, file, and a redacted
excerpt appear in the result properties. Binary distributions (wheels, NuGet
packages, JARs) legitimately ship compiled objects, so the embedded-binary and
high-entropy heuristics are suppressed for them while the secret / obfuscation /
dynamic-exec heuristics still apply. A finding at or above the configured
`failSeverity` is annotated, downgraded, or (under the block action) refused and
evicted, per `contentScan.action`.

<a id="build-provenance-source-mismatch"></a>**`buildprov/source-mismatch`** —
the signed build provenance proves a different source than the package metadata
claims. The inbound build-provenance gate (Task 72) verifies the
upstream-published build-provenance attestation (npm provenance / GitHub artifact
attestation), cryptographically binds the package version to a source repository
and commit, and cross-checks that **proven** source against the commit/repository
**claimed** by package metadata (the package-to-commit association from Task 8). A
disagreement is a strong supply-chain signal that the published metadata
misrepresents where the artifact was built. The proven and claimed
commit/repository and the signing CI workflow appear in the result properties. In
enforce mode a mismatch quarantines (and evicts) the artifact. See
[build-provenance.md](build-provenance.md).

<a id="unverified-build-provenance"></a>**`buildprov/unverified-provenance`** — an
inbound build-provenance attestation was present but could not be verified: its
DSSE signature did not validate against its signing certificate, it did not bind
this artifact's digest, or (when a trusted signer is required) its signer was not
trusted. A present-but-invalid attestation can indicate tampering.

<a id="pypi-attestation-digest-mismatch"></a>**`pypiattest/digest-mismatch`** — a
cryptographically-valid PyPI PEP 740 digital attestation was found for the served
distribution, but it attests a **different** sha256 digest than the wheel/sdist the
proxy served. The inbound PyPI attestation gate (Task 146) fetches the distribution's
PEP 740 provenance (the Integrity API / JSON-index `provenance` field), verifies the
enclosed Sigstore attestations against the Fulcio/Rekor trust root, and binds the
attested digest to the served artifact. A valid attestation for a different digest
means the served file is not the file the Trusted Publisher attested — a strong
substitution/tampering signal. The declared publisher (kind, repository, workflow)
and the authenticated signer identity appear in the result properties. With
`pypiAttestation.action: block` the pull is refused and the artifact evicted.

<a id="unverified-pypi-attestation"></a>**`pypiattest/unverified-attestation`** — a
PyPI PEP 740 attestation was present but could not be verified: its DSSE signature
did not validate against its signing certificate, no verifying attestation bound this
distribution's sha256 digest, or (when a trusted publisher is required) its Trusted
Publisher was not trusted. A present-but-invalid attestation can indicate tampering.

<a id="maintainer-drift"></a>**`continuity/maintainer-drift`** — the
maintainer/publisher continuity gate compared the publisher principals observed for
this coordinate (the registry maintainer roster, the publishing namespace owner, and
any signing-key identity) against the durable trust-on-first-use known-maintainer
set, and found a previously-unseen principal on an already-known package. A brand-new
maintainer, a rotated publishing key, or a new namespace owner is the classic
precursor to an account-takeover or package hijack (event-stream, ua-parser-js, coa,
rc). Confirm the ownership change is legitimate (an intentional transfer, not a
hijacked account) before consuming the version; once verified, pin the version or add
the new maintainer to the continuity allowlist. A configurable per-tenant disposition
(observe / warn / block) and a trust cooldown govern whether a drift is merely
recorded, surfaced, or refused while the new maintainer ages into the known set.

<a id="suspicious-source-commit"></a>**`commitscan/suspicious-commit`** — the
continuous Git commit scanner (webhook/polling-driven, see
[commit-watch.md](commit-watch.md)) scanned a new commit in a watched repository and
the LLM/deterministic commit-scanning pipeline flagged a supply-chain risk in it:
malicious code, an embedded credential, obfuscation, a suspicious dependency change,
data exfiltration, a backdoor, or build tampering. The finding is keyed by repository
and commit SHA (coordinate `git/<repo>@<sha>`), and the result properties carry the
category, the commit-scan risk score, and whether the model called the commit
malicious. Investigate the flagged commit before any artifact built from it is
consumed; the package-to-commit provenance association then links downstream
artifacts back to this verdict.

<a id="unpinned-action"></a>**`actionpin/unpinned-action`** — the GitHub Actions
pinning gate (Task 115) parsed the `uses:` references in a repository's
`.github/workflows/*.yml` and composite `action.yml` files (over the changed lines
of a scanned commit) and found a third-party action or reusable workflow pinned to a
**mutable** git ref — a branch name or a floating tag such as `@v4` — or to no ref at
all, rather than to a full 40-character commit SHA. A mutable ref can be moved by
whoever controls the upstream tag/branch to point at arbitrary code that then runs
with the workflow's credentials (the tj-actions/changed-files compromise,
CVE-2025-30066). Pin the action to a commit SHA:
`uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`. The
offending reference and its pinning classification are in the result properties; no
workflow is ever executed. This is a warning by default (medium severity); lower
`scanning.actions.failSeverity` to `medium` to block mutable pins.

<a id="disallowed-action-owner"></a>**`actionpin/disallowed-owner`** — the GitHub
Actions pinning gate found a `uses:` reference whose owner/org is not among the
configured `scanning.actions.allowedOwners`. Restricting workflows to a vetted set of
action publishers shrinks the third-party supply-chain surface that runs with the
workflow's credentials. Replace the action with one from a permitted owner, or add
the owner to the allowlist if it is trusted. Error severity by default (it blocks at
the default `failSeverity: high`).
