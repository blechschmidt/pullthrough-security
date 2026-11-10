# Supply-chain red-team simulation & gate-efficacy harness

The proxy ships dozens of independently-built admission gates (name guard,
malware feed, signature verification, install-hook analysis, CVE scanning,
license policy, version cooldown, reproducible-build verification, the dependency
firewall, …). Each is unit-tested in isolation, but their **end-to-end efficacy
as a defense-in-depth pipeline** is only meaningfully measured by driving real
attacks through the real gateway and observing the verdict.

`internal/redteam` (Task 76) does exactly that. It injects a curated catalog of
synthetic supply-chain attack scenarios end-to-end through the full admission
pipeline of an **in-process** `proxy.Gateway` — each wired with deterministic
stub backends and the specific gate(s) under test — and asserts that the expected
gate blocks each one (or, for the VEX-suppression case, deliberately admits it).

This is a **security-validation / test harness, not a new admission gate**:
nothing here runs on the production pull path.

## What it proves

For every scenario the harness records:

- which gate **fired** (detected from the response's decision headers),
- the **verdict** (HTTP status → `blocked` / `admitted`), and
- a **pass/fail** against the scenario's assertion.

It emits a **coverage matrix** (scenario × expected-gate × actual outcome) as
JSON or Markdown, and — crucially — fails CI if any expect-block scenario
**regresses from `blocked` to `admitted`**: a defense silently ceasing to work.

## Scenario catalog

| # | Scenario | Attack class | Expected gate | Expectation |
|---|----------|--------------|---------------|-------------|
| 01 | Typosquat of a popular npm package | typosquat | nameguard | block |
| 02 | Dependency-confusion shadowing of an internal package | dependency-confusion | nameguard | block |
| 03 | Known-malicious coordinate on a malware feed | known-malicious | malfeed | block |
| 04 | Dependency-firewall version-pin violation | version-pin-violation | depfirewall | block |
| 05 | Fast publish-and-yank inside the release cooldown | version-cooldown | maturity | block |
| 06 | Unsigned artifact where a signature is required | missing-signature | sigverify | block |
| 07 | Missing/forged inbound build provenance | forged-provenance | buildprov | block |
| 08 | Malicious npm postinstall hook | install-hook | installhooks | block |
| 09 | Embedded credential in the source commit | embedded-secret | secretscan → policy | block |
| 10 | Artifact with a critical CVE | critical-cve | vulnscan | block |
| 11 | Critical CVE suppressed by a VEX `not_affected` statement | vex-suppression | vulnscan | **admit** |
| 12 | Denied (strong-copyleft) license | license-violation | license | block |
| 13 | Binary that does not derive from its attested source | reproducible-build-mismatch | rebuildverify | block |

Notes:

- **Scenario 09 (embedded secret)** reflects the real architecture: secret
  detection (Task 29) is a *commit-scan* control, not a standalone pull gate. A
  secret in the source commit floors the commit's risk score, which the **policy
  gate** then blocks on. The scenario runs the *real* `secretscan` detector over
  a fixture diff, derives the risk floor from what it found, and asserts the
  policy gate refuses the pull — so the block is correctly attributed to the
  `policy` gate.
- **Scenario 11 (VEX)** is the negative control: the *same* critical CVE as
  scenario 10, but with an OpenVEX `not_affected` statement for the exact
  component, which must suppress the finding so the pull is **admitted**. This
  proves VEX suppression works and guards against it silently ceasing to apply
  (which would block a safe artifact).

## Running it

On demand, fully offline (no running proxy, URL, or token required):

```console
# Human-readable coverage matrix (default):
ptctl redteam

# Machine-readable matrix:
ptctl redteam --format json

# Write to a file (e.g. for a CI summary / PR comment):
ptctl redteam --format markdown --output redteam-report.md

# Exit code only (CI gate):
ptctl redteam --quiet
```

`ptctl redteam` exits non-zero if any scenario fails.

As a Go test (the authoritative regression gate):

```console
make redteam
# or
go test ./internal/redteam/...
```

## CI integration

The `redteam` job in `.github/workflows/ci.yml` runs the suite under the race
detector on every PR and push, renders the coverage matrix into the job summary,
and uploads it as the `redteam-report` artifact. The image-build job depends on
it, so an artifact image is never published while a defense has regressed from
block to admit.

## Extending the catalog

Each scenario is a self-contained `Scenario` in `internal/redteam/catalog.go`
with a `setup` that builds an in-process gateway (via `gatewayBuilder`), wires
exactly the gate(s) under test through `proxy.Dependencies`, and returns the
request to issue. To add a new attack:

1. Add a `scenarioXxx()` constructor returning a `Scenario` (give it a unique,
   sortable `ID` and a `Category`).
2. Register it in `Scenarios()`.
3. If it exercises a gate with a new decision header, add that header to
   `blockHeaders` in `redteam.go` so the fired-gate attribution recognizes it.
4. Add the category to the `required` list in `TestCategoryCoverage` if it is a
   class the suite must always cover.

The stubs in `internal/redteam/stubs.go` (vuln scanner, signature/provenance
sources, rebuild builder, timestamp resolver) are the smallest deterministic
implementations that drive a content gate to a specific verdict without any I/O;
reuse or extend them rather than reaching for live infrastructure.
