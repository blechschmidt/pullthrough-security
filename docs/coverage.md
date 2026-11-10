# Code coverage & the coverage-regression gate

This page is the operator/engineer reference for measuring the proxy's
statement coverage and for stopping coverage from silently rotting. It is the
coverage analogue of the [performance-regression guard](performance.md#performance-regression-guard--ptctl-perfguard)
(`ptctl perfguard`): a committed baseline plus a CI gate that fails a change
which drops coverage beyond a threshold or lets a security-critical package fall
under a floor.

- **Tool:** `ptctl covguard` (or `make covguard`)
- **Committed baseline:** [`coverage/coverage-baseline.json`](../coverage/coverage-baseline.json)
- **What it guards:** total (module-wide) statement coverage, plus per-package
  floors for critical packages.

## How coverage is measured

`ptctl covguard` runs `go test ./... -coverprofile=<file>` and parses the
resulting Go coverprofile directly. For each profiled block it sums the
statement count and marks it covered when the hit count is non-zero, then
aggregates:

- **per package** — keyed by full import path, and
- **total** — covered statements over total statements across every package.

Because the percentage is always `covered / total` statements, it is identical
to `go tool cover -func` and **independent of the cover mode** (`set`, `count`,
or `atomic`) — the mode only changes how hits are recorded, not the ratio. A
package with no executable statements counts as 100% (it cannot regress).

> Command packages (`cmd/pullthrough`, `cmd/ptctl`, generators) and the test
> rigs are included in the total, so the module number is lower than the
> library-only figure. This is deliberate — the baseline reflects the whole
> tree. Narrow the run with `--packages ./internal/...` if you want a
> library-only gate.

## Quick start

```sh
# Seed or refresh the committed baseline from the current suite.
ptctl covguard -update-baseline          # or: make covguard-baseline

# Compare the current suite against the baseline (the CI gate).
ptctl covguard                           # or: make covguard

# Render an interactive HTML report of what is / isn't covered.
make coverage-html
```

`ptctl covguard` runs the suite itself, so — unlike the other `ptctl`
subcommands — it does **not** talk to a running proxy and takes no `--url` /
`--token`. If a test fails, coverage is not measured and the guard errors
(a failing suite must never be reported as a coverage pass).

## The committed baseline

`coverage/coverage-baseline.json` is checked in and is the reference every
comparison runs against. It holds total and per-package tallies plus the
critical-package floors:

```jsonc
{
  "schemaVersion": 1,
  "capturedAt": "2026-11-04T06:50:36Z",
  "tool": "ptctl ...",
  "mode": "set",
  "total": { "coveredStatements": 31153, "totalStatements": 50105, "coveragePct": 62.2 },
  "packages": {
    "github.com/blechschmidt/pullthrough-security/internal/sigverify": {
      "coveredStatements": 512, "totalStatements": 715, "coveragePct": 71.6
    }
    // … one entry per package
  },
  "criticalFloors": {
    "github.com/blechschmidt/pullthrough-security/internal/sigverify": 65
    // … hard minimums for security-critical packages
  }
}
```

Regenerate it whenever an **intentional** coverage change lands (new tests, a
refactor that moves statements), review the committed diff, and commit it like
any other baseline. Never widen a threshold or lower a floor just to turn CI
green — re-baseline deliberately instead.

### Critical-package floors

`criticalFloors` maps a package to a hard minimum coverage percentage,
**independent of the baseline**: a critical package may not fall below its floor
even if the overall baseline is low, and a critical package that disappears from
the run (its tests stopped running, or it was removed) is also a violation. Seed
them when updating the baseline:

```sh
ptctl covguard -update-baseline \
  -critical internal/cache=68,internal/sigverify=65,internal/vulnscan=72
```

The floors are persisted in the baseline, so later `ptctl covguard` runs enforce
them without re-specifying them. A `-critical` flag on a compare run overrides
the committed floors for that invocation.

## Checking for regressions

```sh
# Default: total may drop at most 1.0 percentage point; critical floors enforced.
ptctl covguard

# Tighter total budget, and write CI-decoration artifacts.
ptctl covguard -allowed-drop 0.5 \
               -json-out coverage/coverage-report.json \
               -md-out  "$GITHUB_STEP_SUMMARY"

# Also fail any single package that drops more than 3 points.
ptctl covguard -allowed-package-drop 3

# Skip re-running tests and reuse an existing profile (e.g. from the CI test step).
go test ./... -coverprofile=cover.out -covermode=set
ptctl covguard -coverprofile cover.out
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-baseline` | `coverage/coverage-baseline.json` | stored baseline file |
| `-update-baseline` | false | record a new baseline instead of comparing |
| `-coverprofile` | — | use an existing profile instead of running `go test` |
| `-keep-profile` | false | keep the generated profile at `coverage.out` (for `go tool cover -html`) |
| `-packages` | `./...` | package pattern passed to `go test` |
| `-covermode` | `set` | cover mode (does not affect the percentage) |
| `-test-args` | — | extra args appended to `go test` (e.g. `-count=1 -tags=integration`) |
| `-allowed-drop` | `1.0` | max percentage-point drop in **total** coverage before failing |
| `-allowed-package-drop` | `0` | max per-package drop before failing (0 = off; drops still reported) |
| `-critical` | baseline's floors | `pkg[=floorPct]` list; overrides the committed floors |
| `-critical-floor` | `0` | default floor for `-critical` entries given without `=floor` |
| `-top` | `15` | cap the biggest-drops list and the per-package table |
| `-json` | false | emit the report (or new baseline) as JSON to stdout |
| `-json-out` | — | also write the JSON report to a file (CI artifact) |
| `-md-out` | — | also write a Markdown summary to a file (PR / step-summary decoration) |
| `-timeout` | `20m` | overall timeout for the `go test` run |

The gate **exits non-zero** when total coverage drops beyond `-allowed-drop`, a
critical package falls under its floor, or (with `-allowed-package-drop`) any
package drops too far. A drop of *exactly* the allowance is tolerated.

Sample failing report:

```
Coverage regression report
  baseline:   captured 2026-11-04T06:50:36Z by ptctl ...
  tolerance:  total may drop at most 1 pt

  ✗ total coverage  70.0% -> 62.2%  (-7.82 pts, limit -1 pt)  <-- regression

  Critical-package floor violations:
    ✗ .../internal/sigverify  61.0% < floor 65%

  Biggest coverage drops:
    ✗ .../internal/sigverify  71.6% -> 61.0%  (-10.60 pts)  <-- regression

RESULT: FAIL — 2 coverage gate(s) failed
```

## CI workflow snippet

A GitHub Actions job that runs the suite once with coverage and gates on it,
decorating the run's step summary:

```yaml
# .github/workflows/coverage-guard.yml
name: coverage-regression-guard
on: [pull_request]

jobs:
  covguard:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }

      - name: Build ptctl
        run: go build -o bin/ptctl ./cmd/ptctl

      # Run the suite once with coverage, then gate on the profile so the tests
      # are not run twice.
      - name: Test with coverage
        run: go test ./... -coverprofile=cover.out -covermode=set

      - name: Coverage regression gate
        run: |
          ./bin/ptctl covguard \
            -coverprofile cover.out \
            -allowed-drop 1.0 \
            -json-out coverage/coverage-report.json \
            -md-out  "$GITHUB_STEP_SUMMARY"

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: coverage-report
          path: coverage/coverage-report.json
```

To refresh the baseline after an accepted change, run
`ptctl covguard -update-baseline` (optionally with `-critical …`) and commit the
updated `coverage/coverage-baseline.json`.

## Machine-readable output

`-json` / `-json-out` emit the full comparison — total, policy, and every
package delta sorted biggest-drop first — for CI decoration or dashboards.
`-md-out` writes a GitHub-flavored Markdown summary (result badge, total line,
floor-violation and biggest-drops tables) suitable for a PR comment or
`$GITHUB_STEP_SUMMARY`.
