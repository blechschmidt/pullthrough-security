# `mutation/` — mutation-score baseline & test-quality gate

This directory holds the **committed mutation-testing baseline** the test-quality
gate compares against (Task 157). It is the fault-detection analogue of
[`coverage/`](../coverage/README.md): where the coverage gate asks *"did a test
execute this line?"*, the mutation gate asks the sharper question *"would a test
actually **fail** if this line's behavior were wrong?"*.

The gate targets the highest-risk admission-gate packages — `vulnscan`,
`sigverify`, `policyengine`, `riskscore`, `depfirewall`, and the content gates
(`installhooks`, `contentscan`, `license`).

| Path | What it is |
|------|------------|
| `mutation-baseline.json` | committed per-package + total **mutation scores**, run parameters (seed, cap, operators) and critical-package floors |
| `equivalent-mutants.txt` | committed list of mutant IDs accepted as equivalent/benign (excluded from the score) |
| `mutation-report.json` | generated machine-readable comparison report (gitignored) |
| `mutation-summary.md` | generated Markdown summary for CI decoration (gitignored) |

Only `mutation-baseline.json` and `equivalent-mutants.txt` are committed; the
report/summary are build artifacts.

## Usage

```sh
make mutation              # compare the current suite against the baseline (CI gate)
make mutation-baseline     # re-seed the baseline from the current suite
ptctl mutguard -h          # all flags (packages, operators, thresholds, floors, seed)
```

The gate fails when the **total** mutation score drops beyond the allowed
threshold (default 2.0 percentage points) or a **critical package** falls under
its floor.

The run is **seeded** (`--seed`, default 1) and samples at most
`--max-per-package` mutants (default 60), so a given `(seed, cap, operators)`
always produces the same mutant set — the CI gate is deterministic.

See [`docs/mutation-testing.md`](../docs/mutation-testing.md) for the full
reference: how mutation testing works here, the operator catalog, how to triage
surviving mutants, how to mark equivalent mutants, and a CI workflow snippet.
