# Mutation testing & the test-quality gate

Statement coverage (see [coverage.md](coverage.md)) tells you whether a line of
code *ran* during the tests. It does **not** tell you whether a test would
actually **fail** if that line were wrong — a suite can execute a security check
at 100% coverage and still assert nothing meaningful about it.

**Mutation testing** closes that gap. It deliberately introduces small,
behavior-changing faults ("mutants") into the source — flipping a `<` to `<=`,
an `&&` to `||`, a `true` to `false`, negating an `if` condition — then
recompiles and reruns the tests:

- If a test **fails**, the mutant is **killed** — the suite detected the fault. Good.
- If the tests still **pass**, the mutant **survives** — a real gap in
  fault-detection. This is what you fix (usually by adding an assertion).

The **mutation score** is `killed / (killed + survived)`. It is a direct,
adversarial measure of how much the tests actually protect the logic.

This matters most for the **admission gates** — the code that decides whether a
package is allowed through. A survived mutant there means *"we could invert this
security decision and no test would notice"*. The gate therefore targets the
highest-risk packages:

```
internal/vulnscan      internal/sigverify     internal/policyengine
internal/riskscore     internal/depfirewall   internal/installhooks
internal/contentscan   internal/license
```

The harness (`internal/muttest`, driven by `ptctl mutguard`) is built entirely
on the Go standard library (`go/ast`, `go/parser`, the `go` toolchain) — there
is **no third-party mutation tool to install**, and the run is **seeded and
deterministic** so CI is stable.

---

## Running it locally

```sh
make mutation              # compare the current suite against the committed baseline
make mutation-baseline     # re-seed the baseline from the current suite
```

Or drive `ptctl mutguard` directly for finer control:

```sh
# Full run of a single package (no sampling) — the fastest way to triage.
ptctl mutguard --packages internal/sigverify --max-per-package 0

# A different operator subset, tighter tolerance, writing CI artifacts.
ptctl mutguard --operators ROR,LCR,COND --allowed-drop 1.0 \
  --json-out mutation/mutation-report.json --md-out mutation/mutation-summary.md
```

Run `ptctl mutguard -h` for every flag. The most important ones:

| Flag | Meaning |
|------|---------|
| `--packages` | comma-separated module-relative packages to mutate (default: the 8 gate packages) |
| `--operators` | which mutation operators to apply (default: all — see the catalog below) |
| `--max-per-package` | cap mutants per package; a **seeded sample** is taken when exceeded (default 60; `0` = exhaustive) |
| `--seed` | the sampling seed (default 1) — the same seed reproduces the same mutant set |
| `--allowed-drop` | max percentage-point drop in the **total** score before the gate fails (default 2.0) |
| `--allowed-package-drop` | optional per-package drop gate (0 = off) |
| `--critical` | `pkg[=floor]` list of critical packages with a hard minimum score |
| `--ignore-file` | list of mutant IDs accepted as equivalent (default `mutation/equivalent-mutants.txt`) |
| `--short` | pass `-test.short` to each mutant run (default on; faster) |
| `--test-timeout` | per-mutant timeout; a timeout counts as **killed** (an infinite-loop mutant was caught) |

### Why it is deterministic

A given `(seed, --max-per-package, --operators)` always enumerates the same
mutants in the same stable order (sorted by file, byte offset, operator) and
samples the same subset (a per-package seeded shuffle). The committed baseline
records the seed and cap it was produced with, so re-running the gate with the
same knobs compares like-for-like. Keep `--seed` and `--max-per-package` fixed
in CI (the `make mutation` target does).

---

## The operator catalog

| Key | Mutation | Models |
|-----|----------|--------|
| `ROR` | relational/equality swap (`==`↔`!=`, `<`→`<=`/`>=`, …) | off-by-one & inverted threshold checks (severity, cooldown, size) |
| `LCR` | logical connective swap (`&&`↔`\|\|`) | a gate that ANDs what it should OR (or vice versa) |
| `AOR` | arithmetic swap (`+`↔`-`, `*`↔`/`, `%`→`*`) | miscomputed scores, counts, sizes |
| `BOOL` | boolean constant swap (`true`↔`false`) | an allow/deny default or a "scanned/verified" flag stuck wrong |
| `COND` | negate an `if` condition (`cond`→`!(cond)`) | a guard that admits exactly what it should block |
| `NEG` | drop a unary `!` (`!x`→`x`) | a dropped "not" in a predicate |
| `INCDEC` | `++`↔`--` | wrong-direction counters |

Mutants that do not type-check (e.g. `+` on strings mutated to `-`) are
classified **invalid** and excluded from the score — they are not free kills.

---

## Triaging surviving mutants

A failing or low-scoring run prints a **Surviving mutants** section (and the
same data lands in `mutation/mutation-report.json`):

```
Surviving mutants (triage these — add equivalents to the ignore list):
  · internal/sigverify/verify.go:214:9 [ROR] >= -> >  (id 4f2a9c1d8e0b)
```

For each survivor, decide which of three cases applies:

1. **A genuine gap (most common).** The mutation changes real behavior and no
   test caught it. **Add or strengthen a test** so the mutated behavior fails an
   assertion, then re-run. This is the whole point — the score goes up because
   the suite got stronger.

2. **An equivalent mutant.** The mutation cannot change observable behavior, so
   *no* test could ever kill it (e.g. a boundary on a value that is provably
   never at the boundary, or a redundant guard). Record its ID in
   [`mutation/equivalent-mutants.txt`](../mutation/equivalent-mutants.txt) with a
   one-line justification. It is then removed from the denominator.

3. **An accepted survivor.** A deliberately untested defensive/deprecated path
   the team has reviewed and chosen not to cover. Same mechanism as (2): add the
   ID to the ignore file with a justification. Keep these rare.

Get a mutant's ID from the report (`id <...>`) — it is a stable hash of the
package, file, line/column, operator and specific change. Because it is
line-anchored it shifts when the surrounding code moves, so re-triage the
ignore list after large refactors.

To iterate quickly on one package exhaustively:

```sh
ptctl mutguard --packages internal/depfirewall --max-per-package 0 --json-out /tmp/dep.json
```

---

## Updating the baseline

The committed baseline at
[`mutation/mutation-baseline.json`](../mutation/mutation-baseline.json) is the
reference the gate compares against. Refresh it when an **intentional**
test-quality change lands (you added tests and the score went up, or you added a
package to the target set):

```sh
make mutation-baseline     # re-seeds using the committed seed/cap and PRESERVES critical floors
git add mutation/mutation-baseline.json
git commit -m "chore: refresh mutation baseline"
```

`make mutation-baseline` (and `ptctl mutguard --update-baseline`) carry the
existing critical floors forward; pass `--critical` only to change them. To set
floors explicitly:

```sh
ptctl mutguard --update-baseline \
  --critical internal/sigverify=80,internal/vulnscan=75,internal/policyengine=70
```

The baseline stores per-package and total scores, the run parameters (seed, cap,
operators) and the critical floors. Derived percentages are recomputed on load,
so a hand-edited count can never desync from its percentage.

**Floor key format.** Both the per-package scores and the critical floors are
keyed by a package's **full import path** (e.g.
`github.com/blechschmidt/pullthrough-security/internal/sigverify`), so the gate
can match a floor to its package. You still pass `--critical` using the
convenient **module-relative** form (`internal/sigverify=80`) — `ptctl mutguard`
normalizes it to the full import path before storing it. If you hand-edit the
baseline, use the full path; the committed-baseline guard test
(`TestCommittedBaselineDecodes`) fails the build if a floor references a package
that is not in the baseline, so a mistyped or module-relative key cannot silently
disable a floor. Whenever you add or drop a gate package from `--packages`,
re-seed the baseline and re-state the floors for the new package set.

**Never lower a score in the baseline to make a red gate pass.** A drop means the
suite got weaker (or a package regressed); fix the tests. The only legitimate
reasons to commit a *lower* number are an intentional, reviewed code change that
removed logic, or a newly-triaged equivalent mutant (which should *raise* the
score, not lower it).

---

## CI gate

`make mutation` runs the harness, writes `mutation/mutation-report.json` and a
Markdown summary, and exits non-zero on a regression — mirroring the
coverage-regression gate. Because a full seeded run over all eight packages takes
several minutes, it runs as its own job rather than inline with the fast unit
suite:

```yaml
mutation:
  name: Mutation / test-quality gate
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with:
        go-version: ${{ env.GO_VERSION }}
        cache: true
    - name: Mutation-score regression gate
      run: make mutation
    - name: Publish summary
      if: always()
      run: cat mutation/mutation-summary.md >> "$GITHUB_STEP_SUMMARY"
    - name: Upload mutation report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: mutation-report
        path: |
          mutation/mutation-report.json
          mutation/mutation-summary.md
        if-no-files-found: ignore
```

To bound CI time, narrow the package set or lower the cap via the Makefile
variables, e.g. `make mutation MUT_PACKAGES=internal/sigverify,internal/vulnscan
MUT_MAX_PER_PACKAGE=40`.

---

## How it works (implementation notes)

- `internal/muttest/mutate.go` parses each non-test `.go` file and enumerates
  mutants as **byte-range splices** at exact AST token positions — so an applied
  mutant touches only the mutated token(s) and never reformats the file.
- `internal/muttest/engine.go` mutates one file in place, rebuilds the package's
  test binary with `go test -c`, runs it with its working directory set to the
  package dir (so `testdata` relative paths behave exactly as under `go test`),
  classifies the outcome, and **restores the file** — always, including on
  SIGINT/SIGTERM, so an interrupted run never leaves mutated source behind.
- A **green baseline is required**: if a package's unmutated tests do not build
  or do not pass, the run aborts with an error (you cannot mutation-test a red
  suite).
- `internal/muttest/score.go` provides the committed baseline, the comparison
  policy (total/per-package drop, critical floors) and the text/Markdown/JSON
  reports — the same shape as the coverage gate (`internal/covguard`).
