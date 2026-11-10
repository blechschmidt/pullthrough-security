# `coverage/` — statement-coverage baseline & gate

This directory holds the **committed coverage baseline** the coverage-regression
gate compares against (Task 117). It is the coverage analogue of
[`perf/`](../perf/README.md) and its `perf-baseline.json`.

| Path | What it is |
|------|------------|
| `coverage-baseline.json` | committed per-package + total statement coverage, and critical-package floors |
| `coverage-report.json` | generated machine-readable comparison report (gitignored) |
| `coverage-summary.md` | generated Markdown summary for CI decoration (gitignored) |

Only `coverage-baseline.json` is committed; the report/summary are build
artifacts.

## Usage

```sh
make covguard              # compare the current suite against the baseline (CI gate)
make covguard-baseline     # re-seed the baseline from the current suite
ptctl covguard -h          # all flags (thresholds, critical floors, JSON/MD output)
```

The gate fails when **total** coverage drops beyond the allowed threshold
(default 1.0 percentage point) or a **critical package** falls under its floor.

See [`docs/coverage.md`](../docs/coverage.md) for the full reference: how
coverage is measured, how to set critical floors, the report format, and a CI
workflow snippet.
