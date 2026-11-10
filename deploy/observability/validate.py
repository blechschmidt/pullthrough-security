#!/usr/bin/env python3
"""Validate the observability bundle against the code.

Guards against the most common drift: a dashboard panel or alert referencing a
metric name that no longer exists (or never did). Also sanity-checks that the
dashboard JSON parses and the alert rules YAML is well-formed.

Exits non-zero on any problem. Run via `make observability-validate` (also run
automatically by `make observability-gen`). Requires PyYAML.
"""
import glob
import json
import os
import re
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def defined_metrics():
    """Metric base names that the proxy registers, parsed from the two files
    that own every metric definition. Histogram bases also expose
    _bucket/_sum/_count series."""
    src = ""
    for rel in ("cmd/pullthrough/observability.go", "internal/metrics/collector.go"):
        src += open(os.path.join(ROOT, rel)).read()
    names = set(re.findall(r'"(pullthrough_[a-z0-9_]+)"', src))
    valid = set(names)
    for base in (m for m in names if "duration_seconds" in m):
        valid |= {base + "_bucket", base + "_sum", base + "_count"}
    return names, valid


def referenced_metrics(here):
    refs = set()
    texts = [open(os.path.join(here, "prometheus", "alerts.yaml")).read()]
    for f in glob.glob(os.path.join(here, "grafana", "dashboards", "*.json")):
        d = json.load(open(f))  # also validates JSON
        for p in d["panels"]:
            for t in p.get("targets", []):
                texts.append(t.get("expr", ""))
    for t in texts:
        refs |= set(re.findall(r"\bpullthrough_[a-z0-9_]+", t))
    return refs


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    errors = []

    # Alert rules must be well-formed and non-empty.
    rules = yaml.safe_load(open(os.path.join(here, "prometheus", "alerts.yaml")))
    n_alerts = sum(len(g.get("rules", [])) for g in rules.get("groups", []))
    if n_alerts == 0:
        errors.append("alerts.yaml defines no alerts")

    names, valid = defined_metrics()
    refs = referenced_metrics(here)
    missing = sorted(r for r in refs if r not in valid)
    for m in missing:
        errors.append("referenced metric not defined in code: " + m)

    if errors:
        print("observability bundle validation FAILED:")
        for e in errors:
            print("  -", e)
        return 1
    print(
        "observability bundle OK: %d alerts, %d metrics referenced, all defined "
        "(of %d code-defined)" % (n_alerts, len(refs), len(names))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
