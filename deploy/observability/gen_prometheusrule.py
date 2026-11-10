#!/usr/bin/env python3
"""Wrap the canonical alerting rules into a kustomize-ready PrometheusRule.

Reads prometheus/alerts.yaml (the single source of truth, also loaded directly
by vanilla Prometheus and vendored into the Helm chart) and writes
prometheusrule.yaml for the `kubectl apply -k deploy/observability` path. Run via
`make observability-gen`.
"""
import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = (
    "# PrometheusRule for the kustomize/plain-manifest deploy path. Generated from\n"
    "# deploy/observability/prometheus/alerts.yaml by `make observability-gen` —\n"
    "# edit the source rules there, not this file. Requires the Prometheus Operator\n"
    "# CRDs. Set the label your Prometheus's ruleSelector matches (often\n"
    "# `release: kube-prometheus-stack`).\n"
)


def main():
    groups = yaml.safe_load(open(os.path.join(HERE, "prometheus", "alerts.yaml")))
    doc = {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": "pullthrough",
            "namespace": "pullthrough",
            "labels": {
                "app.kubernetes.io/name": "pullthrough",
                "app.kubernetes.io/part-of": "pullthrough",
            },
        },
        "spec": groups,
    }
    out = os.path.join(HERE, "prometheusrule.yaml")
    with open(out, "w") as f:
        f.write(HEADER)
        yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False, width=1000)
    print("wrote", out)


if __name__ == "__main__":
    main()
