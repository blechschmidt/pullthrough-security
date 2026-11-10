# Observability bundle

Turnkey Grafana dashboards and Prometheus alerting rules for the pull-through
security proxy. Everything here is the **single source of truth**; the Helm chart
and kustomize overlays consume copies of it (regenerate with `make
observability-gen`).

```
deploy/observability/
├── prometheus/
│   ├── alerts.yaml          # canonical alerting rules (28 alerts, 6 groups)
│   └── prometheus.yml       # scrape config for the compose monitoring stack
├── grafana/
│   ├── dashboards/*.json    # 4 versioned dashboards (importable + provisionable)
│   ├── provisioning/        # datasource + dashboard providers for compose
│   └── gen_dashboards.py    # dashboard generator (source of the JSON)
├── prometheusrule.yaml      # alerts.yaml wrapped as a PrometheusRule (kustomize path)
├── kustomization.yaml       # `kubectl apply -k` → PrometheusRule + dashboard ConfigMaps
└── gen_prometheusrule.py    # regenerates prometheusrule.yaml from alerts.yaml
```

## Dashboards

| File | Dashboard | Covers |
| --- | --- | --- |
| `cache-performance.json` | Cache Performance | hit/miss ratio, throughput, fills, eviction/expiry, backend (incl. **S3**) errors |
| `supply-chain-security.json` | Supply-chain Security | **compliance scorecard** (score/SLSA/per-control trend), vuln gate, CVE-drift re-scan/quarantine, signature/attestation verification, name guard |
| `upstream-latency-errors.json` | Upstream Latency & Errors | request rate, status codes, upstream latency p50/p95/p99 & error ratios, policy decisions |
| `per-tenant-traffic.json` | Per-tenant Traffic & Limits | rate-limit allow/throttle, per-tenant concurrency & byte quota, traffic mix, notifications |

All four use a `datasource` template variable (any Prometheus datasource) and a
`job` filter, so they import unchanged into an existing Grafana.

## Use it

### Local (Docker Compose)

```bash
docker compose --profile monitoring up --build   # or: make compose-up-monitoring
```

- Grafana → http://localhost:3000 (admin/admin), dashboards pre-loaded under the **Pull-through** folder.
- Prometheus → http://localhost:9090, alerting rules pre-loaded (Status → Rules).

### Kubernetes — Helm (recommended)

Requires the Prometheus Operator (for `ServiceMonitor`/`PrometheusRule`) and the
Grafana dashboard sidecar (both ship with `kube-prometheus-stack`).

```yaml
# values.yaml
serviceMonitor:
  enabled: true
  labels: { release: kube-prometheus-stack }   # so Prometheus scrapes us
prometheusRule:
  enabled: true
  labels: { release: kube-prometheus-stack }   # so the operator loads the rules
  # additionalLabels: { team: platform }       # stamped onto every alert (routing)
grafanaDashboards:
  enabled: true                                 # ConfigMaps the Grafana sidecar imports
```

### Kubernetes — plain manifests / kustomize

```bash
kubectl apply -k deploy/observability
```

Ships the `PrometheusRule` and one `grafana_dashboard`-labelled ConfigMap per
dashboard. Edit `kustomization.yaml` to set the namespace and the label your
Prometheus's `ruleSelector` matches.

### Manual Grafana import

Dashboards → Import → upload any `grafana/dashboards/*.json`, then pick your
Prometheus datasource.

## Editing

Edit the canonical sources, then regenerate the consumed copies:

```bash
# rules:      deploy/observability/prometheus/alerts.yaml
# dashboards: deploy/observability/grafana/gen_dashboards.py
make observability-gen
```

This rewrites the dashboard JSON, `prometheusrule.yaml`, and the Helm-vendored
copies under `deploy/helm/pullthrough/{files,dashboards}/`. See
[docs/observability.md](../../docs/observability.md) for the full metric
reference and alert catalog.
