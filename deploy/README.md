# Deployment

Containerization and deployment assets for the pull-through security proxy.

| Path | Purpose |
| --- | --- |
| `../Dockerfile` | Multi-stage build → minimal Alpine runtime (non-root, healthcheck). |
| `../docker-compose.yml` | Local dev stack: proxy + persistent cache volume, optional Postgres/MinIO. |
| `docker/` | Compose config (`config.docker.yaml`) and `.env.example`. |
| `helm/pullthrough/` | Helm chart (primary k8s deploy path). |
| `k8s/` | Plain manifests / kustomize base (Helm-free path). |
| `k8s/webhook/` | Opt-in overlay: Kubernetes admission webhook for in-cluster enforcement ([docs](../docs/admission-webhook.md)). |
| `observability/` | Grafana dashboards + Prometheus alerting rules ([README](observability/README.md)). |
| `../.github/workflows/ci.yml` | CI: test, lint, build & publish multi-arch images. |

The proxy is configured by a single YAML file (schema: `configs/config.example.yaml`).
Secret-bearing fields use `${VAR}` placeholders resolved from the environment, plus
`PTS_*` env overrides — so secrets stay out of the ConfigMap/image and live in a
Kubernetes Secret or your `.env`.

State (content-addressable cache, audit log, provenance/scan stores) lives under
`/var/lib/pullthrough`; mount a persistent volume there.

## Local development (Docker Compose)

```bash
cp deploy/docker/.env.example deploy/docker/.env   # fill in secrets as needed
make compose-up                                    # proxy on http://localhost:8080
# or with backing services:
make compose-up-extras                             # + Postgres:5432, MinIO:9000/9001
```

Smoke test:

```bash
curl -s localhost:8080/readyz
curl -s localhost:8080/v1/npm/lodash | head
```

## Build & publish the image

```bash
make docker-build                 # builds ghcr.io/.../pullthrough-security:<version>
make docker-push IMAGE_TAG=0.1.0
```

CI publishes multi-arch (`amd64`+`arm64`) images to GHCR on pushes to `main`
(`:latest`, `:sha-...`) and on `v*` tags (`:<semver>`), with build-provenance and
SBOM attestations.

## Verify the binary and image before you deploy

Tagged releases (`v*`) ship reproducibly-built binaries with a cosign-keyless
signed checksums manifest, SLSA provenance, and SBOMs (standard **and** FIPS
variants), plus a cosign-signed container image. Verify before rollout — e.g.
as a Kubernetes init container or post-install hook:

```bash
ptctl verify-self                 # verifies the binary next to its release artifacts
ptctl verify-self --require-cosign   # also require Fulcio/Rekor transparency (needs cosign)
```

Full step-by-step verification (binaries, image, provenance, SBOM) and how to
wire it into deployment: **[../docs/self-release.md](../docs/self-release.md)**.

## Kubernetes — Helm (recommended)

```bash
helm upgrade --install pullthrough deploy/helm/pullthrough \
  --namespace pullthrough --create-namespace \
  --set image.tag=0.1.0 \
  --set ingress.hosts[0].host=proxy.your-corp.com \
  --set-string config.server.publicUrl=https://proxy.your-corp.com \
  --set ingress.certManager.clusterIssuer=letsencrypt-prod
```

Provide secrets either by letting the chart create them:

```bash
helm upgrade --install pullthrough deploy/helm/pullthrough -n pullthrough \
  --set secrets.data.PTS_AUDIT_HMAC_KEY="$(openssl rand -hex 32)" \
  --set secrets.data.GITHUB_TOKEN="ghp_..."
```

…or, preferred for production, reference an externally-managed Secret (e.g. from
External Secrets Operator / Vault) and leave `secrets.data` empty:

```bash
--set secrets.existingSecret=pullthrough-secrets
```

Key chart values (`helm/pullthrough/values.yaml`): `replicaCount`, `autoscaling.*`,
`persistence.*` (size/storageClass/existingClaim), `ingress.*` (hosts/TLS/cert-manager),
`resources`, `serviceMonitor.enabled`, `ssh.enabled`, and the entire app config under
`config.*`.

Rollback is one command (Helm keeps release history):

```bash
helm rollback pullthrough -n pullthrough
```

`helm test pullthrough -n pullthrough` runs a readiness probe against the Service.

## Kubernetes — plain manifests (kustomize)

```bash
kubectl apply -k deploy/k8s
# create real secrets out-of-band (do NOT use secret.example.yaml in prod):
kubectl create secret generic pullthrough-secrets -n pullthrough \
  --from-literal=PTS_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
```

Pin the image to an immutable tag in a kustomize overlay rather than `:latest`.

## Monitoring (Grafana + Prometheus)

The [`observability/`](observability/README.md) bundle ships four Grafana
dashboards and 24 Prometheus alerting rules. Deploy it alongside the proxy:

```bash
# Compose: Grafana :3000 + Prometheus :9090, dashboards & rules pre-loaded
docker compose --profile monitoring up --build        # make compose-up-monitoring

# Helm (Prometheus Operator + Grafana sidecar):
helm upgrade ... \
  --set serviceMonitor.enabled=true \
  --set prometheusRule.enabled=true \
  --set grafanaDashboards.enabled=true

# kustomize (Prometheus Operator + Grafana sidecar):
kubectl apply -k deploy/observability
```

The rules in `observability/prometheus/alerts.yaml` are the single source of
truth; the Helm chart and `prometheusrule.yaml` vendor copies kept in sync with
`make observability-gen`. Full reference: [docs/observability.md](../docs/observability.md).

## Operational notes

- **Probes**: liveness `/healthz`, readiness `/readyz`; metrics at `/metrics`
  (scrape via the `serviceMonitor`), admin UI at `/admin/`.
- **Rollout safety**: `maxUnavailable: 0`, a PodDisruptionBudget, and a
  config/secret checksum annotation that triggers a rolling restart on change.
- **Hardening**: non-root (uid 65532), read-only root FS, all caps dropped,
  `RuntimeDefault` seccomp, `automountServiceAccountToken: false`.
- **Cache volume & scaling**: the default `ReadWriteOnce` PVC cannot be shared
  across nodes. For multi-node horizontal scaling, use a `ReadWriteMany`
  StorageClass (`persistence.accessModes`), or accept node-pinned replicas. The
  cache is rebuildable, so losing it only causes upstream re-fetches.
- **Shared cache for HA (recommended for multi-replica)**: set
  `cache.backend: s3` so all replicas share one cache in an S3-compatible bucket
  (AWS S3 / MinIO / GCS) and become stateless w.r.t. the cache — then scale
  `replicaCount`/the HPA freely and drop the cache PVC. See
  [../docs/ha-shared-cache.md](../docs/ha-shared-cache.md);
  `k8s/shared-cache.example.yaml` has the manifest snippet and credentials Secret,
  and `helm/pullthrough/values.yaml` has the `config.cache.s3` example.
- **Git SSH gateway**: set `ssh.enabled=true` and `config.server.sshAddr=":2222"`
  to expose a dedicated SSH Service (it cannot share the HTTP ingress).
