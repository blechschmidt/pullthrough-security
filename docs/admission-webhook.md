# Kubernetes admission webhook (in-cluster enforcement)

The proxy enforces supply-chain policy on the **pull path**: when a client pulls
an artifact, the admission gates (vulnerabilities, signatures, provenance,
license, risk score, lockdown, …) decide whether to serve it. The
**ValidatingAdmissionWebhook** extends that same enforcement to the **cluster
runtime**: when a Pod is created or updated, the webhook resolves the proxy's
verdict for each container image and admits or rejects the Pod accordingly.

Crucially, the webhook does not invent a second policy. It consumes the
**per-coordinate security dossier** (the "360 view", Task 87) whose headline
verdict (`block` / `warn` / `admit` / `unknown`) already folds in the risk score
(Task 37) and every gate's finding. A policy change at the pull boundary — a new
block threshold, a freshly-ingested CVE, a targeted lockdown — propagates to the
cluster boundary with no extra rule set.

> The webhook is **off by default**. Enable it with `admissionWebhook.enabled`.

---

## How a verdict becomes an admission decision

For every container image in a Pod (regular, init, and ephemeral containers):

1. **Image allowlist** — if the image matches an `ignoreImages` prefix (cluster
   infrastructure the proxy never fronts, e.g. `registry.k8s.io/`), it is
   admitted without inspection.
2. **Lockdown kill-switch** (Task 74) — if a targeted emergency-lockdown block
   (`ModeBlock`) matches the image coordinate, the Pod is **denied**
   cluster-wide, ahead of any recorded dossier verdict.
3. **Verdict lookup** — the image reference is parsed into a coordinate
   (`repository` + `tag`/`digest`) and the dossier verdict is resolved (in-process
   or over HTTP, see *Topologies*).
4. **Risk ceiling** — if `minRiskScoreToDeny > 0` and the dossier risk score is at
   or above it, the Pod is denied regardless of the headline verdict.
5. **Verdict mapping**:

   | Dossier verdict | Meaning | Default action | Config key |
   |---|---|---|---|
   | `block` | A blocking gate fired (critical CVE, quarantine, sig failure, …) | **deny** | `blockAction` |
   | `warn` | Non-blocking concerns (license review, drift, …) | admit + warning | `warnAction` |
   | `admit` | Clean across all wired gates | admit | — |
   | `unknown` | **No recorded signal** — the image was never pulled through the proxy | admit (fail-open) | `unknownAction` |

A Pod is denied if **any** of its images is denied; the rejection message lists
every offending image and the dossier summary behind it.

### `unknown` and the "never pulled through the proxy" case

The dossier is a **read-only projection** over verdicts the pull path already
recorded. An image that was never pulled through the proxy has no dossier signal
and resolves to `unknown`. The default `unknownAction: admit` is permissive (it
will not block images the proxy has not seen); set `unknownAction: deny` to
require that every image be vetted through the proxy first.

---

## Fail-open vs. fail-closed

There are **two** independent failure controls — set them consistently:

- **`admissionWebhook.failurePolicy`** (server-side): what the webhook does when
  it *cannot compute a verdict* (the verdict source errors or times out).
  `open` admits (with a warning); `closed` denies.
- **`ValidatingWebhookConfiguration.webhooks[].failurePolicy`** (API-server
  side): what Kubernetes does when it *cannot reach the webhook at all*
  (timeout, no endpoints). `Ignore` admits; `Fail` denies.

Recommended rollout: start **both open/Ignore** (observe and warn), confirm the
`pullthrough_admission_*` metrics look right, then tighten to **closed/Fail**.

During an **active emergency lockdown** (any mode), the webhook automatically
flips to fail-closed for un-vetted images: an `unknown` image, or one whose
verdict cannot be resolved, is **denied** regardless of `unknownAction` /
`failurePolicy`. The cluster boundary hardens the instant an incident is
declared — see [lockdown.md](lockdown.md).

---

## Integration with the admission gate and kill-switch subsystems

- **Admission gate / risk engine** (Tasks 9, 32, 37) — the webhook reads the
  *same* synthesized verdict the pull-path admission pipeline produces, via the
  dossier (Task 87). It never re-evaluates gates itself; it reflects their result.
  Because the verdict includes the explainable risk score, `minRiskScoreToDeny`
  lets the cluster apply its own ceiling independent of the pull-path threshold.
- **Emergency lockdown / kill-switch** (Task 74) — wired through
  `enforceLockdown` (default on):
  - a **targeted block** on `(ecosystem, name[, version])` denies matching Pod
    images cluster-wide, exactly as `gateLockdown` denies them on the pull path;
  - while **any** lockdown posture (freeze/strict/block) is engaged, `unknown`
    and unresolvable images are denied.
  For a standalone webhook to see the proxy's lockdown state, point
  `lockdown.storePath` at the **same shared store** the proxy uses.

---

## Topologies

### A. In-process (simplest)

Run the webhook inside the proxy pods. The verdict source is the in-process
dossier builder — no network hop, no token, always consistent with live state.
Just enable it in the normal server config:

```yaml
admissionWebhook:
  enabled: true
  addr: ":8443"
  tlsCertFile: /etc/pullthrough/webhook-tls/tls.crt
  tlsKeyFile: /etc/pullthrough/webhook-tls/tls.key
```

Add the `8443` container port, mount the serving-cert Secret, and expose a
Service pointing at the proxy pods. (The webhook starts automatically as an
additional listener alongside the gateway.)

### B. Standalone workload (recommended for scale/isolation)

Run the webhook as its own Deployment, reading verdicts from the proxy's admin
dossier API over HTTP. This is what the shipped manifests use. Start it with the
`webhook` subcommand:

```
pullthrough webhook -config /etc/pullthrough/webhook.yaml
```

```yaml
admissionWebhook:
  enabled: true
  addr: ":8443"
  tlsCertFile: /etc/pullthrough/tls/tls.crt
  tlsKeyFile: /etc/pullthrough/tls/tls.key
  failurePolicy: open
  dossier:
    url: http://pullthrough.pullthrough.svc:8080/admin
    token: ${PTS_ADMIN_TOKEN}      # needs at least the read capability
    # caCertFile: /etc/pullthrough/dossier-ca/ca.crt   # for https
```

The admin token reuses the existing admin bearer-token / RBAC machinery
(Task 10/51); the dossier endpoint requires the **read** capability.

---

## Deploying

### Plain manifests (kustomize overlay)

```
kubectl apply -k deploy/k8s            # base proxy
kubectl apply -k deploy/k8s/webhook    # admission webhook (standalone topology)
```

The overlay (`deploy/k8s/webhook/`) contains the `ConfigMap`, `Deployment`,
`Service`, `ServiceAccount` (+ optional controller RBAC), the serving-cert
`Secret` example, and the cluster-scoped `ValidatingWebhookConfiguration`.

### Helm

```
helm upgrade --install pullthrough deploy/helm/pullthrough \
  --set webhook.enabled=true \
  --set webhook.certManager.enabled=true \
  --set webhook.certManager.issuerRef.name=my-ca-issuer
```

Key `values.yaml` knobs live under `webhook:` — `failurePolicy`,
`serverFailurePolicy`, `blockAction` / `warnAction` / `unknownAction`,
`minRiskScoreToDeny`, `enforceLockdown`, `ignoreNamespaces`, `ignoreImages`, and
the `dossier.url`.

---

## TLS bootstrap

The Kubernetes API server calls webhooks **only over HTTPS** and verifies the
serving certificate against the `caBundle` wired into the
`ValidatingWebhookConfiguration`. The serving cert **must** carry the Service DNS
name as a SAN: `pullthrough-webhook.pullthrough.svc`.

**Option 1 — cert-manager (recommended).** Set `webhook.certManager.enabled=true`
(Helm) or add a `Certificate` + the `cert-manager.io/inject-ca-from` annotation
(manifests). cert-manager issues the serving Secret and injects the CA bundle
automatically.

**Option 2 — manual.** Issue a cert for `pullthrough-webhook.pullthrough.svc`
with your own CA, then:

```sh
# serving cert
kubectl -n pullthrough create secret tls pullthrough-webhook-tls \
  --cert=tls.crt --key=tls.key
# caBundle on the webhook configuration
kubectl patch validatingwebhookconfiguration pullthrough-supply-chain \
  --type=json -p="[{'op':'replace','path':'/webhooks/0/clientConfig/caBundle',\
  'value':'$(base64 -w0 ca.crt)'}]"
```

For **mutual TLS** (verify the API server's client cert), set
`admissionWebhook.clientCaFile` to the API server's client CA bundle; the webhook
then requires and verifies a client certificate on every call.

---

## Namespace selection

Two layers, used together:

- **`ValidatingWebhookConfiguration.namespaceSelector`** (API-server side) — the
  shipped config inspects all namespaces *except* the control-plane namespaces
  and any namespace labeled `pullthrough.io/admission in (ignore,disabled)`. Flip
  to opt-in by changing the selector (e.g. require a
  `pullthrough.io/admission=enforce` label).
- **`admissionWebhook.ignoreNamespaces`** (server-side) — a belt-and-suspenders
  exemption list evaluated by the webhook itself.

Excluding `kube-system` et al. ensures a webhook outage can never wedge the
cluster's own control plane.

---

## Metrics

Exposed on the proxy's Prometheus endpoint (bridged from the handler):

| Metric | Meaning |
|---|---|
| `pullthrough_admission_reviews_total` | AdmissionReview requests handled |
| `pullthrough_admission_admitted_total` / `_denied_total` / `_warned_total` | Pod outcomes |
| `pullthrough_admission_bypassed_total` | exempt namespace / non-Pod |
| `pullthrough_admission_images_checked_total` / `_images_blocked_total` | per-image evaluation |
| `pullthrough_admission_lockdown_denies_total` | kill-switch-driven denials |
| `pullthrough_admission_source_errors_total` | verdict-source errors/timeouts |
| `pullthrough_admission_fail_open_total` / `_fail_closed_total` | failure-policy resolution |
| `pullthrough_admission_verdicts_total{verdict}` | dossier verdict breakdown |

---

## Troubleshooting

- **Every Pod denied right after enabling** — likely `unknownAction: deny` with a
  cluster whose images were never pulled through the proxy. Start with
  `unknownAction: admit`, pre-warm the proxy, then tighten.
- **API server reports TLS errors** — the serving cert SAN must be
  `pullthrough-webhook.pullthrough.svc`, and the `caBundle` must match its issuer.
- **`verdict unavailable` denials (standalone)** — the webhook cannot reach the
  dossier API: check `dossier.url`, the `PTS_ADMIN_TOKEN` (read capability), and
  TLS (`caCertFile` for https). With `failurePolicy: open` these become warnings
  instead of denials.
- **Webhook outage blocks deploys** — set the
  `ValidatingWebhookConfiguration` `failurePolicy: Ignore` (and run ≥2 replicas)
  until you trust the path.
