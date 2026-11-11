# Helm

Add the proxy as a chart repository, or pull OCI charts through its registry
endpoint. The examples use the upstream names `podinfo` (a classic chart
repository) and `helm-oci` (an OCI registry of charts); replace them with the
names your operator gave the upstreams
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `helm` |
| Package source | `https://proxy.example.com/v1/podinfo` (classic) · `oci://proxy.example.com/helm-oci/<repository>` (OCI) |
| Clients | helm |
| Tested | helm 3.16: [in CI on every push](../ecosystem-tests-reference.md#helm) (classic repository) and in the [client lab](../client-lab.md) (classic and OCI). |

## Configure

### A classic chart repository

One upstream fronts one chart repository; add it under any local name:

<!-- verified: lab:helm -->

```sh
helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem
helm repo update
helm pull podinfo/podinfo --version 6.7.1
```

(`--ca-file` is needed only with a private CA; Helm stores it with the
repository.) Chart archives come back through the proxy even when the repository's index
points somewhere else (a release asset on another host, an `oci://` reference):
the proxy rewrites every chart URL in the `index.yaml` it serves.

### An OCI registry of charts

OCI charts are pulled through the proxy's host-root registry endpoint, like
[container images](docker.md): `oci://<proxy>/<upstream>/<repository>`.

<!-- verified: lab:helm -->

```sh
helm pull oci://proxy.example.com/helm-oci/stefanprodan/charts/podinfo --version 6.7.1 \
    --ca-file /etc/ssl/corp-ca.pem --destination oci
```

(`--ca-file` is needed only with a private CA.)

## Authenticate

Only when the proxy has access control switched on.

**Classic repository** — the proxy takes your **proxy token** as the password
of HTTP Basic authentication, with any user name. Helm stores both with the
repository and sends them for the index and the charts:

<!-- verified: lab:helm -->

```sh
helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem \
    --username pullthrough --password "<token>"
```

**OCI charts cannot be pulled from a proxy that requires a token.** Helm's
registry client, like the Docker Engine, reads the proxy's `Bearer` challenge
as the address of a token service; `helm registry login` fails:

<!-- output: lab:helm -->

```
Error: Get "https://proxy.example.com/v2/": Get "pullthrough?account=pullthrough&client_id=docker&offline_token=true": unsupported protocol scheme ""
```

Where access control is on, the operator has to admit anonymous reads for the
OCI chart upstream
([how](../clients.md#clients-that-cannot-present-a-token)).

## Trust a private CA

`--ca-file`: stored with the repository by `helm repo add`, and given to every
OCI command (as in the `helm pull oci://…` command above):

<!-- verified: lab:helm -->

```sh
helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:helm -->

```sh
helm repo update
helm pull podinfo/podinfo --version 6.7.1
```

`helm repo list` shows the address each repository was added under.

## Good to know

- **`Chart.lock` and `Chart.yaml` dependencies name repositories by URL.** A
  chart that depends on `https://stefanprodan.github.io/podinfo` keeps asking
  that host on `helm dependency build`; point the dependency's `repository` at
  the proxy address (or at `@podinfo`, the local name).
- **Provenance files** (`helm pull --verify`) are served next to the archive
  (`.prov`).
- **An index the proxy cannot fully rewrite is refused** (`502`) rather than
  passed on, so an upstream cannot steer Helm around the proxy.
- **Only pulls**: `helm push` needs the registry itself.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  podinfo:
    type: helm
    url: https://stefanprodan.github.io/podinfo
  helm-oci:
    type: helm
    url: https://ghcr.io
    settings:
      oci: "true"
```

`url` of a classic upstream is the repository root that serves `index.yaml`.
Chart archives are verified against the SHA-256 the index publishes and cached
immutably; with `settings.oci: "true"` the upstream is an OCI registry, served
at the proxy's host root like a `docker` upstream. Details:
[backends: helm](../backends.md#helm).
