# Docker, containerd and other OCI clients

Pull container images through the proxy's registry upstreams. The examples use
the upstream names `dockerhub` (Docker Hub) and `ghcr` (GitHub Container
Registry); replace them with the names your operator gave the upstreams
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `docker` |
| Package source | `proxy.example.com/<upstream>/<repository>` — the registry API at the proxy's **host root**, `https://proxy.example.com/v2/` |
| Clients | Docker Engine, containerd (Kubernetes nodes), Podman / Buildah / CRI-O / skopeo |
| Tested | Docker Engine 27.5: [in CI on every push](../ecosystem-tests-reference.md#docker) and in the [client lab](../client-lab.md). containerd 1.7 and skopeo 1.17 (the library Podman, Buildah and CRI-O share): in the client lab. BuildKit: not tested. |

## Configure

Container clients put `/v2/` directly after the registry host, so none of them
can address a path such as `/v1/dockerhub/`. The proxy therefore serves the
registry API at its host root as well, and tells upstreams apart in three ways:

1. a request carrying `?ns=<registry host>` (containerd) is served by the
   upstream that fronts that registry;
2. otherwise, a repository whose first path component is the name of a registry
   upstream is served by it — `proxy.example.com/dockerhub/library/alpine`;
3. otherwise the upstream named by `server.registry.defaultUpstream` serves it
   (registry-mirror mode); without one, the pull is refused with an error that
   lists the upstreams.

### Docker Engine: an explicit reference

Name the image through the proxy — `<proxy>/<upstream>/<repository>`:

<!-- verified: lab:docker -->

```sh
docker pull proxy.example.com/dockerhub/library/alpine:3.19
docker pull proxy.example.com/ghcr/stefanprodan/podinfo:6.7.1
```

Nothing is configured on the daemon, it works for every registry upstream, and
it is fail-closed by construction: when the proxy refuses an image, the pull
fails. Docker Hub's official images live under `library/`.

### Docker Engine: a registry mirror for Docker Hub

To pull Docker Hub images under their usual names (`alpine:3.19`), make the
proxy the daemon's mirror in `/etc/docker/daemon.json`. The mirror is the bare
proxy URL — the Engine rejects a mirror URL that has a path:

<!-- verified: lab:docker -->

```json
{
  "registry-mirrors": ["https://proxy.example.com"]
}
```

Reload the daemon (`registry-mirrors` is one of the settings a `SIGHUP` — which
is what `systemctl reload docker` sends — re-reads) or restart it, then:

<!-- verified: lab:docker -->

```sh
docker pull busybox:1.36
```

`docker system info` lists the mirror under *Registry Mirrors*. The operator has
to name the upstream that answers un-prefixed repositories (see
[On the proxy](#on-the-proxy)).

> **A mirror is fail-open.** When the mirror refuses a pull — because the proxy
> blocked the image — the Engine fetches it from Docker Hub directly. Mirror
> mode enforces the proxy's decisions only where the daemon has no route to
> Docker Hub; use explicit references otherwise.

### containerd (Kubernetes nodes)

containerd mirrors per registry, with one `hosts.toml` for each, and names the
registry it is mirroring in the `ns` query parameter — so one proxy host mirrors
any number of registries without prefixes:

`/etc/containerd/certs.d/docker.io/hosts.toml`:

<!-- verified: lab:containerd -->

```toml
server = "https://registry-1.docker.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
```

`/etc/containerd/certs.d/ghcr.io/hosts.toml`:

<!-- verified: lab:containerd -->

```toml
server = "https://ghcr.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
```

The lab exercises these files with `ctr images pull --hosts-dir
/etc/containerd/certs.d`. For Kubernetes, point the CRI plugin at the directory
in `/etc/containerd/config.toml`:

<!-- untested: the lab reads hosts.toml through ctr --hosts-dir, not through the CRI plugin of a kubelet -->

```toml
[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"
```

`server` is where containerd falls back to when the proxy cannot serve an
image: like a Docker mirror, this is fail-open unless nodes have no route to
the registry.

### Podman, Buildah, CRI-O, skopeo

These share one library and one configuration, `registries.conf`. Unlike the
Docker Engine's, a mirror location may have a path — the upstream's name — so
each registry gets its own mirror entry.
`/etc/containers/registries.conf.d/pullthrough.conf`:

<!-- verified: lab:skopeo -->

```toml
[[registry]]
prefix = "docker.io"
location = "docker.io"

[[registry.mirror]]
location = "proxy.example.com/dockerhub"

[[registry]]
prefix = "ghcr.io"
location = "ghcr.io"

[[registry.mirror]]
location = "proxy.example.com/ghcr"
```

<!-- verified: lab:skopeo -->

```sh
skopeo copy docker://docker.io/library/alpine:3.19 dir:/tmp/alpine
```

The lab runs skopeo. A mirror is tried first and the registry itself after it:
fail-open, as with the other clients.

## Authenticate

**The Docker Engine cannot use a proxy that requires a token.** It reads the
proxy's `Bearer` challenge as the address of a token service and gives up on a
realm that is not a URL. `docker login` fails, and so does every pull:

<!-- output: lab:docker-login -->

```
Error response from daemon: Get "https://proxy.example.com/v2/": Get "pullthrough?account=pullthrough&client_id=docker&offline_token=true": unsupported protocol scheme ""
```

Where access control is on, the operator has to admit the Engine without a
token: an anonymous role scoped to the registry upstreams
([how](../clients.md#clients-that-cannot-present-a-token)).

**Podman, Buildah and CRI-O cannot either.** All they have is a login — a user
name and a password in an auth file — and the library they share answers the
proxy's challenge the way the Engine does. The lab asserts that with skopeo,
which is built on the same library (`skopeo login` and `--creds` fail with the
error above); Podman, Buildah and CRI-O themselves are not run. Helm's OCI
client fails like the Engine as well ([Helm](helm.md#authenticate)).

**skopeo can**: it takes a bearer token for the registry it reads from on the
command line, sends it without waiting for a login, and sends it to a mirror as
well:

<!-- verified: lab:skopeo -->

```sh
skopeo copy --src-registry-token "<token>" docker://docker.io/library/alpine:3.19 dir:/tmp/alpine
skopeo inspect --registry-token "<token>" docker://proxy.example.com/dockerhub/library/alpine:3.19
```

**containerd can**: a `hosts.toml` carries request headers, and the proxy takes
the token as a bearer token.

<!-- verified: lab:containerd -->

```toml
[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
  [host."https://proxy.example.com".header]
    Authorization = "Bearer <token>"
```

## Trust a private CA

**Docker Engine** — a directory per registry host, read on every pull (no
restart):

<!-- verified: lab:docker -->

```sh
mkdir -p /etc/docker/certs.d/proxy.example.com
cp /etc/ssl/corp-ca.pem /etc/docker/certs.d/proxy.example.com/ca.crt
```

**Podman, Buildah, CRI-O, skopeo** — the same, under `/etc/containers`:

<!-- verified: lab:skopeo -->

```sh
mkdir -p /etc/containers/certs.d/proxy.example.com
cp /etc/ssl/corp-ca.pem /etc/containers/certs.d/proxy.example.com/ca.crt
```

**containerd** — in the host's entry of each `hosts.toml`:

<!-- verified: lab:containerd -->

```toml
[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/ssl/corp-ca.pem"
```

## Check that it works

<!-- verified: lab:docker -->

```sh
docker pull proxy.example.com/dockerhub/library/alpine:3.19
```

For a mirror, `docker system info` must list it; and since the Engine falls
back silently, the only proof that an image came through the mirror is the
proxy's side — the [download log](../download-log.md) — or a daemon that has no
other route.

## Good to know

- **An explicit reference is part of the image's name.** Dockerfiles, Compose
  files and Kubernetes manifests then say `proxy.example.com/dockerhub/…`; the
  image digest is unchanged. A mirror keeps the names as they are.
- **Do not name a registry upstream after a namespace you mirror.** An upstream
  called `library` would shadow Docker Hub's `library/…` repositories (rule 2
  above).
- **A mirrored pull still looks up `docker.io`.** The Engine resolves that
  name in DNS once per pull through a mirror (the lab records it); the image
  comes from the mirror.
- **Only pulls.** The proxy serves the read endpoints of the registry API
  (manifests, blobs, referrers, tag lists, the catalog). `docker push` needs
  the registry itself, and a token endpoint the registry hosts is never
  forwarded.
- **Rate limits and private images** are the proxy's business: it logs in to
  the registry with the upstream's `credentials`, once, for everyone.
- **OCI Helm charts** use the same endpoint: see [Helm](helm.md).
- BuildKit (`docker buildx` with a container builder) has its own registry
  configuration, `buildkitd.toml`. It was not tested.

## On the proxy

<!-- proxy-config -->

```yaml
server:
  registry:
    # The registry upstream that serves un-prefixed repositories, i.e. what a
    # Docker registry mirror asks for. Leave it out to serve explicit references
    # and containerd's ?ns= requests only.
    defaultUpstream: dockerhub
upstreams:
  dockerhub:
    type: docker
    url: https://registry-1.docker.io
  ghcr:
    type: docker
    url: https://ghcr.io
```

`server.registry.enabled: false` switches the host-root endpoint off (registries
are then reachable only under `/v1/<name>/v2/`, which no container client can
address). Blobs and manifests by digest are cached immutably and
digest-verified; a manifest by tag is revalidated. Details:
[backends: docker](../backends.md#docker).
