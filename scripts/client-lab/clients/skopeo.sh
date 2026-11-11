#!/bin/sh
# lab: client=skopeo (Podman, Buildah, CRI-O)
# lab: image=quay.io/skopeo/stable:v1.17
# lab: entrypoint=sh
#
# The clients built on the containers/image library — Podman, Buildah, CRI-O,
# skopeo — share registries.conf, the certs.d directory and the way they log in
# to a registry. Exercised with skopeo.
set -eu
echo "LAB_CLIENT_VERSION=$(skopeo --version | awk '{print $3}')"

# The CA, per registry host.
mkdir -p /etc/containers/certs.d/proxy.example.com
cp /etc/ssl/corp-ca.pem /etc/containers/certs.d/proxy.example.com/ca.crt

# A mirror per registry. Unlike the Docker Engine's, a mirror location may have
# a path: the upstream's name.
mkdir -p /etc/containers/registries.conf.d
cat > /etc/containers/registries.conf.d/pullthrough.conf <<EOF
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
EOF

if [ -z "${PROXY_TOKEN:-}" ]; then
    # Images under their usual names come through the mirror (this network
    # reaches nothing else).
    skopeo copy docker://docker.io/library/alpine:3.19 dir:/tmp/alpine
    skopeo copy docker://ghcr.io/stefanprodan/podinfo:6.7.1 dir:/tmp/podinfo
    test -s /tmp/alpine/manifest.json
    test -s /tmp/podinfo/manifest.json

    # The explicit reference works as well.
    skopeo inspect docker://proxy.example.com/dockerhub/library/alpine:3.19 >/dev/null
else
    # skopeo can be handed a bearer token for the registry it reads from, and
    # sends it to the mirror as well: the one client of this family that can
    # present a token to the proxy.
    skopeo copy --src-registry-token "${PROXY_TOKEN}" docker://docker.io/library/alpine:3.19 dir:/tmp/alpine
    test -s /tmp/alpine/manifest.json
    skopeo inspect --registry-token "${PROXY_TOKEN}" docker://proxy.example.com/dockerhub/library/alpine:3.19 >/dev/null

    # A LIMITATION, asserted: a login — a user name and a password in an auth
    # file, which is all Podman, Buildah and CRI-O have — fails. Like the Docker
    # Engine, the library reads the proxy's Bearer challenge as the address of a
    # token service.
    if skopeo login --username pullthrough --password "${PROXY_TOKEN}" proxy.example.com >login.log 2>&1; then
        echo "skopeo logged in to the proxy: the limitation is gone — update docs/clients/docker.md"
        cat login.log; exit 1
    fi
    cat login.log
    grep -q "unsupported protocol scheme" login.log
    if skopeo inspect --creds "pullthrough:${PROXY_TOKEN}" docker://proxy.example.com/dockerhub/library/alpine:3.19 >creds.log 2>&1; then
        echo "skopeo authenticated with --creds: the limitation is gone — update docs/clients/docker.md"
        exit 1
    fi
    grep -q "unsupported protocol scheme" creds.log
fi
