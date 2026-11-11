#!/bin/sh
# lab: client=skopeo (Podman, Buildah, CRI-O)
# lab: image=quay.io/skopeo/stable:v1.17
# lab: entrypoint=sh
# lab: modes=open
#
# The clients built on the containers/image library — Podman, Buildah, CRI-O,
# skopeo — share registries.conf and the certs.d directory. Exercised with
# skopeo. (Like the Docker Engine they cannot present a token to the proxy.)
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

# Images under their usual names come through the mirror (this network reaches
# nothing else).
skopeo copy docker://docker.io/library/alpine:3.19 dir:/tmp/alpine
skopeo copy docker://ghcr.io/stefanprodan/podinfo:6.7.1 dir:/tmp/podinfo
test -s /tmp/alpine/manifest.json
test -s /tmp/podinfo/manifest.json

# The explicit reference works as well.
skopeo inspect docker://proxy.example.com/dockerhub/library/alpine:3.19 >/dev/null
