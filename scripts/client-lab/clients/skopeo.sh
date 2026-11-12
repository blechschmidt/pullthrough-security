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
    # A login — a user name and a password in an auth file, which is all
    # Podman, Buildah and CRI-O have. The proxy challenges a container client
    # with HTTP Basic, and the library answers with the password it holds for
    # the proxy's host: for the mirror as for an explicit reference.
    echo "${PROXY_TOKEN}" | skopeo login --username pullthrough --password-stdin proxy.example.com
    skopeo copy docker://docker.io/library/alpine:3.19 dir:/tmp/alpine
    skopeo copy docker://ghcr.io/stefanprodan/podinfo:6.7.1 dir:/tmp/podinfo
    test -s /tmp/alpine/manifest.json
    test -s /tmp/podinfo/manifest.json
    skopeo inspect docker://proxy.example.com/dockerhub/library/alpine:3.19 >/dev/null
    skopeo logout proxy.example.com

    # The same credential on the command line, for an explicit reference.
    skopeo inspect --creds "pullthrough:${PROXY_TOKEN}" docker://proxy.example.com/dockerhub/library/alpine:3.19 >/dev/null

    # A LIMITATION, asserted: a bearer token on the command line is not sent.
    # The library presents one only in answer to a Bearer challenge.
    if skopeo inspect --registry-token "${PROXY_TOKEN}" docker://proxy.example.com/dockerhub/library/alpine:3.19 >token.log 2>&1; then
        echo "skopeo authenticated with --registry-token: update docs/clients/docker.md"; cat token.log; exit 1
    fi
    cat token.log
    grep -q "authentication required" token.log

    # Without a credential, the proxy refuses.
    if skopeo inspect docker://proxy.example.com/dockerhub/library/alpine:3.19 >anonymous.log 2>&1; then
        echo "skopeo read from a proxy that requires a token without presenting one"; cat anonymous.log; exit 1
    fi
    cat anonymous.log
fi
