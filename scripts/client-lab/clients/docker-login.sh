#!/bin/sh
# lab: client=Docker Engine (with a token: refused)
# lab: image=docker:27-dind
# lab: daemon=docker
# lab: modes=auth
#
# A LIMITATION, asserted: the Docker Engine reads the proxy's Bearer challenge
# as the address of a token service, and gives up on a realm that is not a URL.
# `docker login` fails, and so does every pull.
set -eu
echo "LAB_CLIENT_VERSION=$(docker version --format '{{.Server.Version}}')"

mkdir -p /etc/docker/certs.d/proxy.example.com
cp /etc/ssl/corp-ca.pem /etc/docker/certs.d/proxy.example.com/ca.crt

if echo "${PROXY_TOKEN}" | docker login proxy.example.com --username pullthrough --password-stdin >login.log 2>&1; then
    echo "docker login succeeded: the limitation is gone — update docs/clients/docker.md"; cat login.log; exit 1
fi
cat login.log
grep -q "unsupported protocol scheme" login.log

if docker pull proxy.example.com/dockerhub/library/alpine:3.19 >pull.log 2>&1; then
    echo "docker pull succeeded without credentials on a proxy that requires a token"; cat pull.log; exit 1
fi
cat pull.log
