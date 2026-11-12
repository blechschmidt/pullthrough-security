#!/bin/sh
# lab: client=Docker Engine (docker login)
# lab: image=docker:27-dind
# lab: daemon=docker
# lab: modes=auth
#
# The Docker Engine against a proxy that requires a token. The proxy challenges
# a container client with HTTP Basic, which the Engine answers with what
# `docker login` stored: the token as the password, any user name. (A Bearer
# challenge would not do: the Engine reads one as the address of a token
# service.)
set -eu
echo "LAB_CLIENT_VERSION=$(docker version --format '{{.Server.Version}}')"

mkdir -p /etc/docker/certs.d/proxy.example.com
cp /etc/ssl/corp-ca.pem /etc/docker/certs.d/proxy.example.com/ca.crt

# Without a login, a pull is refused.
if docker pull proxy.example.com/dockerhub/library/alpine:3.19 >anonymous.log 2>&1; then
    echo "docker pull succeeded without credentials on a proxy that requires a token"; cat anonymous.log; exit 1
fi
cat anonymous.log

echo "${PROXY_TOKEN}" | docker login proxy.example.com --username pullthrough --password-stdin
docker pull proxy.example.com/dockerhub/library/alpine:3.19
docker pull proxy.example.com/ghcr/stefanprodan/podinfo:6.7.1
docker run --rm --network none proxy.example.com/dockerhub/library/alpine:3.19 true

# A wrong token is refused at the login.
if echo "not-the-token" | docker login proxy.example.com --username pullthrough --password-stdin >wrong.log 2>&1; then
    echo "docker login succeeded with a wrong token"; cat wrong.log; exit 1
fi
cat wrong.log
