#!/bin/sh
# docker — pull images through the proxy with the Docker Engine.
#
# This script runs inside a Docker daemon that was started with the proxy as its
# registry mirror — the equivalent of this /etc/docker/daemon.json:
#
#   { "registry-mirrors": ["https://proxy.example.com"] }
#
# The Docker Engine rejects a mirror URL that carries a path, so the mirror is
# the proxy's host root: the proxy serves the Registry v2 API at /v2/ and routes
# un-prefixed repositories to server.registry.defaultUpstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(docker --version | awk '{print $3}' | tr -d ,)"

# 1. Explicit reference. "<proxy>/<upstream>/<repository>" addresses any registry
#    upstream by name and needs no daemon configuration. It is fail-closed by
#    construction: when the proxy refuses an image, the pull fails.
#    PKG_UPSTREAM is the proxy upstream that fronts the image's registry.
docker pull "$PROXY_HOST/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION"
docker image rm "$PROXY_HOST/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION" >/dev/null

# 2. Registry mirror. A plain Docker Hub reference is fetched from the mirror
#    transparently. The Engine falls back to Docker Hub when a mirror refuses a
#    pull, so mirror mode enforces admission only where direct egress to Docker
#    Hub is blocked (as it is for this test's daemon).
docker pull "$PKG_NAME:$PKG_VERSION"
docker run --rm --network none "$PKG_NAME:$PKG_VERSION" true
