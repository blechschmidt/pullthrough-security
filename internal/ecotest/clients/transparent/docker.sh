#!/bin/sh
# docker — pull from Docker Hub with a Docker Engine whose traffic the proxy
# intercepts.
#
# This script runs inside a Docker daemon with no registry mirror. Through a
# forward proxy the daemon was started with HTTPS_PROXY in its environment — the
# equivalent of a systemd drop-in for docker.service:
#
#   [Service]
#   Environment=HTTPS_PROXY=http://proxy.example.com:3128
#
# In NAT mode it was started with nothing at all.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(docker --version | awk '{print $3}' | tr -d ,)"

# Trust the proxy's CA. For Docker Hub the daemon verifies against the system
# trust store — /etc/docker/certs.d is not consulted for docker.io — which it
# reads when it first connects to a registry. (On a host: add the CA, then
# restart the daemon.)
cp "$PT_CA_CERT" /usr/local/share/ca-certificates/pullthrough-intercept.crt
update-ca-certificates >/dev/null 2>&1

# A plain Docker Hub reference. The daemon cannot reach Docker Hub any other
# way, so an image the proxy refuses is not pulled.
docker pull "$PKG_NAME:$PKG_VERSION"
docker run --rm --network none "$PKG_NAME:$PKG_VERSION" true
