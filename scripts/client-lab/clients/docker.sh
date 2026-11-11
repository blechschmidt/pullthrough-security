#!/bin/sh
# lab: client=Docker Engine
# lab: image=docker:27-dind
# lab: daemon=docker
# lab: modes=open
# lab: lookups=docker.io
#
# The Docker Engine: an explicit reference to each registry upstream, then the
# registry mirror. (The Engine cannot present a token to the proxy; see
# docker-login.sh.)
set -eu
echo "LAB_CLIENT_VERSION=$(docker version --format '{{.Server.Version}}')"

# The Engine reads a registry's CA from a per-host directory, on every pull.
mkdir -p /etc/docker/certs.d/proxy.example.com
cp /etc/ssl/corp-ca.pem /etc/docker/certs.d/proxy.example.com/ca.crt

# 1. Explicit reference: <proxy>/<upstream>/<repository>. No daemon
#    configuration, any registry upstream, and a refused image fails the pull.
docker pull proxy.example.com/dockerhub/library/alpine:3.19
docker pull proxy.example.com/ghcr/stefanprodan/podinfo:6.7.1

# 2. Registry mirror, for Docker Hub images under their usual names. The mirror
#    is the proxy's host root (the Engine rejects a mirror URL with a path).
cat > /etc/docker/daemon.json <<EOF
{
  "registry-mirrors": ["https://proxy.example.com"]
}
EOF
kill -HUP "$(cat /var/run/docker.pid)" # registry-mirrors is reloadable; or restart the daemon
sleep 2
docker system info 2>/dev/null | grep -A1 "Registry Mirrors" | grep -q "https://proxy.example.com/"
# Docker Hub is not reachable from this network: the image can only have come
# from the mirror. (The Engine still looks the name docker.io up in DNS, once
# per mirrored pull — hence the declared lookup.)
docker pull busybox:1.36
docker run --rm --network none busybox:1.36 true
