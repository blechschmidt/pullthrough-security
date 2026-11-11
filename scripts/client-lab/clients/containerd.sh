#!/bin/sh
# lab: client=containerd
# lab: image=docker:27-dind
# lab: daemon=docker
#
# containerd with a hosts.toml per mirrored registry (the mechanism Kubernetes
# nodes use, through config_path in containerd's CRI configuration). It is
# exercised with ctr against the containerd of a Docker-in-Docker container.
# A hosts.toml can carry request headers, so containerd CAN present a token.
set -eu
echo "LAB_CLIENT_VERSION=$(ctr --version | awk '{print $3}')"

mkdir -p /etc/containerd/certs.d/docker.io /etc/containerd/certs.d/ghcr.io
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > /etc/containerd/certs.d/docker.io/hosts.toml <<EOF
server = "https://registry-1.docker.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/ssl/corp-ca.pem"
  [host."https://proxy.example.com".header]
    Authorization = "Bearer ${PROXY_TOKEN}"
EOF
cat > /etc/containerd/certs.d/ghcr.io/hosts.toml <<EOF
server = "https://ghcr.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/ssl/corp-ca.pem"
  [host."https://proxy.example.com".header]
    Authorization = "Bearer ${PROXY_TOKEN}"
EOF
else
cat > /etc/containerd/certs.d/docker.io/hosts.toml <<EOF
server = "https://registry-1.docker.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/ssl/corp-ca.pem"
EOF
cat > /etc/containerd/certs.d/ghcr.io/hosts.toml <<EOF
server = "https://ghcr.io"

[host."https://proxy.example.com"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/ssl/corp-ca.pem"
EOF
fi

# Each pull reaches the proxy as /v2/<repository>/...?ns=<registry>, which is
# how one proxy host mirrors several registries.
ctr="ctr --address /run/docker/containerd/containerd.sock --namespace lab"
$ctr images pull --hosts-dir /etc/containerd/certs.d docker.io/library/alpine:3.20 >/dev/null
$ctr images pull --hosts-dir /etc/containerd/certs.d ghcr.io/stefanprodan/podinfo:6.7.0 >/dev/null
$ctr images ls -q | grep -q "docker.io/library/alpine:3.20"
$ctr images ls -q | grep -q "ghcr.io/stefanprodan/podinfo:6.7.0"
