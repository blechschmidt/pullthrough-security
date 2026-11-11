#!/bin/sh
# lab: client=Nix
# lab: image=nixos/nix:2.35.6
#
# Nix with the proxy as its only substituter, configured in nix.conf.
set -eu
version=$(nix --version)
echo "LAB_CLIENT_VERSION=${version##* }"

# trusted-public-keys stays the upstream cache's key: the proxy serves the
# signed narinfo as it is, apart from the (unsigned) NAR location.
cat >> /etc/nix/nix.conf <<EOF
substituters = https://proxy.example.com/v1/nix
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
require-sigs = true
ssl-cert-file = /etc/ssl/corp-ca.pem
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > /etc/nix/netrc <<EOF
machine proxy.example.com
  login pullthrough
  password ${PROXY_TOKEN}
EOF
chmod 600 /etc/nix/netrc
cat >> /etc/nix/nix.conf <<EOF
netrc-file = /etc/nix/netrc
EOF
fi

nix-store --realise /nix/store/n5glp21rsz314qssw9fbvfswgy3kc68f-hello-2.12.1
test -e /nix/store/n5glp21rsz314qssw9fbvfswgy3kc68f-hello-2.12.1
