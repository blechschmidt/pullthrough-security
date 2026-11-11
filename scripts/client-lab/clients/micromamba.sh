#!/bin/sh
# lab: client=micromamba
# lab: image=mambaorg/micromamba:2.0.5
#
# micromamba (and mamba) read the same ~/.condarc as conda.
set -eu
echo "LAB_CLIENT_VERSION=$(micromamba --version)"

if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ~/.condarc <<EOF
channel_alias: https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1
channels:
  - conda-forge
default_channels: []
ssl_verify: /etc/ssl/corp-ca.pem
EOF
else
cat > ~/.condarc <<EOF
channel_alias: https://proxy.example.com/v1
channels:
  - conda-forge
default_channels: []
ssl_verify: /etc/ssl/corp-ca.pem
EOF
fi

micromamba create --yes --quiet --prefix "$PWD/env" tzdata=2024a
test -d env/conda-meta
