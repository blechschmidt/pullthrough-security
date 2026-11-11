#!/bin/sh
# lab: client=conda
# lab: image=condaforge/miniforge3:24.9.2-0
#
# conda with a channel alias: a channel NAME (conda-forge, bioconda, …) resolves
# to the proxy upstream of the same name, so `-c conda-forge` and environment
# files keep working unchanged.
set -eu
echo "LAB_CLIENT_VERSION=$(conda --version | awk '{print $2}')"

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
export CONDA_PKGS_DIRS="$PWD/pkgs"

conda create --yes --quiet --prefix "$PWD/env" tzdata=2024a
test -d env/conda-meta

# A channel named on the command line resolves through the alias too.
conda create --yes --quiet --prefix "$PWD/env2" -c conda-forge font-ttf-ubuntu=0.83
test -d env2/conda-meta

# The channels in effect are the proxy's and nothing else.
conda config --show channels default_channels | grep -q "conda-forge"
if conda config --show default_channels | grep -q "repo.anaconda.com"; then echo "repo.anaconda.com is still a default channel"; exit 1; fi
