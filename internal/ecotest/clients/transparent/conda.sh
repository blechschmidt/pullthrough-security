#!/bin/sh
# conda — install from the conda-forge channel, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(conda --version | awk '{print $2}')"

# conda keeps its channel (conda-forge on conda.anaconda.org, as Miniforge
# ships it). It trusts the proxy's CA through ssl_verify (CONDA_SSL_VERIFY);
# through a forward proxy it reads HTTPS_PROXY.
export CONDA_SSL_VERIFY="$PT_CA_CERT" CONDA_PKGS_DIRS="$PWD/pkgs"
export CONDA_AUTO_UPDATE_CONDA=false CONDA_NOTIFY_OUTDATED_CONDA=false

conda create --yes --quiet --prefix "$PWD/env" "$PKG_NAME=$PKG_VERSION"
test -d "$PWD/env/conda-meta"
