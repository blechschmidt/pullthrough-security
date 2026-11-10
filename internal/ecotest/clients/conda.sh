#!/bin/sh
# conda — use the proxy as the only conda channel.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(conda --version | awk '{print $2}')"

# A .condarc whose only channel is the proxy mount (the mount is the channel
# root, e.g. conda-forge) replaces conda.anaconda.org. `default_channels: []`
# and --override-channels keep conda from consulting any other channel.
cat > condarc <<CONDARC
channels:
  - $MOUNT
default_channels: []
channel_priority: strict
auto_update_conda: false
notify_outdated_conda: false
CONDARC
export CONDARC="$PWD/condarc" CONDA_PKGS_DIRS="$PWD/pkgs"

conda create --yes --quiet --prefix "$PWD/env" --override-channels --channel "$MOUNT" \
    "$PKG_NAME=$PKG_VERSION"
test -d "$PWD/env/conda-meta"
