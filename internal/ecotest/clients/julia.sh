#!/bin/sh
# julia — use the proxy as the Pkg server.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(julia --version | awk '{print $3}')"

# JULIA_PKG_SERVER replaces pkg.julialang.org for the registry, package and
# artifact tarballs.
export JULIA_PKG_SERVER="$MOUNT"

julia -e 'using Pkg; Pkg.add(name=ENV["PKG_NAME"], version=ENV["PKG_VERSION"])'
