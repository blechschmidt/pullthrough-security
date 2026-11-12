#!/bin/sh
# julia — add packages from pkg.julialang.org, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(julia --version | awk '{print $3}')"

# JULIA_PKG_SERVER keeps its default, pkg.julialang.org. Julia trusts the
# proxy's CA through JULIA_SSL_CA_ROOTS_PATH; through a forward proxy it reads
# HTTPS_PROXY.
export JULIA_SSL_CA_ROOTS_PATH="$PT_CA_CERT"

julia -e 'using Pkg; Pkg.add(name=ENV["PKG_NAME"], version=ENV["PKG_VERSION"])'
