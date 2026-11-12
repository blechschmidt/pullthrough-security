#!/bin/sh
# npm — install from registry.npmjs.org, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(npm --version)"

# npm keeps its default registry. All it needs is to trust the CA the proxy
# mints registry.npmjs.org's certificate with; through a forward proxy it reads
# HTTPS_PROXY from the environment. The proxy moves the tarball URLs in the
# packuments onto registry.npmjs.org, so the downloads are intercepted too.
export NODE_EXTRA_CA_CERTS="$PT_CA_CERT"

npm init --yes >/dev/null
npm install --no-audit --no-fund "$PKG_NAME@$PKG_VERSION"
node -e "require(process.env.PKG_NAME)"
