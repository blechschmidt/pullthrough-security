#!/bin/sh
# npm — point the npm CLI at the proxy's npm upstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(npm --version)"

# A project-local .npmrc (or ~/.npmrc, or `npm config set registry`) replaces
# registry.npmjs.org. The proxy rewrites the tarball URLs in the metadata it
# serves, so tarball downloads come back through it as well.
echo "registry=$MOUNT/" > .npmrc

npm init --yes >/dev/null
npm install --no-audit --no-fund "$PKG_NAME@$PKG_VERSION"
node -e "require(process.env.PKG_NAME)"
