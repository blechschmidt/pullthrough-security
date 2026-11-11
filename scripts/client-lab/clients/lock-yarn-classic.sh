#!/bin/sh
# lab: client=Yarn 1 (an existing lock file, written against the public registry)
# lab: image=node:22-slim
# lab: lookups=registry.yarnpkg.com
#
# Moving a project onto the proxy: its yarn.lock names registry.yarnpkg.com for
# every tarball, and Yarn 1 fetches exactly the URL the lock file records —
# whatever registry is configured. The lock file has to be rewritten.
set -eu
echo "LAB_CLIENT_VERSION=$(yarn --version)"

cat > .yarnrc <<EOF
registry "https://proxy.example.com/v1/npm/"
cafile "/etc/ssl/corp-ca.pem"
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
always-auth=true
EOF
fi

# A lock file as the public registry would have produced it.
echo '{"name":"lab","version":"1.0.0","license":"MIT"}' > package.json
yarn add is-number@7.0.0 --non-interactive >/dev/null
sed -i 's#https://proxy.example.com/v1/npm/#https://registry.yarnpkg.com/#g' yarn.lock
rm -rf node_modules
yarn cache clean >/dev/null

# Yarn 1 goes to the host in the lock file (the lookup this script declares),
# which this network does not reach.
if yarn install --frozen-lockfile --non-interactive >install.log 2>&1; then
    echo "Yarn 1 installed a public lock file through the proxy: update docs/clients/npm.md"
    cat install.log; exit 1
fi
grep -q "registry.yarnpkg.com" install.log

# Rewriting the URLs in the lock file moves it onto the proxy; the integrity
# hashes stay as they are.
sed -i 's#https://registry.yarnpkg.com/#https://proxy.example.com/v1/npm/#g' yarn.lock
yarn install --frozen-lockfile --non-interactive
node -e "require('is-number')"
