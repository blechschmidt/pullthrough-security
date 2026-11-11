#!/bin/sh
# lab: client=Yarn 4 (berry)
# lab: image=node:22-slim
#
# Yarn 2+ has its own configuration file. Corepack, which downloads the Yarn
# release named in package.json, is a client of the npm registry too.
set -eu

export COREPACK_NPM_REGISTRY=https://proxy.example.com/v1/npm
export NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
if [ -n "${PROXY_TOKEN:-}" ]; then
    export COREPACK_NPM_TOKEN="${PROXY_TOKEN}"
fi
corepack enable

echo '{"name":"lab","version":"1.0.0","license":"MIT","packageManager":"yarn@4.5.3"}' > package.json
cat > .yarnrc.yml <<EOF
npmRegistryServer: "https://proxy.example.com/v1/npm"
httpsCaFilePath: /etc/ssl/corp-ca.pem
enableTelemetry: false
nodeLinker: node-modules
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> .yarnrc.yml <<EOF
npmAlwaysAuth: true
npmAuthToken: "${PROXY_TOKEN}"
EOF
fi
echo "LAB_CLIENT_VERSION=$(yarn --version)"

yarn add is-number@7.0.0
node -e "require('is-number')"

# yarn.lock names the package and a checksum, not a URL: it is the same file
# whichever registry served the package.
grep -q 'resolution: "is-number@npm:7.0.0"' yarn.lock
if grep -q 'proxy.example.com' yarn.lock; then echo "yarn.lock names the proxy"; exit 1; fi
