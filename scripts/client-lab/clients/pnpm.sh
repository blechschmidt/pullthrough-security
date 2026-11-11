#!/bin/sh
# lab: client=pnpm
# lab: image=node:22-slim
#
# pnpm reads .npmrc. Corepack, which downloads pnpm itself, is a client of the
# npm registry too.
set -eu

export COREPACK_NPM_REGISTRY=https://proxy.example.com/v1/npm
export NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
if [ -n "${PROXY_TOKEN:-}" ]; then
    export COREPACK_NPM_TOKEN="${PROXY_TOKEN}"
fi
corepack enable
corepack prepare pnpm@9.15.0 --activate
echo "LAB_CLIENT_VERSION=$(pnpm --version)"

cat > .npmrc <<EOF
registry=https://proxy.example.com/v1/npm/
cafile=/etc/ssl/corp-ca.pem
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
EOF
fi

echo '{"name":"lab","version":"1.0.0","license":"MIT"}' > package.json
pnpm add is-number@7.0.0
node -e "require('is-number')"

# pnpm-lock.yaml records an integrity hash, not a URL.
! grep -q 'proxy.example.com' pnpm-lock.yaml
