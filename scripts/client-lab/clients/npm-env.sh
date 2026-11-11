#!/bin/sh
# lab: client=npm (environment only)
# lab: image=node:22-slim
#
# npm configured through the environment alone, as in a CI job or a Dockerfile.
set -eu
echo "LAB_CLIENT_VERSION=$(npm --version)"

export NPM_CONFIG_REGISTRY=https://proxy.example.com/v1/npm/
export NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    # The token's key contains the registry URL, which an environment variable
    # name cannot spell: write it to the user's ~/.npmrc.
    npm config set //proxy.example.com/v1/npm/:_authToken "${PROXY_TOKEN}"
fi

npm init --yes >/dev/null
npm install --no-audit --no-fund is-number@7.0.0
node -e "require('is-number')"
