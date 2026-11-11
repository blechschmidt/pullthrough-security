#!/bin/sh
# lab: client=npm (JSR packages through npm.jsr.io)
# lab: image=node:22-slim
#
# Node package managers install JSR packages from JSR's npm compatibility
# registry, https://npm.jsr.io — an npm registry, fronted by an upstream of type
# npm (here "npm-jsr"), selected for the @jsr scope.
set -eu
echo "LAB_CLIENT_VERSION=$(npm --version)"

cat > .npmrc <<EOF
registry=https://proxy.example.com/v1/npm/
@jsr:registry=https://proxy.example.com/v1/npm-jsr/
cafile=/etc/ssl/corp-ca.pem
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
//proxy.example.com/v1/npm-jsr/:_authToken=${PROXY_TOKEN}
EOF
fi

npm init --yes >/dev/null
npm install --no-audit --no-fund @jsr/luca__flag@1.0.1
grep -q '"resolved": "https://proxy.example.com/v1/npm-jsr/' package-lock.json
