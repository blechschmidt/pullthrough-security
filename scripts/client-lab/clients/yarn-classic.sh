#!/bin/sh
# lab: client=Yarn 1 (classic)
# lab: image=node:22-slim
set -eu
echo "LAB_CLIENT_VERSION=$(yarn --version)"

cat > .yarnrc <<EOF
registry "https://proxy.example.com/v1/npm/"
cafile "/etc/ssl/corp-ca.pem"
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
# Yarn 1 reads the token from .npmrc, and sends it with every request only
# when always-auth is set.
cat > .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
always-auth=true
EOF
fi

echo '{"name":"lab","version":"1.0.0","license":"MIT"}' > package.json
yarn add is-number@7.0.0 --non-interactive
node -e "require('is-number')"

# yarn.lock records the proxy URL of every tarball.
grep -q 'resolved "https://proxy.example.com/v1/npm/is-number/-/is-number-7.0.0.tgz' yarn.lock
