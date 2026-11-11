#!/bin/sh
# lab: client=npm
# lab: image=node:22-slim
#
# npm with a project .npmrc: the registry, the CA and — where the proxy asks for
# one — the token, scoped to the registry URL.
set -eu
echo "LAB_CLIENT_VERSION=$(npm --version)"

cat > .npmrc <<EOF
registry=https://proxy.example.com/v1/npm/
cafile=/etc/ssl/corp-ca.pem
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
EOF
fi

npm init --yes >/dev/null
npm install --no-fund is-number@7.0.0
node -e "require('is-number')"

# The lock file records where each tarball came from: the proxy.
grep -q '"resolved": "https://proxy.example.com/v1/npm/is-number/-/is-number-7.0.0.tgz"' package-lock.json

npm ping
npm view left-pad version

# The audit endpoints are POST requests, which the proxy does not serve: an
# install is unaffected, `npm audit` reports the failure.
if npm audit >audit.log 2>&1; then
    echo "npm audit unexpectedly succeeded"; cat audit.log; exit 1
fi
grep -q "audit endpoint returned an error" audit.log
